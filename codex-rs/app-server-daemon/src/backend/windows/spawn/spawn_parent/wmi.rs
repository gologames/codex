//! Starts the temporary spawn parent through WMI.
use std::sync::mpsc;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use windows::Win32::System::Com::CLSCTX_INPROC_SERVER;
use windows::Win32::System::Com::COINIT_MULTITHREADED;
use windows::Win32::System::Com::CoCreateInstance;
use windows::Win32::System::Com::CoInitializeEx;
use windows::Win32::System::Com::CoSetProxyBlanket;
use windows::Win32::System::Com::CoUninitialize;
use windows::Win32::System::Com::EOAC_NONE;
use windows::Win32::System::Com::RPC_C_AUTHN_LEVEL_PKT_PRIVACY;
use windows::Win32::System::Com::RPC_C_IMP_LEVEL_IMPERSONATE;
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows::Win32::System::Rpc::RPC_C_AUTHZ_NONE;
use windows::Win32::System::Wmi::IWbemClassObject;
use windows::Win32::System::Wmi::IWbemLocator;
use windows::Win32::System::Wmi::WBEM_FLAG_CONNECT_USE_MAX_WAIT;
use windows::Win32::System::Wmi::WBEM_FLAG_RETURN_WBEM_COMPLETE;
use windows::Win32::System::Wmi::WbemLocator;
use windows::core::BSTR;
use windows::core::Interface;
use windows::core::VARIANT;
use windows::core::w;
use windows_sys::Win32::System::Threading::CREATE_BREAKAWAY_FROM_JOB;
use windows_sys::Win32::System::Threading::DETACHED_PROCESS;

pub(super) fn start(command_line: Vec<u16>) -> Result<u32> {
    let (send, receive) = mpsc::sync_channel(1);
    // WMI may create the temporary parent process after the 15-second timeout.
    // To avoid leaving it running, the calling Codex closes the pipe on failure.
    // The temporary parent process exits when it cannot open the pipe.
    std::thread::Builder::new()
        .name("daemon-wmi-launch-parent".into())
        .spawn(move || {
            let result = create(&command_line);
            let _ = send.send(result);
        })?;
    receive
        .recv_timeout(Duration::from_secs(15))
        .context("WMI launch parent request timed out or worker exited")?
}

fn create(command_line: &[u16]) -> Result<u32> {
    unsafe {
        CoInitializeEx(/*pvreserved*/ None, COINIT_MULTITHREADED).ok()?;
        let _com_guard = ComGuard;
        let locator: IWbemLocator =
            CoCreateInstance(&WbemLocator, /*punkouter*/ None, CLSCTX_INPROC_SERVER)?;
        let empty = BSTR::new();
        let services = locator.ConnectServer(
            &BSTR::from(r"ROOT\CIMV2"),
            &empty,
            &empty,
            &empty,
            WBEM_FLAG_CONNECT_USE_MAX_WAIT.0,
            &empty,
            /*pctx*/ None,
        )?;
        // Use the caller's identity.
        CoSetProxyBlanket(
            &services,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            /*pserverprincname*/ None,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            /*pauthinfo*/ None,
            EOAC_NONE,
        )?;
        let mut process_class = None;
        services.GetObject(
            &BSTR::from("Win32_Process"),
            WBEM_FLAG_RETURN_WBEM_COMPLETE,
            /*pctx*/ None,
            Some(&mut process_class),
            /*ppcallresult*/ None,
        )?;
        let process_class = process_class.context("WMI returned no process class")?;
        let mut definition = None;
        process_class.GetMethod(
            w!("Create"),
            /*lflags*/ 0,
            &mut definition,
            std::ptr::null_mut(),
        )?;
        let input = definition
            .context("WMI returned no Create parameters")?
            .SpawnInstance(/*lflags*/ 0)?;
        let command = BSTR::from_wide(&command_line[..command_line.len() - 1])?;
        input.Put(
            w!("CommandLine"),
            /*lflags*/ 0,
            &VARIANT::from(command),
            /*type*/ 0,
        )?;
        let mut startup_class = None;
        services.GetObject(
            &BSTR::from("Win32_ProcessStartup"),
            WBEM_FLAG_RETURN_WBEM_COMPLETE,
            /*pctx*/ None,
            Some(&mut startup_class),
            /*ppcallresult*/ None,
        )?;
        let startup = startup_class
            .context("WMI returned no startup class")?
            .SpawnInstance(/*lflags*/ 0)?;
        // WMI represents CIM uint32/uint16 properties as VT_I4.
        let flags = (DETACHED_PROCESS | CREATE_BREAKAWAY_FROM_JOB) as i32;
        startup.Put(
            w!("CreateFlags"),
            /*lflags*/ 0,
            &VARIANT::from(flags),
            /*type*/ 0,
        )?;
        startup.Put(
            w!("ShowWindow"),
            /*lflags*/ 0,
            &VARIANT::from(/*value*/ 0i32),
            /*type*/ 0,
        )?;
        let startup_unknown: windows::core::IUnknown = startup.cast()?;
        input.Put(
            w!("ProcessStartupInformation"),
            /*lflags*/ 0,
            &VARIANT::from(startup_unknown),
            /*type*/ 0,
        )?;
        let mut output = None;
        services.ExecMethod(
            &BSTR::from("Win32_Process"),
            &BSTR::from("Create"),
            WBEM_FLAG_RETURN_WBEM_COMPLETE,
            /*pctx*/ None,
            &input,
            Some(&mut output),
            /*ppcallresult*/ None,
        )?;
        let output: IWbemClassObject = output.context("WMI returned no process result")?;
        let mut result = VARIANT::new();
        output.Get(
            w!("ReturnValue"),
            /*lflags*/ 0,
            &mut result,
            /*ptype*/ None,
            /*plflavor*/ None,
        )?;
        let status = u32::try_from(&result)?;
        ensure!(
            status == 0,
            "WMI process creation failed with status {status}"
        );
        let mut result = VARIANT::new();
        output.Get(
            w!("ProcessId"),
            /*lflags*/ 0,
            &mut result,
            /*ptype*/ None,
            /*plflavor*/ None,
        )?;
        Ok(u32::try_from(&result)?)
    }
}

struct ComGuard;
impl Drop for ComGuard {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}
