mod pipe;
mod wmi;

use std::ffi::OsStr;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::OwnedHandle;
use std::process::Command;
use std::ptr;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use windows_sys::Win32::Foundation::ERROR_BROKEN_PIPE;
use windows_sys::Win32::Foundation::GENERIC_READ;
use windows_sys::Win32::Foundation::GENERIC_WRITE;
use windows_sys::Win32::Storage::FileSystem::CreateFileW;
use windows_sys::Win32::Storage::FileSystem::OPEN_EXISTING;
use windows_sys::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION;
use windows_sys::Win32::Storage::FileSystem::SECURITY_SQOS_PRESENT;
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Pipes::PeekNamedPipe;
use windows_sys::Win32::System::Threading::OpenProcess;
use windows_sys::Win32::System::Threading::PROCESS_CREATE_PROCESS;
use windows_sys::Win32::System::Threading::PROCESS_DUP_HANDLE;

use super::check;
use super::encoding;
use super::owned;

pub const CODEX_WINDOWS_SPAWN_PARENT_ARG1: &str = "--codex-daemon-launch-parent";

const PIPE_PREFIX: &str = r"\\.\pipe\codex-daemon-launch-parent-";
const SPAWN_PARENT_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) struct SpawnParent {
    pub(super) process: OwnedHandle,
    // Keep the pipe open until daemon creation finishes, including on failure.
    _pipe: OwnedHandle,
}

impl SpawnParent {
    pub(super) fn create() -> Result<Self> {
        let nonce: u128 = rand::random();
        let name = format!("{PIPE_PREFIX}{nonce:x}");
        let name_wide = encoding::wide(OsStr::new(&name))?;
        let pipe = pipe::create_private(&name_wide)?;
        let executable = std::fs::canonicalize(std::env::current_exe()?)?;
        let mut command = Command::new(&executable);
        command.args([CODEX_WINDOWS_SPAWN_PARENT_ARG1, &name]);
        let pid = wmi::start(encoding::command_line(&command)?)?;
        pipe::wait_for_connection(&pipe)?;
        let process = open_connected_parent(&pipe, pid)?;
        Ok(Self {
            process,
            _pipe: pipe,
        })
    }
}

pub fn run_windows_spawn_parent_main() -> ! {
    let exit_code = match run_spawn_parent() {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("Windows daemon launch parent failed: {error:#}");
            1
        }
    };
    std::process::exit(exit_code);
}

// Keep the temporary parent alive until the launcher closes the pipe
// or the timeout expires.
fn run_spawn_parent() -> Result<()> {
    let mut args = std::env::args_os().skip(2);
    let name = args.next().context("missing launch parent pipe")?;
    ensure!(args.next().is_none(), "unexpected launch parent arguments");
    ensure!(
        name.to_str()
            .is_some_and(|name| name.starts_with(PIPE_PREFIX)),
        "invalid launch parent pipe"
    );
    let name = encoding::wide(&name)?;
    // SECURITY_IDENTIFICATION lets the pipe server identify this process
    // without impersonating it.
    let pipe = owned(unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            /*dwsharemode*/ 0,
            ptr::null(),
            OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            /*htemplatefile*/ 0,
        )
    })
    .context("connect launch parent pipe")?;
    let handle = pipe.as_raw_handle() as isize;
    let deadline = Instant::now() + SPAWN_PARENT_TIMEOUT;
    while Instant::now() < deadline {
        if unsafe {
            PeekNamedPipe(
                handle,
                ptr::null_mut(),
                /*nbuffersize*/ 0,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                break;
            }
            return Err(error).context("wait for launch parent release");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

fn open_connected_parent(pipe: &OwnedHandle, pid: u32) -> Result<OwnedHandle> {
    let handle = pipe.as_raw_handle() as isize;
    let mut connected_pid = 0;
    check(
        unsafe { GetNamedPipeClientProcessId(handle, &mut connected_pid) },
        "query launch parent pipe peer",
    )?;
    ensure!(
        pid == connected_pid,
        "WMI launch parent and pipe peer identities differ"
    );
    let process = owned(unsafe {
        OpenProcess(
            PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE,
            /*binherithandle*/ 0,
            pid,
        )
    })
    .context("open connected launch parent")?;
    // Opening by PID must precede confirming that the original peer is still
    // connected, so a disconnect and PID reuse cannot substitute a process.
    check(
        unsafe {
            PeekNamedPipe(
                handle,
                ptr::null_mut(),
                /*nbuffersize*/ 0,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        },
        "launch parent disconnected before process identity was pinned",
    )?;
    Ok(process)
}
