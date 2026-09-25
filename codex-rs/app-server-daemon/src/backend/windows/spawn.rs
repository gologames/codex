//! Windows daemon launch with a WMI-parent fallback.
mod encoding;
mod spawn_parent;

use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::OwnedHandle;
use std::process::Command;
use std::ptr;

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use windows_sys::Win32::Foundation::DUPLICATE_CLOSE_SOURCE;
use windows_sys::Win32::Foundation::DUPLICATE_SAME_ACCESS;
use windows_sys::Win32::Foundation::DuplicateHandle;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
use windows_sys::Win32::Security::TOKEN_ASSIGN_PRIMARY;
use windows_sys::Win32::Security::TOKEN_DUPLICATE;
use windows_sys::Win32::Security::TOKEN_QUERY;
use windows_sys::Win32::System::JobObjects::IsProcessInJob;
use windows_sys::Win32::System::Threading::CREATE_UNICODE_ENVIRONMENT;
use windows_sys::Win32::System::Threading::CreateProcessAsUserW;
use windows_sys::Win32::System::Threading::DETACHED_PROCESS;
use windows_sys::Win32::System::Threading::DeleteProcThreadAttributeList;
use windows_sys::Win32::System::Threading::EXTENDED_STARTUPINFO_PRESENT;
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::Win32::System::Threading::InitializeProcThreadAttributeList;
use windows_sys::Win32::System::Threading::OpenProcessToken;
use windows_sys::Win32::System::Threading::PROC_THREAD_ATTRIBUTE_HANDLE_LIST;
use windows_sys::Win32::System::Threading::PROC_THREAD_ATTRIBUTE_PARENT_PROCESS;
use windows_sys::Win32::System::Threading::PROCESS_INFORMATION;
use windows_sys::Win32::System::Threading::STARTF_USESHOWWINDOW;
use windows_sys::Win32::System::Threading::STARTF_USESTDHANDLES;
use windows_sys::Win32::System::Threading::STARTUPINFOEXW;
use windows_sys::Win32::System::Threading::UpdateProcThreadAttribute;
use windows_sys::Win32::System::Threading::WaitForSingleObject;

use super::Process;

pub use spawn_parent::CODEX_WINDOWS_SPAWN_PARENT_ARG1;
pub use spawn_parent::run_windows_spawn_parent_main;

pub(in crate::backend) async fn ensure_detached_with_fallback(
    child: std::process::Child,
    command: tokio::process::Command,
    stderr: File,
) -> Result<Process> {
    tokio::task::spawn_blocking(move || {
        ensure_detached_with_fallback_blocking(
            Process(child.into()),
            command.as_std(),
            &stderr,
            /*creation_flags*/ 0,
        )
    })
    .await
    .context("Windows daemon launch worker failed")?
}

pub(super) fn ensure_detached_with_fallback_blocking(
    child: Process,
    command: &Command,
    stderr: &File,
    creation_flags: u32,
) -> Result<Process> {
    let mut in_job = 0;
    let result = check(
        unsafe {
            IsProcessInJob(
                child.0.as_raw_handle() as _,
                /*jobhandle*/ 0,
                &mut in_job,
            )
        },
        "inspect daemon Job",
    );
    if result.is_err() || in_job != 0 {
        terminate_and_wait(&child)?;
        result?;
    } else {
        return Ok(child);
    }
    let spawn_parent = spawn_parent::SpawnParent::create()
        .context("cannot establish independent daemon parent")?;
    spawn_with_parent(command, stderr, &spawn_parent.process, creation_flags)
        .context("cannot create daemon with original token and independent parent")
}

fn spawn_with_parent(
    command: &Command,
    stderr: &File,
    spawn_parent: &OwnedHandle,
    creation_flags: u32,
) -> Result<Process> {
    let application = encoding::wide(command.get_program())?;
    let mut command_line = encoding::command_line(command)?;
    let environment = encoding::environment(command)?;
    let cwd = command
        .get_current_dir()
        .map(|path| encoding::wide(path.as_os_str()))
        .transpose()?;
    let parent = spawn_parent.as_raw_handle() as _;
    let mut handles = SpawnParentHandles {
        parent,
        handles: Vec::new(),
    };
    let nul = File::options().read(true).write(true).open("NUL")?;
    // The daemon inherits stdio handles from the selected parent.
    // Duplicate them into that process before creating the daemon.
    let input = handles.duplicate_into_parent(&nul)?;
    let error = handles.duplicate_into_parent(stderr)?;
    let handle_list = [input, error];
    let mut attributes = ProcessCreationAttributes::new(/*count*/ 2)?;
    let list = attributes.storage.as_mut_ptr().cast();
    check(
        unsafe {
            UpdateProcThreadAttribute(
                list,
                /*dwflags*/ 0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handle_list.as_ptr().cast(),
                std::mem::size_of_val(&handle_list),
                ptr::null_mut(),
                ptr::null(),
            )
        },
        "set daemon handle allowlist",
    )?;
    check(
        unsafe {
            UpdateProcThreadAttribute(
                list,
                /*dwflags*/ 0,
                PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
                (&parent as *const HANDLE).cast(),
                std::mem::size_of::<HANDLE>(),
                ptr::null_mut(),
                ptr::null(),
            )
        },
        "set independent daemon parent",
    )?;
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup.StartupInfo.hStdInput = input;
    startup.StartupInfo.hStdOutput = input;
    startup.StartupInfo.hStdError = error;
    startup.lpAttributeList = list;
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let flags = creation_flags
        | DETACHED_PROCESS
        | EXTENDED_STARTUPINFO_PRESENT
        | CREATE_UNICODE_ENVIRONMENT;
    let cwd = cwd.as_ref().map_or(ptr::null(), Vec::as_ptr);
    let mut token = 0;
    let access = TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY;
    check(
        unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut token) },
        "open daemon caller token",
    )?;
    let token = owned(token)?;
    check(
        unsafe {
            CreateProcessAsUserW(
                token.as_raw_handle() as _,
                application.as_ptr(),
                command_line.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                /*binherithandles*/ 1,
                flags,
                environment.as_ptr().cast(),
                cwd,
                &startup.StartupInfo,
                &mut info,
            )
        },
        "CreateProcessAsUserW daemon",
    )?;
    // Successful CreateProcess always returns both owned handles.
    let process = Process(unsafe { OwnedHandle::from_raw_handle(info.hProcess as _) });
    drop(unsafe { OwnedHandle::from_raw_handle(info.hThread as _) });
    Ok(process)
}

fn check(result: i32, operation: &str) -> Result<()> {
    if result == 0 {
        return Err(io::Error::last_os_error()).with_context(|| operation.to_owned());
    }
    Ok(())
}

fn owned(handle: HANDLE) -> io::Result<OwnedHandle> {
    if handle == 0 || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as _) })
}

pub(super) fn terminate_and_wait(process: &Process) -> Result<()> {
    process.terminate()?;
    ensure!(
        unsafe {
            WaitForSingleObject(process.0.as_raw_handle() as _, /*dwmilliseconds*/ 5000)
        } == WAIT_OBJECT_0,
        "daemon launch process did not exit"
    );
    Ok(())
}

struct SpawnParentHandles {
    parent: HANDLE,
    handles: Vec<HANDLE>,
}
impl SpawnParentHandles {
    fn duplicate_into_parent(&mut self, file: &File) -> Result<HANDLE> {
        let mut remote = 0;
        check(
            unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    file.as_raw_handle() as _,
                    self.parent,
                    &mut remote,
                    /*dwdesiredaccess*/ 0,
                    /*binherithandle*/ 1,
                    DUPLICATE_SAME_ACCESS,
                )
            },
            "duplicate daemon stdio into parent",
        )?;
        self.handles.push(remote);
        Ok(remote)
    }
}
impl Drop for SpawnParentHandles {
    fn drop(&mut self) {
        for handle in &self.handles {
            unsafe {
                DuplicateHandle(
                    self.parent,
                    *handle,
                    /*htargetprocesshandle*/ 0,
                    ptr::null_mut(),
                    /*dwdesiredaccess*/ 0,
                    /*binherithandle*/ 0,
                    DUPLICATE_CLOSE_SOURCE,
                );
            }
        }
    }
}

struct ProcessCreationAttributes {
    storage: Vec<usize>,
}
impl ProcessCreationAttributes {
    fn new(count: u32) -> Result<Self> {
        let mut bytes = 0;
        unsafe {
            InitializeProcThreadAttributeList(
                ptr::null_mut(),
                count,
                /*dwflags*/ 0,
                &mut bytes,
            )
        };
        ensure!(bytes != 0, "invalid startup attribute size");
        let mut storage = vec![0usize; bytes.div_ceil(std::mem::size_of::<usize>())];
        check(
            unsafe {
                InitializeProcThreadAttributeList(
                    storage.as_mut_ptr().cast(),
                    count,
                    /*dwflags*/ 0,
                    &mut bytes,
                )
            },
            "initialize daemon startup attributes",
        )?;
        Ok(Self { storage })
    }
}
impl Drop for ProcessCreationAttributes {
    fn drop(&mut self) {
        unsafe { DeleteProcThreadAttributeList(self.storage.as_mut_ptr().cast()) };
    }
}

#[cfg(test)]
#[path = "spawn_tests.rs"]
mod tests;
