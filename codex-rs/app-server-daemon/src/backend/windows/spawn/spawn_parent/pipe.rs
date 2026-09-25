use std::ffi::OsStr;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::OwnedHandle;
use std::ptr;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED;
use windows_sys::Win32::Foundation::ERROR_PIPE_LISTENING;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::Authorization::SDDL_REVISION_1;
use windows_sys::Win32::Security::GetTokenInformation;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Security::TOKEN_QUERY;
use windows_sys::Win32::Security::TOKEN_USER;
use windows_sys::Win32::Security::TokenUser;
use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_FIRST_PIPE_INSTANCE;
use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
use windows_sys::Win32::System::Pipes::ConnectNamedPipe;
use windows_sys::Win32::System::Pipes::CreateNamedPipeW;
use windows_sys::Win32::System::Pipes::PIPE_NOWAIT;
use windows_sys::Win32::System::Pipes::PIPE_REJECT_REMOTE_CLIENTS;
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::Win32::System::Threading::OpenProcessToken;

use super::SPAWN_PARENT_TIMEOUT;
use super::check;
use super::encoding;
use super::owned;

pub(super) fn create_private(name: &[u16]) -> Result<OwnedHandle> {
    let sid = current_user_sid()?;
    let descriptor_text = encoding::wide(OsStr::new(&format!("D:P(A;;GA;;;{sid})")))?;
    let mut descriptor = ptr::null_mut();
    check(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                descriptor_text.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        },
        "create pipe DACL",
    )?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let result = owned(unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            /*nmaxinstances*/ 1,
            /*noutbuffersize*/ 64,
            /*ninbuffersize*/ 64,
            /*ndefaulttimeout*/ 0,
            &attributes,
        )
    });
    unsafe { LocalFree(descriptor as _) };
    result.context("create private launch parent pipe")
}

pub(super) fn wait_for_connection(pipe: &OwnedHandle) -> Result<()> {
    let deadline = Instant::now() + SPAWN_PARENT_TIMEOUT;
    let handle = pipe.as_raw_handle() as isize;
    loop {
        // NOWAIT may report successful listening before a client connects.
        if unsafe { ConnectNamedPipe(handle, ptr::null_mut()) } == 0 {
            let error = io::Error::last_os_error();
            match error.raw_os_error().map(|code| code as u32) {
                Some(ERROR_PIPE_CONNECTED) => return Ok(()),
                Some(ERROR_PIPE_LISTENING) => {}
                _ => return Err(error).context("connect private launch parent pipe"),
            }
        }
        ensure!(
            Instant::now() < deadline,
            "launch parent connection timed out"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn current_user_sid() -> Result<String> {
    let mut token = 0;
    check(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) },
        "query pipe owner",
    )?;
    let token = owned(token)?;
    let mut length = 0;
    unsafe {
        GetTokenInformation(
            token.as_raw_handle() as _,
            TokenUser,
            ptr::null_mut(),
            /*tokeninformationlength*/ 0,
            &mut length,
        )
    };
    ensure!(
        length as usize >= std::mem::size_of::<TOKEN_USER>(),
        "invalid pipe owner token size"
    );
    let mut user = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
    check(
        unsafe {
            GetTokenInformation(
                token.as_raw_handle() as _,
                TokenUser,
                user.as_mut_ptr().cast(),
                length,
                &mut length,
            )
        },
        "read pipe owner",
    )?;
    let sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let mut text = ptr::null_mut();
    check(
        unsafe { ConvertSidToStringSidW(sid, &mut text) },
        "format pipe owner",
    )?;
    let mut length = 0;
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    let sid = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
    unsafe { LocalFree(text as _) };
    Ok(sid)
}
