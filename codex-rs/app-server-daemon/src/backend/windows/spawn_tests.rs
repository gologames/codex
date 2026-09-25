use super::owned;
use super::spawn_with_parent;
use super::terminate_and_wait;
use pretty_assertions::assert_eq;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::OwnedHandle;
use std::process::Command;
use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;
use windows_sys::Win32::System::Threading::OpenProcess;
use windows_sys::Win32::System::Threading::PROCESS_CREATE_PROCESS;
use windows_sys::Win32::System::Threading::PROCESS_DUP_HANDLE;
use windows_sys::Win32::System::Threading::WaitForSingleObject;

const PAYLOAD: &str = "backend::windows::spawn::tests::native_launch_payload";
const OUTPUT_ENV: &str = "CODEX_TEST_NATIVE_LAUNCH_OUTPUT";

#[test]
fn launch_probe_can_be_terminated_and_reaped() {
    let parent = parent_process();
    let stderr = tempfile::tempfile().unwrap();
    let command = Command::new(std::env::current_exe().unwrap());
    let child = spawn_with_parent(&command, &stderr, &parent, CREATE_SUSPENDED).unwrap();
    terminate_and_wait(&child).unwrap();
    assert_eq!(
        unsafe {
            WaitForSingleObject(child.0.as_raw_handle() as _, /*dwmilliseconds*/ 0)
        },
        WAIT_OBJECT_0
    );
}

#[test]
fn running_process_keeps_environment_directory_and_stderr() {
    let parent = parent_process();
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("payload.txt");
    let mut stderr = tempfile::tempfile().unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", PAYLOAD, "--nocapture"])
        .env(OUTPUT_ENV, &output)
        .env("CODEX_TEST_NATIVE_LAUNCH_VALUE", "process-only override")
        .current_dir(directory.path());
    let child = spawn_with_parent(&command, &stderr, &parent, /*creation_flags*/ 0).unwrap();
    let observer = child.0.try_clone().unwrap();
    drop(child);
    drop(parent);
    std::fs::write(output.with_extension("release"), b"").unwrap();
    assert_eq!(
        unsafe {
            WaitForSingleObject(observer.as_raw_handle() as _, /*dwmilliseconds*/ 15000)
        },
        WAIT_OBJECT_0
    );
    assert_eq!(
        std::fs::read_to_string(&output).unwrap(),
        "process-only override"
    );
    stderr.seek(SeekFrom::Start(0)).unwrap();
    let mut log = String::new();
    stderr.read_to_string(&mut log).unwrap();
    assert!(log.contains("native-launch-stderr"));
}

fn parent_process() -> OwnedHandle {
    owned(unsafe {
        OpenProcess(
            PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE,
            /*binherithandle*/ 0,
            std::process::id(),
        )
    })
    .expect("open alternate parent")
}

#[test]
fn native_launch_payload() {
    let Some(output) = std::env::var_os(OUTPUT_ENV) else {
        return;
    };
    let output = std::path::PathBuf::from(output);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !output.with_extension("release").exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "launcher did not release payload"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(
        std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap(),
        std::fs::canonicalize(output.parent().unwrap()).unwrap()
    );
    let value = std::env::var("CODEX_TEST_NATIVE_LAUNCH_VALUE").unwrap();
    eprintln!("native-launch-stderr");
    std::fs::write(output, value).unwrap();
}
