use super::command_line;
use super::environment;
use super::wide;
use pretty_assertions::assert_eq;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::ffi::OsStringExt;
use std::process::Command;

#[test]
fn arguments_preserve_empty_values_quotes_and_trailing_slashes() {
    let mut command = Command::new(r"C:\path with spaces\codex.exe");
    command.args(["", "a b", "a\"b", "x\\", "x\\\"y"]);
    let expected = concat!(
        "\"C:\\path with spaces\\codex.exe\"",
        " \"\" \"a b\" \"a\\\"b\" \"x\\\\\" \"x\\\\\\\"y\"\0",
    );
    assert_eq!(
        command_line(&command).unwrap(),
        expected.encode_utf16().collect::<Vec<_>>()
    );
}

#[test]
fn windows_strings_keep_unpaired_surrogates() {
    let value = OsString::from_wide(&[0xD800, b'x' as u16]);
    assert_eq!(wide(&value).unwrap(), vec![0xD800, b'x' as u16, 0]);
    let mut command = Command::new("codex.exe");
    command.arg(&value);
    let mut expected: Vec<_> = "\"codex.exe\" \"".encode_utf16().collect();
    expected.extend([0xD800, b'x' as u16, b'"' as u16, 0]);
    assert_eq!(command_line(&command).unwrap(), expected);
}

#[test]
fn embedded_nul_and_overlong_command_lines_are_rejected() {
    assert!(wide(OsStr::new("a\0b")).is_err());
    let mut command = Command::new("codex.exe");
    command.arg("a\0b");
    assert!(command_line(&command).is_err());
    let mut command = Command::new("codex.exe");
    command.arg("x".repeat(32767));
    assert!(command_line(&command).is_err());
}

#[test]
fn environment_overrides_are_case_insensitive_and_lossless() {
    let value = OsString::from_wide(&[b'x' as u16, 0xD800]);
    let mut command = Command::new("codex.exe");
    command.env("PATH", "first").env("Path", &value);
    let block = environment(&command).unwrap();
    assert_eq!(&block[block.len() - 2..], &[0, 0]);
    let paths: Vec<_> = block
        .split(|unit| *unit == 0)
        .filter(|entry| {
            entry.len() >= 5 && String::from_utf16_lossy(&entry[..5]).eq_ignore_ascii_case("path=")
        })
        .map(|entry| entry[5..].to_vec())
        .collect();
    assert_eq!(paths, vec![value.encode_wide().collect::<Vec<_>>()]);
    command.env_remove("pAtH");
    let block = environment(&command).unwrap();
    assert!(!block.split(|unit| *unit == 0).any(|entry| {
        entry.len() >= 5 && String::from_utf16_lossy(&entry[..5]).eq_ignore_ascii_case("path=")
    }));
}
