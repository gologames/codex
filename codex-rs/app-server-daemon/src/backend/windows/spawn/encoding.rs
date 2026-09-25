use std::ffi::OsStr;
use std::ffi::OsString;
use std::os::windows::ffi::OsStrExt;
use std::process::Command;

use anyhow::Result;
use anyhow::ensure;
use windows_sys::Win32::Globalization::CompareStringOrdinal;

pub(super) fn command_line(command: &Command) -> Result<Vec<u16>> {
    let mut line = Vec::new();
    for argument in std::iter::once(command.get_program()).chain(command.get_args()) {
        if !line.is_empty() {
            line.push(b' ' as u16);
        }
        append_quoted_arg(&mut line, argument)?;
    }
    ensure!(
        line.len() < 32767,
        "Windows command line exceeds 32767 UTF-16 units"
    );
    line.push(0);
    Ok(line)
}

fn append_quoted_arg(line: &mut Vec<u16>, argument: &OsStr) -> Result<()> {
    line.push(b'"' as u16);
    let mut slashes = 0;
    for unit in argument.encode_wide() {
        ensure!(unit != 0, "NUL in Windows command line");
        if unit == b'\\' as u16 {
            slashes += 1;
            continue;
        }
        let count = if unit == b'"' as u16 {
            slashes * 2 + 1
        } else {
            slashes
        };
        line.extend(std::iter::repeat_n(b'\\' as u16, count));
        line.push(unit);
        slashes = 0;
    }
    line.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
    line.push(b'"' as u16);
    Ok(())
}

// Does not support Command::env_clear(): always inherits the current environment.
pub(super) fn environment(command: &Command) -> Result<Vec<u16>> {
    let mut variables: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    for (name, value) in command.get_envs() {
        variables.retain(|(existing, _)| !compare_names(existing, name).is_eq());
        if let Some(value) = value {
            variables.push((name.to_owned(), value.to_owned()));
        }
    }
    variables.sort_by(|(left, _), (right, _)| compare_names(left, right));
    let mut block = Vec::new();
    for (name, value) in variables {
        let name = wide(&name)?;
        block.extend_from_slice(&name[..name.len() - 1]);
        block.push(b'=' as u16);
        block.extend(wide(&value)?);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

pub(super) fn wide(value: &OsStr) -> Result<Vec<u16>> {
    let mut encoded: Vec<_> = value.encode_wide().collect();
    ensure!(!encoded.contains(&0), "NUL in Windows launch parameter");
    encoded.push(0);
    Ok(encoded)
}

fn compare_names(left: &OsStr, right: &OsStr) -> std::cmp::Ordering {
    let left: Vec<_> = left.encode_wide().collect();
    let right: Vec<_> = right.encode_wide().collect();
    // Environment names fit in i32; neither side includes a terminating NUL.
    match unsafe {
        CompareStringOrdinal(
            left.as_ptr(),
            left.len() as i32,
            right.as_ptr(),
            right.len() as i32,
            /*bignorecase*/ 1,
        )
    } {
        1 => std::cmp::Ordering::Less,
        2 => std::cmp::Ordering::Equal,
        3 => std::cmp::Ordering::Greater,
        _ => left.cmp(&right),
    }
}

#[cfg(test)]
#[path = "encoding_tests.rs"]
mod tests;
