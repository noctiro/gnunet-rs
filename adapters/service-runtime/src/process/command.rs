//! Shared GNUnet command grammar, independent of process creation.
use super::LaunchError;
use std::ffi::{OsStr, OsString};

/// Compose GNUnet command fragments around literal native arguments.
/// Only `prefix` and `options` use [`parse_command`]. The program and fixed
/// arguments retain their native characters, including spaces and backslashes.
/// `maximum_arguments` includes argv0; no shell or executable lookup occurs.
pub fn compose_arguments(
    prefix: &[u8],
    program: &OsStr,
    arguments: &[OsString],
    options: &[u8],
    maximum_arguments: usize,
) -> Result<Vec<OsString>, LaunchError> {
    let fragment = |bytes: &[u8]| {
        if bytes.iter().all(|byte| *byte == b' ') {
            Ok(Vec::new())
        } else {
            parse_command(bytes, maximum_arguments)
        }
    };
    let mut argv = fragment(prefix)?;
    let options = fragment(options)?;
    let extra = arguments
        .len()
        .checked_add(options.len())
        .and_then(|count| count.checked_add(1))
        .ok_or(LaunchError::Capacity)?;
    if argv
        .len()
        .checked_add(extra)
        .is_none_or(|count| count > maximum_arguments)
    {
        return Err(LaunchError::Capacity);
    }
    argv.try_reserve_exact(extra)
        .map_err(|_| LaunchError::Capacity)?;
    argv.push(program.to_owned());
    argv.extend_from_slice(arguments);
    argv.extend(options);
    Ok(argv)
}

/// Parse configured command text with double-quote groups and byte escapes.
/// Literal spaces delimit outside quotes; apostrophes/tabs remain ordinary data.
/// Quotes are removed, escaped bytes remain literal and empty quoted arguments
/// are retained. Unbalanced quotes and trailing escapes are invalid input.
/// The effective C string stops at its first NUL. Tokens retain native Unix
/// bytes or canonical Windows WTF-8 through the shared local string boundary;
/// malformed Windows encoding is an error, never replacement text.
/// This function never invokes a shell or executes a command.
pub fn parse_command(
    command: &[u8],
    maximum_arguments: usize,
) -> Result<Vec<OsString>, LaunchError> {
    let len = command
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(command.len());
    let mut scratch = Vec::new();
    scratch
        .try_reserve_exact(len)
        .map_err(|_| LaunchError::Capacity)?;
    scratch.extend_from_slice(&command[..len]);
    let mut result = Vec::new();
    let append = |result: &mut Vec<OsString>, bytes: &[u8]| -> Result<(), LaunchError> {
        if result.len() == maximum_arguments {
            return Err(LaunchError::Capacity);
        }
        if result.len() == result.capacity() {
            let capacity = result
                .capacity()
                .max(1)
                .saturating_mul(2)
                .min(maximum_arguments);
            result
                .try_reserve_exact(capacity - result.len())
                .map_err(|_| LaunchError::Capacity)?;
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| LaunchError::Capacity)?;
        owned.extend_from_slice(bytes);
        result.push(gnunet_native::os_bytes::decode_owned(owned)?);
        Ok(())
    };
    let (mut read, mut write, mut start) = (0, 0, 0);
    let (mut quoted, mut active) = (false, false);
    while read < len {
        let byte = scratch[read];
        read += 1;
        match byte {
            b'"' => {
                quoted = !quoted;
                active = true;
            }
            b'\\' => {
                let escaped = *scratch.get(read).ok_or(LaunchError::InvalidInput)?;
                read += 1;
                scratch[write] = escaped;
                write += 1;
                active = true;
            }
            b' ' if !quoted => {
                if active {
                    append(&mut result, &scratch[start..write])?;
                    start = write;
                    active = false;
                }
            }
            byte => {
                scratch[write] = byte;
                write += 1;
                active = true;
            }
        }
    }
    if quoted {
        return Err(LaunchError::InvalidInput);
    }
    if active {
        append(&mut result, &scratch[start..write])?;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(condition: bool, message: &'static str) -> Result<(), LaunchError> {
        if condition {
            Ok(())
        } else {
            Err(std::io::Error::other(message).into())
        }
    }

    #[test]
    fn source_grammar_keeps_literal_syntax_and_first_nul_boundary() -> Result<(), LaunchError> {
        check(
            parse_command(b"cmd arg\tone 'two' $X %PATH%\0ignored", 5)?
                == ["cmd", "arg\tone", "'two'", "$X", "%PATH%"].map(OsString::from),
            "literal syntax or first-NUL command boundary changed",
        )?;
        check(
            parse_command(b"cmd \"two three\" end", 3)?
                == ["cmd", "two three", "end"].map(OsString::from),
            "quoted spaces changed during command parsing",
        )?;
        check(
            matches!(parse_command(b"cmd arg", 1), Err(LaunchError::Capacity)),
            "argument capacity admitted a partial command",
        )?;
        Ok(())
    }

    #[test]
    fn quoted_final_arguments_and_native_path_escapes_are_lossless() -> Result<(), LaunchError> {
        check(
            parse_command(br#"cmd "two  three""#, 2)? == ["cmd", "two  three"].map(OsString::from),
            "final quoted argument retained stale source bytes",
        )?;
        check(
            parse_command(
                br#""C:\\Program Files\\GNUnet\\tool.exe" "final\\name" """#,
                3,
            )? == [r"C:\Program Files\GNUnet\tool.exe", r"final\name", ""].map(OsString::from),
            "native path escapes or explicit empty argument changed",
        )?;
        check(
            matches!(
                parse_command(br#"cmd "unterminated"#, 2),
                Err(LaunchError::InvalidInput)
            ) && matches!(
                parse_command(b"cmd dangling\\", 2),
                Err(LaunchError::InvalidInput)
            ),
            "malformed quoting or trailing escape admitted an altered command",
        )?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn unix_arguments_keep_non_unicode_bytes() -> Result<(), LaunchError> {
        let arguments = parse_command(b"cmd f\xff", 2)?;
        check(
            arguments.get(1).is_some_and(|argument| {
                gnunet_native::os_bytes::encode(argument).as_ref() == b"f\xff"
            }),
            "native Unix command bytes changed",
        )
    }

    #[cfg(windows)]
    #[test]
    fn windows_arguments_keep_surrogates_and_refuse_malformed_local_bytes()
    -> Result<(), LaunchError> {
        use std::os::windows::ffi::OsStringExt;
        let native = OsString::from_wide(&[b'f' as u16, 0xd800, b'o' as u16]);
        let mut command = b"cmd ".to_vec();
        command.extend_from_slice(&gnunet_native::os_bytes::encode(&native));
        check(
            parse_command(&command, 2)? == ["cmd".into(), native],
            "native Windows surrogate command units changed",
        )?;
        check(
            matches!(
                parse_command(b"cmd f\xff", 2),
                Err(LaunchError::Io(error)) if error.kind() == std::io::ErrorKind::InvalidData
            ),
            "malformed Windows command bytes became native arguments",
        )
    }
    #[test]
    fn composed_native_arguments_do_not_roundtrip_through_text() -> Result<(), LaunchError> {
        let program = OsStr::new("C:\\program files\\service.exe");
        let configuration = OsString::from("D:\\configuration files\\service.conf");
        let fixed = [OsString::from("-c"), configuration.clone()];
        check(
            compose_arguments(b"wrapper --mode", program, &fixed, b"--flag value", 7)?
                == [
                    "wrapper".into(),
                    "--mode".into(),
                    program.to_owned(),
                    "-c".into(),
                    configuration,
                    "--flag".into(),
                    "value".into(),
                ],
            "native path boundaries changed",
        )?;
        check(
            matches!(
                compose_arguments(b"", program, &fixed, b"", 2),
                Err(LaunchError::Capacity)
            ),
            "composed argument bound was exceeded",
        )
    }
}
