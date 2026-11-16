//! Read-only Windows Internet database location with bounded native wide strings.
use super::{encoding::MAX_PATH_UNITS, system_directory};
use std::{ffi::OsString, io, os::windows::ffi::OsStringExt, path::PathBuf};
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS},
    System::{
        Environment::ExpandEnvironmentStringsW,
        Registry::{
            HKEY_LOCAL_MACHINE, REG_EXPAND_SZ, REG_SZ, RRF_NOEXPAND, RRF_RT_REG_EXPAND_SZ,
            RRF_RT_REG_SZ, RRF_ZEROONFAILURE, RegGetValueW,
        },
    },
};

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn resize(buffer: &mut Vec<u16>, units: usize) -> io::Result<()> {
    if !(1..=MAX_PATH_UNITS + 1).contains(&units) {
        return Err(invalid(
            "Internet database path exceeds native path capacity",
        ));
    }
    buffer
        .try_reserve_exact(units.saturating_sub(buffer.len()))
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    buffer.resize(units, 0);
    Ok(())
}
fn terminated(buffer: &[u16], units: usize) -> io::Result<&[u16]> {
    let text = buffer
        .get(..units)
        .ok_or_else(|| invalid("native database path exceeds output storage"))?;
    if text.len() < 2 || text.last() != Some(&0) || text[..text.len() - 1].contains(&0) {
        return Err(invalid(
            "native database path must be one nonempty wide string",
        ));
    }
    Ok(&text[..text.len() - 1])
}
// The callback borrows initialized storage only for one synchronous query. The
// byte count is interpreted only after a successful status, never after a short
// output or a registry race.
fn read_value(
    mut query: impl FnMut(&mut [u16], &mut u32, &mut u32) -> u32,
) -> io::Result<Option<(Vec<u16>, u32)>> {
    let mut buffer = Vec::new();
    let mut capacity = 260;
    for _ in 0..3 {
        resize(&mut buffer, capacity)?;
        let mut bytes = (buffer.len() * size_of::<u16>()) as u32;
        let mut kind = 0;
        match query(&mut buffer, &mut bytes, &mut kind) {
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => return Ok(None),
            ERROR_MORE_DATA => {
                capacity = (bytes as usize)
                    .div_ceil(size_of::<u16>())
                    .max(capacity + 1);
            }
            ERROR_SUCCESS => {
                if !matches!(kind, REG_SZ | REG_EXPAND_SZ) || !bytes.is_multiple_of(2) {
                    return Err(invalid(
                        "invalid Internet database registry value type or extent",
                    ));
                }
                let units = bytes as usize / size_of::<u16>();
                terminated(&buffer, units)?;
                buffer.truncate(units);
                return Ok(Some((buffer, kind)));
            }
            code => return Err(io::Error::from_raw_os_error(code as i32)),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::Interrupted,
        "Internet database registry value changed during bounded query",
    ))
}
#[expect(
    unsafe_code,
    reason = "The synchronous Win32 expansion borrows a validated terminated input and initialized bounded output; its count is checked before copying"
)]
fn expand(input: &[u16]) -> io::Result<Vec<u16>> {
    let mut buffer = Vec::new();
    let mut capacity = input.len();
    for _ in 0..3 {
        resize(&mut buffer, capacity)?;
        // SAFETY: read_value validated input's complete terminating NUL; output
        // is a separate initialized allocation with the supplied WCHAR capacity.
        let units = unsafe {
            ExpandEnvironmentStringsW(input.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32)
        } as usize;
        if units == 0 {
            return Err(io::Error::last_os_error());
        }
        if units <= buffer.len() {
            terminated(&buffer, units)?;
            buffer.truncate(units);
            return Ok(buffer);
        }
        capacity = units;
    }
    Err(io::Error::new(
        io::ErrorKind::Interrupted,
        "Internet database environment expansion changed during bounded query",
    ))
}

/// Observe the configured directory for hosts, protocol and services files.
/// Reads HKLM's `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DatabasePath`
/// with RegGetValueW. REG_EXPAND_SZ uses native environment expansion; REG_SZ
/// stays literal. Only an absent key/value selects the native system directory's
/// `drivers/etc` default. The result preserves native UTF-16, including unpaired
/// surrogates. It is a path observation, not an open directory or permission.
///
/// # Errors
/// Preserves registry/expansion/system-directory failures. Wrong types, empty,
/// relative or malformed strings, overflow and repeated query races fail rather
/// than silently substituting another database. At most 32768 UTF-16 units are
/// admitted, including the terminator; each native query has three attempts.
#[expect(
    unsafe_code,
    reason = "RegGetValueW receives static terminated names and one initialized bounded UTF-16 output; returned status/type/extent are validated before use"
)]
pub fn internet_database_directory() -> io::Result<PathBuf> {
    let value = read_value(|buffer, bytes, kind| {
        // SAFETY: predefined HKLM and static UTF-16 names remain valid; the
        // callback supplies initialized storage with its exact byte extent.
        unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                windows_sys::w!("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"),
                windows_sys::w!("DatabasePath"),
                RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND | RRF_ZEROONFAILURE,
                kind,
                buffer.as_mut_ptr().cast(),
                bytes,
            )
        }
    })?;
    let Some((mut buffer, kind)) = value else {
        return Ok(system_directory()?.join("drivers").join("etc"));
    };
    if kind == REG_EXPAND_SZ {
        buffer = expand(&buffer)?;
    }
    let path = PathBuf::from(OsString::from_wide(terminated(&buffer, buffer.len())?));
    if !path.is_absolute() {
        return Err(invalid("Internet database directory must be absolute"));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions qualify bounded native-string transfer and refusal behavior"
    )]
    fn registry_growth_keeps_native_units_and_rejects_invalid_success_extents() -> io::Result<()> {
        let mut calls = 0;
        let value = read_value(|buffer, bytes, kind| {
            calls += 1;
            if calls == 1 {
                *bytes = 1024;
                return ERROR_MORE_DATA;
            }
            buffer[..5].copy_from_slice(&[67, 58, 92, 0xd800, 0]);
            *bytes = 10;
            *kind = REG_SZ;
            ERROR_SUCCESS
        })?
        .ok_or_else(|| invalid("original registry value disappeared"))?;
        assert_eq!(value.0, [67, 58, 92, 0xd800, 0]);
        assert_eq!(calls, 2);
        for bytes in [0, 1, 2, 3, 4096] {
            assert!(
                read_value(|_, length, kind| {
                    *length = bytes;
                    *kind = REG_SZ;
                    ERROR_SUCCESS
                })
                .is_err(),
                "invalid successful extent {bytes}"
            );
        }
        Ok(())
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions distinguish absence from original query and resource failures"
    )]
    fn absent_value_is_distinct_from_native_error_and_unbounded_growth() -> io::Result<()> {
        assert!(read_value(|_, _, _| ERROR_FILE_NOT_FOUND)?.is_none());
        let denied = read_value(|_, _, _| 5)
            .err()
            .ok_or_else(|| invalid("access error was hidden"))?;
        assert_eq!(denied.raw_os_error(), Some(5));
        assert!(
            read_value(|_, bytes, _| {
                *bytes = u32::MAX;
                ERROR_MORE_DATA
            })
            .is_err()
        );
        Ok(())
    }
}
