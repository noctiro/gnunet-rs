//! Bounded UCRT output with checked real-year and explicit-zone expansion.
use super::{Calendar, Clock, civil};
use crate::{
    locale::LocaleSnapshot,
    windows_crt::{Errno, crt_error, errno},
};
use std::{
    ffi::{OsStr, OsString, c_void},
    io,
    os::windows::ffi::{OsStrExt, OsStringExt},
};
const MAX_UNITS: usize = 32767;
const MARKER: u16 = 1;
#[expect(
    unsafe_code,
    reason = "UCRT wchar_t calendar formatters receive bounded wide arrays and validated native fields"
)]
unsafe extern "C" {
    fn wcsftime(
        output: *mut u16,
        capacity: usize,
        format: *const u16,
        value: *const libc::tm,
    ) -> usize;
    fn _wcsftime_l(
        output: *mut u16,
        capacity: usize,
        format: *const u16,
        value: *const libc::tm,
        locale: *mut c_void,
    ) -> usize;
}
impl Calendar {
    /// Format with the current native thread locale. Capacity includes the final
    /// NUL and must be 1..=32768 UTF-16 units. Empty output is valid. Unsupported
    /// native format codes fail before calling CRT validation; no process-wide
    /// invalid-parameter handler is installed or suppressed.
    /// Numeric years cover the complete GNUnet microsecond domain. Localized
    /// `%c`/`%x` require a native formatting year in 1900..9999; unsupported
    /// composite years return an error rather than displaying a substitute year.
    pub fn format(&self, pattern: &OsStr, capacity: usize) -> io::Result<OsString> {
        self.format_selected(pattern, capacity, None)
    }
    /// Format under a retained explicit locale without installing it. All other
    /// buffer, format and zone contracts match `format`.
    pub fn format_in(
        &self,
        pattern: &OsStr,
        capacity: usize,
        locale: &LocaleSnapshot,
    ) -> io::Result<OsString> {
        self.format_selected(pattern, capacity, Some(locale))
    }
    fn format_selected(
        &self,
        pattern: &OsStr,
        capacity: usize,
        locale: Option<&LocaleSnapshot>,
    ) -> io::Result<OsString> {
        if !(1..=MAX_UNITS + 1).contains(&capacity) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let pattern = prepare_format(pattern, self)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(capacity + 1)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        output.resize(capacity + 1, 0_u16);
        let _errno = Errno::clear();
        #[expect(
            unsafe_code,
            reason = "Native conversion produced a valid tm, the format vocabulary is validated, wide buffers are live/bounded, and any explicit locale stays borrowed through its synchronous read"
        )]
        // SAFETY: the extra leading literal makes successful empty expansions
        // distinguishable from the native zero return on insufficient storage.
        let count = unsafe {
            match locale {
                None => wcsftime(
                    output.as_mut_ptr(),
                    output.len(),
                    pattern.as_ptr(),
                    &self.value,
                ),
                Some(locale) => _wcsftime_l(
                    output.as_mut_ptr(),
                    output.len(),
                    pattern.as_ptr(),
                    &self.value,
                    locale.as_raw(),
                ),
            }
        };
        if count == 0 {
            return Err(if errno() != 0 {
                crt_error("wcsftime")
            } else {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "native calendar output exceeds supplied capacity",
                )
            });
        }
        if count >= output.len() || output[0] != MARKER || output[count] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid native calendar output extent",
            ));
        }
        Ok(OsString::from_wide(&output[1..count]))
    }
}

fn reserve(output: &mut Vec<u16>, units: usize) -> io::Result<()> {
    if output.len().saturating_add(units) > MAX_UNITS + 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native calendar format exceeds UTF-16 bound",
        ));
    }
    output
        .try_reserve(units)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    Ok(())
}
fn append(output: &mut Vec<u16>, units: &[u16]) -> io::Result<()> {
    reserve(output, units.len())?;
    output.extend_from_slice(units);
    Ok(())
}
fn append_text(output: &mut Vec<u16>, text: &str) -> io::Result<()> {
    reserve(output, text.encode_utf16().count())?;
    output.extend(text.encode_utf16());
    Ok(())
}
fn prepare_format(pattern: &OsStr, calendar: &Calendar) -> io::Result<Vec<u16>> {
    let mut output = Vec::new();
    append(&mut output, &[MARKER])?;
    let mut input = pattern.encode_wide();
    while let Some(unit) = input.next() {
        if unit == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if unit != u16::from(b'%') {
            append(&mut output, &[unit])?;
            continue;
        }
        let mut code = input.next().ok_or(io::ErrorKind::InvalidInput)?;
        let hash = code == u16::from(b'#');
        if hash {
            code = input.next().ok_or(io::ErrorKind::InvalidInput)?;
        }
        if code > 127 || !b"aAbBcCdDeFgGhHIjmMnprRStTuUVwWxXyYzZ%".contains(&(code as u8)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid native calendar format code",
            ));
        }
        if let Some(number) = calendar.civil.numeric(code as u8, hash) {
            append_text(&mut output, &number)?;
        } else if code == u16::from(b'F') {
            let year = calendar
                .civil
                .numeric(b'Y', hash)
                .ok_or_else(civil::invalid)?;
            append_text(&mut output, &year)?;
            append(
                &mut output,
                if hash {
                    &[
                        '-' as u16, '%' as u16, '#' as u16, 'm' as u16, '-' as u16, '%' as u16,
                        '#' as u16, 'd' as u16,
                    ]
                } else {
                    &[
                        '-' as u16, '%' as u16, 'm' as u16, '-' as u16, '%' as u16, 'd' as u16,
                    ]
                },
            )?;
        } else if code == u16::from(b'z') && !matches!(calendar.clock, Clock::Native) {
            let offset = match &calendar.clock {
                Clock::Extended { offset, .. } => *offset,
                _ => 0,
            };
            let minutes = offset.unsigned_abs() / 60;
            let text = format!(
                "{}{:02}{:02}",
                if offset < 0 { '-' } else { '+' },
                minutes / 60,
                minutes % 60
            );
            append_text(&mut output, &text)?;
        } else if code == u16::from(b'Z') && !matches!(calendar.clock, Clock::Native) {
            let name = match &calendar.clock {
                Clock::Extended { name, .. } => name.as_slice(),
                _ => &[85, 84, 67],
            };
            for unit in name {
                append(&mut output, &[*unit])?;
                if *unit == u16::from(b'%') {
                    append(&mut output, &[*unit])?;
                }
            }
        } else if matches!(code as u8, b'c' | b'x')
            && calendar.value.tm_year + 1900 != calendar.civil.year
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "localized composite calendar exceeds the native formatter's year range",
            ));
        } else {
            append(&mut output, &[u16::from(b'%')])?;
            if hash {
                append(&mut output, &[u16::from(b'#')])?;
            }
            append(&mut output, &[code])?;
        }
    }
    output
        .try_reserve(1)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    output.push(0);
    Ok(output)
}
