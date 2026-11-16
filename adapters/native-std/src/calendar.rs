//! Checked Gregorian conversion, Windows timezone rules and bounded native formatting.
mod civil;
mod format;
mod parse;
mod rules;
mod timezone;
use crate::windows_crt::{Errno, crt_error_code};
use civil::Civil;
pub use parse::{AutomationDateError, DateParser};
use std::{ffi::c_int, io, mem::MaybeUninit};

#[expect(
    unsafe_code,
    reason = "UCRT time.h declares this reentrant explicitly 64-bit local-time conversion"
)]
unsafe extern "C" {
    fn _localtime64_s(output: *mut libc::tm, seconds: *const i64) -> c_int;
}

/// Native calendar selection; UTC formatting does not consult local zone fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Zone {
    /// UTC conversion and explicit UTC zone name/offset.
    Utc,
    /// Local conversion with native TZ/system-zone rules and checked range extension.
    Local,
}
/// Checked Gregorian fields and an initialized UCRT formatting view.
/// Native failures preserve their original CRT or Win32 error domain. This does
/// not change system time, process locale, TZ or a global error handler.
pub struct Calendar {
    value: libc::tm,
    civil: Civil,
    clock: Clock,
}
#[derive(Debug)]
enum Clock {
    Utc,
    Native,
    Extended { offset: i32, name: Vec<u16> },
}
impl std::fmt::Debug for Calendar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Calendar")
            .field("civil", &self.civil)
            .field("clock", &self.clock)
            .finish()
    }
}
impl Calendar {
    /// Convert signed Unix seconds without UCRT's epoch-range restriction.
    /// UTC uses checked Gregorian arithmetic. Local time retains the UCRT fast
    /// path, then uses Windows dynamic-year rules or an explicit Microsoft TZ
    /// selection outside its native range. No timestamp is narrowed or clamped.
    ///
    /// # Errors
    /// Rejects epochs outside signed 32-bit Gregorian years, which exceed the
    /// complete GNUnet microsecond domain. Preserves native timezone/CRT errors
    /// and refuses invalid or unsupported explicit timezone specifications.
    #[expect(
        unsafe_code,
        reason = "Reentrant UCRT conversion receives live i64 time input and exclusively writable aligned tm storage; range errors do not invoke its invalid-parameter handler"
    )]
    pub fn from_epoch(seconds: i64, zone: Zone) -> io::Result<Self> {
        if zone == Zone::Utc {
            return Ok(Self::civil(Civil::from_epoch(seconds)?, Clock::Utc));
        }
        let _errno = Errno::clear();
        let mut value = MaybeUninit::uninit();
        // SAFETY: these explicitly 64-bit APIs do not depend on time_t's target
        // width. Both pointers are nonnull; only success initializes the output.
        let status = unsafe { _localtime64_s(value.as_mut_ptr(), &seconds) };
        if status != 0 {
            if status != libc::EINVAL {
                return Err(crt_error_code("_localtime64_s", status));
            }
            let result = timezone::Source::capture()?.at_utc(seconds)?;
            return Ok(Self::civil(
                result.local.civil,
                Clock::Extended {
                    offset: result.local.offset,
                    name: result.name,
                },
            ));
        }
        // SAFETY: successful native conversion initialized all nine integer fields.
        let value = unsafe { value.assume_init() };
        let civil = Civil::new(
            value.tm_year.checked_add(1900).ok_or_else(civil::invalid)?,
            (value.tm_mon + 1) as u8,
            value.tm_mday as u8,
            value.tm_hour as u8,
            value.tm_min as u8,
            value.tm_sec as u8,
        )?;
        Ok(Self {
            value,
            civil,
            clock: Clock::Native,
        })
    }
    fn civil(civil: Civil, clock: Clock) -> Self {
        // UCRT formatting never receives an invalid year. The equivalent
        // Gregorian cycle preserves month names, weekday and leap-day fields;
        // actual year/week-year fields are expanded before entering the CRT.
        let year = if (1900..=9999).contains(&civil.year) {
            civil.year
        } else {
            2400 + civil.year.rem_euclid(400)
        };
        let value = libc::tm {
            tm_year: year - 1900,
            tm_mon: i32::from(civil.month) - 1,
            tm_mday: i32::from(civil.day),
            tm_hour: i32::from(civil.hour),
            tm_min: i32::from(civil.minute),
            tm_sec: i32::from(civil.second),
            tm_wday: i32::from(civil.weekday),
            tm_yday: i32::from(civil.ordinal),
            tm_isdst: 0,
        };
        Self {
            value,
            civil,
            clock,
        }
    }
}
