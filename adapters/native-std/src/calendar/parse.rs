//! Native Windows absolute dates with retained locale and original error domains.
use super::{
    Calendar, Zone,
    civil::{self, Civil},
    timezone,
};
use crate::locale::nls;
use crate::{
    calendar_fields::{self, Cursor, Date, Fields, Time},
    locale::LocaleSnapshot,
    windows_crt::{Errno, crt_error},
};
use std::{
    ffi::{OsStr, c_int},
    fmt, io,
    os::windows::ffi::OsStrExt,
    sync::{Arc, OnceLock},
};
use windows_sys::Win32::{
    Foundation::{E_OUTOFMEMORY, ERROR_SUCCESS, GetLastError, SYSTEMTIME, SetLastError},
    Globalization::{FIND_STARTSWITH, FindNLSStringEx, NORM_IGNORECASE},
    System::{Ole::VarDateFromStr, Variant::VariantTimeToSystemTime},
};
const MAX_INPUT_UNITS: usize = 32767;
const NAME_CAPACITY: usize = 256;
mod named;
#[expect(
    unsafe_code,
    reason = "UCRT time.h declares this explicitly 64-bit local-time conversion; no platform time_t alias is used"
)]
unsafe extern "C" {
    fn _mktime64(value: *mut libc::tm) -> i64;
}

/// Original OLE Automation date-conversion status, distinct from Win32 and CRT errors.
#[derive(Debug)]
pub struct AutomationDateError {
    status: i32,
}
impl AutomationDateError {
    /// Original HRESULT returned by VarDateFromStr.
    #[must_use]
    pub const fn status(&self) -> i32 {
        self.status
    }
}
impl fmt::Display for AutomationDateError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            output,
            "VarDateFromStr failed (HRESULT {:#010x})",
            self.status as u32
        )
    }
}
impl std::error::Error for AutomationDateError {}

/// A retained LC_TIME parser; later thread-locale selection cannot change its names.
/// ISO dates use Gregorian fields and omitted month/day mean January/first day.
/// Local conversion observes the UCRT timezone policy when parsing, including DST.
/// Supplemental NLS picture/name data is shared after the first successful load.
/// It does not set locale, TZ, system time or native validation handlers.
#[derive(Clone)]
pub struct DateParser {
    locale: LocaleSnapshot,
    name: nls::Name,
    named: Arc<OnceLock<named::Formats>>,
}
impl fmt::Debug for DateParser {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.debug_struct("DateParser").finish_non_exhaustive()
    }
}
impl DateParser {
    /// Retain the current UCRT locale and resolve its LC_TIME name through NLS.
    ///
    /// # Errors
    /// Returns original CRT/NLS errors, allocation failure, or an unresolvable
    /// native locale name. No fallback to another language is performed.
    ///
    /// # Safety
    /// Exclude concurrent UCRT locale mutation until capture returns. External
    /// thread locale storage must stay valid during this synchronous operation.
    #[expect(
        unsafe_code,
        reason = "Caller quiescence protects UCRT name storage and independent snapshot capture; no locale is installed"
    )]
    pub unsafe fn capture_current_thread() -> io::Result<Self> {
        // SAFETY: both reads share the caller's explicit mutation exclusion.
        let (name, locale) = unsafe {
            (
                nls::current_name(nls::Category::Time)?,
                LocaleSnapshot::capture_current_thread()?,
            )
        };
        Ok(Self {
            locale,
            name: nls::resolve_name(&name)?,
            named: Arc::new(OnceLock::new()),
        })
    }
    /// Parse a complete ISO, native ctime-style, or Windows locale date/time.
    /// ISO years with four or more digits can stand alone or with month/day and
    /// optional time. Checked Gregorian arithmetic preserves the complete
    /// GNUnet microsecond domain. Local dates keep the UCRT fast path and use
    /// Windows year-specific rules or explicit Microsoft TZ outside its range.
    ///
    /// # Errors
    /// Rejects NUL, input above 32767 UTF-16 units, invalid ISO fields and native
    /// parsing/conversion errors. Supplemental cultures use named NLS pictures
    /// and their selected native calendar conversion. Native calendar limits
    /// remain explicit. HRESULT, NLS errors and CRT errno keep distinct domains.
    pub fn parse(&self, input: &OsStr, zone: Zone) -> io::Result<i64> {
        let mut wide = wide(input, MAX_INPUT_UNITS)?;
        if wide.is_empty() {
            return Err(calendar_fields::invalid());
        }
        let iso = match civil::iso(&wide) {
            Ok(fields) => fields,
            Err(error) => {
                // A regional picture can start with an ISO-shaped date and end
                // in a localized twelve-hour clock. Only the strict field parser
                // may accept it; malformed ISO never reaches OLE normalization.
                return match self.named_fields(&wide) {
                    Ok(fields) => convert(fields, zone),
                    Err(native)
                        if matches!(
                            native.kind(),
                            io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported
                        ) =>
                    {
                        Err(error)
                    }
                    Err(native) => Err(native),
                };
            }
        };
        if let Some(civil) = iso {
            return convert_civil(civil, zone);
        }
        let fields = if let Some(fields) = self.ctime(&wide)? {
            fields
        } else {
            wide.try_reserve(1)
                .map_err(|_| io::ErrorKind::OutOfMemory)?;
            wide.push(0);
            self.localized(&wide)?
        };
        convert(fields, zone)
    }
    fn named_fields(&self, input: &[u16]) -> io::Result<Fields> {
        let formats = match self.named.get() {
            Some(formats) => formats,
            None => {
                let formats = named::Formats::load(&self.name)?;
                self.named.get_or_init(|| formats)
            }
        };
        formats.parse(input)
    }
    fn localized(&self, input: &[u16]) -> io::Result<Fields> {
        let lcid = match nls::automation_id(&self.name) {
            Ok(id) => id,
            Err(error) if error.kind() == io::ErrorKind::Unsupported => {
                return self.named_fields(&input[..input.len() - 1]);
            }
            Err(error) => return Err(error),
        };
        let mut value = 0_f64;
        #[expect(
            unsafe_code,
            reason = "The owned NUL-terminated UTF-16 input, resolved LCID and exclusive initialized DATE output remain live through the native conversion"
        )]
        // SAFETY: no COM object or allocator ownership crosses the call.
        let status = unsafe { VarDateFromStr(input.as_ptr(), lcid, 0, &mut value) };
        if status != 0 {
            return Err(io::Error::new(
                if status == E_OUTOFMEMORY {
                    io::ErrorKind::OutOfMemory
                } else {
                    io::ErrorKind::InvalidInput
                },
                AutomationDateError { status },
            ));
        }
        let mut civil = SYSTEMTIME::default();
        #[expect(
            unsafe_code,
            reason = "Successful VarDateFromStr produced a DATE and a live exclusive SYSTEMTIME receives its native Gregorian fields"
        )]
        // SAFETY: both values are initialized and pointers cannot escape.
        if unsafe { VariantTimeToSystemTime(value, &mut civil) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VariantTimeToSystemTime rejected a successful native DATE",
            ));
        }
        Fields::new(
            Date {
                year: civil.wYear,
                month: civil.wMonth,
                day: civil.wDay,
            },
            Time {
                hour: civil.wHour,
                minute: civil.wMinute,
                second: civil.wSecond,
            },
        )
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid native date fields"))
    }
    fn word(&self, input: &[u16], kind: Word) -> io::Result<Option<(u16, usize)>> {
        let mut matched = None;
        let count = match kind {
            Word::Weekday => 7,
            Word::Month => 12,
        };
        for index in 0..count {
            let seconds = match kind {
                // 2024-01-07 is a Gregorian Sunday. Names use explicit UTC values.
                Word::Weekday => 1_704_585_600 + i64::from(index) * 86400,
                Word::Month => Fields::new(
                    Date {
                        year: 2024,
                        month: index + 1,
                        day: 1,
                    },
                    Time::default(),
                )?
                .utc_seconds(),
            };
            let value = Calendar::from_epoch(seconds, Zone::Utc)?;
            let patterns: &[&str] = match kind {
                Word::Weekday => &["%a", "%A"],
                Word::Month => &["%b", "%B"],
            };
            for pattern in patterns {
                let name = value.format_in(OsStr::new(pattern), NAME_CAPACITY, &self.locale)?;
                let name = wide(&name, NAME_CAPACITY)?;
                if name.is_empty() || input.is_empty() {
                    continue;
                }
                let Some(length) = prefix(&self.name, input, &name)? else {
                    continue;
                };
                if matched.is_none_or(|(_, previous)| previous < length) {
                    matched = Some((index, length));
                }
            }
        }
        Ok(matched)
    }
    fn ctime(&self, input: &[u16]) -> io::Result<Option<Fields>> {
        // Localized numeric/date-only inputs go straight to the native parser.
        if !input.contains(&u16::from(b':')) {
            return Ok(None);
        }
        let mut cursor = Cursor { input, at: 0 };
        cursor.spaces();
        let Some((_, length)) = self.word(&input[cursor.at..], Word::Weekday)? else {
            return Ok(None);
        };
        cursor.at += length;
        if !cursor.spaces() {
            return Ok(None);
        }
        let Some((month, length)) = self.word(&input[cursor.at..], Word::Month)? else {
            return Ok(None);
        };
        cursor.at += length;
        if !cursor.spaces() {
            return Ok(None);
        }
        let parsed = (|| {
            let day = cursor.number(2)?;
            if !cursor.spaces() {
                return Err(calendar_fields::invalid());
            }
            let hour = cursor.number(2)?;
            cursor.literal(b':')?;
            let minute = cursor.number(2)?;
            cursor.literal(b':')?;
            let second = cursor.number(2)?;
            if !cursor.spaces() {
                return Err(calendar_fields::invalid());
            }
            let year = cursor.number(4)?;
            if !cursor.end() {
                return Err(calendar_fields::invalid());
            }
            Fields::new(
                Date {
                    year,
                    month: month + 1,
                    day,
                },
                Time {
                    hour,
                    minute,
                    second,
                },
            )
        })();
        parsed.map(Some)
    }
}
#[derive(Clone, Copy)]
enum Word {
    Weekday,
    Month,
}
fn wide(input: &OsStr, limit: usize) -> io::Result<Vec<u16>> {
    let mut result = Vec::new();
    for unit in input.encode_wide() {
        if unit == 0 || result.len() == limit {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        result
            .try_reserve(1)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        result.push(unit);
    }
    Ok(result)
}
fn convert(fields: Fields, zone: Zone) -> io::Result<i64> {
    let date = fields.date();
    let time = fields.time();
    convert_civil(
        Civil::new(
            i32::from(date.year),
            date.month as u8,
            date.day as u8,
            time.hour as u8,
            time.minute as u8,
            time.second as u8,
        )?,
        zone,
    )
}
fn convert_civil(civil: Civil, zone: Zone) -> io::Result<i64> {
    if zone == Zone::Utc {
        return Ok(civil.epoch());
    }
    if !(1970..=3000).contains(&civil.year) {
        return timezone::Source::capture()?.resolve_local(civil);
    }
    let mut value = libc::tm {
        tm_year: civil.year - 1900,
        tm_mon: i32::from(civil.month) - 1,
        tm_mday: i32::from(civil.day),
        tm_hour: i32::from(civil.hour),
        tm_min: i32::from(civil.minute),
        tm_sec: i32::from(civil.second),
        tm_wday: i32::from(civil.weekday),
        tm_yday: i32::from(civil.ordinal),
        tm_isdst: -1,
    };
    let _errno = Errno::clear();
    #[expect(
        unsafe_code,
        reason = "Validated Gregorian fields initialize all native tm members, including required DST inference; the nonnull pointer avoids UCRT invalid-parameter validation"
    )]
    // SAFETY: native conversion may normalize this unique tm; no pointer escapes.
    let seconds = unsafe { _mktime64(&mut value) };
    if seconds == -1 {
        // A valid civil date at the epoch boundary can map to negative UTC.
        // UCRT's restricted epoch is not a malformed date or timestamp overflow.
        if crate::windows_crt::errno() == libc::EINVAL || crate::windows_crt::errno() == 0 {
            return timezone::Source::capture()?.resolve_local(civil);
        }
        return Err(crt_error("_mktime64"));
    }
    Ok(seconds)
}

/// Native linguistic prefix length belongs to the source, not the spelling.
fn prefix(name: &nls::Name, input: &[u16], word: &[u16]) -> io::Result<Option<usize>> {
    if input.is_empty() || word.is_empty() {
        return Ok(None);
    }
    let mut length = 0;
    #[expect(
        unsafe_code,
        reason = "Bounded nonempty UTF-16 spans and an exclusive initialized source-length output remain live during the synchronous named NLS search"
    )]
    // SAFETY: all pointers are live, lengths fit native ints; optional inputs are null.
    let (found, error) = unsafe {
        SetLastError(ERROR_SUCCESS);
        let found = FindNLSStringEx(
            name.as_ptr(),
            FIND_STARTSWITH | NORM_IGNORECASE,
            input.as_ptr(),
            input.len() as c_int,
            word.as_ptr(),
            word.len() as c_int,
            &mut length,
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        (
            found,
            if found == -1 {
                GetLastError()
            } else {
                ERROR_SUCCESS
            },
        )
    };
    if found == -1 {
        return if error == ERROR_SUCCESS {
            Ok(None)
        } else {
            Err(io::Error::from_raw_os_error(error as i32))
        };
    }
    let length = usize::try_from(length)
        .ok()
        .filter(|length| *length > 0 && *length <= input.len())
        .filter(|_| found == 0)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid native date-name span")
        })?;
    Ok(Some(length))
}
