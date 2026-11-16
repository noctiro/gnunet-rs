//! Named NLS pictures; supplemental cultures never pass a placeholder LCID to OLE.
use super::nls;
use crate::{
    calendar_fields::Fields,
    calendar_pattern::{self, Budget, Parsed},
};
use std::{
    io,
    panic::{AssertUnwindSafe, catch_unwind},
};
use windows_sys::Win32::Globalization::{
    CAL_GREGORIAN, CAL_GREGORIAN_ARABIC, CAL_GREGORIAN_ME_FRENCH, CAL_GREGORIAN_US,
    CAL_GREGORIAN_XLIT_ENGLISH, CAL_GREGORIAN_XLIT_FRENCH, CAL_ITWODIGITYEARMAX, CAL_RETURN_NUMBER,
    DATE_LONGDATE, DATE_SHORTDATE, EnumDateFormatsExEx, EnumTimeFormatsEx, FoldStringW,
    GetCalendarInfoEx, GetLocaleInfoEx, LOCALE_ICALENDARTYPE, LOCALE_RETURN_NUMBER, MAP_FOLDDIGITS,
    TIME_NOSECONDS,
};
const MAX_PICTURE: usize = 256;
const MAX_PICTURES: usize = 128;
const MAX_NAME: usize = 256;
mod conversion;
use conversion::Conversion;
mod symbols;
use symbols::Symbols;

struct Pictures {
    calendar: u32,
    values: Vec<Vec<u16>>,
    failure: Option<io::Error>,
}
impl Pictures {
    fn push(&mut self, value: &[u16]) -> io::Result<()> {
        if value.is_empty() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let owned = fold_digits(value)?;
        if self.values.iter().any(|previous| previous == &owned) {
            return Ok(());
        }
        if self.values.len() == MAX_PICTURES {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native date picture inventory limit exceeded",
            ));
        }
        self.values
            .try_reserve(1)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        self.values.push(owned);
        Ok(())
    }
}
#[expect(
    unsafe_code,
    reason = "The synchronous NLS enumeration supplies a terminated picture and the original exclusive callback context; copying is bounded and panics cannot cross the C ABI"
)]
unsafe extern "system" fn date_picture(value: *const u16, calendar: u32, context: isize) -> i32 {
    // SAFETY: enumeration borrows this original Pictures exclusively for the call.
    let pictures = unsafe { &mut *(context as *mut Pictures) };
    if calendar != pictures.calendar {
        return 1;
    }
    // SAFETY: the enumerator guarantees a live terminated picture during callback.
    unsafe { collect(value, pictures) }
}
#[expect(
    unsafe_code,
    reason = "The synchronous NLS time callback shares the bounded copying and panic containment of the date callback"
)]
unsafe extern "system" fn time_picture(value: *const u16, context: isize) -> i32 {
    // SAFETY: context is the original exclusive stack owner and value is an NLS string.
    unsafe { collect(value, &mut *(context as *mut Pictures)) }
}
#[expect(
    unsafe_code,
    reason = "Only live NLS callback strings enter this bounded terminated copy; every read is within the documented string lifetime"
)]
unsafe fn collect(value: *const u16, pictures: &mut Pictures) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if value.is_null() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut buffer = [0; MAX_PICTURE];
        for at in 0..MAX_PICTURE {
            // SAFETY: NLS provides a terminated string, inspected only until NUL.
            let unit = unsafe { *value.add(at) };
            if unit == 0 {
                return pictures.push(&buffer[..at]);
            }
            buffer[at] = unit;
        }
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native date picture is too long",
        ))
    }));
    match result {
        Ok(Ok(())) => 1,
        Ok(Err(error)) => {
            pictures.failure = Some(error);
            0
        }
        Err(_) => {
            pictures.failure = Some(io::Error::other("native date callback panicked"));
            0
        }
    }
}

pub(super) struct Formats {
    dates: Vec<Vec<u16>>,
    times: Vec<Vec<u16>>,
    symbols: Symbols,
    year_max: u16,
    conversion: Option<Conversion>,
    initial: Parsed,
}
impl Formats {
    #[expect(
        unsafe_code,
        reason = "Only read-only named NLS APIs receive live validated names and exclusive bounded output or callback storage; no process/thread locale is changed"
    )]
    pub(super) fn load(name: &nls::Name) -> io::Result<Self> {
        let mut calendar = 0u32;
        // SAFETY: LOCALE_RETURN_NUMBER writes exactly two wide units to aligned u32.
        let count = unsafe {
            GetLocaleInfoEx(
                name.as_ptr(),
                LOCALE_ICALENDARTYPE | LOCALE_RETURN_NUMBER,
                (&mut calendar as *mut u32).cast(),
                2,
            )
        };
        if count == 0 {
            return Err(io::Error::last_os_error());
        }
        if count != 2 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let gregorian = matches!(
            calendar,
            CAL_GREGORIAN
                | CAL_GREGORIAN_US
                | CAL_GREGORIAN_ME_FRENCH
                | CAL_GREGORIAN_ARABIC
                | CAL_GREGORIAN_XLIT_ENGLISH
                | CAL_GREGORIAN_XLIT_FRENCH
        );
        let conversion = if gregorian {
            None
        } else {
            Some(Conversion::load(calendar)?)
        };
        let mut dates = Pictures {
            calendar,
            values: Vec::new(),
            failure: None,
        };
        for flags in [DATE_SHORTDATE, DATE_LONGDATE] {
            // SAFETY: callback borrows only this original stack owner synchronously.
            let ok = unsafe {
                EnumDateFormatsExEx(
                    Some(date_picture),
                    name.as_ptr(),
                    flags,
                    (&mut dates as *mut Pictures) as isize,
                )
            };
            if let Some(error) = dates.failure.take() {
                return Err(error);
            }
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let mut times = Pictures {
            calendar,
            values: Vec::new(),
            failure: None,
        };
        for flags in [0, TIME_NOSECONDS] {
            // SAFETY: same exact callback/context lifetime as date enumeration.
            let ok = unsafe {
                EnumTimeFormatsEx(
                    Some(time_picture),
                    name.as_ptr(),
                    flags,
                    (&mut times as *mut Pictures) as isize,
                )
            };
            if let Some(error) = times.failure.take() {
                return Err(error);
            }
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        if dates.values.is_empty() || times.values.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "empty native date/time inventory",
            ));
        }
        let mut year_max = 0;
        // SAFETY: numeric calendar data uses the documented null string/zero extent.
        let count = unsafe {
            GetCalendarInfoEx(
                name.as_ptr(),
                calendar,
                std::ptr::null(),
                CAL_ITWODIGITYEARMAX | CAL_RETURN_NUMBER,
                std::ptr::null_mut(),
                0,
                &mut year_max,
            )
        };
        if count == 0 {
            return Err(io::Error::last_os_error());
        }
        if count != 2 || !(99..=9999).contains(&year_max) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let symbols = Symbols::load(name, calendar, conversion.as_ref())?;
        Ok(Self {
            dates: dates.values,
            times: times.values,
            symbols,
            year_max: year_max as u16,
            conversion,
            initial: if calendar == windows_sys::Win32::Globalization::CAL_HEBREW {
                Parsed::hebrew()
            } else {
                Parsed::default()
            },
        })
    }
    pub(super) fn parse(&self, input: &[u16]) -> io::Result<Fields> {
        let folded;
        let input = if input.iter().all(|unit| *unit < 128) {
            input
        } else {
            folded = fold_digits(input)?;
            &folded
        };
        let mut budget = Budget::new();
        let mut start = 0;
        budget.charge(calendar_pattern::skip_spaces(input, &mut start))?;
        let input = &input[start..];
        for date in &self.dates {
            let Some((parsed, mut at)) =
                calendar_pattern::matches(date, input, self.initial, &self.symbols, &mut budget)?
            else {
                continue;
            };
            let date_end = at;
            budget.charge(calendar_pattern::skip_spaces(input, &mut at))?;
            if at == input.len() {
                if let Some(fields) = self.candidate(parsed)? {
                    return Ok(fields);
                }
                continue;
            }
            if date_end == at {
                continue;
            }
            for time in &self.times {
                let Some((parsed, consumed)) = calendar_pattern::matches(
                    time,
                    &input[at..],
                    parsed,
                    &self.symbols,
                    &mut budget,
                )?
                else {
                    continue;
                };
                let mut end = at + consumed;
                budget.charge(calendar_pattern::skip_spaces(input, &mut end))?;
                if end == input.len()
                    && let Some(fields) = self.candidate(parsed)?
                {
                    return Ok(fields);
                }
            }
        }
        Err(crate::calendar_fields::invalid())
    }
    fn candidate(&self, parsed: Parsed) -> io::Result<Option<Fields>> {
        let result = match &self.conversion {
            Some(conversion) => parsed
                .components(self.year_max)
                .and_then(|parts| conversion.fields(parts)),
            None => parsed.fields(self.year_max),
        };
        match result {
            Ok(fields) => Ok(Some(fields)),
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => Ok(None),
            Err(error) => Err(error),
        }
    }
}

fn text(buffer: &[u16], count: i32) -> io::Result<Vec<u16>> {
    let count = usize::try_from(count).map_err(|_| io::ErrorKind::InvalidData)?;
    let value = buffer
        .get(..count)
        .filter(|value| value.last() == Some(&0))
        .ok_or(io::ErrorKind::InvalidData)?;
    if value[..count - 1].contains(&0) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    fold_digits(&value[..count - 1])
}
#[expect(
    unsafe_code,
    reason = "Unicode digit folding uses explicit input lengths and an independently allocated output sized by the native query; no locale state or pointers are retained"
)]
fn fold_digits(input: &[u16]) -> io::Result<Vec<u16>> {
    let mut output = Vec::new();
    if input.iter().all(|unit| *unit < 128) {
        output
            .try_reserve_exact(input.len())
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        output.extend_from_slice(input);
        return Ok(output);
    }
    // SAFETY: explicit bounded input and a zero-sized query with no output.
    let capacity = unsafe {
        FoldStringW(
            MAP_FOLDDIGITS,
            input.as_ptr(),
            input.len() as i32,
            std::ptr::null_mut(),
            0,
        )
    };
    if capacity == 0 {
        return Err(io::Error::last_os_error());
    }
    let capacity = usize::try_from(capacity).map_err(|_| io::ErrorKind::InvalidData)?;
    if capacity > super::MAX_INPUT_UNITS * 4 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    output
        .try_reserve_exact(capacity)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    output.resize(capacity, 0);
    // SAFETY: the complete queried maximum output is initialized and exclusive.
    let count = unsafe {
        FoldStringW(
            MAP_FOLDDIGITS,
            input.as_ptr(),
            input.len() as i32,
            output.as_mut_ptr(),
            capacity as i32,
        )
    };
    if count == 0 {
        return Err(io::Error::last_os_error());
    }
    let count = usize::try_from(count)
        .ok()
        .filter(|count| *count <= capacity && *count <= super::MAX_INPUT_UNITS)
        .ok_or(io::ErrorKind::InvalidData)?;
    output.truncate(count);
    if output.contains(&0) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(output)
}
#[expect(
    unsafe_code,
    reason = "Exact named calendar and string property are read into initialized fixed output; reserved and unused numeric output are null"
)]
fn calendar_text(name: &nls::Name, calendar: u32, property: u32) -> io::Result<Vec<u16>> {
    let mut buffer = [0; MAX_NAME];
    // SAFETY: live terminated name and exclusive full declared output span.
    let count = unsafe {
        GetCalendarInfoEx(
            name.as_ptr(),
            calendar,
            std::ptr::null(),
            property,
            buffer.as_mut_ptr(),
            buffer.len() as i32,
            std::ptr::null_mut(),
        )
    };
    if count == 0 {
        return Err(io::Error::last_os_error());
    }
    text(&buffer, count)
}
#[expect(
    unsafe_code,
    reason = "Named locale string queries use owned names and exact initialized output extents without locale installation"
)]
fn locale_text(name: &nls::Name, property: u32) -> io::Result<Vec<u16>> {
    let mut buffer = [0; MAX_NAME];
    // SAFETY: string-only property and exclusive bounded output stay live.
    let count = unsafe {
        GetLocaleInfoEx(
            name.as_ptr(),
            property,
            buffer.as_mut_ptr(),
            buffer.len() as i32,
        )
    };
    if count == 0 {
        return Err(io::Error::last_os_error());
    }
    text(&buffer, count)
}
