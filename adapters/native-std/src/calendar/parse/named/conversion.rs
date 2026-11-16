//! Exact native calendar conversion with roundtrip rejection of normalization.
use crate::{
    calendar_fields::{self, Date, Fields},
    calendar_pattern::Components,
    library::Library,
    locale::nls,
};
use std::{ffi::c_void, io};
use windows_sys::Win32::{Foundation::SYSTEMTIME, Globalization::CALDATETIME};
type ToCivil = unsafe extern "system" fn(*const CALDATETIME, *mut SYSTEMTIME) -> i32;
type FromCivil = unsafe extern "system" fn(*const SYSTEMTIME, u32, *mut CALDATETIME) -> i32;
type Range = unsafe extern "system" fn(u32, *mut CALDATETIME, *mut CALDATETIME) -> i32;
type Format = unsafe extern "system" fn(
    *const u16,
    u32,
    *const CALDATETIME,
    *const u16,
    *mut u16,
    i32,
) -> i32;
type Leap = unsafe extern "system" fn(u32, u32, u32) -> i32;
pub(super) struct Conversion {
    id: u32,
    minimum: CALDATETIME,
    maximum: CALDATETIME,
    to_civil: ToCivil,
    from_civil: FromCivil,
    format: Format,
    leap: Option<Leap>,
}
impl Conversion {
    #[expect(
        unsafe_code,
        reason = "Only exact documented calendar exports from the absolute system Kernel32 provider are called; pinning keeps code valid after releasing the loader reference"
    )]
    pub(super) fn load(id: u32) -> io::Result<Self> {
        // Microsoft documents these calendar APIs as dynamically resolved exports.
        // No alternate provider or locale is substituted if one is unavailable.
        let path = crate::paths::system_directory()?.join("kernel32.dll");
        // SAFETY: fixed absolute Windows system library and documented C ABI.
        let library = unsafe { Library::load(&path) }?;
        macro_rules! export {
            ($name:literal, $ty:ty) => {{
                let pointer = library.symbol($name)?;
                // SAFETY: selected exact SDK export signature, not a Rust/C++ ABI.
                unsafe { std::mem::transmute::<*mut c_void, $ty>(pointer) }
            }};
        }
        let to_civil = export!(c"ConvertCalDateTimeToSystemTime", ToCivil);
        let from_civil = export!(c"ConvertSystemTimeToCalDateTime", FromCivil);
        let range = export!(c"GetCalendarSupportedDateRange", Range);
        let format = export!(c"GetCalendarDateFormatEx", Format);
        let leap = if id == windows_sys::Win32::Globalization::CAL_HEBREW {
            Some(export!(c"IsCalendarLeapYear", Leap))
        } else {
            None
        };
        let mut minimum = CALDATETIME::default();
        let mut maximum = CALDATETIME::default();
        // SAFETY: initialized independent full-width SDK output records.
        if unsafe { range(id, &mut minimum, &mut maximum) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if minimum.CalId != id
            || maximum.CalId != id
            || minimum.Era == 0
            || maximum.Era < minimum.Era
            || maximum.Era - minimum.Era >= 64
            || maximum.Era > u32::from(u16::MAX)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid native calendar era inventory",
            ));
        }
        let mut probe = SYSTEMTIME::default();
        // SAFETY: the provider advertised this exact initialized minimum as a
        // supported date. A failure here is provider setup, not user input.
        if unsafe { to_civil(&minimum, &mut probe) } == 0 {
            return Err(io::Error::last_os_error());
        }
        library.pin_for_process()?;
        Ok(Self {
            id,
            minimum,
            maximum,
            to_civil,
            from_civil,
            format,
            leap,
        })
    }
    pub(super) fn current_era(&self) -> u16 {
        self.maximum.Era as u16
    }
    pub(super) fn eras(&self) -> std::ops::RangeInclusive<u16> {
        self.minimum.Era as u16..=self.maximum.Era as u16
    }
    fn representative(&self, era: u16) -> CALDATETIME {
        if u32::from(era) == self.minimum.Era {
            return self.minimum;
        }
        if u32::from(era) == self.maximum.Era {
            return self.maximum;
        }
        // Interior Japanese eras have a full second year, unlike partial year one.
        CALDATETIME {
            CalId: self.id,
            Era: u32::from(era),
            Year: 2,
            Month: 1,
            Day: 1,
            ..Default::default()
        }
    }
    #[expect(
        unsafe_code,
        reason = "Owned validated locale, explicit calendar record, terminated picture and bounded exclusive output remain live for synchronous native formatting"
    )]
    pub(super) fn era_name(&self, name: &nls::Name, era: u16, short: bool) -> io::Result<Vec<u16>> {
        let value = self.representative(era);
        let picture: &[u16] = if short { &[103, 0] } else { &[103, 103, 0] };
        let mut buffer = [0u16; 256];
        // SAFETY: exact explicit calendar, no process/thread locale mutation.
        let count = unsafe {
            (self.format)(
                name.as_ptr(),
                0,
                &value,
                picture.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as i32,
            )
        };
        if count == 0 {
            return Err(io::Error::last_os_error());
        }
        super::text(&buffer, count)
    }
    #[expect(
        unsafe_code,
        reason = "Synchronous conversions borrow only initialized local records; complete date roundtrip rejects normalized or mismatched calendar fields"
    )]
    pub(super) fn fields(&self, parts: Components) -> io::Result<Fields> {
        let mut original = CALDATETIME {
            CalId: self.id,
            Era: u32::from(parts.era.unwrap_or_else(|| self.current_era())),
            Year: u32::from(parts.date.year),
            Month: u32::from(parts.date.month),
            Day: u32::from(parts.date.day),
            ..Default::default()
        };
        if parts.named_month
            && let Some(leap) = self.leap
        {
            // NLS Hebrew names always include the leap month in slot seven.
            // Numeric input already uses the actual year's month numbering.
            // SAFETY: selected calendar and bounded original scalar year/era.
            if unsafe { leap(self.id, original.Year, original.Era) } == 0 {
                match original.Month {
                    7 => return Err(calendar_fields::invalid()),
                    8..=13 => original.Month -= 1,
                    _ => {}
                }
            }
        }
        let mut civil = SYSTEMTIME::default();
        // SAFETY: stable input and independent initialized full output.
        if unsafe { (self.to_civil)(&original, &mut civil) } == 0 {
            return Err(date_error());
        }
        let mut returned = CALDATETIME::default();
        // SAFETY: successful native Gregorian output and selected original CALID.
        if unsafe { (self.from_civil)(&civil, self.id, &mut returned) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if (
            returned.CalId,
            returned.Era,
            returned.Year,
            returned.Month,
            returned.Day,
        ) != (
            original.CalId,
            original.Era,
            original.Year,
            original.Month,
            original.Day,
        ) {
            return Err(calendar_fields::invalid());
        }
        Fields::new(
            Date {
                year: civil.wYear,
                month: civil.wMonth,
                day: civil.wDay,
            },
            parts.time,
        )
    }
}
fn date_error() -> io::Error {
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        // Invalid native date input retains the underlying Win32 diagnostic;
        // other provider failures must not become an ordinary picture mismatch.
        Some(87 | 1901) => io::Error::new(io::ErrorKind::InvalidInput, error),
        _ => error,
    }
}
#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Independent civil-date fixtures assert actual Windows calendar conversion and era-boundary rejection"
)]
mod tests {
    use super::*;
    use crate::calendar_fields::Time;
    use windows_sys::Win32::Globalization::{CAL_HEBREW, CAL_JAPAN, CAL_PERSIAN, CAL_THAI};
    fn parts(year: u16, month: u16, day: u16, era: u16, named_month: bool) -> Components {
        Components {
            date: Date { year, month, day },
            time: Time::default(),
            era: Some(era),
            named_month,
        }
    }
    #[test]
    fn selected_native_calendars_produce_known_civil_dates() -> io::Result<()> {
        for (id, input, civil) in [
            (
                CAL_THAI,
                parts(2567, 3, 20, 1, false),
                Date {
                    year: 2024,
                    month: 3,
                    day: 20,
                },
            ),
            (
                CAL_PERSIAN,
                parts(1403, 1, 1, 1, false),
                Date {
                    year: 2024,
                    month: 3,
                    day: 20,
                },
            ),
            (
                CAL_HEBREW,
                parts(5784, 8, 15, 1, false),
                Date {
                    year: 2024,
                    month: 4,
                    day: 23,
                },
            ),
            (
                CAL_JAPAN,
                parts(31, 4, 30, 4, false),
                Date {
                    year: 2019,
                    month: 4,
                    day: 30,
                },
            ),
        ] {
            assert_eq!(Conversion::load(id)?.fields(input)?.date(), civil);
        }
        Ok(())
    }
    #[test]
    fn era_normalization_and_hebrew_named_month_numbering() -> io::Result<()> {
        let japanese = Conversion::load(CAL_JAPAN)?;
        assert!(japanese.fields(parts(31, 5, 1, 4, false)).is_err());
        let hebrew = Conversion::load(CAL_HEBREW)?;
        assert_eq!(
            hebrew.fields(parts(5783, 8, 15, 1, true))?.date(),
            Date {
                year: 2023,
                month: 4,
                day: 6
            }
        );
        assert_eq!(
            hebrew.fields(parts(5784, 8, 15, 1, true))?.date(),
            Date {
                year: 2024,
                month: 4,
                day: 23
            }
        );
        assert!(hebrew.fields(parts(5783, 7, 15, 1, true)).is_err());
        assert!(hebrew.fields(parts(5783, 13, 1, 1, false)).is_err());
        Ok(())
    }
}
