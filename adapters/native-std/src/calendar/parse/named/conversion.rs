//! Exact native calendar conversion with roundtrip rejection of normalization.
use crate::{
    calendar_fields::{self, Date, Fields},
    calendar_pattern::Components,
    library::Library,
};
use std::{ffi::c_void, io, ops::RangeInclusive};
use windows_sys::Win32::{
    Foundation::{ERROR_INVALID_PARAMETER, ERROR_INVALID_TIME, SYSTEMTIME},
    Globalization::CALDATETIME,
};
type ToCivil = unsafe extern "system" fn(*const CALDATETIME, *mut SYSTEMTIME) -> i32;
type FromCivil = unsafe extern "system" fn(*const SYSTEMTIME, u32, *mut CALDATETIME) -> i32;
type Range = unsafe extern "system" fn(u32, *mut CALDATETIME, *mut CALDATETIME) -> i32;
type Leap = unsafe extern "system" fn(u32, u32, u32) -> i32;
pub(super) struct Conversion {
    id: u32,
    eras: RangeInclusive<u16>,
    to_civil: ToCivil,
    from_civil: FromCivil,
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
        // The calendar inventory can include dates before the conversion
        // function's Gregorian lower bound. Validate actual dates on use.
        library.pin_for_process()?;
        Ok(Self {
            id,
            eras: minimum.Era as u16..=maximum.Era as u16,
            to_civil,
            from_civil,
            leap,
        })
    }
    pub(super) fn current_era(&self) -> u16 {
        *self.eras.end()
    }
    pub(super) fn eras(&self) -> RangeInclusive<u16> {
        self.eras.clone()
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
        let civil = self.civil(original)?;
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

    #[expect(
        unsafe_code,
        reason = "each synchronous conversion borrows initialized calendar data and a separate full-width SYSTEMTIME output"
    )]
    fn civil(&self, mut original: CALDATETIME) -> io::Result<SYSTEMTIME> {
        // The native function validates DayOfWeek even for numeric pictures
        // that omit it. Try the seven possible values before rejecting the date.
        for weekday in 0..7 {
            original.DayOfWeek = weekday;
            let mut civil = SYSTEMTIME::default();
            // SAFETY: ABI-sized input and independent output live for the call.
            if unsafe { (self.to_civil)(&original, &mut civil) } != 0 {
                return Ok(civil);
            }
            let error = io::Error::last_os_error();
            match error.raw_os_error().map(|code| code as u32) {
                Some(ERROR_INVALID_PARAMETER) => {}
                Some(ERROR_INVALID_TIME) => {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, error));
                }
                _ => return Err(error),
            }
        }
        Err(calendar_fields::invalid())
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
