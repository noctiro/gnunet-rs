//! Windows dynamic-year metadata and explicit Microsoft TZ environment selection.
use super::{
    civil::{self, Civil},
    rules::{Day, Local, Rules, Transition},
};
use std::{io, os::windows::ffi::OsStrExt};
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, SYSTEMTIME},
    System::Time::{
        DYNAMIC_TIME_ZONE_INFORMATION, GetDynamicTimeZoneInformation,
        GetDynamicTimeZoneInformationEffectiveYears, GetTimeZoneInformationForYear,
        TIME_ZONE_INFORMATION,
    },
};
mod environment;
use environment::Environment;

pub(super) enum Source {
    Environment(Environment),
    System(Box<System>),
}
pub(super) struct System {
    native: DYNAMIC_TIME_ZONE_INFORMATION,
    years: Option<(u16, u16)>,
}
pub(super) struct Zoned {
    pub local: Local,
    pub name: Vec<u16>,
}
impl Source {
    pub fn capture() -> io::Result<Self> {
        if let Some(value) = std::env::var_os("TZ").filter(|value| !value.is_empty()) {
            let wide: Vec<_> = value.encode_wide().take(129).collect();
            return Environment::parse(&wide).map(Self::Environment);
        }
        System::capture().map(|system| Self::System(Box::new(system)))
    }
    fn rules(&self, year: i32) -> io::Result<(Rules, [Vec<u16>; 2])> {
        match self {
            Self::Environment(value) => Ok(value.rules(year)),
            Self::System(value) => value.rules(year),
        }
    }
    pub fn at_utc(&self, seconds: i64) -> io::Result<Zoned> {
        let mut year = Civil::from_epoch(seconds)?.year;
        // The requested native year is local. Offset crossing January 1 may
        // require the adjacent year's rules; refuse oscillating/invalid metadata.
        for _ in 0..3 {
            let (rules, mut names) = self.rules(year)?;
            let local = rules.at_utc(seconds, year)?;
            if local.civil.year == year {
                return Ok(Zoned {
                    name: std::mem::take(&mut names[usize::from(local.daylight)]),
                    local,
                });
            }
            year = local.civil.year;
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native timezone year selection did not converge",
        ))
    }
    pub fn resolve_local(&self, civil: Civil) -> io::Result<i64> {
        self.rules(civil.year)?.0.resolve_local(civil)
    }
}
impl System {
    #[expect(
        unsafe_code,
        reason = "Read-only Windows timezone APIs receive initialized SDK structures and exclusive scalar outputs; no timezone or registry value is modified"
    )]
    fn capture() -> io::Result<Self> {
        let mut native = DYNAMIC_TIME_ZONE_INFORMATION::default();
        // SAFETY: exact, live, exclusive SDK output storage.
        if unsafe { GetDynamicTimeZoneInformation(&mut native) } == u32::MAX {
            return Err(io::Error::last_os_error());
        }
        if native.DynamicDaylightTimeDisabled {
            return Ok(Self {
                native,
                years: None,
            });
        }
        let (mut first, mut last) = (0, 0);
        // SAFETY: captured native selector and distinct live DWORD outputs.
        let status =
            unsafe { GetDynamicTimeZoneInformationEffectiveYears(&native, &mut first, &mut last) };
        let years = match status {
            0 if first == 0 && last == 0 => None,
            0 if first != 0 && first <= last && last <= u32::from(u16::MAX) => {
                Some((first as u16, last as u16))
            }
            0 => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid native timezone effective years",
                ));
            }
            ERROR_FILE_NOT_FOUND => None, // No dynamic table: the captured static rule applies.
            error => return Err(io::Error::from_raw_os_error(error as i32)),
        };
        Ok(Self { native, years })
    }
    #[expect(
        unsafe_code,
        reason = "A captured explicit timezone selector, validated effective-year bounds and an exclusive initialized SDK output remain borrowed through one read-only query"
    )]
    fn rules(&self, year: i32) -> io::Result<(Rules, [Vec<u16>; 2])> {
        let mut value = TIME_ZONE_INFORMATION {
            Bias: self.native.Bias,
            StandardBias: self.native.StandardBias,
            DaylightBias: self.native.DaylightBias,
            StandardDate: self.native.StandardDate,
            DaylightDate: self.native.DaylightDate,
            StandardName: self.native.StandardName,
            DaylightName: self.native.DaylightName,
        };
        if let Some((first, last)) = self.years {
            let selected = i64::from(year).clamp(i64::from(first), i64::from(last)) as u16;
            // SAFETY: explicit original selector, supported native metadata year and exact output.
            if unsafe { GetTimeZoneInformationForYear(selected, &self.native, &mut value) } == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let transitions = if self.native.DynamicDaylightTimeDisabled
            || value.StandardDate.wMonth == 0 && value.DaylightDate.wMonth == 0
        {
            None
        } else {
            Some((
                transition(value.DaylightDate)?,
                transition(value.StandardDate)?,
            ))
        };
        let bias = |extra: i32| -> io::Result<i32> {
            let seconds = (i64::from(value.Bias) + i64::from(extra)) * -60;
            if seconds.abs() > 86_400 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "native timezone bias exceeds one day",
                ));
            }
            Ok(seconds as i32)
        };
        let standard = bias(if transitions.is_some() {
            value.StandardBias
        } else {
            0
        })?;
        let daylight = if transitions.is_some() {
            bias(value.DaylightBias)?
        } else {
            standard
        };
        Ok((
            Rules {
                standard,
                daylight,
                transitions,
            },
            [name(&value.StandardName)?, name(&value.DaylightName)?],
        ))
    }
}
fn name(input: &[u16]) -> io::Result<Vec<u16>> {
    let count = input
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(io::ErrorKind::InvalidData)?;
    Ok(input[..count].to_vec())
}
fn transition(value: SYSTEMTIME) -> io::Result<Transition> {
    if !(1..=12).contains(&value.wMonth)
        || value.wHour > 23
        || value.wMinute > 59
        || value.wSecond > 59
        || value.wMilliseconds > 999
    {
        return Err(civil::invalid());
    }
    let day = if value.wYear == 0 {
        if !(1..=5).contains(&value.wDay) || value.wDayOfWeek > 6 {
            return Err(civil::invalid());
        }
        Day::Annual {
            month: value.wMonth as u8,
            week: value.wDay as u8,
            weekday: value.wDayOfWeek as u8,
        }
    } else {
        Day::Absolute {
            year: i32::from(value.wYear),
            month: value.wMonth as u8,
            day: u8::try_from(value.wDay).map_err(|_| civil::invalid())?,
        }
    };
    Ok(Transition {
        day,
        seconds: u32::from(value.wHour) * 3600
            + u32::from(value.wMinute) * 60
            + u32::from(value.wSecond),
        milliseconds: value.wMilliseconds,
    })
}
