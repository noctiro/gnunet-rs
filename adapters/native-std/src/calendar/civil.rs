//! Checked proleptic Gregorian arithmetic, independent of native epoch limits.
use std::io;
const DAY: i64 = 86_400;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Civil {
    pub year: i32,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub weekday: u8,
    pub ordinal: u16,
}
pub(crate) fn leap(year: i32) -> bool {
    leap_year(i64::from(year))
}
fn leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}
pub(crate) fn month_days(year: i32, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => 28 + u8::from(leap(year)),
        _ => 0,
    }
}
fn days(year: i32, month: u8, day: u8) -> i64 {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let within = year - era * 400;
    let month = i64::from(month) + if month > 2 { -3 } else { 9 };
    let ordinal = (153 * month + 2) / 5 + i64::from(day) - 1;
    era * 146_097 + within * 365 + within / 4 - within / 100 + ordinal - 719_468
}
pub(crate) fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "calendar fields exceed the Gregorian range",
    )
}
impl Civil {
    pub fn new(
        year: i32,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> io::Result<Self> {
        if day == 0 || day > month_days(year, month) || hour > 23 || minute > 59 || second > 60 {
            return Err(invalid());
        }
        // A leap-second spelling follows native mktime normalization. All i32
        // years and their complete day/second totals fit signed 64-bit seconds.
        Self::from_epoch(
            days(year, month, day) * DAY
                + i64::from(hour) * 3600
                + i64::from(minute) * 60
                + i64::from(second),
        )
    }
    pub fn from_epoch(seconds: i64) -> io::Result<Self> {
        let original_days = seconds.div_euclid(DAY);
        let z = original_days + 719_468;
        let era = z.div_euclid(146_097);
        let within = z - era * 146_097;
        let year = (within - within / 1460 + within / 36524 - within / 146096) / 365;
        let ordinal = within - (365 * year + year / 4 - year / 100);
        let month = (5 * ordinal + 2) / 153;
        let day = ordinal - (153 * month + 2) / 5 + 1;
        let month = month + if month < 10 { 3 } else { -9 };
        let year =
            i32::try_from(year + era * 400 + i64::from(month <= 2)).map_err(|_| invalid())?;
        let time = seconds.rem_euclid(DAY);
        Ok(Self {
            year,
            month: month as u8,
            day: day as u8,
            hour: (time / 3600) as u8,
            minute: (time / 60 % 60) as u8,
            second: (time % 60) as u8,
            weekday: (original_days + 4).rem_euclid(7) as u8,
            ordinal: (original_days - days(year, 1, 1)) as u16,
        })
    }
    pub fn epoch(self) -> i64 {
        days(self.year, self.month, self.day) * DAY
            + i64::from(self.hour) * 3600
            + i64::from(self.minute) * 60
            + i64::from(self.second)
    }
    pub fn iso_week(self) -> (i64, u8) {
        let weekday = (self.weekday + 6) % 7;
        let thursday = days(self.year, self.month, self.day) + 3 - i64::from(weekday);
        let mut year = i64::from(self.year);
        if thursday < days(self.year, 1, 1) {
            year -= 1;
        } else if thursday > days(self.year, 12, 31) {
            year += 1;
        }
        // The adjacent ISO year may lie just outside i32 civil input. Its first
        // Thursday remains computable from this year's January reference.
        let first = if year < i64::from(self.year) {
            days(self.year, 1, 1)
                - if leap_year(i64::from(self.year) - 1) {
                    366
                } else {
                    365
                }
        } else if year > i64::from(self.year) {
            days(self.year, 12, 31) + 1
        } else {
            days(self.year, 1, 1)
        };
        (year, ((thursday - first) / 7 + 1) as u8)
    }
    pub fn numeric(self, code: u8, unpadded: bool) -> Option<String> {
        let (value, width) = match code {
            b'Y' => (i64::from(self.year), 4),
            b'y' => (i64::from(self.year).rem_euclid(100), 2),
            b'C' => (i64::from(self.year).div_euclid(100), 2),
            b'G' => (self.iso_week().0, 4),
            b'g' => (self.iso_week().0.rem_euclid(100), 2),
            b'V' => (i64::from(self.iso_week().1), 2),
            b'U' => (
                (i64::from(self.ordinal) + 7 - i64::from(self.weekday)) / 7,
                2,
            ),
            b'W' => (
                (i64::from(self.ordinal) + 7 - i64::from((self.weekday + 6) % 7)) / 7,
                2,
            ),
            _ => return None,
        };
        Some(if unpadded && !b"Gg".contains(&code) {
            value.to_string()
        } else {
            format!("{value:0width$}")
        })
    }
}

/// Four or more year digits followed by '-' select ISO, never a regional picture.
pub(crate) fn iso(input: &[u16]) -> io::Result<Option<Civil>> {
    let digits = input
        .iter()
        .take_while(|&&unit| (48..=57).contains(&unit))
        .count();
    if digits < 4
        || input
            .get(digits)
            .is_some_and(|unit| *unit != u16::from(b'-'))
    {
        return Ok(None);
    }
    let mut year = 0i32;
    for unit in &input[..digits] {
        year = year
            .checked_mul(10)
            .and_then(|year| year.checked_add(i32::from(*unit - 48)))
            .ok_or_else(invalid)?;
    }
    if year == 0 {
        return Err(invalid());
    }
    let mut c = crate::calendar_fields::Cursor { input, at: digits };
    let (mut month, mut day, mut hour, mut minute, mut second) = (1, 1, 0, 0, 0);
    if !c.end() {
        c.literal(b'-')?;
        month = c.number(2)?;
        if !c.end() {
            c.literal(b'-')?;
            day = c.number(2)?;
            if !c.end() {
                if input.get(c.at) == Some(&u16::from(b'T')) {
                    c.at += 1;
                } else if !c.spaces() {
                    return Err(invalid());
                }
                hour = c.number(2)?;
                c.literal(b':')?;
                minute = c.number(2)?;
                if !c.end() {
                    c.literal(b':')?;
                    second = c.number(2)?;
                }
            }
        }
    }
    if !c.end() {
        return Err(invalid());
    }
    Civil::new(
        year,
        month as u8,
        day as u8,
        hour as u8,
        minute as u8,
        second as u8,
    )
    .map(Some)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Gregorian boundary fixtures compare native-independent field and epoch contracts"
    )]
    use super::*;
    #[test]
    fn signed_epochs_and_expanded_iso_years_preserve_complete_fields() -> io::Result<()> {
        for (seconds, text) in [
            (-62_135_596_800, "0001-01-01"),
            (-2_208_988_800, "1900-01-01"),
            (-1, "1969-12-31T23:59:59"),
            (0, "1970-01-01"),
            (951_782_400, "2000-02-29"),
            (32_535_216_000, "3001-01-01"),
            (253_402_300_800, "10000-01-01"),
        ] {
            let parsed = iso(&text.encode_utf16().collect::<Vec<_>>())?.ok_or_else(invalid)?;
            assert_eq!(parsed.epoch(), seconds, "{text}");
            assert_eq!(Civil::from_epoch(seconds)?, parsed, "{text}");
        }
        let maximum_protocol = (u64::MAX / 1_000_000) as i64;
        assert_eq!(
            Civil::from_epoch(maximum_protocol)?.epoch(),
            maximum_protocol
        );
        for text in [
            "0000",
            "2100-02-29",
            "2024-01-01 trailing",
            "2024-13-01",
            "2147483648-01-01",
        ] {
            assert!(
                iso(&text.encode_utf16().collect::<Vec<_>>()).is_err(),
                "{text}"
            );
        }
        assert!(iso(&"1/2/2024".encode_utf16().collect::<Vec<_>>())?.is_none());
        assert!(Civil::from_epoch(i64::MAX).is_err());
        assert!(Civil::from_epoch(i64::MIN).is_err());
        Ok(())
    }
    #[test]
    fn iso_week_year_and_cycle_fields_keep_real_years() -> io::Result<()> {
        for (date, week_year, week) in [
            ((2016, 1, 1), 2015, 53),
            ((2017, 1, 1), 2016, 52),
            ((2018, 12, 31), 2019, 1),
            ((2021, 1, 1), 2020, 53),
            ((12021, 1, 1), 12020, 53),
        ] {
            let civil = Civil::new(date.0, date.1, date.2, 0, 0, 0)?;
            assert_eq!(civil.iso_week(), (week_year, week));
            assert_eq!(civil.numeric(b'G', false), Some(week_year.to_string()));
            assert_eq!(civil.numeric(b'V', false), Some(format!("{week:02}")));
            assert!(civil.numeric(b'Y', true).is_some());
            assert!(civil.numeric(b'Q', false).is_none());
        }
        Ok(())
    }
    #[cfg(unix)]
    #[test]
    #[expect(
        unsafe_code,
        reason = "Read-only native UTC conversion writes an exclusive initialized tm for independently checking Gregorian arithmetic"
    )]
    fn complete_protocol_epoch_range_matches_native_utc() -> io::Result<()> {
        // Include century boundaries, pre-epoch dates and GNUnet's full u64
        // microsecond domain. No local timezone or process setting is changed.
        let mut samples = vec![
            -62_135_596_800,
            -1,
            0,
            32_535_216_000,
            253_402_300_800,
            (u64::MAX / 1_000_000) as i64,
        ];
        for year in [
            -800, 1, 1600, 1700, 1900, 2000, 2400, 3001, 9999, 12024, 584_554,
        ] {
            for month in 1..=12 {
                samples.push(Civil::new(year, month, month_days(year, month), 23, 59, 59)?.epoch());
            }
        }
        for seconds in samples {
            let civil = Civil::from_epoch(seconds)?;
            let value = libc::time_t::try_from(seconds).map_err(io::Error::other)?;
            // SAFETY: POSIX tm integer/pointer fields admit all-zero initialization.
            let mut native: libc::tm = unsafe { std::mem::zeroed() };
            // SAFETY: live input scalar and exact exclusive output; no pointer escapes.
            if unsafe { libc::gmtime_r(&value, &mut native) }.is_null() {
                return Err(io::Error::last_os_error());
            }
            assert_eq!(
                (civil.year, i32::from(civil.month), i32::from(civil.day)),
                (native.tm_year + 1900, native.tm_mon + 1, native.tm_mday)
            );
            assert_eq!(
                (
                    i32::from(civil.hour),
                    i32::from(civil.minute),
                    i32::from(civil.second)
                ),
                (native.tm_hour, native.tm_min, native.tm_sec)
            );
            assert_eq!(
                (i32::from(civil.weekday), i32::from(civil.ordinal)),
                (native.tm_wday, native.tm_yday)
            );
            assert_eq!(civil.epoch(), seconds);
        }
        Ok(())
    }
}
