//! Checked Gregorian fields and complete ISO calendar input, independent of FFI.
use std::io;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Date {
    pub(crate) year: u16,
    pub(crate) month: u16,
    pub(crate) day: u16,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Time {
    pub(crate) hour: u16,
    pub(crate) minute: u16,
    pub(crate) second: u16,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Fields {
    date: Date,
    time: Time,
}
impl Fields {
    pub(crate) fn new(date: Date, time: Time) -> io::Result<Self> {
        let leap = date.year.is_multiple_of(4)
            && (!date.year.is_multiple_of(100) || date.year.is_multiple_of(400));
        let days = match date.month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 => {
                if leap {
                    29
                } else {
                    28
                }
            }
            _ => return Err(invalid()),
        };
        if !(1..=9999).contains(&date.year)
            || !(1..=days).contains(&date.day)
            || time.hour > 23
            || time.minute > 59
            || time.second > 60
        {
            return Err(invalid());
        }
        Ok(Self { date, time })
    }
    pub(crate) fn date(self) -> Date {
        self.date
    }
    pub(crate) fn time(self) -> Time {
        self.time
    }
    pub(crate) fn utc_seconds(self) -> i64 {
        fn days_before_year(year: i64) -> i64 {
            let completed = year - 1;
            365 * completed + completed / 4 - completed / 100 + completed / 400
        }
        let preceding = [0i64, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
        let year = i64::from(self.date.year);
        let leap = self.date.month > 2 && year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let days = days_before_year(year) - days_before_year(1970)
            + preceding[usize::from(self.date.month) - 1]
            + i64::from(leap)
            + i64::from(self.date.day)
            - 1;
        days * 86400
            + i64::from(self.time.hour) * 3600
            + i64::from(self.time.minute) * 60
            + i64::from(self.time.second)
    }
}
pub(crate) fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid calendar date")
}

pub(crate) struct Cursor<'input> {
    pub(crate) input: &'input [u16],
    pub(crate) at: usize,
}
impl Cursor<'_> {
    pub(crate) fn number(&mut self, digits: usize) -> io::Result<u16> {
        let start = self.at;
        let mut value = 0;
        while self.at - start < digits {
            let Some(digit) = self
                .input
                .get(self.at)
                .and_then(|unit| unit.checked_sub(u16::from(b'0')))
                .filter(|unit| *unit <= 9)
            else {
                break;
            };
            value = value * 10 + digit;
            self.at += 1;
        }
        if start == self.at {
            return Err(invalid());
        }
        Ok(value)
    }
    pub(crate) fn literal(&mut self, byte: u8) -> io::Result<()> {
        if self.input.get(self.at) != Some(&u16::from(byte)) {
            return Err(invalid());
        }
        self.at += 1;
        Ok(())
    }
    pub(crate) fn spaces(&mut self) -> bool {
        let start = self.at;
        while self
            .input
            .get(self.at)
            .is_some_and(|unit| char::from_u32(u32::from(*unit)).is_some_and(char::is_whitespace))
        {
            self.at += 1;
        }
        self.at != start
    }
    pub(crate) fn end(&self) -> bool {
        self.at == self.input.len()
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "NLS field boundaries and independent Gregorian epoch fixtures must agree before native conversion"
    )]
    use super::*;
    #[test]
    fn bounded_native_fields_keep_epoch_and_leap_validation() -> io::Result<()> {
        for (year, month, day, seconds) in [
            (1, 1, 1, -62_135_596_800),
            (1970, 1, 1, 0),
            (2000, 2, 29, 951_782_400),
            (9999, 1, 1, 253_370_764_800),
        ] {
            let date = Date { year, month, day };
            let value = Fields::new(date, Time::default())?;
            assert_eq!(value.date(), date);
            assert_eq!(value.time(), Time::default());
            assert_eq!(value.utc_seconds(), seconds);
        }
        assert!(
            Fields::new(
                Date {
                    year: 2100,
                    month: 2,
                    day: 29
                },
                Time::default()
            )
            .is_err()
        );
        Ok(())
    }
}
