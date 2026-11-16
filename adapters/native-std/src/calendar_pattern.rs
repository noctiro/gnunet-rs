//! Bounded Windows NLS picture matching, independent of native locale ownership.
use crate::calendar_fields::{Date, Fields, Time};
use std::io;
mod hebrew;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Word {
    Month,
    Weekday,
    Meridian,
    ShortMeridian,
    Era,
    FirstYear,
}
pub(crate) trait Names {
    fn prefix(
        &self,
        input: &[u16],
        kind: Word,
        budget: &mut Budget,
    ) -> io::Result<Option<(u16, usize)>>;
}

/// One budget spans every date/time alternative, including failed matches.
pub(crate) struct Budget(usize);
impl Budget {
    pub(crate) fn new() -> Self {
        Self(262_144)
    }
    pub(crate) fn charge(&mut self, units: usize) -> io::Result<()> {
        self.0 = self.0.checked_sub(units).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "date matching work limit exceeded",
            )
        })?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Parsed {
    year: Option<u16>,
    month: Option<u16>,
    day: Option<u16>,
    hour: Option<u16>,
    minute: Option<u16>,
    second: Option<u16>,
    meridian: Option<u16>,
    era: Option<u16>,
    named_month: bool,
    short_year: bool,
    twelve_hour: bool,
    hebrew_numbers: bool,
}
/// Syntactically complete calendar components; calendar-specific validity is
/// checked by the selected calendar rather than assuming Gregorian month rules.
pub(crate) struct Components {
    pub(crate) date: Date,
    pub(crate) time: Time,
    pub(crate) era: Option<u16>,
    pub(crate) named_month: bool,
}
impl Parsed {
    pub(crate) fn hebrew() -> Self {
        Self {
            hebrew_numbers: true,
            ..Self::default()
        }
    }
    pub(crate) fn fields(self, year_max: u16) -> io::Result<Fields> {
        let parts = self.components(year_max)?;
        Fields::new(parts.date, parts.time)
    }
    pub(crate) fn components(self, year_max: u16) -> io::Result<Components> {
        let mut year = self.year.ok_or_else(crate::calendar_fields::invalid)?;
        if self.short_year {
            year += (year_max / 100) * 100;
            if year > year_max {
                year = year
                    .checked_sub(100)
                    .ok_or_else(crate::calendar_fields::invalid)?;
            }
        }
        let mut hour = self.hour.unwrap_or(0);
        if self.twelve_hour {
            if !(1..=12).contains(&hour) {
                return Err(crate::calendar_fields::invalid());
            }
            hour %= 12;
            hour += self.meridian.unwrap_or(0) * 12;
        } else if self.meridian.is_some() {
            return Err(crate::calendar_fields::invalid());
        }
        let date = Date {
            year,
            month: self.month.ok_or_else(crate::calendar_fields::invalid)?,
            day: self.day.ok_or_else(crate::calendar_fields::invalid)?,
        };
        let time = Time {
            hour,
            minute: self.minute.unwrap_or(0),
            second: self.second.unwrap_or(0),
        };
        if date.year == 0
            || !(1..=13).contains(&date.month)
            || !(1..=31).contains(&date.day)
            || time.hour > 23
            || time.minute > 59
            || time.second > 60
        {
            return Err(crate::calendar_fields::invalid());
        }
        Ok(Components {
            date,
            time,
            era: self.era,
            named_month: self.named_month,
        })
    }
}

fn assign(slot: &mut Option<u16>, value: u16) -> Option<()> {
    if slot.is_some_and(|previous| previous != value) {
        return None;
    }
    *slot = Some(value);
    Some(())
}
fn space(unit: u16) -> bool {
    char::from_u32(u32::from(unit)).is_some_and(char::is_whitespace)
}
pub(crate) fn skip_spaces(input: &[u16], at: &mut usize) -> usize {
    let first = *at;
    while input.get(*at).is_some_and(|unit| space(*unit)) {
        *at += 1;
    }
    *at - first
}
fn year_length(
    pattern: &[u16],
    mut position: usize,
    input: &[u16],
    budget: &mut Budget,
) -> io::Result<Option<usize>> {
    let mut reserved = 0;
    while let Some(&unit) = pattern.get(position) {
        budget.charge(1)?;
        if !matches!(unit, 77 | 100 | 72 | 104 | 109 | 115) {
            // A following numeric literal cannot choose the year's extra digit.
            if (48..=57).contains(&unit)
                || (unit == 39
                    && pattern
                        .get(position + 1)
                        .is_some_and(|u| (48..=57).contains(u)))
            {
                return Ok(Some(4));
            }
            break;
        }
        let first = position;
        while pattern.get(position) == Some(&unit) {
            budget.charge(1)?;
            position += 1;
        }
        match position - first {
            2 => reserved += 2,
            1 => return Ok(Some(4)), // Adjacent variable-width fields retain the fixed-year choice.
            _ => break,              // A month/weekday name ends the decimal run.
        }
    }
    if reserved == 0 {
        return Ok(Some(5));
    }
    let mut digits = 0;
    while input.get(digits).is_some_and(|u| (48..=57).contains(u)) {
        budget.charge(1)?;
        digits += 1;
        if digits > reserved + 5 {
            return Ok(None);
        }
    }
    Ok(digits
        .checked_sub(reserved)
        .filter(|digits| (3..=5).contains(digits)))
}

/// Match one complete native picture against a prefix. No search or backtracking.
/// A mismatch is None; provider and resource failures retain their error domain.
pub(crate) fn matches(
    pattern: &[u16],
    input: &[u16],
    initial: Parsed,
    names: &impl Names,
    budget: &mut Budget,
) -> io::Result<Option<(Parsed, usize)>> {
    let mut result = initial;
    let mut at = 0;
    let mut position = 0;
    let mut quoted = false;
    while let Some(&unit) = pattern.get(position) {
        budget.charge(1)?;
        position += 1;
        if unit == u16::from(b'\'') {
            if pattern.get(position) == Some(&unit) {
                position += 1;
                if input.get(at) != Some(&unit) {
                    return Ok(None);
                }
                at += 1;
            } else {
                quoted = !quoted;
            }
            continue;
        }
        if space(unit) {
            if !input.get(at).is_some_and(|unit| space(*unit)) {
                return Ok(None);
            }
            budget.charge(skip_spaces(input, &mut at))?;
            continue;
        }
        let token = u8::try_from(unit).ok();
        if quoted
            || !matches!(
                token,
                Some(b'd' | b'M' | b'y' | b'H' | b'h' | b'm' | b's' | b't' | b'g')
            )
        {
            if input.get(at) != Some(&unit) {
                return Ok(None);
            }
            at += 1;
            continue;
        }
        let start = position - 1;
        while pattern.get(position) == Some(&unit) {
            position += 1;
        }
        let width = position - start;
        budget.charge(width)?;
        let kind = match token {
            Some(b'M') if width >= 3 => Some(Word::Month),
            Some(b'd') if width >= 3 => Some(Word::Weekday),
            Some(b't') if width == 1 => Some(Word::ShortMeridian),
            Some(b't') => Some(Word::Meridian),
            Some(b'g') => Some(Word::Era),
            _ => None,
        };
        if let Some(kind) = kind {
            // A native prefix operation can inspect the entire remaining input.
            let Some((value, length)) = names.prefix(&input[at..], kind, budget)? else {
                return Ok(None);
            };
            if length > input.len() - at || (length == 0 && kind != Word::Era) {
                return Err(io::ErrorKind::InvalidData.into());
            }
            at += length;
            let assigned = match kind {
                Word::Month => {
                    result.named_month = true;
                    assign(&mut result.month, value)
                }
                Word::Meridian | Word::ShortMeridian => assign(&mut result.meridian, value),
                Word::Era => assign(&mut result.era, value),
                Word::Weekday => Some(()),
                Word::FirstYear => return Err(io::ErrorKind::InvalidData.into()),
            };
            if assigned.is_none() {
                return Ok(None);
            }
            continue;
        }
        if token == Some(b'y')
            && let Some((year, length)) = names.prefix(&input[at..], Word::FirstYear, budget)?
        {
            if year != 1 || length == 0 || length > input.len() - at {
                return Err(io::ErrorKind::InvalidData.into());
            }
            if assign(&mut result.year, year).is_none() {
                return Ok(None);
            }
            result.short_year = false;
            at += length;
            continue;
        }
        if result.hebrew_numbers
            && matches!(token, Some(b'y' | b'M' | b'd'))
            && let Some((mut value, length)) = hebrew::prefix(&input[at..], budget)?
        {
            let slot = match token {
                Some(b'y') => {
                    // Native Hebrew year numerals omit the five-thousand prefix.
                    value += 5000;
                    result.short_year = false;
                    &mut result.year
                }
                Some(b'M') => &mut result.month,
                Some(b'd') => &mut result.day,
                _ => return Err(io::ErrorKind::InvalidData.into()),
            };
            if assign(slot, value).is_none() {
                return Ok(None);
            }
            at += length;
            continue;
        }
        let limit = if token == Some(b'y') && width >= 3 {
            let Some(length) = year_length(pattern, position, &input[at..], budget)? else {
                return Ok(None);
            };
            length
        } else {
            2
        };
        let mut value = 0u32;
        let first = at;
        while at - first < limit {
            let Some(digit) = input
                .get(at)
                .and_then(|unit| unit.checked_sub(u16::from(b'0')))
                .filter(|digit| *digit <= 9)
            else {
                break;
            };
            value = value * 10 + u32::from(digit);
            at += 1;
        }
        if at == first || (width >= 3 && token == Some(b'y') && at - first < width) {
            return Ok(None);
        }
        let Ok(value) = u16::try_from(value) else {
            return Ok(None);
        };
        let slot = match token {
            Some(b'y') => {
                result.short_year = width <= 2;
                &mut result.year
            }
            Some(b'M') => &mut result.month,
            Some(b'd') => &mut result.day,
            Some(b'H' | b'h') => {
                result.twelve_hour = token == Some(b'h');
                &mut result.hour
            }
            Some(b'm') => &mut result.minute,
            Some(b's') => &mut result.second,
            _ => return Err(io::ErrorKind::InvalidData.into()),
        };
        if assign(slot, value).is_none() {
            return Ok(None);
        }
    }
    if quoted {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unterminated native date literal",
        ));
    }
    Ok(Some((result, at)))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "Tests unwrap only fixed valid fixtures and assert malformed cases explicitly"
)]
mod tests {
    use super::*;
    struct English;
    impl Names for English {
        fn prefix(
            &self,
            input: &[u16],
            kind: Word,
            budget: &mut Budget,
        ) -> io::Result<Option<(u16, usize)>> {
            budget.charge(input.len())?;
            let candidates: &[(u16, &str)] = match kind {
                Word::Month => &[(3, "March"), (3, "Mar")],
                Word::Weekday => &[(5, "Friday")],
                Word::Meridian => &[(0, "AM"), (1, "PM")],
                Word::ShortMeridian => &[(0, "A"), (1, "P")],
                Word::Era => &[(0, "AD"), (5, "Reiwa")],
                Word::FirstYear => &[(1, "元")],
            };
            Ok(candidates.iter().find_map(|(value, text)| {
                let text: Vec<_> = text.encode_utf16().collect();
                input.starts_with(&text).then_some((*value, text.len()))
            }))
        }
    }
    fn parse(pattern: &str, input: &str, maximum: u16) -> Option<Fields> {
        let pattern: Vec<_> = pattern.encode_utf16().collect();
        let input: Vec<_> = input.encode_utf16().collect();
        let (parsed, length) = matches(
            &pattern,
            &input,
            Parsed::default(),
            &English,
            &mut Budget::new(),
        )
        .unwrap()?;
        (length == input.len())
            .then(|| parsed.fields(maximum).ok())
            .flatten()
    }
    #[test]
    fn localized_pictures_and_native_year_window() {
        let expected = Fields::new(
            Date {
                year: 2024,
                month: 3,
                day: 1,
            },
            Time {
                hour: 12,
                minute: 34,
                second: 56,
            },
        )
        .unwrap();
        assert_eq!(
            parse(
                "dddd, d MMMM yyyy h:mm:ss tt",
                "Friday, 1 March 2024 12:34:56 PM",
                2049
            )
            .unwrap()
            .utc_seconds(),
            expected.utc_seconds()
        );
        assert_eq!(
            parse("yyyy-MM-dd h:mm:ss tt", "2024-03-01 12:34:56 PM", 2049)
                .unwrap()
                .utc_seconds(),
            expected.utc_seconds()
        );
        assert_eq!(
            parse("dd/MM/yy", "01/03/49", 2049).unwrap().date().year,
            2049
        );
        assert_eq!(
            parse("dd/MM/yy", "01/03/50", 2049).unwrap().date().year,
            1950
        );
        assert_eq!(
            parse(
                "yyyy年M月d日 'o''clock' h:mm t",
                "2024年3月1日 o'clock 12:00 A",
                2049
            )
            .unwrap()
            .time()
            .hour,
            0
        );
    }
    #[test]
    fn complete_valid_fields_and_finite_work() {
        for input in ["31/02/24", "01/03/24 extra", "01/03/24\0", "00/03/24"] {
            assert!(parse("dd/MM/yy", input, 2049).is_none(), "{input:?}");
        }
        assert!(parse("dd/MM/yyyy h:mm tt", "01/03/2024 13:00 AM", 2049).is_none());
        let mut budget = Budget(0);
        assert!(
            matches(
                &[u16::from(b'd')],
                &[],
                Parsed::default(),
                &English,
                &mut budget
            )
            .is_err()
        );
    }
    #[test]
    fn native_calendar_parts_preserve_era_and_non_gregorian_months() {
        let picture: Vec<_> = "g y/M/d".encode_utf16().collect();
        let input: Vec<_> = "Reiwa 元/5/1".encode_utf16().collect();
        let (parsed, used) = matches(
            &picture,
            &input,
            Parsed::default(),
            &English,
            &mut Budget::new(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(used, input.len());
        let parts = parsed.components(99).unwrap();
        assert_eq!(parts.era, Some(5));
        assert_eq!(parts.date.year, 1);
        assert!(!parts.named_month);
        for (text, expected_year, expected_month) in
            [("5784/13/30", 5784, 13), ("10542/12/31", 10542, 12)]
        {
            let input: Vec<_> = text.encode_utf16().collect();
            let pattern: Vec<_> = "yyyy/MM/dd".encode_utf16().collect();
            let (parsed, used) = matches(
                &pattern,
                &input,
                Parsed::default(),
                &English,
                &mut Budget::new(),
            )
            .unwrap()
            .unwrap();
            assert_eq!(used, input.len());
            let parts = parsed.components(2049).unwrap();
            assert_eq!(
                (parts.date.year, parts.date.month),
                (expected_year, expected_month)
            );
            assert!(parsed.fields(2049).is_err());
        }
        let input: Vec<_> = "1 March 2024".encode_utf16().collect();
        let pattern: Vec<_> = "d MMMM yyyy".encode_utf16().collect();
        let (parsed, _) = matches(
            &pattern,
            &input,
            Parsed::default(),
            &English,
            &mut Budget::new(),
        )
        .unwrap()
        .unwrap();
        assert!(parsed.components(2049).unwrap().named_month);
        assert!(parse("yyyy/MM/dd", "65536/01/01", 2049).is_none());
        assert_eq!(
            parse("yyyyMMdd", "20240301", 2049).unwrap().date(),
            Date {
                year: 2024,
                month: 3,
                day: 1
            }
        );
        let picture: Vec<_> = "yyyyMMdd".encode_utf16().collect();
        let input: Vec<_> = "105421231".encode_utf16().collect();
        let (parsed, used) = matches(
            &picture,
            &input,
            Parsed::default(),
            &English,
            &mut Budget::new(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(used, input.len());
        assert_eq!(
            parsed.components(2049).unwrap().date,
            Date {
                year: 10542,
                month: 12,
                day: 31
            }
        );
    }
    #[test]
    fn hebrew_date_numbers_keep_the_native_year_and_numeric_month() {
        let input: Vec<_> = "ט״ו/ח׳/תשפ״ד".encode_utf16().collect();
        let picture: Vec<_> = "dd/MM/yyyy".encode_utf16().collect();
        let (parsed, used) = matches(
            &picture,
            &input,
            Parsed::hebrew(),
            &English,
            &mut Budget::new(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(used, input.len());
        let parts = parsed.components(5790).unwrap();
        assert_eq!(
            parts.date,
            Date {
                year: 5784,
                month: 8,
                day: 15
            }
        );
        assert!(!parts.named_month);
        assert!(
            matches(
                &picture,
                &input,
                Parsed::default(),
                &English,
                &mut Budget::new()
            )
            .unwrap()
            .is_none()
        );
    }
}
