//! Retained native calendar names and their linguistic prefix matching.
use super::super::{nls, prefix};
use super::{calendar_text, conversion::Conversion, locale_text};
use crate::calendar_pattern::{Budget, Names, Word};
use std::io;
use windows_sys::Win32::Globalization::{
    CAL_RETURN_GENITIVE_NAMES, CAL_SABBREVDAYNAME1, CAL_SABBREVMONTHNAME1, CAL_SDAYNAME1,
    CAL_SERASTRING, CAL_SMONTHNAME1, LOCALE_S1159, LOCALE_S2359,
};
mod eras;
struct Symbol {
    kind: Word,
    value: u16,
    text: Vec<u16>,
}
pub(super) struct Symbols {
    name: nls::Name,
    entries: Vec<Symbol>,
}
impl Names for Symbols {
    fn prefix(
        &self,
        input: &[u16],
        kind: Word,
        budget: &mut Budget,
    ) -> io::Result<Option<(u16, usize)>> {
        let mut matched = None;
        for entry in self.entries.iter().filter(|entry| entry.kind == kind) {
            budget.charge(input.len() + entry.text.len())?;
            let length = if entry.text.is_empty() {
                Some(0) // Native Gregorian pictures may contain an empty era.
            } else {
                prefix(&self.name, input, &entry.text)?
            };
            if let Some(length) = length
                && matched.is_none_or(|(_, previous)| length > previous)
            {
                matched = Some((entry.value, length));
            }
        }
        Ok(matched)
    }
}
impl Symbols {
    fn push(&mut self, kind: Word, value: u16, text: Vec<u16>) -> io::Result<()> {
        if self
            .entries
            .iter()
            .any(|entry| entry.kind == kind && entry.value == value && entry.text == text)
        {
            return Ok(());
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        self.entries.push(Symbol { kind, value, text });
        Ok(())
    }
}

impl Symbols {
    pub(super) fn load(
        name: &nls::Name,
        calendar: u32,
        conversion: Option<&Conversion>,
    ) -> io::Result<Self> {
        let mut symbols = Symbols {
            name: name.clone(),
            entries: Vec::new(),
        };
        let months = if calendar == windows_sys::Win32::Globalization::CAL_HEBREW {
            13
        } else {
            12
        };
        for month in 0..months {
            for base in [CAL_SMONTHNAME1, CAL_SABBREVMONTHNAME1] {
                for flags in [0, CAL_RETURN_GENITIVE_NAMES] {
                    let mut text = calendar_text(name, calendar, (base + month) | flags)?;
                    if text.is_empty() {
                        // NLS omits calendar names identical to locale metadata.
                        // Locale month thirteen is not contiguous with months 1..12.
                        use windows_sys::Win32::Globalization::{
                            LOCALE_SABBREVMONTHNAME1, LOCALE_SABBREVMONTHNAME13,
                            LOCALE_SMONTHNAME1, LOCALE_SMONTHNAME13,
                        };
                        let property = match (base == CAL_SMONTHNAME1, month) {
                            (true, 12) => LOCALE_SMONTHNAME13,
                            (false, 12) => LOCALE_SABBREVMONTHNAME13,
                            (true, _) => LOCALE_SMONTHNAME1 + month,
                            (false, _) => LOCALE_SABBREVMONTHNAME1 + month,
                        };
                        text = locale_text(name, property | flags)?;
                    }
                    if text.is_empty() {
                        continue;
                    }
                    symbols.push(Word::Month, month as u16 + 1, text)?;
                }
            }
        }
        for day in 0..7 {
            for base in [CAL_SDAYNAME1, CAL_SABBREVDAYNAME1] {
                let mut text = calendar_text(name, calendar, base + day)?;
                if text.is_empty() {
                    use windows_sys::Win32::Globalization::{
                        LOCALE_SABBREVDAYNAME1, LOCALE_SDAYNAME1,
                    };
                    let property = if base == CAL_SDAYNAME1 {
                        LOCALE_SDAYNAME1
                    } else {
                        LOCALE_SABBREVDAYNAME1
                    };
                    text = locale_text(name, property + day)?;
                }
                symbols.push(Word::Weekday, day as u16, text)?;
            }
        }
        if let Some(conversion) = conversion {
            eras::append(&mut symbols, name, calendar, conversion.eras())?;
        } else {
            symbols.push(Word::Era, 0, calendar_text(name, calendar, CAL_SERASTRING)?)?;
        }
        if calendar == windows_sys::Win32::Globalization::CAL_JAPAN {
            match calendar_text(
                name,
                calendar,
                windows_sys::Win32::Globalization::CAL_SJAPANESEERAFIRSTYEAR,
            ) {
                Ok(text)
                    if !text.is_empty() && !text.iter().all(|unit| (48..=57).contains(unit)) =>
                {
                    symbols.push(Word::FirstYear, 1, text)?;
                }
                Ok(_) => {} // Numeric ichinen already uses the ordinary year parser.
                Err(error) if error.raw_os_error() == Some(1004) => {} // SDK: old NLS without gannen uses ichinen.
                Err(error) => return Err(error),
            }
        }
        for (value, property) in [(0, LOCALE_S1159), (1, LOCALE_S2359)] {
            let text = locale_text(name, property)?;
            let first = text.first().copied().into_iter().collect();
            symbols.push(Word::ShortMeridian, value, first)?;
            symbols.push(Word::Meridian, value, text)?;
        }
        Ok(symbols)
    }
}
