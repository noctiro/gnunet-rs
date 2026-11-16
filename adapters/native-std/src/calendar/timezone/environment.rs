//! The documented Microsoft TZ grammar, with U.S. default daylight transitions.
use super::{Day, Rules, Transition};
use std::io;
pub(in super::super) struct Environment {
    standard: i32,
    names: [Vec<u16>; 2],
}
impl Environment {
    pub fn parse(input: &[u16]) -> io::Result<Self> {
        if !(4..=128).contains(&input.len())
            || !input[..3]
                .iter()
                .all(|unit| (65..=90).contains(unit) || (97..=122).contains(unit))
        {
            return Err(invalid());
        }
        let mut at = 3;
        let sign = match input.get(at).copied() {
            Some(43) => {
                at += 1;
                1
            }
            Some(45) => {
                at += 1;
                -1
            }
            _ => 1,
        };
        let hour = number(input, &mut at)?;
        let mut minute = 0;
        let mut second = 0;
        if input.get(at) == Some(&58) {
            at += 1;
            minute = number(input, &mut at)?;
            if input.get(at) == Some(&58) {
                at += 1;
                second = number(input, &mut at)?;
            }
        }
        if hour > 24 || minute > 59 || second > 59 || hour == 24 && minute + second != 0 {
            return Err(invalid());
        }
        let daylight = &input[at..];
        if !daylight.is_empty()
            && (daylight.len() != 3
                || !daylight
                    .iter()
                    .all(|unit| (65..=90).contains(unit) || (97..=122).contains(unit)))
        {
            return Err(invalid());
        }
        Ok(Self {
            standard: -sign * (hour * 3600 + minute * 60 + second),
            names: [input[..3].to_vec(), daylight.to_vec()],
        })
    }
    pub fn rules(&self, year: i32) -> (Rules, [Vec<u16>; 2]) {
        let transitions = if self.names[1].is_empty() {
            None
        } else {
            let transition = |month, week| Transition {
                day: Day::Annual {
                    month,
                    week,
                    weekday: 0,
                },
                seconds: 7200,
                milliseconds: 0,
            };
            Some(if year >= 2007 {
                (transition(3, 2), transition(11, 1))
            } else {
                (transition(4, 1), transition(10, 5))
            })
        };
        (
            Rules {
                standard: self.standard,
                daylight: self.standard + if transitions.is_some() { 3600 } else { 0 },
                transitions,
            },
            self.names.clone(),
        )
    }
}
fn number(input: &[u16], at: &mut usize) -> io::Result<i32> {
    let start = *at;
    let mut value = 0;
    while *at - start < 2 {
        let Some(digit) = input
            .get(*at)
            .and_then(|unit| unit.checked_sub(48))
            .filter(|digit| *digit < 10)
        else {
            break;
        };
        value = value * 10 + i32::from(digit);
        *at += 1;
    }
    if *at == start {
        Err(invalid())
    } else {
        Ok(value)
    }
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid Microsoft TZ specification",
    )
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Named Microsoft TZ fixtures cover fractional offsets, default daylight boundaries and malformed input"
    )]
    use super::*;
    #[cfg(windows)]
    use crate::calendar::civil::Civil;
    #[cfg(unix)]
    use crate::calendar_model::civil::Civil;
    #[test]
    fn explicit_names_offsets_and_annual_rules_keep_original_selection() -> io::Result<()> {
        let parse = |text: &str| Environment::parse(&text.encode_utf16().collect::<Vec<_>>());
        let (fixed, names) = parse("NST3:30:30")?.rules(12024);
        assert_eq!(fixed.standard, -12630);
        assert!(fixed.transitions.is_none());
        assert_eq!(names[0], "NST".encode_utf16().collect::<Vec<_>>());
        let (east, _) = parse("UTC-8")?.rules(1);
        assert_eq!(east.standard, 28800);
        let environment = parse("EST5EDT")?;
        let (future, _) = environment.rules(12024);
        assert!(
            future
                .at_utc(Civil::new(12024, 3, 20, 12, 0, 0)?.epoch(), 12024)?
                .daylight
        );
        let (legacy, _) = environment.rules(2006);
        assert!(
            !legacy
                .at_utc(Civil::new(2006, 3, 20, 12, 0, 0)?.epoch(), 2006)?
                .daylight
        );
        for text in [
            "",
            "UTC",
            "UTC25",
            "UTC0:60",
            "UTC24:01",
            "UTC0D",
            "UTC0\0",
            "Europe/Berlin",
            "UTC0EDT,trailing",
        ] {
            assert!(parse(text).is_err(), "{text}");
        }
        Ok(())
    }
}
