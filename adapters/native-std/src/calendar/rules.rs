//! Native annual transition rules with explicit fold and gap resolution.
use super::civil::{self, Civil};
use std::io;
#[derive(Clone, Copy, Debug)]
pub(super) enum Day {
    Annual { month: u8, week: u8, weekday: u8 },
    Absolute { year: i32, month: u8, day: u8 },
}
#[derive(Clone, Copy, Debug)]
pub(super) struct Transition {
    pub day: Day,
    pub seconds: u32,
    pub milliseconds: u16,
}
impl Transition {
    fn local(self, year: i32) -> io::Result<Option<i64>> {
        if self.seconds >= 86_400 || self.milliseconds > 999 {
            return Err(civil::invalid());
        }
        let (month, day) = match self.day {
            Day::Annual {
                month,
                week,
                weekday,
            } => {
                if !(1..=5).contains(&week) || weekday > 6 {
                    return Err(civil::invalid());
                }
                let first = Civil::new(year, month, 1, 0, 0, 0)?;
                let mut day = 1 + (weekday + 7 - first.weekday) % 7 + 7 * (week - 1);
                let maximum = civil::month_days(year, month);
                if day > maximum {
                    day -= 7;
                }
                (month, day)
            }
            Day::Absolute {
                year: actual,
                month,
                day,
            } => {
                if actual != year {
                    return Ok(None);
                }
                (month, day)
            }
        };
        // The public calendar input is an integral Unix second, so a fractional
        // transition takes effect at the next representable second.
        Ok(Some(
            Civil::new(year, month, day, 0, 0, 0)?.epoch()
                + i64::from(self.seconds)
                + i64::from(self.milliseconds != 0),
        ))
    }
}
#[derive(Clone, Copy, Debug)]
pub(super) struct Rules {
    /// Seconds east of UTC; native Windows bias has the opposite sign.
    pub standard: i32,
    pub daylight: i32,
    pub transitions: Option<(Transition, Transition)>,
}
#[derive(Clone, Copy, Debug)]
pub(super) struct Local {
    pub civil: Civil,
    pub offset: i32,
    pub daylight: bool,
}
impl Rules {
    pub fn at_utc(self, seconds: i64, local_year: i32) -> io::Result<Local> {
        let daylight = match self.transitions {
            None => false,
            Some((start, end)) => match (start.local(local_year)?, end.local(local_year)?) {
                (Some(start), Some(end)) => {
                    let start = start - i64::from(self.standard);
                    let end = end - i64::from(self.daylight);
                    if start < end {
                        (start..end).contains(&seconds)
                    } else if start > end {
                        seconds >= start || seconds < end
                    } else {
                        false
                    }
                }
                (None, None) => false,
                _ => return Err(civil::invalid()),
            },
        };
        let offset = if daylight {
            self.daylight
        } else {
            self.standard
        };
        Ok(Local {
            civil: Civil::from_epoch(
                seconds
                    .checked_add(i64::from(offset))
                    .ok_or_else(civil::invalid)?,
            )?,
            offset,
            daylight,
        })
    }
    pub fn resolve_local(self, local: Civil) -> io::Result<i64> {
        let wall = local.epoch();
        // Windows chooses daylight time in an ambiguous fold. A skipped wall
        // time receives standard bias and consequently normalizes forward.
        if self.transitions.is_some() {
            let candidate = wall - i64::from(self.daylight);
            let roundtrip = self.at_utc(candidate, local.year)?;
            if roundtrip.civil == local && roundtrip.daylight {
                return Ok(candidate);
            }
        }
        Ok(wall - i64::from(self.standard))
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Independent transition fixtures assert spring gaps, autumn folds and opposite hemispheres"
    )]
    use super::*;
    fn transition(month: u8, week: u8, weekday: u8) -> Transition {
        Transition {
            day: Day::Annual {
                month,
                week,
                weekday,
            },
            seconds: 7200,
            milliseconds: 0,
        }
    }
    #[test]
    fn northern_rules_keep_exact_boundaries_and_windows_fold_policy() -> io::Result<()> {
        let rules = Rules {
            standard: -18000,
            daylight: -14400,
            transitions: Some((transition(3, 2, 0), transition(11, 1, 0))),
        };
        for (utc, expected, daylight) in [
            ("2024-03-10T06:59:59", "2024-03-10T01:59:59", false),
            ("2024-03-10T07:00:00", "2024-03-10T03:00:00", true),
            ("2024-11-03T05:59:59", "2024-11-03T01:59:59", true),
            ("2024-11-03T06:00:00", "2024-11-03T01:00:00", false),
        ] {
            let parse = |text: &str| {
                civil::iso(&text.encode_utf16().collect::<Vec<_>>())?.ok_or_else(civil::invalid)
            };
            let observed = rules.at_utc(parse(utc)?.epoch(), 2024)?;
            assert_eq!(observed.civil, parse(expected)?, "{utc}");
            assert_eq!(observed.daylight, daylight, "{utc}");
        }
        let fold = Civil::new(2024, 11, 3, 1, 30, 0)?;
        assert_eq!(
            rules.resolve_local(fold)?,
            Civil::new(2024, 11, 3, 5, 30, 0)?.epoch()
        );
        let gap = Civil::new(2024, 3, 10, 2, 30, 0)?;
        assert_eq!(
            rules.resolve_local(gap)?,
            Civil::new(2024, 3, 10, 7, 30, 0)?.epoch()
        );
        let mut fractional = transition(3, 2, 0);
        fractional.milliseconds = 500;
        let subsecond = Rules {
            transitions: Some((fractional, transition(11, 1, 0))),
            ..rules
        };
        assert!(
            !subsecond
                .at_utc(Civil::new(2024, 3, 10, 7, 0, 0)?.epoch(), 2024)?
                .daylight
        );
        assert!(
            subsecond
                .at_utc(Civil::new(2024, 3, 10, 7, 0, 1)?.epoch(), 2024)?
                .daylight
        );
        let no_interval = Rules {
            standard: 0,
            daylight: 0,
            transitions: Some((transition(3, 2, 0), transition(3, 2, 0))),
        };
        assert!(
            !no_interval
                .at_utc(Civil::new(2024, 7, 1, 0, 0, 0)?.epoch(), 2024)?
                .daylight
        );
        Ok(())
    }
    #[test]
    fn southern_and_fixed_zones_cover_large_and_negative_epochs() -> io::Result<()> {
        let southern = Rules {
            standard: 36000,
            daylight: 39600,
            transitions: Some((transition(10, 1, 0), transition(4, 1, 0))),
        };
        assert!(
            southern
                .at_utc(Civil::new(12024, 1, 1, 0, 0, 0)?.epoch(), 12024)?
                .daylight
        );
        assert!(
            !southern
                .at_utc(Civil::new(12024, 7, 1, 0, 0, 0)?.epoch(), 12024)?
                .daylight
        );
        let fixed = Rules {
            standard: 19800,
            daylight: 19800,
            transitions: None,
        };
        assert_eq!(
            fixed.at_utc(-1, 1970)?.civil,
            Civil::new(1970, 1, 1, 5, 29, 59)?
        );
        assert_eq!(fixed.at_utc(-1, 1970)?.offset, 19800);
        let absolute = |month| Transition {
            day: Day::Absolute {
                year: 2000,
                month,
                day: 1,
            },
            seconds: 0,
            milliseconds: 0,
        };
        let one_year = Rules {
            standard: 0,
            daylight: 3600,
            transitions: Some((absolute(3), absolute(4))),
        };
        assert!(
            one_year
                .at_utc(Civil::new(2000, 3, 15, 0, 0, 0)?.epoch(), 2000)?
                .daylight
        );
        assert!(
            !one_year
                .at_utc(Civil::new(2001, 3, 15, 0, 0, 0)?.epoch(), 2001)?
                .daylight
        );
        Ok(())
    }
}
