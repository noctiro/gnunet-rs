//! One absolute preparation window, shared by crypto/files/process operations.
use crate::Cause;
use gnunet_program_host::{reporting::Reporter, shared_clock::SharedClock};
use gnunet_types::AbsoluteTime;
use std::{
    io,
    time::{Duration, Instant},
};

pub(super) struct Budget {
    clock: SharedClock,
    reporter: Reporter,
    hard: Instant,
    until: AbsoluteTime,
}
impl Budget {
    pub(super) fn new(clock: SharedClock, reporter: Reporter) -> Result<Self, Cause> {
        let duration = Duration::from_secs(120);
        let hard = Instant::now()
            .checked_add(duration)
            .ok_or("preparation deadline overflow")?;
        let now = clock.sample()?.now;
        let until = now
            .as_micros()
            .checked_add(120_000_000)
            .filter(|value| *value != u64::MAX)
            .ok_or("preparation canonical deadline overflow")?;
        let budget = Self {
            clock,
            reporter,
            hard,
            until: AbsoluteTime::from_micros(until),
        };
        budget.check()?;
        Ok(budget)
    }
    pub(super) fn check(&self) -> Result<(), Cause> {
        if Instant::now() >= self.hard {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original CA preparation window expired",
            )
            .into());
        }
        if self.reporter.failed() {
            return Err(io::Error::other("selected CA preparation logger failed").into());
        }
        let now = self.clock.sample()?.now;
        if Instant::now() >= self.hard || now >= self.until {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original CA preparation window expired",
            )
            .into());
        }
        Ok(())
    }
}
