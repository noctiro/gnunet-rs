//! Immutable original logical/native targets, with lazy native timers.
use crate::Error;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as Fault;
use std::time::{Duration, Instant};
/// Original caller bound. A target is not an operation/source capability.
#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    /// Original canonical absolute microseconds.
    pub expires: u64,
    /// Original native hard target, never renewed by retries or partial IO.
    pub hard: Instant,
}
impl Bounds {
    /// Capture native first and then the actual shared canonical clock.
    pub fn new(clock: &dyn RuntimeClock, life: Duration) -> Result<Self, Error> {
        let start = Instant::now();
        let us = u64::try_from(life.as_micros()).map_err(|_| Fault::Overflow)?;
        if us == 0 || us == u64::MAX {
            return Err(Fault::InvalidInput.into());
        }
        let hard = start.checked_add(life).ok_or(Fault::Overflow)?;
        let now = clock.sample()?.now.as_micros();
        let expires = now
            .checked_add(us)
            .filter(|v| *v != u64::MAX)
            .ok_or(Fault::Overflow)?;
        let b = Self { expires, hard };
        b.check(clock)?;
        Ok(b)
    }
    pub(crate) fn check(self, clock: &dyn RuntimeClock) -> Result<(), Error> {
        if Instant::now() >= self.hard {
            return Err(Fault::Deadline.into());
        }
        let now = clock.sample()?.now.as_micros();
        if Instant::now() >= self.hard || now >= self.expires {
            return Err(Fault::Deadline.into());
        }
        Ok(())
    }
    pub(crate) fn clamp(self, clock: &dyn RuntimeClock, expires: u64) -> Result<Self, Error> {
        let native = Instant::now();
        let now = clock.sample()?.now.as_micros();
        let expires = expires.min(self.expires);
        let life = expires
            .checked_sub(now)
            .filter(|n| *n != 0)
            .ok_or(Fault::Deadline)?;
        let hard = native
            .checked_add(Duration::from_micros(life))
            .ok_or(Fault::Overflow)?
            .min(self.hard);
        let b = Self { expires, hard };
        b.check(clock)?;
        Ok(b)
    }
}
pub(crate) struct Bound {
    pub target: Bounds,
}
impl Bound {
    pub fn new(target: Bounds) -> Self {
        Self { target }
    }
    pub fn phase(clock: &dyn RuntimeClock, life: Duration, overall: Bounds) -> Result<Self, Error> {
        let mut target = Bounds::new(clock, life)?;
        target.expires = target.expires.min(overall.expires);
        target.hard = target.hard.min(overall.hard);
        target.check(clock)?;
        Ok(Self::new(target))
    }
}
