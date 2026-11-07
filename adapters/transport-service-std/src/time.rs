//! Actual independent native scheduling / canonical absolute clock adapter.
//! Original operation Bounds stay immutable through corrections and retries.
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_transport::Times;
use gnunet_types::{Error, MonoInstant};
use std::{sync::Arc, time::Duration};
use tokio::time::Instant;
/// One fixed original operation's independent targets.
#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    /// Actual canonical Unix target.
    pub expires: u64,
    /// Actual monotonic target, never reminted.
    pub hard: Instant,
}
impl Bounds {
    /// Mint once at actual admission, never while retrying.
    pub fn after(now: u64, d: Duration) -> Result<Self, Error> {
        let us = u64::try_from(d.as_micros()).map_err(|_| Error::Overflow)?;
        if us == 0 {
            return Err(Error::Deadline);
        }
        Ok(Self {
            expires: now
                .checked_add(us)
                .filter(|n| *n != u64::MAX)
                .ok_or(Error::Overflow)?,
            hard: Instant::now().checked_add(d).ok_or(Error::Overflow)?,
        })
    }
    /// Test actual original targets without changing either.
    pub fn live(self, now: u64) -> bool {
        now < self.expires && Instant::now() < self.hard
    }
}
/// One explicit native monotonic epoch plus the actual canonical absolute
/// clock port. Logical/absolute corrections never become scheduling elapsed
/// time or reset a previously captured original native deadline.
#[derive(Clone)]
pub struct Clock {
    clock: Arc<dyn RuntimeClock>,
    anchor: Instant,
    last_monotonic: u64,
}
impl Clock {
    /// Bind one immutable native anchor. No service/native owner is created.
    /// The initial absolute sample must be a finite actual port observation;
    /// later revisions/corrections are accepted through fresh real samples.
    pub fn new(clock: Arc<dyn RuntimeClock>) -> Result<Self, Error> {
        let anchor = Instant::now();
        Times::new(MonoInstant(0), clock.sample()?.now).validate()?;
        Ok(Self {
            clock,
            anchor,
            last_monotonic: 0,
        })
    }
    /// Exact source for the caller's shared CLIENT clock/Resolver context.
    pub fn source(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    /// Map an already captured original local monotonic target to this exact
    /// native anchor. This does not use or project wall/absolute time.
    pub fn native_bound(&self, target: MonoInstant) -> Result<Instant, Error> {
        self.anchor
            .checked_add(Duration::from_micros(target.0))
            .ok_or(Error::Overflow)
    }
    /// Sample nondecreasing native elapsed microseconds and independent actual
    /// GNUnet logical absolute time. No wall/native offset projection or revision
    /// rejection exists; a real port error is returned without invented UTC.
    pub fn sample(&mut self) -> Result<Times, Error> {
        let elapsed = Instant::now()
            .checked_duration_since(self.anchor)
            .ok_or(Error::TimeUncertain)?;
        let mono = u64::try_from(elapsed.as_micros()).map_err(|_| Error::Overflow)?;
        if mono < self.last_monotonic {
            return Err(Error::TimeUncertain);
        }
        let absolute = self.clock.sample()?.now;
        let times = Times::new(MonoInstant(mono), absolute);
        times.validate()?;
        self.last_monotonic = mono;
        Ok(times)
    }
}
