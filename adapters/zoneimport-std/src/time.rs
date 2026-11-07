//! One process clock and immutable native epoch; operation budgets never renew.
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error;
use gnunet_wire::official::AbsoluteTime;
use gnunet_zoneimport_core::{Bounds, MonoInstant, Times};
use std::{future::Future, pin::Pin, sync::Arc, task::Context, time::Duration};
use tokio::time::{Instant, Sleep};

/// The same original RuntimeClock used by all real CLIENT/Resolver owners.
pub struct Clock {
    source: Arc<dyn RuntimeClock>,
    epoch: Instant,
}
impl Clock {
    /// Capture the native epoch once, before any owned importer operation.
    pub fn new(source: Arc<dyn RuntimeClock>) -> Self {
        Self {
            source,
            epoch: Instant::now(),
        }
    }
    /// Clone only the same process-shared source, not another clock or driver.
    pub fn source(&self) -> Arc<dyn RuntimeClock> {
        self.source.clone()
    }
    /// Map an original core monotonic target into the same native domain.
    pub fn native(&self, target: MonoInstant) -> Result<Instant, Error> {
        self.epoch
            .checked_add(Duration::from_micros(target.as_micros()))
            .ok_or(Error::Overflow)
    }
    /// Sample actual canonical time and same-epoch monotonic time separately.
    pub fn sample(&self) -> Result<Times, Error> {
        let absolute = self.source.sample()?.now;
        let elapsed = Instant::now()
            .checked_duration_since(self.epoch)
            .ok_or(Error::Stale)?;
        Ok(Times {
            absolute,
            mono: MonoInstant::from_micros(
                u64::try_from(elapsed.as_micros()).map_err(|_| Error::Overflow)?,
            ),
        })
    }
}
/// One immutable original canonical/native operation budget.
pub struct Budget {
    /// Original logical target, passed unchanged to actual CLIENT admission.
    pub until: u64,
    /// Original native hard, including all local queue/IO/capacity waits.
    pub hard: Instant,
    alarm: Pin<Box<Sleep>>,
}
impl Budget {
    /// Establish one finite initial operation budget, native bound first.
    pub fn new(clock: &Clock, lifetime: Duration) -> Result<Self, Error> {
        if lifetime.is_zero() {
            return Err(Error::InvalidInput);
        }
        let hard = Instant::now()
            .checked_add(lifetime)
            .ok_or(Error::Overflow)?;
        let now = clock.sample()?.absolute.as_micros();
        let until = now
            .checked_add(u64::try_from(lifetime.as_micros()).map_err(|_| Error::Overflow)?)
            .filter(|value| *value != u64::MAX)
            .ok_or(Error::Overflow)?;
        let budget = Self {
            until,
            hard,
            alarm: Box::pin(tokio::time::sleep_until(hard)),
        };
        budget.check(clock)?;
        Ok(budget)
    }
    /// Adopt the original pure-core targets using the immutable native epoch.
    pub fn from_targets(
        clock: &Clock,
        until: AbsoluteTime,
        hard: MonoInstant,
    ) -> Result<Self, Error> {
        if until.as_micros() == u64::MAX {
            return Err(Error::InvalidInput);
        }
        let hard = clock.native(hard)?;
        let budget = Self {
            until: until.as_micros(),
            hard,
            alarm: Box::pin(tokio::time::sleep_until(hard)),
        };
        budget.check(clock)?;
        Ok(budget)
    }
    /// Adopt one actual pure-core job's fixed original bounds.
    pub fn from_bounds(clock: &Clock, original: Bounds) -> Result<Self, Error> {
        Self::from_targets(clock, original.expires, original.until)
    }
    /// Native check/registration before any outer canonical or provider wait.
    pub fn native_guard(&mut self, cx: &mut Context<'_>) -> Result<(), Error> {
        if Instant::now() >= self.hard || self.alarm.as_mut().poll(cx).is_ready() {
            Err(Error::Deadline)
        } else {
            Ok(())
        }
    }
    /// Check around the actual canonical sample; it cannot extend native life.
    pub fn check(&self, clock: &Clock) -> Result<(), Error> {
        if Instant::now() >= self.hard {
            return Err(Error::Deadline);
        }
        let now = clock.sample()?.absolute.as_micros();
        if Instant::now() >= self.hard || now >= self.until {
            return Err(Error::Deadline);
        }
        Ok(())
    }
}
