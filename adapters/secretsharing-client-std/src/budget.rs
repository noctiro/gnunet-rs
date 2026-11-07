use crate::Error;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as Fault;
use std::{
    future::Future,
    pin::Pin,
    task::Context,
    time::{Duration, Instant},
};
use tokio::time::Sleep;

/// Original canonical and independent native targets, not reset by retry or IO.
#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    /// Original canonical microsecond target.
    pub expires: u64,
    /// Original monotonic native target.
    pub hard: Instant,
}
impl Bounds {
    /// Capture native first and sample only the explicit original shared clock.
    pub fn new(clock: &dyn RuntimeClock, life: Duration) -> Result<Self, Error> {
        let start = Instant::now();
        if life.is_zero() || life.as_micros() >= u128::from(u64::MAX) {
            return Err(Fault::InvalidInput.into());
        }
        let hard = start.checked_add(life).ok_or(Fault::Overflow)?;
        let now = clock.sample()?.now.as_micros();
        if Instant::now() >= hard {
            return Err(Fault::Deadline.into());
        }
        let expires = now
            .checked_add(u64::try_from(life.as_micros()).map_err(|_| Fault::Overflow)?)
            .filter(|n| *n != u64::MAX)
            .ok_or(Fault::Overflow)?;
        Ok(Self { expires, hard })
    }
    /// Recheck original native both before and after a canonical clock sample.
    pub fn check(self, clock: &dyn RuntimeClock) -> Result<(), Error> {
        if self.expires == u64::MAX {
            return Err(Fault::InvalidInput.into());
        }
        if Instant::now() >= self.hard {
            return Err(Fault::Deadline.into());
        }
        let now = clock.sample()?.now.as_micros();
        if Instant::now() >= self.hard || now >= self.expires {
            return Err(Fault::Deadline.into());
        }
        Ok(())
    }
}
pub(crate) struct Bound {
    pub targets: Bounds,
    alarm: Pin<Box<Sleep>>,
}
impl Bound {
    pub fn new(targets: Bounds) -> Self {
        Self {
            alarm: Box::pin(tokio::time::sleep_until(targets.hard.into())),
            targets,
        }
    }
    pub fn phase(
        clock: &dyn RuntimeClock,
        life: Duration,
        original: Bounds,
    ) -> Result<Self, Error> {
        let mut targets = Bounds::new(clock, life)?;
        targets.hard = targets.hard.min(original.hard);
        targets.expires = targets.expires.min(original.expires);
        targets.check(clock)?;
        Ok(Self::new(targets))
    }
    pub fn native(&mut self, cx: &mut Context<'_>) -> bool {
        Instant::now() >= self.targets.hard || self.alarm.as_mut().poll(cx).is_ready()
    }
}
