//! Once-captured original operation/source targets; no phase silently renews them.
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
/// Immutable caller budget. A copy is a deadline, not a source/operation token.
#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    /// Original canonical expiration in microseconds.
    pub expires: u64,
    /// Original native target; never refreshed by retry/partial write/attach.
    pub hard: Instant,
}
impl Bounds {
    /// Capture native first, then the caller's actual shared canonical sample.
    /// The resulting targets remain fixed throughout this original operation.
    pub fn new(clock: &dyn RuntimeClock, life: Duration) -> Result<Self, Error> {
        let started = Instant::now();
        let hard = started.checked_add(life).ok_or(Fault::Overflow)?;
        if life.is_zero() || life.as_micros() >= u128::from(u64::MAX) {
            return Err(Fault::InvalidInput.into());
        }
        let now = clock.sample()?.now.as_micros();
        if Instant::now() >= hard {
            return Err(Fault::Deadline.into());
        }
        let expires = now
            .checked_add(u64::try_from(life.as_micros()).map_err(|_| Fault::Overflow)?)
            .filter(|target| *target != u64::MAX)
            .ok_or(Fault::Overflow)?;
        Ok(Self { expires, hard })
    }
}
pub(crate) struct Bound {
    pub targets: Bounds,
    alarm: Pin<Box<Sleep>>,
}
impl Bound {
    pub fn new(clock: &dyn RuntimeClock, life: Duration) -> Result<Self, Error> {
        Ok(Self::targets(Bounds::new(clock, life)?))
    }
    pub fn targets(targets: Bounds) -> Self {
        Self {
            alarm: Box::pin(tokio::time::sleep_until(targets.hard.into())),
            targets,
        }
    }
    pub fn poll_native(&mut self, cx: &mut Context<'_>) -> bool {
        Instant::now() >= self.targets.hard || self.alarm.as_mut().poll(cx).is_ready()
    }
    pub fn check(&self, clock: &dyn RuntimeClock) -> Result<(), Error> {
        if Instant::now() >= self.targets.hard {
            return Err(Fault::Deadline.into());
        }
        let now = clock.sample()?.now.as_micros();
        if Instant::now() >= self.targets.hard || now >= self.targets.expires {
            return Err(Fault::Deadline.into());
        }
        Ok(())
    }
}
