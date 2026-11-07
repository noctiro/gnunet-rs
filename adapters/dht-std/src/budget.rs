//! Once-captured native targets; sampling/clock revision never renews them.
use crate::Error;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as Fault;
use std::{future::Future, pin::Pin, task::Context, time::Duration};
use tokio::time::{Instant, Sleep};

pub(crate) struct Bound {
    pub until: u64,
    pub hard: Instant,
    alarm: Pin<Box<Sleep>>,
}
#[derive(Clone, Copy)]
pub(crate) struct Anchor {
    pub now: u64,
    pub native: Instant,
    pub hard: Instant,
}
impl Bound {
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
        let until = now
            .checked_add(u64::try_from(life.as_micros()).map_err(|_| Fault::Overflow)?)
            .filter(|n| *n != u64::MAX)
            .ok_or(Fault::Overflow)?;
        Ok(Self::targets(until, hard))
    }
    pub fn targets(until: u64, hard: Instant) -> Self {
        Self {
            until,
            hard,
            alarm: Box::pin(tokio::time::sleep_until(hard)),
        }
    }
    pub fn for_job(until: u64, anchor: Anchor) -> Result<Self, Error> {
        let remaining = until.checked_sub(anchor.now).ok_or(Fault::Deadline)?;
        let hard = anchor
            .native
            .checked_add(Duration::from_micros(remaining))
            .ok_or(Fault::Overflow)?
            .min(anchor.hard);
        Ok(Self::targets(until, hard))
    }
    pub fn poll_native(&mut self, cx: &mut Context<'_>) -> bool {
        Instant::now() >= self.hard || self.alarm.as_mut().poll(cx).is_ready()
    }
    pub fn check(&self, clock: &dyn RuntimeClock) -> Result<Anchor, Error> {
        if Instant::now() >= self.hard {
            return Err(Fault::Deadline.into());
        }
        let native = Instant::now();
        let now = clock.sample()?.now.as_micros();
        if Instant::now() >= self.hard || now >= self.until {
            return Err(Fault::Deadline.into());
        }
        Ok(Anchor {
            now,
            native,
            hard: self.hard,
        })
    }
}
pub(crate) fn duration(value: Duration) -> Result<u64, Error> {
    let micros = u64::try_from(value.as_micros()).map_err(|_| Fault::Overflow)?;
    if micros == 0 || micros == u64::MAX || Instant::now().checked_add(value).is_none() {
        return Err(Fault::InvalidInput.into());
    }
    Ok(micros)
}
