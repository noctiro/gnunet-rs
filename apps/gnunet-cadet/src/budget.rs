//! One immutable native/logical budget; copies retain the same original targets.
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_types::{AbsoluteTime, Error};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
#[derive(Clone, Copy)]
pub(super) struct Start {
    native: Instant,
    logical: AbsoluteTime,
}
impl Start {
    pub(super) fn sample(source: &Arc<dyn RuntimeClock>) -> Result<Self, Error> {
        let native = Instant::now();
        let logical = source.sample()?.now;
        Ok(Self { native, logical })
    }
    pub(super) fn native(self) -> Instant {
        self.native
    }
    pub(super) fn budget(self, duration: Duration) -> Result<Budget, Error> {
        let hard = self.native.checked_add(duration).ok_or(Error::Overflow)?;
        let until = self
            .logical
            .as_micros()
            .checked_add(u64::try_from(duration.as_micros()).map_err(|_| Error::Overflow)?)
            .filter(|value| *value != u64::MAX)
            .ok_or(Error::Overflow)?;
        Ok(Budget {
            hard,
            until: AbsoluteTime::from_micros(until),
        })
    }
}
#[derive(Clone, Copy)]
pub(super) struct Budget {
    pub hard: Instant,
    pub until: AbsoluteTime,
}
pub(super) struct Alarm {
    source: Arc<dyn RuntimeClock>,
    hard: Option<Instant>,
    until: Option<AbsoluteTime>,
    native: Option<Pin<Box<Sleep>>>,
    logical: Option<Pin<Box<Deadline>>>,
}
impl Alarm {
    pub(super) fn new(source: Arc<dyn RuntimeClock>) -> Self {
        Self {
            source,
            hard: None,
            until: None,
            native: None,
            logical: None,
        }
    }
    pub(super) fn set(
        &mut self,
        cx: &mut Context<'_>,
        budgets: impl Iterator<Item = Budget>,
    ) -> Result<(), Error> {
        let (mut hard, mut until) = (None, None);
        for b in budgets {
            hard = Some(hard.map_or(b.hard, |old: Instant| old.min(b.hard)));
            until = Some(until.map_or(b.until, |old: AbsoluteTime| old.min(b.until)));
        }
        if hard != self.hard {
            self.hard = hard;
            self.native = hard.map(|target| Box::pin(tokio::time::sleep_until(target)));
        }
        self.native_guard(cx)?;
        if until != self.until {
            self.until = until;
            self.logical = until
                .map(|target| Deadline::at(self.source.clone(), target).map(Box::pin))
                .transpose()?;
        }
        self.native_guard(cx)
    }
    pub(super) fn native_guard(&mut self, cx: &mut Context<'_>) -> Result<(), Error> {
        if self.hard.is_some_and(|at| Instant::now() >= at)
            || self
                .native
                .as_mut()
                .is_some_and(|timer| timer.as_mut().poll(cx).is_ready())
        {
            return Err(Error::Deadline);
        }
        Ok(())
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Result<(), Error> {
        self.native_guard(cx)?;
        if let Some(timer) = &mut self.logical
            && let Poll::Ready(result) = timer.as_mut().poll(cx)
        {
            result?;
            return Err(Error::Deadline);
        }
        self.native_guard(cx)
    }
    pub(super) fn hard(&self) -> Option<Instant> {
        self.hard
    }
}
