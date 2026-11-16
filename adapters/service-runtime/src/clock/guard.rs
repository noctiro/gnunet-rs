//! Exclusive clock subscription and alarm for one finite effect owner.
use super::{AbsoluteTime, Bounds, BoundsError, ClockSample, ClockSubscription, RuntimeClock};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

/// One original clock, finite targets and exclusively owned wake registration.
pub struct DeadlineGuard {
    clock: Arc<dyn RuntimeClock>,
    subscription: Box<dyn ClockSubscription>,
    revision: u64,
    bounds: Bounds,
    alarm: Option<Pin<Box<Sleep>>>,
    waker: Option<Waker>,
}
impl std::fmt::Debug for DeadlineGuard {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output
            .debug_struct("DeadlineGuard")
            .field("bounds", &self.bounds)
            .field("revision", &self.revision)
            .field("registered", &self.alarm.is_some())
            .finish()
    }
}
impl DeadlineGuard {
    /// Reserve a waiter and capture a finite canonical/native lease exactly once.
    ///
    /// # Errors
    /// Preserves source failure, admission expiry and target overflow.
    pub fn until(clock: Arc<dyn RuntimeClock>, expires: AbsoluteTime) -> Result<Self, BoundsError> {
        let started = Instant::now();
        let subscription = clock.subscribe().map_err(BoundsError::Clock)?;
        let sample = clock.sample().map_err(BoundsError::Clock)?;
        let bounds = Bounds::at_sample(expires, started, sample)?;
        Ok(Self {
            clock,
            subscription,
            revision: sample.revision,
            bounds,
            alarm: None,
            waker: None,
        })
    }
    /// Reserve a waiter for existing targets without renewing either one.
    ///
    /// # Errors
    /// Preserves source failure and expiry during waiter admission.
    pub fn new(clock: Arc<dyn RuntimeClock>, bounds: Bounds) -> Result<Self, BoundsError> {
        bounds.check_native()?;
        let subscription = clock.subscribe().map_err(BoundsError::Clock)?;
        let sample = bounds.sample(clock.as_ref())?;
        Ok(Self {
            clock,
            subscription,
            revision: sample.revision,
            bounds,
            alarm: None,
            waker: None,
        })
    }
    /// Original finite targets.
    #[must_use]
    pub const fn bounds(&self) -> Bounds {
        self.bounds
    }
    /// Original process clock shared with the consuming owner.
    #[must_use]
    pub fn clock(&self) -> &Arc<dyn RuntimeClock> {
        &self.clock
    }
    /// Intersect targets and wake the original owner when either limit tightens.
    pub fn tighten(&mut self, expires: u64, hard: Instant) {
        let bounds = self.bounds.tightened(expires, hard);
        if bounds.expires() == self.bounds.expires() && bounds.hard() == self.bounds.hard() {
            return;
        }
        self.bounds = bounds;
        if let Some(alarm) = &mut self.alarm {
            let at = alarm.deadline().min(bounds.hard());
            alarm.as_mut().reset(at);
        }
        if let Some(waker) = &self.waker {
            waker.wake_by_ref();
        }
    }
    /// Check both targets at the current effect boundary without polling a waiter.
    ///
    /// # Errors
    /// Preserves source failure and original expiry.
    pub fn check(&self) -> Result<u64, BoundsError> {
        self.bounds.check(self.clock.as_ref())
    }
    fn poll_alarm(&mut self, cx: &mut Context<'_>, at: Instant) -> bool {
        if let Some(alarm) = &mut self.alarm {
            alarm.as_mut().reset(at);
        } else {
            self.alarm = Some(Box::pin(tokio::time::sleep_until(at)));
        }
        self.alarm
            .as_mut()
            .is_some_and(|alarm| alarm.as_mut().poll(cx).is_ready())
    }
    /// Stabilize canonical time while retaining the independent native deadline.
    /// A successful sample cannot authorize effects after later waits or callbacks.
    ///
    /// # Errors
    /// Preserves source failure and refuses expiry after each source callback.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<ClockSample, BoundsError>> {
        if self
            .waker
            .as_ref()
            .is_none_or(|waker| !waker.will_wake(cx.waker()))
        {
            self.waker = Some(cx.waker().clone());
        }
        self.bounds.check_native()?;
        if self.poll_alarm(cx, self.bounds.hard()) {
            return Poll::Ready(Err(BoundsError::Deadline));
        }
        match self.subscription.poll_changed(cx, self.revision) {
            Poll::Ready(Err(error)) => return Poll::Ready(Err(BoundsError::Clock(error))),
            Poll::Ready(Ok(sample)) => self.revision = sample.revision,
            Poll::Pending => {}
        }
        self.bounds.check_native()?;
        let sample = self.bounds.sample(self.clock.as_ref())?;
        let changed = match self.subscription.poll_changed(cx, sample.revision) {
            Poll::Ready(Err(error)) => return Poll::Ready(Err(BoundsError::Clock(error))),
            Poll::Ready(Ok(_)) => true,
            Poll::Pending => false,
        };
        self.bounds.check_native()?;
        if changed {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.revision = sample.revision;
        let wake = Instant::now()
            .checked_add(Duration::from_micros(
                self.bounds.expires() - sample.now.as_micros(),
            ))
            .ok_or(BoundsError::Overflow)?
            .min(self.bounds.hard());
        if self.poll_alarm(cx, wake) {
            self.bounds.check_native()?;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.bounds.check_native()?;
        Poll::Ready(Ok(sample))
    }
}

#[cfg(test)]
mod tests;
