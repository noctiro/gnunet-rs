//! Per-owner lazy native alarm over immutable original bounds.
use super::{Bounds, BoundsError, RuntimeClock};
use std::{future::Future, pin::Pin, task::Context, time::Duration};
use tokio::time::Sleep;

/// Original targets and one exclusively owned lazy native alarm.
pub struct Alarm {
    bounds: Bounds,
    alarm: Option<Pin<Box<Sleep>>>,
}
impl std::fmt::Debug for Alarm {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output
            .debug_struct("Alarm")
            .field("bounds", &self.bounds)
            .field("registered", &self.alarm.is_some())
            .finish()
    }
}
impl Alarm {
    /// Retain existing targets without creating a timer or sampling time.
    #[must_use]
    pub const fn new(bounds: Bounds) -> Self {
        Self {
            bounds,
            alarm: None,
        }
    }
    /// Capture one finite original interval without creating a timer.
    ///
    /// # Errors
    /// Preserves bounds admission failure.
    pub fn after(clock: &dyn RuntimeClock, lifetime: Duration) -> Result<Self, BoundsError> {
        Bounds::after(clock, lifetime).map(Self::new)
    }
    /// Capture a finite phase bounded by its original enclosing lifetime.
    ///
    /// # Errors
    /// Reports source failure, exhausted original lifetime or overflow.
    pub fn phase(
        clock: &dyn RuntimeClock,
        lifetime: Duration,
        parent: Bounds,
    ) -> Result<Self, BoundsError> {
        parent.check_native()?;
        let bounds = Bounds::after(clock, lifetime)?.capped_by(parent);
        bounds.check(clock)?;
        Ok(Self::new(bounds))
    }
    /// Original targets retained by this waiter.
    #[must_use]
    pub const fn bounds(&self) -> Bounds {
        self.bounds
    }
    /// Apply only stricter limits to this same original waiter.
    pub fn tighten(&mut self, bounds: Bounds) {
        self.bounds = self.bounds.capped_by(bounds);
        if let Some(alarm) = &mut self.alarm {
            alarm.as_mut().reset(self.bounds.hard());
        }
    }
    /// Register the native hard target and observe expiry without consulting the clock.
    pub fn poll_expired(&mut self, cx: &mut Context<'_>) -> bool {
        if self.bounds.check_native().is_err() {
            return true;
        }
        let alarm = self
            .alarm
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(self.bounds.hard())));
        alarm.as_mut().poll(cx).is_ready()
    }
    /// Check both original targets without altering the waiter.
    ///
    /// # Errors
    /// Preserves source failure and original expiry.
    pub fn check(&self, clock: &dyn RuntimeClock) -> Result<u64, BoundsError> {
        self.bounds.check(clock)
    }
}
