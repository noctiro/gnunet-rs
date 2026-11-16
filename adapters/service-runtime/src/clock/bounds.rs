//! Fixed original canonical expiry and monotonic target without a waiter.
use super::{AbsoluteTime, ClockSample, RuntimeClock};
use gnunet_types::Error as Fault;
use std::{fmt, time::Duration};
use tokio::time::Instant;
/// Original deadline admission/check failure, preserving clock-source errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundsError {
    /// An original expiry was reached or its requested lifetime was zero.
    Deadline,
    /// An original target cannot be represented.
    Overflow,
    /// The actual canonical source failed, independently of expiry.
    Clock(Fault),
}
impl fmt::Display for BoundsError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deadline => output.write_str("original deadline expired"),
            Self::Overflow => output.write_str("original deadline overflow"),
            Self::Clock(error) => write!(output, "original deadline clock: {error}"),
        }
    }
}
impl std::error::Error for BoundsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Clock(error) => Some(error),
            _ => None,
        }
    }
}
/// Copied targets preserve an admitted operation's original lifetime.
#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    expires: AbsoluteTime,
    hard: Instant,
}
impl Bounds {
    /// Admit finite targets once before native work. No waiter or I/O is created.
    pub fn after(clock: &dyn RuntimeClock, lifetime: Duration) -> Result<Self, BoundsError> {
        let delta = u64::try_from(lifetime.as_micros()).map_err(|_| BoundsError::Overflow)?;
        if delta == 0 {
            return Err(BoundsError::Deadline);
        }
        let hard = Instant::now()
            .checked_add(lifetime)
            .ok_or(BoundsError::Overflow)?;
        let now = clock.sample().map_err(BoundsError::Clock)?.now.as_micros();
        let bounds = Self::from_targets(
            AbsoluteTime::from_micros(now.checked_add(delta).ok_or(BoundsError::Overflow)?),
            hard,
        )?;
        bounds.check_native()?;
        Ok(bounds)
    }
    /// Check the unchanged native target first, then the original canonical expiry.
    pub fn check(self, clock: &dyn RuntimeClock) -> Result<u64, BoundsError> {
        self.sample(clock).map(|sample| sample.now.as_micros())
    }
    /// Retain original targets; an expired target grants no admission authority.
    ///
    /// # Errors
    /// Rejects the canonical never sentinel.
    pub fn from_targets(expires: AbsoluteTime, hard: Instant) -> Result<Self, BoundsError> {
        if expires.is_never() {
            return Err(BoundsError::Overflow);
        }
        Ok(Self { expires, hard })
    }
    /// Capture the native interval before observing a finite canonical target.
    ///
    /// # Errors
    /// Preserves source failure, original expiry and target overflow.
    pub fn until(clock: &dyn RuntimeClock, expires: AbsoluteTime) -> Result<Self, BoundsError> {
        let started = Instant::now();
        let sample = clock.sample().map_err(BoundsError::Clock)?;
        Self::at_sample(expires, started, sample)
    }
    pub(super) fn at_sample(
        expires: AbsoluteTime,
        started: Instant,
        sample: ClockSample,
    ) -> Result<Self, BoundsError> {
        if expires.is_never() {
            return Err(BoundsError::Overflow);
        }
        let remaining = expires
            .as_micros()
            .checked_sub(sample.now.as_micros())
            .filter(|remaining| *remaining != 0)
            .ok_or(BoundsError::Deadline)?;
        let hard = started
            .checked_add(Duration::from_micros(remaining))
            .ok_or(BoundsError::Overflow)?;
        let bounds = Self::from_targets(expires, hard)?;
        bounds.check_native()?;
        Ok(bounds)
    }
    /// Original finite canonical target in microseconds.
    #[must_use]
    pub const fn expires(self) -> u64 {
        self.expires.as_micros()
    }
    /// Original native hard target.
    #[must_use]
    pub const fn hard(self) -> Instant {
        self.hard
    }
    /// Intersect unchanged original targets without sampling or renewal.
    #[must_use]
    pub fn capped_by(self, parent: Self) -> Self {
        self.tightened(parent.expires(), parent.hard)
    }
    /// Apply only stricter canonical and native limits.
    #[must_use]
    pub fn tightened(self, expires: u64, hard: Instant) -> Self {
        Self {
            expires: AbsoluteTime::from_micros(self.expires().min(expires)),
            hard: self.hard.min(hard),
        }
    }
    /// Refuse native expiry without consulting the canonical source.
    ///
    /// # Errors
    /// Returns only expiry of the unchanged native target.
    pub fn check_native(self) -> Result<(), BoundsError> {
        if Instant::now() >= self.hard {
            Err(BoundsError::Deadline)
        } else {
            Ok(())
        }
    }
    /// Sample the original source between checks of the same native target.
    ///
    /// # Errors
    /// Preserves source failure and refuses native or canonical expiry.
    pub fn sample(self, clock: &dyn RuntimeClock) -> Result<ClockSample, BoundsError> {
        self.check_native()?;
        let sample = clock.sample().map_err(BoundsError::Clock)?;
        self.check_native()?;
        if sample.now >= self.expires {
            return Err(BoundsError::Deadline);
        }
        Ok(sample)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{ClockSample, ClockSubscription};
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Clock {
        calls: AtomicUsize,
        delay: Duration,
        failure: Option<Fault>,
    }
    impl RuntimeClock for Clock {
        fn sample(&self) -> Result<ClockSample, Fault> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            std::thread::sleep(self.delay);
            match self.failure {
                Some(error) => Err(error),
                None => Ok(ClockSample {
                    now: gnunet_types::AbsoluteTime::from_micros(0),
                    revision: 0,
                }),
            }
        }
        fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Fault> {
            Err(Fault::Capacity)
        }
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Deadline regression asserts source-call and expiry behavior while keeping admission failure fallible"
    )]
    fn source_sampling_cannot_extend_native_admission() -> Result<(), BoundsError> {
        let clock = Clock {
            calls: AtomicUsize::new(0),
            delay: Duration::from_millis(4),
            failure: None,
        };
        assert!(
            matches!(
                Bounds::after(&clock, Duration::from_millis(1)),
                Err(BoundsError::Deadline)
            ),
            "sample preparation consumes the original native lifetime"
        );
        assert_eq!(
            clock.calls.load(Ordering::Relaxed),
            1,
            "expired native work must not consult the canonical source again"
        );
        Ok(())
    }
    #[test]
    fn clock_deadline_cause_remains_a_source_failure() {
        let clock = Clock {
            calls: AtomicUsize::new(0),
            delay: Duration::ZERO,
            failure: Some(Fault::Deadline),
        };
        let result = Bounds::after(&clock, Duration::from_secs(1));
        assert!(
            matches!(result, Err(BoundsError::Clock(Fault::Deadline))),
            "clock failure must remain distinct from operation expiry"
        );
    }
}
