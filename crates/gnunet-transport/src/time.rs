//! Explicit local scheduling and GNUnet absolute-time coordinates.
//!
//! Scheduling/RTT use a nondecreasing local monotonic clock. Cache expiration
//! uses the actual GNUnet logical absolute clock, which can be corrected in
//! either direction. These values are caller clock inputs, not source, signer
//! or route authority. A remote wire monotime/echo/generation scalar is neither
//! a local scheduling sample nor an authenticated UTC observation.
use gnunet_types::{Error, MonoInstant};
use gnunet_wire::official::{AbsoluteTime, RelativeTime};
/// One coherent caller observation of two independently meaningful coordinates.
/// No wire field, global clock, OS access or implicit coordinate conversion is
/// introduced. The monotonic epoch stays fixed for one live Engine instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Times {
    monotonic: MonoInstant,
    absolute: AbsoluteTime,
}
impl Times {
    /// Supply local monotonic microseconds and actual GNUnet logical absolute
    /// microseconds. Construction grants no clock/source authenticity.
    #[must_use]
    pub const fn new(monotonic: MonoInstant, absolute: AbsoluteTime) -> Self {
        Self {
            monotonic,
            absolute,
        }
    }
    /// Explicit embedding profile in which the caller asserts both coordinates
    /// have the same microsecond value. Scalar Engine methods use this profile;
    /// independent clocks must use the typed `*_at` methods instead.
    #[must_use]
    pub const fn shared_coordinate(value: u64) -> Self {
        Self::new(MonoInstant(value), AbsoluteTime::from_micros(value))
    }
    /// Local scheduling/RTT coordinate. It cannot regress within a live Engine.
    #[must_use]
    pub const fn monotonic(self) -> MonoInstant {
        self.monotonic
    }
    /// Actual GNUnet absolute clock sample; wall/logical corrections may regress.
    #[must_use]
    pub const fn absolute(self) -> AbsoluteTime {
        self.absolute
    }
    /// A sample is finite. FOREVER/NEVER are deadline sentinels, not samples.
    /// This checks representation only, not monotonic history or source trust.
    pub fn validate(self) -> Result<(), Error> {
        if self.monotonic.0 == u64::MAX || self.absolute.is_never() {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
    /// Compute a finite local scheduling deadline without adding a relative
    /// duration to UTC. Overflow never becomes an accidental forever lease.
    pub fn monotonic_after(self, duration: RelativeTime) -> Result<MonoInstant, Error> {
        self.validate()?;
        Ok(MonoInstant(add(self.monotonic.0, duration)?))
    }
    /// Compute a finite GNUnet absolute expiration from the actual absolute
    /// sample. It is independent of the current monotonic epoch/offset.
    pub fn absolute_after(self, duration: RelativeTime) -> Result<AbsoluteTime, Error> {
        self.validate()?;
        Ok(AbsoluteTime::from_micros(add(
            self.absolute.as_micros(),
            duration,
        )?))
    }
}
fn add(base: u64, duration: RelativeTime) -> Result<u64, Error> {
    if duration.is_forever() {
        return Err(Error::InvalidInput);
    }
    base.checked_add(duration.as_micros())
        .filter(|value| *value != u64::MAX)
        .ok_or(Error::Overflow)
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::{Engine, Limits, PeerId, WorkStatus};
    struct NoEntropy;
    impl gnunet_crypto::Entropy for NoEntropy {
        fn fill(&mut self, _output: &mut [u8]) -> Result<(), Error> {
            Err(Error::Entropy)
        }
    }
    /// Public clock/empty-engine scheduling model only. It performs no entropy,
    /// key, hash, signature, IO, storage, worker, process or native operation.
    #[test]
    fn absolute_correction_does_not_rewind_local_schedule() {
        let result = Engine::new(PeerId([0; 32]), Limits::default()).map(|mut engine| {
            let mut entropy = NoEntropy;
            let first = Times::new(MonoInstant(100), AbsoluteTime::from_micros(1_000_000));
            assert_eq!(engine.tick_at(first, &mut entropy), Ok(WorkStatus::Ready));
            let corrected = Times::new(MonoInstant(200), AbsoluteTime::from_micros(900));
            assert_eq!(
                engine.tick_at(corrected, &mut entropy),
                Ok(WorkStatus::Ready)
            );
            assert_eq!(engine.monotonic_now(), MonoInstant(200));
            assert_eq!(
                engine.validate_times(Times::new(
                    MonoInstant(199),
                    AbsoluteTime::from_micros(2_000_000)
                )),
                Err(Error::TimeUncertain)
            );
            assert_eq!(engine.monotonic_now(), MonoInstant(200));
            assert_eq!(
                corrected.monotonic_after(RelativeTime::from_micros(5)),
                Ok(MonoInstant(205))
            );
            assert_eq!(
                corrected.absolute_after(RelativeTime::from_micros(5)),
                Ok(AbsoluteTime::from_micros(905))
            );
            let separate = Times::new(MonoInstant(0), AbsoluteTime::from_micros(9_000_000));
            assert_eq!(
                separate.monotonic_after(RelativeTime::from_micros(10)),
                Ok(MonoInstant(10))
            );
            assert_eq!(
                separate.absolute_after(RelativeTime::from_micros(10)),
                Ok(AbsoluteTime::from_micros(9_000_010))
            );
            assert_eq!(
                Times::new(MonoInstant(1), AbsoluteTime::from_micros(u64::MAX - 1))
                    .absolute_after(RelativeTime::from_micros(1)),
                Err(Error::Overflow)
            );
        });
        assert_eq!(result, Ok(()));
    }
}
