//! One native scheduling epoch and an independent configured absolute source.
//! No logical adjustment resets native targets or grants signing monotime.
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::{Error, MonoInstant};
use gnunet_wire::official::AbsoluteTime;
use std::{sync::Arc, time::Duration};
use tokio::time::Instant;

struct Epoch {
    source: Arc<dyn RuntimeClock>,
    anchor: Instant,
}
/// Shared by the connected Book, CORE bridge, Node and PILS job owners.
/// Clones preserve this exact native epoch, rather than deriving a wall offset.
#[derive(Clone)]
pub struct Timebase {
    epoch: Arc<Epoch>,
}
/// Actual independent observations from one sampling call. The logical absolute
/// sample may regress; the elapsed coordinate belongs to this fixed native epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sample {
    /// Nondecreasing elapsed microseconds for local scheduling only.
    pub monotonic: MonoInstant,
    /// Actual configured GNUnet absolute time, including logical adjustments.
    pub absolute: AbsoluteTime,
    /// Original logical source revision, used by its exclusive subscribers.
    pub revision: u64,
}
impl Timebase {
    /// Create once before constructing the connected pure/native owners.
    /// A real source refusal returns unchanged; no IO or subscription is started.
    pub fn new(source: Arc<dyn RuntimeClock>) -> Result<Self, Error> {
        let anchor = Instant::now();
        source.sample()?;
        Ok(Self {
            epoch: Arc::new(Epoch { source, anchor }),
        })
    }
    /// Exact original logical source, without reserving another listener.
    #[must_use]
    pub fn source(&self) -> Arc<dyn RuntimeClock> {
        self.epoch.source.clone()
    }
    /// Whether both owners share the actual same native epoch and logical source.
    /// Equal wall values or independently created native anchors are insufficient.
    #[must_use]
    pub fn same_epoch(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.epoch, &other.epoch)
    }
    /// Read the real source and native elapsed independently. A provider failure
    /// never returns a fabricated absolute sample or a successful scheduling step.
    pub fn sample(&self) -> Result<Sample, Error> {
        let source = self.epoch.source.sample()?;
        let elapsed = Instant::now()
            .checked_duration_since(self.epoch.anchor)
            .ok_or(Error::TimeUncertain)?;
        let micros = u64::try_from(elapsed.as_micros()).map_err(|_| Error::Overflow)?;
        Ok(Sample {
            monotonic: MonoInstant(micros),
            absolute: source.now,
            revision: source.revision,
        })
    }
    /// Map the same original elapsed target to its fixed native anchor. This
    /// neither samples nor projects wall time, and cannot renew a target.
    pub fn native_bound(&self, target: MonoInstant) -> Result<Instant, Error> {
        self.epoch
            .anchor
            .checked_add(Duration::from_micros(target.0))
            .ok_or(Error::Overflow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnunet_service_runtime::clock::{ClockSample, ClockSubscription};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    struct Adjustable {
        absolute: AtomicU64,
        failure: AtomicBool,
    }
    impl RuntimeClock for Adjustable {
        fn sample(&self) -> Result<ClockSample, Error> {
            if self.failure.load(Ordering::SeqCst) {
                return Err(Error::Unavailable);
            }
            Ok(ClockSample {
                now: gnunet_types::AbsoluteTime::from_micros(self.absolute.load(Ordering::SeqCst)),
                revision: 0,
            })
        }
        fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Error> {
            Err(Error::Unsupported)
        }
    }
    fn check(value: bool) -> Result<(), Error> {
        value.then_some(()).ok_or(Error::InvalidInput)
    }
    #[test]
    fn logical_rollback_preserves_actual_absolute_and_original_native_target() -> Result<(), Error>
    {
        let source = Arc::new(Adjustable {
            absolute: AtomicU64::new(1_000_000),
            failure: AtomicBool::new(false),
        });
        let timebase = Timebase::new(source.clone())?;
        let first = timebase.sample()?;
        let target = first.monotonic.after(gnunet_types::Duration(10_000))?;
        let native = timebase.native_bound(target)?;
        source.absolute.store(10, Ordering::SeqCst);
        let second = timebase.sample()?;
        check(first.absolute.as_micros() == 1_000_000 && second.absolute.as_micros() == 10)?;
        check(second.monotonic >= first.monotonic)?;
        check(timebase.native_bound(target)? == native)?;
        source.absolute.store(9_000_000, Ordering::SeqCst);
        check(timebase.sample()?.absolute.as_micros() == 9_000_000)?;
        check(timebase.native_bound(target)? == native)
    }
    #[test]
    fn epoch_identity_and_real_source_failure_are_not_absolute_value_guesses() -> Result<(), Error>
    {
        let source = Arc::new(Adjustable {
            absolute: AtomicU64::new(100),
            failure: AtomicBool::new(false),
        });
        let timebase = Timebase::new(source.clone())?;
        let clone = timebase.clone();
        let other = Timebase::new(source.clone())?;
        check(timebase.same_epoch(&clone) && !timebase.same_epoch(&other))?;
        check(Arc::ptr_eq(&timebase.source(), &other.source()))?;
        let target = timebase.native_bound(MonoInstant(1_000))?;
        source.failure.store(true, Ordering::SeqCst);
        check(timebase.sample() == Err(Error::Unavailable))?;
        check(timebase.native_bound(MonoInstant(1_000))? == target)?;
        check(matches!(Timebase::new(source), Err(Error::Unavailable)))
    }
}
