//! Common logical scheduler clock for caller-driven native service owners.
//! Logical GNUnet absolute time can regress. A driver owns one change-listener;
//! sampling a clock never submits native work or creates a background task.
pub use gnunet_types::AbsoluteTime;
use gnunet_types::Error;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
/// One coherent logical absolute source time and adjustment revision.
/// Native elapsed coordinates cannot be supplied as absolute samples.
/// ```compile_fail
/// use gnunet_service_runtime::clock::ClockSample;
/// use gnunet_types::MonoInstant;
/// let sample = ClockSample { now: MonoInstant(1), revision: 0 };
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockSample {
    /// Logical source microseconds, including any configured process offset.
    pub now: AbsoluteTime,
    /// Incremented when an explicit adjustment can alter a pending wait.
    pub revision: u64,
}
/// Shared logical time domain. Cloning its Arc shares only the time source;
/// each independently polled owner must explicitly reserve a subscription.
pub trait RuntimeClock: Send + Sync {
    /// Read source time without scheduling, resolution or native I/O effects.
    fn sample(&self) -> Result<ClockSample, Error>;
    /// Reserve one exclusive bounded change listener. Failure creates no waiter.
    /// There is deliberately no Arc-clone default implementation.
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Error>;
}
/// One non-Clone waiter owned by exactly one independently polled future/driver.
/// A pending poll registers that owner's current waker. Drop retires only this
/// original listener, freeing its capacity and dropping its stored waker.
pub trait ClockSubscription: Send {
    /// Register before sampling. A concurrent adjustment must either be returned
    /// here or wake this same subscription. Logical time may move backwards.
    fn poll_changed(
        &mut self,
        cx: &mut Context<'_>,
        observed_revision: u64,
    ) -> Poll<Result<ClockSample, Error>>;
}
/// Native GNUNET_TIME_absolute_get profile without a process offset.
/// System time is read on each native/scheduler wake. This owner does not alter
/// the OS clock or invent notifications for external OS clock changes.
pub struct SystemClock;
impl RuntimeClock for SystemClock {
    fn sample(&self) -> Result<ClockSample, Error> {
        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d
                .as_secs()
                .wrapping_mul(1_000_000)
                .wrapping_add(u64::from(d.subsec_micros())),
            Err(e) => {
                let d = e.duration();
                let us = d
                    .as_secs()
                    .wrapping_mul(1_000_000)
                    .wrapping_add(u64::from(d.subsec_micros()))
                    .wrapping_add(u64::from(!d.subsec_nanos().is_multiple_of(1000)));
                0u64.wrapping_sub(us)
            }
        };
        Ok(ClockSample {
            now: AbsoluteTime::from_micros(now),
            revision: 0,
        })
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Error> {
        Ok(Box::new(SystemSubscription))
    }
}
struct SystemSubscription;
impl ClockSubscription for SystemSubscription {
    fn poll_changed(
        &mut self,
        _cx: &mut Context<'_>,
        _observed_revision: u64,
    ) -> Poll<Result<ClockSample, Error>> {
        Poll::Pending
    }
}

use tokio::time::{Instant, Sleep};
impl Deadline {
    /// Register one exact absolute logical target with its exclusive listener.
    /// The original target remains authoritative across native early wakeups.
    pub fn at(clock: Arc<dyn RuntimeClock>, target: AbsoluteTime) -> Result<Self, Error> {
        let subscription = clock.subscribe()?;
        let sample = clock.sample()?;
        Ok(Self {
            clock,
            subscription: Some(subscription),
            target,
            registration_ready: !target.is_never() && sample.now >= target,
            revision: sample.revision,
            timer: None,
        })
    }
    /// Register a relative delay at this source's current absolute time.
    /// Failure returns its reserved waiter without publishing a timer.
    pub fn after(clock: Arc<dyn RuntimeClock>, duration: Duration) -> Result<Self, Error> {
        let subscription = clock.subscribe()?;
        let sample = clock.sample()?;
        let delay = u64::try_from(duration.as_micros()).unwrap_or(u64::MAX);
        let target = AbsoluteTime::from_micros(sample.now.as_micros().saturating_add(delay));
        Ok(Self {
            clock,
            subscription: Some(subscription),
            target,
            registration_ready: delay == 0 && !target.is_never(),
            revision: sample.revision,
            timer: None,
        })
    }
}
/// One registered absolute logical target with its own exclusive waiter.
/// Cancellation/drop retires only this timer. Native sleep is a wake source;
/// source time (including rollback) remains authoritative.
pub struct Deadline {
    clock: Arc<dyn RuntimeClock>,
    subscription: Option<Box<dyn ClockSubscription>>,
    target: AbsoluteTime,
    registration_ready: bool,
    revision: u64,
    timer: Option<Pin<Box<Sleep>>>,
}
impl Future for Deadline {
    type Output = Result<(), Error>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let Some(subscription) = &mut this.subscription else {
            return Poll::Ready(Err(Error::NotReady));
        };
        // Source add_delayed(ZERO) enters the ready queue at registration.
        // Preserve the original target data but never suspend that ready lease
        // after a later clock rollback. A MAX registration remains FOREVER.
        if this.registration_ready {
            return this.finish(Ok(()));
        }
        let result = subscription.poll_changed(cx, this.revision);
        match result {
            Poll::Ready(Err(error)) => return this.finish(Err(error)),
            Poll::Ready(Ok(sample)) => this.revision = sample.revision,
            Poll::Pending => {}
        }
        let sample = match this.clock.sample() {
            Ok(sample) => sample,
            Err(error) => return this.finish(Err(error)),
        };
        this.revision = sample.revision;
        match subscription.poll_changed(cx, sample.revision) {
            Poll::Ready(Err(error)) => return this.finish(Err(error)),
            Poll::Ready(Ok(_)) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Pending => {}
        }
        if this.target.is_never() {
            return Poll::Pending;
        }
        if sample.now >= this.target {
            return this.finish(Ok(()));
        }
        let Some(target) = Instant::now().checked_add(Duration::from_micros(
            this.target.as_micros() - sample.now.as_micros(),
        )) else {
            return this.finish(Err(Error::Overflow));
        };
        if let Some(timer) = &mut this.timer {
            timer.as_mut().reset(target);
        } else {
            this.timer = Some(Box::pin(tokio::time::sleep_until(target)));
        }
        let result = match &mut this.timer {
            Some(timer) => timer.as_mut().poll(cx).map(|()| Ok(())),
            None => Poll::Ready(Err(Error::NotReady)),
        };
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => this.finish(Err(error)),
            Poll::Ready(Ok(())) => {
                // Native readiness wakes the owner; the logical absolute target
                // is authoritative, including rollback without a revision.
                this.timer = None;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}

impl Deadline {
    fn finish(&mut self, result: Result<(), Error>) -> Poll<Result<(), Error>> {
        self.subscription = None;
        self.timer = None;
        Poll::Ready(result)
    }
}
