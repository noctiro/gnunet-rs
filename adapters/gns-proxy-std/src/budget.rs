//! One original session budget, including synchronous capability boundaries.
use crate::Error;
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_types::{AbsoluteTime, Error as Fault};
use std::{
    future::{Future, poll_fn},
    pin::pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::time::Instant;
struct StopState {
    stopped: AtomicBool,
    wake: Mutex<Option<Waker>>,
    cleanup_hard: Mutex<Option<Instant>>,
}
/// A caller-owned stop capability for one original session, not a source token.
#[derive(Clone)]
pub struct Stop(Arc<StopState>);
impl Default for Stop {
    fn default() -> Self {
        Self::new()
    }
}
impl Stop {
    /// Construct no native resource or hidden task.
    pub fn new() -> Self {
        Self(Arc::new(StopState {
            stopped: AtomicBool::new(false),
            wake: Mutex::new(None),
            cleanup_hard: Mutex::new(None),
        }))
    }
    /// Capture the first original cleanup target; a second stop may only shorten.
    pub fn request_at(&self, hard: Instant) {
        if let Ok(mut target) = self.0.cleanup_hard.lock() {
            *target = Some(target.map_or(hard, |old| old.min(hard)));
        }
        self.request();
    }
    /// Original cleanup target, never a refreshed duration.
    pub fn cleanup_hard(&self) -> Option<Instant> {
        self.0.cleanup_hard.lock().ok().and_then(|slot| *slot)
    }
    /// Permanently fence this session and wake its original task.
    pub fn request(&self) {
        self.0.stopped.store(true, Ordering::Release);
        if let Ok(mut wake) = self.0.wake.lock()
            && let Some(wake) = wake.take()
        {
            wake.wake();
        }
    }
    /// Whether the original stop has already been requested.
    pub fn requested(&self) -> bool {
        self.0.stopped.load(Ordering::Acquire)
    }
    fn poll(&self, cx: &mut Context<'_>) -> Poll<()> {
        if self.requested() {
            return Poll::Ready(());
        }
        if let Ok(mut wake) = self.0.wake.lock() {
            *wake = Some(cx.waker().clone());
        } else {
            return Poll::Ready(());
        }
        if self.requested() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}
struct Inner {
    clock: Arc<dyn RuntimeClock>,
    until: AbsoluteTime,
    hard: Instant,
    stop: Stop,
    first_clock: Mutex<Option<Fault>>,
}
/// Cheap clones share the same original targets and stop capability.
#[derive(Clone)]
pub struct Budget(Arc<Inner>);
impl Budget {
    /// Capture native hard before canonical time. Construction starts no IO.
    pub fn new(
        clock: Arc<dyn RuntimeClock>,
        duration: Duration,
        stop: Stop,
    ) -> Result<Self, Error> {
        let hard = Instant::now()
            .checked_add(duration)
            .ok_or(Fault::Overflow)?;
        if duration.is_zero() {
            return Err(Fault::InvalidInput.into());
        }
        if stop.requested() {
            return Err(Error::Stopped);
        }
        let sample = clock.sample().map_err(Error::Clock)?;
        if Instant::now() >= hard {
            return Err(Error::Deadline);
        }
        let micros = u64::try_from(duration.as_micros()).map_err(|_| Fault::Overflow)?;
        let until = AbsoluteTime::from_micros(
            sample
                .now
                .as_micros()
                .checked_add(micros)
                .filter(|v| *v != u64::MAX)
                .ok_or(Fault::Overflow)?,
        );
        Ok(Self(Arc::new(Inner {
            clock,
            until,
            hard,
            stop,
            first_clock: Mutex::new(None),
        })))
    }
    /// Original native target, never recomputed for a new phase.
    pub fn hard(&self) -> Instant {
        self.0.hard
    }
    /// Original canonical target, never recomputed for a new phase.
    pub fn until(&self) -> u64 {
        self.0.until.as_micros()
    }
    /// Same actual source clock Arc as the process broker.
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.0.clock.clone()
    }
    /// Check before starting a new capability and after synchronous crypto.
    /// Synchronous syscalls/crypto cannot be forcibly preempted by this guard.
    pub fn check(&self) -> Result<(), Error> {
        if Instant::now() >= self.0.hard {
            return Err(Error::Deadline);
        }
        if self.0.stop.requested() {
            return Err(Error::Stopped);
        }
        let sample = self.0.clock.sample().map_err(|e| {
            if let Ok(mut slot) = self.0.first_clock.lock() {
                slot.get_or_insert(e);
            }
            Error::Clock(e)
        })?;
        if Instant::now() >= self.0.hard || sample.now >= self.0.until {
            return Err(Error::Deadline);
        }
        if self.0.stop.requested() {
            return Err(Error::Stopped);
        }
        Ok(())
    }
    /// Current real canonical microseconds, charged to the same original hard.
    pub fn now(&self) -> Result<u64, Error> {
        self.check()?;
        let now = self.0.clock.sample().map_err(Error::Clock)?.now.as_micros();
        self.check()?;
        Ok(now)
    }
    /// Await only this original future, while retaining original deadline/Stop
    /// wakeups. A native result is not discarded merely because a synchronous
    /// poll crossed hard; the caller records it and guards the next capability.
    pub async fn wait<F: Future>(&self, original: F) -> Result<F::Output, Error> {
        self.check()?;
        let mut original = pin!(original);
        let mut native = pin!(tokio::time::sleep_until(self.0.hard));
        let mut logical =
            pin!(Deadline::at(self.0.clock.clone(), self.0.until).map_err(Error::Clock)?);
        poll_fn(|cx| {
            if Instant::now() >= self.0.hard || native.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(Error::Deadline));
            }
            if self.0.stop.poll(cx).is_ready() {
                return Poll::Ready(Err(Error::Stopped));
            }
            if let Poll::Ready(result) = logical.as_mut().poll(cx) {
                return Poll::Ready(Err(match result {
                    Ok(()) => Error::Deadline,
                    Err(e) => Error::Clock(e),
                }));
            }
            if let Err(error) = self.check() {
                return Poll::Ready(Err(error));
            }
            original.as_mut().poll(cx).map(Ok)
        })
        .await
    }
    /// Same original guard inside real rustls certificate/signature callbacks.
    pub fn tls_guard(&self) -> crate::tls::Guard {
        let original = self.clone();
        Arc::new(move || {
            original.check().map_err(|e| match e {
                Error::Stopped => crate::tls::TlsError::Cancelled,
                Error::Deadline => crate::tls::TlsError::Deadline,
                _ => crate::tls::TlsError::Clock,
            })
        })
    }
    /// Original clock diagnostic retained even inside a synchronous TLS guard.
    pub fn first_clock_error(&self) -> Option<Fault> {
        self.0.first_clock.lock().ok().and_then(|slot| *slot)
    }
}
