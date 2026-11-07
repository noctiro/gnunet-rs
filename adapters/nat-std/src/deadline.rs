//! Original logical/native dual bound with independent native alarms before
//! canonical clock stabilization. A racing clock cannot starve hard shutdown.
use crate::Error;
use gnunet_service_runtime::clock::{ClockSubscription, RuntimeClock};
use gnunet_types::Error as Fault;
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
/// Original admitted bounds; copies preserve exact targets, never a fresh TTL.
#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    /// Absolute original process-clock expiry in microseconds.
    pub expires: u64,
    /// Independent original native hard bound.
    pub hard: Instant,
}
impl Bounds {
    /// Admit a finite relative request once, before any native work.
    pub fn after(clock: &dyn RuntimeClock, timeout: Duration) -> Result<Self, Error> {
        if timeout.is_zero() {
            return Err(Fault::Deadline.into());
        }
        let now = clock.sample().map_err(Error::Clock)?.now.as_micros();
        let delta = u64::try_from(timeout.as_micros()).map_err(|_| Fault::Overflow)?;
        Ok(Self {
            expires: now.checked_add(delta).ok_or(Fault::Overflow)?,
            hard: Instant::now().checked_add(timeout).ok_or(Fault::Overflow)?,
        })
    }
    /// Validate original targets without extending either.
    pub fn check(self, clock: &dyn RuntimeClock) -> Result<u64, Error> {
        if Instant::now() >= self.hard {
            return Err(Fault::Deadline.into());
        }
        let now = clock.sample().map_err(Error::Clock)?.now.as_micros();
        if now >= self.expires {
            return Err(Fault::Deadline.into());
        }
        Ok(now)
    }
}
/// One exclusive logical waiter plus exact native hard/earliest logical alarms.
/// Every blocked IO must be polled through this owner; dropping it cancels only
/// this logical waiter/timer, not some other original operation or socket.
pub struct Gate {
    clock: Arc<dyn RuntimeClock>,
    subscription: Box<dyn ClockSubscription>,
    revision: u64,
    bounds: Bounds,
    hard: Pin<Box<Sleep>>,
    logical: Pin<Box<Sleep>>,
}
impl Gate {
    /// Reserve exactly one clock waiter for an admitted original operation.
    pub fn new(clock: Arc<dyn RuntimeClock>, bounds: Bounds) -> Result<Self, Error> {
        let now = bounds.check(&*clock)?;
        let subscription = clock.subscribe().map_err(Error::Clock)?;
        let revision = clock.sample().map_err(Error::Clock)?.revision;
        let wake = Instant::now()
            .checked_add(Duration::from_micros(bounds.expires - now))
            .ok_or(Fault::Overflow)?
            .min(bounds.hard);
        Ok(Self {
            clock,
            subscription,
            revision,
            bounds,
            hard: Box::pin(tokio::time::sleep_until(bounds.hard)),
            logical: Box::pin(tokio::time::sleep_until(wake)),
        })
    }
    /// Original source clock, shared by identity with the selected Resolver.
    pub fn clock(&self) -> &Arc<dyn RuntimeClock> {
        &self.clock
    }
    /// Original immutable targets.
    pub const fn bounds(&self) -> Bounds {
        self.bounds
    }
    /// Immediate admission/receipt guard. Independent hard check is first.
    pub fn check(&self) -> Result<u64, Error> {
        self.bounds.check(&*self.clock)
    }
    /// Register hard alarm first, then stabilize the canonical source and
    /// register the absolute logical target (including actual rollback).
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<u64, Error>> {
        if Instant::now() >= self.bounds.hard || self.hard.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(Fault::Deadline.into()));
        }
        match self.subscription.poll_changed(cx, self.revision) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(Error::Clock(e))),
            Poll::Ready(Ok(sample)) => self.revision = sample.revision,
            Poll::Pending => {}
        }
        let sample = self.clock.sample().map_err(Error::Clock)?;
        match self.subscription.poll_changed(cx, sample.revision) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(Error::Clock(e))),
            Poll::Ready(Ok(_)) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Pending => {}
        }
        self.revision = sample.revision;
        if sample.now.as_micros() >= self.bounds.expires {
            return Poll::Ready(Err(Fault::Deadline.into()));
        }
        let wake = Instant::now()
            .checked_add(Duration::from_micros(
                self.bounds.expires - sample.now.as_micros(),
            ))
            .ok_or(Fault::Overflow)?
            .min(self.bounds.hard);
        self.logical.as_mut().reset(wake);
        if self.logical.as_mut().poll(cx).is_ready() {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Poll::Ready(Ok(sample.now.as_micros()))
    }
    /// Run real bounded IO, retaining an actual completed result during a clock
    /// revision race instead of polling an already-completed future again.
    pub async fn run<T>(
        &mut self,
        future: impl Future<Output = std::io::Result<T>>,
    ) -> Result<T, Error> {
        let mut future = std::pin::pin!(future);
        let mut result = None;
        poll_fn(|cx| {
            match self.poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(_)) => {}
            }
            if result.is_none() {
                match future.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(value) => result = Some(value),
                }
            }
            match self.poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Ready(Ok(_)) => Poll::Ready(
                    result
                        .take()
                        .ok_or(Fault::NotReady.into())
                        .and_then(|r| r.map_err(Error::Io)),
                ),
            }
        })
        .await
    }
}
