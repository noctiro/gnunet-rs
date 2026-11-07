//! Original logical/native spans and independent wake registration. No canonical
//! revision race can suppress an already admitted job's native hard retirement.
use gnunet_service_runtime::clock::{ClockSubscription, Deadline as LogicalDeadline, RuntimeClock};
use gnunet_types::Error as Fault;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
#[derive(Clone, Copy, Debug)]
pub(crate) struct Span {
    pub logical: u64,
    pub hard: Instant,
}
impl Span {
    pub fn new(now: u64, duration: Duration) -> Result<Self, Fault> {
        let micros = u64::try_from(duration.as_micros()).map_err(|_| Fault::Overflow)?;
        if micros == 0 {
            return Err(Fault::InvalidInput);
        }
        let logical = now
            .checked_add(micros)
            .filter(|n| *n != u64::MAX)
            .ok_or(Fault::Overflow)?;
        let hard = Instant::now()
            .checked_add(duration)
            .ok_or(Fault::Overflow)?;
        Ok(Self { logical, hard })
    }
    pub fn expired(self, now: Option<u64>) -> bool {
        Instant::now() >= self.hard || now.is_some_and(|n| n >= self.logical)
    }
}
/// Immutable original logical/native calling budget from one actual Api clock.
/// Copying preserves both targets and owner; it grants no message authentication,
/// provider receipt, membership or native admission.
#[derive(Clone, Copy, Debug)]
pub struct Deadline {
    pub(crate) owner: u64,
    pub(crate) span: Span,
}
impl Deadline {
    /// Original absolute logical microsecond target, never recomputed on retry.
    pub const fn expires(self) -> u64 {
        self.span.logical
    }
    /// Original native target captured before the initial canonical sample.
    pub const fn hard(self) -> Instant {
        self.span.hard
    }
    /// Check the original native target and optional same-clock observation.
    pub fn expired(self, now: Option<u64>) -> bool {
        self.span.expired(now)
    }
}
pub(crate) struct DriverClock {
    pub source: Arc<dyn RuntimeClock>,
    subscription: Box<dyn ClockSubscription>,
    revision: u64,
    logical: Option<Pin<Box<LogicalDeadline>>>,
    logical_at: Option<u64>,
    native: Option<Pin<Box<Sleep>>>,
    native_at: Option<Instant>,
}
impl DriverClock {
    pub fn new(source: Arc<dyn RuntimeClock>) -> Result<Self, Fault> {
        let subscription = source.subscribe()?;
        let revision = source.sample()?.revision;
        Ok(Self {
            source,
            subscription,
            revision,
            logical: None,
            logical_at: None,
            native: None,
            native_at: None,
        })
    }
    pub fn sample(&self) -> Result<u64, Fault> {
        Ok(self.source.sample()?.now.as_micros())
    }
    pub fn poll_now(&mut self, cx: &mut Context<'_>) -> Poll<Result<u64, Fault>> {
        match self.subscription.poll_changed(cx, self.revision) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(s)) => self.revision = s.revision,
            Poll::Pending => {}
        }
        let sample = match self.source.sample() {
            Ok(v) => v,
            Err(e) => return Poll::Ready(Err(e)),
        };
        self.revision = sample.revision;
        match self.subscription.poll_changed(cx, sample.revision) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Pending => Poll::Ready(Ok(sample.now.as_micros())),
        }
    }
    /// Must be called before poll_now, with the ORIGINAL outstanding hard bounds.
    pub fn poll_native(&mut self, cx: &mut Context<'_>, target: Option<Instant>) -> bool {
        let Some(target) = target else {
            self.native = None;
            self.native_at = None;
            return false;
        };
        if self.native_at != Some(target) {
            self.native = Some(Box::pin(tokio::time::sleep_until(target)));
            self.native_at = Some(target);
        }
        self.native
            .as_mut()
            .is_some_and(|timer| timer.as_mut().poll(cx).is_ready())
    }
    pub fn poll_logical(
        &mut self,
        cx: &mut Context<'_>,
        target: Option<u64>,
    ) -> Result<bool, Fault> {
        let Some(target) = target else {
            self.logical = None;
            self.logical_at = None;
            return Ok(false);
        };
        if self.logical_at != Some(target) {
            self.logical = Some(Box::pin(LogicalDeadline::at(
                self.source.clone(),
                gnunet_types::AbsoluteTime::from_micros(target),
            )?));
            self.logical_at = Some(target);
        }
        if let Some(timer) = self.logical.as_mut() {
            match timer.as_mut().poll(cx) {
                Poll::Ready(result) => {
                    self.logical = None;
                    self.logical_at = None;
                    result?;
                    return Ok(true);
                }
                Poll::Pending => {}
            }
        }
        Ok(false)
    }
    pub fn clear_alarms(&mut self) {
        self.logical = None;
        self.logical_at = None;
        self.native = None;
        self.native_at = None;
    }
}
