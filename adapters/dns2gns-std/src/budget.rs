//! Original finite query lifetime; polling never renews either target.
use crate::{RequestError, StopReason};
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_types::{AbsoluteTime, Error as Fault};
use std::{
    cell::Cell,
    future::{Future, poll_fn},
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};

pub(crate) struct Budget {
    pub(crate) clock: Arc<dyn RuntimeClock>,
    pub(crate) until: u64,
    pub(crate) hard: Instant,
    pub(crate) cancel: Rc<Cell<Option<StopReason>>>,
    native: Pin<Box<Sleep>>,
    logical: Pin<Box<Deadline>>,
}
impl Budget {
    pub(crate) fn new(
        clock: Arc<dyn RuntimeClock>,
        until: u64,
        hard: Instant,
        cancel: Rc<Cell<Option<StopReason>>>,
    ) -> Result<Self, RequestError> {
        check_native(&cancel, hard)?;
        let logical = Deadline::at(clock.clone(), AbsoluteTime::from_micros(until))
            .map_err(RequestError::Protocol)?;
        check_native(&cancel, hard)?;
        Ok(Self {
            clock,
            until,
            hard,
            cancel,
            native: Box::pin(tokio::time::sleep_until(hard)),
            logical: Box::pin(logical),
        })
    }
    pub(crate) fn now(&self) -> Result<u64, RequestError> {
        check_native(&self.cancel, self.hard)?;
        let now = self
            .clock
            .sample()
            .map_err(RequestError::Protocol)?
            .now
            .as_micros();
        check_native(&self.cancel, self.hard)?;
        if now >= self.until {
            return Err(RequestError::LogicalDeadline);
        }
        Ok(now)
    }
    pub(crate) fn poll_guard(&mut self, cx: &mut Context<'_>) -> Result<(), RequestError> {
        check_native(&self.cancel, self.hard)?;
        if self.native.as_mut().poll(cx).is_ready() {
            self.cancel.set(Some(StopReason::NativeDeadline));
            return Err(RequestError::Stopped(StopReason::NativeDeadline));
        }
        match self.logical.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => return Err(RequestError::LogicalDeadline),
            Poll::Ready(Err(error)) => return Err(RequestError::Protocol(error)),
            Poll::Pending => {}
        }
        check_native(&self.cancel, self.hard)
    }
    pub(crate) async fn wait<F: Future>(&mut self, future: F) -> Result<F::Output, RequestError> {
        let mut future = std::pin::pin!(future);
        poll_fn(|cx| {
            if let Err(error) = self.poll_guard(cx) {
                return Poll::Ready(Err(error));
            }
            future.as_mut().poll(cx).map(Ok)
        })
        .await
    }
    pub(crate) async fn yield_turn(&mut self) -> Result<(), RequestError> {
        let mut yielded = false;
        self.wait(poll_fn(|cx| {
            if yielded {
                Poll::Ready(())
            } else {
                yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }))
        .await
    }
}
pub(crate) fn check_native(
    cancel: &Cell<Option<StopReason>>,
    hard: Instant,
) -> Result<(), RequestError> {
    if let Some(reason) = cancel.get() {
        return Err(RequestError::Stopped(reason));
    }
    if Instant::now() >= hard {
        return Err(RequestError::Stopped(StopReason::NativeDeadline));
    }
    Ok(())
}
pub(crate) fn duration_micros(value: std::time::Duration) -> Result<u64, Fault> {
    let micros = u64::try_from(value.as_micros()).map_err(|_| Fault::Overflow)?;
    if micros == 0 || micros == u64::MAX {
        return Err(Fault::InvalidInput);
    }
    Ok(micros)
}
