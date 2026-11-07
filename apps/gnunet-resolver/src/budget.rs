//! The original five-second call budget, including output/callback backpressure.
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_types::{AbsoluteTime, Error};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
pub(super) struct Budget {
    pub hard: Instant,
    native: Pin<Box<Sleep>>,
    logical: Pin<Box<Deadline>>,
}
impl Budget {
    pub(super) fn new(source: Arc<dyn RuntimeClock>) -> Result<Self, Error> {
        let hard = Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or(Error::Overflow)?;
        let native = Box::pin(tokio::time::sleep_until(hard));
        let until = source
            .sample()?
            .now
            .as_micros()
            .checked_add(5_000_000)
            .filter(|value| *value != u64::MAX)
            .map(AbsoluteTime::from_micros)
            .ok_or(Error::Overflow)?;
        if Instant::now() >= hard {
            return Err(Error::Deadline);
        }
        let logical = Box::pin(Deadline::at(source, until)?);
        if Instant::now() >= hard {
            return Err(Error::Deadline);
        }
        Ok(Self {
            hard,
            native,
            logical,
        })
    }
    pub(super) fn native_guard(&mut self, cx: &mut Context<'_>) -> Result<(), Error> {
        if Instant::now() >= self.hard || self.native.as_mut().poll(cx).is_ready() {
            return Err(Error::Deadline);
        }
        Ok(())
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Result<(), Error> {
        self.native_guard(cx)?;
        if let Poll::Ready(result) = self.logical.as_mut().poll(cx) {
            result?;
            return Err(Error::Deadline);
        }
        self.native_guard(cx)
    }
}
