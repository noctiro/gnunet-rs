//! One original optional total budget. FOREVER has no fabricated native alarm.
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_types::{AbsoluteTime, Error};
use std::{future::Future, pin::Pin, sync::Arc, task::Context, time::Duration};
use tokio::time::{Instant, Sleep};
pub(super) struct Budget {
    pub until: AbsoluteTime,
    pub hard: Option<Instant>,
    native: Option<Pin<Box<Sleep>>>,
    logical: Option<Pin<Box<Deadline>>>,
}
impl Budget {
    pub(super) fn new(source: Arc<dyn RuntimeClock>, timeout: u64) -> Result<Self, Error> {
        let hard = if timeout == u64::MAX {
            None
        } else {
            Some(
                Instant::now()
                    .checked_add(Duration::from_micros(timeout))
                    .ok_or(Error::Overflow)?,
            )
        };
        let native = hard.map(|value| Box::pin(tokio::time::sleep_until(value)));
        let until = if timeout == u64::MAX {
            AbsoluteTime::NEVER
        } else {
            AbsoluteTime::from_micros(
                source
                    .sample()?
                    .now
                    .as_micros()
                    .checked_add(timeout)
                    .filter(|v| *v != u64::MAX)
                    .ok_or(Error::Overflow)?,
            )
        };
        if hard.is_some_and(|value| Instant::now() >= value) {
            return Err(Error::Deadline);
        }
        let logical = if until.is_never() {
            None
        } else {
            Some(Box::pin(Deadline::at(source, until)?))
        };
        if hard.is_some_and(|value| Instant::now() >= value) {
            return Err(Error::Deadline);
        }
        Ok(Self {
            until,
            hard,
            native,
            logical,
        })
    }
    pub(super) fn native_guard(&mut self, cx: &mut Context<'_>) -> Result<(), Error> {
        if self.hard.is_some_and(|value| Instant::now() >= value)
            || self
                .native
                .as_mut()
                .is_some_and(|alarm| alarm.as_mut().poll(cx).is_ready())
        {
            return Err(Error::Deadline);
        }
        Ok(())
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Result<(), Error> {
        self.native_guard(cx)?;
        if let Some(deadline) = &mut self.logical
            && let std::task::Poll::Ready(result) = deadline.as_mut().poll(cx)
        {
            result?;
            return Err(Error::Deadline);
        }
        self.native_guard(cx)
    }
}
