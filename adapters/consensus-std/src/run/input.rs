//! Original application frame cursor while PILS and the session advance.
use super::Wait;
use crate::{Bounds, Error};
use gnunet_service_runtime::{
    clock::RuntimeClock,
    framing::{Framed, ReadStep},
};
use gnunet_types::Error as Fault;
use std::{
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

pub(super) struct Input {
    pub(super) framed: Framed<()>,
    pub(super) partial: Option<Wait>,
    pub(super) bytes: usize,
}

impl Input {
    pub(super) fn new(framed: Framed<()>) -> Self {
        Self {
            framed,
            partial: None,
            bytes: 0,
        }
    }

    pub(super) fn poll_deadline(&mut self, cx: &mut Context<'_>) -> Result<(), Error> {
        if let Some(wait) = &mut self.partial {
            wait.poll(cx)?;
        }
        Ok(())
    }

    pub(super) fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        clock: &Arc<dyn RuntimeClock>,
        original: Bounds,
        lifetime: Duration,
    ) -> Poll<Result<ReadStep, Error>> {
        let before = Instant::now();
        if before >= original.hard
            || self
                .partial
                .as_ref()
                .is_some_and(|wait| before >= wait.bounds.hard)
        {
            return Poll::Ready(Err(Fault::Deadline.into()));
        }
        let Poll::Ready(result) = self.framed.poll_read(cx) else {
            return Poll::Pending;
        };
        let step = result?;
        if let ReadStep::Progress { bytes, .. } = step {
            self.bytes = self.bytes.checked_add(bytes).ok_or(Fault::Overflow)?;
            if self.partial.is_none() {
                let now = clock.sample()?.now.as_micros();
                let micros = u64::try_from(lifetime.as_micros()).map_err(|_| Fault::Overflow)?;
                let expires = now
                    .checked_add(micros)
                    .ok_or(Fault::Overflow)?
                    .min(original.expires);
                let hard = before
                    .checked_add(lifetime)
                    .ok_or(Fault::Overflow)?
                    .min(original.hard);
                self.partial = Some(Wait::new(clock.clone(), Bounds { expires, hard })?);
            }
        }
        Poll::Ready(Ok(step))
    }
}
