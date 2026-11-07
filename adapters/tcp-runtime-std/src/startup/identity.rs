//! Original observer continuity and one bounded, coalescing replacement window.
use super::Failure;
use crate::statistics::Metrics;
use gnunet_pils::client::{Epoch, Identity};
use gnunet_pils_host::client::{LossCause, Progress};
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_types::{AbsoluteTime, Error};
use std::{
    error::Error as StdError, fmt, future::Future, pin::Pin, sync::Arc, task::Context,
    time::Duration,
};
use tokio::time::{Instant, Sleep};

pub(super) struct Window {
    pub hard: Instant,
    pub until: u64,
    native: Pin<Box<Sleep>>,
    canonical: Pin<Box<Deadline>>,
}
impl Window {
    fn new(source: Arc<dyn RuntimeClock>) -> Result<Self, Failure> {
        let hard = Instant::now()
            .checked_add(Duration::from_secs(30))
            .ok_or(Error::Overflow)?;
        let until = source
            .sample()?
            .now
            .as_micros()
            .checked_add(30_000_000)
            .filter(|v| *v != u64::MAX)
            .ok_or(Error::Overflow)?;
        Ok(Self {
            hard,
            until,
            native: Box::pin(tokio::time::sleep_until(hard)),
            canonical: Box::pin(Deadline::at(source, AbsoluteTime::from_micros(until))?),
        })
    }
    fn guard(&mut self, cx: &mut Context<'_>) -> Result<(), Failure> {
        if Instant::now() >= self.hard || self.native.as_mut().poll(cx).is_ready() {
            return Err("original TCP identity recovery deadline expired".into());
        }
        if let std::task::Poll::Ready(result) = self.canonical.as_mut().poll(cx) {
            result?;
            return Err("original TCP canonical identity recovery deadline expired".into());
        }
        if Instant::now() >= self.hard {
            return Err("original TCP identity recovery deadline expired".into());
        }
        Ok(())
    }
}

pub(super) struct Continuity<'id> {
    epoch: Epoch<'id>,
    window: Option<Window>,
    retired: Metrics,
    ready: bool,
}
impl<'id> Continuity<'id> {
    pub(super) fn new(identity: Identity<'id>) -> Self {
        Self {
            epoch: identity.epoch(),
            window: None,
            retired: Metrics::default(),
            ready: false,
        }
    }
    pub(super) fn verify(
        &self,
        identity: Identity<'id>,
        source: &dyn RuntimeClock,
    ) -> Result<(), Failure> {
        if identity.epoch() != self.epoch {
            return Err(Error::StaleGeneration.into());
        }
        if identity.expiration().as_micros() <= source.sample()?.now.as_micros() {
            return Err(Error::Timeout.into());
        }
        Ok(())
    }
    pub(super) fn changing(
        &mut self,
        next: Identity<'id>,
        source: Arc<dyn RuntimeClock>,
    ) -> Result<(), Failure> {
        self.verify(next, source.as_ref())?;
        if self.window.is_none() {
            self.window = Some(Window::new(source)?);
        }
        Ok(())
    }
    pub(super) fn guard(&mut self, cx: &mut Context<'_>) -> Result<(), Failure> {
        if let Some(window) = &mut self.window {
            window.guard(cx)?;
        }
        Ok(())
    }
    pub(super) fn bounds(&self) -> Option<(Instant, u64)> {
        self.window.as_ref().map(|v| (v.hard, v.until))
    }
    pub(super) fn activate(&mut self) -> bool {
        self.window = None;
        let first = !self.ready;
        self.ready = true;
        first
    }
    pub(super) fn combine(&self, live: Metrics) -> Metrics {
        let mut total = self.retired;
        total.add_active(live);
        total
    }
    pub(super) fn retire(&mut self, combined: Option<Metrics>) {
        if let Some(combined) = combined {
            self.retired = Metrics::default();
            self.retired.add_retired(combined);
        }
    }
}

#[derive(Debug)]
struct ProviderLoss {
    epoch: u64,
    cause: LossCause,
    feeds: usize,
    retained: usize,
}
impl fmt::Display for ProviderLoss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "original TCP PILS source epoch={} lost: {:?}; feeds={} retained={}",
            self.epoch, self.cause, self.feeds, self.retained
        )
    }
}
impl StdError for ProviderLoss {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match &self.cause {
            LossCause::Io(e) => Some(e),
            LossCause::Protocol(e) | LossCause::Resource(e) => Some(e),
            LossCause::Setup(e) => Some(e),
            LossCause::Eof | LossCause::Requested => None,
        }
    }
}
/// Observe by borrow, then retain the original fatal producer cause by value.
pub(super) fn observe(
    event: Progress<'_>,
    callback: &mut dyn for<'p> FnMut(&Progress<'p>),
) -> Result<(), Failure> {
    callback(&event);
    match event {
        Progress::Lost {
            epoch,
            cause,
            report,
        } => Err(Box::new(ProviderLoss {
            epoch: epoch.value(),
            cause,
            feeds: report.feeds().count(),
            retained: report.retained(),
        })),
        Progress::Unavailable(error) => Err(Box::new(error)),
        Progress::Closed => Err(Error::Closed.into()),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests;
