//! Original observer continuity and one bounded, coalescing replacement window.
use super::Failure;
use crate::statistics::Metrics;
use gnunet_pils::client::{Epoch, Identity};
use gnunet_pils_host::client::{Client, ConnectionLoss, LossCause, Progress};
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

enum Source<'id> {
    Current(Identity<'id>),
    Lost {
        previous: Option<Identity<'id>>,
        epoch: Epoch<'id>,
    },
}
pub(super) struct Continuity<'id> {
    source: Source<'id>,
    first_loss: Option<ConnectionLoss>,
    window: Option<Window>,
    retired: Metrics,
    ready: bool,
}
impl<'id> Continuity<'id> {
    pub(super) fn new(identity: Identity<'id>) -> Self {
        Self {
            source: Source::Current(identity),
            first_loss: None,
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
        let valid = match &self.source {
            Source::Current(previous) => {
                identity.epoch() == previous.epoch()
                    && identity.revision() >= previous.revision()
                    && (identity.revision() != previous.revision() || identity == *previous)
            }
            Source::Lost { previous, epoch } => {
                identity.epoch().is_successor_of(*epoch)
                    && previous.is_none_or(|previous| identity.revision() > previous.revision())
            }
        };
        if !valid {
            return Err(Error::StaleGeneration.into());
        }
        let now = source.sample()?.now.as_micros();
        if identity.expiration().as_micros() <= now {
            return Err(Error::Timeout.into());
        }
        if self
            .window
            .as_ref()
            .is_some_and(|window| Instant::now() >= window.hard || now >= window.until)
        {
            return Err(Error::Deadline.into());
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
        self.source = Source::Current(next);
        Ok(())
    }
    pub(super) fn paused(&self) -> bool {
        matches!(self.source, Source::Lost { .. })
    }
    fn failure(&mut self, terminal: Failure) -> Failure {
        match self.first_loss.take() {
            Some(first) => Box::new(RecoveryFailure { first, terminal }),
            None => terminal,
        }
    }
    pub(super) fn guard(&mut self, cx: &mut Context<'_>) -> Result<(), Failure> {
        if let Some(window) = &mut self.window
            && let Err(error) = window.guard(cx)
        {
            return Err(self.failure(error));
        }
        Ok(())
    }
    pub(super) fn guard_io(&mut self, source: &dyn RuntimeClock) -> Result<(), Failure> {
        let Some(window) = &self.window else {
            return Ok(());
        };
        let (hard, until) = (window.hard, window.until);
        if Instant::now() >= hard {
            return Err(self.failure(Error::Deadline.into()));
        }
        let sampled = source.sample();
        if Instant::now() >= hard {
            return Err(self.failure(Error::Deadline.into()));
        }
        let now = sampled
            .map_err(|error| self.failure(error.into()))?
            .now
            .as_micros();
        if now >= until {
            return Err(self.failure(Error::Deadline.into()));
        }
        Ok(())
    }
    pub(super) fn poll_source(
        &mut self,
        client: &mut Client<'id>,
        source: &dyn RuntimeClock,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<Result<Progress<'id>, Failure>> {
        let mut refused = None;
        let result = client.poll_guarded(cx, None, &mut || match self.guard_io(source) {
            Ok(()) => Ok(()),
            Err(error) => {
                refused = Some(error);
                Err(Error::Deadline.into())
            }
        });
        match refused {
            Some(error) => std::task::Poll::Ready(Err(error)),
            None => result.map(|result| result.map_err(|error| Box::new(error) as Failure)),
        }
    }
    pub(super) fn bounds(&self) -> Option<(Instant, u64)> {
        self.window.as_ref().map(|v| (v.hard, v.until))
    }
    pub(super) fn activate(&mut self) -> bool {
        self.window = None;
        self.first_loss = None;
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
#[derive(Debug)]
struct RecoveryFailure {
    first: ConnectionLoss,
    terminal: Failure,
}
impl fmt::Display for RecoveryFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TCP PILS recovery ended: {}; first connection loss: {}",
            self.terminal, self.first
        )
    }
}
impl StdError for RecoveryFailure {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.terminal.as_ref())
    }
}
/// Only actual stream loss with an idle public observer can enter recovery.
/// This predicate grants neither a replacement epoch nor private-key access.
pub(super) fn recoverable(event: &Progress<'_>) -> bool {
    matches!(event,Progress::Lost {cause,report,..}
        if cause.is_connection_loss() && report.retained()==0 && report.feeds().next().is_none())
}
impl<'id> Continuity<'id> {
    pub(super) fn observe(
        &mut self,
        event: Progress<'id>,
        callback: &mut dyn for<'p> FnMut(&Progress<'p>),
        source: Arc<dyn RuntimeClock>,
    ) -> Result<bool, Failure> {
        callback(&event);
        match event {
            Progress::Lost {
                epoch,
                cause,
                report,
            } => {
                if report.retained() != 0 || report.feeds().next().is_some() {
                    return Err(Box::new(ProviderLoss {
                        epoch: epoch.value(),
                        cause,
                        feeds: report.feeds().count(),
                        retained: report.retained(),
                    }));
                }
                let first = match cause.into_connection_loss() {
                    Ok(first) => first,
                    Err(cause) => {
                        return Err(Box::new(ProviderLoss {
                            epoch: epoch.value(),
                            cause,
                            feeds: 0,
                            retained: 0,
                        }));
                    }
                };
                let previous = match self.source {
                    Source::Current(previous) if previous.epoch() == epoch => Some(previous),
                    Source::Lost {
                        previous,
                        epoch: old,
                    } if epoch == old || epoch.is_successor_of(old) => previous,
                    _ => return Err(Error::StaleGeneration.into()),
                };
                self.source = Source::Lost { previous, epoch };
                self.first_loss.get_or_insert(first);
                if self.window.is_none() {
                    self.window = Some(Window::new(source)?);
                }
                Ok(true)
            }
            Progress::Connected(epoch) => {
                if let Source::Lost { epoch: lost, .. } = self.source
                    && !epoch.is_successor_of(lost)
                {
                    return Err(Error::StaleGeneration.into());
                }
                Ok(false)
            }
            Progress::Inbound(gnunet_pils::client::Inbound::Identity { identity, .. }) => {
                self.verify(identity, source.as_ref())?;
                self.source = Source::Current(identity);
                Ok(false)
            }
            Progress::Unavailable(error) => Err(Box::new(error)),
            Progress::Closed => Err(Error::Closed.into()),
            _ => Ok(false),
        }
    }
}
pub(super) fn observe_initial<'id>(
    event: Progress<'id>,
    callback: &mut dyn for<'p> FnMut(&Progress<'p>),
    continuity: &mut Option<Continuity<'id>>,
    source: Arc<dyn RuntimeClock>,
) -> Result<bool, Failure> {
    if let Some(continuity) = continuity {
        return continuity.observe(event, callback, source);
    }
    if let Progress::Inbound(gnunet_pils::client::Inbound::Identity { identity, .. }) = &event {
        *continuity = Some(Continuity::new(*identity));
        callback(&event);
        return Ok(false);
    }
    if let Progress::Lost { epoch, .. } = &event {
        *continuity = Some(Continuity {
            source: Source::Lost {
                previous: None,
                epoch: *epoch,
            },
            first_loss: None,
            window: None,
            retired: Metrics::default(),
            ready: false,
        });
        return continuity
            .as_mut()
            .ok_or(Error::Conflict)?
            .observe(event, callback, source);
    }
    callback(&event);
    match event {
        Progress::Unavailable(error) => Err(Box::new(error)),
        Progress::Closed => Err(Error::Closed.into()),
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests;
