use super::session::Observation;
use super::{Bounds, Error, Fault, LocalEvent, PilsIdentity, PilsInbound, State, pils};
use crate::run::Known;
use gnunet_client_host::ConnectError;
use std::{
    task::{Context, Poll},
    time::{Duration, Instant},
};

pub(super) fn current<'p>(
    pils: &pils::Client<'p, 1>,
    expected: Option<PilsIdentity<'p>>,
) -> Result<(), Fault> {
    let expected = expected.ok_or(Fault::NotReady)?;
    let actual = pils.identity().ok_or(Fault::StaleGeneration)?;
    if actual.epoch() != expected.epoch()
        || actual.peer() != expected.peer()
        || pils.epoch() != Some(expected.epoch())
    {
        return Err(Fault::StaleGeneration);
    }
    Ok(())
}
impl<'s, 'p, 'c, 'slots> State<'s, 'p, 'c, 'slots> {
    pub(super) fn poll_identity(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        self.refresh()?;
        if self.session.core().is_some() {
            current(&self.pils, self.session.observed())?;
        }
        // Preserve the actual input until its public identity observation can
        // be emitted. No verified update is consumed into a full event queue.
        if !self.events.room()? {
            return Ok(false);
        }
        let control = &self.control;
        let clock = &self.sources.clock;
        let required = self.session.core().is_some();
        let mut guard = || {
            control
                .check(clock.as_ref(), required)
                .map(|_| ())
                .map_err(ConnectError::from)
        };
        let wait = self.earliest()?.map(|b| b.hard.into());
        let event = match self.pils.poll_guarded(cx, wait, &mut guard) {
            Poll::Pending => return Ok(false),
            Poll::Ready(event) => event?,
        };
        if matches!(&event, pils::Progress::Inbound(_))
            && let Some(original) = self.pils_input
        {
            original.check(self.sources.clock.as_ref())?;
        }
        match event {
            pils::Progress::Connected(_) => Ok(true),
            pils::Progress::Inbound(PilsInbound::Identity { identity, .. }) => {
                self.pils_input = None;
                self.session.check(identity)?;
                let begin = Instant::now();
                let sample = self.sources.clock.sample()?.now.as_micros();
                let uncertainty = u64::try_from(self.limits.utc_uncertainty.as_micros())
                    .map_err(|_| Fault::Overflow)?;
                let utc = sample
                    .checked_add(uncertainty)
                    .filter(|v| *v != u64::MAX)
                    .ok_or(Fault::TimeUncertain)?;
                let expires = identity.expiration().as_micros();
                if utc >= expires {
                    return Err(Fault::Timeout.into());
                }
                let unchanged = self
                    .session
                    .observed()
                    .is_some_and(|old| old.expiration() == identity.expiration());
                if !unchanged {
                    self.ttl = if expires == u64::MAX {
                        None
                    } else {
                        Some(Bounds {
                            canonical: expires
                                .checked_sub(uncertainty)
                                .ok_or(Fault::TimeUncertain)?,
                            hard: begin
                                .checked_add(Duration::from_micros(expires - utc))
                                .ok_or(Fault::Overflow)?,
                        })
                    };
                }
                let known = Known {
                    peer: *identity.peer().as_bytes(),
                    epoch: identity.epoch().value(),
                    revision: identity.revision(),
                    expiration: expires,
                };
                let previous = self.session.observed().map(|old| Known {
                    peer: *old.peer().as_bytes(),
                    epoch: old.epoch().value(),
                    revision: old.revision(),
                    expiration: old.expiration().as_micros(),
                });
                let now = if self.session.core().is_none() {
                    self.now()?
                } else {
                    self.last_now
                };
                let change = self.session.observe(identity, self.limits.core, now)?;
                self.control.known(previous, known)?;
                if change != Observation::Refresh {
                    self.report.identity = Some((known.peer, known.epoch));
                    self.events.emit(LocalEvent::Identity {
                        peer: known.peer,
                        epoch: known.epoch,
                    })?;
                }
                self.control.check(self.sources.clock.as_ref(), true)?;
                self.account()?;
                self.mark();
                Ok(true)
            }
            pils::Progress::Inbound(PilsInbound::Ignored) => {
                self.pils_input = None;
                Ok(true)
            }
            pils::Progress::Inbound(PilsInbound::Complete(_)) | pils::Progress::Written(_) => {
                Err(Fault::StaleGeneration.into())
            }
            pils::Progress::Activity { read_bytes, .. } => {
                if read_bytes > 0 && self.pils_input.is_none() {
                    self.pils_input = Some(self.origin.after(self.limits.peer_input)?);
                }
                Ok(true)
            }
            pils::Progress::Lost { cause, .. } => Err(Error::Pils(cause)),
            pils::Progress::ConnectRetry { error, .. } => {
                self.report.first_pils_retry.get_or_insert(error);
                Ok(true)
            }
            pils::Progress::Unavailable(error) => Err(error.into()),
            pils::Progress::Closed => Err(Fault::Closed.into()),
            pils::Progress::WaitDeadline => {
                self.refresh()?;
                self.control
                    .check(self.sources.clock.as_ref(), self.session.core().is_some())?;
                Ok(false)
            }
        }
    }
}
