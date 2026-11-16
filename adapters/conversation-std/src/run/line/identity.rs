use super::session::Observation;
use super::{Bounds, Error, Fault, LocalEvent, PilsIdentity, PilsInbound, State, pils};
use crate::run::Known;
use gnunet_client_host::ConnectError;
use std::{
    task::{Context, Poll},
    time::{Duration, Instant},
};
fn known(identity: PilsIdentity<'_>) -> Known {
    Known {
        peer: *identity.peer().as_bytes(),
        epoch: identity.epoch().value(),
        revision: identity.revision(),
        expiration: identity.expiration().as_micros(),
    }
}

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
        if !self.session.waiting() && self.session.core().is_some() {
            current(&self.pils, self.session.observed())?;
        }
        // Preserve the actual input until its public identity observation can
        // be emitted. No verified update is consumed into a full event queue.
        if !self.events.room()? {
            return Ok(false);
        }
        let control = &self.control;
        let clock = &self.sources.clock;
        let required = self.session.observed().is_some();
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
                    .previous()
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
                let next = known(identity);
                let previous = self.session.observed().map(known);
                let now = if self.session.core().is_none() {
                    self.now()?
                } else {
                    self.last_now
                };
                let change = self.session.observe(identity, self.limits.core, now)?;
                self.control.known(previous, next)?;
                if change != Observation::Refresh {
                    self.report.identity = Some((next.peer, next.epoch));
                    self.events.emit(LocalEvent::Identity {
                        peer: next.peer,
                        epoch: next.epoch,
                    })?;
                }
                self.refresh()?;
                self.control.check(self.sources.clock.as_ref(), true)?;
                self.recovery = None;
                self.refresh()?;
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
            pils::Progress::Lost {
                epoch,
                cause,
                report,
            } if cause.is_connection_loss()
                && report.feeds().next().is_none()
                && report.retained() == 0 =>
            {
                let previous = self.session.observed().map(known);
                self.session.pause(epoch)?;
                self.control.pause_identity(previous)?;
                // No unattached connector may retain a captured pre-loss gate.
                // An attached CADET source and all byte cursors stay untouched.
                self.cadet.cancel_connect();
                self.pils_input = None;
                if self.recovery.is_none() {
                    self.recovery = Some(self.origin.after(self.limits.startup)?);
                }
                let loss = cause.into_connection_loss().map_err(Error::Pils)?;
                self.report.first_pils_loss.get_or_insert(loss);
                self.refresh()?;
                self.mark();
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
                self.control.check(
                    self.sources.clock.as_ref(),
                    self.session.observed().is_some(),
                )?;
                Ok(false)
            }
        }
    }
}
