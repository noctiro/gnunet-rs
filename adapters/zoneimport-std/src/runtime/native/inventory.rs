//! Actual initial IDENTITY END and original CREATE outcomes.
use super::*;
use crate::{Exposure, LocalOutcome, SourceFailure};
fn initial_hard(hard: Instant) -> Result<(), Fault> {
    if Instant::now() >= hard {
        Err(Fault::Deadline)
    } else {
        Ok(())
    }
}
impl<'id> Runtime<'id> {
    /// Loss already detached the actual MQ. Drain its retained per-operation
    /// outcomes before the same client attaches a fresh epoch; never replay them.
    pub(super) fn identity_disconnected(
        &mut self,
        report: identity::Loss<'id>,
        cause: identity::LossCause,
    ) -> Result<(), Error> {
        let retry = self.limits.identity.reconnect
            && matches!(
                &cause,
                identity::LossCause::Eof
                    | identity::LossCause::Io(_)
                    | identity::LossCause::RetirementDeadline
                    | identity::LossCause::Requested
            );
        self.identity_loss(report);
        self.source_error(SourceFailure::Identity(cause));
        if !self.closing && !retry {
            return Err(Fault::Closed.into());
        }
        Ok(())
    }
    fn inventory(&mut self, observe: &mut impl FnMut(Event<'_>)) -> Result<(), Error> {
        let hard = self.initial.as_ref().ok_or(Fault::StaleGeneration)?.hard;
        initial_hard(hard)?;
        let client = self.identity.as_ref().ok_or(Fault::StaleGeneration)?;
        let mut candidates: Vec<Candidate> = Vec::new();
        candidates
            .try_reserve_exact(self.core.limits().zones)
            .map_err(|_| Fault::Capacity)?;
        for ego in client.egos() {
            initial_hard(hard)?;
            let name = match self.names.inventory(ego.name()) {
                Ok(name) => name,
                Err(Error::InvalidName(_)) => {
                    self.report.ignored_identities =
                        self.report.ignored_identities.saturating_add(1);
                    observe(Event::IgnoredIdentity);
                    continue;
                }
                Err(error) => return Err(error),
            };
            initial_hard(hard)?;
            let public = ZoneKey::from_wire(&ego.public_key()?)?;
            if let Some(old) = candidates
                .iter_mut()
                .find(|candidate| candidate.canonical == name)
            {
                initial_hard(hard)?;
                old.ambiguous |= ZoneKey::from_wire(&old.secret.public_key()?)? != public;
                continue;
            }
            if candidates.len() >= self.core.limits().zones {
                return Err(Fault::Capacity.into());
            }
            initial_hard(hard)?;
            candidates.push(Candidate {
                canonical: name,
                secret: ego.secret().try_clone_secret(),
                ambiguous: false,
            });
        }
        for candidate in candidates {
            initial_hard(hard)?;
            if candidate.ambiguous {
                // Never choose one actual ego arbitrarily or create a new key
                // over an existing canonical collision. Unrelated names remain
                // usable and private material stays with its original owner.
                self.ambiguous.push(candidate.canonical);
                continue;
            }
            initial_hard(hard)?;
            let public = ZoneKey::from_wire(&candidate.secret.public_key()?)?;
            initial_hard(hard)?;
            let zone = self.core.seed_zone(&candidate.canonical, public)?;
            self.keys.push(Key {
                zone,
                secret: candidate.secret,
            });
        }
        self.initial
            .as_ref()
            .ok_or(Fault::StaleGeneration)?
            .check(&self.clock)?;
        self.last = self.clock.sample()?;
        self.core.finish_inventory(self.last)?;
        self.initial
            .as_ref()
            .ok_or(Fault::StaleGeneration)?
            .check(&self.clock)?;
        // The app sealed genuine EOF before the lazy monitor was constructed.
        // Only now can pure input activation use the actual ended inventory.
        self.last = self.clock.sample()?;
        self.core.finish_input(self.last)?;
        self.initial = None;
        self.initialized = true;
        Ok(())
    }
    pub(super) fn poll_identity(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'_>),
    ) -> Result<bool, Error> {
        if self.identity_closed {
            return Ok(false);
        }
        let Some(client) = &mut self.identity else {
            return Ok(false);
        };
        let event = match client.poll(cx, None) {
            Poll::Pending => return Ok(false),
            Poll::Ready(Err(error)) => return Err(Error::Identity(error)),
            Poll::Ready(Ok(event)) => event,
        };
        match event {
            identity::Progress::Initialized(_) if !self.initialized && !self.closing => {
                self.inventory(observe)?
            }
            identity::Progress::Completed(completion) => self.creation(completion, observe)?,
            identity::Progress::Queued { epoch, operation } => {
                self.identity_attached(operation, epoch, false)?
            }
            identity::Progress::Written { epoch, operation } => {
                self.identity_attached(operation, epoch, true)?
            }
            identity::Progress::Lost { report, cause } => {
                self.identity_disconnected(report, cause)?;
            }
            identity::Progress::ConnectRetry { error, .. } => self.note_io(None, error, observe),
            identity::Progress::Unavailable(error) => return Err(Error::Identity(error)),
            identity::Progress::Closed => {
                self.identity_closed = true;
            }
            // The fixed public tool consumes the initial snapshot. Later ego
            // rename/delete events do not revoke an already held capability.
            _ => {}
        }
        Ok(true)
    }
    fn identity_attached(
        &mut self,
        operation: identity::Operation<'id>,
        epoch: identity::Epoch<'id>,
        written: bool,
    ) -> Result<(), Error> {
        let row = self.pending.iter_mut().flatten().find(|row| matches!(&row.native, Native::Create { operation: original, .. } if *original == operation)).ok_or(Fault::StaleGeneration)?;
        if row
            .epoch
            .is_some_and(|original| original != epoch.diagnostic())
        {
            return Err(Fault::StaleGeneration.into());
        }
        row.epoch = Some(epoch.diagnostic());
        row.written |= written;
        Ok(())
    }
    fn creation(
        &mut self,
        completion: identity::Completion<'id>,
        observe: &mut impl FnMut(Event<'_>),
    ) -> Result<(), Error> {
        let index = self.pending.iter().position(|slot| slot.as_ref().is_some_and(|row| matches!(&row.native, Native::Create { operation, .. } if *operation == completion.operation))).ok_or(Fault::StaleGeneration)?;
        let mut row = self.pending[index].take().ok_or(Fault::StaleGeneration)?;
        let actual_epoch = completion.epoch.map(|epoch| epoch.diagnostic());
        if row.epoch.is_some_and(|epoch| Some(epoch) != actual_epoch) {
            self.pending[index] = Some(row);
            return Err(Fault::StaleGeneration.into());
        }
        row.epoch = actual_epoch;
        let zone = match &row.native {
            Native::Create { zone, .. } => zone.clone(),
            _ => return Err(Fault::Conflict.into()),
        };
        let (result, code) = match completion.outcome {
            identity::Outcome::Result {
                code: 0,
                created: Some(secret),
            } => {
                let public = match secret
                    .public_key()
                    .and_then(|public| ZoneKey::from_wire(&public))
                {
                    Ok(public) => public,
                    Err(error) => {
                        row.native = Native::Settled;
                        self.pending[index] = Some(row);
                        self.stalled = true;
                        return Err(error.into());
                    }
                };
                self.keys.push(Key { zone, secret });
                (
                    self.core.created(&row.job, core::Creation::Created(public)),
                    Some(0),
                )
            }
            identity::Outcome::Result { code, .. } => (
                self.core.created(&row.job, core::Creation::Rejected(code)),
                Some(code),
            ),
            identity::Outcome::Local {
                reason,
                submission,
                result_code,
                ..
            } => {
                row.exposure = match submission {
                    identity::Submission::Unsent => Exposure::Unsent,
                    identity::Submission::Partial { bytes, total } => {
                        Exposure::Partial { bytes, total }
                    }
                    identity::Submission::Written { bytes } => Exposure::Whole { bytes },
                };
                self.local_outcome(LocalOutcome::Identity {
                    job: row.job.diagnostic(),
                    reason,
                    submission,
                    result_code,
                });
                let zero = matches!(submission, identity::Submission::Unsent);
                let result = if row.retiring {
                    self.core.retired(
                        &row.job,
                        if zero {
                            core::Retirement::Unsent
                        } else {
                            core::Retirement::Unknown
                        },
                    )
                } else {
                    // A late status is kept as a diagnostic, not paired with
                    // material that the real cancellation deliberately revoked.
                    self.core.created(
                        &row.job,
                        if zero {
                            core::Creation::Unsent
                        } else {
                            core::Creation::Unknown
                        },
                    )
                };
                (result, result_code)
            }
            identity::Outcome::Found(_) => {
                row.native = Native::Settled;
                self.pending[index] = Some(row);
                return Err(Fault::Conflict.into());
            }
        };
        observe(Event::Result {
            job: row.job.diagnostic(),
            kind: row.kind,
            code,
        });
        self.finish_row(index, row, result)
    }
}
