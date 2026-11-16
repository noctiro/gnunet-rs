//! One verified PILS MQ, with a bounded drain before changing local authority.
use super::*;

#[derive(Clone, Copy)]
pub(super) enum LocalIdentity<'p> {
    Retired,
    Awaiting { observed: Option<pc::Identity<'p>> },
    Active(pc::Identity<'p>),
    Rotating(Rotation<'p>),
    Recovering(Recovery<'p>),
}
#[derive(Clone, Copy)]
pub(super) struct Rotation<'p> {
    original: pc::Identity<'p>,
    latest: pc::Identity<'p>,
    deadline: u64,
    until: Instant,
    hard: Instant,
}
#[derive(Clone, Copy)]
pub(super) struct Recovery<'p> {
    pub(super) original: Option<pc::Identity<'p>>,
    pub(super) lost: pc::Epoch<'p>,
    pub(super) latest: Option<pc::Identity<'p>>,
    pub(super) deadline: u64,
    pub(super) until: Instant,
    pub(super) hard: Instant,
}

impl<'c, 'slots, 'p, E: Entropy, const O: usize> Server<'c, 'slots, 'p, E, O> {
    /// The applied Core identity; a newer observed identity is not yet writable.
    pub(super) fn current_peer(&self) -> Option<[u8; 32]> {
        self.applied_identity().map(|id| *id.peer().as_bytes())
    }
    pub(super) fn applied_identity(&self) -> Option<pc::Identity<'p>> {
        match &self.identity {
            LocalIdentity::Awaiting { .. } | LocalIdentity::Retired => None,
            LocalIdentity::Active(identity) => Some(*identity),
            LocalIdentity::Rotating(rotation) => Some(rotation.original),
            LocalIdentity::Recovering(recovery) => recovery.original,
        }
    }
    pub(super) fn active_identity(&self) -> Option<pc::Identity<'p>> {
        match &self.identity {
            LocalIdentity::Active(identity) => Some(*identity),
            _ => None,
        }
    }
    pub(super) fn identity_ready(&self) -> bool {
        self.active_identity().is_some()
    }
    pub(super) fn identity_deadline(&self) -> Option<Instant> {
        match &self.identity {
            LocalIdentity::Rotating(rotation) => Some(rotation.hard),
            LocalIdentity::Recovering(recovery) => Some(recovery.until),
            _ => None,
        }
    }
    fn observed_epoch(&self) -> Option<pc::Epoch<'p>> {
        match &self.identity {
            LocalIdentity::Awaiting { observed } => observed.map(|identity| identity.epoch()),
            LocalIdentity::Recovering(recovery) => recovery.latest.map(|identity| identity.epoch()),
            _ => self.applied_identity().map(|identity| identity.epoch()),
        }
    }
    pub(super) fn check_pils_epoch(&self, epoch: pc::Epoch<'p>) -> Result<(), Error> {
        if let LocalIdentity::Recovering(recovery) = &self.identity {
            return if epoch.is_successor_of(recovery.lost) {
                Ok(())
            } else {
                Err(Fault::StaleGeneration.into())
            };
        }
        if self
            .observed_epoch()
            .is_some_and(|original| original != epoch)
        {
            return Err(Fault::StaleGeneration.into());
        }
        Ok(())
    }
    pub(super) fn observe_identity(&mut self, identity: pc::Identity<'p>) -> Result<(), Error> {
        if matches!(self.identity, LocalIdentity::Retired) {
            return Err(Fault::Closed.into());
        }
        if let Err(error) = self.check_pils_epoch(identity.epoch()) {
            self.retire_pils();
            return Err(error);
        }
        let previous = match &self.identity {
            LocalIdentity::Awaiting { observed } => *observed,
            LocalIdentity::Active(previous) => Some(*previous),
            LocalIdentity::Rotating(rotation) => Some(rotation.latest),
            LocalIdentity::Recovering(recovery) => recovery.latest.or(recovery.original),
            LocalIdentity::Retired => None,
        };
        if previous.is_some_and(|previous| {
            identity.revision() < previous.revision()
                || identity.epoch() != previous.epoch()
                    && identity.revision() == previous.revision()
        }) {
            self.retire_pils();
            return Err(Fault::StaleGeneration.into());
        }
        match &mut self.identity {
            LocalIdentity::Retired => return Err(Fault::Closed.into()),
            LocalIdentity::Awaiting { observed } => {
                *observed = Some(identity);
            }
            LocalIdentity::Active(original) => {
                if identity.peer() == original.peer() {
                    *original = identity;
                } else {
                    let original = *original;
                    let until = self.until()?;
                    let deadline = self.deadline()?;
                    let hard = until
                        .checked_add(self.limits.retirement_grace)
                        .ok_or(Fault::Overflow)?;
                    self.identity = LocalIdentity::Rotating(Rotation {
                        original,
                        latest: identity,
                        deadline,
                        until,
                        hard,
                    });
                }
            }
            LocalIdentity::Rotating(rotation) => {
                // An identity not yet applied/signed can be superseded by a
                // later real observation. The first drain bound is immutable.
                rotation.latest = identity;
            }
            LocalIdentity::Recovering(recovery) => recovery.latest = Some(identity),
        }
        Ok(())
    }
    pub(super) fn recover_pils(
        &mut self,
        epoch: pc::Epoch<'p>,
        first: pils::ConnectionLoss,
    ) -> Result<(), Error> {
        if let LocalIdentity::Recovering(recovery) = &mut self.identity {
            if recovery.lost != epoch && !epoch.is_successor_of(recovery.lost) {
                return Err(Fault::StaleGeneration.into());
            }
            recovery.lost = epoch;
            recovery.latest = None;
        } else {
            if matches!(self.identity, LocalIdentity::Retired) {
                return Err(Fault::Closed.into());
            }
            self.check_pils_epoch(epoch)?;
            let (deadline, until, hard) = match self.identity {
                LocalIdentity::Rotating(rotation) => {
                    (rotation.deadline, rotation.until, rotation.hard)
                }
                _ => {
                    let until = self.until()?;
                    (
                        self.deadline()?,
                        until,
                        until
                            .checked_add(self.limits.retirement_grace)
                            .ok_or(Fault::Overflow)?,
                    )
                }
            };
            self.identity = LocalIdentity::Recovering(Recovery {
                original: self.applied_identity(),
                lost: epoch,
                latest: None,
                deadline,
                until,
                hard,
            });
            self.pils_recovery_cause = Some(first);
        }
        self.retire_signing_requests(epoch)
    }
    pub(super) fn identity_timeout(&mut self) -> Error {
        self.pils_recovery_cause
            .take()
            .map_or_else(|| Fault::Deadline.into(), Error::PilsRecoveryTimeout)
    }
    /// Retire only drafts which never entered the actual PILS operation owner.
    /// Admitted operations retain their original frame, identity and hard stop.
    pub(super) fn identity_step(&mut self) -> Result<bool, Error> {
        if matches!(self.identity, LocalIdentity::Retired) {
            return Err(Fault::Closed.into());
        }
        if let LocalIdentity::Awaiting {
            observed: Some(identity),
        } = &self.identity
        {
            let identity = *identity;
            if self.history_frozen() {
                return Ok(false);
            }
            // A trusted committed archive contains historical authors, not
            // the current PILS capability or a proof of a stable master.
            self.core
                .configure_local_peer(*identity.peer().as_bytes())?;
            self.history_identity_changed()?;
            self.identity = LocalIdentity::Active(identity);
            return Ok(true);
        }
        let (original, latest, deadline, until, hard) = match &self.identity {
            LocalIdentity::Rotating(rotation) => (
                Some(rotation.original),
                Some(rotation.latest),
                rotation.deadline,
                rotation.until,
                rotation.hard,
            ),
            LocalIdentity::Recovering(recovery) => (
                recovery.original,
                recovery.latest,
                recovery.deadline,
                recovery.until,
                recovery.hard,
            ),
            _ => return Ok(false),
        };
        if Instant::now() >= hard {
            return Err(self.identity_timeout());
        }
        if matches!(self.identity, LocalIdentity::Recovering(_))
            && (self.last_now >= deadline || Instant::now() >= until)
        {
            return Err(self.identity_timeout());
        }
        if self.history_frozen() {
            return Ok(false);
        }
        if let Some(index) = self.signs.iter().position(|s| {
            s.as_ref()
                .is_some_and(|s| matches!(&s.state, SignState::Crypto(signing) if matches!(signing.phase, SignPhase::Draft)))
        }) {
            self.signs[index].as_mut().ok_or(Fault::Stale)?.state = SignState::Retiring {
                original: None,
                reason: Fault::StaleGeneration,
                stage: SignRetirement::Core,
            };
            return Ok(true);
        }
        // Prepared controls have not even leased a provider draft. Take one
        // original job before recording its local provider failure, as required
        // by the Core's original operation state machine.
        for index in 0..self.rooms.len() {
            let Some(free) = self.signs.iter().position(Option::is_none) else {
                break;
            };
            let Some(room) = self.rooms[index].as_ref().map(|r| r.room) else {
                continue;
            };
            let Some(core::ServiceSignWork { binding, kind, .. }) =
                self.core.take_service_signing_work(room)?
            else {
                continue;
            };
            let slot = self
                .control_budgets
                .iter()
                .position(|b| {
                    b.as_ref()
                        .is_some_and(|b| b.operation == binding.operation())
                })
                .ok_or(Fault::StaleGeneration)?;
            let budget = self.control_budgets[slot].as_ref().ok_or(Fault::Stale)?;
            let until = budget.until;
            let hard = until
                .checked_add(self.limits.retirement_grace)
                .ok_or(Fault::Overflow)?;
            self.signs[free] = Some(Sign {
                room,
                kind,
                binding,
                state: SignState::Retiring {
                    original: None,
                    reason: Fault::StaleGeneration,
                    stage: SignRetirement::Core,
                },
                until,
                hard,
            });
            self.control_budgets[slot] = None;
            return Ok(true);
        }
        if self.signs.iter().any(Option::is_some) {
            return Ok(false);
        }
        // Terminal controls can have expired through ordinary Core advancement.
        // Their original terminal state is consumed, never reported as a SIGN.
        for slot in 0..self.control_budgets.len() {
            let Some(operation) = self.control_budgets[slot].as_ref().map(|b| b.operation) else {
                continue;
            };
            let phase = self.core.operation_phase(operation)?;
            if matches!(
                phase,
                core::OperationPhase::Complete
                    | core::OperationPhase::Cancelled
                    | core::OperationPhase::Failed
            ) {
                self.room_control_finished(operation, phase == core::OperationPhase::Complete)?;
                self.core.retire_operation(operation)?;
                self.control_budgets[slot] = None;
                return Ok(true);
            }
            return Err(Fault::NotReady.into());
        }
        let Some(latest) = latest else {
            return Ok(false);
        };
        let previous = original.map(|original| *original.peer().as_bytes());
        let current = *latest.peer().as_bytes();
        if self.last_now >= deadline || Instant::now() >= until {
            return Err(self.identity_timeout());
        }
        match previous {
            None => self.core.configure_local_peer(current)?,
            Some(previous) if previous != current => {
                self.core.rotate_local_peer(current)?;
            }
            Some(_) => {}
        }
        self.identity = LocalIdentity::Active(latest);
        self.history_identity_changed()?;
        if let Some(previous) = previous
            && previous != current
        {
            self.room_identity_changed(previous, current, deadline, until)?;
        }
        self.pils_recovery_cause = None;
        Ok(true)
    }
    /// Revoke live authority at the observed physical-source boundary. Core
    /// retains historical facts for final storage, never a reusable MQ.
    pub(super) fn retire_pils(&mut self) {
        self.identity = LocalIdentity::Retired;
        let _original = self.pils.close();
    }
}
