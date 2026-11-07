//! One verified PILS MQ, with a bounded drain before changing local authority.
use super::*;

#[derive(Clone, Copy)]
#[expect(
    clippy::large_enum_variant,
    reason = "One inline server owner keeps both original and latest verified identities without allocating on PID changes"
)]
pub(super) enum LocalIdentity<'p> {
    Retired,
    Awaiting { observed: Option<pc::Identity<'p>> },
    Active(pc::Identity<'p>),
    Rotating(Rotation<'p>),
}
#[derive(Clone, Copy)]
pub(super) struct Rotation<'p> {
    original: pc::Identity<'p>,
    latest: pc::Identity<'p>,
    deadline: u64,
    until: Instant,
    hard: Instant,
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
            _ => None,
        }
    }
    fn observed_epoch(&self) -> Option<pc::Epoch<'p>> {
        match &self.identity {
            LocalIdentity::Awaiting { observed } => observed.map(|identity| identity.epoch()),
            _ => self.applied_identity().map(|identity| identity.epoch()),
        }
    }
    pub(super) fn check_pils_epoch(&self, epoch: pc::Epoch<'p>) -> Result<(), Error> {
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
        }
        Ok(())
    }
    /// Retire only drafts which never entered the actual PILS operation owner.
    /// Admitted operations retain their original frame, identity and hard stop.
    pub(super) fn identity_step(&mut self, observe: &mut impl FnMut(Event)) -> Result<bool, Error> {
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
        let LocalIdentity::Rotating(rotation) = &self.identity else {
            return Ok(false);
        };
        let (original, latest, deadline, until, hard) = (
            rotation.original,
            rotation.latest,
            rotation.deadline,
            rotation.until,
            rotation.hard,
        );
        if Instant::now() >= hard {
            return Err(Fault::Deadline.into());
        }
        if self.history_frozen() {
            return Ok(false);
        }
        if let Some(index) = self.signs.iter().position(|s| {
            s.as_ref()
                .is_some_and(|s| matches!(s.phase, SignPhase::Draft))
        }) {
            let binding = self.signs[index].as_ref().ok_or(Fault::Stale)?.binding;
            self.reject_identity_draft(binding, observe)?;
            self.signs[index] = None;
            return Ok(true);
        }
        // Prepared controls have not even leased a provider draft. Take one
        // original job before recording its local provider failure, as required
        // by the Core's original operation state machine.
        for index in 0..self.rooms.len() {
            let Some(room) = self.rooms[index].as_ref().map(|r| r.room) else {
                continue;
            };
            let Some(core::ServiceSignWork { binding, .. }) =
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
            self.reject_identity_draft(binding, observe)?;
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
        let previous = *original.peer().as_bytes();
        let current = *latest.peer().as_bytes();
        if self.last_now >= deadline || Instant::now() >= until {
            return Err(Fault::Deadline.into());
        }
        self.core.rotate_local_peer(current)?;
        self.identity = LocalIdentity::Active(latest);
        self.history_identity_changed()?;
        if previous != current {
            self.room_identity_changed(previous, current, deadline, until)?;
        }
        Ok(true)
    }
    /// Revoke live authority at the observed physical-source boundary. Core
    /// retains historical facts for final storage, never a reusable MQ.
    pub(super) fn retire_pils(&mut self) {
        self.identity = LocalIdentity::Retired;
        let _original = self.pils.close();
    }
    fn reject_identity_draft(
        &mut self,
        binding: Binding<'c>,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Error> {
        self.core
            .provider_failed(binding, Fault::StaleGeneration.into())?;
        self.room_control_finished(binding.operation(), false)?;
        self.core.retire_operation(binding.operation())?;
        observe(Event::SignDraftRetired {
            operation: binding.operation().observation(),
            reason: Fault::StaleGeneration,
        });
        Ok(())
    }
}
