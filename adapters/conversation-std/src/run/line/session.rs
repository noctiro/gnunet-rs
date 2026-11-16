//! The original Line's initialization capability and verified session are exclusive.
use super::{Fault, Identity, Instance, PilsIdentity, Session};
use gnunet_conversation::Limits;
use gnunet_pils::client::Epoch;

pub(super) struct LineSession<'s, 'p> {
    phase: Phase<'s, 'p>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Observation {
    Initial,
    Refresh,
    PeerChanged,
    SourceReplaced,
}

enum Phase<'s, 'p> {
    Awaiting(&'s mut Instance),
    Active {
        core: Session<'s>,
        observed: PilsIdentity<'p>,
    },
    /// Public observation is unavailable. The original core, native channel
    /// bindings, bytes and deadlines remain frozen under their existing owners.
    Paused {
        core: Session<'s>,
        previous: PilsIdentity<'p>,
    },
    /// Consuming the original brand may fail while reserving the bounded core.
    /// This terminal state retains no initialization or identity authority.
    Failed,
}

#[cfg(test)]
mod tests;
impl<'s, 'p> LineSession<'s, 'p> {
    pub(super) fn new(instance: &'s mut Instance) -> Self {
        Self {
            phase: Phase::Awaiting(instance),
        }
    }
    pub(super) fn core(&self) -> Option<&Session<'s>> {
        match &self.phase {
            Phase::Active { core, .. } | Phase::Paused { core, .. } => Some(core),
            Phase::Awaiting(_) | Phase::Failed => None,
        }
    }
    pub(super) fn core_mut(&mut self) -> Option<&mut Session<'s>> {
        match &mut self.phase {
            Phase::Active { core, .. } | Phase::Paused { core, .. } => Some(core),
            Phase::Awaiting(_) | Phase::Failed => None,
        }
    }
    pub(super) fn previous(&self) -> Option<PilsIdentity<'p>> {
        match &self.phase {
            Phase::Active { observed, .. } => Some(*observed),
            Phase::Paused { previous, .. } => Some(*previous),
            Phase::Awaiting(_) | Phase::Failed => None,
        }
    }
    pub(super) fn waiting(&self) -> bool {
        matches!(self.phase, Phase::Paused { .. })
    }
    /// Fence exactly the actual lost MQ. Later unsuccessful attempts of the
    /// same original client may fail while this first observation stays frozen.
    pub(super) fn pause(&mut self, epoch: Epoch<'p>) -> Result<(), Fault> {
        match &self.phase {
            Phase::Active { observed, .. } if observed.epoch() != epoch => {
                return Err(Fault::StaleGeneration);
            }
            Phase::Paused { previous, .. } => {
                return if epoch == previous.epoch() || epoch.is_successor_of(previous.epoch()) {
                    Ok(())
                } else {
                    Err(Fault::StaleGeneration)
                };
            }
            Phase::Awaiting(_) => return Ok(()),
            Phase::Failed => return Err(Fault::Conflict),
            Phase::Active { .. } => {}
        }
        let Phase::Active { core, observed } = core::mem::replace(&mut self.phase, Phase::Failed)
        else {
            return Err(Fault::Conflict);
        };
        self.phase = Phase::Paused {
            core,
            previous: observed,
        };
        Ok(())
    }
    pub(super) fn observed(&self) -> Option<PilsIdentity<'p>> {
        match &self.phase {
            Phase::Active { observed, .. } => Some(*observed),
            Phase::Awaiting(_) | Phase::Paused { .. } | Phase::Failed => None,
        }
    }
    /// A healthy peer change must still come from the original branded MQ.
    pub(super) fn check(&self, next: PilsIdentity<'p>) -> Result<(), Fault> {
        match &self.phase {
            Phase::Active { observed, .. }
                if observed.epoch() != next.epoch() || next.revision() < observed.revision() =>
            {
                Err(Fault::StaleGeneration)
            }
            Phase::Failed => Err(Fault::Conflict),
            Phase::Paused { previous, .. }
                if !next.epoch().is_successor_of(previous.epoch())
                    || next.revision() <= previous.revision() =>
            {
                Err(Fault::StaleGeneration)
            }
            Phase::Paused { .. } => Ok(()),
            Phase::Awaiting(_) | Phase::Active { .. } => Ok(()),
        }
    }
    /// Initialize or update the original core in place. A failed
    /// construction is terminal; no second brand or replacement core is minted.
    pub(super) fn observe(
        &mut self,
        observed: PilsIdentity<'p>,
        limits: Limits,
        now: u64,
    ) -> Result<Observation, Fault> {
        self.check(observed)?;
        if let Phase::Paused { core, .. } = &mut self.phase {
            let next = Identity::new(*observed.peer().as_bytes(), observed.epoch().value())?;
            core.replace_identity_source(&core.identity(), next)?;
            let Phase::Paused { core, .. } = core::mem::replace(&mut self.phase, Phase::Failed)
            else {
                return Err(Fault::Conflict);
            };
            self.phase = Phase::Active { core, observed };
            return Ok(Observation::SourceReplaced);
        }
        if let Phase::Active {
            core,
            observed: old,
        } = &mut self.phase
        {
            let change = if old.peer() == observed.peer() {
                Observation::Refresh
            } else {
                Observation::PeerChanged
            };
            let next = Identity::new(*observed.peer().as_bytes(), observed.epoch().value())?;
            core.rebind_identity(&core.identity(), next)?;
            *old = observed;
            return Ok(change);
        }
        let Phase::Awaiting(instance) = std::mem::replace(&mut self.phase, Phase::Failed) else {
            return Err(Fault::Conflict);
        };
        let identity = Identity::new(*observed.peer().as_bytes(), observed.epoch().value())?;
        let core = Session::new(instance, identity, limits, now)?;
        self.phase = Phase::Active { core, observed };
        Ok(Observation::Initial)
    }
}
