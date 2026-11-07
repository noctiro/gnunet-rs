//! The original Line's initialization capability and verified session are exclusive.
use super::{Fault, Identity, Instance, PilsIdentity, Session};
use gnunet_conversation::Limits;

pub(super) struct LineSession<'s, 'p> {
    phase: Phase<'s, 'p>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Observation {
    Initial,
    Refresh,
    PeerChanged,
}

#[expect(
    clippy::large_enum_variant,
    reason = "one inline original session; boxing would add an allocation to every Line"
)]
enum Phase<'s, 'p> {
    Awaiting(&'s mut Instance),
    Active {
        core: Session<'s>,
        observed: PilsIdentity<'p>,
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
            Phase::Active { core, .. } => Some(core),
            Phase::Awaiting(_) | Phase::Failed => None,
        }
    }
    pub(super) fn core_mut(&mut self) -> Option<&mut Session<'s>> {
        match &mut self.phase {
            Phase::Active { core, .. } => Some(core),
            Phase::Awaiting(_) | Phase::Failed => None,
        }
    }
    pub(super) fn observed(&self) -> Option<PilsIdentity<'p>> {
        match &self.phase {
            Phase::Active { observed, .. } => Some(*observed),
            Phase::Awaiting(_) | Phase::Failed => None,
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
