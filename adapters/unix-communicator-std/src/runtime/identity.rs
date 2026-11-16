//! Public identity continuity; paused observations never authorize fresh claims.
use super::{Bound, Fault, Protocol};
use gnunet_pils::client::{Epoch, Identity};
use gnunet_pils_host::client::ConnectionLoss;

enum Phase<'id> {
    Awaiting,
    Active(Identity<'id>),
    Paused {
        previous: Option<Identity<'id>>,
        lost: Epoch<'id>,
        bound: Bound,
        first_epoch: Epoch<'id>,
        first: ConnectionLoss,
    },
    Closed,
}
pub(super) struct Loss {
    pub epoch: u64,
    pub cause: ConnectionLoss,
}
pub(super) struct Owner<'id> {
    phase: Phase<'id>,
}
impl<'id> Owner<'id> {
    pub fn new() -> Self {
        Self {
            phase: Phase::Awaiting,
        }
    }
    pub fn peer(&self) -> Option<[u8; 32]> {
        match &self.phase {
            Phase::Active(identity) => Some(*identity.peer().as_bytes()),
            _ => None,
        }
    }
    pub fn expiration(&self) -> Option<u64> {
        match &self.phase {
            Phase::Active(identity) => Some(identity.expiration().as_micros()),
            _ => None,
        }
    }
    pub fn paused(&self) -> bool {
        matches!(self.phase, Phase::Paused { .. })
    }
    pub fn bound(&self) -> Option<Bound> {
        match &self.phase {
            Phase::Paused { bound, .. } => Some(*bound),
            _ => None,
        }
    }
    pub fn expired(&self, now: Option<u64>) -> bool {
        match &self.phase {
            Phase::Active(identity) => {
                now.is_some_and(|now| now >= identity.expiration().as_micros())
            }
            Phase::Paused { bound, .. } => bound.expired(now),
            _ => false,
        }
    }
    pub fn observe(&mut self, next: Identity<'id>, now: u64) -> Result<bool, Fault> {
        if self.expired(Some(now)) {
            return Err(Fault::Deadline);
        }
        if next.expiration().as_micros() <= now {
            return Err(Fault::IdentityLost);
        }
        let resumed = match &self.phase {
            Phase::Active(previous) => {
                if next.epoch() != previous.epoch()
                    || next.revision() < previous.revision()
                    || next.revision() == previous.revision() && next != *previous
                {
                    return Err(Protocol::StaleGeneration.into());
                }
                false
            }
            Phase::Paused { previous, lost, .. } => {
                if !next.epoch().is_successor_of(*lost)
                    || previous.is_some_and(|old| next.revision() <= old.revision())
                {
                    return Err(Protocol::StaleGeneration.into());
                }
                true
            }
            Phase::Awaiting => false,
            Phase::Closed => return Err(Fault::Closed),
        };
        self.phase = Phase::Active(next);
        Ok(resumed)
    }
    pub fn pause(
        &mut self,
        epoch: Epoch<'id>,
        cause: ConnectionLoss,
        bound: Bound,
    ) -> Result<(), Fault> {
        match &mut self.phase {
            Phase::Active(previous) => {
                if previous.epoch() != epoch {
                    return Err(Protocol::StaleGeneration.into());
                }
                self.phase = Phase::Paused {
                    previous: Some(*previous),
                    lost: epoch,
                    bound,
                    first_epoch: epoch,
                    first: cause,
                };
            }
            Phase::Awaiting => {
                self.phase = Phase::Paused {
                    previous: None,
                    lost: epoch,
                    bound,
                    first_epoch: epoch,
                    first: cause,
                }
            }
            Phase::Paused { lost, .. } => {
                if epoch != *lost && !epoch.is_successor_of(*lost) {
                    return Err(Protocol::StaleGeneration.into());
                }
                *lost = epoch;
            }
            Phase::Closed => return Err(Fault::Closed),
        }
        Ok(())
    }
    pub fn connected(&self, epoch: Epoch<'id>) -> Result<(), Fault> {
        let valid = match &self.phase {
            Phase::Active(previous) => epoch == previous.epoch(),
            Phase::Paused { lost, .. } => epoch.is_successor_of(*lost),
            Phase::Awaiting => true,
            Phase::Closed => return Err(Fault::Closed),
        };
        if valid {
            Ok(())
        } else {
            Err(Protocol::StaleGeneration.into())
        }
    }
    pub fn close(&mut self) -> Option<Loss> {
        match std::mem::replace(&mut self.phase, Phase::Closed) {
            Phase::Paused {
                first_epoch, first, ..
            } => Some(Loss {
                epoch: first_epoch.value(),
                cause: first,
            }),
            _ => None,
        }
    }
}
