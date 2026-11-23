//! An original SYNC cursor is usable only after bounded authenticated ancestry.
use super::*;
use alloc::vec::Vec;
mod proof;
#[cfg(test)]
mod tests;

#[derive(Clone, Copy)]
enum Stage {
    Reply,
    Candidate,
    Waiting,
    Epoch(Hash, usize),
    Walk,
    Targets(usize),
    Normalize(usize),
    Commit,
}
impl Stage {
    const fn context(self) -> FrontierProofStage {
        match self {
            Self::Reply | Self::Candidate | Self::Waiting => FrontierProofStage::Candidate,
            Self::Epoch(..) => FrontierProofStage::EpochAncestry,
            Self::Walk => FrontierProofStage::SignedAncestry,
            Self::Targets(_) => FrontierProofStage::CapturedRoots,
            Self::Normalize(_) => FrontierProofStage::Reconciliation,
            Self::Commit => FrontierProofStage::Commit,
        }
    }
}

/// Original room-local generations, acquired and cleared together.
#[derive(Clone, Copy)]
struct ProofOwner {
    operation: Slot,
    source: Slot,
    stage: Stage,
}

pub(crate) struct Validation {
    owner: Option<ProofOwner>,
    previous: Hash,
    epoch: Hash,
    candidate: Option<Slot>,
    anchor: Option<Slot>,
    targets: Vec<Hash>,
    stack: Vec<Slot>,
    visited: Vec<u64>,
    bytes: usize,
}
impl Validation {
    pub(crate) const fn bytes(&self) -> usize {
        self.bytes
    }
    fn seen(&self, slot: Slot) -> bool {
        self.visited[slot.index] == slot.generation
    }
    fn push(&mut self, slot: Slot) -> Result<(), Error> {
        if !self.seen(slot) {
            if self.stack.len() == self.stack.capacity() {
                return Err(Fault::Capacity.into());
            }
            self.visited[slot.index] = slot.generation;
            self.stack.push(slot);
        }
        Ok(())
    }
    pub(crate) fn runnable(&self) -> bool {
        self.owner
            .is_some_and(|owner| !matches!(owner.stage, Stage::Reply | Stage::Waiting))
    }
    fn set_stage(&mut self, stage: Stage) -> Result<(), Error> {
        self.owner.as_mut().ok_or(Fault::Conflict)?.stage = stage;
        Ok(())
    }
}

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    /// Whether a new ordinary draft must wait for an authenticated frontier.
    pub fn frontier_sync_required(&self, room: Room<'id>) -> Result<bool, Error> {
        let row = self.rooms.get(self.check_room(room)?)?;
        Ok(self.mode == Mode::Client
            && (row.frontier_control.is_some()
                || row.frontier_base.is_some()
                || row.frontier_control_hash.is_some()
                || row.queues.frontier.len() > 1
                || row
                    .frontier_validation
                    .as_ref()
                    .is_some_and(|v| v.owner.is_some())))
    }
    /// Actual graph-view generation, independent from key/GET bookkeeping.
    pub fn frontier_version(&self, room: Room<'id>) -> Result<u64, Error> {
        Ok(self.rooms.get(self.check_room(room)?)?.frontier_version)
    }
    /// An original SYNC reply/proof still owns its original operation lifetime.
    pub fn frontier_sync_in_flight(&self, room: Room<'id>) -> Result<bool, Error> {
        Ok(self
            .rooms
            .get(self.check_room(room)?)?
            .frontier_validation
            .as_ref()
            .is_some_and(|v| v.owner.is_some()))
    }
    /// Reserve and account every proof allocation before a historical draft or
    /// SYNC can be exposed. One room-owned workspace also serves later reads.
    pub(crate) fn reserve_frontier_scratch(&mut self, r: Slot) -> Result<(), Error> {
        if self.rooms.get(r)?.frontier_validation.is_some() {
            return Ok(());
        }
        let messages = self.limits.messages_per_room;
        let words = messages;
        let targets_count = messages.checked_add(2).ok_or(Fault::Overflow)?;
        let lower = messages
            .checked_mul(core::mem::size_of::<Slot>())
            .and_then(|b| targets_count.checked_mul(64).and_then(|t| b.checked_add(t)))
            .and_then(|b| words.checked_mul(8).and_then(|v| b.checked_add(v)))
            .ok_or(Fault::Overflow)?;
        if lower > self.remaining_bytes() {
            return Err(Fault::Capacity.into());
        }
        let mut targets = Vec::new();
        targets
            .try_reserve_exact(targets_count)
            .map_err(|_| Fault::Capacity)?;
        let mut stack = Vec::new();
        stack
            .try_reserve_exact(messages)
            .map_err(|_| Fault::Capacity)?;
        let mut visited = Vec::new();
        visited
            .try_reserve_exact(words)
            .map_err(|_| Fault::Capacity)?;
        visited.resize(words, 0);
        let bytes = targets
            .capacity()
            .checked_mul(64)
            .and_then(|b| {
                stack
                    .capacity()
                    .checked_mul(core::mem::size_of::<Slot>())
                    .and_then(|s| b.checked_add(s))
            })
            .and_then(|b| {
                visited
                    .capacity()
                    .checked_mul(8)
                    .and_then(|v| b.checked_add(v))
            })
            .ok_or(Fault::Overflow)?;
        self.charge(bytes)?;
        self.rooms.get_mut(r)?.frontier_validation = Some(Validation {
            owner: None,
            previous: [0; 64],
            epoch: [0; 64],
            candidate: None,
            anchor: None,
            targets,
            stack,
            visited,
            bytes,
        });
        Ok(())
    }
    pub(crate) fn begin_frontier_sync(&mut self, r: Slot, operation: Slot) -> Result<(), Error> {
        let row = self.rooms.get_mut(r)?;
        let original = row.operations.get(operation)?;
        let source = original.binding.source;
        let validation = row.frontier_validation.as_mut().ok_or(Fault::Conflict)?;
        if validation.owner.is_some() {
            return Err(Fault::WouldBlock.into());
        }
        validation.targets.clear();
        validation.targets.extend_from_slice(&row.queues.frontier);
        validation.targets.extend(row.frontier_base);
        validation.targets.extend(row.frontier_control_hash);
        validation.targets.retain(|hash| *hash != [0; 64]);
        validation.targets.sort_unstable();
        validation.targets.dedup();
        validation.stack.clear();
        validation.visited.fill(0);
        validation.candidate = None;
        validation.anchor = None;
        validation.owner = Some(ProofOwner {
            operation,
            source,
            stage: Stage::Reply,
        });
        Ok(())
    }
    pub(crate) fn observe_frontier_sync(
        &mut self,
        source: Source<'id>,
        operation: Slot,
        previous: Hash,
        epoch: Hash,
    ) -> Result<(), Error> {
        let validation = self
            .rooms
            .get_mut(source.room)?
            .frontier_validation
            .as_mut()
            .ok_or(Fault::Conflict)?;
        if !validation.owner.is_some_and(|owner| {
            owner.operation == operation
                && owner.source == source.slot
                && matches!(owner.stage, Stage::Reply)
        }) {
            return Err(Fault::Replay.into());
        }
        validation.previous = previous;
        validation.epoch = epoch;
        validation.set_stage(Stage::Candidate)
    }
    pub(crate) fn wake_frontier_sync(&mut self, r: Slot) -> Result<(), Error> {
        if let Some(owner) = self
            .rooms
            .get_mut(r)?
            .frontier_validation
            .as_mut()
            .and_then(|validation| validation.owner.as_mut())
            && matches!(owner.stage, Stage::Waiting)
        {
            owner.stage = Stage::Candidate;
        }
        Ok(())
    }
    pub(crate) fn frontier_proof_runnable(&self, r: Slot) -> Result<bool, Error> {
        Ok(self
            .rooms
            .get(r)?
            .frontier_validation
            .as_ref()
            .is_some_and(Validation::runnable))
    }
    /// One node, captured obligation, frontier cell or state boundary per turn.
    pub(crate) fn advance_frontier_sync(&mut self, r: Slot, now: u64) -> Result<bool, Error> {
        if !self.frontier_proof_runnable(r)? {
            return Ok(false);
        }
        let owner = self
            .rooms
            .get(r)?
            .frontier_validation
            .as_ref()
            .and_then(|v| v.owner)
            .ok_or(Fault::Conflict)?;
        if self.rooms.get(r)?.operations.get(owner.operation)?.deadline <= now {
            return Err(Fault::Timeout.into());
        }
        self.reserve_events(3)?;
        let mut validation = self
            .rooms
            .get_mut(r)?
            .frontier_validation
            .take()
            .ok_or(Fault::Conflict)?;
        let stage = owner.stage.context();
        let result = self
            .advance_frontier_validation(r, &mut validation)
            .map_err(|error| match error {
                Error::Protocol(
                    fault @ (Fault::Authentication | Fault::Malformed | Fault::InvalidInput),
                ) => Error::FrontierProof {
                    stage,
                    cause: FrontierProofCause::Protocol(fault),
                },
                Error::AttributionConflict => Error::FrontierProof {
                    stage,
                    cause: FrontierProofCause::AttributionConflict,
                },
                other => other,
            });
        self.rooms.get_mut(r)?.frontier_validation = Some(validation);
        result.map(|()| true)
    }
    pub(crate) fn clear_frontier_scratch(&mut self, source: Source<'id>) -> Result<(), Error> {
        let row = self.rooms.get(source.room)?;
        let reserved_for_other = row.frontier_control.is_some_and(|operation| {
            row.operations
                .get(operation)
                .is_ok_and(|o| o.binding.source != source.slot)
        });
        let clear = row.frontier_validation.as_ref().is_some_and(|v| {
            v.owner
                .map_or(!reserved_for_other, |owner| owner.source == source.slot)
        });
        if clear {
            let validation = self
                .rooms
                .get_mut(source.room)?
                .frontier_validation
                .take()
                .ok_or(Fault::Conflict)?;
            self.release(validation.bytes)?;
        }
        Ok(())
    }
}
