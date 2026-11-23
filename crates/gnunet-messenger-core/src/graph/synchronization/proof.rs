//! One bounded authenticated graph-validation transition per caller unit.
use super::*;

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    pub(super) fn advance_frontier_validation(
        &mut self,
        r: Slot,
        v: &mut Validation,
    ) -> Result<(), Error> {
        let owner = v.owner.ok_or(Fault::Conflict)?;
        let source = self.source_id(r, owner.source);
        self.check_source(source)?;
        match owner.stage {
            Stage::Candidate => {
                if v.previous == [0; 64] {
                    if v.epoch != [0; 64] || !v.targets.is_empty() {
                        return Err(Fault::Authentication.into());
                    }
                    v.set_stage(Stage::Commit)?;
                    return Ok(());
                }
                let Some(slot) = self.rooms.get(r)?.find_node(&v.previous) else {
                    self.note_dependency(r, v.previous, source)?;
                    v.set_stage(Stage::Waiting)?;
                    return Ok(());
                };
                let row = self.rooms.get(r)?;
                let node = row.nodes.get(slot)?;
                if node.auth.is_none() || !node.complete {
                    v.set_stage(Stage::Waiting)?;
                    return Ok(());
                }
                if node.epoch != v.epoch {
                    return Err(Error::AttributionConflict);
                }
                v.candidate = Some(slot);
                if v.epoch != [0; 64]
                    && !row
                        .find_epoch(&v.epoch)
                        .and_then(|e| row.epochs.get(e).ok())
                        .is_some_and(|e| e.complete)
                {
                    self.note_dependency(r, v.epoch, source)?;
                    v.set_stage(Stage::Waiting)?;
                    return Ok(());
                }
                v.set_stage(Stage::Epoch(v.previous, 0))?;
            }
            Stage::Epoch(hash, steps) => {
                if hash == [0; 64] {
                    if v.epoch != [0; 64] {
                        return Err(Fault::Authentication.into());
                    }
                    let root = self
                        .rooms
                        .get(r)?
                        .find_node(&v.previous)
                        .ok_or(Fault::NotReady)?;
                    v.push(root)?;
                    v.set_stage(Stage::Walk)?;
                    return Ok(());
                }
                if steps == self.limits.messages_per_room {
                    return Err(Fault::Malformed.into());
                }
                let row = self.rooms.get(r)?;
                let slot = row.find_node(&hash).ok_or(Fault::NotReady)?;
                let node = row.nodes.get(slot)?;
                if node.auth.is_none() || !node.complete || node.epoch != v.epoch {
                    return Err(Fault::Authentication.into());
                }
                if node.hash == v.epoch {
                    if !epoch_kind(node.kind) {
                        return Err(Fault::Authentication.into());
                    }
                    v.anchor = Some(slot);
                    v.push(row.find_node(&v.previous).ok_or(Fault::NotReady)?)?;
                    v.set_stage(Stage::Walk)?;
                } else {
                    if epoch_kind(node.kind)
                        && !matches!(node.body(&self.frames)?,
                        Body::Merge { first_epoch, second_epoch, .. }
                        if *first_epoch == v.epoch && *second_epoch == v.epoch)
                    {
                        return Err(Fault::Authentication.into());
                    }
                    v.set_stage(Stage::Epoch(node.parents[0], steps + 1))?;
                }
            }
            Stage::Walk => {
                let Some(slot) = v.stack.pop() else {
                    v.set_stage(Stage::Targets(0))?;
                    return Ok(());
                };
                let row = self.rooms.get(r)?;
                let node = row.nodes.get(slot)?;
                if node.auth.is_none() || !node.complete {
                    return Err(Fault::Authentication.into());
                }
                for parent in node.parents {
                    if parent != [0; 64] {
                        let parent = row.find_node(&parent).ok_or(Fault::NotReady)?;
                        v.push(parent)?;
                    }
                }
            }
            Stage::Targets(index) => {
                if let Some(hash) = v.targets.get(index) {
                    let row = self.rooms.get(r)?;
                    let slot = row.find_node(hash);
                    if !slot.is_some_and(|slot| v.seen(slot)) {
                        let root = slot.and_then(|slot| row.nodes.get(slot).ok());
                        let candidate = v.candidate.and_then(|slot| row.nodes.get(slot).ok());
                        return Err(Error::FrontierProof {
                            stage: FrontierProofStage::CapturedRoots,
                            cause: FrontierProofCause::CapturedRoot {
                                fault: Fault::Authentication,
                                root: root.map(|node| node.kind),
                                phase: root.map(|node| node.phase),
                                candidate: candidate.map(|node| node.kind),
                                same: *hash == v.previous,
                                parent: candidate.is_some_and(|node| node.parents.contains(hash)),
                                child: root.is_some_and(|node| node.parents.contains(&v.previous)),
                                base: row.frontier_base == Some(*hash),
                                control: row.frontier_control_hash == Some(*hash),
                                recent: root.is_some_and(|node| node.frontier_recent),
                                requested: root.is_some_and(|node| node.requested),
                            },
                        });
                    }
                    v.set_stage(Stage::Targets(index + 1))?;
                } else {
                    let row = self.rooms.get_mut(r)?;
                    if v.previous != [0; 64] && !row.queues.frontier.contains(&v.previous) {
                        row.queues.frontier.push(v.previous)?;
                    }
                    v.set_stage(Stage::Normalize(0))?;
                }
            }
            Stage::Normalize(index) => {
                let row = self.rooms.get_mut(r)?;
                if let Some(hash) = row.queues.frontier.get(index) {
                    if *hash != v.previous && row.find_node(hash).is_some_and(|slot| v.seen(slot)) {
                        row.queues.frontier.swap_remove(index)?;
                    } else {
                        v.set_stage(Stage::Normalize(index + 1))?;
                    }
                } else {
                    v.set_stage(Stage::Commit)?;
                }
            }
            Stage::Commit => {
                let row = self.rooms.get_mut(r)?;
                if v.previous != [0; 64] {
                    let candidate = v.candidate.ok_or(Fault::Authentication)?;
                    let node = row.nodes.get(candidate)?;
                    if node.hash != v.previous
                        || node.epoch != v.epoch
                        || node.auth.is_none()
                        || !node.complete
                        || !v.seen(candidate)
                    {
                        return Err(Fault::Authentication.into());
                    }
                }
                if v.epoch != [0; 64] {
                    let anchor = row.nodes.get(v.anchor.ok_or(Fault::Authentication)?)?;
                    if anchor.hash != v.epoch
                        || anchor.auth.is_none()
                        || !anchor.complete
                        || !epoch_kind(anchor.kind)
                        || !row
                            .find_epoch(&v.epoch)
                            .and_then(|slot| row.epochs.get(slot).ok())
                            .is_some_and(|e| e.complete)
                    {
                        return Err(Fault::Authentication.into());
                    }
                }
                if v.previous != [0; 64] && !row.queues.frontier.contains(&v.previous) {
                    row.queues.frontier.push(v.previous)?;
                }
                // Advance only a paired cursor actually covered by this proof.
                // A newer uncovered observation retains its own epoch pairing.
                if row.last_message == [0; 64]
                    || row
                        .find_node(&row.last_message)
                        .is_some_and(|slot| v.seen(slot))
                {
                    row.last_message = v.previous;
                    row.current_epoch = v.epoch;
                }
                let phase = row.sync_phase.take().ok_or(Fault::Conflict)?;
                row.phase = phase;
                row.frontier_control = None;
                row.frontier_base = None;
                row.frontier_control_hash = None;
                self.finish_wire(source, owner.operation)?;
                self.event(Event::RoomChanged(self.event_room(r), phase))?;
                v.owner = None;
                v.targets.clear();
                v.stack.clear();
                v.visited.fill(0);
            }
            Stage::Reply | Stage::Waiting => {}
        }
        Ok(())
    }
}
