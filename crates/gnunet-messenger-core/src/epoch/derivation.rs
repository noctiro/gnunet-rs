//! Bounded late-key propagation over the original immutable epoch graph.
use super::*;

/// A fixed sweep cursor; no key, source or epoch authority is stored here.
#[derive(Default)]
pub(crate) struct DerivationCursor {
    epoch: usize,
    group: usize,
    pending: bool,
    changed: bool,
    turn: bool,
}
impl DerivationCursor {
    pub(crate) fn arm(&mut self) {
        if self.pending {
            self.changed = true;
        } else {
            self.epoch = 0;
            self.group = 0;
            self.pending = true;
            self.changed = false;
        }
    }
    pub(crate) const fn pending(&self) -> bool {
        self.pending
    }
    pub(crate) fn scheduled(&mut self, graph_idle: bool) -> bool {
        if !self.pending {
            return false;
        }
        self.turn = !self.turn;
        graph_idle || self.turn
    }
}

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    pub(super) fn inherited_group_key(
        &self,
        r: Slot,
        e: Slot,
        id: &ShortHash,
        order: Endian,
    ) -> Result<Option<(crypto::AeadKey, Hash)>, Error> {
        let row = self.rooms.get(r)?;
        let epoch = row.epochs.get(e)?;
        if !epoch.complete {
            return Ok(None);
        }
        let is_group = identifier_order(order, id).0;
        let parents = if is_group {
            epoch.parents
        } else {
            // C announcements follow the original causal predecessor only;
            // they never borrow a MERGE's other branch or cross a LEAVE.
            if matches!(epoch.mutation, EpochMutation::Leave(_)) {
                return Ok(None);
            }
            let Some(node) = row.find_node(&epoch.hash) else {
                return Ok(None);
            };
            let node = row.nodes.get(node)?;
            if node.auth.is_none() {
                return Ok(None);
            }
            let Some(previous) = row.find_node(&node.parents[0]) else {
                return Ok(None);
            };
            let previous = row.nodes.get(previous)?;
            if previous.auth.is_none() || previous.epoch != epoch.parents[0] {
                return Ok(None);
            }
            [previous.epoch, [0; 64]]
        };
        let mut selected = None;
        for parent in parents {
            let Some(previous) = row.find_epoch(&parent) else {
                continue;
            };
            let old = row.epochs.get(previous)?;
            if let Some((slot, group)) =
                old.groups.iter().find(|(_, group)| group.identifier == *id)
            {
                let count = verified(group);
                if selected.is_none_or(|(_, _, _, previous_count)| count > previous_count) {
                    selected = Some((previous, slot, parent, count));
                }
            }
        }
        let Some((previous, slot, parent, count)) = selected else {
            return Ok(None);
        };
        let old = row.epochs.get(previous)?;
        let group = old.groups.get(slot)?;
        // Selection is only a candidate. C ranks before testing authority; a
        // revoked selected parent cannot be replaced by a different old key.
        if !old.complete
            || group.identifier_order != order
            || !group.valid
            || group.phase != KeyPhase::Present
            || count != group.target
            || group.key.is_none()
            || !group
                .confirmations
                .iter()
                .filter(|c| c.verified_mac)
                .all(|confirmation| row.epoch_has_member(epoch, confirmation.contact))
        {
            return Ok(None);
        }
        Ok(Some((
            group
                .key
                .as_ref()
                .ok_or(Fault::NotReady)?
                .derive_epoch(&epoch.hash, id, is_group)?,
            parent,
        )))
    }

    /// Consume one caller work unit: one group slot, empty epoch slot or sweep
    /// boundary. Sparse tables cannot hide a whole metadata scan in one unit.
    pub(crate) fn derive_epoch_step(&mut self, r: Slot) -> Result<bool, Error> {
        if !self.rooms.get(r)?.derivation.pending {
            return Ok(false);
        }
        let target = {
            let row = self.rooms.get_mut(r)?;
            let cursor = &mut row.derivation;
            if cursor.epoch == row.epochs.limit() {
                None
            } else if let Some(epoch) = row.epochs.slot_at(cursor.epoch) {
                let groups = &row.epochs.get(epoch)?.groups;
                if cursor.group == groups.limit() {
                    cursor.epoch += 1;
                    cursor.group = 0;
                    return Ok(true);
                }
                if let Some(group) = groups.slot_at(cursor.group) {
                    Some((epoch, group))
                } else {
                    cursor.group += 1;
                    return Ok(true);
                }
            } else {
                cursor.epoch += 1;
                cursor.group = 0;
                return Ok(true);
            }
        };
        let Some((epoch, group)) = target else {
            let cursor = &mut self.rooms.get_mut(r)?.derivation;
            if cursor.changed {
                cursor.epoch = 0;
                cursor.group = 0;
                cursor.changed = false;
            } else {
                cursor.pending = false;
            }
            return Ok(true);
        };
        let row = self.rooms.get(r)?.epochs.get(epoch)?.groups.get(group)?;
        if row.valid && row.phase == KeyPhase::Missing && row.key.is_none() {
            let id = row.identifier;
            if let Some((key, parent)) =
                self.inherited_group_key(r, epoch, &id, row.identifier_order)?
            {
                // This validates every retained tentative child announcement
                // before it can count towards another generation's cohort.
                self.install_group_key_from(r, epoch, group, key, Some(parent))?;
            }
        }
        // On capacity refusal, retain the exact cell for the next caller turn.
        self.rooms.get_mut(r)?.derivation.group += 1;
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
