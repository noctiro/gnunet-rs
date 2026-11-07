//! Official SERVICE first-write epoch hints. Missing hash lookup returns that
//! original hash, keeping real IPC/REQUEST history recovery live.
use crate::{
    engine::Core,
    state::{EpochAlias, RoomRow},
    *,
};
use alloc::vec::Vec;
use gnunet_types::Error as Fault;
/// Actual frontier facts; these metadata values are not epoch membership proof.
#[derive(Clone, Copy)]
pub struct ServiceMerge {
    /// Actual current chain carried epoch or missing-hash placeholder.
    pub first_epoch: Hash,
    /// Actual other chain carried epoch or missing-hash placeholder.
    pub second_epoch: Hash,
    /// Actual other retained message-chain frontier.
    pub previous: Hash,
}
impl core::fmt::Debug for ServiceMerge {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ServiceMerge([REDACTED])")
    }
}
fn start(key: &Hash, len: usize) -> usize {
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&key[..8]);
    // Internal hash bucket only. Every candidate still compares all64 key bytes;
    // neither an index nor a prefix is a protocol/authentication identifier.
    (u64::from_le_bytes(bytes) as usize) % len
}

impl<'id> RoomRow<'id> {
    pub(crate) fn alias(&self, key: &Hash) -> Option<Hash> {
        if self.epoch_aliases.is_empty() {
            return None;
        }
        let at = start(key, self.epoch_aliases.len());
        for n in 0..self.epoch_aliases.len() {
            match &self.epoch_aliases[(at + n) % self.epoch_aliases.len()] {
                None => return None,
                Some(a) if a.key == *key => return Some(a.epoch),
                Some(_) => {}
            }
        }
        None
    }
    fn epoch_for(&self, key: &Hash) -> Hash {
        let mut cursor = *key;
        // A retired discourse has no retained own epoch. Follow its single
        // original previous link to an actual non-transient association; this
        // is a bounded metadata lookup, never membership/authentication proof.
        for _ in 0..=self.nodes.len() {
            if let Some(epoch) = self.alias(&cursor) {
                return epoch;
            }
            let Some(slot) = self.find_node(&cursor) else {
                return cursor;
            };
            let Ok(node) = self.nodes.get(slot) else {
                return cursor;
            };
            if !crate::graph::discourse_kind(node.kind) || node.phase != MessagePhase::Deleted {
                return cursor;
            }
            if node.parents[0] == [0; 64] {
                return [0; 64];
            }
            cursor = node.parents[0];
        }
        // A bounded cyclic/unresolved chain supplies no inferred association.
        *key
    }
    fn alias_allowed(&self, key: &Hash) -> bool {
        !self
            .find_node(key)
            .and_then(|s| self.nodes.get(s).ok())
            .is_some_and(|n| {
                crate::graph::discourse_kind(n.kind) && n.phase == MessagePhase::Deleted
            })
    }
    /// Remove one exact key and repair its original linear-probe cluster.
    /// All arithmetic/refusal preflights precede the first table mutation.
    pub(crate) fn remove_alias(&mut self, key: &Hash) -> Result<bool, Error> {
        let len = self.epoch_aliases.len();
        if len == 0 {
            return Ok(false);
        }
        let at = start(key, len);
        let mut found = None;
        for n in 0..len {
            let i = (at + n) % len;
            match &self.epoch_aliases[i] {
                Some(a) if a.key == *key => {
                    found = Some(i);
                    break;
                }
                Some(_) => {}
                None => return Ok(false),
            }
        }
        let Some(mut hole) = found else {
            return Ok(false);
        };
        let count = self
            .epoch_alias_count
            .checked_sub(1)
            .ok_or(Fault::Conflict)?;
        // A formerly full table can wrap once after the moving hole. A second
        // pass reaches that hole; already shifted entries cannot move again.
        let work = len.checked_mul(2).ok_or(Fault::Overflow)?;
        self.epoch_aliases[hole] = None;
        self.epoch_alias_count = count;
        let mut scan = (hole + 1) % len;
        let distance = |from: usize, to: usize| {
            if to >= from {
                to - from
            } else {
                len - (from - to)
            }
        };
        for _ in 0..work {
            let Some(entry) = &self.epoch_aliases[scan] else {
                break;
            };
            let home = start(&entry.key, len);
            if distance(home, hole) < distance(home, scan) {
                self.epoch_aliases[hole] = self.epoch_aliases[scan].take();
                hole = scan;
            }
            scan = (scan + 1) % len;
        }
        Ok(true)
    }
    pub(crate) fn put_alias(&mut self, key: Hash, epoch: Hash) -> Result<(), Error> {
        if key == [0; 64] || !self.alias_allowed(&key) {
            return Ok(());
        }
        let len = self.epoch_aliases.len();
        if len == 0 {
            return Err(Fault::Capacity.into());
        }
        let at = start(&key, len);
        for n in 0..len {
            let i = (at + n) % len;
            match &self.epoch_aliases[i] {
                Some(a) if a.key == key => return Ok(()),
                Some(_) => {}
                None => {
                    self.epoch_aliases[i] = Some(EpochAlias { key, epoch });
                    self.epoch_alias_count += 1;
                    return Ok(());
                }
            }
        }
        Err(Fault::Capacity.into())
    }
}
impl<'id> Core<'id> {
    /// Record exactly once after this node's actual authentication, before its
    /// semantic handler. Deferred unknown signers consume no first-write hints
    /// and never block other already authenticated original messages.
    pub(crate) fn service_index_epoch(
        &mut self,
        r: Slot,
        node: Slot,
        message: wire::message::Message<'_>,
    ) -> Result<(), Error> {
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        let n = self.rooms.get(r)?.nodes.get(node)?;
        if n.auth.is_none() {
            return Err(Fault::NotReady.into());
        }
        if n.epoch_indexed {
            return Ok(());
        }
        if self.rooms.get(r)?.epoch_aliases.is_empty() {
            let count = self
                .limits
                .messages_per_room
                .checked_mul(4)
                .ok_or(Fault::Overflow)?;
            let minimum = count
                .checked_mul(core::mem::size_of::<Option<EpochAlias>>())
                .ok_or(Fault::Overflow)?;
            if minimum > self.remaining_bytes() {
                return Err(Fault::Capacity.into());
            }
            let mut aliases = Vec::new();
            aliases
                .try_reserve_exact(count)
                .map_err(|_| Fault::Capacity)?;
            aliases.resize_with(count, || None);
            let actual = aliases
                .capacity()
                .checked_mul(core::mem::size_of::<Option<EpochAlias>>())
                .ok_or(Fault::Overflow)?;
            self.charge(actual)?;
            self.rooms.get_mut(r)?.epoch_aliases = aliases;
        }
        let hash = self.rooms.get(r)?.nodes.get(node)?.hash;
        let previous = *message.header().previous;
        let row = self.rooms.get(r)?;
        let epoch = if let Some(existing) = row.alias(&hash) {
            existing
        } else {
            match message.body() {
                wire::body::Body::Join { .. } | wire::body::Body::Leave { .. } => hash,
                wire::body::Body::Merge {
                    first_epoch,
                    second_epoch,
                    ..
                } => {
                    if first_epoch == second_epoch {
                        *first_epoch
                    } else {
                        hash
                    }
                }
                _ => row.epoch_for(&previous),
            }
        };
        let mut hints = [None, None, None];
        hints[0] = Some((hash, epoch));
        match message.body() {
            wire::body::Body::Join { epoch, .. } | wire::body::Body::Leave { epoch } => {
                hints[1] = Some((previous, *epoch))
            }
            wire::body::Body::Merge {
                first_epoch,
                second_epoch,
                previous: other,
            } => {
                hints[1] = Some((previous, *first_epoch));
                hints[2] = Some((*other, *second_epoch));
            }
            _ => hints[1] = Some((previous, epoch)),
        }
        // At most3 distinct keys per retained node, and4*M buckets. Preflight all
        // free cells before changing the table, even under duplicate/zero hints.
        let row = self.rooms.get(r)?;
        let mut needed = 0;
        for (i, hint) in hints.iter().enumerate() {
            if let Some((key, _)) = hint
                && *key != [0; 64]
                && row.alias_allowed(key)
                && row.alias(key).is_none()
                && !hints[..i].iter().flatten().any(|(k, _)| k == key)
            {
                needed += 1
            }
        }
        if row
            .epoch_aliases
            .len()
            .saturating_sub(row.epoch_alias_count)
            < needed
        {
            return Err(Fault::Capacity.into());
        }
        let row = self.rooms.get_mut(r)?;
        for (key, value) in hints.into_iter().flatten() {
            row.put_alias(key, value)?
        }
        let n = row.nodes.get_mut(node)?;
        n.epoch = epoch;
        n.epoch_indexed = true;
        Ok(())
    }
    /// First known original alias, or a bounded original previous-link lookup
    /// through retired discourse anchors, otherwise an unresolved original hash.
    /// None of these metadata hints proves epoch existence/completeness/rights.
    /// Validate this original room generation even for the zero-hash special case.
    pub fn service_message_epoch(&self, room: Room<'id>, hash: &Hash) -> Result<Hash, Error> {
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        let row = self.rooms.get(self.check_room(room)?)?;
        Ok(row.epoch_for(hash))
    }
    /// Actual two-frontier facts for an original purpose12 peer MERGE draft.
    /// The original signer Binding subsequently fixes header and complete body.
    pub fn service_merge(&self, room: Room<'id>) -> Result<Option<ServiceMerge>, Error> {
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        let row = self.rooms.get(self.check_room(room)?)?;
        let Some(previous) = row
            .frontier
            .iter()
            .copied()
            .find(|h| *h != row.last_message)
        else {
            return Ok(None);
        };
        Ok(Some(ServiceMerge {
            first_epoch: row.epoch_for(&row.last_message),
            second_epoch: row.epoch_for(&previous),
            previous,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Public hash-bucket metadata assertions with fallible allocation"
    )]
    fn first_epoch_hint_full_key_collision_and_missing_placeholder() -> Result<(), Error> {
        let limits = Limits {
            messages_per_room: 1,
            sources_per_room: 1,
            sessions_per_room: 1,
            epochs_per_room: 1,
            operations_per_room: 1,
            subscriptions_per_room: 1,
            missing_per_room: 1,
            ..Limits::default()
        };
        let mut room = RoomRow::new([1; 64], None, limits, wire::profile::Profile::LITTLE_255)?;
        assert!(room.epoch_aliases.is_empty());
        room.epoch_aliases
            .try_reserve_exact(4)
            .map_err(|_| Fault::Capacity)?;
        room.epoch_aliases.resize_with(4, || None);
        // Explicit public bucket keys, not computed digests or crypto fixtures.
        let first = [2; 64];
        let mut collision = first;
        collision[63] = 3;
        let original = [4; 64];
        room.put_alias(first, original)?;
        room.put_alias(first, [5; 64])?;
        room.put_alias(collision, [6; 64])?;
        assert_eq!(room.epoch_for(&first), original);
        assert_eq!(room.epoch_for(&collision), [6; 64]);
        assert_eq!(room.epoch_for(&[9; 64]), [9; 64]);
        room.put_alias([0; 64], [8; 64])?;
        assert_eq!(room.epoch_for(&[0; 64]), [0; 64]);
        assert_eq!(room.epoch_alias_count, 2);
        room.put_alias([7; 64], [8; 64])?;
        room.put_alias([8; 64], [9; 64])?;
        assert!(matches!(
            room.put_alias([9; 64], [1; 64]),
            Err(Error::Protocol(Fault::Capacity))
        ));
        assert_eq!(room.epoch_for(&first), original);
        Ok(())
    }
}
