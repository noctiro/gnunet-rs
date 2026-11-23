//! Official SERVICE first-write epoch hints. Missing hash lookup returns that
//! original hash, keeping real IPC/REQUEST history recovery live.
use crate::{
    archive::CommittedRoomHistory,
    engine::Core,
    state::{AliasBuckets, EpochAlias, RoomRow},
    *,
};
use gnunet_types::Error as Fault;
use wire::envelope::Kind;
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

/// A first-write slot in a room's unchanged alias table.
pub(crate) struct VacantAlias(usize);

impl RoomRow<'_> {
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
    fn epoch_for(
        &self,
        key: &Hash,
        history: Option<&CommittedRoomHistory<'_, '_>>,
    ) -> Result<Hash, Error> {
        let mut cursor = *key;
        // A retired discourse has no retained own epoch. Follow its single
        // original previous link to an actual non-transient association; this
        // is a bounded metadata lookup, never membership/authentication proof.
        for _ in 0..=self.nodes.len() {
            let alias = self.alias(&cursor);
            if history.is_none()
                && let Some(epoch) = alias
            {
                return Ok(epoch);
            }
            let at = self.find_node(&cursor);
            if at.is_none()
                && let Some(history) = history
                && let Some(parent) = history.detached_parent(&cursor)?
            {
                return Ok(parent.epoch);
            }
            if let Some(epoch) = alias {
                return Ok(epoch);
            }
            let Some(slot) = at else {
                return Ok(cursor);
            };
            let node = self.nodes.get(slot)?;
            if !crate::graph::discourse_kind(node.kind) || node.phase != MessagePhase::Deleted {
                return Ok(cursor);
            }
            if node.parents[0] == [0; 64] {
                return Ok([0; 64]);
            }
            cursor = node.parents[0];
        }
        // A bounded cyclic/unresolved chain supplies no inferred association.
        Ok(*key)
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
        if let Some(at) = self.vacant_alias(&key)? {
            self.insert_alias(at, key, epoch);
        }
        Ok(())
    }

    pub(crate) fn vacant_alias(&self, key: &Hash) -> Result<Option<VacantAlias>, Error> {
        if *key == [0; 64] || !self.alias_allowed(key) {
            return Ok(None);
        }
        let len = self.epoch_aliases.len();
        if len == 0 {
            return Err(Fault::Capacity.into());
        }
        let at = start(key, len);
        for n in 0..len {
            let i = (at + n) % len;
            match &self.epoch_aliases[i] {
                Some(a) if &a.key == key => return Ok(None),
                Some(_) => {}
                None => return Ok(Some(VacantAlias(i))),
            }
        }
        Err(Fault::Capacity.into())
    }

    pub(crate) fn insert_alias(&mut self, at: VacantAlias, key: Hash, epoch: Hash) {
        self.epoch_aliases[at.0] = Some(EpochAlias { key, epoch });
        self.epoch_alias_count += 1;
    }
}
impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    /// Register authenticated service originals still awaiting semantic work.
    /// This bounded pass records their sequence and initial epoch aliases in
    /// ready order without consuming the queue, applying message bodies or
    /// granting membership. The archive may then preserve these originals even
    /// when semantic work is temporarily blocked.
    ///
    /// # Errors
    /// Refuses client mode, exhausted sequence space or insufficient alias
    /// storage. Earlier registrations remain valid and are skipped on retry.
    pub fn register_archive_ingress(&mut self) -> Result<(), Error> {
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        for index in 0..self.rooms.limit() {
            let Some(room) = self.rooms.slot_at(index) else {
                continue;
            };
            self.register_room_archive_ingress(room, None)?;
        }
        Ok(())
    }

    /// Register authenticated pending originals in one SERVICE room while
    /// retaining the native owner's pinned graph pages. Like
    /// [`Self::register_archive_ingress`], this leaves semantic work queued.
    ///
    /// # Errors
    /// Refuses client mode, a foreign or future room history, and the same
    /// sequence or storage failures as [`Self::register_archive_ingress`].
    pub fn register_archive_ingress_with_committed_history(
        &mut self,
        room: Room<'id>,
        history: CommittedRoomHistory<'_, '_>,
    ) -> Result<(), Error> {
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        let room = self.check_room(room)?;
        history.check_working_room(self.rooms.get(room)?, room, self.local_peer)?;
        self.register_room_archive_ingress(room, Some(&history))
    }

    fn register_room_archive_ingress(
        &mut self,
        room: Slot,
        history: Option<&CommittedRoomHistory<'_, '_>>,
    ) -> Result<(), Error> {
        let mut offset = 0;
        while let Some(slot) = self.rooms.get(room)?.ready.get(offset) {
            let node = self.rooms.get(room)?.nodes.get(slot)?;
            if node.auth.is_some() && !node.epoch_indexed {
                self.register_service_ingress(room, slot, history)?;
            }
            offset += 1;
        }
        Ok(())
    }

    /// Record exactly once after this node's actual authentication, before its
    /// semantic handler. Deferred unknown signers consume no first-write hints
    /// and never block other already authenticated original messages.
    pub(crate) fn register_service_ingress(
        &mut self,
        r: Slot,
        node: Slot,
        history: Option<&CommittedRoomHistory<'_, '_>>,
    ) -> Result<(), Error> {
        let row = self.rooms.get(r)?;
        let n = row.nodes.get(node)?;
        if n.auth.is_none() {
            return Err(Fault::NotReady.into());
        }
        if n.epoch_indexed {
            return Ok(());
        }
        let sequence = row.sequence.checked_add(1).ok_or(Fault::Overflow)?;
        if row.epoch_aliases.is_empty() {
            let count = AliasBuckets::bucket_count(self.limits.messages_per_room)?;
            let budget = self.remaining_bytes();
            let actual = self
                .rooms
                .get_mut(r)?
                .epoch_aliases
                .initialize(count, budget)?;
            self.charge(actual)?;
        }
        let row = self.rooms.get(r)?;
        let n = row.nodes.get(node)?;
        let hash = n.hash;
        let [previous, other] = n.parents;
        let [first_epoch, second_epoch, _] = n.references;
        let epoch = if let Some(epoch) = row.alias(&hash) {
            epoch
        } else {
            match n.kind {
                Kind::JOIN | Kind::LEAVE => hash,
                Kind::MERGE if first_epoch == second_epoch => first_epoch,
                Kind::MERGE => hash,
                _ => row.epoch_for(&previous, history)?,
            }
        };
        let (previous_epoch, other_hint) = match n.kind {
            Kind::JOIN | Kind::LEAVE => (first_epoch, None),
            Kind::MERGE => (first_epoch, Some((other, second_epoch))),
            _ => (epoch, None),
        };
        let mut hints = [
            Some((hash, epoch)),
            Some((previous, previous_epoch)),
            other_hint,
        ];
        if let Some(history) = history {
            for hint in &mut hints[1..] {
                if let Some((key, _)) = hint
                    && *key != [0; 64]
                    && row.find_node(key).is_none()
                    && history.detached_parent(key)?.is_some()
                {
                    // The pinned record already has its exact association;
                    // a new hint must not reinsert or replace that alias.
                    *hint = None;
                }
            }
        }
        // At most three distinct keys per retained node. Preflight all
        // free cells before changing the table, even under duplicate/zero hints.
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
        row.sequence = sequence;
        let n = row.nodes.get_mut(node)?;
        n.sequence = sequence;
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
        row.epoch_for(hash, None)
    }
    /// Actual two-frontier facts for an original purpose12 peer MERGE draft.
    /// The original signer Binding subsequently fixes header and complete body.
    pub fn service_merge(&self, room: Room<'id>) -> Result<Option<ServiceMerge>, Error> {
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        let row = self.rooms.get(self.check_room(room)?)?;
        let Some(previous) = row
            .queues
            .frontier
            .iter()
            .copied()
            .find(|h| *h != row.last_message)
        else {
            return Ok(None);
        };
        Ok(Some(ServiceMerge {
            first_epoch: row.epoch_for(&row.last_message, None)?,
            second_epoch: row.epoch_for(&previous, None)?,
            previous,
        }))
    }
}

#[cfg(all(test, feature = "alloc"))]
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
        room.epoch_aliases.initialize(4, usize::MAX)?;
        // Explicit public bucket keys, not computed digests or crypto fixtures.
        let first = [2; 64];
        let mut collision = first;
        collision[63] = 3;
        let original = [4; 64];
        room.put_alias(first, original)?;
        room.put_alias(first, [5; 64])?;
        room.put_alias(collision, [6; 64])?;
        assert_eq!(room.epoch_for(&first, None)?, original);
        assert_eq!(room.epoch_for(&collision, None)?, [6; 64]);
        assert_eq!(room.epoch_for(&[9; 64], None)?, [9; 64]);
        room.put_alias([0; 64], [8; 64])?;
        assert_eq!(room.epoch_for(&[0; 64], None)?, [0; 64]);
        assert_eq!(room.epoch_alias_count, 2);
        room.put_alias([7; 64], [8; 64])?;
        room.put_alias([8; 64], [9; 64])?;
        assert!(matches!(
            room.put_alias([9; 64], [1; 64]),
            Err(Error::Protocol(Fault::Capacity))
        ));
        assert_eq!(room.epoch_for(&first, None)?, original);
        Ok(())
    }
}
