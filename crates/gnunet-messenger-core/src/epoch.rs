//! Actual immutable membership epochs, tentative versus MAC-checked group
//! confirmations, bound key operations and safe successor-key invalidation.
#[cfg(feature = "alloc")]
use crate::slots::Slots;
use crate::{engine::Core, state::*, *};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use gnunet_types::Error as Fault;
use wire::body::Body;
#[cfg(feature = "alloc")]
use wire::{envelope::Kind, message::Message, profile::Endian};
#[cfg(feature = "alloc")]
mod authorization;
#[cfg(feature = "alloc")]
mod client;
#[cfg(feature = "alloc")]
pub(crate) mod derivation;
#[cfg(feature = "alloc")]
mod group;
#[cfg(feature = "alloc")]
mod group_keys;
pub(crate) mod members;
#[cfg(feature = "alloc")]
pub(crate) use group::GroupProposalBinding;
#[cfg(feature = "alloc")]
pub(crate) const GROUP_PROPOSAL_RETRY_MICROS: u64 = 60_000_000;
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum EpochMutation {
    Join(Slot),
    Leave(Slot),
    Merge,
}
#[cfg(feature = "alloc")]
#[derive(Clone, Copy)]
pub(crate) struct Nonce {
    /// Original value value.
    pub value: ShortHash,
    /// Original message value.
    pub message: Hash,
}
#[cfg(all(test, feature = "alloc"))]
pub(crate) fn identifier(profile: wire::profile::Profile, id: &ShortHash) -> (bool, u32) {
    identifier_order(profile.endian, id)
}
#[cfg(feature = "alloc")]
pub(crate) fn identifier_order(order: Endian, id: &ShortHash) -> (bool, u32) {
    match order {
        Endian::Little => (id[0] & 1 != 0, u32::from(id[0] >> 1)),
        Endian::Big => (id[0] & 0x80 != 0, u32::from(id[0] & 0x7f)),
    }
}
#[cfg(feature = "alloc")]
fn verified(group: &GroupRow) -> usize {
    group
        .confirmations
        .iter()
        .filter(|c| c.verified_mac)
        .count()
}
impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    pub(crate) fn epoch_message(
        &mut self,
        r: Slot,
        node: Slot,
        body: Body<'_>,
    ) -> Result<(), Error> {
        let n = self.rooms.get(r)?.nodes.get(node)?;
        let hash = n.hash;
        let source = n.origin.require_live(self.instance)?;
        let (parents, mutation) = match body {
            Body::Leave { epoch } => (
                [*epoch, [0; 64]],
                EpochMutation::Leave(
                    n.auth
                        .and_then(|a| a.owner)
                        .ok_or(Fault::Authentication)?
                        .contact,
                ),
            ),
            Body::Merge {
                first_epoch,
                second_epoch,
                ..
            } => ([*first_epoch, *second_epoch], EpochMutation::Merge),
            _ => return Err(Fault::InvalidInput.into()),
        };
        if parents.contains(&hash) {
            return Err(Fault::Malformed.into());
        }
        if self.rooms.get(r)?.find_epoch(&hash).is_none() {
            self.rooms.get(r)?.epochs.next_key()?;
            let (epoch, bytes) = self.prepare_epoch(r, hash, parents, mutation)?;
            self.insert_epoch(r, epoch, bytes)?;
        }
        for p in parents {
            if p != [0; 64] && self.rooms.get(r)?.find_epoch(&p).is_none() {
                self.note_dependency(r, p, source)?;
            }
        }
        self.refresh_epochs(r)?;
        Ok(())
    }
    /// Stage the immutable snapshot before installing any live JOIN identity.
    /// A complete restored snapshot can be reused only in the exact same scope.
    pub(crate) fn prepare_join_epoch(
        &mut self,
        r: Slot,
        node: Slot,
        parent: Hash,
        contact: Slot,
    ) -> Result<bool, Error> {
        let row = self.rooms.get(r)?;
        let original = row.nodes.get(node)?;
        let source = original.origin.require_live(self.instance)?;
        let hash = original.hash;
        if hash == parent {
            return Err(Fault::Malformed.into());
        }
        if parent != [0; 64] {
            let Some(at) = row.find_epoch(&parent) else {
                self.note_dependency(r, parent, source)?;
                return Err(Fault::NotReady.into());
            };
            if !row.epochs.get(at)?.complete {
                return Err(Fault::NotReady.into());
            }
        }
        let parents = [parent, [0; 64]];
        let mutation = EpochMutation::Join(contact);
        if let Some(at) = row.find_epoch(&hash) {
            let existing = row.epochs.get(at)?;
            if existing.parents != parents || existing.mutation != mutation || !existing.complete {
                return Err(Fault::Conflict.into());
            }
            return Ok(false);
        }
        row.epochs.next_key()?;
        let (mut epoch, bytes) = self.prepare_epoch(r, hash, parents, mutation)?;
        self.rooms.get_mut(r)?.finish_epoch_snapshot(
            parents,
            mutation,
            &mut epoch.members,
            self.limits.sessions_per_room,
        )?;
        epoch.complete = true;
        self.insert_epoch(r, epoch, bytes)?;
        Ok(true)
    }

    fn prepare_epoch(
        &self,
        r: Slot,
        hash: Hash,
        parents: [Hash; 2],
        mutation: EpochMutation,
    ) -> Result<(EpochRow, usize), Error> {
        let budget = self.remaining_bytes();
        #[cfg(feature = "alloc")]
        let (groups, nonces, budget) = self.prepare_epoch_keys(budget)?;
        let members = self
            .rooms
            .get(r)?
            .member_arena
            .reserve(self.limits.sessions_per_room, budget)?;
        let bytes = members.owned_bytes()?;
        let epoch = EpochRow::hosted(hash, parents, mutation, members, false, 1);
        #[cfg(feature = "alloc")]
        let (epoch, bytes) = {
            let group_bytes = groups.bytes()?;
            let bytes = nonces
                .capacity()
                .checked_mul(core::mem::size_of::<Nonce>())
                .and_then(|n| n.checked_add(group_bytes))
                .and_then(|n| n.checked_add(bytes))
                .ok_or(Fault::Overflow)?;
            (
                EpochRow {
                    groups,
                    nonces,
                    ..epoch
                },
                bytes,
            )
        };
        Ok((epoch, bytes))
    }

    fn insert_epoch(&mut self, r: Slot, epoch: EpochRow, bytes: usize) -> Result<(), Error> {
        self.charge(bytes)?;
        if let Err((error, _)) = self.rooms.get_mut(r)?.epochs.insert(epoch) {
            self.release(bytes)?;
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn publish_epoch(&mut self, r: Slot, hash: Hash) -> Result<(), Error> {
        #[cfg(feature = "alloc")]
        let derives = self.mode.is_client();
        let room = self.rooms.get_mut(r)?;
        #[cfg(feature = "alloc")]
        if derives {
            room.derivation.arm();
        }
        room.queue_dependants(&hash)?;
        self.event(Event::EpochChanged(self.event_room(r), hash))
    }

    pub(crate) fn refresh_epochs(&mut self, r: Slot) -> Result<(), Error> {
        // Every pass either completes an actual immutable snapshot or stops.
        // Iterative fixed slots avoid recursion on maliciously deep epoch DAGs.
        for _ in 0..self.limits.work_per_turn {
            if self.reserve_events(3).is_err() {
                break;
            }
            let next = self.rooms.get(r)?.epochs.iter().find_map(|(s, e)| {
                (!e.complete
                    && e.parents.iter().all(|h| {
                        *h == [0; 64]
                            || self
                                .rooms
                                .get(r)
                                .ok()
                                .and_then(|row| {
                                    row.find_epoch(h).and_then(|p| row.epochs.get(p).ok())
                                })
                                .is_some_and(|p| p.complete)
                    }))
                .then_some(s)
            });
            let Some(s) = next else {
                break;
            };
            self.reserve_events(1)?;
            let room = self.rooms.get_mut(r)?;
            room.complete_epoch_members(s, self.limits.sessions_per_room)?;
            let hash = room.epochs.get(s)?.hash;
            if let Some(node) = room.find_node(&hash) {
                room.queue_node(node)?;
            }
            self.publish_epoch(r, hash)?;
        }
        Ok(())
    }
    /// Return the complete epoch's original contact generations as live handles.
    /// Unknown or incomplete epochs cannot supply a membership snapshot.
    pub fn epoch_members(
        &self,
        room: Room<'id>,
        hash: &Hash,
    ) -> Result<impl ExactSizeIterator<Item = Contact<'id>> + DoubleEndedIterator + '_, Error> {
        let row = self.rooms.get(self.check_room(room)?)?;
        let e = row
            .epochs
            .get(row.find_epoch(hash).ok_or(Fault::NotFound)?)?;
        if !e.complete {
            return Err(Fault::NotReady.into());
        }
        let members = row.epoch_members(e);
        for slot in members.clone() {
            self.contacts.get(slot)?;
        }
        Ok(members.map(move |slot| self.contact_id(slot)))
    }
}
