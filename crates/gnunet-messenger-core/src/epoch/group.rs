//! Original member announcements that can parent a GROUP proposal.
use super::*;

/// One accepted identifier and its exact authenticated GROUP for the lifetime
/// of the client room. The graph retains the slot even if the body is erased.
#[derive(Clone, Copy)]
pub(crate) struct GroupProposalBinding {
    pub(super) identifier: ShortHash,
    pub(super) epoch: Slot,
    pub(super) node: Slot,
    pub(super) order: Endian,
}

impl RoomRow<'_> {
    pub(crate) fn group_proposal_position(
        &self,
        epoch: Slot,
        identifier: &ShortHash,
    ) -> Result<usize, usize> {
        self.group_proposals.binary_search_by(|proposal| {
            (
                proposal.identifier,
                proposal.epoch.index,
                proposal.epoch.generation,
            )
                .cmp(&(*identifier, epoch.index, epoch.generation))
        })
    }
}

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    pub(super) fn ensure_group_capacity(
        &mut self,
        room: Slot,
        epoch: Slot,
        confirmation_bytes: usize,
    ) -> Result<(), Error> {
        let groups = &self.rooms.get(room)?.epochs.get(epoch)?.groups;
        let current = groups.limit();
        if current != 0 && (groups.len() < current || self.mode == Mode::Service) {
            groups.next_key()?;
            return Ok(());
        }
        let budget = self
            .remaining_bytes()
            .checked_sub(confirmation_bytes)
            .ok_or(Fault::Capacity)?;
        let next = if current == 0 {
            self.limits.groups_per_epoch
        } else {
            let maximum = self
                .limits
                .groups_per_epoch
                .checked_add(self.limits.messages_per_room)
                .ok_or(Fault::Overflow)?;
            let unit = Slots::<GroupRow>::required_bytes(1)?;
            let more = current
                .min(maximum.saturating_sub(current))
                .min(budget / unit);
            if more == 0 {
                return Err(Fault::Capacity.into());
            }
            current + more
        };
        let grown = self
            .rooms
            .get_mut(room)?
            .epochs
            .get_mut(epoch)?
            .groups
            .grow_to(next, budget)?;
        self.charge(grown)
    }

    pub(super) fn reserve_group_proposal(&mut self, room: Slot) -> Result<(), Error> {
        let row = self.rooms.get(room)?;
        let old = row.group_proposals.capacity();
        if row.group_proposals.len() >= row.nodes.limit() {
            return Err(Fault::Capacity.into());
        }
        if row.group_proposals.len() < old {
            return Ok(());
        }
        let width = core::mem::size_of::<GroupProposalBinding>();
        let affordable = old.saturating_add(self.remaining_bytes() / width);
        let next = old
            .saturating_mul(2)
            .max(4)
            .min(row.nodes.limit())
            .min(affordable);
        if next <= old {
            return Err(Fault::Capacity.into());
        }
        let mut proposals = Vec::new();
        proposals
            .try_reserve_exact(next)
            .map_err(|_| Fault::Capacity)?;
        let bytes = (proposals.capacity() - old)
            .checked_mul(width)
            .ok_or(Fault::Overflow)?;
        self.charge(bytes)?;
        let row = self.rooms.get_mut(room)?;
        proposals.append(&mut row.group_proposals);
        row.group_proposals = proposals;
        Ok(())
    }

    pub(crate) fn group_proposal_deadline(
        &self,
        room: Slot,
        epoch_slot: Slot,
        identifier: ShortHash,
        event: Hash,
    ) -> Result<u64, Error> {
        let row = self.rooms.get(room)?;
        let epoch = row.epochs.get(epoch_slot)?;
        let node = row.find_node(&event).ok_or(Fault::NotReady)?;
        let proposal = row.nodes.get(node)?;
        if proposal.epoch != epoch.hash
            || matches!(
                proposal.phase,
                MessagePhase::Deleted | MessagePhase::Rejected
            )
        {
            return Err(Error::Permission);
        }
        if !proposal.complete || !proposal.semantic_applied || proposal.auth.is_none() {
            return Err(Fault::NotReady.into());
        }
        let accepted = row
            .group_proposal_position(epoch_slot, &identifier)
            .map_err(|_| Fault::NotReady)?;
        if row.group_proposals[accepted].node != node {
            return Err(Error::Permission);
        }
        let group = epoch
            .groups
            .iter()
            .find_map(|(_, group)| (group.identifier == identifier && group.valid).then_some(group))
            .ok_or(Fault::Timeout)?;
        if group.proposal.is_some_and(|proposal| proposal != event) {
            return Err(Error::Permission);
        }
        if group.proposal.is_none() || group.expires == u64::MAX {
            return Err(Fault::Timeout.into());
        }
        let Body::Group {
            identifier: original,
            timeout,
            ..
        } = proposal.body(&self.frames)?
        else {
            return Err(Fault::Malformed.into());
        };
        if *original != identifier {
            return Err(Error::Permission);
        }
        let deadline = proposal
            .timestamp
            .checked_add(timeout.as_micros())
            .ok_or(Fault::Overflow)?;
        if deadline != group.expires {
            return Err(Error::AttributionConflict);
        }
        Ok(deadline)
    }

    pub(crate) fn check_group_parents(
        &self,
        room: Slot,
        epoch: Slot,
        level: u32,
        parents: [Slot; 2],
        sender: Slot,
    ) -> Result<(), Error> {
        let row = self.rooms.get(room)?;
        let epoch = row.epochs.get(epoch)?;
        let parent_level = level.checked_sub(1).ok_or(Fault::InvalidInput)?;
        if 1usize
            .checked_shl(level)
            .is_none_or(|members| members > row.epoch_member_count(epoch))
        {
            return Err(Error::Permission);
        }
        let announcement = |slot| {
            let node = row.nodes.get(slot)?;
            if node.epoch != epoch.hash
                || matches!(node.phase, MessagePhase::Deleted | MessagePhase::Rejected)
            {
                return Err(Error::Permission);
            }
            if !node.complete || !node.semantic_applied {
                return Err(Fault::NotReady.into());
            }
            let contact = node
                .auth
                .and_then(|a| a.owner)
                .ok_or(Fault::Authentication)?
                .contact;
            let Body::Announcement { identifier, .. } = node.body(&self.frames)? else {
                return Err(Fault::Malformed.into());
            };
            let (_, group) = epoch
                .groups
                .iter()
                .find(|(_, group)| group.identifier == *identifier)
                .ok_or(Fault::NotReady)?;
            if !group.valid
                || !row.epoch_has_member(epoch, contact)
                || !group
                    .confirmations
                    .iter()
                    .any(|member| member.contact == contact && member.message == node.hash)
                || identifier_order(group.identifier_order, identifier)
                    != (parent_level != 0, parent_level)
            {
                return Err(Error::Permission);
            }
            Ok((contact, group))
        };
        let (initiator, first) = announcement(parents[0])?;
        let (partner, second) = announcement(parents[1])?;
        if initiator != sender || initiator == partner {
            return Err(Error::Permission);
        }
        // The initial proposal joins two individual members. Their signed
        // announcements may describe the same room-wide key identifier.
        if parent_level == 0 {
            return Ok(());
        }
        if first.confirmations.len() != first.target || second.confirmations.len() != second.target
        {
            return Err(Fault::NotReady.into());
        }
        if first
            .confirmations
            .iter()
            .any(|a| second.confirmations.iter().any(|b| b.contact == a.contact))
        {
            return Err(Error::Permission);
        }
        Ok(())
    }
}
