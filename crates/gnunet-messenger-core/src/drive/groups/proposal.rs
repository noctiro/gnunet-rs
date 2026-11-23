//! Select parents for one automatic GROUP proposal in the current private epoch.
use super::*;
use crate::epoch::GROUP_PROPOSAL_RETRY_MICROS;

const PROPOSAL_LIFETIME: u64 = 3_600_000_000;
const ANNOUNCEMENT_LIFETIME: u64 = 60_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProposalStep {
    Refresh(ShortHash),
    Send {
        level: u32,
        initiator: Hash,
        partner: Hash,
        anchors_until: u64,
    },
}

fn contains_member(group: &GroupRow, contact: Slot) -> bool {
    group
        .confirmations
        .iter()
        .any(|member| member.contact == contact)
}

fn is_valid_cohort(group: &GroupRow) -> bool {
    group.valid && identifier_order(group.identifier_order, &group.identifier).0
}

fn can_claim_members(group: &GroupRow) -> bool {
    is_valid_cohort(group) && (!group.historical() || group.confirmations.len() == group.target)
}

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    fn local_cohort(&self, epoch: &EpochRow, contact: Slot) -> Option<Slot> {
        epoch
            .groups
            .iter()
            .filter(|(_, group)| {
                is_valid_cohort(group)
                    && group.phase == KeyPhase::Present
                    && group.key.is_some()
                    && group.confirmations.len() == group.target
                    && group.confirmations.iter().all(|member| member.verified_mac)
                    && contains_member(group, contact)
            })
            .max_by_key(|(_, group)| {
                (
                    identifier_order(group.identifier_order, &group.identifier).1,
                    group.identifier,
                )
            })
            .map(|(slot, _)| slot)
    }

    fn proposal_step(
        &self,
        source: Source<'id>,
        member: MemberSession<'id>,
        now: u64,
    ) -> Result<Option<ProposalStep>, Error> {
        let room = self.rooms.get(source.room)?;
        if room.capabilities.is_public() {
            return Ok(None);
        }
        let contact = room.sessions.get(member.slot)?.contact;
        let epoch = room.epochs.get(
            room.find_epoch(&room.current_epoch)
                .ok_or(Fault::NotReady)?,
        )?;
        let local = self.local_cohort(epoch, contact);
        let local_group = local.map(|slot| epoch.groups.get(slot)).transpose()?;
        let level = local_group.map_or(0, |group| {
            identifier_order(group.identifier_order, &group.identifier).1
        });
        let next_level = level.checked_add(1).ok_or(Fault::Overflow)?;
        if 1usize
            .checked_shl(next_level)
            .is_none_or(|size| size > room.epoch_member_count(epoch))
            || epoch.active_group_count() >= self.limits.groups_per_epoch
        {
            return Ok(None);
        }
        if room.automatic_proposal.is_some_and(|attempt| {
            attempt.epoch == epoch.hash
                && attempt.level > level
                && attempt.expires > now
                && !room
                    .find_node(&attempt.event)
                    .and_then(|slot| room.nodes.get(slot).ok())
                    .is_some_and(|node| {
                        matches!(node.phase, MessagePhase::Deleted | MessagePhase::Rejected)
                    })
                && !epoch
                    .groups
                    .iter()
                    .any(|(_, group)| group.proposal == Some(attempt.event) && !group.valid)
        }) {
            return Ok(None);
        }
        if epoch.groups.iter().any(|(_, group)| {
            let (_, proposed_level) = identifier_order(group.identifier_order, &group.identifier);
            if !is_valid_cohort(group)
                || proposed_level <= level
                || group.expires == u64::MAX
                || group.expires <= now
            {
                return false;
            }
            group
                .proposal
                .and_then(|event| room.find_node(&event))
                .and_then(|slot| room.nodes.get(slot).ok())
                .is_some_and(|node| {
                    node.local_sent
                        && node.complete
                        && node.semantic_applied
                        && now < node.timestamp.saturating_add(GROUP_PROPOSAL_RETRY_MICROS)
                        && !matches!(node.phase, MessagePhase::Deleted | MessagePhase::Rejected)
                        && node
                            .auth
                            .and_then(|a| a.owner)
                            .is_some_and(|owner| owner.contact == contact)
                })
        }) {
            return Ok(None);
        }
        Ok(if let Some(group) = local_group {
            self.higher_proposal(room, epoch, group, (level, next_level), contact, now)
        } else {
            self.initial_proposal(room, epoch, contact, now)
        })
    }

    fn initial_proposal(
        &self,
        room: &RoomRow<'id>,
        epoch: &EpochRow,
        contact: Slot,
        now: u64,
    ) -> Option<ProposalStep> {
        let announcement = epoch.groups.get(epoch.best_announcement?).ok()?;
        if !announcement.valid
            || announcement.key.is_none()
            || identifier_order(announcement.identifier_order, &announcement.identifier)
                != (false, 0)
            || epoch
                .groups
                .iter()
                .any(|(_, cohort)| can_claim_members(cohort) && contains_member(cohort, contact))
        {
            return None;
        }
        let own = announcement
            .confirmations
            .iter()
            .find(|member| member.contact == contact && member.verified_mac)?;
        let (partner, partner_until) = announcement
            .confirmations
            .iter()
            .filter(|member| {
                member.contact != contact
                    && member.verified_mac
                    && !epoch.groups.iter().any(|(_, cohort)| {
                        can_claim_members(cohort) && contains_member(cohort, member.contact)
                    })
            })
            .filter_map(|member| {
                let deadline = self.announcement_deadline(room, epoch, member, now, false)?;
                Some((member.message, deadline))
            })
            .min_by_key(|(hash, _)| *hash)?;
        let Some(own_until) = self.announcement_deadline(room, epoch, own, now, true) else {
            return Some(ProposalStep::Refresh(announcement.identifier));
        };
        Some(ProposalStep::Send {
            level: 1,
            initiator: own.message,
            partner,
            anchors_until: own_until.min(partner_until),
        })
    }

    fn higher_proposal(
        &self,
        room: &RoomRow<'id>,
        epoch: &EpochRow,
        local: &GroupRow,
        (level, next_level): (u32, u32),
        contact: Slot,
        now: u64,
    ) -> Option<ProposalStep> {
        let own = local
            .confirmations
            .iter()
            .find(|member| member.contact == contact)?;
        let Some(own_until) = self.announcement_deadline(room, epoch, own, now, true) else {
            return Some(ProposalStep::Refresh(local.identifier));
        };
        let (partner, partner_until) = epoch
            .groups
            .iter()
            .filter(|(_, group)| {
                is_valid_cohort(group)
                    && identifier_order(group.identifier_order, &group.identifier).1 == level
                    && group.confirmations.len() == group.target
                    && group
                        .confirmations
                        .iter()
                        .all(|member| !contains_member(local, member.contact))
                    && !epoch.groups.iter().any(|(_, higher)| {
                        can_claim_members(higher)
                            && identifier_order(higher.identifier_order, &higher.identifier).1
                                > level
                            && group
                                .confirmations
                                .iter()
                                .all(|member| contains_member(higher, member.contact))
                    })
            })
            .flat_map(|(_, group)| &group.confirmations)
            .filter_map(|member| {
                let deadline = self.announcement_deadline(room, epoch, member, now, false)?;
                Some((member.message, deadline))
            })
            .min_by_key(|(hash, _)| *hash)?;
        Some(ProposalStep::Send {
            level: next_level,
            initiator: own.message,
            partner,
            anchors_until: own_until.min(partner_until),
        })
    }

    pub(in crate::drive) fn propose_next_group(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        entropy: &mut impl crypto::Entropy,
        now: u64,
        deadline: u64,
    ) -> Result<Option<Operation<'id>>, Error> {
        match self.proposal_step(source, member, now)? {
            None => Ok(None),
            Some(ProposalStep::Refresh(identifier)) => self
                .prepare_announcement(
                    source,
                    member,
                    identifier,
                    ANNOUNCEMENT_LIFETIME,
                    entropy,
                    now,
                    deadline,
                )
                .map(Some),
            Some(ProposalStep::Send {
                level,
                initiator,
                partner,
                anchors_until,
            }) => {
                let identifier = self.fresh_identifier(Some(level), entropy)?;
                let expires = now
                    .checked_add(PROPOSAL_LIFETIME)
                    .filter(|expires| *expires != u64::MAX)
                    .ok_or(Fault::Overflow)?;
                let operation = self.prepare_send(
                    source,
                    member,
                    Body::Group {
                        identifier: &identifier,
                        initiator: &initiator,
                        partner: &partner,
                        timeout: gnunet_wire::official::RelativeTime::from_micros(
                            PROPOSAL_LIFETIME,
                        ),
                    },
                    now,
                    deadline.min(expires).min(anchors_until),
                )?;
                let room = self.rooms.get_mut(source.room)?;
                let binding = room.operations.get(operation.slot)?.binding;
                room.automatic_proposal = Some(AutomaticProposal {
                    operation: operation.slot,
                    epoch: binding.epoch,
                    event: binding.message,
                    level,
                    expires,
                });
                Ok(Some(operation))
            }
        }
    }
}
