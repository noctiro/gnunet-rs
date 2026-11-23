//! Advance admitted GROUP proposals using only the original participant roles.
use super::*;
use crate::epoch::identifier_order;
mod proposal;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GroupStep {
    Generate(ShortHash),
    Access(Hash),
    Authorize(ShortHash, Hash),
    Announce(ShortHash),
}

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    fn group_step(
        &self,
        source: Source<'id>,
        member: MemberSession<'id>,
        now: u64,
    ) -> Result<Option<(GroupStep, u64)>, Error> {
        let room = self.rooms.get(source.room)?;
        let contact = room.sessions.get(member.slot)?.contact;
        let epoch = room.epochs.get(
            room.find_epoch(&room.current_epoch)
                .ok_or(Fault::NotReady)?,
        )?;
        let next = epoch.groups.iter().find_map(|(_, group)| {
            if !group.valid || group.expires == u64::MAX {
                return None;
            }
            let event = group.proposal?;
            let proposal = room.nodes.get(room.find_node(&event)?).ok()?;
            if !proposal.complete
                || !proposal.semantic_applied
                || proposal.epoch != epoch.hash
                || matches!(
                    proposal.phase,
                    MessagePhase::Deleted | MessagePhase::Rejected
                )
            {
                return None;
            }
            let Body::Group {
                initiator,
                partner,
                timeout,
                ..
            } = proposal.body(&self.frames).ok()?
            else {
                return None;
            };
            let expires = proposal.timestamp.saturating_add(timeout.as_micros());
            if now >= expires || group.expires != expires {
                return None;
            }
            let owner = proposal.auth?.owner?.contact;
            let ours = owner == contact && proposal.local_sent;
            let own_event = if ours { initiator } else { partner };
            let original = room.nodes.get(room.find_node(own_event)?).ok()?;
            if !original.local_sent
                || !original.complete
                || !original.semantic_applied
                || original.auth?.owner?.contact != contact
                || original.epoch != epoch.hash
                || matches!(
                    original.phase,
                    MessagePhase::Deleted | MessagePhase::Rejected
                )
            {
                return None;
            }
            let Body::Announcement {
                identifier: wrapper,
                ..
            } = original.body(&self.frames).ok()?
            else {
                return None;
            };
            if group.phase == KeyPhase::Missing && ours && !room.derivation.pending() {
                return Some((GroupStep::Generate(group.identifier), expires));
            }
            if group.phase != KeyPhase::Present {
                return None;
            }
            let sent = |kind| {
                room.nodes.iter().any(|(_, reply)| {
                    reply.local_sent
                        && reply.kind == kind
                        && reply.epoch == epoch.hash
                        && reply.references[0] == event
                })
            };
            if ours && !sent(Kind::ACCESS) {
                let remote = room.nodes.get(room.find_node(partner)?).ok()?;
                if !remote.semantic_applied
                    || remote.epoch != epoch.hash
                    || matches!(remote.phase, MessagePhase::Deleted | MessagePhase::Rejected)
                {
                    return None;
                }
                let Body::Announcement { timeout, .. } = remote.body(&self.frames).ok()? else {
                    return None;
                };
                let access_until =
                    expires.min(remote.timestamp.saturating_add(timeout.as_micros()));
                return (now < access_until).then_some((GroupStep::Access(event), access_until));
            }
            let wraps = epoch.groups.iter().any(|(_, key)| {
                key.identifier == *wrapper
                    && key.valid
                    && key.phase == KeyPhase::Present
                    && identifier_order(key.identifier_order, wrapper).0
            });
            if wraps && !sent(Kind::AUTHORIZATION) {
                return Some((GroupStep::Authorize(*wrapper, event), expires));
            }
            if !group
                .confirmations
                .iter()
                .any(|c| c.contact == contact && c.verified_mac)
            {
                return Some((GroupStep::Announce(group.identifier), expires));
            }
            None
        });
        Ok(next)
    }

    pub(super) fn drive_groups(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        entropy: &mut impl crypto::Entropy,
        now: u64,
        deadline: u64,
    ) -> Result<Option<Operation<'id>>, Error> {
        let Some((step, expires)) = self.group_step(source, member, now)? else {
            return Ok(None);
        };
        let deadline = deadline.min(expires);
        match step {
            GroupStep::Generate(id) => {
                let epoch = self.rooms.get(source.room)?.current_epoch;
                self.request_shared_key(source, member, epoch, id, now, deadline)
            }
            GroupStep::Access(event) => {
                self.prepare_access(source, member, event, entropy, now, deadline)
            }
            GroupStep::Authorize(wrapper, event) => {
                self.prepare_authorization(source, member, wrapper, event, now, deadline)
            }
            GroupStep::Announce(id) => {
                self.prepare_announcement(source, member, id, expires - now, entropy, now, deadline)
            }
        }
        .map(Some)
    }
}
