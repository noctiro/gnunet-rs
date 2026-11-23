//! One real historical key-control action per driver turn. Selection scans only
//! the room's fixed message/group tables and never generates a new old key.
use super::*;
use wire::envelope::Kind;

enum Recovery {
    Access(Hash),
    Appeal(Hash),
    Announce(ShortHash, Hash),
}
impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    pub(crate) fn drive_historical_keys(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        entropy: &mut impl crypto::Entropy,
        now: u64,
        deadline: u64,
    ) -> Result<Option<Operation<'id>>, Error> {
        let row = self.rooms.get(source.room)?;
        let local = row.sessions.get(member.slot)?.contact;
        let selected = row.nodes.iter().find_map(|(_, node)| {
            if node.epoch == row.current_epoch
                || node.auth.is_none()
                || matches!(node.phase, MessagePhase::Deleted | MessagePhase::Rejected)
            {
                return None;
            }
            let epoch = row.epochs.get(row.find_epoch(&node.epoch)?).ok()?;
            let sender = node.auth?.owner?.contact;
            if !epoch.complete
                || !row.epoch_has_member(epoch, local)
                || !row.epoch_has_member(epoch, sender)
            {
                return None;
            }
            let action = if node.semantic_applied
                && node.semantic_kind == Kind::APPEAL
                && !node.local_sent
            {
                if row.nodes.iter().any(|(_, reply)| {
                    reply.local_sent
                        && reply.semantic_kind == Kind::ACCESS
                        && reply.references[0] == node.hash
                }) {
                    return None;
                }
                let Body::Appeal { event, .. } = node.body(&self.frames).ok()? else {
                    return None;
                };
                let original = row.nodes.get(row.find_node(event)?).ok()?;
                if original.auth.is_none()
                    || !original.complete
                    || !original.semantic_applied
                    || original.epoch != epoch.hash
                {
                    return None;
                }
                let Body::Announcement { identifier, .. } = original.body(&self.frames).ok()?
                else {
                    return None;
                };
                if !epoch.groups.iter().any(|(_, group)| {
                    group.identifier == *identifier
                        && group.valid
                        && group.phase == KeyPhase::Present
                        && group.key.is_some()
                        && !crate::epoch::identifier_order(group.identifier_order, identifier).0
                        && group
                            .confirmations
                            .iter()
                            .any(|c| c.contact == local && c.verified_mac)
                }) {
                    return None;
                }
                Recovery::Access(node.hash)
            } else if node.semantic_applied && node.semantic_kind == Kind::APPEAL && node.local_sent
            {
                let Body::Appeal { event, .. } = node.body(&self.frames).ok()? else {
                    return None;
                };
                let original = row.nodes.get(row.find_node(event)?).ok()?;
                if !original.complete
                    || !original.semantic_applied
                    || original.auth.is_none()
                    || original.epoch != epoch.hash
                {
                    return None;
                }
                let Body::Announcement { identifier, .. } = original.body(&self.frames).ok()?
                else {
                    return None;
                };
                let (_, group) = epoch.groups.iter().find(|(_, group)| {
                    group.identifier == *identifier
                        && group.valid
                        && group.key.is_some()
                        && group.appeal == Some(node.hash)
                })?;
                if group
                    .confirmations
                    .iter()
                    .any(|confirmation| confirmation.contact == local && confirmation.verified_mac)
                {
                    return None;
                }
                Recovery::Announce(*identifier, *event)
            } else if node.kind == Kind::SECRET
                && node.phase == MessagePhase::AwaitingEpoch
                && node.plaintext.is_none()
            {
                let Body::Secret { identifier, .. } = node.message(&self.frames).ok()?.body()
                else {
                    return None;
                };
                let (_, group) = epoch
                    .groups
                    .iter()
                    .find(|(_, group)| group.identifier == *identifier && group.valid)?;
                if crate::epoch::identifier_order(group.identifier_order, identifier).0 {
                    return None;
                }
                let event = group.confirmations.iter().find_map(|confirmation| {
                    row.nodes
                        .get(row.find_node(&confirmation.message)?)
                        .ok()
                        .filter(|original| {
                            original.auth.is_some()
                                && original.complete
                                && original.semantic_applied
                        })
                        .map(|_| confirmation.message)
                })?;
                if group.key.is_none() && group.appeal.is_none() {
                    Recovery::Appeal(event)
                } else if group.key.is_some()
                    && !group
                        .confirmations
                        .iter()
                        .any(|c| c.contact == local && c.verified_mac)
                {
                    Recovery::Announce(*identifier, event)
                } else {
                    return None;
                }
            } else {
                return None;
            };
            Some((epoch.hash, action))
        });
        let Some((epoch_hash, action)) = selected else {
            return Ok(None);
        };
        if row.operations.iter().any(|(_, operation)| {
            operation.binding.source == source.slot
                && operation.binding.epoch == epoch_hash
                && !matches!(
                    operation.phase,
                    OperationPhase::Complete | OperationPhase::Failed | OperationPhase::Cancelled
                )
        }) {
            return Ok(None);
        }
        if !matches!(action, Recovery::Access(_)) {
            let epoch = row
                .epochs
                .get(row.find_epoch(&epoch_hash).ok_or(Fault::NotReady)?)?;
            if epoch.ephemeral_at(now).is_none() {
                let until = now.checked_add(60_000_000).ok_or(Fault::Overflow)?;
                return self
                    .request_ephemeral_key(source, member, epoch_hash, until, now, deadline)
                    .map(Some);
            }
        }
        match action {
            Recovery::Access(event) => {
                self.prepare_access(source, member, event, entropy, now, deadline)
            }
            Recovery::Appeal(event) => {
                self.prepare_appeal(source, member, event, 60_000_000, now, deadline)
            }
            Recovery::Announce(id, event) => self.prepare_announcement_for_event(
                source, member, id, event, 60_000_000, entropy, now, deadline,
            ),
        }
        .map(Some)
    }
}
