//! Typed key-control drafts preserve the actual epoch branch. Historical key
//! recovery never re-labels an old key with the latest frontier's epoch.
use crate::{engine::Core, *};
use gnunet_types::Error as Fault;
use wire::body::Body;
mod announcement;
mod recovery;

pub(crate) struct SigningPosition {
    pub previous: Hash,
    pub epoch: Hash,
}
struct Scope {
    public: PublicKey,
    sender: ShortHash,
    epoch: Slot,
    position: SigningPosition,
}
impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    /// Verify the carried epoch against the original authenticated predecessor
    /// chain, not native epoch metadata alone. The room's fixed node table is
    /// the finite walk bound; no recursion, allocation or epoch fallback exists.
    pub(crate) fn verified_key_control_epoch(&self, r: Slot, start: Slot) -> Result<Slot, Error> {
        let row = self.rooms.get(r)?;
        let target = row.nodes.get(start)?.epoch;
        let epoch = row.find_epoch(&target).ok_or(Fault::NotReady)?;
        if !row.epochs.get(epoch)?.complete {
            return Err(Fault::NotReady.into());
        }
        let mut at = start;
        for _ in 0..row.nodes.limit() {
            let node = row.nodes.get(at)?;
            if node.auth.is_none() || !node.complete {
                return Err(Fault::NotReady.into());
            }
            if node.epoch != target {
                return Err(Error::AttributionConflict);
            }
            if node.hash == target {
                if !crate::graph::epoch_kind(node.kind) || !node.semantic_applied {
                    return Err(Error::AttributionConflict);
                }
                return Ok(epoch);
            }
            if crate::graph::epoch_kind(node.kind)
                && !matches!(node.body(&self.frames)?, Body::Merge { first_epoch, second_epoch, .. }
                    if *first_epoch == target && *second_epoch == target)
            {
                return Err(Error::AttributionConflict);
            }
            at = row.find_node(&node.parents[0]).ok_or(Fault::NotReady)?;
        }
        Err(Fault::Malformed.into())
    }
    fn key_control_scope(
        &self,
        source: Source<'id>,
        member: MemberSession<'id>,
        event: Hash,
    ) -> Result<Scope, Error> {
        let (public, sender) = self.local_sender(source, member)?;
        let row = self.rooms.get(source.room)?;
        let slot = row.find_node(&event).ok_or(Fault::NotFound)?;
        let node = row.nodes.get(slot)?;
        if node.auth.is_none()
            || matches!(node.phase, MessagePhase::Deleted | MessagePhase::Rejected)
        {
            return Err(Error::Permission);
        }
        if !node.complete || !node.semantic_applied {
            return Err(Fault::NotReady.into());
        }
        self.verified_key_control_epoch(source.room, slot)?;
        // Both the original sender and current local contact must actually
        // belong to this exact immutable epoch; current membership is no proxy.
        let epoch = self.available_epoch(source.room, slot)?;
        if node.epoch != row.current_epoch {
            let original = row
                .nodes
                .get(row.find_node(&node.epoch).ok_or(Fault::NotReady)?)?;
            if original.auth.is_none()
                || !original.complete
                || !original.semantic_applied
                || !crate::graph::epoch_kind(original.kind)
                || matches!(
                    original.phase,
                    MessagePhase::Deleted | MessagePhase::Rejected
                )
            {
                return Err(Error::Permission);
            }
        }
        if node.epoch == row.current_epoch {
            let previous = row.find_node(&row.last_message).ok_or(Fault::NotReady)?;
            if self.verified_key_control_epoch(source.room, previous)? != epoch {
                return Err(Error::AttributionConflict);
            }
        }
        let position = SigningPosition {
            previous: if node.epoch == row.current_epoch {
                row.last_message
            } else {
                node.epoch
            },
            epoch: node.epoch,
        };
        Ok(Scope {
            public,
            sender,
            epoch,
            position,
        })
    }
    /// Prepare an appeal bound to an authenticated announcement and this
    /// member's original ephemeral key in that announcement's exact epoch.
    pub fn prepare_appeal(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        event: Hash,
        timeout: u64,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        let scope = self.key_control_scope(source, member, event)?;
        let row = self.rooms.get(source.room)?;
        let node = row
            .nodes
            .get(row.find_node(&event).ok_or(Fault::NotFound)?)?;
        if !matches!(node.body(&self.frames)?, Body::Announcement { identifier, .. } if !self.identifier_bits(source.room, identifier)?.0)
        {
            return Err(Error::Permission);
        }
        let epoch = row.epochs.get(scope.epoch)?;
        let ephemeral = epoch.ephemeral_at(now).ok_or(Fault::Timeout)?;
        let public_key = *ephemeral.public.as_bytes();
        self.queue_sign_at(
            source,
            Some(member),
            None,
            scope.public,
            scope.sender,
            Body::Appeal {
                event: &event,
                public_key: &public_key,
                timeout: gnunet_wire::official::RelativeTime::from_micros(
                    timeout.min(ephemeral.valid_until - now),
                ),
            },
            scope.position,
            now,
            deadline,
        )
    }
    /// Real ACCESS response to an authenticated original appeal or own group
    /// proposal. Recipient and epoch come from that exact retained event.
    pub fn prepare_access(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        event: Hash,
        entropy: &mut impl crypto::Entropy,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        let scope = self.key_control_scope(source, member, event)?;
        let row = self.rooms.get(source.room)?;
        let node = row
            .nodes
            .get(row.find_node(&event).ok_or(Fault::NotFound)?)?;
        let epoch = row.epochs.get(scope.epoch)?;
        let contact = row.sessions.get(member.slot)?.contact;
        let mut deadline = deadline;
        let (id, recipient) = match node.body(&self.frames)? {
            Body::Appeal {
                event, public_key, ..
            } => {
                let original = row
                    .nodes
                    .get(row.find_node(event).ok_or(Fault::NotReady)?)?;
                let Body::Announcement { identifier, .. } = original.body(&self.frames)? else {
                    return Err(Fault::Malformed.into());
                };
                if original.auth.is_none()
                    || !original.complete
                    || !original.semantic_applied
                    || matches!(
                        original.phase,
                        MessagePhase::Deleted | MessagePhase::Rejected
                    )
                    || original.epoch != node.epoch
                    || !epoch.groups.iter().any(|(_, g)| {
                        g.identifier == *identifier
                            && g.confirmations.iter().any(|c| c.message == *event)
                    })
                {
                    return Err(Error::Permission);
                }
                self.verified_key_control_epoch(
                    source.room,
                    row.find_node(event).ok_or(Fault::NotReady)?,
                )?;
                (*identifier, *public_key)
            }
            Body::Group {
                identifier,
                partner,
                ..
            } => {
                if !node.local_sent
                    || node.auth.and_then(|a| a.owner).map(|o| o.contact) != Some(contact)
                {
                    return Err(Error::Permission);
                }
                deadline = deadline.min(self.group_proposal_deadline(
                    source.room,
                    scope.epoch,
                    *identifier,
                    event,
                )?);
                if now >= deadline {
                    return Err(Fault::Timeout.into());
                }
                let partner = row
                    .nodes
                    .get(row.find_node(partner).ok_or(Fault::NotReady)?)?;
                let Body::Announcement {
                    public_key,
                    timeout,
                    ..
                } = partner.body(&self.frames)?
                else {
                    return Err(Fault::Malformed.into());
                };
                deadline = deadline.min(partner.timestamp.saturating_add(timeout.as_micros()));
                if now >= deadline {
                    return Err(Fault::Timeout.into());
                }
                if partner.auth.is_none()
                    || !partner.complete
                    || !partner.semantic_applied
                    || matches!(
                        partner.phase,
                        MessagePhase::Deleted | MessagePhase::Rejected
                    )
                    || partner.epoch != node.epoch
                {
                    return Err(Error::Permission);
                }
                self.verified_key_control_epoch(
                    source.room,
                    row.find_node(&partner.hash).ok_or(Fault::NotReady)?,
                )?;
                (*identifier, *public_key)
            }
            _ => return Err(Fault::InvalidInput.into()),
        };
        let (_, group) = epoch
            .groups
            .iter()
            .find(|(_, g)| g.identifier == id && g.valid && g.phase == KeyPhase::Present)
            .ok_or(Fault::NotReady)?;
        if !crate::epoch::identifier_order(group.identifier_order, &id).0
            && !group
                .confirmations
                .iter()
                .any(|c| c.contact == contact && c.verified_mac)
        {
            return Err(Error::Permission);
        }
        let access = crypto::group::Access::seal(
            &event,
            crypto::EcdhePublic::from_bytes(recipient),
            group.key.as_ref().ok_or(Fault::NotReady)?,
            entropy,
        )?;
        self.queue_sign_at(
            source,
            Some(member),
            None,
            scope.public,
            scope.sender,
            access.body(),
            scope.position,
            now,
            deadline,
        )
    }
}
