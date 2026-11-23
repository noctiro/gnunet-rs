//! Current and explicitly referenced historical announcements use one actual
//! possessed key, original recipient DH key and authenticated signing scope.
use super::*;
impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    /// Prepare a real own ANNOUNCEMENT from a possessed current-epoch key and
    /// the original retained ephemeral recipient public key.
    #[expect(
        clippy::too_many_arguments,
        reason = "Original authority, entropy and deadline are independent"
    )]
    pub fn prepare_announcement(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        id: ShortHash,
        timeout: u64,
        entropy: &mut impl crypto::Entropy,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        let (public, sender) = self.local_sender(source, member)?;
        let row = self.rooms.get(source.room)?;
        let epoch = row.find_epoch(&row.current_epoch).ok_or(Fault::NotReady)?;
        let previous = row.find_node(&row.last_message).ok_or(Fault::NotReady)?;
        if self.verified_key_control_epoch(source.room, previous)? != epoch {
            return Err(Error::AttributionConflict);
        }
        let snapshot = row.epochs.get(epoch)?;
        if !snapshot.complete
            || !row.epoch_has_member(snapshot, row.sessions.get(member.slot)?.contact)
        {
            return Err(Error::Permission);
        }
        let scope = Scope {
            public,
            sender,
            epoch,
            position: SigningPosition {
                previous: row.last_message,
                epoch: row.current_epoch,
            },
        };
        self.announcement_in_scope(source, member, id, scope, timeout, entropy, now, deadline)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Original event, authority, entropy and deadline are independent"
    )]
    pub(crate) fn prepare_announcement_for_event(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        id: ShortHash,
        event: Hash,
        timeout: u64,
        entropy: &mut impl crypto::Entropy,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        let scope = self.key_control_scope(source, member, event)?;
        let row = self.rooms.get(source.room)?;
        let node = row
            .nodes
            .get(row.find_node(&event).ok_or(Fault::NotFound)?)?;
        if !matches!(node.body(&self.frames)?, Body::Announcement { identifier, .. } if *identifier == id)
        {
            return Err(Error::Permission);
        }
        self.announcement_in_scope(source, member, id, scope, timeout, entropy, now, deadline)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Original scope, entropy and deadline are independent"
    )]
    fn announcement_in_scope(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        id: ShortHash,
        scope: Scope,
        timeout: u64,
        entropy: &mut impl crypto::Entropy,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        let epoch = self.rooms.get(source.room)?.epochs.get(scope.epoch)?;
        let (_, group) = epoch
            .groups
            .iter()
            .find(|(_, g)| g.identifier == id && g.valid)
            .ok_or(Fault::NotReady)?;
        let ephemeral = epoch.ephemeral.as_ref().ok_or(Fault::NotReady)?;
        if ephemeral.valid_until <= now {
            return Err(Fault::Timeout.into());
        }
        let public_key = *ephemeral.public.as_bytes();
        let valid_for = timeout.min(ephemeral.valid_until - now);
        let deadline = deadline.min(now + valid_for);
        let timeout = gnunet_wire::official::RelativeTime::from_micros(valid_for);
        let mut nonce = [0; 32];
        entropy.fill(&mut nonce).map_err(|_| Fault::Entropy)?;
        if epoch.nonces.iter().any(|n| n.value == nonce) {
            return Err(Fault::Replay.into());
        }
        let zero = [0; 64];
        let draft = Body::Announcement {
            identifier: &id,
            public_key: &public_key,
            nonce: &nonce,
            timeout,
            hmac: &zero,
        };
        let mac = crypto::group::message_mac(draft, group.key.as_ref().ok_or(Fault::NotReady)?)?;
        self.queue_sign_at(
            source,
            Some(member),
            None,
            scope.public,
            scope.sender,
            Body::Announcement {
                identifier: &id,
                public_key: &public_key,
                nonce: &nonce,
                timeout,
                hmac: &mac,
            },
            scope.position,
            now,
            deadline,
        )
    }
}
