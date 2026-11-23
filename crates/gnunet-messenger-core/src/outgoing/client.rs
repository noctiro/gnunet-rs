//! Client-only signing, key providers and original native operations.

use super::{DraftAuthority, SigningDraft};
use crate::{
    engine::Core,
    graph::{epoch_kind, owns, peer_kind},
    recipient::MemberRecipient,
    state::*,
    *,
};
use gnunet_types::Error as Fault;
use wire::{body::Body, envelope::Kind};

mod composition;
mod providers;

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    #[expect(
        clippy::too_many_arguments,
        reason = "original source, member, crypto workspace and finite deadline remain explicit"
    )]
    fn queue_sign(
        &mut self,
        source: Source<'id>,
        member: Option<MemberSession<'id>>,
        recipient: Option<MemberRecipient>,
        public: PublicKey,
        sender: ShortHash,
        body: Body<'_>,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        self.check_source(source)?;
        let room = self.rooms.get(source.room)?;
        if self.frontier_sync_required(self.event_room(source.room))? {
            return Err(Fault::NotReady.into());
        }
        let position = crate::key_controls::SigningPosition {
            previous: room.last_message,
            epoch: room.current_epoch,
        };
        self.queue_sign_at(
            source, member, recipient, public, sender, body, position, now, deadline,
        )
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Original signing authority, exact causal position and finite lifetime are independent"
    )]
    pub(crate) fn queue_sign_at(
        &mut self,
        source: Source<'id>,
        member: Option<MemberSession<'id>>,
        recipient: Option<MemberRecipient>,
        public: PublicKey,
        sender: ShortHash,
        body: Body<'_>,
        position: crate::key_controls::SigningPosition,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        self.check_signing_draft(source, &public, now, deadline)?;
        let room = self.rooms.get(source.room)?;
        if self.mode != Mode::Client || room.sources.get(source.slot)?.role != SourceRole::Client {
            return Err(Error::Permission);
        }
        let historical = position.epoch != room.current_epoch;
        let bootstrap = self.bootstrap_position(source, member, public, sender, body, &position)?;
        let scope = self.event_room(source.room);
        if self.rooms.get(source.room)?.frontier_control.is_some()
            || self.frontier_sync_in_flight(scope)?
        {
            return Err(Fault::WouldBlock.into());
        }
        if !historical && !bootstrap && self.frontier_sync_required(scope)? {
            return Err(Fault::NotReady.into());
        }
        if historical {
            if !matches!(
                body.kind(),
                Kind::ANNOUNCEMENT | Kind::APPEAL | Kind::ACCESS
            ) {
                return Err(Error::Permission);
            }
            let actual = self.local_sender(source, member.ok_or(Error::Permission)?)?;
            if actual != (public, sender) || position.previous != position.epoch {
                return Err(Error::Permission);
            }
            self.reserve_frontier_scratch(source.room)?;
        }
        let room = self.rooms.get(source.room)?;
        let group_keys = self.group_keys_for_message(room, &position.epoch, body)?;
        if historical {
            if room
                .operations
                .limit()
                .saturating_sub(room.operations.len())
                < 2
            {
                return Err(Fault::Capacity.into());
            }
            if room.operations.iter().any(|(_, operation)| {
                matches!(
                    operation.job,
                    Job::Wire {
                        purpose: NativePurpose::Sync,
                        ..
                    }
                ) && !matches!(
                    operation.phase,
                    OperationPhase::Complete | OperationPhase::Failed | OperationPhase::Cancelled
                )
            }) {
                return Err(Fault::WouldBlock.into());
            }
        }
        let member = self.operation_member_slot(source.room, member)?;
        let (operation, hash) = self.publish_signing_draft(
            source,
            SigningDraft {
                authority: DraftAuthority::Client {
                    member,
                    group_keys,
                    recipient,
                },
                public,
                sender,
                body,
                previous: position.previous,
                epoch: position.epoch,
                now,
                deadline,
            },
        )?;
        if bootstrap {
            self.rooms
                .get_mut(source.room)?
                .sources
                .get_mut(source.slot)?
                .join_operation = Some(operation.slot);
        }
        if historical {
            let row = self.rooms.get_mut(source.room)?;
            row.frontier_base = Some(row.last_message);
            row.frontier_control_hash = Some(hash);
            row.frontier_control = Some(operation.slot);
        }
        Ok(operation)
    }
    /// Prepare a real initial JOIN after actual native member-ID assignment.
    /// The signature provider owns its IDENTITY secret; Core retains no copy.
    pub fn prepare_join(
        &mut self,
        source: Source<'id>,
        hpke: PublicKey,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        if self.mode != Mode::Client {
            return Err(Error::Permission);
        }
        self.check_source(source)?;
        let row = self.rooms.get(source.room)?;
        let s = row.sources.get(source.slot)?;
        if !s.create_written
            || s.role != SourceRole::Client
            || !matches!(row.phase, RoomPhase::Open | RoomPhase::Entered)
            || self.source_joined(source)?
        {
            return Err(Fault::NotReady.into());
        }
        if row.operations.iter().any(|(_, operation)| {
            operation.binding.source == source.slot
                && operation.signed_kind == Some(Kind::JOIN)
                && !matches!(
                    operation.phase,
                    OperationPhase::Complete | OperationPhase::Failed | OperationPhase::Cancelled
                )
        }) {
            return Err(Fault::WouldBlock.into());
        }
        let public = row.local_public.ok_or(Fault::NotReady)?;
        let sender = s.member_id.ok_or(Fault::NotReady)?;
        let epoch = row.current_epoch;
        let position = crate::key_controls::SigningPosition {
            previous: row.last_message,
            epoch,
        };
        self.queue_sign_at(
            source,
            None,
            None,
            public,
            sender,
            Body::Join {
                epoch: &epoch,
                public_key: wire::PublicKey::new(&public)?,
                hpke_key: wire::keys::HpkePublicKey::new(&hpke)?,
            },
            position,
            now,
            deadline,
        )
    }
    /// Prepare an actual member-owned message. Service/peer-generated kinds
    /// require their separate actual signer port. Key-transfer producers should
    /// use the dedicated preparation methods to bind actual possessed keys.
    /// Key controls require their original epoch, groups and event references.
    pub fn prepare_send(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        body: Body<'_>,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        let (public, sender) = self.local_sender(source, member)?;
        let row = self.rooms.get(source.room)?;
        let session = row.sessions.get(member.slot)?;
        if peer_kind(body.kind())
            || matches!(
                body,
                Body::Join { .. } | Body::Private { .. } | Body::Secret { .. }
            )
        {
            return Err(Error::Permission);
        }
        if let Body::Deletion { hash, .. } = body {
            let target = row.nodes.get(row.find_node(hash).ok_or(Fault::NotFound)?)?;
            if epoch_kind(target.kind) || !owns(session, target) {
                return Err(Error::Permission);
            }
        }
        if let Body::Group {
            identifier,
            initiator,
            partner,
            ..
        } = body
        {
            let (group, level) = crate::epoch::identifier_order(self.profile.endian, identifier);
            if !group {
                return Err(Fault::InvalidInput.into());
            }
            let epoch = row.find_epoch(&row.current_epoch).ok_or(Fault::NotReady)?;
            if row.group_proposal_position(epoch, identifier).is_ok() {
                return Err(Fault::Conflict.into());
            }
            let parents = [
                row.find_node(initiator).ok_or(Fault::NotReady)?,
                row.find_node(partner).ok_or(Fault::NotReady)?,
            ];
            self.check_group_parents(source.room, epoch, level, parents, session.contact)?;
        }
        self.queue_sign(
            source,
            Some(member),
            None,
            public,
            sender,
            body,
            now,
            deadline,
        )
    }
    /// Prepare a member-signed REQUEST after the original local GET completed
    /// with Missing. Only a retained causal dependency may use the reserved
    /// recovery credit while the ordinary send frontier is unsettled.
    pub fn prepare_history_request(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        hash: Hash,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        self.check_source(source)?;
        if hash == [0; 64] {
            return Err(Fault::InvalidInput.into());
        }
        let room = self.rooms.get(source.room)?;
        let required = room.missing.iter().find_map(|(_, missing)| {
            (missing.source == source.slot && missing.hash == hash).then_some(missing)
        });
        if let Some(required) = required {
            if !required.absent || deadline > required.retry_at {
                return Err(Fault::NotReady.into());
            }
            return self.queue_history_recovery(source, member, hash, now, deadline);
        }
        self.prepare_send(source, member, Body::Request { hash: &hash }, now, deadline)
    }

    /// Prepare a REQUEST for a proactive Missing notice from the trusted
    /// native service. The caller must attribute and deduplicate the notice on
    /// the original live room connection. This grants no GET completion or
    /// absence, and does not change the authenticated frontier.
    pub fn prepare_notified_history_request(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        hash: Hash,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        self.queue_history_recovery(source, member, hash, now, deadline)
    }

    fn queue_history_recovery(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        hash: Hash,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        if hash == [0; 64] {
            return Err(Fault::InvalidInput.into());
        }
        let (public, sender) = self.local_sender(source, member)?;
        self.check_signing_draft(source, &public, now, deadline)?;
        let room = self.rooms.get(source.room)?;
        let session = room.sessions.get(member.slot)?;
        // REQUEST never participates in frontier reconciliation. Its fallback
        // predecessor is the member's authenticated bound original, never a
        // raw SYNC/ENTRY cursor or an unavailable branch chosen by the caller.
        let (previous, epoch) = if self.frontier_sync_required(self.event_room(source.room))? {
            let node = room
                .nodes
                .get(room.find_node(&session.last_bound).ok_or(Fault::NotReady)?)?;
            if !node.semantic_applied || !node.epoch_indexed || !owns(session, node) {
                return Err(Fault::NotReady.into());
            }
            (node.hash, node.epoch)
        } else {
            (room.last_message, room.current_epoch)
        };
        self.publish_signing_draft(
            source,
            SigningDraft {
                authority: DraftAuthority::HistoryRequest {
                    member: member.slot,
                },
                public,
                sender,
                body: Body::Request { hash: &hash },
                previous,
                epoch,
                now,
                deadline,
            },
        )
        .map(|(operation, _)| operation)
    }
    /// Actual LEAVE is signed first. A CLOSE remains a distinct native operation
    /// and may be submitted by close() after the real echoed LEAVE is applied.
    pub fn prepare_leave(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        let epoch = self.rooms.get(source.room)?.current_epoch;
        self.prepare_send(source, member, Body::Leave { epoch: &epoch }, now, deadline)
    }
    /// Request an actual missing original message. An absence is only recorded
    /// after its original Written GET receives the real matching Missing frame.
    pub fn request_missing(
        &mut self,
        source: Source<'id>,
        hash: Hash,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        self.check_source(source)?;
        if now >= deadline {
            return Err(Fault::Timeout.into());
        }
        let row = self.rooms.get(source.room)?;
        if row.sources.get(source.slot)?.role != SourceRole::Client
            || !row.sources.get(source.slot)?.create_written
        {
            return Err(Error::Permission);
        }
        // Response attribution requires Written, but admission deduplication
        // covers the original GET before native writing as well. Optional
        // history and required protocol retrieval can observe the same hash.
        if row.operations.iter().any(|(_, operation)| {
            operation.binding.source == source.slot
                && operation.binding.message == hash
                && matches!(
                    operation.job,
                    Job::Wire {
                        purpose: NativePurpose::Get,
                        ..
                    }
                )
                && !matches!(
                    operation.phase,
                    OperationPhase::Complete | OperationPhase::Failed | OperationPhase::Cancelled
                )
        }) {
            return Err(Fault::WouldBlock.into());
        }
        let key = row.key;
        let op = self.queue_wire(
            source,
            NativePurpose::Get,
            wire::Request::Get {
                key: &key,
                hash: &hash,
            },
            None,
            hash,
            deadline,
        )?;
        if let Some((_, m)) = self
            .rooms
            .get_mut(source.room)?
            .missing
            .iter_mut()
            .find(|(_, m)| m.hash == hash && m.source == source.slot)
        {
            m.operation = Some(op.slot);
            m.absent = false;
            if m.retry_at == 0 {
                m.retry_at = deadline;
            }
        }
        Ok(op)
    }
    pub(crate) fn local_sender(
        &self,
        source: Source<'id>,
        member: MemberSession<'id>,
    ) -> Result<(PublicKey, ShortHash), Error> {
        if self.mode != Mode::Client {
            return Err(Error::Permission);
        }
        self.check_source(source)?;
        self.check_member(member)?;
        if source.room != member.room {
            return Err(Error::Permission);
        }
        let row = self.rooms.get(source.room)?;
        let m = row.sessions.get(member.slot)?;
        let s = row.sources.get(source.slot)?;
        if s.join_required {
            return Err(Fault::NotReady.into());
        }
        if s.role != SourceRole::Client
            || !s.create_written
            || m.phase != SessionPhase::Active
            || s.member_id != Some(m.id)
            || row.local_public != Some(m.public)
            || !self.contacts.get(m.contact)?.local
        {
            return Err(Error::Permission);
        }
        Ok((m.public, m.id))
    }
    /// Withdraw this client room's local renewal timers when a higher owner
    /// drives its logical subscription intent. Signed interval/history facts and
    /// all already admitted operations remain untouched, including old SENDs.
    pub fn pause_subscription_renewals(&mut self, source: Source<'id>) -> Result<(), Error> {
        self.check_source(source)?;
        if self.mode != Mode::Client {
            return Err(Error::Permission);
        }
        for (_, subscription) in self.rooms.get_mut(source.room)?.subscriptions.iter_mut() {
            subscription.keep_alive = false;
            subscription.renew_at = None;
        }
        Ok(())
    }
    /// Continue the actual native member-ID notification: initial/reset needs a
    /// real JOIN with the advertised HPKE key; a collision needs ID(new) signed
    /// with the original old member ID and current authorized signing key.
    pub fn prepare_assigned_identity(
        &mut self,
        source: Source<'id>,
        hpke: PublicKey,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        self.check_source(source)?;
        let row = self.rooms.get(source.room)?;
        let s = row.sources.get(source.slot)?;
        if row.operations.iter().any(|(_, o)| {
            o.binding.source == source.slot
                && matches!(o.signed_kind, Some(Kind::JOIN | Kind::ID))
                && !matches!(
                    o.phase,
                    OperationPhase::Complete | OperationPhase::Failed | OperationPhase::Cancelled
                )
        }) {
            return Err(Fault::WouldBlock.into());
        }
        if s.join_required {
            return self.prepare_join(source, hpke, now, deadline);
        }
        let id = s.pending_member_id.ok_or(Fault::NotReady)?;
        let member = self.member_id(source.room, row.local_session().ok_or(Fault::NotReady)?);
        self.prepare_send(source, member, Body::Id { id: &id }, now, deadline)
    }
}
