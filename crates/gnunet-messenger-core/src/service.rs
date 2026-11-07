//! Hosted SERVICE facts and signed local provider leases. These hooks do not
//! manufacture transport, signatures, membership or client-side notifications.
use crate::{engine::Core, state::*, *};
use gnunet_crypto::hash512;
use gnunet_types::Error as Fault;
/// Read-only current graph frontier for actual daemon IPC responses; this is
/// local state metadata, not a transport/publication acknowledgement.
#[derive(Clone, Copy)]
pub struct ServiceState {
    /// Actual original most recent chain frontier.
    pub previous: Hash,
    /// Actual current epoch selected by admitted semantics.
    pub epoch: Hash,
}
impl core::fmt::Debug for ServiceState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ServiceState([REDACTED])")
    }
}
/// Actual signature-attributed original-message routing metadata. It exposes no
/// secret or mutable authentication constructor; ordinary fields are not proof.
#[derive(Clone, Copy)]
pub struct ServiceAttribution<'id> {
    /// Exact original source.
    pub source: Option<Source<'id>>,
    /// Hash of the actual original signer snapshot (not current Contact.key).
    pub sender: Hash,
    /// Latest successor context, or the actual peer sender hash.
    pub context: Hash,
    /// Actual sender's original member session if any.
    pub member: Option<MemberSession<'id>>,
    /// The actual message is a peer-signed kind.
    pub peer: bool,
    /// Actual admitted node epoch.
    pub epoch: Hash,
}
impl core::fmt::Debug for ServiceAttribution<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ServiceAttribution([REDACTED])")
    }
}
impl<'id> Core<'id> {
    pub(crate) fn check_service_role(&self, role: SourceRole) -> Result<(), Error> {
        if let SourceRole::ServiceSigner(peer) = role
            && (self.mode != Mode::Service || self.local_peer != Some(peer))
        {
            return Err(Error::Permission);
        }
        Ok(())
    }
    /// Bind the native daemon's actual initial per-handle OPEN/ENTRY principal
    /// and freshly assigned/reused member ID. Caller must already own the exact
    /// accepted app source and real assignment; this is not signature admission.
    /// Existing active assignments cannot be rebound. Actual verified KEY/ID
    /// messages remain the only transition to another established principal/id.
    /// Equal ID/public aliases are allowed, matching the official service reuse;
    /// an ID retained by another current principal is refused. Historical
    /// predecessor/completed sessions cannot block an authenticated KEY rejoin.
    pub fn bind_service_client(
        &mut self,
        source: Source<'id>,
        public: PublicKey,
        id: ShortHash,
    ) -> Result<(), Error> {
        self.check_source(source)?;
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        wire::PublicKey::new(&public)?;
        let room = self.rooms.get(source.room)?;
        let row = room.sources.get(source.slot)?;
        if row.role != SourceRole::Client || row.public.is_some_and(|p| p != public) {
            return Err(Error::Permission);
        }
        if let Some(old) = row.member_id {
            return if old == id && row.public == Some(public) {
                Ok(())
            } else {
                Err(Error::Permission)
            };
        }
        if room
            .nodes
            .iter()
            .any(|(_, n)| n.origin.live() == Some(source))
        {
            return Err(Fault::NotReady.into());
        }
        if room.sources.iter().any(|(slot, s)| {
            slot != source.slot && s.member_id == Some(id) && s.public != Some(public)
        }) || room.sessions.iter().any(|(_, s)| {
            s.id == id
                && s.public != public
                && s.phase != SessionPhase::Completed
                && s.successor.is_none()
        }) {
            return Err(Fault::Conflict.into());
        }
        let row = self
            .rooms
            .get_mut(source.room)?
            .sources
            .get_mut(source.slot)?;
        row.public = Some(public);
        row.member_id = Some(id);
        Ok(())
    }
    /// Actual current per-room client assignment, after authenticated rotations.
    /// Read-only metadata cannot grant a source or change its principal.
    pub fn service_client(&self, source: Source<'id>) -> Result<(PublicKey, ShortHash), Error> {
        self.check_source(source)?;
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        let row = self.rooms.get(source.room)?.sources.get(source.slot)?;
        if row.role != SourceRole::Client {
            return Err(Error::Permission);
        }
        Ok((
            row.public.ok_or(Fault::NotReady)?,
            row.member_id.ok_or(Fault::NotReady)?,
        ))
    }
    /// Actual daemon collision allocator may propose another ID for the same
    /// live principal. This changes no current sender/authority until the real
    /// signed ID message is verified and applied by Core.
    pub fn propose_service_client_id(
        &mut self,
        source: Source<'id>,
        id: ShortHash,
    ) -> Result<(), Error> {
        let (public, old) = self.service_client(source)?;
        if old == id {
            return Err(Fault::Replay.into());
        }
        let room = self.rooms.get(source.room)?;
        if room
            .sources
            .iter()
            .any(|(_, s)| s.member_id == Some(id) && s.public != Some(public))
            || room.sessions.iter().any(|(_, s)| {
                s.id == id
                    && s.public != public
                    && s.phase != SessionPhase::Completed
                    && s.successor.is_none()
            })
        {
            return Err(Fault::Conflict.into());
        }
        let row = self
            .rooms
            .get_mut(source.room)?
            .sources
            .get_mut(source.slot)?;
        if row.pending_member_id.is_some_and(|p| p != id) {
            return Err(Fault::WouldBlock.into());
        }
        row.pending_member_id = Some(id);
        Ok(())
    }
    /// Read current authentic state to encode actual OPEN/ENTRY/SYNC responses.
    /// Calling it does not pretend the daemon received its own client response.
    pub fn service_state(&self, room: Room<'id>) -> Result<ServiceState, Error> {
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        let row = self.rooms.get(self.check_room(room)?)?;
        Ok(ServiceState {
            previous: row.last_message,
            epoch: row.current_epoch,
        })
    }
    /// Exact original auth snapshot, with bounded successor traversal. It works
    /// for verified opaque PRIVATE/SECRET outer messages without decrypting them.
    /// Unknown/awaiting signatures remain NotReady and cannot be relayed as verified.
    pub fn service_attribution(
        &self,
        room: Room<'id>,
        hash: &Hash,
    ) -> Result<ServiceAttribution<'id>, Error> {
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        let r = self.check_room(room)?;
        let row = self.rooms.get(r)?;
        let node = row.nodes.get(row.find_node(hash).ok_or(Fault::NotFound)?)?;
        let auth = node.auth.ok_or(Fault::NotReady)?;
        if !node.epoch_indexed {
            return Err(Fault::NotReady.into());
        }
        if let Some(peer) = auth.peer {
            let sender = hash512(&peer);
            return Ok(ServiceAttribution {
                source: node.origin.live(),
                sender,
                context: sender,
                member: None,
                peer: true,
                epoch: node.epoch,
            });
        }
        let original = auth.session.ok_or(Fault::NotReady)?;
        let mut latest = original;
        let mut ended = false;
        for _ in 0..self.limits.sessions_per_room {
            match row.sessions.get(latest)?.successor {
                Some(next) => latest = next,
                None => {
                    ended = true;
                    break;
                }
            }
        }
        if !ended {
            return Err(Fault::Malformed.into());
        }
        let id = row.sessions.get(latest)?.id;
        let digest = hash512(&id);
        let mut context = row.key;
        for (value, part) in context.iter_mut().zip(digest) {
            *value ^= part;
        }
        Ok(ServiceAttribution {
            source: node.origin.live(),
            sender: hash512(&auth.public),
            context,
            member: Some(self.member_id(r, original)),
            peer: false,
            epoch: node.epoch,
        })
    }
    /// Whether a local client has this authentic original message's history
    /// right. No current Contact.key is substituted for an old author snapshot.
    pub fn service_may_read(&self, source: Source<'id>, hash: &Hash) -> Result<bool, Error> {
        let (public, id) = self.service_client(source)?;
        let row = self.rooms.get(source.room)?;
        let node = row.nodes.get(row.find_node(hash).ok_or(Fault::NotFound)?)?;
        let current = row.sessions.iter().find_map(|(_, m)| {
            (m.public == public && m.id == id && m.phase != SessionPhase::Completed && !m.archived)
                .then_some(m)
        });
        let Some(current) = current else {
            return Ok(false);
        };
        Ok(crate::graph::epoch_kind(node.kind)
            || row.sessions.iter().any(|(_, old)| {
                old.contact == current.contact
                    && old.lineage == current.lineage
                    && old.generation <= current.generation
                    && crate::graph::known(old, node)
            }))
    }
    /// Authorize an actual peer REQUEST's original verified member session
    /// against the requested retained original node. This is only a history
    /// read decision, never a source or signature constructor.
    pub fn service_request_may_read(
        &self,
        room: Room<'id>,
        request: &Hash,
        target: &Hash,
    ) -> Result<bool, Error> {
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        let row = self.rooms.get(self.check_room(room)?)?;
        let req = row
            .nodes
            .get(row.find_node(request).ok_or(Fault::NotFound)?)?;
        if req.kind != wire::envelope::Kind::REQUEST {
            return Err(Error::Permission);
        }
        if !matches!(req.body(self.profile)?, wire::body::Body::Request { hash } if hash == target)
        {
            return Err(Error::AttributionConflict);
        }
        let member = req.auth.and_then(|a| a.session).ok_or(Fault::NotReady)?;
        let node = row
            .nodes
            .get(row.find_node(target).ok_or(Fault::NotFound)?)?;
        Ok(crate::graph::epoch_kind(node.kind)
            || crate::graph::known(row.sessions.get(member)?, node))
    }
    /// Release a local room's signer lease after its original PILS jobs actually
    /// quiesced and every corresponding Core operation has been retired. This
    /// ends a scoped room lease; it is not source_stopped on the shared PILS MQ.
    /// The caller must perform/retain original physical retirement independently.
    pub fn release_service_signer(&mut self, source: Source<'id>) -> Result<(), Error> {
        self.check_source(source)?;
        let room = self.rooms.get(source.room)?;
        if self.mode != Mode::Service
            || !matches!(
                room.sources.get(source.slot)?.role,
                SourceRole::ServiceSigner(_)
            )
        {
            return Err(Error::Permission);
        }
        if room
            .operations
            .iter()
            .any(|(_, o)| o.binding.source == source)
        {
            return Err(Fault::NotReady.into());
        }
        self.rooms
            .get_mut(source.room)?
            .sources
            .remove(source.slot)?;
        Ok(())
    }
    /// Current authentic active member for this actual per-room client source.
    /// Local assignment alone is not membership; None remains until JOIN applies.
    pub fn service_member(&self, source: Source<'id>) -> Result<Option<MemberSession<'id>>, Error> {
        let (public, id) = self.service_client(source)?;
        let room = self.rooms.get(source.room)?;
        let mut selected = None;
        for (slot, m) in room.sessions.iter() {
            if m.public == public
                && m.id == id
                && m.phase == SessionPhase::Active
                && m.successor.is_none()
            {
                if selected.is_some() {
                    return Err(Fault::Conflict.into());
                }
                selected = Some(self.member_id(source.room, slot));
            }
        }
        Ok(selected)
    }
    /// Actual current-session sender relation for the official SENT flag.
    /// Historical ownership and current Contact aliases do not manufacture it.
    pub fn service_is_sender(&self, source: Source<'id>, hash: &Hash) -> Result<bool, Error> {
        let Some(member) = self.service_member(source)? else {
            return Ok(false);
        };
        let room = self.rooms.get(source.room)?;
        let node = room
            .nodes
            .get(room.find_node(hash).ok_or(Fault::NotFound)?)?;
        Ok(node
            .auth
            .is_some_and(|a| a.peer.is_none() && a.session == Some(member.slot)))
    }
    /// Commit only the private original Wire frame produced by a successful
    /// complete_signature for this same local signer Binding. No input bytes
    /// or transport notification can be injected through this entry point.
    /// This is an actual verified local state commit, not Written/remote delivery.
    /// The native relay separately owns all actual app/CADET output attempts.
    pub fn service_commit_signature(
        &mut self,
        binding: Binding<'id>,
        now: u64,
    ) -> Result<Hash, Error> {
        self.check_source(binding.source)?;
        let op = self.check_binding(binding)?;
        let role = self
            .rooms
            .get(binding.source.room)?
            .sources
            .get(binding.source.slot)?
            .role;
        if self.mode != Mode::Service
            || !matches!(role,SourceRole::ServiceSigner(p) if self.local_peer==Some(p))
        {
            return Err(Error::Permission);
        }
        if op.phase != OperationPhase::Prepared || op.deadline <= now {
            return Err(Fault::StaleGeneration.into());
        }
        if !matches!(
            &op.job,
            Job::Wire {
                purpose: NativePurpose::Send,
                encoding: Encoding::PeerMessage,
                frame: Some(_),
                ..
            }
        ) {
            return Err(Fault::NotReady.into());
        }
        self.reserve_events(3)?;
        let (input, charge) = {
            let op = self
                .rooms
                .get_mut(binding.source.room)?
                .operations
                .get_mut(binding.operation.slot)?;
            let Job::Wire { frame, .. } = &mut op.job else {
                return Err(Fault::Conflict.into());
            };
            let input = frame.take().ok_or(Fault::NotReady)?;
            let charge = op.charged_bytes;
            op.charged_bytes = 0;
            (input, charge)
        };
        self.release(charge)?;
        let peer = self.local_peer.ok_or(Fault::NotReady)?;
        let sender = hash512(&peer);
        let meta = ReceiveMeta {
            epoch: binding.epoch,
            flags: 4,
            requested: false,
            sender_hash: Some(sender),
            context: Some(sender),
        };
        let result = match self.receive_check(binding.source, meta, &input) {
            Ok(admission) => self.receive_commit(binding.source, meta, input, admission),
            Err(error) => Err(RejectedInput { error, input }),
        };
        match result {
            Ok(hash) => {
                let op = self
                    .rooms
                    .get_mut(binding.source.room)?
                    .operations
                    .get_mut(binding.operation.slot)?;
                op.phase = OperationPhase::Complete;
                self.event(Event::OperationChanged(
                    binding.operation,
                    OperationPhase::Complete,
                ))?;
                Ok(hash)
            }
            Err(rejected) => {
                // No intervening mutation/observer exists. Returning the same
                // reserved charge cannot allocate; retain the original frame
                // for caller retry or explicit original operation retirement.
                self.charge(charge)?;
                let op = self
                    .rooms
                    .get_mut(binding.source.room)?
                    .operations
                    .get_mut(binding.operation.slot)?;
                let Job::Wire { frame, .. } = &mut op.job else {
                    return Err(Fault::Conflict.into());
                };
                *frame = Some(rejected.input);
                op.charged_bytes = charge;
                Err(rejected.error)
            }
        }
    }

    /// Public published anonymous principal, for actual daemon ID allocation.
    /// This does not generate a private key or establish a member session.
    pub fn service_anonymous_public(&self) -> Result<&PublicKey, Error> {
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        Ok(&self.anonymous)
    }
    /// Retire only this actual app's per-room SERVICE lease after its original
    /// CLOSE response has actually fully written, and all original operations
    /// are already retired. The shared accepted MQ may remain live for other
    /// rooms; this explicitly does not claim a physical source_stopped event.
    pub fn release_service_client(&mut self, source: Source<'id>) -> Result<(), Error> {
        self.check_source(source)?;
        let room = self.rooms.get(source.room)?;
        if self.mode != Mode::Service || room.sources.get(source.slot)?.role != SourceRole::Client {
            return Err(Error::Permission);
        }
        if room
            .operations
            .iter()
            .any(|(_, o)| o.binding.source == source)
        {
            return Err(Fault::NotReady.into());
        }
        self.rooms
            .get_mut(source.room)?
            .sources
            .remove(source.slot)?;
        Ok(())
    }
}
