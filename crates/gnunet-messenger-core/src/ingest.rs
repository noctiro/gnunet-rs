//! Original-source admission, actual signature attribution and IPC observations.
use crate::{engine::Core, graph::*, state::*, *};
use gnunet_crypto::hash512;
use gnunet_types::Error as Fault;
use wire::{body::Body, envelope::Kind, message::Message, padding};
impl<'id> Core<'id> {
    /// Check the actual original signer. A JOIN is self-authenticating key
    /// introduction, not an established membership until its handler commits.
    pub(crate) fn authenticate(
        &self,
        source: Source<'id>,
        message: Message<'_>,
        meta: ReceiveMeta,
    ) -> Result<Option<Authentication<'id>>, Error> {
        self.check_source(source)?;
        let room = self.rooms.get(source.room)?;
        let source_row = room.sources.get(source.slot)?;
        if self.mode == Mode::Service
            && source_row.role == SourceRole::Client
            && (source_row.public.is_none() || source_row.member_id.is_none())
        {
            return Err(Error::Permission);
        }
        let header = message.header();
        let mut result = None;
        if peer_kind(header.kind) {
            if let Body::Peer { peer } = message.body()
                && crypto::signature::verify_peer(message, peer).is_ok()
            {
                result = Some(Self::peer_auth(*peer));
            }
            if result.is_none()
                && matches!(source_row.role, SourceRole::Peer(_))
                && crypto::signature::verify_peer(message, header.sender_id).is_ok()
            {
                result = Some(Self::peer_auth(*header.sender_id));
            }
            if result.is_none()
                && let SourceRole::Peer(peer) = source_row.role
                && crypto::signature::verify_peer(message, &peer).is_ok()
            {
                result = Some(Self::peer_auth(peer));
            }
            if result.is_none()
                && let Some(peer) = self.local_peer
                && crypto::signature::verify_peer(message, &peer).is_ok()
            {
                result = Some(Self::peer_auth(peer));
            }
            if result.is_none() {
                for p in &room.peers {
                    if p.announced && crypto::signature::verify_peer(message, &p.peer).is_ok() {
                        result = Some(Self::peer_auth(p.peer));
                        break;
                    }
                }
            }
        } else if let Body::Join { public_key, .. } = message.body() {
            crypto::signature::verify_member(message, public_key)?;
            result = Some(Authentication {
                owner: None,
                session: None,
                public: *public_key.as_bytes(),
                peer: None,
            });
        } else {
            let digest = crypto::signature::message_hash(message);
            // Completed sessions can only authenticate an already-owned original
            // hash. Retained auth metadata survives deletion and key rotation.
            if let Some(node) = room.find_node(&digest).and_then(|s| room.nodes.get(s).ok())
                && let Some(auth) = node.auth
                && auth.peer.is_none()
                && crypto::signature::verify_member(message, wire::PublicKey::new(&auth.public)?)
                    .is_ok()
            {
                result = Some(auth);
            }
            if result.is_none() {
                for (slot, session) in room.sessions.iter() {
                    let historical = self.mode == Mode::Service
                        && session.archived
                        && session.historical_phase == SessionPhase::Active
                        && session.successor.is_none();
                    if (session.phase == SessionPhase::Completed && !historical)
                        || session.id != *header.sender_id
                    {
                        continue;
                    }
                    if crypto::signature::verify_member(
                        message,
                        wire::PublicKey::new(&session.public)?,
                    )
                    .is_ok()
                    {
                        result = Some(Authentication {
                            owner: Some(owner(session)),
                            session: Some(slot),
                            public: session.public,
                            peer: None,
                        });
                        break;
                    }
                }
            }
        }
        let Some(auth) = result else {
            return Ok(None);
        };
        if let Some(sender) = meta.sender_hash {
            let expected = if let Some(peer) = auth.peer {
                hash512(&peer)
            } else {
                hash512(&auth.public)
            };
            if sender != expected {
                return Err(Error::AttributionConflict);
            }
        }
        // A locally submitted service SEND cannot impersonate another client.
        // A peer source can relay signatures by other actual room members.
        if self.mode == Mode::Service
            && source_row.role == SourceRole::Client
            && (auth.peer.is_some()
                || source_row.public != Some(auth.public)
                || source_row.member_id != Some(*header.sender_id))
        {
            return Err(Error::Permission);
        }
        Ok(Some(auth))
    }
    fn peer_auth(peer: [u8; 32]) -> Authentication<'id> {
        let mut public = [0; 36];
        public[..4].copy_from_slice(&wire::KeyType::Eddsa.value().to_be_bytes());
        public[4..].copy_from_slice(&peer);
        Authentication {
            owner: None,
            session: None,
            public,
            peer: Some(peer),
        }
    }
    /// Admit exclusively owned original frame bytes. A deferred signer consumes
    /// bounded storage, but grants no state permission. Failed admission returns
    /// the original input for a caller retry; invalid first signatures cannot
    /// permanently reserve a canonical hash against a later valid signature.
    pub fn receive_owned(
        &mut self,
        source: Source<'id>,
        meta: ReceiveMeta,
        input: OwnedBytes,
    ) -> Result<Hash, RejectedInput> {
        // A local daemon frame enters only through its original verified
        // complete_signature binding and service_commit_signature transfer.
        if self.check_source(source).is_ok()
            && self
                .rooms
                .get(source.room)
                .and_then(|r| r.sources.get(source.slot))
                .is_ok_and(|s| matches!(s.role, SourceRole::ServiceSigner(_)))
        {
            return Err(RejectedInput {
                error: Error::Permission,
                input,
            });
        }
        match self.receive_check(source, meta, &input) {
            Err(error) => Err(RejectedInput { error, input }),
            Ok(admission) => self.receive_commit(source, meta, input, admission),
        }
    }
    pub(crate) fn receive_check(
        &self,
        source: Source<'id>,
        meta: ReceiveMeta,
        input: &OwnedBytes,
    ) -> Result<Admission<'id>, Error> {
        self.receive_check_profiled(source, meta, input, OriginalLayout::same(self.profile))
    }
    pub(crate) fn receive_check_profiled(
        &self,
        source: Source<'id>,
        meta: ReceiveMeta,
        input: &OwnedBytes,
        layout: OriginalLayout,
    ) -> Result<Admission<'id>, Error> {
        layout.validate()?;
        self.check_source(source)?;
        self.reserve_events(1)?;
        if input.len() > self.limits.frame_bytes {
            return Err(Fault::TooLarge.into());
        }
        let room = self.rooms.get(source.room)?;
        let pad = room.sources.get(source.slot)?.padding;
        let m = Message::decode_with_profiles(
            input.expose(),
            layout.body_profile(
                wire::envelope::Envelope::decode(input.expose())?
                    .header()?
                    .kind,
            )?,
            layout.padding,
            pad,
        )?;
        let hash = crypto::signature::message_hash(m);
        let auth = self.authenticate(source, m, meta)?;
        if let Some(auth) = auth {
            layout.check_signer(auth.public, auth.peer)?;
        }
        let refs = references(m.body());
        let mut parents = [*m.header().previous, [0; 64]];
        let mut discourse = None;
        if let Body::Merge { previous, .. } = m.body() {
            parents[1] = *previous;
        }
        if parents.contains(&hash) {
            return Err(Fault::Malformed.into());
        }
        if let Body::Talk { discourse: d, .. } | Body::Subscription { discourse: d, .. } = m.body()
        {
            discourse = Some(*d);
        }
        let existing = room.find_node(&hash);
        if let Some(slot) = existing {
            let old = room.nodes.get(slot)?;
            if let (Some(a), Some(b)) = (old.auth, auth)
                && (a.public != b.public
                    || a.peer != b.peer
                    || a.owner.is_some() && b.owner.is_some() && a.owner != b.owner)
            {
                return Err(Error::AttributionConflict);
            }
            let resumable = matches!(old.origin, MessageOrigin::Archived(_))
                && !old.semantic_applied
                && matches!(
                    old.phase,
                    MessagePhase::Ready
                        | MessagePhase::AwaitingParents
                        | MessagePhase::AwaitingEpoch
                )
                && old.auth.is_some_and(|accepted| match accepted.session {
                    None => true,
                    Some(slot) => room.sessions.get(slot).is_ok_and(|session| {
                        session.archived
                            && session.historical_phase == SessionPhase::Active
                            && session.successor.is_none()
                    }),
                });
            if old.auth.is_some() && !resumable {
                return Ok(Admission {
                    hash,
                    auth,
                    pad,
                    layout,
                    cipher_layout: (self.mode == Mode::Client)
                        .then_some(ShortLayout::same(self.profile)),
                    transcript_layout: (self.mode == Mode::Client)
                        .then_some(ShortLayout::same(self.profile)),
                    identifier_order: (self.mode == Mode::Client).then_some(self.profile.endian),
                    provenance: SourceObservation {
                        room: source.room,
                        source: source.slot,
                        role: room.sources.get(source.slot)?.role,
                    },
                    parents,
                    references: refs,
                    discourse,
                    kind: m.header().kind,
                    timestamp: m.header().timestamp.as_micros(),
                    existing,
                    duplicate: true,
                });
            }
            if auth.is_none() {
                return Err(Fault::WouldBlock.into());
            }
        } else {
            room.nodes.next_key()?;
        }
        let reclaimed = existing
            .and_then(|s| room.nodes.get(s).ok())
            .map_or(0, Node::payload_bytes);
        if input.capacity() > self.remaining_bytes().saturating_add(reclaimed) {
            return Err(Fault::Capacity.into());
        }
        room.sequence.checked_add(1).ok_or(Fault::Overflow)?;
        Ok(Admission {
            hash,
            auth,
            pad,
            layout,
            cipher_layout: (self.mode == Mode::Client).then_some(ShortLayout::same(self.profile)),
            transcript_layout: (self.mode == Mode::Client)
                .then_some(ShortLayout::same(self.profile)),
            identifier_order: (self.mode == Mode::Client).then_some(self.profile.endian),
            provenance: SourceObservation {
                room: source.room,
                source: source.slot,
                role: room.sources.get(source.slot)?.role,
            },
            parents,
            references: refs,
            discourse,
            kind: m.header().kind,
            timestamp: m.header().timestamp.as_micros(),
            existing,
            duplicate: false,
        })
    }
    pub(crate) fn receive_commit(
        &mut self,
        source: Source<'id>,
        meta: ReceiveMeta,
        input: OwnedBytes,
        a: Admission<'id>,
    ) -> Result<Hash, RejectedInput> {
        if a.duplicate {
            return Ok(a.hash);
        }
        // All admission checks precede moving the input. Fixed-capacity table
        // insertion and ready-queue append cannot allocate or fail afterwards.
        let capacity = input.capacity();
        let room = match self.rooms.get_mut(source.room) {
            Ok(r) => r,
            Err(error) => return Err(RejectedInput { error, input }),
        };
        let sequence = 0;
        let outgoing = room.operations.iter().find_map(|(_, o)| {
            (o.binding.source == source
                && o.binding.message == a.hash
                && o.phase == OperationPhase::Written
                && matches!(
                    &o.job,
                    Job::Wire {
                        purpose: NativePurpose::Send,
                        ..
                    }
                ))
            .then_some(o)
        });
        let local_sent = outgoing.is_some();
        let recipient = outgoing.and_then(|operation| operation.recipient);
        let phase = if a.auth.is_some() {
            MessagePhase::Ready
        } else {
            MessagePhase::AwaitingSender
        };
        let node = Node {
            hash: a.hash,
            origin: MessageOrigin::Live(source),
            provenance: a.provenance,
            resume_pending: a
                .auth
                .and_then(|a| a.session)
                .and_then(|s| room.sessions.get(s).ok())
                .is_some_and(|s| s.archived),
            meta,
            phase,
            frame: Some(input),
            plaintext: None,
            auth: a.auth,
            padding: a.pad,
            layout: a.layout,
            cipher_layout: a.cipher_layout,
            plain_layout: a.cipher_layout,
            transcript_layout: a.transcript_layout,
            identifier_order: a.identifier_order,
            plain_padding: padding::Decode::Required,
            semantic_applied: false,
            complete: false,
            parents: a.parents,
            references: a.references,
            frontier_applied: false,
            epoch: meta.epoch,
            epoch_indexed: self.mode != Mode::Service,
            kind: a.kind,
            semantic_kind: a.kind,
            timestamp: a.timestamp,
            sequence,
            queued: false,
            requested: meta.requested,
            delete_at: None,
            deleted_by: None,
            discourse: a.discourse,
            local_sent,
            transcript: None,
            private_recipient: None,
            recipient,
            visit: 0,
        };
        let mut already_queued = false;
        let (slot, released) = if let Some(slot) = a.existing {
            let old = match room.nodes.get_mut(slot) {
                Ok(n) => n,
                Err(error) => {
                    return Err(RejectedInput {
                        error,
                        input: node.into_original(),
                    });
                }
            };
            already_queued = old.queued;
            let released = old.payload_bytes();
            *old = node;
            (slot, released)
        } else {
            (room.insert_node(node)?, 0)
        };

        // Preallocated one-entry-per-node queue; every admission owns a slot.
        if let Ok(n) = room.nodes.get_mut(slot) {
            n.queued = true;
        }
        if !already_queued {
            room.ready.push_back(slot);
        }
        self.used = self.used - released + capacity;
        // reserve_events already succeeded before input ownership changed.
        self.events.push_back(Event::MessageChanged(
            self.event_room(source.room),
            a.hash,
            phase,
        ));
        Ok(a.hash)
    }
    /// Borrowed original IPC notification. Receive makes one bounded zeroizing
    /// copy; callers owning raw frames can use receive_owned to avoid that copy.
    pub fn on_notification(
        &mut self,
        source: Source<'id>,
        response: wire::Response<'_>,
        now: u64,
    ) -> Result<(), Error> {
        self.notification_profiled(source, response, ClientLayout::same(self.profile), now)
    }
    /// Apply the actual original notification with explicit original body,
    /// plaintext and identifier facts. This is a CLIENT port, not daemon ingress;
    /// original key/hash/source/signature checks and pending-job binding remain.
    pub fn on_notification_profiled(
        &mut self,
        source: Source<'id>,
        response: wire::Response<'_>,
        layout: ClientLayout,
        now: u64,
    ) -> Result<(), Error> {
        if self.mode != Mode::Client {
            return Err(Error::Permission);
        }
        self.notification_profiled(source, response, layout, now)
    }
    fn notification_profiled(
        &mut self,
        source: Source<'id>,
        response: wire::Response<'_>,
        layout: ClientLayout,
        now: u64,
    ) -> Result<(), Error> {
        layout.validate()?;
        self.check_source(source)?;
        if self
            .rooms
            .get(source.room)?
            .operations
            .iter()
            .any(|(_, o)| {
                o.binding.source == source
                    && !matches!(
                        o.phase,
                        OperationPhase::Complete
                            | OperationPhase::Failed
                            | OperationPhase::Cancelled
                    )
                    && o.deadline <= now
            })
        {
            return Err(Fault::Timeout.into());
        }
        let key = self.rooms.get(source.room)?.key;
        match response {
            wire::Response::Receive {
                key: k,
                sender,
                context,
                hash,
                epoch,
                flags,
                message,
            } => {
                if *k != key {
                    return Err(Error::AttributionConflict);
                }
                let parsed = Message::decode_with_profiles(
                    message.expose(),
                    layout.original.body_profile(
                        wire::envelope::Envelope::decode(message.expose())?
                            .header()?
                            .kind,
                    )?,
                    layout.original.padding,
                    self.rooms
                        .get(source.room)?
                        .sources
                        .get(source.slot)?
                        .padding,
                )?;
                if crypto::signature::message_hash(parsed) != *hash {
                    return Err(Fault::Authentication.into());
                }
                let requested = self
                    .pending_wire(source, NativePurpose::Get, Some(hash))
                    .is_some();
                let bytes = OwnedBytes::copy_from(message.expose())?;
                let meta = ReceiveMeta {
                    epoch: *epoch,
                    flags,
                    requested,
                    sender_hash: Some(*sender),
                    context: Some(*context),
                };
                let mut admission =
                    self.receive_check_profiled(source, meta, &bytes, layout.original)?;
                admission.cipher_layout = Some(layout.plaintext);
                admission.transcript_layout = Some(layout.transcript);
                admission.identifier_order = layout.identifier_order;
                self.receive_commit(source, meta, bytes, admission)
                    .map_err(|r| r.error)?;

                if let Some(op) = self.pending_wire(source, NativePurpose::Get, Some(hash)) {
                    self.finish_wire(source, op)?;
                }
                if let Some(op) = self.pending_wire(source, NativePurpose::Send, Some(hash)) {
                    self.finish_wire(source, op)?;
                }
            }
            wire::Response::Missing { key: k, hash } => {
                if *k != key {
                    return Err(Error::AttributionConflict);
                }
                let op = self
                    .pending_wire(source, NativePurpose::Get, Some(hash))
                    .ok_or(Fault::StaleGeneration)?;
                self.reserve_events(2)?;
                self.finish_wire(source, op)?;
                let room = self.rooms.get_mut(source.room)?;
                if let Some((_, missing)) = room
                    .missing
                    .iter_mut()
                    .find(|(_, m)| m.hash == *hash && m.source == source)
                {
                    missing.absent = true;
                    missing.operation = None;
                }
                self.event(Event::Missing(self.event_room(source.room), *hash))?;
            }
            wire::Response::MemberId { key: k, id, reset } => {
                if *k != key {
                    return Err(Error::AttributionConflict);
                }
                // Response::decode uses the explicit original producer profile
                // for this single native-endian C field; no second swap here.
                self.reserve_events(1)?;
                let room = self.rooms.get_mut(source.room)?;
                let src = room.sources.get_mut(source.slot)?;
                if src.member_id.is_none() || reset == 1 {
                    src.member_id = Some(*id);
                    src.pending_member_id = None;
                    src.join_required = true;
                    room.local_id = Some(*id);
                    room.joined = false;
                } else {
                    // Keep the old sender ID until the signed ID(new) is really
                    // applied. Overwriting it here breaks original verification.
                    src.pending_member_id = Some(*id);
                }
                self.event(Event::RoomChanged(
                    self.event_room(source.room),
                    self.rooms.get(source.room)?.phase,
                ))?;
            }
            other => {
                let (r, purpose, phase) = match other {
                    wire::Response::Open(r) => (r, NativePurpose::Open, RoomPhase::Open),
                    wire::Response::Entry(r) => (r, NativePurpose::Enter, RoomPhase::Entered),
                    wire::Response::Close(r) => (r, NativePurpose::Close, RoomPhase::Detached),
                    wire::Response::Sync(r) => (
                        r,
                        NativePurpose::Sync,
                        if self.rooms.get(source.room)?.phase == RoomPhase::Closing {
                            RoomPhase::Closing
                        } else {
                            self.rooms
                                .get(source.room)?
                                .sync_phase
                                .ok_or(Fault::Conflict)?
                        },
                    ),
                    _ => return Err(Fault::Malformed.into()),
                };
                if *r.key != key {
                    return Err(Error::AttributionConflict);
                }
                let op = self
                    .pending_wire(source, purpose, None)
                    .ok_or(Fault::StaleGeneration)?;
                self.reserve_events(2)?;
                self.finish_wire(source, op)?;
                let row = self.rooms.get_mut(source.room)?;
                row.phase = phase;
                if purpose == NativePurpose::Sync {
                    row.sync_phase = None;
                }
                if purpose == NativePurpose::Close {
                    row.joined = false;
                }
                // Actual synchronization metadata is a cursor, not proof that
                // an unknown message/epoch has arrived or passed authentication.
                row.last_message = *r.previous;
                row.current_epoch = *r.epoch;
                self.event(Event::RoomChanged(self.event_room(source.room), phase))?;
            }
        }
        Ok(())
    }
}
pub(crate) struct Admission<'id> {
    hash: Hash,
    auth: Option<Authentication<'id>>,
    pad: padding::Decode,
    layout: OriginalLayout,
    cipher_layout: Option<ShortLayout>,
    transcript_layout: Option<ShortLayout>,
    identifier_order: Option<wire::profile::Endian>,
    provenance: SourceObservation,
    parents: [Hash; 2],
    references: [Hash; 3],
    discourse: Option<ShortHash>,
    kind: Kind,
    timestamp: u64,
    existing: Option<Slot>,
    duplicate: bool,
}

// Every privately constructed admission Node has its original owner present.
// Returning a conflict keeps this path fallible even if an internal invariant
// is changed later; no panic can be induced through the public frame API.

pub(crate) fn references(body: Body<'_>) -> [Hash; 3] {
    let zero = [0; 64];
    match body {
        Body::Join { epoch, .. } | Body::Leave { epoch } => [*epoch, zero, zero],
        Body::Merge {
            first_epoch,
            second_epoch,
            ..
        } => [*first_epoch, *second_epoch, zero],
        Body::Request { hash }
        | Body::Deletion { hash, .. }
        | Body::Transcript { hash, .. }
        | Body::Tag { hash, .. } => [*hash, zero, zero],
        Body::Appeal { event, .. }
        | Body::Access { event, .. }
        | Body::Authorization { event, .. } => [*event, zero, zero],
        Body::Group {
            initiator, partner, ..
        } => [*initiator, *partner, zero],
        _ => [zero; 3],
    }
}
