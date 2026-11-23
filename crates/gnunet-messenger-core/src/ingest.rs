//! Original-source admission, actual signature attribution and IPC observations.
use crate::{
    archive::CommittedRoomHistory, engine::Core, graph::*, room_storage::RoomDirectory,
    service_routing::VacantAlias, state::*, *,
};
use gnunet_crypto::hash512;
use gnunet_types::Error as Fault;
use wire::{
    body::Body,
    envelope::{Envelope, Kind},
    message::Message,
    padding,
};

#[cfg(feature = "alloc")]
mod notification;

struct OriginalFrame<'frame> {
    message: Message<'frame>,
    hash: Hash,
    pad: padding::Decode,
    layout: OriginalLayout,
}

impl<'frame> OriginalFrame<'frame> {
    fn decode(
        input: &'frame [u8],
        pad: padding::Decode,
        layout: OriginalLayout,
    ) -> Result<Self, Error> {
        let message = Message::decode_with_profiles(
            input,
            layout.body_profile(Envelope::decode(input)?.header()?.kind)?,
            layout.padding,
            pad,
        )?;
        Ok(Self {
            hash: crypto::signature::message_hash(message),
            message,
            pad,
            layout,
        })
    }
}

struct FrameCommit<'turn, 'id, const ROOMS: usize> {
    mode: Mode,
    #[cfg(feature = "alloc")]
    instance: Brand<'id>,
    rooms: &'turn mut RoomDirectory<'id, ROOMS>,
    frames: &'turn mut FrameStore<'id>,
    events: &'turn mut EventQueue<'id>,
    used: &'turn mut usize,
    total_bytes: usize,
}

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    /// Check the actual original signer. A JOIN is self-authenticating key
    /// introduction, not an established membership until its handler commits.
    /// `hash` is the canonical digest computed at admission, also retained
    /// as the history key for an original that awaits its signer.
    pub(crate) fn authenticate(
        &self,
        source: Source<'id>,
        message: Message<'_>,
        hash: &Hash,
        meta: ReceiveMeta,
    ) -> Result<Option<Authentication>, Error> {
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
        if self.mode == Mode::Service
            && header.kind == Kind::INFO
            && let SourceRole::Peer(peer) = source_row.role
        {
            // INFO is channel-local. Verify this original frame before any
            // historical hash hit can be considered a duplicate.
            crypto::signature::verify_peer(message, &peer)?;
            result = Some(Self::peer_auth(peer));
        } else if peer_kind(header.kind) {
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
                for p in &room.queues.peers {
                    if p.is_announced() && crypto::signature::verify_peer(message, &p.peer).is_ok()
                    {
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
            // Completed sessions can only authenticate an already-owned original
            // hash. Retained auth metadata survives deletion and key rotation.
            if let Some(node) = room.find_node(hash).and_then(|s| room.nodes.get(s).ok())
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
                    if (!session.has_live_authority() && !historical)
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
        self.check_ingress_attribution(
            source_row,
            header.sender_id,
            &auth.public,
            auth.peer.as_ref(),
            meta,
        )?;
        Ok(Some(auth))
    }

    fn check_ingress_attribution(
        &self,
        source: &SourceRow,
        member: &ShortHash,
        public: &PublicKey,
        peer: Option<&ShortHash>,
        meta: ReceiveMeta,
    ) -> Result<(), Error> {
        if let Some(sender) = meta.sender_hash {
            let expected = peer.map_or_else(|| hash512(public), |peer| hash512(peer));
            if sender != expected {
                return Err(Error::AttributionConflict);
            }
        }
        // A locally submitted service SEND cannot impersonate another client.
        // A peer source can relay signatures by other actual room members.
        if self.mode == Mode::Service
            && source.role == SourceRole::Client
            && (peer.is_some()
                || source.public != Some(*public)
                || source.member_id != Some(*member))
        {
            return Err(Error::Permission);
        }
        Ok(())
    }
    fn peer_auth(peer: [u8; 32]) -> Authentication {
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
    #[cfg(feature = "alloc")]
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
        match self.receive_check(source, meta, input.expose()) {
            Err(error) => Err(RejectedInput { error, input }),
            Ok(admission) => self.receive_commit(source, meta, input, admission),
        }
    }
    /// Actual SERVICE ingress with explicitly selected original layout. The
    /// caller must bind this policy to the original signer/hash, not just a relay.
    /// Signature/header/hash checks remain mandatory. Wrong/foreign declarations
    /// return the original owned frame and grant no authentication or membership.
    #[cfg(feature = "alloc")]
    pub fn receive_profiled(
        &mut self,
        source: Source<'id>,
        meta: ReceiveMeta,
        layout: OriginalLayout,
        input: OwnedBytes,
    ) -> Result<Hash, RejectedInput> {
        let checked = self
            .check_service_ingress(source)
            .and_then(|()| self.receive_check_profiled(source, meta, input.expose(), layout));
        match checked {
            Ok(admission) => self.receive_commit(source, meta, input, admission),
            Err(error) => Err(RejectedInput { error, input }),
        }
    }

    /// Admit borrowed SERVICE ingress with the same signer and layout checks
    /// as owned ingress. A fixed frame store copies directly into its pool.
    pub fn receive_borrowed(
        &mut self,
        source: Source<'id>,
        meta: ReceiveMeta,
        layout: OriginalLayout,
        input: &[u8],
    ) -> Result<Hash, Error> {
        self.receive_borrowed_in(source, meta, layout, input, None)
    }

    /// Admit borrowed SERVICE ingress against the current room and its exact
    /// committed graph directory. The native caller pins the original storage
    /// receipt for this operation. An exact detached message, including a
    /// tombstone, supplies only its original signer to verify a replay.
    /// Successful replays retain no bytes, allocate no work and never apply
    /// the original again or grant authority from archived facts.
    ///
    /// # Errors
    /// Refuses foreign room or peer history, a future acceptance cursor,
    /// invalid signatures or attribution, and ordinary admission failures.
    pub fn receive_borrowed_with_history(
        &mut self,
        source: Source<'id>,
        meta: ReceiveMeta,
        layout: OriginalLayout,
        input: &[u8],
        archive: CommittedRoomHistory<'_, '_>,
    ) -> Result<Hash, Error> {
        self.receive_borrowed_in(source, meta, layout, input, Some(archive))
    }

    fn receive_borrowed_in(
        &mut self,
        source: Source<'id>,
        meta: ReceiveMeta,
        layout: OriginalLayout,
        input: &[u8],
        archive: Option<CommittedRoomHistory<'_, '_>>,
    ) -> Result<Hash, Error> {
        self.check_service_ingress(source)?;
        let original = self.decode_incoming(source, input, layout)?;
        if let Some(archive) = archive {
            let room = self.rooms.get(source.room)?;
            archive.check_working_room(room, source.room, self.local_peer)?;
            // A current observation shadows older durable records. A detached
            // hit never reaches the admission path that can create a node.
            if room.find_node(&original.hash).is_none()
                && let Some((kind, signer)) = archive.detached_signer(&original.hash)?
            {
                let header = original.message.header();
                if header.kind != kind {
                    return Err(Fault::Authentication.into());
                }
                let (public, peer) = match signer {
                    OriginalSigner::Member(public) => (public, None),
                    OriginalSigner::Peer(peer) => (Self::peer_auth(peer).public, Some(peer)),
                };
                layout.check_signer(public, peer)?;
                if let Some(peer) = &peer {
                    crypto::signature::verify_peer(original.message, peer)?;
                    if let Body::Peer { peer: announced } = original.message.body()
                        && announced != peer
                    {
                        return Err(Fault::Authentication.into());
                    }
                } else {
                    crypto::signature::verify_member(
                        original.message,
                        wire::PublicKey::new(&public)?,
                    )?;
                }
                self.check_ingress_attribution(
                    room.sources.get(source.slot)?,
                    header.sender_id,
                    &public,
                    peer.as_ref(),
                    meta,
                )?;
                return Ok(original.hash);
            }
        }
        let admission = self.check_decoded(source, meta, original)?;
        self.frame_commit()
            .0
            .commit(source, meta, input, admission, 0)
            .map_err(|(error, _)| error)
    }

    fn check_service_ingress(&self, source: Source<'id>) -> Result<(), Error> {
        self.check_source(source)?;
        if self.mode != Mode::Service
            || matches!(
                self.rooms.get(source.room)?.sources.get(source.slot)?.role,
                SourceRole::ServiceSigner(_)
            )
        {
            return Err(Error::Permission);
        }
        Ok(())
    }

    pub(crate) fn receive_check(
        &self,
        source: Source<'id>,
        meta: ReceiveMeta,
        input: &[u8],
    ) -> Result<Admission, Error> {
        self.receive_check_profiled(source, meta, input, OriginalLayout::same(self.profile))
    }
    pub(crate) fn receive_check_profiled(
        &self,
        source: Source<'id>,
        meta: ReceiveMeta,
        input: &[u8],
        layout: OriginalLayout,
    ) -> Result<Admission, Error> {
        self.check_decoded(source, meta, self.decode_incoming(source, input, layout)?)
    }

    /// Plan an immediate local withdrawal while the observed announcement
    /// still holds. Normal queued ingress is settled before this native action.
    pub(crate) fn receive_route_loss_check(
        &self,
        source: Source<'id>,
        meta: ReceiveMeta,
        input: &[u8],
        local: &ShortHash,
        expected: &Hash,
    ) -> Result<Admission, Error> {
        let original = self.decode_incoming(source, input, OriginalLayout::same(self.profile))?;
        let Body::Miss { peer } = original.message.body() else {
            return Err(Error::Permission);
        };
        if peer == local {
            return Err(Error::Permission);
        }
        let room = self.rooms.get(source.room)?;
        let peers = &room.queues.peers;
        if peers.announcement(peer).is_none_or(|a| &a.hash != expected) {
            return Err(Fault::StaleGeneration.into());
        }
        if !room.ready.is_empty() {
            return Err(Fault::WouldBlock.into());
        }
        if original.message.header().previous != &room.last_message {
            return Err(Fault::StaleGeneration.into());
        }
        let target = *peer;
        let mut admission = self.check_decoded(source, meta, original)?;
        if admission.auth.and_then(|auth| auth.peer).as_ref() != Some(local) {
            return Err(Fault::Authentication.into());
        }
        if admission.existing.is_some() {
            return Err(Fault::Replay.into());
        }
        admission.route_loss = Some(LocalRouteLoss {
            target,
            alias: room.vacant_alias(&admission.hash)?,
            epoch: room.alias(&admission.hash).unwrap_or(room.current_epoch),
            sequence: room.sequence.checked_add(1).ok_or(Fault::Overflow)?,
        });
        Ok(admission)
    }

    fn decode_incoming<'frame>(
        &self,
        source: Source<'id>,
        input: &'frame [u8],
        layout: OriginalLayout,
    ) -> Result<OriginalFrame<'frame>, Error> {
        layout.validate()?;
        self.check_source(source)?;
        self.check_receive_capacity(input.len())?;
        let pad = self
            .rooms
            .get(source.room)?
            .sources
            .get(source.slot)?
            .padding;
        OriginalFrame::decode(input, pad, layout)
    }

    fn check_receive_capacity(&self, length: usize) -> Result<(), Error> {
        self.reserve_events(1)?;
        if length > self.limits.frame_bytes {
            return Err(Fault::TooLarge.into());
        }
        Ok(())
    }

    fn check_decoded(
        &self,
        source: Source<'id>,
        meta: ReceiveMeta,
        original: OriginalFrame<'_>,
    ) -> Result<Admission, Error> {
        let OriginalFrame {
            message: m,
            hash,
            pad,
            layout,
        } = original;
        let room = self.rooms.get(source.room)?;
        let auth = self.authenticate(source, m, &hash, meta)?;
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
            let resumable = old.origin.is_archived()
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
            // Matching a settled original, including one stored in the
            // checkpoint, never adopts the duplicate's resident frame.
            if old.auth.is_some() && !resumable {
                return Ok(Admission {
                    hash,
                    auth,
                    pad,
                    layout,
                    cipher_layout: self
                        .mode
                        .is_client()
                        .then_some(ShortLayout::same(self.profile)),
                    transcript_layout: self
                        .mode
                        .is_client()
                        .then_some(ShortLayout::same(self.profile)),
                    identifier_order: self.mode.is_client().then_some(self.profile.endian),
                    source_role: room.sources.get(source.slot)?.role,
                    parents,
                    references: refs,
                    discourse,
                    kind: m.header().kind,
                    timestamp: m.header().timestamp.as_micros(),
                    existing,
                    duplicate: true,
                    route_loss: None,
                });
            }
            if auth.is_none() {
                return Err(Fault::WouldBlock.into());
            }
        } else {
            room.nodes.next_key()?;
        }
        room.sequence.checked_add(1).ok_or(Fault::Overflow)?;
        Ok(Admission {
            hash,
            auth,
            pad,
            layout,
            cipher_layout: self
                .mode
                .is_client()
                .then_some(ShortLayout::same(self.profile)),
            transcript_layout: self
                .mode
                .is_client()
                .then_some(ShortLayout::same(self.profile)),
            identifier_order: self.mode.is_client().then_some(self.profile.endian),
            source_role: room.sources.get(source.slot)?.role,
            parents,
            references: refs,
            discourse,
            kind: m.header().kind,
            timestamp: m.header().timestamp.as_micros(),
            existing,
            duplicate: false,
            route_loss: None,
        })
    }
    #[cfg(feature = "alloc")]
    pub(crate) fn receive_commit(
        &mut self,
        source: Source<'id>,
        meta: ReceiveMeta,
        input: OwnedBytes,
        a: Admission,
    ) -> Result<Hash, RejectedInput> {
        self.frame_commit()
            .0
            .commit(source, meta, input, a, 0)
            .map_err(|(error, input)| RejectedInput { error, input })
    }

    pub(crate) fn receive_retained_service_commit(
        &mut self,
        source: Source<'id>,
        meta: ReceiveMeta,
        input: RetainedFrame,
        admission: Admission,
        charge: usize,
    ) -> Result<Hash, (Error, RetainedFrame)> {
        let (mut target, work) = self.frame_commit();
        match input {
            #[cfg(feature = "alloc")]
            RetainedFrame::Heap(bytes) => target
                .commit(source, meta, bytes, admission, charge)
                .map_err(|(error, bytes)| (error, RetainedFrame::Heap(bytes))),
            fixed @ RetainedFrame::Fixed { .. } => work
                .consume_fixed(&fixed, |bytes| {
                    target
                        .commit(source, meta, bytes, admission, charge)
                        .map_err(|(error, _)| error)
                })
                .map_err(|error| (error, fixed)),
            archived @ RetainedFrame::Archived(_) => Err((Fault::Conflict.into(), archived)),
        }
    }

    fn frame_commit(&mut self) -> (FrameCommit<'_, 'id, ROOMS>, &mut ByteStore<'id>) {
        (
            FrameCommit {
                mode: self.mode,
                #[cfg(feature = "alloc")]
                instance: self.instance,
                rooms: &mut self.rooms,
                frames: &mut self.frames,
                events: &mut self.events,
                used: &mut self.used,
                total_bytes: self.limits.total_bytes,
            },
            &mut self.work,
        )
    }
}

impl<'id, const ROOMS: usize> FrameCommit<'_, 'id, ROOMS> {
    fn commit<I: IncomingFrame>(
        &mut self,
        source: Source<'id>,
        meta: ReceiveMeta,
        input: I,
        a: Admission,
        released_work: usize,
    ) -> Result<Hash, (Error, I)> {
        let Some(used) = self.used.checked_sub(released_work) else {
            return Err((Fault::Conflict.into(), input));
        };
        if a.duplicate {
            // A bootstrap/history notification may precede its live RECENT
            // delivery. Only the exact still-live original source and epoch
            // can promote that authenticated frame's frontier observation.
            #[cfg(feature = "alloc")]
            if self.mode.is_client() && meta.flags & 8 != 0 && a.auth.is_some() {
                let result = (|| {
                    let room = self.rooms.get_mut(source.room)?;
                    let slot = a.existing.ok_or(Fault::Conflict)?;
                    let old = room.nodes.get(slot)?;
                    if old.origin.live(self.instance) == Some(source)
                        && old.epoch == meta.epoch
                        && !old.frontier_recent
                    {
                        room.queue_node(slot)?;
                        room.nodes.get_mut(slot)?.frontier_recent = true;
                    }
                    Ok::<(), Error>(())
                })();
                if let Err(error) = result {
                    return Err((error, input));
                }
            }
            *self.used = used;
            return Ok(a.hash);
        }
        // Reserve metadata before retaining these bytes. Replacement preserves
        // the previous row and payload when the new payload will not fit.
        let event = match self.events.vacant() {
            Ok(event) => event,
            Err(error) => return Err((error, input)),
        };
        let room = match self.rooms.get_mut(source.room) {
            Ok(r) => r,
            Err(error) => return Err((error, input)),
        };
        let loss = a.route_loss.as_ref();
        let outgoing = room.operations.iter().find_map(|(_, o)| {
            (o.binding.source == source.slot
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
        #[cfg(feature = "alloc")]
        let recipient = outgoing
            .and_then(|operation| operation.recipient)
            .map(RecipientAttribution::member);
        let phase = if a.auth.is_some() {
            MessagePhase::Ready
        } else {
            MessagePhase::AwaitingSender
        };
        let mut node = Node {
            hash: a.hash,
            origin: NodeOrigin::from_source(source, a.source_role),
            resume_pending: a
                .auth
                .and_then(|a| a.session)
                .and_then(|s| room.sessions.get(s).ok())
                .is_some_and(|s| s.archived),
            meta,
            phase,
            frame: None,
            #[cfg(feature = "alloc")]
            plaintext: None,
            auth: a.auth,
            padding: a.pad,
            layout: a.layout,
            cipher_layout: a.cipher_layout,
            plain_layout: a.cipher_layout,
            transcript_layout: a.transcript_layout,
            identifier_order: a.identifier_order,
            semantic_applied: loss.is_some(),
            complete: false,
            parents: a.parents,
            references: a.references,
            frontier_applied: false,
            frontier_recent: meta.flags & 8 != 0,
            epoch: loss.map_or(meta.epoch, |loss| loss.epoch),
            epoch_indexed: self.mode != Mode::Service || loss.is_some(),
            kind: a.kind,
            semantic_kind: a.kind,
            timestamp: a.timestamp,
            sequence: loss.map_or(0, |loss| loss.sequence),
            queued: true,
            requested: meta.requested,
            delete_at: None,
            deleted_by: None,
            discourse: a.discourse,
            local_sent,
            transcript: None,
            private_recipient: None,
            #[cfg(feature = "alloc")]
            recipient,
        };
        let (used, capacity) = if let Some(slot) = a.existing {
            let old = match room.nodes.get_mut(slot) {
                Ok(n) => n,
                Err(error) => return Err((error, input)),
            };
            let ready = if old.queued {
                None
            } else {
                match room.ready.vacant() {
                    Ok(ready) => Some(ready),
                    Err(error) => return Err((error, input)),
                }
            };
            let Some(used) = used.checked_sub(old.payload_bytes()) else {
                return Err((Fault::Conflict.into(), input));
            };
            let budget = self.total_bytes.saturating_sub(used);
            let retained = self.frames.retain(input, old.frame.as_ref(), budget)?;
            let capacity = retained.capacity();
            node.frame = Some(retained);
            node.origin = old.origin.with_source(source, a.source_role);
            if self.mode == Mode::Service
                && !node.origin.is_first_received()
                && matches!(node.kind, Kind::PEER | Kind::MISS | Kind::CONNECTION)
            {
                // Reattachment can restore the original graph record. It
                // cannot turn an archived route control into a live notice.
                node.requested = true;
            }
            *old = node;
            if let Some(ready) = ready {
                ready.insert(slot);
            }
            (used, capacity)
        } else {
            let index = match room
                .index
                .vacant(&a.hash, |slot| room.nodes.get(slot).map(|node| &node.hash))
            {
                Ok(index) => index,
                Err(error) => return Err((error, input)),
            };
            let vacant = match room.nodes.vacant() {
                Ok(vacant) => vacant,
                Err(error) => return Err((error, input)),
            };
            let ready = match room.ready.vacant() {
                Ok(ready) => ready,
                Err(error) => return Err((error, input)),
            };
            let budget = self.total_bytes.saturating_sub(used);
            let retained = self.frames.retain(input, None, budget)?;
            let capacity = retained.capacity();
            node.frame = Some(retained);
            let slot = vacant.insert(node);
            index.insert(slot);
            ready.insert(slot);
            if let Some(loss) = a.route_loss {
                if let Some(alias) = loss.alias {
                    room.insert_alias(alias, a.hash, loss.epoch);
                }
                room.sequence = loss.sequence;
                room.queues.peers.remove(&loss.target);
            }
            (used, capacity)
        };

        *self.used = used + capacity;
        event.insert(QueuedEvent::MessageChanged(source.room, a.hash, phase));
        Ok(a.hash)
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests;
pub(crate) struct Admission {
    hash: Hash,
    auth: Option<Authentication>,
    pad: padding::Decode,
    layout: OriginalLayout,
    cipher_layout: Option<ShortLayout>,
    transcript_layout: Option<ShortLayout>,
    identifier_order: Option<wire::profile::Endian>,
    source_role: SourceRole,
    parents: [Hash; 2],
    references: [Hash; 3],
    discourse: Option<ShortHash>,
    kind: Kind,
    timestamp: u64,
    existing: Option<Slot>,
    duplicate: bool,
    route_loss: Option<LocalRouteLoss>,
}

/// Prepared only for a fresh authenticated local MISS. Frame retention must
/// succeed before installing any of these graph and routing changes.
struct LocalRouteLoss {
    target: ShortHash,
    alias: Option<VacantAlias>,
    epoch: Hash,
    sequence: u64,
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
