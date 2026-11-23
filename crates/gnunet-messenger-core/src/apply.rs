//! Actual bounded semantic application, member lineage and timer progression.
use crate::{
    archive::{CommittedRoomHistory, DetachedDeleteTarget, DetachedDeletion},
    engine::Core,
    graph::*,
    state::*,
    *,
};
use core::num::NonZeroU64;
use gnunet_crypto::hash512;
use gnunet_types::Error as Fault;
use wire::{body::Body, envelope::Kind, message::Message};
#[cfg(feature = "alloc")]
use {crate::recipient::MemberRecipient, wire::padding};

mod routing;

#[derive(Default)]
struct AdvanceHistory<'turn, 'archive, 'index> {
    view: Option<&'turn CommittedRoomHistory<'archive, 'index>>,
    deletion: Option<&'turn mut Option<DetachedDeletion>>,
}

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    /// Whether admitted vertices are queued for another bounded room turn.
    ///
    /// # Errors
    /// Rejects a stale or foreign room.
    pub fn has_ready_room_work(&self, room: Room<'id>) -> Result<bool, Error> {
        Ok(!self.rooms.get(self.check_room(room)?)?.ready.is_empty())
    }

    /// Perform a finite number of admitted transitions. A missing parent/signer/
    /// key remains deferred and is woken only by relevant actual input. Native
    /// writes, entropy and signatures remain original caller-port work.
    pub fn advance(&mut self, room: Room<'id>, now: u64) -> Result<usize, Error> {
        self.advance_room(room, now, AdvanceHistory::default())
    }

    /// Advance SERVICE using parent facts from the native owner's pinned room
    /// history when an authenticated predecessor is absent from working state.
    /// The owner must retain the selected root for the duration of this call.
    ///
    /// # Errors
    /// Refuses client mode, a foreign room history or a history whose acceptance
    /// cursor is newer than the working room. Other errors match [`Self::advance`].
    pub fn advance_with_committed_history(
        &mut self,
        room: Room<'id>,
        now: u64,
        history: CommittedRoomHistory<'_, '_>,
    ) -> Result<usize, Error> {
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        self.advance_room(
            room,
            now,
            AdvanceHistory {
                view: Some(&history),
                deletion: None,
            },
        )
    }

    /// Advance SERVICE against an exact committed directory, handing the owner
    /// at most one detached DELETE to prepare. The operation stops after that
    /// DELETE; further work must use the directory selected by its publication.
    ///
    /// # Errors
    /// Refuses client mode, a filled output slot and foreign or future history.
    /// If an error is returned after the slot is filled, the entire update must
    /// be discarded. A successful update commits the working checkpoint and
    /// the page replacement under one root before exposing either transition.
    pub fn advance_with_detached_deletion(
        &mut self,
        room: Room<'id>,
        now: u64,
        history: CommittedRoomHistory<'_, '_>,
        deletion: &mut Option<DetachedDeletion>,
    ) -> Result<usize, Error> {
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        if deletion.is_some() {
            return Err(Fault::WouldBlock.into());
        }
        self.advance_room(
            room,
            now,
            AdvanceHistory {
                view: Some(&history),
                deletion: Some(deletion),
            },
        )
    }

    fn advance_room(
        &mut self,
        room: Room<'id>,
        now: u64,
        mut archive: AdvanceHistory<'_, '_, '_>,
    ) -> Result<usize, Error> {
        let r = self.check_room(room)?;
        let history = archive.view;
        if let Some(history) = history {
            history.check_working_room(self.rooms.get(r)?, r, self.local_peer)?;
        }
        #[cfg(feature = "alloc")]
        self.expire_epochs(r, now)?;
        self.refresh_epochs(r)?;
        let mut steps = 0;
        for _ in 0..self.limits.work_per_turn {
            self.reserve_events(6)?;
            #[cfg(feature = "alloc")]
            let prove = {
                let row = self.rooms.get_mut(r)?;
                row.frontier_validation_turn = !row.frontier_validation_turn;
                row.frontier_validation_turn || row.ready.is_empty() && !row.derivation.pending()
            };
            #[cfg(feature = "alloc")]
            if prove && self.advance_frontier_sync(r, now)? {
                steps += 1;
                continue;
            }
            #[cfg(feature = "alloc")]
            let derive = {
                let row = self.rooms.get_mut(r)?;
                row.derivation.scheduled(row.ready.is_empty())
            };
            #[cfg(feature = "alloc")]
            if derive && self.derive_epoch_step(r)? {
                steps += 1;
                continue;
            }
            let next = self.rooms.get_mut(r)?.take_ready()?;
            let Some(slot) = next else {
                break;
            };
            let node = self.rooms.get(r)?.nodes.get(slot)?;
            if node.original_is_archived() {
                // Only settled bodies can leave resident storage, and they
                // cannot reenter the semantic work queue.
                return Err(Fault::Conflict.into());
            }
            if node.origin.is_archived() {
                // A restored graph can become complete after real parents arrive,
                // but no old semantic handler may mint current membership/keys.
                let complete = self.rooms.get(r)?.graph_complete(slot, history)?;
                let node = self.rooms.get_mut(r)?.nodes.get_mut(slot)?;
                let changed = node.complete != complete;
                node.complete = complete;
                let hash = node.hash;
                let phase = node.phase;
                if changed {
                    self.rooms.get_mut(r)?.queue_dependants(&hash)?;
                    self.event(Event::MessageChanged(room, hash, phase))?;
                    steps += 1;
                }
                continue;
            }
            if self.rooms.get(r)?.nodes.get(slot)?.phase == MessagePhase::Rejected {
                let complete = self.rooms.get(r)?.graph_complete(slot, history)?;
                let n = self.rooms.get_mut(r)?.nodes.get_mut(slot)?;
                let changed = complete && !n.complete;
                n.complete = complete;
                let hash = n.hash;
                if changed {
                    self.rooms.get_mut(r)?.queue_dependants(&hash)?;
                }
                continue;
            }
            let node = self.rooms.get_mut(r)?.nodes.get_mut(slot)?;
            let frame = node.frame.take();
            #[cfg(feature = "alloc")]
            let plain = node.plaintext.take();
            let Some(frame) = frame else {
                if self.rooms.get(r)?.nodes.get(slot)?.auth.is_some() {
                    let complete = self.rooms.get(r)?.graph_complete(slot, history)?;
                    let n = self.rooms.get_mut(r)?.nodes.get_mut(slot)?;
                    let changed = complete && !n.complete;
                    n.complete = complete;
                    let hash = n.hash;
                    if changed {
                        self.rooms.get_mut(r)?.queue_dependants(&hash)?;
                    }
                }
                continue;
            };
            let working = match self.frames.checkout(frame) {
                Ok(working) => working,
                Err((error, frame)) => {
                    let row = self.rooms.get_mut(r)?;
                    let node = row.nodes.get_mut(slot)?;
                    node.frame = Some(frame);
                    #[cfg(feature = "alloc")]
                    {
                        node.plaintext = plain;
                    }
                    row.queue_node(slot)?;
                    return Err(error);
                }
            };
            let result = (|| {
                let node = self.rooms.get(r)?.nodes.get(slot)?;
                let message = node.decode_original(working.bytes())?;
                self.apply_one(
                    r,
                    slot,
                    message,
                    #[cfg(feature = "alloc")]
                    plain.as_ref(),
                    now,
                    &mut archive,
                )
            })();
            // Restore the exact original owners before handling every result.
            // No internal callback can substitute another frame or key owner.
            let frame = self.frames.checkin(working)?;
            let deleted = self.rooms.get(r)?.nodes.get(slot)?.phase == MessagePhase::Deleted;
            if deleted {
                let amount = frame.capacity();
                #[cfg(feature = "alloc")]
                let amount = amount + plain.as_ref().map_or(0, Plaintext::capacity);
                self.frames.remove(frame)?;
                self.release(amount)?;
            } else {
                let n = self.rooms.get_mut(r)?.nodes.get_mut(slot)?;
                n.frame = Some(frame);
                #[cfg(feature = "alloc")]
                {
                    n.plaintext = plain;
                }
            }
            if archive.deletion.as_ref().is_some_and(|edit| edit.is_some()) {
                return result.map(|()| steps + 1);
            }
            match result {
                Ok(()) => {}
                Err(Error::Protocol(Fault::NotReady | Fault::NotFound)) => {
                    // Signature/causal completion is independent from a key or
                    // epoch needed to interpret this authenticated vertex.
                    // Its successors must not wait for an earlier epoch-key
                    // control that can itself depend on those successors.
                    let authenticated = self.rooms.get(r)?.nodes.get(slot)?.auth.is_some();
                    let complete =
                        authenticated && self.rooms.get(r)?.graph_complete(slot, history)?;
                    let n = self.rooms.get_mut(r)?.nodes.get_mut(slot)?;
                    let changed = complete && !n.complete;
                    n.complete = complete;
                    let hash = n.hash;
                    let phase_changed = n.auth.is_some() && n.phase == MessagePhase::Ready;
                    if phase_changed {
                        n.phase = MessagePhase::AwaitingEpoch;
                    }
                    if changed {
                        self.rooms.get_mut(r)?.queue_dependants(&hash)?;
                    }
                    if phase_changed || changed {
                        self.event(Event::MessageChanged(
                            room,
                            hash,
                            self.rooms.get(r)?.nodes.get(slot)?.phase,
                        ))?;
                    }
                }
                Err(e @ Error::Protocol(Fault::Capacity | Fault::WouldBlock)) => {
                    self.rooms.get_mut(r)?.queue_node(slot)?;
                    // An elapsed deletion can release exactly the confirmation
                    // or payload that this original input is waiting for.
                    self.run_timers(r, now)?;
                    return Err(e);
                }
                Err(error) => {
                    let n = self.rooms.get_mut(r)?.nodes.get_mut(slot)?;
                    n.phase = MessagePhase::Rejected;
                    let hash = n.hash;
                    // A denied key/control transition cannot poison an actually
                    // authenticated outer DAG vertex. A failed body MAC grants
                    // no key, while later valid messages can still link to it.
                    let complete = self.rooms.get(r)?.graph_complete(slot, history)?;
                    let n = self.rooms.get_mut(r)?.nodes.get_mut(slot)?;
                    let changed = complete && !n.complete;
                    n.complete = complete;
                    if !n.frontier_applied {
                        self.rooms.get_mut(r)?.update_frontier(slot, self.mode)?;
                    }
                    if changed {
                        self.rooms.get_mut(r)?.queue_dependants(&hash)?;
                    }
                    self.event(Event::Rejected(room, hash, error))?;
                }
            }
            steps += 1;
        }
        // Completion is iterative, bounded and preserves the original session
        // generation while missing history is requested through its own source.
        for _ in steps..self.limits.work_per_turn {
            let completed = self.rooms.get_mut(r)?.completion_step(history)?;
            if let Some(s) = completed {
                self.event(Event::MemberChanged(
                    self.member_id(r, s),
                    SessionPhase::Completed,
                ))?;
            } else if !self.rooms.get(r)?.has_completion_work() {
                break;
            }
        }
        self.run_timers(r, now)?;
        Ok(steps)
    }
    fn apply_one(
        &mut self,
        r: Slot,
        slot: Slot,
        message: Message<'_>,
        #[cfg(feature = "alloc")] plain: Option<&Plaintext>,
        now: u64,
        archive: &mut AdvanceHistory<'_, '_, '_>,
    ) -> Result<(), Error> {
        let history = archive.view;
        let (source, meta, hash, was_applied) = {
            let n = self.rooms.get(r)?.nodes.get(slot)?;
            (
                n.origin.require_live(self.instance)?,
                n.meta,
                n.hash,
                n.semantic_applied,
            )
        };
        if self.rooms.get(r)?.nodes.get(slot)?.auth.is_none() {
            let Some(auth) = self.authenticate(source, message, &hash, meta)? else {
                self.rooms.get_mut(r)?.nodes.get_mut(slot)?.phase = MessagePhase::AwaitingSender;
                return Err(Fault::NotReady.into());
            };
            self.rooms
                .get(r)?
                .nodes
                .get(slot)?
                .layout
                .check_signer(auth.public, auth.peer)?;
            let historical = auth
                .session
                .and_then(|at| self.rooms.get(r).ok()?.sessions.get(at).ok())
                .is_some_and(|session| session.archived);
            let node = self.rooms.get_mut(r)?.nodes.get_mut(slot)?;
            node.auth = Some(auth);
            node.resume_pending = historical;
        }
        if self.mode == Mode::Service {
            self.register_service_ingress(r, slot, history)?;
        } else if self.rooms.get(r)?.nodes.get(slot)?.sequence == 0 {
            let room = self.rooms.get_mut(r)?;
            room.sequence = room.sequence.checked_add(1).ok_or(Fault::Overflow)?;
            room.nodes.get_mut(slot)?.sequence = room.sequence;
        }
        #[cfg(feature = "alloc")]
        self.wake_frontier_sync(r)?;
        // The authenticated outer DAG is independent of routing, epoch and
        // decryption prerequisites for the body.
        if !self.rooms.get(r)?.nodes.get(slot)?.frontier_applied {
            self.rooms.get_mut(r)?.update_frontier(slot, self.mode)?;
        }
        self.resolve_missing(r, &hash)?;
        let (parents, origin) = {
            let n = self.rooms.get(r)?.nodes.get(slot)?;
            (n.parents, n.origin.require_live(self.instance)?)
        };
        for p in parents {
            self.note_dependency_in(r, p, origin, history)?;
        }
        if self.rooms.get(r)?.nodes.get(slot)?.resume_pending
            && !self.rebind_historical(r, slot, history)?
        {
            return Err(Fault::NotReady.into());
        }
        if !was_applied && !self.rooms.get(r)?.nodes.get(slot)?.semantic_applied {
            let body = message.body();
            #[cfg(feature = "alloc")]
            let body = plain.map(Plaintext::body).transpose()?.unwrap_or(body);
            #[cfg(feature = "alloc")]
            if matches!(message.header().kind, Kind::PRIVATE | Kind::SECRET)
                && plain.is_none()
                && self.mode.is_client()
            {
                // AEAD/inner semantics can wait for a recipient key without
                // blocking this valid signed outer vertex in the room DAG.
                let complete = self.rooms.get(r)?.graph_complete(slot, history)?;
                let n = self.rooms.get_mut(r)?.nodes.get_mut(slot)?;
                let changed = complete && !n.complete;
                let phase_changed = n.phase != MessagePhase::AwaitingEpoch;
                n.complete = complete;
                n.phase = MessagePhase::AwaitingEpoch;
                let hash = n.hash;
                if changed {
                    self.rooms.get_mut(r)?.queue_dependants(&hash)?;
                }
                if phase_changed || changed {
                    self.event(Event::MessageChanged(
                        self.event_room(r),
                        hash,
                        MessagePhase::AwaitingEpoch,
                    ))?;
                }
                return Ok(());
            }
            self.rooms.get_mut(r)?.nodes.get_mut(slot)?.references =
                crate::ingest::references(body);
            if !(self.mode == Mode::Service
                && matches!(
                    body.kind(),
                    Kind::PRIVATE
                        | Kind::SECRET
                        | Kind::TRANSCRIPT
                        | Kind::ANNOUNCEMENT
                        | Kind::APPEAL
                        | Kind::ACCESS
                        | Kind::REVOLUTION
                        | Kind::GROUP
                        | Kind::AUTHORIZATION
                ))
            {
                self.apply_body(r, slot, message, body, now, archive)?;
            }
            if session_bound(body.kind())
                && let Some(s) = self
                    .rooms
                    .get(r)?
                    .nodes
                    .get(slot)?
                    .auth
                    .and_then(|a| a.session)
            {
                let hash = self.rooms.get(r)?.nodes.get(slot)?.hash;
                let session = self.rooms.get_mut(r)?.sessions.get_mut(s)?;
                session.last_bound = hash;
            }
            {
                let n = self.rooms.get_mut(r)?.nodes.get_mut(slot)?;
                n.semantic_applied = true;
                n.semantic_kind = body.kind();
            }
        }
        let complete = self.rooms.get(r)?.graph_complete(slot, history)?;
        let own_epoch_ready = {
            let row = self.rooms.get(r)?;
            let n = row.nodes.get(slot)?;
            !epoch_kind(n.kind)
                || row
                    .find_epoch(&n.hash)
                    .and_then(|e| row.epochs.get(e).ok())
                    .is_some_and(|e| e.complete)
        };
        let (changed, hash) = {
            let n = self.rooms.get_mut(r)?.nodes.get_mut(slot)?;
            let changed = complete && !n.complete;
            n.complete = complete;
            if n.phase != MessagePhase::Deleted {
                n.phase = if !own_epoch_ready {
                    MessagePhase::AwaitingEpoch
                } else if complete {
                    MessagePhase::Applied
                } else {
                    MessagePhase::AwaitingParents
                };
            }
            (changed, n.hash)
        };
        if changed || !was_applied {
            self.rooms.get_mut(r)?.queue_dependants(&hash)?;
        }
        if !was_applied || changed {
            let phase = self.rooms.get(r)?.nodes.get(slot)?.phase;
            self.event(Event::MessageChanged(self.event_room(r), hash, phase))?;
        }
        Ok(())
    }
    fn apply_body(
        &mut self,
        r: Slot,
        slot: Slot,
        outer: Message<'_>,
        body: Body<'_>,
        now: u64,
        archive: &mut AdvanceHistory<'_, '_, '_>,
    ) -> Result<(), Error> {
        let history = archive.view;
        let node = self.rooms.get(r)?.nodes.get(slot)?;
        let auth = node.auth.ok_or(Fault::Authentication)?;
        let hash = node.hash;
        match body {
            Body::Join {
                public_key,
                hpke_key,
                epoch,
            } => self.apply_join(
                r,
                slot,
                *outer.header().sender_id,
                *epoch,
                *public_key.as_bytes(),
                *hpke_key.as_bytes(),
            )?,
            Body::Leave { epoch } => {
                let session = auth.session.ok_or(Fault::Authentication)?;
                let contact = auth.owner.ok_or(Fault::Authentication)?.contact;
                let Some(previous) = self.rooms.get(r)?.find_epoch(epoch) else {
                    self.note_dependency(
                        r,
                        *epoch,
                        self.rooms
                            .get(r)?
                            .nodes
                            .get(slot)?
                            .origin
                            .require_live(self.instance)?,
                    )?;
                    return Err(Fault::NotReady.into());
                };
                let previous = self.rooms.get(r)?.epochs.get(previous)?;
                if !previous.complete {
                    return Err(Fault::NotReady.into());
                }
                if !self.rooms.get(r)?.epoch_has_member(previous, contact) {
                    return Err(Error::Permission);
                }
                self.epoch_message(r, slot, body)?;
                let s = self.rooms.get_mut(r)?.sessions.get_mut(session)?;
                s.phase = SessionPhase::Closing;
                s.last_bound = hash;
                if Some(s.public) == self.rooms.get(r)?.local_public {
                    self.rooms.get_mut(r)?.joined = false;
                }
                self.rooms.get_mut(r)?.schedule_completion(session)?;
                self.event(Event::MemberChanged(
                    self.member_id(r, session),
                    SessionPhase::Closing,
                ))?;
            }
            Body::Key {
                public_key,
                hpke_key,
            } => self.switch_session(
                r,
                slot,
                Some((*public_key.as_bytes(), *hpke_key.as_bytes())),
                None,
            )?,
            Body::Id { id } => self.switch_session(r, slot, None, Some(*id))?,
            Body::Name { name } => {
                let contact = auth.owner.ok_or(Fault::Authentication)?.contact;
                self.replace_contact_name(contact, name.content().expose())?;
                if let Some(s) = auth.session {
                    self.rooms.get_mut(r)?.sessions.get_mut(s)?.last_bound = hash;
                }
                self.event(Event::ContactChanged(self.contact_id(contact)))?;
            }
            Body::Info { version } => {
                if version != wire::VERSION {
                    return Err(Fault::Unsupported.into());
                }
            }
            Body::Peer { peer } => {
                if auth.peer != Some(*peer) {
                    return Err(Error::Permission);
                }
                if self.mode != Mode::Service || !node.requested {
                    let sequence = NonZeroU64::new(node.sequence).ok_or(Fault::Conflict)?;
                    self.rooms
                        .get_mut(r)?
                        .queues
                        .peers
                        .announce(*peer, PeerAnnouncement { hash, sequence })?;
                }
            }
            Body::Miss { peer } => {
                if self.mode == Mode::Service && node.requested {
                    return self.recover_peer_withdrawal(r, slot, peer, history);
                }
                let remote = self.mode == Mode::Service
                    && node.origin.is_first_received()
                    && matches!(node.origin.provenance().role, SourceRole::Peer(origin)
                        if self.local_peer != Some(origin))
                    && auth
                        .peer
                        .is_some_and(|signer| self.local_peer != Some(signer));
                let peers = &mut self.rooms.get_mut(r)?.queues.peers;
                let members_before =
                    remote.then(|| peers.iter().filter(|p| p.is_announced()).count());
                peers.remove(peer);
                if let Some(members_before) = members_before {
                    self.event(Event::ServicePeerMiss {
                        room: self.event_room(r),
                        members_before,
                    })?;
                }
            }
            Body::Merge { .. } => self.epoch_message(r, slot, body)?,
            Body::Request { .. } => {
                if auth.session.is_none() {
                    return Err(Error::Permission);
                }
                // The request authorizes its native owner's bounded history
                // exchange. It creates neither a graph dependency nor a GET.
            }
            Body::Deletion {
                hash: target,
                delay,
            } => {
                if delay.as_micros() == u64::MAX {
                    return Err(Fault::InvalidInput.into());
                }
                let session = auth.session.ok_or(Fault::Authentication)?;
                let room = self.rooms.get(r)?;
                let origin = room.nodes.get(slot)?;
                // The actual timeout helper caps remaining delay at 60s. Keep
                // that observable policy, using checked absolute arithmetic.
                let due = origin
                    .timestamp
                    .saturating_add(delay.as_micros())
                    .min(now.saturating_add(60_000_000));
                let session = room.sessions.get(session)?;
                if let Some(target_slot) = room.find_node(target) {
                    let target_node = room.nodes.get(target_slot)?;
                    if epoch_kind(target_node.kind) || !owns(session, target_node) {
                        return Err(Error::Permission);
                    }
                    let n = self.rooms.get_mut(r)?.nodes.get_mut(target_slot)?;
                    n.delete_at = Some(n.delete_at.map_or(due, |old| old.min(due)));
                    n.deleted_by = Some(hash);
                } else {
                    let target_row = match history {
                        Some(history) => {
                            history.plan_detached_deletion(target, session, due, hash, now)?
                        }
                        None => DetachedDeleteTarget::Missing,
                    };
                    match target_row {
                        DetachedDeleteTarget::Missing => {
                            let source = origin.origin.require_live(self.instance)?;
                            self.note_dependency(r, *target, source)?;
                            return Err(Fault::NotReady.into());
                        }
                        DetachedDeleteTarget::Deleted => (),
                        DetachedDeleteTarget::Mutation(mutation) => {
                            *archive.deletion.as_deref_mut().ok_or(Fault::WouldBlock)? =
                                Some(mutation);
                        }
                    }
                }
            }
            Body::Connection { amount, flags } => {
                let peer = auth.peer.ok_or(Fault::Authentication)?;
                if self.mode != Mode::Service || !node.requested {
                    self.rooms
                        .get_mut(r)?
                        .queues
                        .peers
                        .record_connection(&peer, ServiceConnection { amount, flags });
                }
            }
            Body::Subscription {
                discourse,
                time,
                flags,
            } => self.apply_subscription(r, slot, *discourse, time.as_micros(), flags)?,
            Body::Talk { discourse, .. } => {
                if self.mode == Mode::Service {
                    let timestamp = self.rooms.get(r)?.nodes.get(slot)?.timestamp;
                    if timestamp < self.rooms.get(r)?.discourse_cutoff(discourse) {
                        // The original frame is currently borrowed by advance;
                        // mark deletion and let its owner erase it on restoration.
                        let erased =
                            self.rooms
                                .get_mut(r)?
                                .erase_message(&mut self.frames, slot, None)?;
                        self.release(erased)?;
                    }
                }
            }
            #[cfg(feature = "alloc")]
            Body::Transcript {
                hash: original,
                recipient_key,
                data,
            } => {
                if !self.rooms.get(r)?.nodes.get(slot)?.local_sent {
                    return Err(Error::Permission);
                }
                let inner_layout = self
                    .rooms
                    .get(r)?
                    .nodes
                    .get(slot)?
                    .transcript_layout
                    .ok_or(Fault::NotReady)?;
                let checked = crypto::signature::decode_short_with_profiles(
                    data.expose(),
                    inner_layout.body,
                    inner_layout.padding,
                    padding::Decode::Absent,
                )?;
                if !crypto::message::permits_private(checked.short().body().kind()) {
                    return Err(Fault::Malformed.into());
                }
                let target = self
                    .rooms
                    .get(r)?
                    .find_node(original)
                    .ok_or(Fault::NotReady)?;
                let t = self.rooms.get(r)?.nodes.get(target)?;
                let transcript_owner = auth.owner.ok_or(Fault::Authentication)?;
                let original_owner = t.auth.and_then(|a| a.owner).ok_or(Fault::Authentication)?;
                if !t.local_sent
                    || original_owner.contact != transcript_owner.contact
                    || original_owner.lineage != transcript_owner.lineage
                    || original_owner.generation > transcript_owner.generation
                    || t.phase == MessagePhase::Deleted
                {
                    return Err(Error::Permission);
                }
                if t.recipient
                    .as_ref()
                    .and_then(RecipientAttribution::public_key)
                    .or(t.private_recipient.as_ref())
                    .is_some_and(|original| original != recipient_key.as_bytes())
                {
                    return Err(Error::AttributionConflict);
                }
                let plain = Plaintext::new(
                    OwnedBytes::copy_from(data.expose())?,
                    inner_layout,
                    padding::Decode::Absent,
                );
                self.charge(plain.capacity())?;
                let target = self.rooms.get_mut(r)?.nodes.get_mut(target)?;
                let old = target.plaintext.replace(plain);
                target.transcript = Some(hash);
                target.private_recipient = Some(*recipient_key.as_bytes());
                if target.recipient.is_none() {
                    target.recipient =
                        Some(RecipientAttribution::transcript(*recipient_key.as_bytes()));
                }
                if let Some(old) = old {
                    self.release(old.capacity())?;
                }
                let target_slot = target_slot(self.rooms.get(r)?, original)?;
                self.rooms.get_mut(r)?.queue_node(target_slot)?;
            }
            #[cfg(feature = "alloc")]
            Body::Announcement { .. }
            | Body::Appeal { .. }
            | Body::Access { .. }
            | Body::Revolution { .. }
            | Body::Group { .. }
            | Body::Authorization { .. } => self.epoch_control(r, slot, outer, now)?,
            #[cfg(not(feature = "alloc"))]
            Body::Announcement { .. }
            | Body::Appeal { .. }
            | Body::Access { .. }
            | Body::Revolution { .. }
            | Body::Group { .. }
            | Body::Authorization { .. }
            | Body::Transcript { .. } => {}
            // Service stores authentic ciphertext without possessing client
            // recipient/epoch keys. Applications retain the exact typed bytes.
            Body::Private { .. }
            | Body::Secret { .. }
            | Body::Invite { .. }
            | Body::Text { .. }
            | Body::File { .. }
            | Body::Ticket { .. }
            | Body::Tag { .. } => {}
        }
        Ok(())
    }
    fn prepare_join_contact(
        &self,
        r: Slot,
        id: ShortHash,
        public: PublicKey,
    ) -> Result<(Slot, Option<ContactRow>), Error> {
        let context = if public == self.anonymous {
            let digest = hash512(&id);
            let key = self.rooms.get(r)?.key;
            let mut context = [0; 64];
            for i in 0..64 {
                context[i] = digest[i] ^ key[i];
            }
            Some(context)
        } else {
            None
        };
        if let Some((s, _)) = self
            .contacts
            .iter()
            .find(|(_, c)| c.canonical && c.key == public && c.anonymous_context == context)
        {
            return Ok((s, None));
        }
        let key = self.contacts.next_key()?;
        Ok((
            key,
            Some(ContactRow {
                key: public,
                name: None,
                anonymous_context: context,
                #[cfg(feature = "alloc")]
                local: Some(public) == self.rooms.get(r)?.local_public,
                canonical: true,
                rooms: 0,
            }),
        ))
    }
    fn apply_join(
        &mut self,
        r: Slot,
        node: Slot,
        id: ShortHash,
        parent: Hash,
        public: PublicKey,
        hpke: PublicKey,
    ) -> Result<(), Error> {
        let hash = self.rooms.get(r)?.nodes.get(node)?.hash;
        let prior = self.rooms.get(r)?.sessions.iter().find_map(|(s, m)| {
            (m.id == id
                && m.public == public
                && (m.phase != SessionPhase::Completed
                    || m.archived && m.historical_phase == SessionPhase::Active)
                && m.successor.is_none())
            .then_some(s)
        });
        let (contact, new_contact, new_lineage) = if let Some(s) = prior {
            (self.rooms.get(r)?.sessions.get(s)?.contact, None, None)
        } else {
            let row = self.rooms.get(r)?;
            row.sessions.next_key()?;
            let lineage = row.lineage.checked_add(1).ok_or(Fault::Overflow)?;
            let (contact, new_contact) = self.prepare_join_contact(r, id, public)?;
            (contact, new_contact, Some(lineage))
        };
        // The signed vertex can be observed and can request its parent before
        // this point, but its contact and session do not exist until the epoch
        // snapshot fits and its inherited membership is known.
        self.reserve_events(4)?;
        let epoch_changed = self.prepare_join_epoch(r, node, parent, contact)?;
        if let Some(row) = new_contact {
            let vacant = self.contacts.vacant()?;
            vacant.insert(row);
            self.event(Event::ContactChanged(self.contact_id(contact)))?;
        }
        let session = if let Some(lineage) = new_lineage {
            let room = self.rooms.get_mut(r)?;
            let session = room
                .sessions
                .insert(SessionRow {
                    contact,
                    id,
                    public,
                    hpke,
                    lineage,
                    generation: 1,
                    known_from: room.sequence,
                    phase: SessionPhase::Active,
                    first_bound: hash,
                    last_bound: hash,
                    successor: None,
                    completed_at: None,
                    archived: false,
                    historical_phase: SessionPhase::Active,
                })
                .map_err(|(error, _)| error)?;
            room.lineage = lineage;
            self.contacts.get_mut(contact)?.rooms += 1;
            session
        } else {
            prior.ok_or(Fault::Conflict)?
        };
        {
            let room = self.rooms.get_mut(r)?;
            let s = room.sessions.get_mut(session)?;
            let resumed = s.archived && s.historical_phase == SessionPhase::Active;
            s.archived = false;
            s.historical_phase = SessionPhase::Active;
            s.phase = SessionPhase::Active;
            if !resumed {
                s.first_bound = hash;
            }
            s.last_bound = hash;
            s.hpke = hpke;
            s.completed_at = None;
            let a = room
                .nodes
                .get_mut(node)?
                .auth
                .as_mut()
                .ok_or(Fault::Authentication)?;
            a.owner = Some(owner(s));
            a.session = Some(session);
            let own = Some(public) == room.local_public && Some(id) == room.local_id;
            if self.mode.is_client() {
                // Source readiness is settled only by the original JOIN's
                // independent full-write and authenticated-echo observations.
                if own
                    && room
                        .nodes
                        .get(node)?
                        .origin
                        .live(self.instance)
                        .is_some_and(|origin| {
                            room.sources.get(origin.slot).is_ok_and(|source| {
                                source.role == SourceRole::Client
                                    && source.create_written
                                    && !source.join_required
                                    && source.public == Some(public)
                                    && source.member_id == Some(id)
                            })
                        })
                {
                    room.joined = true;
                }
            } else if own {
                room.joined = true;
                for (_, source) in room.sources.iter_mut() {
                    if source.member_id == Some(id) {
                        source.join_required = false;
                    }
                }
            }
        }
        if epoch_changed {
            self.publish_epoch(r, hash)?;
        }
        self.wake_senders(r)?;
        self.event(Event::MemberChanged(
            self.member_id(r, session),
            SessionPhase::Active,
        ))?;
        Ok(())
    }
    // Resolve only an unapplied KEY whose verified signing identity remains
    // identical across actual successor sessions. Historical hashes and every
    // other message keep their original authentication; arrival order alone is
    // not permission to advance a cached owner to a later generation.
    fn key_successor(&mut self, r: Slot, node: Slot, auth: Authentication) -> Result<Slot, Error> {
        let first = auth.session.ok_or(Fault::Authentication)?;
        let row = self.rooms.get(r)?;
        let original = row.sessions.get(first)?;
        if auth.peer.is_some()
            || auth.public != original.public
            || auth.owner != Some(owner(original))
        {
            return Err(Fault::Authentication.into());
        }
        let Some(next) = original.successor else {
            return Ok(first);
        };
        let next = row.sessions.get(next)?;
        if next.public != original.public || next.id != original.id {
            return Ok(first);
        }
        let original_public = original.public;
        let original_id = original.id;
        let original_contact = original.contact;
        let original_lineage = original.lineage;
        let prove = |workspace: &mut HistoryWorkspace<'_>, width| {
            let mut ancestry = workspace.start(width, node.index)?;
            let mut missing = false;
            // The immutable room pins every generation for this walk. No
            // unauthenticated predecessor supplies a causal edge or authority.
            while let Some(index) = ancestry.pop() {
                let slot = row.nodes.slot_at(index).ok_or(Fault::Conflict)?;
                let current = row.nodes.get(slot)?;
                if current.auth.is_none() {
                    missing = true;
                    continue;
                }
                for hash in current.parents {
                    if hash == [0; 64] {
                        continue;
                    }
                    let Some(parent) = row.find_node(&hash) else {
                        missing = true;
                        continue;
                    };
                    ancestry.schedule(parent.index)?;
                }
            }
            let mut current = first;
            for _ in 0..row.sessions.len() {
                let old = row.sessions.get(current)?;
                let Some(next) = old.successor else {
                    return Ok(current);
                };
                let successor = row.sessions.get(next)?;
                if successor.public != original_public || successor.id != original_id {
                    return Ok(current);
                }
                if successor.contact != original_contact
                    || successor.lineage != original_lineage
                    || successor.generation
                        != old.generation.checked_add(1).ok_or(Fault::Overflow)?
                    || successor.archived
                {
                    return Err(Fault::StaleGeneration.into());
                }
                // last_bound may include late historical NAME/LEAVE traffic.
                // The accepted transition node retains its immutable hash/auth
                // even after its payload is erased; exactly one closes a session.
                let mut transitions = row.nodes.iter().filter_map(|(slot, message)| {
                    (message.semantic_applied
                        && matches!(message.semantic_kind, Kind::KEY | Kind::ID)
                        && message.auth.is_some_and(|a| {
                            a.session == Some(current) && a.owner == Some(owner(old))
                        }))
                    .then_some(slot)
                });
                let transition = transitions.next().ok_or(Fault::NotReady)?;
                if transitions.next().is_some() {
                    return Err(Fault::Conflict.into());
                }
                if !ancestry.contains(transition.index) {
                    return Err(if missing {
                        Fault::NotReady
                    } else {
                        Fault::Replay
                    }
                    .into());
                }
                current = next;
            }
            Err(Fault::Conflict.into())
        };
        if let Some(workspace) = self.ancestry.as_mut() {
            return prove(workspace, row.nodes.limit());
        }
        #[cfg(not(feature = "alloc"))]
        return Err(Fault::Conflict.into());
        #[cfg(feature = "alloc")]
        {
            // The heap-backed owner only needs marks through the highest occupied
            // index, even when the configured room capacity is much larger.
            let width = row
                .index
                .iter()
                .map(|slot| slot.index)
                .max()
                .ok_or(Fault::Conflict)?
                .checked_add(1)
                .ok_or(Fault::Overflow)?;
            let mut workspace = HistoryWorkspace::budgeted(width, self.remaining_bytes())?;
            prove(&mut workspace, width)
        }
    }
    fn switch_session(
        &mut self,
        r: Slot,
        node: Slot,
        key: Option<(PublicKey, PublicKey)>,
        id: Option<ShortHash>,
    ) -> Result<(), Error> {
        let auth = self
            .rooms
            .get(r)?
            .nodes
            .get(node)?
            .auth
            .ok_or(Fault::Authentication)?;
        let old = if key.is_some() {
            self.key_successor(r, node, auth)?
        } else {
            auth.session.ok_or(Fault::Authentication)?
        };
        let old_row = self.rooms.get(r)?.sessions.get(old)?;
        if old_row.successor.is_some() || old_row.phase == SessionPhase::Completed {
            return Err(Fault::Replay.into());
        }
        let (public, hpke) = key.unwrap_or((old_row.public, old_row.hpke));
        let id = id.unwrap_or(old_row.id);
        if public == old_row.public && id == old_row.id && hpke == old_row.hpke {
            return Err(Fault::Replay.into());
        }
        let generation = old_row.generation.checked_add(1).ok_or(Fault::Overflow)?;
        let hash = self.rooms.get(r)?.nodes.get(node)?.hash;
        let contact = old_row.contact;
        let successor = SessionRow {
            contact,
            id,
            public,
            hpke,
            lineage: old_row.lineage,
            generation,
            known_from: old_row.known_from,
            phase: SessionPhase::Active,
            first_bound: old_row.first_bound,
            last_bound: hash,
            successor: None,
            completed_at: None,
            archived: false,
            historical_phase: SessionPhase::Active,
        };
        let old_public = old_row.public;
        let old_id = old_row.id;
        let resolved_auth = Authentication {
            owner: Some(owner(old_row)),
            session: Some(old),
            ..auth
        };
        self.rooms.get(r)?.sessions.next_key()?;
        let canonical = !self.contacts.iter().any(|(s, c)| {
            s != contact && c.canonical && c.key == public && c.anonymous_context.is_none()
        });
        if key.is_some() {
            let c = self.contacts.get_mut(contact)?;
            c.key = public;
            c.canonical = canonical;
        }
        if public == self.anonymous {
            let digest = hash512(&id);
            let key = self.rooms.get(r)?.key;
            let mut context = [0; 64];
            for i in 0..64 {
                context[i] = digest[i] ^ key[i];
            }
            self.contacts.get_mut(contact)?.anonymous_context = Some(context);
        } else {
            self.contacts.get_mut(contact)?.anonymous_context = None;
        }
        let room = self.rooms.get_mut(r)?;
        let next = room.sessions.insert(successor).map_err(|(e, _)| e)?;
        // All fallible preflight and successor allocation precede the original
        // unapplied KEY's causal owner binding. Known historical hashes never
        // reach this transition or have their original author rewritten.
        room.nodes.get_mut(node)?.auth = Some(resolved_auth);
        let old = room.sessions.get_mut(old)?;
        old.successor = Some(next);
        old.phase = SessionPhase::Closing;
        old.last_bound = hash;
        for (_, s) in room.sources.iter_mut() {
            if s.public == Some(old_public) && s.member_id == Some(old_id) {
                s.public = Some(public);
                s.member_id = Some(id);
                s.pending_member_id = None;
            }
        }
        if room.local_public == Some(old_public) && room.local_id == Some(old_id) {
            room.local_public = Some(public);
            room.local_id = Some(id);
        }
        room.schedule_completion(resolved_auth.session.ok_or(Fault::Authentication)?)?;
        self.wake_senders(r)?;
        self.event(Event::MemberChanged(
            self.member_id(r, next),
            SessionPhase::Active,
        ))?;
        self.event(Event::ContactChanged(self.contact_id(contact)))?;
        Ok(())
    }
    pub(crate) fn wake_senders(&mut self, r: Slot) -> Result<(), Error> {
        let row = self.rooms.get_mut(r)?;
        for i in 0..row.index.len() {
            let slot = row.index[i];
            if row.nodes.get(slot)?.phase == MessagePhase::AwaitingSender {
                row.queue_node(slot)?;
            }
        }
        Ok(())
    }
    fn apply_subscription(
        &mut self,
        r: Slot,
        node: Slot,
        discourse: ShortHash,
        duration: u64,
        flags: u32,
    ) -> Result<(), Error> {
        let n = self.rooms.get(r)?.nodes.get(node)?;
        let owner = n.auth.and_then(|a| a.owner).ok_or(Fault::Authentication)?;
        let start = n.timestamp;
        let end = if flags & 1 != 0 {
            start
        } else {
            start.saturating_add(duration)
        };
        let local = n.local_sent;
        let row = self.rooms.get_mut(r)?;
        let existing = row.subscriptions.iter().find_map(|(s, x)| {
            (x.lineage == owner.lineage && x.discourse == discourse).then_some(s)
        });
        let keep_alive = flags & 2 != 0 && flags & 1 == 0 && local;
        let renew_at = (keep_alive && duration != u64::MAX)
            .then_some(start.saturating_add(duration / 10 * 9 + (duration % 10) * 9 / 10));
        if let Some(s) = existing {
            let old = row.subscriptions.get_mut(s)?;
            if end < old.start {
                return Ok(());
            }
            old.start = old.start.min(start);
            old.end = end;
            old.keep_alive = keep_alive;
            old.duration = duration;
            old.renew_at = renew_at;
            old.renew_operation = None;
        } else {
            row.subscriptions
                .insert(Subscription {
                    contact: owner.contact,
                    discourse,
                    lineage: owner.lineage,
                    start,
                    end,
                    keep_alive,
                    duration,
                    renew_at,
                    renew_operation: None,
                })
                .map_err(|(e, _)| e)?;
        }
        self.event(Event::SubscriptionChanged(
            self.event_room(r),
            self.contact_id(owner.contact),
            discourse,
        ))?;
        Ok(())
    }
    pub(crate) fn note_dependency(
        &mut self,
        r: Slot,
        hash: Hash,
        source: Source<'id>,
    ) -> Result<(), Error> {
        self.note_dependency_in(r, hash, source, None)
    }
    fn note_dependency_in(
        &mut self,
        r: Slot,
        hash: Hash,
        source: Source<'id>,
        history: Option<&CommittedRoomHistory<'_, '_>>,
    ) -> Result<(), Error> {
        // A historical original may already have stopped. Keep its generation
        // so the missing row can be retired without transferring it to a new source.
        if source.core != self.instance || source.room != r {
            return Err(Fault::StaleGeneration.into());
        }
        if hash == [0; 64] || self.rooms.get(r)?.find_node(&hash).is_some() {
            return Ok(());
        }
        if let Some(history) = history
            && history.detached_parent(&hash)?.is_some()
        {
            return Ok(());
        }
        if self
            .rooms
            .get(r)?
            .missing
            .iter()
            .any(|(_, m)| m.hash == hash && m.source == source.slot)
        {
            // Its original admission deadline and actual absence are retained.
            return Ok(());
        }
        self.rooms
            .get_mut(r)?
            .missing
            .insert(MissingRow {
                hash,
                source: source.slot,
                #[cfg(feature = "alloc")]
                operation: None,
                retry_at: 0,
                absent: false,
            })
            .map_err(|(e, _)| e)?;
        self.event(Event::Missing(self.event_room(r), hash))?;
        Ok(())
    }
    pub(crate) fn resolve_missing(&mut self, r: Slot, hash: &Hash) -> Result<(), Error> {
        loop {
            let next = self
                .rooms
                .get(r)?
                .missing
                .iter()
                .find_map(|(s, m)| (m.hash == *hash).then_some(s));
            let Some(s) = next else {
                break;
            };
            let row = self.rooms.get_mut(r)?;
            row.missing.remove(s)?;
            #[cfg(feature = "alloc")]
            row.derivation.arm();
        }
        Ok(())
    }
    /// Acknowledge a real absence/lost original source to free only its logical
    /// retrieval row. This never cancels or moves an outstanding wire operation.
    pub fn retire_missing(
        &mut self,
        room: Room<'id>,
        hash: &Hash,
        source: Source<'id>,
    ) -> Result<(), Error> {
        let r = self.check_room(room)?;
        if source.core != self.instance || source.room != r {
            return Err(Fault::NotFound.into());
        }
        let slot = self
            .rooms
            .get(r)?
            .missing
            .iter()
            .find_map(|(s, m)| (m.hash == *hash && m.source == source.slot).then_some(s))
            .ok_or(Fault::NotFound)?;
        let m = self.rooms.get(r)?.missing.get(slot)?;
        if !m.absent
            && self.check_source(source).is_ok()
            && self.rooms.get(r)?.find_node(hash).is_none()
        {
            return Err(Fault::NotReady.into());
        }
        self.rooms.get_mut(r)?.missing.remove(slot)?;
        Ok(())
    }
    fn run_timers(&mut self, r: Slot, now: u64) -> Result<(), Error> {
        let mut remaining = self.limits.work_per_turn;
        while remaining > 0 {
            let due = self.rooms.get(r)?.nodes.iter().find_map(|(s, n)| {
                (n.phase != MessagePhase::Deleted && n.delete_at.is_some_and(|t| t <= now))
                    .then_some(s)
            });
            let Some(slot) = due else {
                break;
            };
            self.reserve_events(2)?;
            let (hash, by) = {
                let n = self.rooms.get(r)?.nodes.get(slot)?;
                (n.hash, n.deleted_by)
            };
            #[cfg(feature = "alloc")]
            self.revoke_confirmation(r, &hash)?;
            let released = self
                .rooms
                .get_mut(r)?
                .erase_message(&mut self.frames, slot, by)?;
            self.release(released)?;
            self.event(Event::MessageChanged(
                self.event_room(r),
                hash,
                MessagePhase::Deleted,
            ))?;
            remaining -= 1;
        }
        while remaining > 0 {
            let expired = self
                .rooms
                .get(r)?
                .subscriptions
                .iter()
                .find_map(|(s, x)| (x.end < now && !x.keep_alive).then_some(s));
            let Some(s) = expired else {
                break;
            };
            self.reserve_events(1)?;
            let sub = self.rooms.get_mut(r)?.subscriptions.remove(s)?;
            self.event(Event::SubscriptionChanged(
                self.event_room(r),
                self.contact_id(sub.contact),
                sub.discourse,
            ))?;
            remaining -= 1;
        }
        if self.mode == Mode::Service {
            for i in 0..self.rooms.get(r)?.index.len() {
                if remaining == 0 {
                    break;
                }
                let s = self.rooms.get(r)?.index[i];
                let n = self.rooms.get(r)?.nodes.get(s)?;
                if n.auth.is_none() || !discourse_kind(n.kind) || n.phase == MessagePhase::Deleted {
                    continue;
                }
                if let Some(d) = n.discourse
                    && n.timestamp < self.rooms.get(r)?.discourse_cutoff(&d)
                {
                    self.reserve_events(1)?;
                    let hash = self.rooms.get(r)?.nodes.get(s)?.hash;
                    let b = self
                        .rooms
                        .get_mut(r)?
                        .erase_message(&mut self.frames, s, None)?;
                    self.release(b)?;
                    self.event(Event::MessageChanged(
                        self.event_room(r),
                        hash,
                        MessagePhase::Deleted,
                    ))?;
                    remaining -= 1;
                }
            }
        }
        Ok(())
    }
    /// Decrypt with actual retained authorized epoch/recipient capabilities and
    /// caller-owned bounded scratch. The service mode never decrypts client
    /// content. No plaintext is installed until AEAD and inner hash both pass.
    #[cfg(feature = "alloc")]
    pub fn decrypt_message<const N: usize>(
        &mut self,
        room: Room<'id>,
        hash: &Hash,
        scratch: &mut SensitiveBuffer<N>,
    ) -> Result<(), Error> {
        if !self.mode.is_client() {
            return Err(Error::Permission);
        }
        let r = self.check_room(room)?;
        let slot = self.rooms.get(r)?.find_node(hash).ok_or(Fault::NotFound)?;
        let row = self.rooms.get(r)?;
        let node = row.nodes.get(slot)?;
        if node.auth.is_none() || node.phase == MessagePhase::Deleted || node.plaintext.is_some() {
            return Err(Fault::NotReady.into());
        }
        let message = node.message(&self.frames)?;
        let cipher_layout = node.cipher_layout.ok_or(Fault::NotReady)?;
        let mut recipient = None;
        let opened = match message.body() {
            Body::Secret { identifier, .. } => {
                let e = row
                    .epochs
                    .get(row.find_epoch(&node.epoch).ok_or(Fault::NotReady)?)?;
                if !e.complete
                    || !node
                        .auth
                        .and_then(|a| a.owner)
                        .is_some_and(|o| row.epoch_has_member(e, o.contact))
                {
                    return Err(Error::Permission);
                }
                let (_, g) = e
                    .groups
                    .iter()
                    .find(|(_, g)| g.identifier == *identifier && g.key.is_some())
                    .ok_or(Fault::NotReady)?;
                if crate::epoch::identifier_order(g.identifier_order, identifier).0 {
                    return Err(Error::Permission);
                }
                scratch.open_secret_with_profiles(
                    message,
                    identifier,
                    g.key.as_ref().ok_or(Fault::NotReady)?,
                    cipher_layout.body,
                    cipher_layout.padding,
                )?;
                true
            }
            Body::Private { .. } => {
                let mut opened = false;
                for key in &row.queues.hpke_keys {
                    match scratch.open_private_with_profiles(
                        message,
                        &key.secret,
                        cipher_layout.body,
                        cipher_layout.padding,
                    ) {
                        Ok(_) => {
                            recipient = Some(RecipientAttribution::from_key(key));
                            opened = true;
                            break;
                        }
                        Err(crypto::Error::Protocol(Fault::Authentication)) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                opened
            }
            _ => return Err(Fault::InvalidInput.into()),
        };
        if !opened {
            scratch.clear();
            return Err(Fault::Authentication.into());
        }
        let plain_layout = cipher_layout;
        let copied = (|| -> Result<Plaintext, Error> {
            let checked = crypto::signature::decode_short_with_profiles(
                scratch.expose(),
                plain_layout.body,
                plain_layout.padding,
                padding::Decode::Required,
            )?;
            if !crypto::message::permits_private(checked.short().body().kind()) {
                return Err(Fault::Malformed.into());
            }
            Ok(Plaintext::new(
                OwnedBytes::copy_from(scratch.expose())?,
                plain_layout,
                padding::Decode::Required,
            ))
        })();
        scratch.clear();
        let plain = copied?;
        self.charge(plain.capacity())?;
        let node = self.rooms.get_mut(r)?.nodes.get_mut(slot)?;
        node.plaintext = Some(plain);
        if node.recipient.is_none() {
            node.recipient = recipient;
        }
        self.rooms.get_mut(r)?.queue_node(slot)?;
        Ok(())
    }
    /// Recover only historical local decryption capability from an explicitly
    /// authorized private-zone record. The caller must bind its actual original
    /// NAMESTORE query/monitor, zone, source, room and finite deadline before this
    /// call. This is neither a native receipt nor persistence evidence. It grants
    /// no old membership, sender identity, future-send or epoch authorization.
    #[cfg(feature = "alloc")]
    pub fn recover_encryption_record(
        &mut self,
        source: Source<'id>,
        zone_public: PublicKey,
        root: &crypto::records::RecordSecret,
        record: wire::records::Record<'_>,
    ) -> Result<bool, Error> {
        self.check_source(source)?;
        let row = self.rooms.get(source.room)?;
        let src = row.sources.get(source.slot)?;
        let wire::records::Record::EncryptionKey { room_key, .. } = record else {
            return Err(Fault::InvalidInput.into());
        };
        if !self.mode.is_client()
            || src.role != SourceRole::Client
            || !src.create_written
            || src.public != Some(zone_public)
            || row.local_public != Some(zone_public)
            || *room_key != row.key
        {
            return Err(Error::Permission);
        }
        // Authenticate and parse the complete ciphertext even for a duplicate;
        // a matching public key cannot turn a corrupt record into a success.
        let key = crypto::records::open_encryption_record(root, record)?;
        let public = key.public_key();
        if let Some(index) = row
            .queues
            .hpke_keys
            .iter()
            .position(|old| old.secret.public_key() == public)
        {
            self.rooms
                .get_mut(source.room)?
                .queues
                .hpke_keys
                .get_mut(index)
                .ok_or(Fault::Conflict)?
                .merge_origin(RecipientKeyOrigin::Zone(zone_public));
            // Existing ciphertext capability is not another key installation.
            return Ok(false);
        }

        self.rooms
            .get_mut(source.room)?
            .queues
            .hpke_keys
            .push(RecipientKey {
                secret: key,
                origin: RecipientKeyOrigin::Zone(zone_public),
            })?;
        Ok(true)
    }
    /// Register an actual locally owned HPKE recipient key after checking its
    /// public component against a real current local member's advertised key.
    #[cfg(feature = "alloc")]
    pub fn retain_recipient_key(
        &mut self,
        member: MemberSession<'id>,
        key: crypto::EcdheSecret,
    ) -> Result<(), Error> {
        self.check_member(member)?;
        let row = self.rooms.get(member.room)?;
        let session = row.sessions.get(member.slot)?;
        if row.local_session() != Some(member.slot)
            || !self.contacts.get(session.contact)?.local
            || session.phase != SessionPhase::Active
            || key.public_key().as_bytes() != &session.hpke[4..]
        {
            return Err(Error::Permission);
        }
        let origin =
            RecipientKeyOrigin::Member(MemberRecipient::new(owner(session), session.public));
        let public = key.public_key();
        if let Some(index) = row
            .queues
            .hpke_keys
            .iter()
            .position(|old| old.secret.public_key() == public)
        {
            self.rooms
                .get_mut(member.room)?
                .queues
                .hpke_keys
                .get_mut(index)
                .ok_or(Fault::Conflict)?
                .merge_origin(origin);
            return Ok(());
        }
        let row = self.rooms.get_mut(member.room)?;

        row.queues.hpke_keys.push(RecipientKey {
            secret: key,
            origin,
        })?;
        Ok(())
    }
}
#[cfg(feature = "alloc")]
fn target_slot(room: &RoomRow, hash: &Hash) -> Result<Slot, Error> {
    room.find_node(hash).ok_or(Fault::NotFound.into())
}

#[cfg(all(test, feature = "alloc"))]
mod join_tests;
#[cfg(all(test, feature = "alloc"))]
mod key_refresh_tests;

#[cfg(all(test, feature = "alloc"))]
mod subscription_tests {
    use super::*;
    use crate::model::{node, structural_core};

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Actual subscription transition over existing public structural metadata"
    )]
    fn forever_timer_and_local_pause_preserve_the_signed_interval() -> Result<(), Error> {
        let mut instance = Instance::new();
        let mut core = structural_core(&mut instance)?;
        let room = core.room([1; 64], None)?;
        let source = core.attach_source(
            room,
            SourceRole::Client,
            wire::padding::Decode::Absent,
            None,
        )?;
        let mut original = node(core.instance, 1, 0, 1, 1, 1)?;
        original.local_sent = true;
        original.timestamp = 5;
        let first = core.rooms.get_mut(room.slot)?.insert_node(original)?;
        core.apply_subscription(room.slot, first, [7; 32], u64::MAX, 2)?;
        let (_, interval) = core
            .rooms
            .get(room.slot)?
            .subscriptions
            .iter()
            .next()
            .ok_or(Fault::NotFound)?;
        assert!(interval.keep_alive && interval.renew_at.is_none());
        assert_eq!(interval.end, u64::MAX);
        assert_eq!(core.next_deadline(room)?, None);

        let mut finite = node(core.instance, 2, 1, 1, 1, 2)?;
        finite.local_sent = true;
        finite.timestamp = 10;
        let second = core.rooms.get_mut(room.slot)?.insert_node(finite)?;
        core.apply_subscription(room.slot, second, [7; 32], u64::MAX - 1, 2)?;
        let (_, interval) = core
            .rooms
            .get(room.slot)?
            .subscriptions
            .iter()
            .next()
            .ok_or(Fault::NotFound)?;
        assert_eq!(interval.end, u64::MAX);
        assert!(interval.renew_at.is_some()); // finite duration, even with saturated end
        let signed_interval = (interval.start, interval.end);
        let operations = core.operations(room)?.count();
        core.pause_subscription_renewals(source)?;
        let (_, interval) = core
            .rooms
            .get(room.slot)?
            .subscriptions
            .iter()
            .next()
            .ok_or(Fault::NotFound)?;
        assert_eq!((interval.start, interval.end), signed_interval);
        assert!(interval.renew_at.is_none());
        assert_eq!(core.operations(room)?.count(), operations);
        Ok(())
    }
}
