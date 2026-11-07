//! Actual bounded semantic application, member lineage and timer progression.
use crate::{engine::Core, graph::*, state::*, *};
use gnunet_crypto::hash512;
use gnunet_types::Error as Fault;
use wire::{
    body::Body,
    envelope::Kind,
    message::{Message, Short},
    padding,
};
impl<'id> Core<'id> {
    /// Perform a finite number of admitted transitions. A missing parent/signer/
    /// key remains deferred and is woken only by relevant actual input. Native
    /// writes, entropy and signatures remain original caller-port work.
    pub fn advance(&mut self, room: Room<'id>, now: u64) -> Result<usize, Error> {
        let r = self.check_room(room)?;
        self.refresh_epochs(r)?;
        let mut steps = 0;
        for _ in 0..self.limits.work_per_turn {
            self.reserve_events(6)?;
            let next = self.rooms.get_mut(r)?.ready.pop_front();
            let Some(slot) = next else {
                break;
            };
            self.rooms.get_mut(r)?.nodes.get_mut(slot)?.queued = false;
            if matches!(
                self.rooms.get(r)?.nodes.get(slot)?.origin,
                MessageOrigin::Archived(_)
            ) {
                // A restored graph can become complete after real parents arrive,
                // but no old semantic handler may mint current membership/keys.
                let complete = self.rooms.get(r)?.graph_complete(slot)?;
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
                let complete = self.rooms.get(r)?.graph_complete(slot)?;
                let n = self.rooms.get_mut(r)?.nodes.get_mut(slot)?;
                let changed = complete && !n.complete;
                n.complete = complete;
                let hash = n.hash;
                if changed {
                    self.rooms.get_mut(r)?.queue_dependants(&hash)?;
                }
                continue;
            }
            let (frame, plain, pad, plain_pad) = {
                let node = self.rooms.get_mut(r)?.nodes.get_mut(slot)?;
                (
                    node.frame.take(),
                    node.plaintext.take(),
                    node.padding,
                    node.plain_padding,
                )
            };
            let Some(frame) = frame else {
                if self.rooms.get(r)?.nodes.get(slot)?.auth.is_some() {
                    let complete = self.rooms.get(r)?.graph_complete(slot)?;
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
            let result = (|| {
                let layout = self.rooms.get(r)?.nodes.get(slot)?.layout;
                let message = Message::decode_with_profiles(
                    frame.expose(),
                    layout.body_profile(self.rooms.get(r)?.nodes.get(slot)?.kind)?,
                    layout.padding,
                    pad,
                )?;
                self.apply_one(
                    r,
                    slot,
                    message,
                    plain.as_ref().map(OwnedBytes::expose),
                    plain_pad,
                    now,
                )
            })();
            // Restore the exact original owners before handling every result.
            // No internal callback can substitute another frame or key owner.
            let deleted = self.rooms.get(r)?.nodes.get(slot)?.phase == MessagePhase::Deleted;
            if deleted {
                self.release(frame.capacity() + plain.as_ref().map_or(0, OwnedBytes::capacity))?;
            } else {
                let n = self.rooms.get_mut(r)?.nodes.get_mut(slot)?;
                n.frame = Some(frame);
                n.plaintext = plain;
            }
            match result {
                Ok(()) => {}
                Err(Error::Protocol(Fault::NotReady | Fault::NotFound)) => {
                    let n = self.rooms.get_mut(r)?.nodes.get_mut(slot)?;
                    if n.auth.is_some() && n.phase == MessagePhase::Ready {
                        n.phase = MessagePhase::AwaitingEpoch;
                        let hash = n.hash;
                        self.event(Event::MessageChanged(
                            room,
                            hash,
                            MessagePhase::AwaitingEpoch,
                        ))?;
                    }
                }
                Err(e @ Error::Protocol(Fault::Capacity | Fault::WouldBlock)) => {
                    self.rooms.get_mut(r)?.queue_node(slot)?;
                    return Err(e);
                }
                Err(error) => {
                    let n = self.rooms.get_mut(r)?.nodes.get_mut(slot)?;
                    n.phase = MessagePhase::Rejected;
                    let hash = n.hash;
                    // A denied key/control transition cannot poison an actually
                    // authenticated outer DAG vertex. AUTH's omitted MAC grants
                    // no key, while later valid C messages can still link to it.
                    let complete = self.rooms.get(r)?.graph_complete(slot)?;
                    let n = self.rooms.get_mut(r)?.nodes.get_mut(slot)?;
                    let changed = complete && !n.complete;
                    n.complete = complete;
                    if !n.frontier_applied {
                        self.rooms.get_mut(r)?.update_frontier(slot)?;
                        self.rooms.get_mut(r)?.nodes.get_mut(slot)?.frontier_applied = true;
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
            let completed = self.rooms.get_mut(r)?.completion_step()?;
            if let Some(s) = completed {
                self.event(Event::MemberChanged(
                    self.member_id(r, s),
                    SessionPhase::Completed,
                ))?;
            } else if self.rooms.get(r)?.completion_session.is_none()
                && self.rooms.get(r)?.completion_queue.is_empty()
            {
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
        plain: Option<&[u8]>,
        plain_pad: padding::Decode,
        now: u64,
    ) -> Result<(), Error> {
        let (source, meta, was_applied) = {
            let n = self.rooms.get(r)?.nodes.get(slot)?;
            (n.origin.require_live()?, n.meta, n.semantic_applied)
        };
        if self.rooms.get(r)?.nodes.get(slot)?.auth.is_none() {
            let Some(auth) = self.authenticate(source, message, meta)? else {
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
        if self.rooms.get(r)?.nodes.get(slot)?.sequence == 0 {
            let room = self.rooms.get_mut(r)?;
            room.sequence = room.sequence.checked_add(1).ok_or(Fault::Overflow)?;
            room.nodes.get_mut(slot)?.sequence = room.sequence;
        }
        if self.mode == Mode::Service {
            self.service_index_epoch(r, slot, message)?;
        }
        self.resolve_missing(r, &crypto::signature::message_hash(message))?;
        let (parents, origin) = {
            let n = self.rooms.get(r)?.nodes.get(slot)?;
            (n.parents, n.origin.require_live()?)
        };
        for p in parents {
            self.note_missing(r, p, origin)?;
        }
        if self.rooms.get(r)?.nodes.get(slot)?.resume_pending && !self.rebind_historical(r, slot)? {
            return Err(Fault::NotReady.into());
        }
        if !was_applied && !self.rooms.get(r)?.nodes.get(slot)?.semantic_applied {
            let body = if let Some(bytes) = plain {
                let layout = self
                    .rooms
                    .get(r)?
                    .nodes
                    .get(slot)?
                    .plain_layout
                    .ok_or(Fault::NotReady)?;
                Short::decode_with_profiles(bytes, layout.body, layout.padding, plain_pad)?.body()
            } else {
                message.body()
            };
            if matches!(message.header().kind, Kind::PRIVATE | Kind::SECRET)
                && plain.is_none()
                && self.mode == Mode::Client
            {
                // AEAD/inner semantics can wait for a recipient key without
                // blocking this valid signed outer vertex in the room DAG.
                if !self.rooms.get(r)?.nodes.get(slot)?.frontier_applied {
                    self.rooms.get_mut(r)?.update_frontier(slot)?;
                    self.rooms.get_mut(r)?.nodes.get_mut(slot)?.frontier_applied = true;
                }
                let complete = self.rooms.get(r)?.graph_complete(slot)?;
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
                self.apply_body(r, slot, message, body, now)?;
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
            if !self.rooms.get(r)?.nodes.get(slot)?.frontier_applied {
                self.rooms.get_mut(r)?.update_frontier(slot)?;
                self.rooms.get_mut(r)?.nodes.get_mut(slot)?.frontier_applied = true;
            }
        }
        let complete = self.rooms.get(r)?.graph_complete(slot)?;
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
        if changed {
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
    ) -> Result<(), Error> {
        let auth = self
            .rooms
            .get(r)?
            .nodes
            .get(slot)?
            .auth
            .ok_or(Fault::Authentication)?;
        let hash = self.rooms.get(r)?.nodes.get(slot)?.hash;
        match body {
            Body::Join {
                public_key,
                hpke_key,
                ..
            } => self.apply_join(r, slot, outer, *public_key.as_bytes(), *hpke_key.as_bytes())?,
            Body::Leave { epoch } => {
                let session = auth.session.ok_or(Fault::Authentication)?;
                let contact = auth.owner.ok_or(Fault::Authentication)?.contact;
                let Some(previous) = self.rooms.get(r)?.find_epoch(epoch) else {
                    self.note_missing(
                        r,
                        *epoch,
                        self.rooms.get(r)?.nodes.get(slot)?.origin.require_live()?,
                    )?;
                    return Err(Fault::NotReady.into());
                };
                let previous = self.rooms.get(r)?.epochs.get(previous)?;
                if !previous.complete {
                    return Err(Fault::NotReady.into());
                }
                if !previous.members.contains(&contact) {
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
                let content = name.content().expose();
                if content.len() > self.limits.name_bytes {
                    return Err(Fault::TooLarge.into());
                }
                let name = OwnedBytes::copy_from(content)?;
                let bytes = name.capacity();
                let old = self
                    .contacts
                    .get(contact.slot)?
                    .name
                    .as_ref()
                    .map_or(0, OwnedBytes::capacity);
                if bytes > self.remaining_bytes().saturating_add(old) {
                    return Err(Fault::Capacity.into());
                }
                self.contacts.get_mut(contact.slot)?.name = Some(name);
                self.used = self.used - old + bytes;
                if let Some(s) = auth.session {
                    self.rooms.get_mut(r)?.sessions.get_mut(s)?.last_bound = hash;
                }
                self.event(Event::ContactChanged(contact))?;
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
                let row = self.rooms.get_mut(r)?;
                if let Some(p) = row.peers.iter_mut().find(|p| p.peer == *peer) {
                    p.announced = true;
                    p.historical_candidate = false;
                } else {
                    if row.peers.len() == row.peers.capacity() {
                        return Err(Fault::Capacity.into());
                    }
                    row.peers.push(PeerRow {
                        peer: *peer,
                        announced: true,
                        historical_candidate: false,
                        connection_amount: 0,
                        connection_flags: 0,
                    });
                }
            }
            Body::Miss { peer } => {
                if let Some(p) = self
                    .rooms
                    .get_mut(r)?
                    .peers
                    .iter_mut()
                    .find(|p| p.peer == *peer)
                {
                    p.announced = false;
                    p.historical_candidate = false;
                }
            }
            Body::Merge { .. } => self.epoch_message(r, slot, body)?,
            Body::Request { hash: requested } => {
                // A real request is retained as such. Delivery is a service port
                // action and must use history() with this actual sender session.
                if auth.session.is_none() {
                    return Err(Error::Permission);
                }
                if self.rooms.get(r)?.find_node(requested).is_none() {
                    self.note_missing(
                        r,
                        *requested,
                        self.rooms.get(r)?.nodes.get(slot)?.origin.require_live()?,
                    )?;
                }
            }
            Body::Deletion {
                hash: target,
                delay,
            } => {
                if delay.as_micros() == u64::MAX {
                    return Err(Fault::InvalidInput.into());
                }
                let session = auth.session.ok_or(Fault::Authentication)?;
                let Some(target_slot) = self.rooms.get(r)?.find_node(target) else {
                    self.note_missing(
                        r,
                        *target,
                        self.rooms.get(r)?.nodes.get(slot)?.origin.require_live()?,
                    )?;
                    return Err(Fault::NotReady.into());
                };
                let room = self.rooms.get(r)?;
                let target_node = room.nodes.get(target_slot)?;
                if epoch_kind(target_node.kind) || !owns(room.sessions.get(session)?, target_node) {
                    return Err(Error::Permission);
                }
                let timestamp = self.rooms.get(r)?.nodes.get(slot)?.timestamp;
                // The actual timeout helper caps remaining delay at60s. Keep
                // that observable policy, using checked absolute arithmetic.
                let due = timestamp
                    .saturating_add(delay.as_micros())
                    .min(now.saturating_add(60_000_000));
                let n = self.rooms.get_mut(r)?.nodes.get_mut(target_slot)?;
                n.delete_at = Some(n.delete_at.map_or(due, |old| old.min(due)));
                n.deleted_by = Some(hash);
            }
            Body::Connection { amount, flags } => {
                let peer = auth.peer.ok_or(Fault::Authentication)?;
                let p = self
                    .rooms
                    .get_mut(r)?
                    .peers
                    .iter_mut()
                    .find(|p| p.peer == peer)
                    .ok_or(Fault::NotReady)?;
                p.connection_amount = amount;
                p.connection_flags = flags;
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
                        let erased = self.rooms.get_mut(r)?.erase_message(slot, None)?;
                        self.release(erased)?;
                    }
                }
            }
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
                let plain = OwnedBytes::copy_from(data.expose())?;
                self.charge(plain.capacity())?;
                let target = self.rooms.get_mut(r)?.nodes.get_mut(target)?;
                let old = target.plaintext.replace(plain);
                target.plain_padding = padding::Decode::Absent;
                target.plain_layout = Some(inner_layout);
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
            Body::Announcement { .. }
            | Body::Appeal { .. }
            | Body::Access { .. }
            | Body::Revolution { .. }
            | Body::Group { .. }
            | Body::Authorization { .. } => self.epoch_control(r, slot, outer, now)?,
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
    fn contact_for(
        &mut self,
        r: Slot,
        id: ShortHash,
        public: PublicKey,
    ) -> Result<Contact<'id>, Error> {
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
            return Ok(self.contact_id(s));
        }
        let local = Some(public) == self.rooms.get(r)?.local_public;
        let s = self
            .contacts
            .insert(ContactRow {
                key: public,
                name: None,
                anonymous_context: context,
                local,
                canonical: true,
                rooms: 0,
            })
            .map_err(|(e, _)| e)?;
        let contact = self.contact_id(s);
        self.event(Event::ContactChanged(contact))?;
        Ok(contact)
    }
    fn apply_join(
        &mut self,
        r: Slot,
        node: Slot,
        message: Message<'_>,
        public: PublicKey,
        hpke: PublicKey,
    ) -> Result<(), Error> {
        let id = *message.header().sender_id;
        let hash = self.rooms.get(r)?.nodes.get(node)?.hash;
        let prior = self.rooms.get(r)?.sessions.iter().find_map(|(s, m)| {
            (m.id == id
                && m.public == public
                && (m.phase != SessionPhase::Completed
                    || m.archived && m.historical_phase == SessionPhase::Active)
                && m.successor.is_none())
            .then_some(s)
        });
        let session = if let Some(s) = prior {
            s
        } else {
            self.rooms.get(r)?.sessions.next_key()?;
            let contact = self.contact_for(r, id, public)?;
            let room = self.rooms.get_mut(r)?;
            let lineage = room.lineage.checked_add(1).ok_or(Fault::Overflow)?;
            let s = room
                .sessions
                .insert(SessionRow {
                    contact,
                    id,
                    public,
                    hpke,
                    lineage,
                    generation: 1,
                    known_from: room.sequence,
                    phase: SessionPhase::Joining,
                    first_bound: hash,
                    last_bound: hash,
                    successor: None,
                    completed_at: None,
                    archived: false,
                    historical_phase: SessionPhase::Joining,
                })
                .map_err(|(e, _)| e)?;
            room.lineage = lineage;
            self.contacts.get_mut(contact.slot)?.rooms += 1;
            s
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
            if Some(public) == room.local_public && Some(id) == room.local_id {
                room.joined = true;
                for (_, source) in room.sources.iter_mut() {
                    if source.member_id == Some(id) {
                        source.join_required = false;
                    }
                }
            }
        }
        self.epoch_message(r, node, message.body())?;
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
    fn key_successor(
        &mut self,
        r: Slot,
        node: Slot,
        auth: Authentication<'id>,
    ) -> Result<Slot, Error> {
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
        let count = row.nodes.len();
        let requested = count
            .checked_mul(core::mem::size_of::<Slot>())
            .ok_or(Fault::Overflow)?;
        if requested > self.remaining_bytes() {
            return Err(Fault::Capacity.into());
        }
        let mut ancestry = alloc::vec::Vec::new();
        ancestry
            .try_reserve_exact(count)
            .map_err(|_| Fault::Capacity)?;
        let bytes = ancestry
            .capacity()
            .checked_mul(core::mem::size_of::<Slot>())
            .ok_or(Fault::Overflow)?;
        self.charge(bytes)?;
        let result = (|| {
            let row = self.rooms.get(r)?;
            ancestry.push(node);
            let mut cursor = 0;
            let mut missing = false;
            // One entry per actual Slot, including diamonds and cycles. No
            // unauthenticated predecessor supplies a causal edge or authority.
            while cursor < ancestry.len() {
                let current = row.nodes.get(ancestry[cursor])?;
                cursor += 1;
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
                    if !ancestry.contains(&parent) {
                        if ancestry.len() == count {
                            return Err(Fault::Conflict.into());
                        }
                        ancestry.push(parent);
                    }
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
                if !ancestry.contains(&transition) {
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
        })();
        drop(ancestry);
        self.release(bytes)?;
        result
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
            s != contact.slot && c.canonical && c.key == public && c.anonymous_context.is_none()
        });
        if key.is_some() {
            let c = self.contacts.get_mut(contact.slot)?;
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
            self.contacts.get_mut(contact.slot)?.anonymous_context = Some(context);
        } else {
            self.contacts.get_mut(contact.slot)?.anonymous_context = None;
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
        self.event(Event::ContactChanged(contact))?;
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
            owner.contact,
            discourse,
        ))?;
        Ok(())
    }
    pub(crate) fn note_missing(
        &mut self,
        r: Slot,
        hash: Hash,
        source: Source<'id>,
    ) -> Result<(), Error> {
        if hash == [0; 64] || self.rooms.get(r)?.find_node(&hash).is_some() {
            return Ok(());
        }
        if self
            .rooms
            .get(r)?
            .missing
            .iter()
            .any(|(_, m)| m.hash == hash && m.source == source)
        {
            return Ok(());
        }
        self.rooms
            .get_mut(r)?
            .missing
            .insert(MissingRow {
                hash,
                source,
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
            self.rooms.get_mut(r)?.missing.remove(s)?;
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
        let slot = self
            .rooms
            .get(r)?
            .missing
            .iter()
            .find_map(|(s, m)| (m.hash == *hash && m.source == source).then_some(s))
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
            self.revoke_confirmation(r, &hash)?;
            let released = self.rooms.get_mut(r)?.erase_message(slot, by)?;
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
                sub.contact,
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
                if !discourse_kind(n.kind) || n.phase == MessagePhase::Deleted {
                    continue;
                }
                if let Some(d) = n.discourse
                    && n.timestamp < self.rooms.get(r)?.discourse_cutoff(&d)
                {
                    self.reserve_events(1)?;
                    let hash = self.rooms.get(r)?.nodes.get(s)?.hash;
                    let b = self.rooms.get_mut(r)?.erase_message(s, None)?;
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
        self.expire_epochs(r, now)?;
        Ok(())
    }
    /// Decrypt with actual retained authorized epoch/recipient capabilities and
    /// caller-owned bounded scratch. The service mode never decrypts client
    /// content. No plaintext is installed until AEAD and inner hash both pass.
    pub fn decrypt_message<const N: usize>(
        &mut self,
        room: Room<'id>,
        hash: &Hash,
        scratch: &mut SensitiveBuffer<N>,
    ) -> Result<(), Error> {
        if self.mode != Mode::Client {
            return Err(Error::Permission);
        }
        let r = self.check_room(room)?;
        let slot = self.rooms.get(r)?.find_node(hash).ok_or(Fault::NotFound)?;
        let row = self.rooms.get(r)?;
        let node = row.nodes.get(slot)?;
        if node.auth.is_none() || node.phase == MessagePhase::Deleted || node.plaintext.is_some() {
            return Err(Fault::NotReady.into());
        }
        let message = node.message(self.profile)?;
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
                        .is_some_and(|o| e.members.contains(&o.contact))
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
                for key in &row.hpke_keys {
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
        let checked = crypto::signature::decode_short_with_profiles(
            scratch.expose(),
            plain_layout.body,
            plain_layout.padding,
            padding::Decode::Required,
        )?;
        if !crypto::message::permits_private(checked.short().body().kind()) {
            scratch.clear();
            return Err(Fault::Malformed.into());
        }
        let copied = OwnedBytes::copy_from(scratch.expose());
        scratch.clear();
        let plain = copied?;
        self.charge(plain.capacity())?;
        let node = self.rooms.get_mut(r)?.nodes.get_mut(slot)?;
        node.plaintext = Some(plain);
        node.plain_layout = Some(plain_layout);
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
        if self.mode != Mode::Client
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
            .hpke_keys
            .iter()
            .position(|old| old.secret.public_key() == public)
        {
            self.rooms.get_mut(source.room)?.hpke_keys[index]
                .merge_origin(RecipientKeyOrigin::Zone(zone_public));
            // Existing ciphertext capability is not another key installation.
            return Ok(false);
        }
        if row.hpke_keys.len() == row.hpke_keys.capacity() {
            return Err(Fault::Capacity.into());
        }
        self.rooms
            .get_mut(source.room)?
            .hpke_keys
            .push(RecipientKey {
                secret: key,
                origin: RecipientKeyOrigin::Zone(zone_public),
            });
        Ok(true)
    }
    /// Register an actual locally owned HPKE recipient key after checking its
    /// public component against a real current local member's advertised key.
    pub fn retain_recipient_key(
        &mut self,
        member: MemberSession<'id>,
        key: crypto::EcdheSecret,
    ) -> Result<(), Error> {
        self.check_member(member)?;
        let row = self.rooms.get(member.room)?;
        let session = row.sessions.get(member.slot)?;
        if row.local_session() != Some(member.slot)
            || !self.contacts.get(session.contact.slot)?.local
            || session.phase != SessionPhase::Active
            || key.public_key().as_bytes() != &session.hpke[4..]
        {
            return Err(Error::Permission);
        }
        let origin = RecipientKeyOrigin::Member {
            owner: owner(session),
            public: session.public,
        };
        let public = key.public_key();
        if let Some(index) = row
            .hpke_keys
            .iter()
            .position(|old| old.secret.public_key() == public)
        {
            self.rooms.get_mut(member.room)?.hpke_keys[index].merge_origin(origin);
            return Ok(());
        }
        let row = self.rooms.get_mut(member.room)?;
        if row.hpke_keys.len() == row.hpke_keys.capacity() {
            return Err(Fault::Capacity.into());
        }
        row.hpke_keys.push(RecipientKey {
            secret: key,
            origin,
        });
        Ok(())
    }
}
fn target_slot(room: &RoomRow<'_>, hash: &Hash) -> Result<Slot, Error> {
    room.find_node(hash).ok_or(Fault::NotFound.into())
}

#[cfg(test)]
mod key_refresh_tests;

#[cfg(test)]
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
        let first = core
            .rooms
            .get_mut(room.slot)?
            .insert_node(original)
            .map_err(|r| r.error)?;
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
        let second = core
            .rooms
            .get_mut(room.slot)?
            .insert_node(finite)
            .map_err(|r| r.error)?;
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
