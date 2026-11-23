//! Bounded signing drafts and verified signer results.
use crate::{
    engine::Core,
    graph::{epoch_kind, peer_kind},
    state::*,
    *,
};
use gnunet_types::{AbsoluteTime, Error as Fault};
use wire::{body::Body, message::Message, padding};

#[cfg(feature = "alloc")]
mod client;
mod signing;

enum DraftAuthority {
    Peer,
    #[cfg(feature = "alloc")]
    Client {
        member: Option<Slot>,
        group_keys: [Option<Slot>; 2],
        recipient: Option<crate::recipient::MemberRecipient>,
    },
    #[cfg(feature = "alloc")]
    HistoryRequest {
        member: Slot,
    },
}

struct SigningDraft<'frame> {
    authority: DraftAuthority,
    public: PublicKey,
    sender: ShortHash,
    body: Body<'frame>,
    previous: Hash,
    epoch: Hash,
    now: u64,
    deadline: u64,
}

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    fn check_signing_draft(
        &self,
        source: Source<'id>,
        public: &PublicKey,
        now: u64,
        deadline: u64,
    ) -> Result<(), Error> {
        self.check_source(source)?;
        self.reserve_events(1)?;
        if now >= deadline || deadline == u64::MAX {
            return Err(Fault::Timeout.into());
        }
        wire::PublicKey::new(public)?;
        Ok(())
    }

    fn publish_signing_draft(
        &mut self,
        source: Source<'id>,
        draft: SigningDraft<'_>,
    ) -> Result<(Operation<'id>, Hash), Error> {
        let SigningDraft {
            authority,
            public,
            sender,
            body,
            previous,
            epoch,
            now,
            deadline,
        } = draft;
        let (is_ipc, member, class) = match authority {
            DraftAuthority::Peer => (false, None, OperationClass::Ordinary),
            #[cfg(feature = "alloc")]
            DraftAuthority::Client { member, .. } => (true, member, OperationClass::Ordinary),
            #[cfg(feature = "alloc")]
            DraftAuthority::HistoryRequest { member } => {
                (true, Some(member), OperationClass::Dependency)
            }
        };
        #[cfg(feature = "alloc")]
        let (group_keys, recipient) = match authority {
            DraftAuthority::Peer => ([None; 2], None),
            DraftAuthority::Client {
                group_keys,
                recipient,
                ..
            } => (group_keys, recipient),
            DraftAuthority::HistoryRequest { .. } => ([None; 2], None),
        };
        let slot = self.next_operation_slot(source.room, class)?;
        let timestamp = if epoch_kind(body.kind()) { 0 } else { now };
        let len = body.encoded_len(self.profile)?;
        let full = len
            .checked_add(wire::envelope::HEADER_LEN)
            .ok_or(Fault::Overflow)?;
        let physical = if is_ipc {
            full.checked_add(wire::SEND_PREFIX).ok_or(Fault::Overflow)?
        } else {
            full
        };
        if physical > self.limits.frame_bytes || physical > usize::from(u16::MAX) {
            return Err(Fault::TooLarge.into());
        }
        let budget = self.remaining_bytes();
        let vacant = self.rooms.get_mut(source.room)?.operations.vacant()?;
        let mut hash = [0; 64];
        let draft = self.work.write(len, budget, |output| {
            hash = signing::encode(
                body,
                self.profile,
                crypto::signature::SigningHeader {
                    timestamp: AbsoluteTime::from_micros(timestamp),
                    sender_id: &sender,
                    previous: &previous,
                },
                output,
            )?;
            Ok(())
        })?;
        let capacity = draft.capacity();
        let operation = self.instance.operation_id(source.room, slot);
        let binding = OperationBinding {
            source: source.slot,
            member,
            message: hash,
            epoch,
            identifier: [0; 32],
            epoch_revision: 0,
        };
        let row = OperationRow {
            class,
            #[cfg(feature = "alloc")]
            join_echo: false,
            binding,
            #[cfg(feature = "alloc")]
            signed_kind: Some(body.kind()),
            #[cfg(feature = "alloc")]
            group_keys,
            #[cfg(feature = "alloc")]
            recipient,
            job: Job::Sign {
                body: Some(draft),
                kind: body.kind(),
                public,
                sender,
                previous,
                timestamp,
            },
            phase: OperationPhase::Prepared,
            deadline,
            written: 0,
            charged_bytes: capacity,
        };
        vacant.insert(row);
        self.used += capacity;
        self.event(Event::OperationChanged(operation, OperationPhase::Prepared))?;
        Ok((operation, hash))
    }

    /// Prepare an official raw peer message for the original caller-owned peer
    /// port. It is never encoded as a private invented IPC request.
    pub fn prepare_peer(
        &mut self,
        source: Source<'id>,
        sender: ShortHash,
        body: Body<'_>,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        self.check_source(source)?;
        if self.mode != Mode::Service
            || !peer_kind(body.kind())
            || !matches!(
                self.rooms.get(source.room)?.sources.get(source.slot)?.role,
                SourceRole::Peer(_) | SourceRole::ServiceSigner(_)
            )
        {
            return Err(Error::Permission);
        }
        let peer = self.local_peer.ok_or(Fault::NotReady)?;
        let mut public = [0; 36];
        public[..4].copy_from_slice(&wire::KeyType::Eddsa.value().to_be_bytes());
        public[4..].copy_from_slice(&peer);
        self.check_signing_draft(source, &public, now, deadline)?;
        let room = self.rooms.get(source.room)?;
        let draft = SigningDraft {
            authority: DraftAuthority::Peer,
            public,
            sender,
            body,
            previous: room.last_message,
            epoch: room.current_epoch,
            now,
            deadline,
        };
        self.publish_signing_draft(source, draft)
            .map(|(operation, _)| operation)
    }
    /// Consume an actual signed result, rechecking original canonical hash,
    /// public key and every header/body field. No provider assertion can replace
    /// cryptographic verification. On rejection original result bytes survive.
    #[cfg(feature = "alloc")]
    pub fn complete_signature(
        &mut self,
        binding: Binding<'id>,
        input: OwnedBytes,
        pad: padding::Decode,
        now: u64,
    ) -> Result<(), RejectedInput> {
        self.complete_signing_input(binding, input, pad, now)
            .map_err(|(error, input)| RejectedInput { error, input })
    }

    /// Verify a signer result in caller storage. If refused, the operation
    /// remains taken and the caller can submit the same bytes again.
    pub fn complete_signature_from(
        &mut self,
        binding: Binding<'id>,
        input: &[u8],
        pad: padding::Decode,
        now: u64,
    ) -> Result<(), Error> {
        self.complete_signing_input(binding, input, pad, now)
            .map_err(|(error, _)| error)
    }

    fn complete_signing_input<I: IncomingFrame>(
        &mut self,
        binding: Binding<'id>,
        input: I,
        pad: padding::Decode,
        now: u64,
    ) -> Result<(), (Error, I)> {
        let (encoding, len, used) = match self.check_signing_input(binding, input.bytes(), pad, now)
        {
            Ok(checked) => checked,
            Err(error) => return Err((error, input)),
        };
        let budget = self.limits.total_bytes - used;
        let event = match self.events.vacant() {
            Ok(event) => event,
            Err(error) => return Err((error, input)),
        };
        let room = match self.rooms.get_mut(binding.source.room) {
            Ok(room) => room,
            Err(error) => return Err((error, input)),
        };
        let op = match room.operations.get_mut(binding.operation.slot) {
            Ok(op) => op,
            Err(error) => return Err((error, input)),
        };
        let frame = match encoding {
            Encoding::PeerMessage => self.work.retain(input, None, budget)?,
            Encoding::Ipc => {
                let request = wire::Request::Send {
                    key: &room.key,
                    message: wire::SensitiveBytes::new(input.bytes()),
                };
                match self.work.write(len, budget, |output| {
                    request.encode(output)?;
                    Ok(())
                }) {
                    Ok(frame) => frame,
                    Err(error) => return Err((error, input)),
                }
            }
        };
        let capacity = frame.capacity();
        op.job = Job::Wire {
            purpose: NativePurpose::Send,
            frame: Some(frame),
            length: len,
            encoding,
        };
        op.phase = OperationPhase::Prepared;
        op.charged_bytes = capacity;
        self.used = used + capacity;
        event.insert(QueuedEvent::OperationChanged {
            room: binding.source.room,
            operation: binding.operation.slot,
            phase: OperationPhase::Prepared,
        });
        Ok(())
    }

    fn check_signing_input(
        &self,
        binding: Binding<'id>,
        input: &[u8],
        pad: padding::Decode,
        now: u64,
    ) -> Result<(Encoding, usize, usize), Error> {
        let op = self.check_binding(binding)?;
        if op.phase != OperationPhase::Taken || op.deadline <= now {
            return Err(Fault::StaleGeneration.into());
        }
        let Job::Sign {
            body: None,
            kind,
            public,
            sender,
            previous,
            timestamp,
        } = &op.job
        else {
            return Err(Fault::Conflict.into());
        };
        let room = self.rooms.get(binding.source.room)?;
        let (encoding, len) = match room.sources.get(binding.source.slot)?.role {
            SourceRole::Client => {
                let request = wire::Request::Send {
                    key: &room.key,
                    message: wire::SensitiveBytes::new(input),
                };
                (Encoding::Ipc, request.encoded_len()?)
            }
            SourceRole::Peer(_) | SourceRole::ServiceSigner(_) => {
                if !peer_kind(*kind) || self.local_peer.is_none_or(|peer| public[4..] != peer) {
                    return Err(Error::Permission);
                }
                (Encoding::PeerMessage, input.len())
            }
        };
        if len > self.limits.frame_bytes || len > usize::from(u16::MAX) {
            return Err(Fault::TooLarge.into());
        }
        let message = Message::decode(input, self.profile, pad)?;
        let checked = crypto::signature::verify_member(message, wire::PublicKey::new(public)?)?;
        if *checked.digest() != binding.message
            || message.header().kind != *kind
            || message.header().sender_id != sender
            || message.header().previous != previous
            || message.header().timestamp.as_micros() != *timestamp
        {
            return Err(Error::AttributionConflict);
        }
        let used = self
            .used
            .checked_sub(op.charged_bytes)
            .ok_or(Fault::Conflict)?;
        Ok((encoding, len, used))
    }
    /// Original pending missing set. No timer silently retries a non-idempotent
    /// operation or swaps a lost source for a new MQ generation.
    pub fn missing_messages(
        &self,
        room: Room<'id>,
    ) -> Result<impl Iterator<Item = (Hash, Source<'id>, bool)> + '_, Error> {
        let r = self.check_room(room)?;
        Ok(self
            .rooms
            .get(r)?
            .missing
            .iter()
            .map(move |(_, m)| (m.hash, self.source_id(r, m.source), m.absent)))
    }
    /// Whether this exact live source/hash has a retained required protocol
    /// dependency. Absence and its first requested deadline do not change the
    /// classification; this grants no retrieval result or replacement source.
    pub fn is_required_dependency(&self, source: Source<'id>, hash: &Hash) -> Result<bool, Error> {
        self.check_source(source)?;
        Ok(self
            .rooms
            .get(source.room)?
            .missing
            .iter()
            .any(|(_, missing)| missing.source == source.slot && missing.hash == *hash))
    }
    /// Required original causal/control hashes whose first GET has not been
    /// admitted. A matching absence or retired first request never renews this
    /// requirement; a different source generation remains a different cause.
    pub fn pending_dependencies(
        &self,
        room: Room<'id>,
    ) -> Result<impl Iterator<Item = (Hash, Source<'id>)> + '_, Error> {
        let r = self.check_room(room)?;
        Ok(self
            .rooms
            .get(r)?
            .missing
            .iter()
            .filter(|(_, m)| !m.absent && m.retry_at == 0)
            .map(move |(_, m)| (m.hash, self.source_id(r, m.source))))
    }
    /// Suppress repeated service-side dispatch of this exact peer dependency
    /// after the owner has admitted its one bounded request. The retained
    /// graph still requires the original, and a new native peer generation
    /// cannot inherit this observation.
    pub fn service_note_peer_dependency_dispatched(
        &mut self,
        source: Source<'id>,
        hash: &Hash,
        deadline: u64,
    ) -> Result<(), Error> {
        self.check_source(source)?;
        if deadline == 0 || deadline == u64::MAX {
            return Err(Fault::InvalidInput.into());
        }
        let room = self.rooms.get_mut(source.room)?;
        if self.mode != Mode::Service
            || !matches!(room.sources.get(source.slot)?.role, SourceRole::Peer(_))
        {
            return Err(Error::Permission);
        }
        let (_, missing) = room
            .missing
            .iter_mut()
            .find(|(_, missing)| missing.source == source.slot && missing.hash == *hash)
            .ok_or(Fault::NotFound)?;
        if missing.retry_at != 0 {
            return Err(Fault::Replay.into());
        }
        missing.retry_at = deadline;
        Ok(())
    }
    /// A provider failure is an actual local fact. A failed shared-key job does
    /// not install a key, advance the epoch or report a transmitted revolution.
    pub fn provider_failed(&mut self, binding: Binding<'id>, error: Error) -> Result<(), Error> {
        if matches!(self.check_binding(binding)?.job, Job::Wire { .. }) {
            return Err(Fault::Conflict.into());
        }
        self.reserve_events(2)?;
        let op = self
            .rooms
            .get_mut(binding.source.room)?
            .operations
            .get_mut(binding.operation.slot)?;
        if op.phase != OperationPhase::Taken {
            return Err(Fault::Replay.into());
        }
        op.phase = OperationPhase::Failed;
        self.event(Event::OperationChanged(
            binding.operation,
            OperationPhase::Failed,
        ))?;
        self.reset_failed_key_job(binding.source.room, binding.operation.slot)?;
        self.event(Event::ProviderFailed(binding, error))?;
        Ok(())
    }
    /// Native expiry/cancellation requires physical source stop. The core never
    /// issues a nonexistent Messenger cancel command, claims zero exposure or
    /// starts a retry on another source. Owner then calls source_stopped().
    pub fn source_requiring_stop(
        &self,
        room: Room<'id>,
        now: u64,
    ) -> Result<Option<Source<'id>>, Error> {
        let r = self.check_room(room)?;
        Ok(self
            .rooms
            .get(r)?
            .operations
            .iter()
            .find_map(|(_, o)| {
                (!matches!(
                    o.phase,
                    OperationPhase::Complete | OperationPhase::Cancelled | OperationPhase::Failed
                ) && o.deadline <= now)
                    .then_some(o.binding.source)
            })
            .map(|source| self.source_id(r, source)))
    }
    /// Earliest actual local timer, suitable for one owner-driven alarm. Native
    /// hard deadlines still belong to the original native adapter independently.
    pub fn next_deadline(&self, room: Room<'id>) -> Result<Option<u64>, Error> {
        let r = self.rooms.get(self.check_room(room)?)?;
        let mut min = semantic_deadline(r);
        for (_, o) in r.operations.iter() {
            if !matches!(
                o.phase,
                OperationPhase::Complete | OperationPhase::Failed | OperationPhase::Cancelled
            ) {
                observe_deadline(&mut min, o.deadline);
            }
        }
        #[cfg(feature = "alloc")]
        for (_, s) in r.subscriptions.iter() {
            if s.keep_alive
                && s.renew_operation.is_none()
                && let Some(d) = s.renew_at
            {
                observe_deadline(&mut min, d);
            }
        }
        Ok(min)
    }

    /// Next working-state timer consumed by [`Self::advance`]. A native
    /// transport deadline or work that needs an I/O poll has its own wake port.
    ///
    /// # Errors
    /// Rejects a foreign or stale room.
    pub fn next_semantic_deadline(&self, room: Room<'id>) -> Result<Option<u64>, Error> {
        Ok(semantic_deadline(self.rooms.get(self.check_room(room)?)?))
    }
}

fn observe_deadline(min: &mut Option<u64>, time: u64) {
    if time != u64::MAX {
        *min = Some(min.map_or(time, |old| old.min(time)));
    }
}

fn semantic_deadline(room: &RoomRow<'_>) -> Option<u64> {
    let mut min = None;
    for (_, node) in room.nodes.iter() {
        if node.phase != MessagePhase::Deleted
            && let Some(deadline) = node.delete_at
        {
            observe_deadline(&mut min, deadline);
        }
    }
    for (_, subscription) in room.subscriptions.iter() {
        if !subscription.keep_alive {
            observe_deadline(&mut min, subscription.end.saturating_add(1));
        }
    }
    #[cfg(feature = "alloc")]
    if let Some(automatic) = room.automatic_proposal {
        observe_deadline(&mut min, automatic.expires);
    }
    #[cfg(feature = "alloc")]
    for (_, epoch) in room.epochs.iter() {
        if let Some(recipient) = &epoch.ephemeral {
            observe_deadline(&mut min, recipient.valid_until);
        }
        for (_, group) in epoch.groups.iter() {
            if group.appeal.is_some() {
                observe_deadline(&mut min, group.appeal_until);
            }
            if group.proposal.is_some() {
                observe_deadline(&mut min, group.expires);
            }
        }
    }
    min
}

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    pub(crate) fn reset_failed_key_job(
        &mut self,
        room: Slot,
        operation: Slot,
    ) -> Result<(), Error> {
        let row = self.rooms.get_mut(room)?;
        #[cfg(feature = "alloc")]
        {
            let original = row.operations.get(operation)?;
            let identifier = original.binding.identifier;
            if matches!(&original.job, Job::SharedKey)
                && let Some(e) = row.find_epoch(&original.binding.epoch)
            {
                let epoch = row.epochs.get_mut(e)?;
                if let Some((_, g)) = epoch.groups.iter_mut().find(|(_, g)| {
                    g.identifier == identifier && g.phase == KeyPhase::Generating && g.key.is_none()
                }) {
                    g.phase = KeyPhase::Missing;
                    row.derivation.arm();
                }
            }
        }
        for (_, s) in row.subscriptions.iter_mut() {
            if s.renew_operation == Some(operation) {
                s.renew_operation = None;
                s.keep_alive = false;
                s.renew_at = None;
            }
        }
        Ok(())
    }
}
