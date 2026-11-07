//! Original bounded drafts and actual signer/entropy results. No synthetic wire
//! acknowledgement, replacement MQ, replay, generated key or successful crypto.
use crate::{engine::Core, graph::*, state::*, *};
use alloc::vec::Vec;
use gnunet_crypto::hash512;
use gnunet_types::Error as Fault;
use wire::{body::Body, envelope::Kind, message::Message, padding};
impl<'id> Core<'id> {
    #[expect(
        clippy::too_many_arguments,
        reason = "original source, member, crypto workspace and finite deadline remain explicit"
    )]
    fn queue_sign(
        &mut self,
        source: Source<'id>,
        member: Option<MemberSession<'id>>,
        recipient: Option<RecipientAttribution<'id>>,
        public: PublicKey,
        sender: ShortHash,
        body: Body<'_>,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        self.check_source(source)?;
        self.reserve_events(1)?;
        if now >= deadline || deadline == u64::MAX {
            return Err(Fault::Timeout.into());
        }
        wire::PublicKey::new(&public)?;
        let room = self.rooms.get(source.room)?;
        let previous = room.last_message;
        let timestamp = if epoch_kind(body.kind()) { 0 } else { now };
        let len = body.encoded_len(self.profile)?;
        let full = len.checked_add(176).ok_or(Fault::Overflow)?;
        let physical = if room.sources.get(source.slot)?.role == SourceRole::Client {
            full.checked_add(wire::SEND_PREFIX).ok_or(Fault::Overflow)?
        } else {
            full
        };
        if physical > self.limits.frame_bytes || physical > usize::from(u16::MAX) {
            return Err(Fault::TooLarge.into());
        }
        // Hash the exact future canonical encoding; signature68 is excluded.
        // The original draft hash therefore binds every requested body byte.
        let mut data = zeroize::Zeroizing::new(Vec::new());
        data.try_reserve_exact(full).map_err(|_| Fault::Capacity)?;
        data.resize(full, 0);
        data[..4].copy_from_slice(
            &wire::PublicKey::new(&public)?
                .key_type()
                .value()
                .to_be_bytes(),
        );
        data[68..76].copy_from_slice(&timestamp.to_be_bytes());
        data[76..108].copy_from_slice(&sender);
        data[108..172].copy_from_slice(&previous);
        data[172..176].copy_from_slice(&body.kind().value().to_be_bytes());
        body.encode(self.profile, &mut data[176..])?;
        let hash = hash512(&data[68..]);
        // The provider receives an exclusively owned body, without a revealing
        // diagnostic or a duplicate retained plaintext template in Core.
        data.copy_within(176.., 0);
        use zeroize::Zeroize;
        data[len..].zeroize();
        data.truncate(len);
        let owned = OwnedBytes::new(data);
        let capacity = owned.capacity();
        let slot = room.operations.next_key()?;
        let operation = Operation {
            core: self.instance,
            room: source.room,
            slot,
        };
        let binding = Binding {
            operation,
            source,
            member,
            message: hash,
            epoch: room.current_epoch,
            identifier: [0; 32],
            epoch_revision: 0,
        };
        self.charge(capacity)?;
        let row = OperationRow {
            binding,
            recipient,
            job: Job::Sign {
                body: owned,
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
        if let Err((error, _)) = self.rooms.get_mut(source.room)?.operations.insert(row) {
            self.release(capacity)?;
            return Err(error);
        }
        self.event(Event::OperationChanged(operation, OperationPhase::Prepared))?;
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
        self.check_source(source)?;
        let row = self.rooms.get(source.room)?;
        let s = row.sources.get(source.slot)?;
        if !s.create_written
            || s.role != SourceRole::Client
            || !matches!(row.phase, RoomPhase::Open | RoomPhase::Entered)
            || row.joined
        {
            return Err(Fault::NotReady.into());
        }
        let public = row.local_public.ok_or(Fault::NotReady)?;
        let sender = s.member_id.ok_or(Fault::NotReady)?;
        let epoch = row.current_epoch;
        self.queue_sign(
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
            now,
            deadline,
        )
    }
    /// Prepare an actual member-owned message. Service/peer-generated kinds
    /// require their separate actual signer port. AUTHORIZATION cannot establish
    /// an interoperable received key because the active wire omits its MAC.
    pub fn prepare_send(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        body: Body<'_>,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        self.check_source(source)?;
        self.check_member(member)?;
        if member.room != source.room {
            return Err(Error::Permission);
        }
        let row = self.rooms.get(source.room)?;
        let session = row.sessions.get(member.slot)?;
        let src = row.sources.get(source.slot)?;
        if src.role != SourceRole::Client
            || !src.create_written
            || session.phase != SessionPhase::Active
            || !self.contacts.get(session.contact.slot)?.local
            || src.member_id != Some(session.id)
            || row.local_public != Some(session.public)
        {
            return Err(Error::Permission);
        }
        if peer_kind(body.kind())
            || matches!(
                body,
                Body::Join { .. } | Body::Private { .. } | Body::Secret { .. }
            )
        {
            return Err(Error::Permission);
        }
        if matches!(body, Body::Authorization { .. }) {
            return Err(Error::AuthorizationMacOmitted);
        }
        if let Body::Deletion { hash, .. } = body {
            let target = row.nodes.get(row.find_node(hash).ok_or(Fault::NotFound)?)?;
            if epoch_kind(target.kind) || !owns(session, target) {
                return Err(Error::Permission);
            }
        }
        self.queue_sign(
            source,
            Some(member),
            None,
            session.public,
            session.id,
            body,
            now,
            deadline,
        )
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
        self.queue_sign(source, None, None, public, sender, body, now, deadline)
    }
    /// Consume an actual signed result, rechecking original canonical hash,
    /// public key and every header/body field. No provider assertion can replace
    /// cryptographic verification. On rejection original result bytes survive.
    pub fn complete_signature(
        &mut self,
        binding: Binding<'id>,
        input: OwnedBytes,
        pad: padding::Decode,
        now: u64,
    ) -> Result<(), RejectedInput> {
        let result = (|| {
            let op = self.check_binding(binding)?;
            if op.phase != OperationPhase::Taken || op.deadline <= now {
                return Err(Fault::StaleGeneration.into());
            }
            let Job::Sign {
                kind,
                public,
                sender,
                previous,
                timestamp,
                ..
            } = &op.job
            else {
                return Err(Fault::Conflict.into());
            };
            let message = Message::decode(input.expose(), self.profile, pad)?;
            let checked = crypto::signature::verify_member(message, wire::PublicKey::new(public)?)?;
            if *checked.digest() != binding.message
                || message.header().kind != *kind
                || message.header().sender_id != sender
                || message.header().previous != previous
                || message.header().timestamp.as_micros() != *timestamp
            {
                return Err(Error::AttributionConflict);
            }
            let source_role = self
                .rooms
                .get(binding.source.room)?
                .sources
                .get(binding.source.slot)?
                .role;
            let peer = matches!(
                source_role,
                SourceRole::Peer(_) | SourceRole::ServiceSigner(_)
            );
            if peer && (!peer_kind(*kind) || self.local_peer.is_none_or(|p| public[4..] != p)) {
                return Err(Error::Permission);
            }
            let frame = if peer {
                OwnedBytes::copy_from(input.expose())?
            } else {
                let key = self.rooms.get(binding.source.room)?.key;
                let request = wire::Request::Send {
                    key: &key,
                    message: wire::SensitiveBytes::new(input.expose()),
                };
                let len = request.encoded_len()?;
                let mut bytes = zeroize::Zeroizing::new(Vec::new());
                bytes.try_reserve_exact(len).map_err(|_| Fault::Capacity)?;
                bytes.resize(len, 0);
                request.encode(&mut bytes)?;
                OwnedBytes::new(bytes)
            };
            let capacity = frame.capacity();
            let old = self.check_binding(binding)?.charged_bytes;
            if capacity > self.remaining_bytes().saturating_add(old) {
                return Err(Fault::Capacity.into());
            }
            self.reserve_events(1)?;
            let len = frame.len();
            let op = self
                .rooms
                .get_mut(binding.source.room)?
                .operations
                .get_mut(binding.operation.slot)?;
            op.job = Job::Wire {
                purpose: NativePurpose::Send,
                frame: Some(frame),
                length: len,
                encoding: if peer {
                    Encoding::PeerMessage
                } else {
                    Encoding::Ipc
                },
            };
            op.phase = OperationPhase::Prepared;
            op.charged_bytes = capacity;
            self.used = self.used - old + capacity;
            self.event(Event::OperationChanged(
                binding.operation,
                OperationPhase::Prepared,
            ))?;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(()),
            Err(error) => Err(RejectedInput { error, input }),
        }
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
        if self
            .pending_wire(source, NativePurpose::Get, Some(&hash))
            .is_some()
        {
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
            .find(|(_, m)| m.hash == hash && m.source == source)
        {
            m.operation = Some(op.slot);
            m.absent = false;
            m.retry_at = deadline;
        }
        Ok(op)
    }
    /// Original pending missing set. No timer silently retries a non-idempotent
    /// operation or swaps a lost source for a new MQ generation.
    pub fn missing_messages(
        &self,
        room: Room<'id>,
    ) -> Result<impl Iterator<Item = (Hash, Source<'id>, bool)> + '_, Error> {
        Ok(self
            .rooms
            .get(self.check_room(room)?)?
            .missing
            .iter()
            .map(|(_, m)| (m.hash, m.source, m.absent)))
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "original source, member, crypto workspace and finite deadline remain explicit"
    )]
    fn key_operation(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        epoch: Hash,
        id: ShortHash,
        ephemeral_until: Option<u64>,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        self.check_source(source)?;
        self.check_member(member)?;
        self.reserve_events(2)?;
        if source.room != member.room || now >= deadline || deadline == u64::MAX {
            return Err(Fault::InvalidInput.into());
        }
        let row = self.rooms.get(source.room)?;
        let m = row.sessions.get(member.slot)?;
        let contact = m.contact;
        let es = row.find_epoch(&epoch).ok_or(Fault::NotReady)?;
        let e = row.epochs.get(es)?;
        if m.phase != SessionPhase::Active
            || !self.contacts.get(m.contact.slot)?.local
            || !e.complete
            || !e.members.contains(&m.contact)
            || row.local_session() != Some(member.slot)
        {
            return Err(Error::Permission);
        }
        let g = if ephemeral_until.is_none() {
            Some(self.ensure_group(source.room, es, id)?)
        } else {
            None
        };
        if let Some(until) = ephemeral_until
            && (until <= now || until == u64::MAX)
        {
            return Err(Fault::InvalidInput.into());
        }
        let row = self.rooms.get(source.room)?;
        let e = row.epochs.get(es)?;
        let message = if let Some(g) = g {
            let group = e.groups.get(g)?;
            if !group.valid || group.key.is_some() || group.phase == KeyPhase::Generating {
                return Err(Fault::Conflict.into());
            }
            if crate::epoch::identifier_order(group.identifier_order, &id).0
                && crate::epoch::identifier_order(group.identifier_order, &id).1 > 0
            {
                let p = group.proposal.ok_or(Fault::NotReady)?;
                let n = row.nodes.get(row.find_node(&p).ok_or(Fault::NotReady)?)?;
                if !n.local_sent || n.auth.and_then(|a| a.owner).map(|o| o.contact) != Some(contact)
                {
                    return Err(Error::Permission);
                }
                p
            } else {
                [0; 64]
            }
        } else {
            if e.ephemeral.is_some()
                || row.operations.iter().any(|(_, o)| {
                    o.binding.epoch == epoch
                        && matches!(&o.job, Job::EphemeralKey { .. })
                        && !matches!(
                            o.phase,
                            OperationPhase::Complete
                                | OperationPhase::Failed
                                | OperationPhase::Cancelled
                        )
                })
            {
                return Err(Fault::Conflict.into());
            }
            [0; 64]
        };
        let slot = row.operations.next_key()?;
        let operation = Operation {
            core: self.instance,
            room: source.room,
            slot,
        };
        let binding = Binding {
            operation,
            source,
            member: Some(member),
            message,
            epoch,
            identifier: id,
            epoch_revision: e.revision,
        };
        let job = if let Some(valid_until) = ephemeral_until {
            Job::EphemeralKey { valid_until }
        } else {
            Job::SharedKey
        };
        self.rooms
            .get_mut(source.room)?
            .operations
            .insert(OperationRow {
                binding,
                recipient: None,
                job,
                phase: OperationPhase::Prepared,
                deadline,
                written: 0,
                charged_bytes: 0,
            })
            .map_err(|(e, _)| e)?;
        if let Some(g) = g {
            self.rooms
                .get_mut(source.room)?
                .epochs
                .get_mut(es)?
                .groups
                .get_mut(g)?
                .phase = KeyPhase::Generating;
        }
        self.event(Event::OperationChanged(operation, OperationPhase::Prepared))?;
        Ok(operation)
    }
    /// Prepare one original bounded shared-key-provider job for an authorized epoch.
    pub fn request_shared_key(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        epoch: Hash,
        id: ShortHash,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        self.key_operation(source, member, epoch, id, None, now, deadline)
    }
    /// Prepare one actual ephemeral-key-provider job with its original expiry.
    pub fn request_ephemeral_key(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        epoch: Hash,
        valid_until: u64,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        self.key_operation(
            source,
            member,
            epoch,
            [0; 32],
            Some(valid_until),
            now,
            deadline,
        )
    }
    fn checked_key_job(&self, binding: Binding<'id>, now: u64) -> Result<Slot, Error> {
        let op = self.check_binding(binding)?;
        if op.phase != OperationPhase::Taken || op.deadline <= now {
            return Err(Fault::StaleGeneration.into());
        }
        let row = self.rooms.get(binding.source.room)?;
        let e = row
            .find_epoch(&binding.epoch)
            .ok_or(Fault::StaleGeneration)?;
        let epoch = row.epochs.get(e)?;
        let m = row
            .sessions
            .get(binding.member.ok_or(Fault::StaleGeneration)?.slot)?;
        if binding.message != [0; 64] {
            let node = row.nodes.get(
                row.find_node(&binding.message)
                    .ok_or(Fault::StaleGeneration)?,
            )?;
            if matches!(node.phase, MessagePhase::Deleted | MessagePhase::Rejected)
                || !node.semantic_applied
                || !node.local_sent
                || node.epoch != binding.epoch
                || !node.auth.and_then(|a| a.owner).is_some_and(|o| {
                    o.contact == m.contact && o.lineage == m.lineage && o.generation <= m.generation
                })
                || !matches!(node.body(self.profile)?,Body::Group {identifier,..} if *identifier==binding.identifier)
            {
                return Err(Fault::StaleGeneration.into());
            }
        }

        if epoch.revision != binding.epoch_revision
            || !epoch.complete
            || !epoch.members.contains(&m.contact)
            || m.phase != SessionPhase::Active
            || row.local_session() != Some(binding.member.ok_or(Fault::StaleGeneration)?.slot)
        {
            return Err(Fault::StaleGeneration.into());
        }
        Ok(e)
    }
    /// Install only the actual key capability returned for this original admitted job.
    pub fn complete_shared_key(
        &mut self,
        binding: Binding<'id>,
        key: crypto::AeadKey,
        now: u64,
    ) -> Result<(), Error> {
        let e = self.checked_key_job(binding, now)?;
        if !matches!(&self.check_binding(binding)?.job, Job::SharedKey) {
            return Err(Fault::Conflict.into());
        }
        self.reserve_events(3)?;
        let g = self
            .rooms
            .get(binding.source.room)?
            .epochs
            .get(e)?
            .groups
            .iter()
            .find_map(|(s, g)| {
                (g.identifier == binding.identifier && g.phase == KeyPhase::Generating).then_some(s)
            })
            .ok_or(Fault::StaleGeneration)?;
        self.install_group_key(binding.source.room, e, g, key)?;
        self.rooms
            .get_mut(binding.source.room)?
            .operations
            .get_mut(binding.operation.slot)?
            .phase = OperationPhase::Complete;
        self.event(Event::OperationChanged(
            binding.operation,
            OperationPhase::Complete,
        ))?;
        Ok(())
    }
    /// Install only the actual ephemeral capability returned for its original job.
    pub fn complete_ephemeral_key(
        &mut self,
        binding: Binding<'id>,
        key: crypto::EcdheSecret,
        now: u64,
    ) -> Result<(), Error> {
        let e = self.checked_key_job(binding, now)?;
        let Job::EphemeralKey { valid_until } = &self.check_binding(binding)?.job else {
            return Err(Fault::Conflict.into());
        };
        let until = *valid_until;
        if until <= now {
            return Err(Fault::Timeout.into());
        }
        self.reserve_events(1)?;
        let epoch = self.rooms.get_mut(binding.source.room)?.epochs.get_mut(e)?;
        epoch.ephemeral = Some(key);
        epoch.ephemeral_until = until;
        self.rooms
            .get_mut(binding.source.room)?
            .operations
            .get_mut(binding.operation.slot)?
            .phase = OperationPhase::Complete;
        self.event(Event::OperationChanged(
            binding.operation,
            OperationPhase::Complete,
        ))?;
        Ok(())
    }
    /// A provider failure is an actual local fact. A failed shared-key job does
    /// not install a key, advance the epoch or report a transmitted revolution.
    pub fn provider_failed(&mut self, binding: Binding<'id>, error: Error) -> Result<(), Error> {
        self.check_binding(binding)?;
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
        self.reset_failed_key_job(binding)?;
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
        Ok(self
            .rooms
            .get(self.check_room(room)?)?
            .operations
            .iter()
            .find_map(|(_, o)| {
                (!matches!(
                    o.phase,
                    OperationPhase::Complete | OperationPhase::Cancelled | OperationPhase::Failed
                ) && o.deadline <= now)
                    .then_some(o.binding.source)
            }))
    }
}
impl<'id> Core<'id> {
    fn local_sender(
        &self,
        source: Source<'id>,
        member: MemberSession<'id>,
    ) -> Result<(PublicKey, ShortHash), Error> {
        self.check_source(source)?;
        self.check_member(member)?;
        if source.room != member.room {
            return Err(Error::Permission);
        }
        let row = self.rooms.get(source.room)?;
        let m = row.sessions.get(member.slot)?;
        let s = row.sources.get(source.slot)?;
        if s.role != SourceRole::Client
            || !s.create_written
            || m.phase != SessionPhase::Active
            || s.member_id != Some(m.id)
            || row.local_public != Some(m.public)
            || !self.contacts.get(m.contact.slot)?.local
        {
            return Err(Error::Permission);
        }
        Ok((m.public, m.id))
    }
    /// Actual private-message composition for one real advertised recipient.
    /// The caller owns bounded encrypted/plain scratch and real entropy.
    #[expect(
        clippy::too_many_arguments,
        reason = "original source, member, crypto workspace and finite deadline remain explicit"
    )]
    pub fn prepare_private<const N: usize, const M: usize>(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        recipient: MemberSession<'id>,
        body: Body<'_>,
        encrypted: &mut SensitiveBuffer<N>,
        scratch: &mut SensitiveBuffer<M>,
        entropy: &mut impl crypto::Entropy,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        self.prepare_private_profiled(
            source,
            member,
            recipient,
            body,
            ShortLayout::same(self.profile),
            encrypted,
            scratch,
            entropy,
            now,
            deadline,
        )
    }
    /// Real recipient-specific short encoding, independent from this sender's
    /// signed outer grammar and any later relay padding. Recipient/id/public
    /// key remain exact raw protocol bytes, never byte-swapped by this method.
    #[expect(
        clippy::too_many_arguments,
        reason = "Original source/member/recipient, explicit payload and bounded crypto owners stay separate"
    )]
    pub fn prepare_private_profiled<const N: usize, const M: usize>(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        recipient: MemberSession<'id>,
        body: Body<'_>,
        payload: ShortLayout,
        encrypted: &mut SensitiveBuffer<N>,
        scratch: &mut SensitiveBuffer<M>,
        entropy: &mut impl crypto::Entropy,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        let (public, sender) = self.local_sender(source, member)?;
        self.check_member(recipient)?;
        if recipient.room != source.room {
            return Err(Error::Permission);
        }
        let recipient = self
            .rooms
            .get(recipient.room)?
            .sessions
            .get(recipient.slot)?;
        if recipient.phase != SessionPhase::Active {
            return Err(Fault::NotReady.into());
        }
        let attribution = RecipientAttribution::member(
            Owner {
                contact: recipient.contact,
                lineage: recipient.lineage,
                generation: recipient.generation,
            },
            recipient.public,
        );
        let (key, _) = crypto::EcdhePublic::decode_hpke(&recipient.hpke)?;
        encrypted.seal_private_profiled(key, body, payload, scratch, entropy)?;
        let result = self.queue_sign(
            source,
            Some(member),
            Some(attribution),
            public,
            sender,
            crypto::message::private_body(encrypted),
            now,
            deadline,
        );
        encrypted.clear();
        result
    }
    /// Encrypt only with an actual admitted current-epoch announcement key.
    /// Group-subset identifiers cannot silently become whole-room SECRET keys.
    #[expect(
        clippy::too_many_arguments,
        reason = "original source, member, crypto workspace and finite deadline remain explicit"
    )]
    pub fn prepare_secret<const N: usize, const M: usize>(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        body: Body<'_>,
        encrypted: &mut SensitiveBuffer<N>,
        scratch: &mut SensitiveBuffer<M>,
        entropy: &mut impl crypto::Entropy,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        self.prepare_secret_profiled(
            source,
            member,
            body,
            ShortLayout::same(self.profile),
            encrypted,
            scratch,
            entropy,
            now,
            deadline,
        )
    }
    /// Actually encrypt the selected epoch announcement using independent
    /// plaintext encoders. The raw identifier and sender/recipient capabilities
    /// are never normalized into this host's bitfield order.
    #[expect(
        clippy::too_many_arguments,
        reason = "Actual scoped providers and explicit plaintext profile require independent owners"
    )]
    pub fn prepare_secret_profiled<const N: usize, const M: usize>(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        body: Body<'_>,
        payload: ShortLayout,
        encrypted: &mut SensitiveBuffer<N>,
        scratch: &mut SensitiveBuffer<M>,
        entropy: &mut impl crypto::Entropy,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        let (public, sender) = self.local_sender(source, member)?;
        if !crypto::message::permits_private(body.kind()) {
            return Err(Fault::InvalidInput.into());
        }
        let row = self.rooms.get(source.room)?;
        let epoch = row
            .epochs
            .get(row.find_epoch(&row.current_epoch).ok_or(Fault::NotReady)?)?;
        let contact = row.sessions.get(member.slot)?.contact;
        if !epoch.complete || !epoch.members.contains(&contact) {
            return Err(Error::Permission);
        }
        let group = epoch
            .groups
            .get(epoch.best_announcement.ok_or(Fault::NotReady)?)?;
        if !group.valid
            || crate::epoch::identifier_order(group.identifier_order, &group.identifier).0
        {
            return Err(Error::Permission);
        }
        encrypted.seal_secret_profiled(
            &group.identifier,
            group.key.as_ref().ok_or(Fault::NotReady)?,
            body,
            payload,
            scratch,
            entropy,
        )?;
        let encoded = Body::decode(Kind::SECRET, encrypted.expose(), self.profile)?;
        let result = self.queue_sign(
            source,
            Some(member),
            None,
            public,
            sender,
            encoded,
            now,
            deadline,
        );
        encrypted.clear();
        result
    }
    /// Create the exact official identifier bits from an explicit entropy port.
    /// None means announcement(level0, group0); Some(level) means a group.
    pub fn fresh_identifier(
        &self,
        level: Option<u32>,
        entropy: &mut impl crypto::Entropy,
    ) -> Result<ShortHash, Error> {
        if level.is_some_and(|l| {
            l >= usize::BITS
                || l >= 128
                || 1usize
                    .checked_shl(l)
                    .is_none_or(|n| n > self.limits.sessions_per_room)
        }) {
            return Err(Fault::InvalidInput.into());
        }
        let mut id = [0; 32];
        entropy.fill(&mut id).map_err(|_| Fault::Entropy)?;
        id[0] = match (self.profile.endian, level) {
            (wire::profile::Endian::Little, Some(l)) => ((l as u8) << 1) | 1,
            (wire::profile::Endian::Big, Some(l)) => (l as u8) | 0x80,
            (_, None) => 0,
        };
        Ok(id)
    }
    /// Prepare a real own ANNOUNCEMENT from a possessed key and the original
    /// retained ephemeral recipient public key. The nonce is committed only
    /// when a real signature/MAC-checked announcement is received and applied.
    #[expect(
        clippy::too_many_arguments,
        reason = "original source, member, crypto workspace and finite deadline remain explicit"
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
        self.local_sender(source, member)?;
        let row = self.rooms.get(source.room)?;
        let epoch = row
            .epochs
            .get(row.find_epoch(&row.current_epoch).ok_or(Fault::NotReady)?)?;
        let (_, group) = epoch
            .groups
            .iter()
            .find(|(_, g)| g.identifier == id && g.valid)
            .ok_or(Fault::NotReady)?;
        let public_key = *epoch
            .ephemeral
            .as_ref()
            .ok_or(Fault::NotReady)?
            .public_key()
            .as_bytes();
        if epoch.ephemeral_until <= now {
            return Err(Fault::Timeout.into());
        }
        let timeout = timeout.min(epoch.ephemeral_until - now);
        let mut nonce = [0; 32];
        entropy.fill(&mut nonce).map_err(|_| Fault::Entropy)?;
        if epoch.nonces.iter().any(|n| n.value == nonce) {
            return Err(Fault::Replay.into());
        }
        let zero = [0; 64];
        let timeout = gnunet_wire::official::RelativeTime::from_micros(timeout);
        let draft = Body::Announcement {
            identifier: &id,
            public_key: &public_key,
            nonce: &nonce,
            timeout,
            hmac: &zero,
        };
        let mac = crypto::group::message_mac(draft, group.key.as_ref().ok_or(Fault::NotReady)?)?;
        self.prepare_send(
            source,
            member,
            Body::Announcement {
                identifier: &id,
                public_key: &public_key,
                nonce: &nonce,
                timeout,
                hmac: &mac,
            },
            now,
            deadline,
        )
    }
    /// Prepare an appeal bound to one real announcement and own ephemeral public key.
    pub fn prepare_appeal(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        event: Hash,
        timeout: u64,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        self.local_sender(source, member)?;
        let row = self.rooms.get(source.room)?;
        let n = row
            .nodes
            .get(row.find_node(&event).ok_or(Fault::NotFound)?)?;
        if n.auth.is_none()
            || !matches!(n.body(self.profile)?, Body::Announcement {identifier,..} if !self.identifier_bits(source.room,identifier)?.0)
            || n.epoch != row.current_epoch
        {
            return Err(Error::Permission);
        }
        let epoch = row
            .epochs
            .get(row.find_epoch(&n.epoch).ok_or(Fault::NotReady)?)?;
        if epoch.ephemeral_until <= now {
            return Err(Fault::Timeout.into());
        }
        let public_key = *epoch
            .ephemeral
            .as_ref()
            .ok_or(Fault::NotReady)?
            .public_key()
            .as_bytes();
        self.prepare_send(
            source,
            member,
            Body::Appeal {
                event: &event,
                public_key: &public_key,
                timeout: gnunet_wire::official::RelativeTime::from_micros(
                    timeout.min(epoch.ephemeral_until - now),
                ),
            },
            now,
            deadline,
        )
    }
    /// Real ACCESS response to an authenticated original appeal or own group
    /// proposal. The target public key is read from that exact retained event.
    pub fn prepare_access(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        event: Hash,
        entropy: &mut impl crypto::Entropy,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        self.local_sender(source, member)?;
        let row = self.rooms.get(source.room)?;
        let node = row
            .nodes
            .get(row.find_node(&event).ok_or(Fault::NotFound)?)?;
        let epoch = row
            .epochs
            .get(row.find_epoch(&node.epoch).ok_or(Fault::NotReady)?)?;
        if !epoch.complete || node.epoch != row.current_epoch {
            return Err(Fault::NotReady.into());
        }
        let contact = row.sessions.get(member.slot)?.contact;
        let (id, recipient) = match node.body(self.profile)? {
            Body::Appeal {
                event, public_key, ..
            } => {
                if !node
                    .auth
                    .and_then(|a| a.owner)
                    .is_some_and(|o| epoch.members.contains(&o.contact))
                {
                    return Err(Error::Permission);
                }
                let original = row
                    .nodes
                    .get(row.find_node(event).ok_or(Fault::NotReady)?)?;
                let Body::Announcement { identifier, .. } = original.body(self.profile)? else {
                    return Err(Fault::Malformed.into());
                };
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
                let partner = row
                    .nodes
                    .get(row.find_node(partner).ok_or(Fault::NotReady)?)?;
                let Body::Announcement { public_key, .. } = partner.body(self.profile)? else {
                    return Err(Fault::Malformed.into());
                };
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
        self.prepare_send(source, member, access.body(), now, deadline)
    }
    /// Compute and queue an actual key-authenticated revolution; receipt changes validity.
    pub fn prepare_revolution(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        id: ShortHash,
        entropy: &mut impl crypto::Entropy,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        self.local_sender(source, member)?;
        let row = self.rooms.get(source.room)?;
        let e = row
            .epochs
            .get(row.find_epoch(&row.current_epoch).ok_or(Fault::NotReady)?)?;
        let (_, g) = e
            .groups
            .iter()
            .find(|(_, g)| g.identifier == id && g.valid)
            .ok_or(Fault::NotReady)?;
        let mut nonce = [0; 32];
        entropy.fill(&mut nonce).map_err(|_| Fault::Entropy)?;
        if e.nonces.iter().any(|n| n.value == nonce) {
            return Err(Fault::Replay.into());
        }
        let zero = [0; 64];
        let draft = Body::Revolution {
            identifier: &id,
            nonce: &nonce,
            hmac: &zero,
        };
        let mac = crypto::group::message_mac(draft, g.key.as_ref().ok_or(Fault::NotReady)?)?;
        self.prepare_send(
            source,
            member,
            Body::Revolution {
                identifier: &id,
                nonce: &nonce,
                hmac: &mac,
            },
            now,
            deadline,
        )
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
    /// Earliest actual local timer, suitable for one owner-driven alarm. Native
    /// hard deadlines still belong to the original native adapter independently.
    pub fn next_deadline(&self, room: Room<'id>) -> Result<Option<u64>, Error> {
        let r = self.rooms.get(self.check_room(room)?)?;
        let mut min = None;
        let mut observe = |n: u64| {
            if n != u64::MAX {
                min = Some(min.map_or(n, |old: u64| old.min(n)));
            }
        };
        for (_, o) in r.operations.iter() {
            if !matches!(
                o.phase,
                OperationPhase::Complete | OperationPhase::Failed | OperationPhase::Cancelled
            ) {
                observe(o.deadline);
            }
        }
        for (_, n) in r.nodes.iter() {
            if n.phase != MessagePhase::Deleted
                && let Some(d) = n.delete_at
            {
                observe(d);
            }
        }
        for (_, s) in r.subscriptions.iter() {
            if s.keep_alive && s.renew_operation.is_none() {
                if let Some(d) = s.renew_at {
                    observe(d);
                }
            } else if !s.keep_alive {
                observe(s.end.saturating_add(1));
            }
        }
        for (_, e) in r.epochs.iter() {
            if e.ephemeral.is_some() {
                observe(e.ephemeral_until);
            }
            for (_, g) in e.groups.iter() {
                if g.appeal.is_some() {
                    observe(g.appeal_until);
                }
                if g.proposal.is_some() {
                    observe(g.expires);
                }
            }
        }
        Ok(min)
    }
}

impl<'id> Core<'id> {
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
            o.binding.source == source
                && matches!(
                    &o.job,
                    Job::Sign {
                        kind: Kind::JOIN | Kind::ID,
                        ..
                    }
                )
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
impl<'id> Core<'id> {
    /// Seal an actual possessed epoch key into the official encrypted record.
    /// The returned ciphertext is not a NAMESTORE commit or zone-signature fact.
    pub fn seal_epoch_record(
        &self,
        room: Room<'id>,
        epoch: &Hash,
        id: &ShortHash,
        root: &crypto::records::RecordSecret,
        entropy: &mut impl crypto::Entropy,
    ) -> Result<crypto::records::EpochRecord, Error> {
        let row = self.rooms.get(self.check_room(room)?)?;
        let e = row
            .epochs
            .get(row.find_epoch(epoch).ok_or(Fault::NotFound)?)?;
        let (_, g) = e
            .groups
            .iter()
            .find(|(_, g)| {
                g.identifier == *id
                    && g.key.is_some()
                    && matches!(g.phase, KeyPhase::Present | KeyPhase::Revoked)
            })
            .ok_or(Fault::NotReady)?;
        if !e.complete {
            return Err(Fault::NotReady.into());
        }
        Ok(crypto::records::EpochRecord::seal(
            root,
            &row.key,
            epoch,
            id,
            u32::from(g.valid),
            g.key.as_ref().ok_or(Fault::NotReady)?,
            entropy,
        )?)
    }
    /// Complete only an original explicit record-provider job. Exact original
    /// source/member/zone-public/epoch/identifier/revision is checked before
    /// real record AEAD. A flags0 record restores only historical capability,
    /// directly Revoked; flags1 can never revive an already revoked identifier.
    /// No NAMESTORE zone signature, native retrieval or fsync is invented here.
    pub fn complete_epoch_record(
        &mut self,
        binding: Binding<'id>,
        root: &crypto::records::RecordSecret,
        record: wire::records::Record<'_>,
        now: u64,
    ) -> Result<(), Error> {
        let e = self.checked_record_job(binding, now)?;
        let wire::records::Record::EpochKey {
            room_key,
            epoch,
            identifier,
            flags,
            ..
        } = record
        else {
            return Err(Fault::InvalidInput.into());
        };
        if *room_key != self.rooms.get(binding.source.room)?.key
            || *epoch != binding.epoch
            || *identifier != binding.identifier
        {
            return Err(Error::AttributionConflict);
        }
        let g = self
            .rooms
            .get(binding.source.room)?
            .epochs
            .get(e)?
            .groups
            .iter()
            .find_map(|(s, g)| (g.identifier == binding.identifier).then_some(s))
            .ok_or(Fault::StaleGeneration)?;
        if flags & 1 != 0
            && !self
                .rooms
                .get(binding.source.room)?
                .epochs
                .get(e)?
                .groups
                .get(g)?
                .valid
        {
            return Err(Error::Permission);
        }
        self.reserve_events(3)?;
        let key = crypto::records::open_epoch_record(root, record)?;
        // Source cannot change while &mut self is owned. The original record
        // job remains Taken until the actual scoped capability is installed.
        if flags & 1 != 0 {
            self.install_group_key(binding.source.room, e, g, key)?;
        } else {
            self.install_historical_key(binding.source.room, e, g, key)?;
        }
        self.rooms
            .get_mut(binding.source.room)?
            .operations
            .get_mut(binding.operation.slot)?
            .phase = OperationPhase::Complete;
        self.event(Event::OperationChanged(
            binding.operation,
            OperationPhase::Complete,
        ))?;
        Ok(())
    }
    /// Prepare an actual local encrypted-record lookup without withdrawing or
    /// changing any present key. The original current local member/source and
    /// zone public snapshot remain bound; private record AEAD is the historical
    /// key recovery authority, not an invented old-epoch membership grant.
    pub fn request_epoch_record(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        epoch: Hash,
        id: ShortHash,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        self.request_epoch_record_profiled(
            source,
            member,
            EpochRecordTarget {
                epoch,
                identifier: id,
                identifier_order: Some(self.profile.endian),
            },
            now,
            deadline,
        )
    }
    /// Request the actual original record with explicit identifier creator
    /// provenance; a native record producer/receiver ABI does not imply it.
    pub fn request_epoch_record_profiled(
        &mut self,
        source: Source<'id>,
        member: MemberSession<'id>,
        target: EpochRecordTarget,
        now: u64,
        deadline: u64,
    ) -> Result<Operation<'id>, Error> {
        let EpochRecordTarget {
            epoch,
            identifier: id,
            identifier_order,
        } = target;
        if self.mode != Mode::Client {
            return Err(Error::Permission);
        }
        let (public, _) = self.local_sender(source, member)?;
        if now >= deadline || deadline == u64::MAX {
            return Err(Fault::Timeout.into());
        }
        self.reserve_events(2)?;
        let row = self.rooms.get(source.room)?;
        let e = row.find_epoch(&epoch).ok_or(Fault::NotReady)?;
        if !row.epochs.get(e)?.complete {
            return Err(Fault::NotReady.into());
        }
        if row.operations.iter().any(|(_, op)| {
            op.binding.epoch == epoch
                && op.binding.identifier == id
                && matches!(&op.job, Job::EpochRecord { .. })
                && !matches!(
                    op.phase,
                    OperationPhase::Complete | OperationPhase::Failed | OperationPhase::Cancelled
                )
        }) {
            return Err(Fault::WouldBlock.into());
        }
        let slot = row.operations.next_key()?;
        self.ensure_record_group(source.room, e, id, identifier_order)?;
        let operation = Operation {
            core: self.instance,
            room: source.room,
            slot,
        };
        let binding = Binding {
            operation,
            source,
            member: Some(member),
            message: [0; 64],
            epoch,
            identifier: id,
            epoch_revision: self.rooms.get(source.room)?.epochs.get(e)?.revision,
        };
        self.rooms
            .get_mut(source.room)?
            .operations
            .insert(OperationRow {
                binding,
                recipient: None,
                job: Job::EpochRecord { public },
                phase: OperationPhase::Prepared,
                deadline,
                written: 0,
                charged_bytes: 0,
            })
            .map_err(|(e, _)| e)?;
        self.event(Event::OperationChanged(operation, OperationPhase::Prepared))?;
        Ok(operation)
    }
    fn checked_record_job(&self, binding: Binding<'id>, now: u64) -> Result<Slot, Error> {
        if self.mode != Mode::Client {
            return Err(Error::Permission);
        }
        let op = self.check_binding(binding)?;
        if op.phase != OperationPhase::Taken || op.deadline <= now {
            return Err(Fault::StaleGeneration.into());
        }
        let Job::EpochRecord { public } = &op.job else {
            return Err(Fault::Conflict.into());
        };
        let member = binding.member.ok_or(Fault::StaleGeneration)?;
        if self.local_sender(binding.source, member)?.0 != *public {
            return Err(Fault::StaleGeneration.into());
        }
        let row = self.rooms.get(binding.source.room)?;
        let e = row
            .find_epoch(&binding.epoch)
            .ok_or(Fault::StaleGeneration)?;
        let epoch = row.epochs.get(e)?;
        if !epoch.complete || epoch.revision != binding.epoch_revision {
            return Err(Fault::StaleGeneration.into());
        }
        Ok(e)
    }
}

impl<'id> Core<'id> {
    pub(crate) fn reset_failed_key_job(&mut self, binding: Binding<'id>) -> Result<(), Error> {
        let row = self.rooms.get_mut(binding.source.room)?;
        if matches!(
            &row.operations.get(binding.operation.slot)?.job,
            Job::SharedKey
        ) && let Some(e) = row.find_epoch(&binding.epoch)
        {
            let epoch = row.epochs.get_mut(e)?;
            if let Some((_, g)) = epoch.groups.iter_mut().find(|(_, g)| {
                g.identifier == binding.identifier
                    && g.phase == KeyPhase::Generating
                    && g.key.is_none()
            }) {
                g.phase = KeyPhase::Missing;
            }
        }
        for (_, s) in row.subscriptions.iter_mut() {
            if s.renew_operation == Some(binding.operation.slot) {
                s.renew_operation = None;
                s.keep_alive = false;
                s.renew_at = None;
            }
        }
        Ok(())
    }
}
