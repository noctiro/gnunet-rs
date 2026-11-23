//! Client key-provider jobs and checked epoch record access.

use crate::{engine::Core, state::*, *};
use gnunet_types::Error as Fault;
use wire::body::Body;

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
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
        self.local_sender(source, member)?;
        self.reserve_events(2)?;
        if now >= deadline || deadline == u64::MAX {
            return Err(Fault::InvalidInput.into());
        }
        let row = self.rooms.get(source.room)?;
        let m = row.sessions.get(member.slot)?;
        let contact = m.contact;
        let es = row.find_epoch(&epoch).ok_or(Fault::NotReady)?;
        let e = row.epochs.get(es)?;
        if m.phase != SessionPhase::Active
            || !self.contacts.get(m.contact)?.local
            || !e.complete
            || !row.epoch_has_member(e, m.contact)
            || row.local_session() != Some(member.slot)
        {
            return Err(Error::Permission);
        }
        let g = if ephemeral_until.is_some() {
            None
        } else {
            let order = self
                .known_identifier_order(source.room, &id)?
                .unwrap_or(self.profile.endian);
            let (group, level) = crate::epoch::identifier_order(order, &id);
            if group && level != 0 {
                let admitted = e.groups.iter().find_map(|(slot, group)| {
                    (group.identifier == id && group.proposal.is_some()).then_some(slot)
                });
                let Some(admitted) = admitted else {
                    let reason = if row.group_proposal_position(es, &id).is_ok() {
                        Fault::Timeout
                    } else {
                        Fault::NotReady
                    };
                    return Err(reason.into());
                };
                Some(admitted)
            } else {
                Some(self.ensure_group(source.room, es, id)?)
            }
        };
        if let Some(until) = ephemeral_until
            && (until <= now || until == u64::MAX)
        {
            return Err(Fault::InvalidInput.into());
        }
        let row = self.rooms.get(source.room)?;
        let e = row.epochs.get(es)?;
        if ephemeral_until.is_none() && row.derivation.pending() {
            return Err(Fault::WouldBlock.into());
        }
        let mut deadline = deadline;
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
                deadline = deadline.min(self.group_proposal_deadline(source.room, es, id, p)?);
                if now >= deadline {
                    return Err(Fault::Timeout.into());
                }
                p
            } else {
                [0; 64]
            }
        } else {
            if e.ephemeral_at(now).is_some()
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
        let slot = self.next_operation_slot(source.room, OperationClass::Ordinary)?;
        let operation = self.instance.operation_id(source.room, slot);
        let binding = OperationBinding {
            source: source.slot,
            member: Some(member.slot),
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
                class: OperationClass::Ordinary,
                join_echo: false,
                binding,
                signed_kind: None,
                group_keys: [None; 2],
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
            if now
                >= self.group_proposal_deadline(
                    binding.source.room,
                    e,
                    binding.identifier,
                    binding.message,
                )?
                || matches!(node.phase, MessagePhase::Deleted | MessagePhase::Rejected)
                || !node.semantic_applied
                || !node.local_sent
                || node.epoch != binding.epoch
                || !node.auth.and_then(|a| a.owner).is_some_and(|o| {
                    o.contact == m.contact && o.lineage == m.lineage && o.generation <= m.generation
                })
                || !matches!(node.body(&self.frames)?,Body::Group {identifier,..} if *identifier==binding.identifier)
            {
                return Err(Fault::StaleGeneration.into());
            }
        }

        if epoch.revision != binding.epoch_revision
            || !epoch.complete
            || !row.epoch_has_member(epoch, m.contact)
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
        let (g, local_only) = self
            .rooms
            .get(binding.source.room)?
            .epochs
            .get(e)?
            .groups
            .iter()
            .find_map(|(s, g)| {
                (g.identifier == binding.identifier && g.phase == KeyPhase::Generating).then_some((
                    s,
                    g.confirmations.is_empty() && g.key_custody == GroupKeyCustody::Provisional,
                ))
            })
            .ok_or(Fault::StaleGeneration)?;
        self.install_group_key(binding.source.room, e, g, key)?;
        if binding.message != [0; 64] && local_only {
            let group = self
                .rooms
                .get_mut(binding.source.room)?
                .epochs
                .get_mut(e)?
                .groups
                .get_mut(g)?;
            group.key_custody = GroupKeyCustody::Provisional;
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
        epoch.ephemeral = Some(EphemeralRecipient {
            public: key.public_key(),
            secret: key,
            valid_until: until,
        });
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
    /// Seal an actual possessed epoch key into the official encrypted record.
    /// The returned ciphertext is not a NAMESTORE commit or zone-signature fact.
    pub fn seal_epoch_record(
        &mut self,
        room: Room<'id>,
        epoch: &Hash,
        id: &ShortHash,
        root: &crypto::records::RecordSecret,
        entropy: &mut impl crypto::Entropy,
    ) -> Result<crypto::records::EpochRecord, Error> {
        let room = self.check_room(room)?;
        let row = self.rooms.get_mut(room)?;
        let e = row.find_epoch(epoch).ok_or(Fault::NotFound)?;
        let e = row.epochs.get_mut(e)?;
        let (_, g) = e
            .groups
            .iter_mut()
            .find(|(_, g)| {
                g.identifier == *id
                    && g.key.is_some()
                    && matches!(g.phase, KeyPhase::Present | KeyPhase::Revoked)
            })
            .ok_or(Fault::NotReady)?;
        if !e.complete {
            return Err(Fault::NotReady.into());
        }
        let sealed = crypto::records::EpochRecord::seal(
            root,
            &row.key,
            epoch,
            id,
            u32::from(g.valid),
            g.key.as_ref().ok_or(Fault::NotReady)?,
            entropy,
        )?;
        // The returned ciphertext is independently usable by its caller.
        g.key_custody = GroupKeyCustody::Retained;
        Ok(sealed)
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
        let (e, identifier_order) = self.checked_record_job(binding, now)?;
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
        self.reserve_events(3)?;
        let key = crypto::records::open_epoch_record(root, record)?;
        if self
            .known_identifier_order(binding.source.room, identifier)?
            .is_some_and(|known| known != identifier_order)
        {
            return Err(Error::AttributionConflict);
        }
        let historical = flags & 1 == 0;
        let g = self.ensure_record_group(
            binding.source.room,
            e,
            *identifier,
            identifier_order,
            historical,
        )?;
        // Source cannot change while &mut self is owned. The original record
        // job remains Taken until the actual scoped capability is installed.
        if historical {
            self.install_historical_key(binding.source.room, e, g, key)?;
        } else {
            self.install_group_key(binding.source.room, e, g, key)?;
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
        let slot = self.next_operation_slot(source.room, OperationClass::Ordinary)?;
        let identifier_order = self
            .known_identifier_order(source.room, &id)?
            .or(identifier_order)
            .ok_or(Fault::NotReady)?;
        let group = row
            .epochs
            .get(e)?
            .groups
            .iter()
            .find_map(|(slot, group)| (group.identifier == id).then_some(slot));
        let operation = self.instance.operation_id(source.room, slot);
        let binding = OperationBinding {
            source: source.slot,
            member: Some(member.slot),
            message: [0; 64],
            epoch,
            identifier: id,
            epoch_revision: self.rooms.get(source.room)?.epochs.get(e)?.revision,
        };
        self.rooms
            .get_mut(source.room)?
            .operations
            .insert(OperationRow {
                class: OperationClass::Ordinary,
                join_echo: false,
                binding,
                signed_kind: None,
                group_keys: [group, None],
                recipient: None,
                job: Job::EpochRecord {
                    public,
                    identifier_order,
                },
                phase: OperationPhase::Prepared,
                deadline,
                written: 0,
                charged_bytes: 0,
            })
            .map_err(|(e, _)| e)?;
        self.event(Event::OperationChanged(operation, OperationPhase::Prepared))?;
        Ok(operation)
    }
    fn checked_record_job(
        &self,
        binding: Binding<'id>,
        now: u64,
    ) -> Result<(Slot, wire::profile::Endian), Error> {
        if self.mode != Mode::Client {
            return Err(Error::Permission);
        }
        let op = self.check_binding(binding)?;
        if op.phase != OperationPhase::Taken || op.deadline <= now {
            return Err(Fault::StaleGeneration.into());
        }
        let Job::EpochRecord {
            public,
            identifier_order,
        } = &op.job
        else {
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
        if let Some(group) = op.group_keys[0]
            && epoch.groups.get(group)?.identifier != binding.identifier
        {
            return Err(Fault::StaleGeneration.into());
        }
        Ok((e, *identifier_order))
    }
}
