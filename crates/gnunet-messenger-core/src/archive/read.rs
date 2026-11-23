use super::*;
fn spend(budget: &mut usize, bytes: usize) -> Result<(), Error> {
    *budget = budget.checked_sub(bytes).ok_or(Fault::Capacity)?;
    Ok(())
}

fn count(r: &mut Decoder<'_>, limit: usize) -> Result<usize, Error> {
    r.size(limit)
}
impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    fn read_contact_slot(&self, r: &mut Decoder<'_>) -> Result<Slot, Error> {
        let slot = r.slot(self.limits.contacts)?;
        self.contacts.get(slot)?;
        Ok(slot)
    }
    pub(super) fn read_archive(
        &mut self,
        r: &mut Decoder<'_>,
        generation: u64,
        originals: RecoveryOriginals,
    ) -> Result<(), Error> {
        let l = self.limits;
        for _ in 0..count(r, l.contacts)? {
            let ContactRecord {
                at: slot,
                key,
                name,
                anonymous_context,
                canonical,
            } = ContactRecord::read(r, l)?;
            self.contacts.restore_entry(
                slot.index,
                slot.generation,
                ContactRow {
                    key,
                    name: None,
                    anonymous_context,
                    #[cfg(feature = "alloc")]
                    local: false,
                    canonical,
                    rooms: 0,
                },
            )?;
            if let Some(name) = name {
                self.replace_contact_name(slot, name)?;
            }
        }
        self.contacts.finish_restore();
        for _ in 0..count(r, l.rooms)? {
            let record = RoomRecord::read(r, l)?;
            let slot = record.at;
            if self.rooms.iter().any(|(_, room)| room.key == record.key) {
                return Err(Fault::Conflict.into());
            }
            if self.rooms.slot_at(slot.index).is_some() {
                return Err(Fault::Malformed.into());
            }
            let mut room = self.build_room(slot.index, record.key, None, record.profile)?;
            let mut room_budget = self
                .remaining_bytes()
                .checked_sub(room.metadata_bytes()?)
                .ok_or(Fault::Capacity)?;
            room.current_epoch = record.current_epoch;
            room.last_message = record.last_message;
            room.sequence = record.sequence;
            room.lineage = record.lineage;
            for _ in 0..count(r, l.sessions_per_room)? {
                let SessionRecord { at, row } = SessionRecord::read(r, l, &record)?;
                self.contacts.get(row.contact)?;
                room.sessions.restore_entry(at.index, at.generation, row)?;
            }
            room.sessions.finish_restore();
            for index in 0..room.sessions.limit() {
                if let Some(session) = room.sessions.slot_at(index) {
                    room.schedule_completion(session)?;
                }
            }
            for _ in 0..count(r, l.messages_per_room)? {
                let MessageRecord {
                    at,
                    hash,
                    provenance,
                    phase,
                    frame,
                    owner,
                    session,
                    public,
                    peer,
                    padding,
                    layout,
                    cipher_layout,
                    plain_layout,
                    transcript_layout,
                    identifier_order,
                    semantic_applied,
                    complete,
                    parents,
                    references,
                    frontier_applied,
                    epoch,
                    kind,
                    semantic_kind,
                    timestamp,
                    sequence,
                    requested,
                    delete_at,
                    deleted_by,
                    discourse,
                    local_sent,
                    transcript,
                    private_recipient,
                    meta,
                } = MessageRecord::read(r, l, room.sequence)?;
                if let Some(owner) = owner {
                    self.contacts.get(owner.contact)?;
                }
                let origin = NodeOrigin::archived(
                    ArchivedFact {
                        generation,
                        sequence,
                    },
                    provenance,
                );
                let mut node = Node {
                    hash,
                    origin,
                    resume_pending: false,
                    meta,
                    phase,
                    frame: None,
                    #[cfg(feature = "alloc")]
                    plaintext: None,
                    auth: Some(Authentication {
                        owner,
                        session,
                        public,
                        peer,
                    }),
                    padding,
                    layout,
                    cipher_layout,
                    plain_layout,
                    transcript_layout,
                    identifier_order,
                    semantic_applied,
                    complete,
                    parents,
                    references,
                    frontier_applied,
                    frontier_recent: false,
                    epoch,
                    epoch_indexed: true,
                    kind,
                    semantic_kind,
                    timestamp,
                    sequence,
                    queued: false,
                    requested,
                    delete_at,
                    deleted_by,
                    discourse,
                    local_sent,
                    transcript,
                    private_recipient,
                    #[cfg(feature = "alloc")]
                    recipient: None,
                };
                if let Some((offset, bytes)) = frame {
                    node.frame = Some(
                        if matches!(originals, RecoveryOriginals::Paged)
                            && node.can_archive_original()
                        {
                            // Keep only a locator. Global graph, body and signature
                            // validation still run against this guarded image.
                            RetainedFrame::Archived(ArchiveOriginalRange::at(offset, bytes))
                        } else {
                            let frame = self.frames.copy(bytes, room_budget)?;
                            spend(&mut room_budget, frame.capacity())?;
                            frame
                        },
                    );
                }
                room.restore_node(at, node)?;
            }
            room.nodes.finish_restore();
            for _ in 0..count(r, l.messages_per_room)? {
                let hash = r.array()?;
                if room.queues.frontier.contains(&hash) {
                    return Err(Fault::Malformed.into());
                }
                room.queues.frontier.push(hash)?;
            }
            let aliases = alias_count(r, l)?;
            if aliases > 0 {
                let buckets = AliasBuckets::bucket_count(l.messages_per_room)?;
                let bytes = room.epoch_aliases.initialize(buckets, room_budget)?;
                spend(&mut room_budget, bytes)?;
                for _ in 0..aliases {
                    let key = r.array()?;
                    let epoch = r.array()?;
                    if key == [0; 64]
                        || room.alias(&key).is_some()
                        || room
                            .find_node(&key)
                            .and_then(|s| room.nodes.get(s).ok())
                            .is_some_and(|n| crate::graph::discourse_kind(n.kind))
                    {
                        return Err(Fault::Malformed.into());
                    }
                    room.put_alias(key, epoch)?;
                }
            }
            for _ in 0..count(r, l.epochs_per_room)? {
                use crate::epoch::EpochMutation;
                let record = EpochRecord::read(r, l)?;
                if let EpochMutation::Join(contact) | EpochMutation::Leave(contact) =
                    record.mutation
                {
                    self.contacts.get(contact)?;
                }
                let members = room.member_arena.restore(
                    record.members,
                    l.sessions_per_room,
                    room_budget,
                    || self.read_contact_slot(r),
                )?;
                spend(&mut room_budget, members.owned_bytes()?)?;
                let (complete, revision) = record.finish(r)?;
                if room.find_epoch(&record.hash).is_some() {
                    return Err(Fault::Malformed.into());
                }
                room.epochs.restore_entry(
                    record.at.index,
                    record.at.generation,
                    EpochRow::hosted(
                        record.hash,
                        record.parents,
                        record.mutation,
                        members,
                        complete,
                        revision,
                    ),
                )?;
            }
            room.epochs.finish_restore();
            no_subscriptions(r, l)?;
            room.subscriptions.finish_restore();
            for _ in 0..count(r, l.sources_per_room)? {
                let Some(peer) = read_peer(r)? else {
                    continue;
                };
                if room.queues.peers.iter().any(|p| p.peer == peer.peer) {
                    return Err(Fault::Malformed.into());
                }
                room.queues.peers.push(peer)?;
            }
            let bytes = room.retained_bytes()?;
            self.charge(bytes)?;
            self.rooms
                .restore_entry(slot.index, slot.generation, room)?;
        }
        self.rooms.finish_restore();
        for (_, c) in self.contacts.iter_mut() {
            c.rooms = 0;
        }
        for (_, room) in self.rooms.iter() {
            for (contact_slot, contact) in self.contacts.iter_mut() {
                if room.sessions.iter().any(|(_, s)| s.contact == contact_slot) {
                    contact.rooms = contact.rooms.checked_add(1).ok_or(Fault::Overflow)?
                }
            }
        }
        Ok(())
    }
}
