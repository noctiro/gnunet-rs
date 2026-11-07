use super::*;
fn reserve<T>(limit: usize) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(limit).map_err(|_| Fault::Capacity)?;
    Ok(v)
}
fn count(r: &mut Decoder<'_>, limit: usize) -> Result<usize, Error> {
    r.size(limit)
}
fn number(r: &mut Decoder<'_>) -> Result<u32, Error> {
    u32::try_from(r.u64()?).map_err(|_| Fault::Overflow.into())
}
impl<'id> Core<'id> {
    fn restored_contact(&self, slot: Slot) -> Result<Contact<'id>, Error> {
        self.contacts.get(slot)?;
        Ok(Contact {
            core: self.instance,
            room: Slot {
                index: usize::MAX,
                generation: 0,
            },
            slot,
        })
    }
    pub(super) fn read_archive(
        &mut self,
        r: &mut Decoder<'_>,
        generation: u64,
    ) -> Result<(), Error> {
        let l = self.limits;
        for _ in 0..count(r, l.contacts)? {
            let slot = r.slot(l.contacts)?;
            let key = r.array()?;
            wire::PublicKey::new(&key)?;
            let name = r.owned(l.name_bytes)?;
            let anonymous_context = r.opt_array()?;
            let canonical = r.bool()?;
            let bytes = name.as_ref().map_or(0, OwnedBytes::capacity);
            self.charge(bytes)?;
            self.contacts.restore_entry(
                slot.index,
                slot.generation,
                ContactRow {
                    key,
                    name,
                    anonymous_context,
                    local: false,
                    canonical,
                    rooms: 0,
                },
            )?;
        }
        self.contacts.finish_restore();
        for _ in 0..count(r, l.rooms)? {
            let slot = r.slot(l.rooms)?;
            let key = r.array()?;
            if self.rooms.iter().any(|(_, room)| room.key == key) {
                return Err(Fault::Conflict.into());
            }
            let profile = r.profile()?;
            if RoomRow::required_bytes(l)? > self.remaining_bytes() {
                return Err(Fault::Capacity.into());
            }
            let mut room = RoomRow::new(key, None, l, profile)?;
            room.current_epoch = r.array()?;
            room.last_message = r.array()?;
            room.sequence = r.u64()?;
            room.lineage = r.u64()?;
            for _ in 0..count(r, l.sessions_per_room)? {
                let at = r.slot(l.sessions_per_room)?;
                let contact = self.restored_contact(r.slot(l.contacts)?)?;
                let id = r.array()?;
                let public = r.array()?;
                wire::PublicKey::new(&public)?;
                let hpke = r.array()?;
                wire::keys::HpkePublicKey::new(&hpke)?;
                let lineage = r.u64()?;
                let version = r.u64()?;
                let known_from = r.u64()?;
                let historical_phase = read_session_phase(r)?;
                let first_bound = r.array()?;
                let last_bound = r.array()?;
                let successor = r.opt_slot(l.sessions_per_room)?;
                let completed_at = r.opt_u64()?;
                if lineage == 0
                    || version == 0
                    || lineage > room.lineage
                    || known_from > room.sequence
                {
                    return Err(Fault::Malformed.into());
                }
                room.sessions.restore_entry(
                    at.index,
                    at.generation,
                    SessionRow {
                        contact,
                        id,
                        public,
                        hpke,
                        lineage,
                        generation: version,
                        known_from,
                        phase: SessionPhase::Completed,
                        first_bound,
                        last_bound,
                        successor,
                        completed_at,
                        archived: true,
                        historical_phase,
                    },
                )?;
            }
            room.sessions.finish_restore();
            for index in 0..room.sessions.limit() {
                if let Some(session) = room.sessions.slot_at(index) {
                    room.schedule_completion(session)?;
                }
            }
            for _ in 0..count(r, l.messages_per_room)? {
                let at = r.slot(l.messages_per_room)?;
                let hash = r.array()?;
                let provenance = r.source()?;
                let phase = read_phase(r)?;
                let frame = r.owned(l.frame_bytes)?;
                let owner = if r.bool()? {
                    Some(Owner {
                        contact: self.restored_contact(r.slot(l.contacts)?)?,
                        lineage: r.u64()?,
                        generation: r.u64()?,
                    })
                } else {
                    None
                };
                let session = r.opt_slot(l.sessions_per_room)?;
                let public = r.array()?;
                wire::PublicKey::new(&public)?;
                let peer = r.opt_array()?;
                let padding = read_pad(r)?;
                let layout = r.layout()?;
                let cipher_layout = if r.bool()? {
                    Some(ShortLayout {
                        body: r.profile()?,
                        padding: r.profile()?,
                    })
                } else {
                    None
                };
                let plain_layout = if r.bool()? {
                    Some(ShortLayout {
                        body: r.profile()?,
                        padding: r.profile()?,
                    })
                } else {
                    None
                };
                let transcript_layout = if r.bool()? {
                    Some(ShortLayout {
                        body: r.profile()?,
                        padding: r.profile()?,
                    })
                } else {
                    None
                };
                let identifier_order = match r.u8()? {
                    0 => None,
                    1 => Some(wire::profile::Endian::Little),
                    2 => Some(wire::profile::Endian::Big),
                    _ => return Err(Fault::Malformed.into()),
                };
                let semantic_applied = r.bool()?;
                let complete = r.bool()?;
                let parents = [r.array()?, r.array()?];
                let references = [r.array()?, r.array()?, r.array()?];
                let frontier_applied = r.bool()?;
                let epoch = r.array()?;
                let kind = wire::envelope::Kind::new(number(r)?);
                let semantic_kind = wire::envelope::Kind::new(number(r)?);
                let timestamp = r.u64()?;
                let sequence = r.u64()?;
                let requested = r.bool()?;
                let delete_at = r.opt_u64()?;
                let deleted_by = r.opt_array()?;
                let discourse = r.opt_array()?;
                let local_sent = r.bool()?;
                let transcript = r.opt_array()?;
                let private_recipient = r.opt_array()?;
                let meta = ReceiveMeta {
                    epoch: r.array()?,
                    flags: number(r)?,
                    requested: r.bool()?,
                    sender_hash: r.opt_array()?,
                    context: r.opt_array()?,
                };
                if sequence == 0
                    || sequence > room.sequence
                    || !kind.is_known()
                    || !semantic_kind.is_known()
                    || hash == [0; 64]
                    || parents.contains(&hash)
                    || frame.is_none() && phase != MessagePhase::Deleted
                {
                    return Err(Fault::Malformed.into());
                }
                let origin = MessageOrigin::Archived(ArchivedFact {
                    generation,
                    sequence,
                });
                let node = Node {
                    hash,
                    origin,
                    provenance,
                    resume_pending: false,
                    meta,
                    phase,
                    frame,
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
                    plain_padding: wire::padding::Decode::Required,
                    semantic_applied,
                    complete,
                    parents,
                    references,
                    frontier_applied,
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
                    recipient: None,
                    visit: 0,
                };
                if room.find_node(&hash).is_some() {
                    return Err(Fault::Conflict.into());
                }
                room.nodes.restore_entry(at.index, at.generation, node)?;
                let insert = room
                    .index
                    .binary_search_by(|s| {
                        room.nodes
                            .get(*s)
                            .map_or(core::cmp::Ordering::Less, |n| n.hash.cmp(&hash))
                    })
                    .unwrap_or_else(|i| i);
                room.index.insert(insert, at);
            }
            room.nodes.finish_restore();
            for _ in 0..count(r, l.messages_per_room)? {
                let hash = r.array()?;
                if room.frontier.contains(&hash) {
                    return Err(Fault::Malformed.into());
                }
                room.frontier.push(hash);
            }
            let aliases = count(
                r,
                l.messages_per_room.checked_mul(3).ok_or(Fault::Overflow)?,
            )?;
            if aliases > 0 {
                let buckets = l.messages_per_room.checked_mul(4).ok_or(Fault::Overflow)?;
                room.epoch_aliases = reserve(buckets)?;
                room.epoch_aliases.resize_with(buckets, || None);
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
                let at = r.slot(l.epochs_per_room)?;
                let hash = r.array()?;
                let parents = [r.array()?, r.array()?];
                let mutation = match r.u8()? {
                    0 => crate::epoch::EpochMutation::Join(
                        self.restored_contact(r.slot(l.contacts)?)?,
                    ),
                    1 => crate::epoch::EpochMutation::Leave(
                        self.restored_contact(r.slot(l.contacts)?)?,
                    ),
                    2 => crate::epoch::EpochMutation::Merge,
                    _ => return Err(Fault::Malformed.into()),
                };
                let mut members = reserve(l.sessions_per_room)?;
                for _ in 0..count(r, l.sessions_per_room)? {
                    let c = self.restored_contact(r.slot(l.contacts)?)?;
                    if members.contains(&c) {
                        return Err(Fault::Malformed.into());
                    }
                    members.push(c)
                }
                let complete = r.bool()?;
                let revision = r.u64()?;
                let mut nonces = reserve(l.nonce_per_epoch)?;
                for _ in 0..count(r, l.nonce_per_epoch)? {
                    let value = r.array()?;
                    let message = r.array()?;
                    if nonces
                        .iter()
                        .any(|n: &crate::epoch::Nonce| n.value == value)
                    {
                        return Err(Fault::Malformed.into());
                    }
                    nonces.push(crate::epoch::Nonce { value, message })
                }
                let mut groups = Slots::new(l.groups_per_epoch)?;
                for _ in 0..count(r, l.groups_per_epoch)? {
                    let at = r.slot(l.groups_per_epoch)?;
                    let identifier = r.array()?;
                    let identifier_order = match r.u8()? {
                        0 => wire::profile::Endian::Little,
                        1 => wire::profile::Endian::Big,
                        _ => return Err(Fault::Malformed.into()),
                    };
                    let target = count(r, l.sessions_per_room)?;
                    let valid = r.bool()?;
                    let revoked = r.bool()?;
                    let expires = r.u64()?;
                    let appeal = r.opt_array()?;
                    let appeal_until = r.u64()?;
                    let proposal = r.opt_array()?;
                    let generation = r.u64()?;
                    let derived_from = if r.bool()? {
                        Some((r.array()?, r.array()?))
                    } else {
                        None
                    };
                    let mut confirmations = reserve(target)?;
                    for _ in 0..count(r, target)? {
                        let contact = self.restored_contact(r.slot(l.contacts)?)?;
                        let message = r.array()?;
                        let verified_mac = r.bool()?;
                        if confirmations
                            .iter()
                            .any(|c: &Confirmation<'id>| c.contact == contact)
                        {
                            return Err(Fault::Malformed.into());
                        }
                        confirmations.push(Confirmation {
                            contact,
                            message,
                            verified_mac,
                        })
                    }
                    if target == 0 || target > members.len() || generation == 0 {
                        return Err(Fault::Malformed.into());
                    }
                    groups.restore_entry(
                        at.index,
                        at.generation,
                        GroupRow {
                            identifier,
                            identifier_order,
                            target,
                            valid,
                            phase: if revoked {
                                KeyPhase::Revoked
                            } else {
                                KeyPhase::Missing
                            },
                            key: None,
                            confirmations,
                            expires,
                            appeal,
                            appeal_until,
                            proposal,
                            generation,
                            derived_from,
                        },
                    )?;
                }
                groups.finish_restore();
                if hash == [0; 64]
                    || parents.contains(&hash)
                    || revision == 0
                    || room.find_epoch(&hash).is_some()
                {
                    return Err(Fault::Malformed.into());
                }
                room.epochs.restore_entry(
                    at.index,
                    at.generation,
                    EpochRow {
                        hash,
                        parents,
                        mutation,
                        members,
                        complete,
                        groups,
                        nonces,
                        revision,
                        ephemeral: None,
                        ephemeral_until: 0,
                        best_announcement: None,
                        best_group: None,
                    },
                )?;
            }
            room.epochs.finish_restore();
            if count(r, l.subscriptions_per_room)? != 0 {
                return Err(Fault::Malformed.into());
            }
            room.subscriptions.finish_restore();
            for _ in 0..count(r, l.sources_per_room)? {
                let peer = r.array()?;
                let historical_candidate = r.bool()?;
                let connection_amount = number(r)?;
                let connection_flags = number(r)?;
                if room.peers.iter().any(|p| p.peer == peer) {
                    return Err(Fault::Malformed.into());
                }
                room.peers.push(PeerRow {
                    peer,
                    announced: false,
                    historical_candidate,
                    connection_amount,
                    connection_flags,
                })
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
                if room
                    .sessions
                    .iter()
                    .any(|(_, s)| s.contact.slot == contact_slot)
                {
                    contact.rooms = contact.rooms.checked_add(1).ok_or(Fault::Overflow)?
                }
            }
        }
        Ok(())
    }
}
