//! Canonical GMSHIS06 rows for publication, recovery and borrowed history.

use super::*;

pub(super) fn number(r: &mut Decoder<'_>) -> Result<u32, Error> {
    u32::try_from(r.u64()?).map_err(|_| Fault::Overflow.into())
}

pub(super) fn alias_count(r: &mut Decoder<'_>, l: Limits) -> Result<usize, Error> {
    r.size(l.messages_per_room.checked_mul(3).ok_or(Fault::Overflow)?)
}

pub(super) fn no_subscriptions(r: &mut Decoder<'_>, l: Limits) -> Result<(), Error> {
    if r.size(l.subscriptions_per_room)? != 0 {
        return Err(Fault::Malformed.into());
    }
    Ok(())
}

pub(super) fn read_peer(r: &mut Decoder<'_>) -> Result<Option<PeerRow>, Error> {
    let peer = r.array()?;
    let candidate = r.bool()?;
    // Consume the archived amount and flags without granting live metadata.
    number(r)?;
    number(r)?;
    Ok(candidate.then_some(PeerRow::candidate(peer)))
}

pub(super) struct EpochRecord {
    pub(super) at: Slot,
    pub(super) hash: Hash,
    pub(super) parents: [Hash; 2],
    pub(super) mutation: crate::epoch::EpochMutation,
    pub(super) members: usize,
}

impl EpochRecord {
    pub(super) fn read(r: &mut Decoder<'_>, l: Limits) -> Result<Self, Error> {
        use crate::epoch::EpochMutation;
        let at = r.slot(l.epochs_per_room)?;
        let hash = r.array()?;
        let parents: [Hash; 2] = [r.array()?, r.array()?];
        let mutation = match r.u8()? {
            0 => EpochMutation::Join(r.slot(l.contacts)?),
            1 => EpochMutation::Leave(r.slot(l.contacts)?),
            2 => EpochMutation::Merge,
            _ => return Err(Fault::Malformed.into()),
        };
        if hash == [0; 64] || parents.contains(&hash) {
            return Err(Fault::Malformed.into());
        }
        Ok(Self {
            at,
            hash,
            parents,
            mutation,
            members: r.size(l.sessions_per_room)?,
        })
    }

    pub(super) fn finish(&self, r: &mut Decoder<'_>) -> Result<(bool, u64), Error> {
        let complete = r.bool()?;
        let revision = r.u64()?;
        // The two client-only key and replay counts are reserved in service history.
        if (!complete && self.members != 0) || revision == 0 || r.u64()? != 0 || r.u64()? != 0 {
            return Err(Fault::Malformed.into());
        }
        Ok((complete, revision))
    }
}

pub(super) struct ContactRecord<'archive> {
    pub(super) at: Slot,
    pub(super) key: PublicKey,
    pub(super) name: Option<&'archive [u8]>,
    pub(super) anonymous_context: Option<Hash>,
    pub(super) canonical: bool,
}

impl<'archive> ContactRecord<'archive> {
    pub(super) fn read(r: &mut Decoder<'archive>, l: Limits) -> Result<Self, Error> {
        let at = r.slot(l.contacts)?;
        let key = r.array()?;
        wire::PublicKey::new(&key)?;
        Ok(Self {
            at,
            key,
            name: r.opt_bytes(l.name_bytes)?,
            anonymous_context: r.opt_array()?,
            canonical: r.bool()?,
        })
    }
}

pub(super) struct RoomRecord {
    pub(super) at: Slot,
    pub(super) key: Hash,
    pub(super) profile: wire::profile::Profile,
    pub(super) current_epoch: Hash,
    pub(super) last_message: Hash,
    pub(super) sequence: u64,
    pub(super) lineage: u64,
}

impl RoomRecord {
    pub(super) fn read(r: &mut Decoder<'_>, l: Limits) -> Result<Self, Error> {
        Ok(Self {
            at: r.slot(l.rooms)?,
            key: r.array()?,
            profile: r.profile()?,
            current_epoch: r.array()?,
            last_message: r.array()?,
            sequence: r.u64()?,
            lineage: r.u64()?,
        })
    }
}

pub(super) struct SessionRecord {
    pub(super) at: Slot,
    pub(super) row: SessionRow,
}

impl SessionRecord {
    pub(super) fn read(r: &mut Decoder<'_>, l: Limits, room: &RoomRecord) -> Result<Self, Error> {
        let at = r.slot(l.sessions_per_room)?;
        let contact = r.slot(l.contacts)?;
        let id = r.array()?;
        let public = r.array()?;
        wire::PublicKey::new(&public)?;
        let hpke = r.array()?;
        wire::keys::HpkePublicKey::new(&hpke)?;
        let lineage = r.u64()?;
        let generation = r.u64()?;
        let known_from = r.u64()?;
        if lineage == 0 || generation == 0 || lineage > room.lineage || known_from > room.sequence {
            return Err(Fault::Malformed.into());
        }
        Ok(Self {
            at,
            row: SessionRow {
                contact,
                id,
                public,
                hpke,
                lineage,
                generation,
                known_from,
                phase: SessionPhase::Completed,
                historical_phase: read_session_phase(r)?,
                first_bound: r.array()?,
                last_bound: r.array()?,
                successor: r.opt_slot(l.sessions_per_room)?,
                completed_at: r.opt_u64()?,
                archived: true,
            },
        })
    }
}

/// One authenticated node projected into its canonical SERVICE archive row.
pub(super) struct AuthenticatedMessageRow<'row> {
    room: &'row Hash,
    at: Slot,
    node: &'row Node,
    auth: &'row Authentication,
}

impl<'row> AuthenticatedMessageRow<'row> {
    pub(super) fn from_node(room: &'row Hash, at: Slot, node: &'row Node) -> Option<Self> {
        Some(Self {
            room,
            at,
            node,
            auth: node.auth.as_ref()?,
        })
    }

    /// Write one complete row. The sink controls where original bytes are
    /// read and placed, while the row controls durable projection.
    pub(super) fn write(
        self,
        w: &mut Encoder<impl ArchiveSink>,
        frames: &FrameStore<'_>,
    ) -> Result<(), Error> {
        let Self {
            room,
            at,
            node,
            auth,
        } = self;
        if !node.epoch_indexed {
            return Err(Fault::WouldBlock.into());
        }
        if has_client_message_state(node) {
            return Err(Error::Permission);
        }
        let transient = crate::graph::discourse_kind(node.kind);
        w.slot(at)?;
        w.raw(&node.hash)?;
        w.source(node.origin.provenance())?;
        w.u8(phase(if transient {
            MessagePhase::Deleted
        } else {
            node.phase
        }))?;
        if transient {
            w.original(room, &node.hash, None)?;
        } else if let Some(range) = node.archived_original() {
            if !node.can_archive_original() {
                return Err(Fault::Conflict.into());
            }
            w.archived_original(room, &node.hash, range)?;
        } else {
            w.original(room, &node.hash, node.original(frames)?)?;
        }
        w.bool(auth.owner.is_some())?;
        if let Some(o) = auth.owner {
            w.slot(o.contact)?;
            w.u64(o.lineage)?;
            w.u64(o.generation)?
        }
        w.opt_slot(auth.session)?;
        w.raw(&auth.public)?;
        w.opt_array(auth.peer.as_ref())?;
        w.u8(pad(node.padding))?;
        w.layout(node.layout)?;
        w.bool(!transient && node.cipher_layout.is_some())?;
        if let Some(layout) = node.cipher_layout.filter(|_| !transient) {
            w.profile(layout.body)?;
            w.profile(layout.padding)?;
        }
        w.bool(!transient && node.plain_layout.is_some())?;
        if let Some(layout) = node.plain_layout.filter(|_| !transient) {
            w.profile(layout.body)?;
            w.profile(layout.padding)?;
        }
        w.bool(!transient && node.transcript_layout.is_some())?;
        if let Some(layout) = node.transcript_layout.filter(|_| !transient) {
            w.profile(layout.body)?;
            w.profile(layout.padding)?;
        }
        w.u8(
            match if transient {
                None
            } else {
                node.identifier_order
            } {
                None => 0,
                Some(wire::profile::Endian::Little) => 1,
                Some(wire::profile::Endian::Big) => 2,
            },
        )?;
        w.bool(transient || node.semantic_applied)?;
        w.bool(node.complete)?;
        for p in &node.parents {
            w.raw(p)?
        }
        for p in if transient {
            &[[0; 64]; 3]
        } else {
            &node.references
        } {
            w.raw(p)?
        }
        w.bool(transient || node.frontier_applied)?;
        w.raw(if transient { &[0; 64] } else { &node.epoch })?;
        w.u64(u64::from(node.kind.value()))?;
        w.u64(u64::from(node.semantic_kind.value()))?;
        w.u64(node.timestamp)?;
        w.u64(node.sequence)?;
        w.bool(!transient && node.requested)?;
        w.opt_u64(if transient { None } else { node.delete_at })?;
        w.opt_array(if transient {
            None
        } else {
            node.deleted_by.as_ref()
        })?;
        w.opt_array(if transient {
            None
        } else {
            node.discourse.as_ref()
        })?;
        w.bool(!transient && node.local_sent)?;
        w.opt_array(if transient {
            None
        } else {
            node.transcript.as_ref()
        })?;
        w.opt_array(if transient {
            None
        } else {
            node.private_recipient.as_ref()
        })?;
        w.raw(if transient {
            &[0; 64]
        } else {
            &node.meta.epoch
        })?;
        w.u64(if transient {
            0
        } else {
            u64::from(node.meta.flags)
        })?;
        w.bool(!transient && node.meta.requested)?;
        w.opt_array(if transient {
            None
        } else {
            node.meta.sender_hash.as_ref()
        })?;
        w.opt_array(if transient {
            None
        } else {
            node.meta.context.as_ref()
        })?;
        Ok(())
    }
}

pub(super) struct MessageRecord<'archive> {
    pub(super) at: Slot,
    pub(super) hash: Hash,
    pub(super) provenance: SourceObservation,
    pub(super) phase: MessagePhase,
    pub(super) frame: Option<(usize, &'archive [u8])>,
    pub(super) owner: Option<Owner>,
    pub(super) session: Option<Slot>,
    pub(super) public: PublicKey,
    pub(super) peer: Option<ShortHash>,
    pub(super) padding: wire::padding::Decode,
    pub(super) layout: OriginalLayout,
    pub(super) cipher_layout: Option<ShortLayout>,
    pub(super) plain_layout: Option<ShortLayout>,
    pub(super) transcript_layout: Option<ShortLayout>,
    pub(super) identifier_order: Option<wire::profile::Endian>,
    pub(super) semantic_applied: bool,
    pub(super) complete: bool,
    pub(super) parents: [Hash; 2],
    pub(super) references: [Hash; 3],
    pub(super) frontier_applied: bool,
    pub(super) epoch: Hash,
    pub(super) kind: wire::envelope::Kind,
    pub(super) semantic_kind: wire::envelope::Kind,
    pub(super) timestamp: u64,
    pub(super) sequence: u64,
    pub(super) requested: bool,
    pub(super) delete_at: Option<u64>,
    pub(super) deleted_by: Option<Hash>,
    pub(super) discourse: Option<ShortHash>,
    pub(super) local_sent: bool,
    pub(super) transcript: Option<Hash>,
    pub(super) private_recipient: Option<PublicKey>,
    pub(super) meta: ReceiveMeta,
}

/// Offsets into the one checked canonical byte encoding. A detached page edit
/// can reuse unchanged spans without decoding or rewriting an original body.
pub(super) struct MessageOffsets {
    pub(super) phase: usize,
    pub(super) after_frame: usize,
    pub(super) sequence: usize,
    pub(super) delete: usize,
    pub(super) after_delete: usize,
}

impl<'archive> MessageRecord<'archive> {
    pub(super) fn graph_facts(&self) -> crate::room_history::AcceptedFacts {
        crate::room_history::AcceptedFacts {
            hash: self.hash,
            parents: self.parents,
            phase: self.phase,
            kind: self.kind,
            sequence: self.sequence,
            complete: self.complete,
            semantic_applied: self.semantic_applied,
            epoch_indexed: true,
            has_original: self.frame.is_some(),
        }
    }

    pub(super) fn read(
        r: &mut Decoder<'archive>,
        l: Limits,
        room_sequence: u64,
    ) -> Result<Self, Error> {
        Self::read_indexed(r, l, room_sequence).map(|(row, _)| row)
    }

    /// Decode the row and locate its existing canonical big-endian sequence.
    /// The history index can then validate sequence uniqueness without decoding
    /// every variable-width row again or keeping the complete row in memory.
    pub(super) fn read_indexed(
        r: &mut Decoder<'archive>,
        l: Limits,
        room_sequence: u64,
    ) -> Result<(Self, usize), Error> {
        Self::read_with_offsets(r, l, room_sequence).map(|(row, offsets)| (row, offsets.sequence))
    }

    pub(super) fn read_with_offsets(
        r: &mut Decoder<'archive>,
        l: Limits,
        room_sequence: u64,
    ) -> Result<(Self, MessageOffsets), Error> {
        let at = r.slot(l.messages_per_room)?;
        let hash = r.array()?;
        let provenance = r.source()?;
        let phase_offset = r.position();
        let phase = read_phase(r)?;
        let frame = r.opt_range(l.frame_bytes)?;
        let after_frame = r.position();
        let owner = if r.bool()? {
            Some(Owner {
                contact: r.slot(l.contacts)?,
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
        let sequence_offset = r.position();
        let sequence = r.u64()?;
        let requested = r.bool()?;
        let delete = r.position();
        let delete_at = r.opt_u64()?;
        let deleted_by = r.opt_array()?;
        let after_delete = r.position();
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
            || sequence > room_sequence
            || !kind.is_known()
            || !semantic_kind.is_known()
            || hash == [0; 64]
            || parents.contains(&hash)
            || (phase == MessagePhase::Deleted) != frame.is_none()
        {
            return Err(Fault::Malformed.into());
        }
        Ok((
            Self {
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
            },
            MessageOffsets {
                phase: phase_offset,
                after_frame,
                sequence: sequence_offset,
                delete,
                after_delete,
            },
        ))
    }
}
