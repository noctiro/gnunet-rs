use super::*;

/// A conservative byte ceiling for the service archive encoder at these limits.
/// This includes full original frames, optional metadata and every epoch alias.
/// It does not include a storage backend's record envelope or commit witnesses.
///
/// # Errors
/// Returns an overflow error if the ceiling cannot be represented.
pub fn maximum_service_bytes(limits: Limits) -> Result<usize, Error> {
    const TAG: usize = 1;
    const WORD: usize = 8;
    const SLOT: usize = 2 * WORD;
    const HASH: usize = core::mem::size_of::<Hash>();
    const SHORT: usize = core::mem::size_of::<ShortHash>();
    const PUBLIC: usize = core::mem::size_of::<PublicKey>();
    const PROFILE: usize = TAG + WORD;
    const OPT_WORD: usize = TAG + WORD;
    const OPT_HASH: usize = TAG + HASH;
    const CONTACT: usize = SLOT + PUBLIC + OPT_WORD + OPT_HASH + TAG;
    const ROOM: usize = SLOT + 3 * HASH + PROFILE + 9 * WORD;
    const SESSION: usize = 3 * SLOT + SHORT + 2 * PUBLIC + 4 * WORD + 3 * TAG + 2 * HASH;
    const SOURCE: usize = 2 * SLOT + TAG + SHORT;
    const AUTH: usize = TAG + SLOT + 2 * WORD + TAG + SLOT + PUBLIC + TAG + SHORT;
    const LAYOUT: usize = 2 * TAG + 2 * PROFILE + PUBLIC;
    const EPOCH: usize = 2 * SLOT + 3 * HASH + 2 * TAG + 4 * WORD;
    const PEER: usize = SHORT + TAG + 2 * WORD;

    // Node widths follow the writer. The frame body is counted separately.
    const ORIGINAL: usize = SLOT + HASH + SOURCE + TAG + OPT_WORD;
    const FORMATS: usize = TAG + LAYOUT + 3 * (TAG + 2 * PROFILE);
    const GRAPH: usize = 4 * TAG + 6 * HASH + 4 * WORD;
    const STATE: usize = 4 * TAG + OPT_WORD + 2 * OPT_HASH + SHORT + PUBLIC;
    const RECEIVE_META: usize = HASH + WORD + TAG + 2 * OPT_HASH;
    const NODE: usize = ORIGINAL + AUTH + FORMATS + GRAPH + STATE + RECEIVE_META;

    fn total(prefix: usize, rows: &[(usize, usize)]) -> Result<usize, Error> {
        rows.iter().try_fold(prefix, |sum, &(count, width)| {
            count
                .checked_mul(width)
                .and_then(|size| sum.checked_add(size))
                .ok_or_else(|| Fault::Overflow.into())
        })
    }

    let epoch = total(EPOCH, &[(limits.sessions_per_room, SLOT)])?;
    let node_and_frontier = total(NODE + HASH, &[(1, limits.frame_bytes)])?;
    let room = total(
        ROOM,
        &[
            (limits.sessions_per_room, SESSION),
            (limits.messages_per_room, node_and_frontier),
            (
                AliasBuckets::bucket_count(limits.messages_per_room)?,
                2 * HASH,
            ),
            (limits.epochs_per_room, epoch),
            (limits.sources_per_room, PEER),
        ],
    )?;
    let contact = total(CONTACT, &[(1, limits.name_bytes)])?;
    total(
        MAGIC.len() + PROFILE + TAG + SHORT + 3 * WORD,
        &[
            (limits.own_signers, SHORT),
            (limits.contacts, contact),
            (limits.rooms, room),
        ],
    )
}

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    pub(super) fn write_archive(
        &self,
        w: &mut Encoder<impl ArchiveSink>,
        selection: Option<Selection<'_>>,
    ) -> Result<(), Error> {
        w.size(self.contacts.len())?;
        for (slot, c) in self.contacts.iter() {
            w.slot(slot)?;
            w.raw(&c.key)?;
            w.opt_bytes(self.contact_name_at(slot)?)?;
            w.opt_array(c.anonymous_context.as_ref())?;
            w.bool(c.canonical)?;
        }
        w.size(self.rooms.len())?;
        for (slot, room) in self.rooms.iter() {
            let detached =
                |hash: &Hash| selection.is_some_and(|selection| selection.contains(slot, hash));
            if room.queues.has_recipient_keys() {
                return Err(Error::Permission);
            }
            w.slot(slot)?;
            w.raw(&room.key)?;
            w.profile(room.profile)?;
            w.raw(&room.current_epoch)?;
            w.raw(&room.last_message)?;
            w.u64(room.sequence)?;
            w.u64(room.lineage)?;
            w.size(room.sessions.len())?;
            for (slot, s) in room.sessions.iter() {
                w.slot(slot)?;
                w.slot(s.contact)?;
                w.raw(&s.id)?;
                w.raw(&s.public)?;
                w.raw(&s.hpke)?;
                w.u64(s.lineage)?;
                w.u64(s.generation)?;
                w.u64(s.known_from)?;
                w.u8(session_phase(if s.archived {
                    s.historical_phase
                } else {
                    s.phase
                }))?;
                w.raw(&s.first_bound)?;
                w.raw(&s.last_bound)?;
                w.opt_slot(s.successor)?;
                w.opt_u64(s.completed_at)?;
            }
            let messages = || {
                room.nodes
                    .iter()
                    .filter(|(_, node)| !detached(&node.hash))
                    .filter_map(|(slot, node)| {
                        AuthenticatedMessageRow::from_node(&room.key, slot, node)
                    })
            };
            w.size(messages().count())?;
            for message in messages() {
                message.write(w, &self.frames)?;
            }
            w.size(room.queues.frontier.len())?;
            for h in &room.queues.frontier {
                w.raw(h)?
            }
            let durable_alias = |key: &Hash| {
                !detached(key)
                    && !room
                        .find_node(key)
                        .and_then(|s| room.nodes.get(s).ok())
                        .is_some_and(|n| crate::graph::discourse_kind(n.kind))
            };
            w.size(
                room.epoch_aliases
                    .iter()
                    .flatten()
                    .filter(|a| durable_alias(&a.key))
                    .count(),
            )?;
            for alias in room
                .epoch_aliases
                .iter()
                .flatten()
                .filter(|a| durable_alias(&a.key))
            {
                w.raw(&alias.key)?;
                w.raw(&alias.epoch)?
            }
            w.size(room.epochs.len())?;
            for (slot, e) in room.epochs.iter() {
                if e.has_client_secrets() {
                    return Err(Error::Permission);
                }
                w.slot(slot)?;
                w.raw(&e.hash)?;
                for p in &e.parents {
                    w.raw(p)?
                }
                match e.mutation {
                    crate::epoch::EpochMutation::Join(c) => {
                        w.u8(0)?;
                        w.slot(c)?
                    }
                    crate::epoch::EpochMutation::Leave(c) => {
                        w.u8(1)?;
                        w.slot(c)?
                    }
                    crate::epoch::EpochMutation::Merge => w.u8(2)?,
                }
                let members = room.epoch_members(e);
                w.size(members.len())?;
                for c in members {
                    w.slot(c)?
                }
                w.bool(e.complete)?;
                w.u64(e.revision)?;
                // Reserved counts for client replay and group key state.
                w.u64(0)?;
                w.u64(0)?;
            }
            // Discourse subscriptions are live/temporary intervals. Recovering
            // old intervals would silently restore audience/renewal authority.
            w.size(0)?;
            w.size(room.queues.peers.len())?;
            for peer in &room.queues.peers {
                w.raw(&peer.peer)?;
                w.bool(true)?;
                // Current CONNECTION metadata is not part of a recovered route.
                w.u64(0)?;
                w.u64(0)?;
            }
        }
        Ok(())
    }
}
