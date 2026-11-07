use super::*;
impl<'id> Core<'id> {
    pub(super) fn write_archive(&self, w: &mut Encoder) -> Result<(), Error> {
        w.size(self.contacts.len())?;
        for (slot, c) in self.contacts.iter() {
            w.slot(slot)?;
            w.raw(&c.key)?;
            w.owned(c.name.as_ref())?;
            w.opt_array(c.anonymous_context.as_ref())?;
            w.bool(c.canonical)?;
        }
        w.size(self.rooms.len())?;
        for (slot, room) in self.rooms.iter() {
            if !room.hpke_keys.is_empty() {
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
                w.slot(s.contact.slot)?;
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
            let count = room.nodes.iter().filter(|(_, n)| n.auth.is_some()).count();
            w.size(count)?;
            for (slot, n) in room.nodes.iter() {
                let Some(auth) = n.auth else { continue };
                if !n.epoch_indexed {
                    return Err(Fault::WouldBlock.into());
                }
                if n.plaintext.is_some() || n.recipient.is_some() {
                    return Err(Error::Permission);
                }
                let transient = crate::graph::discourse_kind(n.kind);
                w.slot(slot)?;
                w.raw(&n.hash)?;
                w.source(n.provenance)?;
                w.u8(phase(if transient {
                    MessagePhase::Deleted
                } else {
                    n.phase
                }))?;
                w.owned(if transient { None } else { n.frame.as_ref() })?;
                w.bool(auth.owner.is_some())?;
                if let Some(o) = auth.owner {
                    w.slot(o.contact.slot)?;
                    w.u64(o.lineage)?;
                    w.u64(o.generation)?
                }
                w.opt_slot(auth.session)?;
                w.raw(&auth.public)?;
                w.opt_array(auth.peer.as_ref())?;
                w.u8(pad(n.padding))?;
                w.layout(n.layout)?;
                w.bool(!transient && n.cipher_layout.is_some())?;
                if let Some(layout) = n.cipher_layout.filter(|_| !transient) {
                    w.profile(layout.body)?;
                    w.profile(layout.padding)?;
                }
                w.bool(!transient && n.plain_layout.is_some())?;
                if let Some(layout) = n.plain_layout.filter(|_| !transient) {
                    w.profile(layout.body)?;
                    w.profile(layout.padding)?;
                }
                w.bool(!transient && n.transcript_layout.is_some())?;
                if let Some(layout) = n.transcript_layout.filter(|_| !transient) {
                    w.profile(layout.body)?;
                    w.profile(layout.padding)?;
                }
                w.u8(match if transient { None } else { n.identifier_order } {
                    None => 0,
                    Some(wire::profile::Endian::Little) => 1,
                    Some(wire::profile::Endian::Big) => 2,
                })?;
                w.bool(transient || n.semantic_applied)?;
                w.bool(n.complete)?;
                for p in &n.parents {
                    w.raw(p)?
                }
                for p in if transient {
                    &[[0; 64]; 3]
                } else {
                    &n.references
                } {
                    w.raw(p)?
                }
                w.bool(transient || n.frontier_applied)?;
                w.raw(if transient { &[0; 64] } else { &n.epoch })?;
                w.u64(u64::from(n.kind.value()))?;
                w.u64(u64::from(n.semantic_kind.value()))?;
                w.u64(n.timestamp)?;
                w.u64(n.sequence)?;
                w.bool(!transient && n.requested)?;
                w.opt_u64(if transient { None } else { n.delete_at })?;
                w.opt_array(if transient {
                    None
                } else {
                    n.deleted_by.as_ref()
                })?;
                w.opt_array(if transient {
                    None
                } else {
                    n.discourse.as_ref()
                })?;
                w.bool(!transient && n.local_sent)?;
                w.opt_array(if transient {
                    None
                } else {
                    n.transcript.as_ref()
                })?;
                w.opt_array(if transient {
                    None
                } else {
                    n.private_recipient.as_ref()
                })?;
                w.raw(if transient { &[0; 64] } else { &n.meta.epoch })?;
                w.u64(if transient {
                    0
                } else {
                    u64::from(n.meta.flags)
                })?;
                w.bool(!transient && n.meta.requested)?;
                w.opt_array(if transient {
                    None
                } else {
                    n.meta.sender_hash.as_ref()
                })?;
                w.opt_array(if transient {
                    None
                } else {
                    n.meta.context.as_ref()
                })?;
            }
            w.size(room.frontier.len())?;
            for h in &room.frontier {
                w.raw(h)?
            }
            let durable_alias = |key: &Hash| {
                !room
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
                if e.ephemeral.is_some() {
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
                        w.slot(c.slot)?
                    }
                    crate::epoch::EpochMutation::Leave(c) => {
                        w.u8(1)?;
                        w.slot(c.slot)?
                    }
                    crate::epoch::EpochMutation::Merge => w.u8(2)?,
                }
                w.size(e.members.len())?;
                for c in &e.members {
                    w.slot(c.slot)?
                }
                w.bool(e.complete)?;
                w.u64(e.revision)?;
                w.size(e.nonces.len())?;
                for n in &e.nonces {
                    w.raw(&n.value)?;
                    w.raw(&n.message)?
                }
                w.size(e.groups.len())?;
                for (slot, g) in e.groups.iter() {
                    if g.key.is_some() {
                        return Err(Error::Permission);
                    }
                    w.slot(slot)?;
                    w.raw(&g.identifier)?;
                    w.u8(match g.identifier_order {
                        wire::profile::Endian::Little => 0,
                        wire::profile::Endian::Big => 1,
                    })?;
                    w.size(g.target)?;
                    w.bool(g.valid)?;
                    w.bool(g.phase == KeyPhase::Revoked)?;
                    w.u64(g.expires)?;
                    w.opt_array(g.appeal.as_ref())?;
                    w.u64(g.appeal_until)?;
                    w.opt_array(g.proposal.as_ref())?;
                    w.u64(g.generation)?;
                    w.bool(g.derived_from.is_some())?;
                    if let Some((epoch, id)) = g.derived_from {
                        w.raw(&epoch)?;
                        w.raw(&id)?
                    }
                    w.size(g.confirmations.len())?;
                    for c in &g.confirmations {
                        w.slot(c.contact.slot)?;
                        w.raw(&c.message)?;
                        w.bool(c.verified_mac)?
                    }
                }
            }
            // Discourse subscriptions are live/temporary intervals. Recovering
            // old intervals would silently restore audience/renewal authority.
            w.size(0)?;
            w.size(room.peers.len())?;
            for peer in &room.peers {
                w.raw(&peer.peer)?;
                w.bool(peer.announced || peer.historical_candidate)?;
                w.u64(u64::from(peer.connection_amount))?;
                w.u64(u64::from(peer.connection_flags))?;
            }
        }
        Ok(())
    }
}
