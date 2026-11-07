//! Structural/resource validation plus actual retained raw signature rechecks.
//! Deleted payload metadata relies on the explicit trusted owned-store contract;
//! checksum and an ArchivedFact are never described as new network signatures.
use super::*;
impl<'id> Core<'id> {
    pub(super) fn validate_archive(&self, historical_peer: Option<[u8; 32]>) -> Result<(), Error> {
        if self.own_signers.len() > self.limits.own_signers
            || self.own_signers.windows(2).any(|p| p[0] >= p[1])
            || historical_peer.is_some_and(|peer| !self.is_own_signer(&peer))
            || (historical_peer.is_none() && !self.own_signers.is_empty())
        {
            return Err(Fault::Authentication.into());
        }
        for (room_slot, room) in self.rooms.iter() {
            if room.sources.len() != 0
                || room.operations.len() != 0
                || !room.hpke_keys.is_empty()
                || room.joined
                || room.local_public.is_some()
            {
                return Err(Fault::Malformed.into());
            }
            for (slot, s) in room.sessions.iter() {
                self.contacts.get(s.contact.slot)?;
                if !s.archived || s.phase != SessionPhase::Completed {
                    return Err(Fault::Malformed.into());
                }
                if s.first_bound != [0; 64] {
                    let first = room
                        .nodes
                        .get(room.find_node(&s.first_bound).ok_or(Fault::Malformed)?)?;
                    if first.auth.and_then(|a| a.owner).is_none_or(|o| {
                        o.contact != s.contact
                            || o.lineage != s.lineage
                            || o.generation > s.generation
                    }) || first.kind != wire::envelope::Kind::JOIN
                    {
                        return Err(Fault::Authentication.into());
                    }
                }
                if s.last_bound != [0; 64] {
                    let last = room
                        .nodes
                        .get(room.find_node(&s.last_bound).ok_or(Fault::Malformed)?)?;
                    if last.auth.and_then(|a| a.owner).is_none_or(|o| {
                        o.contact != s.contact
                            || o.lineage != s.lineage
                            || o.generation > s.generation
                    }) {
                        return Err(Fault::Authentication.into());
                    }
                }
                if s.completed_at
                    .is_some_and(|at| at < s.known_from || at > room.sequence)
                {
                    return Err(Fault::Malformed.into());
                }
                let mut next = s.successor;
                let mut ended = false;
                for _ in 0..=self.limits.sessions_per_room {
                    let Some(at) = next else {
                        ended = true;
                        break;
                    };
                    if at == slot {
                        return Err(Fault::Malformed.into());
                    }
                    let row = room.sessions.get(at)?;
                    if row.contact != s.contact
                        || row.lineage != s.lineage
                        || row.generation <= s.generation
                    {
                        return Err(Fault::Malformed.into());
                    }
                    next = row.successor;
                }
                if !ended {
                    return Err(Fault::Malformed.into());
                }
            }
            if room.nodes.iter().any(|(_, node)| node.recipient.is_some()) {
                return Err(Fault::Malformed.into());
            }
            for (_, n) in room.nodes.iter() {
                let Some(auth) = n.auth else {
                    return Err(Fault::Authentication.into());
                };
                if !matches!(n.origin, MessageOrigin::Archived(_))
                    || !n.epoch_indexed
                    || n.plaintext.is_some()
                    || n.parents.contains(&n.hash)
                {
                    return Err(Fault::Malformed.into());
                }
                if let Some(o) = auth.owner {
                    self.contacts.get(o.contact.slot)?;
                    if o.lineage == 0 || o.generation == 0 {
                        return Err(Fault::Malformed.into());
                    }
                }
                if let Some(at) = auth.session {
                    let s = room.sessions.get(at)?;
                    let owner = auth.owner.ok_or(Fault::Malformed)?;
                    if owner.contact != s.contact
                        || owner.lineage != s.lineage
                        || owner.generation != s.generation
                        || auth.public != s.public
                    {
                        return Err(Fault::Authentication.into());
                    }
                }
                if let Some(peer) = auth.peer
                    && (auth.owner.is_some()
                        || auth.session.is_some()
                        || auth.public[..4] != wire::KeyType::Eddsa.value().to_be_bytes()
                        || auth.public[4..] != peer)
                {
                    return Err(Fault::Authentication.into());
                }
                n.layout.check_signer(auth.public, auth.peer)?;
                if let Some(layout) = n.cipher_layout {
                    layout.validate()?;
                }
                if let Some(layout) = n.plain_layout {
                    layout.validate()?;
                }
                if let Some(layout) = n.transcript_layout {
                    layout.validate()?;
                }
                if n.provenance.room != room_slot {
                    return Err(Fault::Malformed.into());
                }
                if let SourceRole::ServiceSigner(peer) = n.provenance.role
                    && (!self.is_own_signer(&peer) || auth.peer != Some(peer))
                {
                    return Err(Fault::Authentication.into());
                }
                if let Some(raw) = &n.frame {
                    if n.phase == MessagePhase::Deleted {
                        return Err(Fault::Malformed.into());
                    }
                    let message = wire::message::Message::decode_with_profiles(
                        raw.expose(),
                        n.layout.body_profile(n.kind)?,
                        n.layout.padding,
                        n.padding,
                    )?;
                    if crypto::signature::message_hash(message) != n.hash
                        || message.header().kind != n.kind
                        || message.header().timestamp.as_micros() != n.timestamp
                        || *message.header().previous != n.parents[0]
                    {
                        return Err(Fault::Authentication.into());
                    }
                    let second = if let wire::body::Body::Merge { previous, .. } = message.body() {
                        *previous
                    } else {
                        [0; 64]
                    };
                    if n.parents[1] != second
                        || n.references != crate::ingest::references(message.body())
                    {
                        return Err(Fault::Malformed.into());
                    }
                    if let Some(peer) = auth.peer {
                        crypto::signature::verify_peer(message, &peer)?;
                    } else {
                        crypto::signature::verify_member(
                            message,
                            wire::PublicKey::new(&auth.public)?,
                        )?;
                    }
                } else if n.phase != MessagePhase::Deleted {
                    return Err(Fault::Malformed.into());
                }
                if let Some(sender) = n.meta.sender_hash {
                    let expected = if let Some(peer) = auth.peer {
                        gnunet_crypto::hash512(&peer)
                    } else {
                        gnunet_crypto::hash512(&auth.public)
                    };
                    if sender != expected {
                        return Err(Fault::Authentication.into());
                    }
                }
                if crate::graph::discourse_kind(n.kind) {
                    if n.frame.is_some()
                        || n.phase != MessagePhase::Deleted
                        || !n.semantic_applied
                        || !n.frontier_applied
                        || n.discourse.is_some()
                        || n.epoch != [0; 64]
                        || n.meta.epoch != [0; 64]
                        || n.meta.flags != 0
                        || n.meta.requested
                        || n.meta.sender_hash.is_some()
                        || n.meta.context.is_some()
                        || n.requested
                        || n.local_sent
                        || n.delete_at.is_some()
                        || n.deleted_by.is_some()
                        || n.transcript.is_some()
                        || n.private_recipient.is_some()
                        || n.references != [[0; 64]; 3]
                        || n.parents[1] != [0; 64]
                        || n.semantic_kind != n.kind
                        || n.cipher_layout.is_some()
                        || n.plain_layout.is_some()
                        || n.transcript_layout.is_some()
                        || n.identifier_order.is_some()
                        || room.alias(&n.hash).is_some()
                    {
                        return Err(Fault::Malformed.into());
                    }
                } else if room.alias(&n.hash) != Some(n.epoch) {
                    return Err(Fault::Malformed.into());
                }
                if n.complete
                    && n.parents
                        .iter()
                        .any(|h| *h != [0; 64] && room.find_node(h).is_none())
                {
                    return Err(Fault::Malformed.into());
                }
            }
            // Linear bounded adjacency/Kahn walk. Missing ancestors remain
            // lookup targets; known-node and epoch cycles are refused independently.
            check_dag(
                room.nodes.limit(),
                room.nodes.iter().map(|(slot, node)| {
                    (
                        slot.index,
                        node.parents
                            .map(|hash| room.find_node(&hash).map(|at| at.index)),
                    )
                }),
            )?;
            check_dag(
                room.epochs.limit(),
                room.epochs.iter().map(|(slot, epoch)| {
                    (
                        slot.index,
                        epoch
                            .parents
                            .map(|hash| room.find_epoch(&hash).map(|at| at.index)),
                    )
                }),
            )?;
            for hash in &room.frontier {
                if *hash == [0; 64]
                    || room.find_node(hash).is_none()
                    || room
                        .find_node(hash)
                        .and_then(|s| room.nodes.get(s).ok())
                        .is_some_and(|n| crate::graph::discourse_kind(n.kind))
                {
                    return Err(Fault::Malformed.into());
                }
            }
            for (_, e) in room.epochs.iter() {
                let node = room
                    .nodes
                    .get(room.find_node(&e.hash).ok_or(Fault::Malformed)?)?;
                if !crate::graph::epoch_kind(node.kind) || e.parents.contains(&e.hash) {
                    return Err(Fault::Malformed.into());
                }
                if node.frame.is_some() {
                    let body = node.body(self.profile)?;
                    match (e.mutation, body) {
                        (
                            crate::epoch::EpochMutation::Join(c),
                            wire::body::Body::Join { epoch, .. },
                        ) => {
                            if e.parents != [*epoch, [0; 64]]
                                || node
                                    .auth
                                    .and_then(|a| a.owner)
                                    .is_none_or(|o| o.contact != c)
                            {
                                return Err(Fault::Authentication.into());
                            }
                        }
                        (
                            crate::epoch::EpochMutation::Leave(c),
                            wire::body::Body::Leave { epoch },
                        ) => {
                            if e.parents != [*epoch, [0; 64]]
                                || node
                                    .auth
                                    .and_then(|a| a.owner)
                                    .is_none_or(|o| o.contact != c)
                            {
                                return Err(Fault::Authentication.into());
                            }
                        }
                        (
                            crate::epoch::EpochMutation::Merge,
                            wire::body::Body::Merge {
                                first_epoch,
                                second_epoch,
                                ..
                            },
                        ) => {
                            if e.parents != [*first_epoch, *second_epoch] {
                                return Err(Fault::Malformed.into());
                            }
                        }
                        _ => return Err(Fault::Malformed.into()),
                    }
                } else {
                    match e.mutation {
                        crate::epoch::EpochMutation::Join(c)
                            if node.kind == wire::envelope::Kind::JOIN =>
                        {
                            if node
                                .auth
                                .and_then(|a| a.owner)
                                .is_none_or(|o| o.contact != c)
                            {
                                return Err(Fault::Authentication.into());
                            }
                        }
                        crate::epoch::EpochMutation::Leave(c)
                            if node.kind == wire::envelope::Kind::LEAVE =>
                        {
                            if node
                                .auth
                                .and_then(|a| a.owner)
                                .is_none_or(|o| o.contact != c)
                            {
                                return Err(Fault::Authentication.into());
                            }
                        }
                        crate::epoch::EpochMutation::Merge
                            if node.kind == wire::envelope::Kind::MERGE => {}
                        _ => return Err(Fault::Malformed.into()),
                    }
                }
                if e.complete {
                    let mut expected = Vec::new();
                    expected
                        .try_reserve_exact(self.limits.sessions_per_room)
                        .map_err(|_| Fault::Capacity)?;
                    for parent in e.parents {
                        if parent == [0; 64] {
                            continue;
                        }
                        let previous = room
                            .epochs
                            .get(room.find_epoch(&parent).ok_or(Fault::Malformed)?)?;
                        if !previous.complete {
                            return Err(Fault::Malformed.into());
                        }
                        for contact in &previous.members {
                            if !expected.contains(contact) {
                                if expected.len() == self.limits.sessions_per_room {
                                    return Err(Fault::Capacity.into());
                                }
                                expected.push(*contact)
                            }
                        }
                    }
                    match e.mutation {
                        crate::epoch::EpochMutation::Join(c) => {
                            if !expected.contains(&c) {
                                if expected.len() == self.limits.sessions_per_room {
                                    return Err(Fault::Capacity.into());
                                }
                                expected.push(c)
                            }
                        }
                        crate::epoch::EpochMutation::Leave(c) => expected.retain(|m| *m != c),
                        crate::epoch::EpochMutation::Merge => {}
                    }
                    if expected.len() != e.members.len()
                        || expected.iter().any(|m| !e.members.contains(m))
                    {
                        return Err(Fault::Authentication.into());
                    }
                }
                for nonce in &e.nonces {
                    if room.find_node(&nonce.message).is_none() {
                        return Err(Fault::Malformed.into());
                    }
                }
                for (_, g) in e.groups.iter() {
                    if g.key.is_some()
                        || !matches!(g.phase, KeyPhase::Missing | KeyPhase::Revoked)
                        || g.phase == KeyPhase::Revoked && g.valid
                        || g.target == 0
                        || g.target > e.members.len()
                    {
                        return Err(Fault::Malformed.into());
                    }
                    let (is_group, level) =
                        crate::epoch::identifier_order(g.identifier_order, &g.identifier);
                    let target = if is_group {
                        1usize.checked_shl(level).ok_or(Fault::Overflow)?
                    } else {
                        e.members.len()
                    };
                    if target != g.target {
                        return Err(Fault::Malformed.into());
                    }
                    for c in &g.confirmations {
                        if !e.members.contains(&c.contact) || room.find_node(&c.message).is_none() {
                            return Err(Fault::Malformed.into());
                        }
                    }
                }
            }
            if room.subscriptions.len() != 0 {
                return Err(Fault::Malformed.into());
            }
            if room.peers.iter().any(|p| p.announced) {
                return Err(Fault::Malformed.into());
            }
        }
        Ok(())
    }
}

// Temporary recovery workspace is <= limit heads/degrees/queue and 2*limit edges.
// It is fallibly allocated and released before the recovered owner is returned.
fn check_dag(
    limit: usize,
    rows: impl Iterator<Item = (usize, [Option<usize>; 2])>,
) -> Result<(), Error> {
    let mut heads: Vec<Option<usize>> = Vec::new();
    let mut degrees: Vec<u8> = Vec::new();
    let mut queue: Vec<usize> = Vec::new();
    let mut edges: Vec<(usize, Option<usize>)> = Vec::new();
    heads
        .try_reserve_exact(limit)
        .map_err(|_| Fault::Capacity)?;
    degrees
        .try_reserve_exact(limit)
        .map_err(|_| Fault::Capacity)?;
    queue
        .try_reserve_exact(limit)
        .map_err(|_| Fault::Capacity)?;
    edges
        .try_reserve_exact(limit.checked_mul(2).ok_or(Fault::Overflow)?)
        .map_err(|_| Fault::Capacity)?;
    heads.resize(limit, None);
    degrees.resize(limit, 0);
    let mut count = 0usize;
    for (child, parents) in rows {
        if child >= limit || count == limit {
            return Err(Fault::Malformed.into());
        }
        count += 1;
        for parent in parents.into_iter().flatten() {
            if parent >= limit {
                return Err(Fault::Malformed.into());
            }
            degrees[child] = degrees[child].checked_add(1).ok_or(Fault::Overflow)?;
            let next = heads[parent];
            heads[parent] = Some(edges.len());
            edges.push((child, next));
        }
        if degrees[child] == 0 {
            queue.push(child);
        }
    }
    let mut visited = 0usize;
    while let Some(parent) = queue.pop() {
        visited += 1;
        let mut cursor = heads[parent];
        while let Some(at) = cursor {
            let (child, next) = edges[at];
            degrees[child] = degrees[child].checked_sub(1).ok_or(Fault::Malformed)?;
            if degrees[child] == 0 {
                queue.push(child);
            }
            cursor = next;
        }
    }
    if visited != count {
        return Err(Fault::Malformed.into());
    }
    Ok(())
}
