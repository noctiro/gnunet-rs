//! Structural/resource validation plus actual retained raw signature rechecks.
//! Deleted payload metadata relies on the explicit trusted owned-store contract;
//! checksum and an ArchivedFact are never described as new network signatures.
mod dag;
mod pages;

use super::{MessageRecord, has_client_message_state};
use crate::{
    Core, Error, Hash, MessagePhase, OriginalLayout, SessionPhase, Slot, SourceObservation,
    SourceRole, crypto,
    epoch::EpochMutation,
    state::{Authentication, PeerRow, RoomRow},
    wire,
};
use gnunet_types::Error as Fault;

pub use dag::ArchiveGraphCell;
pub(super) use dag::DagWorkspace;
pub use pages::CommittedGraphPages;
use pages::RoomGraph;

struct SignedFacts<'row> {
    hash: &'row Hash,
    kind: wire::envelope::Kind,
    timestamp: u64,
    parents: &'row [Hash; 2],
    references: &'row [Hash; 3],
}

fn check_original(
    message: wire::message::Message<'_>,
    facts: SignedFacts<'_>,
    auth: Authentication,
) -> Result<(), Error> {
    let header = message.header();
    if &crypto::signature::message_hash(message) != facts.hash
        || header.kind != facts.kind
        || header.timestamp.as_micros() != facts.timestamp
        || header.previous != &facts.parents[0]
    {
        return Err(Fault::Authentication.into());
    }
    let second = if let wire::body::Body::Merge { previous, .. } = message.body() {
        *previous
    } else {
        [0; 64]
    };
    if facts.parents[1] != second || facts.references != &crate::ingest::references(message.body())
    {
        return Err(Fault::Malformed.into());
    }
    if let Some(peer) = auth.peer {
        crypto::signature::verify_peer(message, &peer)?;
    } else {
        crypto::signature::verify_member(message, wire::PublicKey::new(&auth.public)?)?;
    }
    Ok(())
}

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    pub(super) fn validate_archive_using(
        &self,
        historical_peer: Option<[u8; 32]>,
        mut graph: DagWorkspace<'_>,
        archive: &[u8],
        pages: CommittedGraphPages<'_, '_>,
    ) -> Result<(), Error> {
        let own_signers = self.own_signers.peers();
        if own_signers.len() > self.limits.own_signers
            || historical_peer.is_some_and(|peer| !self.is_own_signer(&peer))
            || (historical_peer.is_none() && !own_signers.is_empty())
        {
            return Err(Fault::Authentication.into());
        }
        pages.check_directory(historical_peer, &self.rooms)?;
        for (room_slot, room) in self.rooms.iter() {
            if room.sources.len() != 0
                || room.operations.len() != 0
                || room.queues.has_recipient_keys()
                || room.joined
                || room.local_public.is_some()
            {
                return Err(Fault::Malformed.into());
            }
            let history = RoomGraph::new(room, pages)?;
            graph.check_unique_sequences(history.sequences())?;
            for (slot, s) in room.sessions.iter() {
                self.contacts.get(s.contact)?;
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
                        || !first.semantic_applied
                        || !room
                            .find_epoch(&first.hash)
                            .and_then(|slot| room.epochs.get(slot).ok())
                            .is_some_and(|epoch| epoch.complete)
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
            for (_, n) in room.nodes.iter() {
                if has_client_message_state(n) {
                    return Err(Fault::Malformed.into());
                }
                let Some(auth) = n.auth else {
                    return Err(Fault::Authentication.into());
                };
                if !n.origin.is_archived() || !n.epoch_indexed || n.parents.contains(&n.hash) {
                    return Err(Fault::Malformed.into());
                }
                self.check_archive_attribution(
                    room_slot,
                    room,
                    auth,
                    n.layout,
                    n.origin.provenance(),
                    n.meta.sender_hash.as_ref(),
                )?;
                if let Some(layout) = n.cipher_layout {
                    layout.validate()?;
                }
                if let Some(layout) = n.plain_layout {
                    layout.validate()?;
                }
                if let Some(layout) = n.transcript_layout {
                    layout.validate()?;
                }
                let original = if let Some(range) = n.archived_original() {
                    if !n.can_archive_original() {
                        return Err(Fault::Malformed.into());
                    }
                    Some(range.in_image(archive)?)
                } else {
                    n.original(&self.frames)?
                };
                if let Some(raw) = original {
                    if n.phase == MessagePhase::Deleted {
                        return Err(Fault::Malformed.into());
                    }
                    check_original(
                        n.decode_original(raw)?,
                        SignedFacts {
                            hash: &n.hash,
                            kind: n.kind,
                            timestamp: n.timestamp,
                            parents: &n.parents,
                            references: &n.references,
                        },
                        auth,
                    )?;
                } else if n.phase != MessagePhase::Deleted {
                    return Err(Fault::Malformed.into());
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
            }
            for record in history.detached_rows() {
                let (_, row) = record?;
                self.check_detached_record(room_slot, room, &row)?;
            }
            // Linear bounded adjacency/Kahn walk. Missing ancestors remain
            // lookup targets; known-node and epoch cycles are refused independently.
            graph.check(history.width(), history.edges())?;
            graph.check(
                room.epochs.limit(),
                room.epochs.iter().map(|(slot, epoch)| {
                    Ok((
                        slot.index,
                        epoch
                            .parents
                            .map(|hash| room.find_epoch(&hash).map(|at| at.index)),
                    ))
                }),
            )?;
            for hash in &room.queues.frontier {
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
                    let body = node.body(&self.frames)?;
                    match (e.mutation, body) {
                        (EpochMutation::Join(c), wire::body::Body::Join { epoch, .. }) => {
                            if e.parents != [*epoch, [0; 64]]
                                || node
                                    .auth
                                    .and_then(|a| a.owner)
                                    .is_none_or(|o| o.contact != c)
                            {
                                return Err(Fault::Authentication.into());
                            }
                        }
                        (EpochMutation::Leave(c), wire::body::Body::Leave { epoch }) => {
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
                            EpochMutation::Merge,
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
                        EpochMutation::Join(c) if node.kind == wire::envelope::Kind::JOIN => {
                            if node
                                .auth
                                .and_then(|a| a.owner)
                                .is_none_or(|o| o.contact != c)
                            {
                                return Err(Fault::Authentication.into());
                            }
                        }
                        EpochMutation::Leave(c) if node.kind == wire::envelope::Kind::LEAVE => {
                            if node
                                .auth
                                .and_then(|a| a.owner)
                                .is_none_or(|o| o.contact != c)
                            {
                                return Err(Fault::Authentication.into());
                            }
                        }
                        EpochMutation::Merge if node.kind == wire::envelope::Kind::MERGE => {}
                        _ => return Err(Fault::Malformed.into()),
                    }
                }
                if e.complete {
                    room.validate_epoch_members(e, self.limits.sessions_per_room)?;
                }
            }
            if room.subscriptions.len() != 0 {
                return Err(Fault::Malformed.into());
            }
            if room.queues.peers.iter().any(PeerRow::is_announced) {
                return Err(Fault::Malformed.into());
            }
        }
        Ok(())
    }

    fn check_archive_attribution(
        &self,
        room_slot: Slot,
        room: &RoomRow<'_>,
        auth: Authentication,
        layout: OriginalLayout,
        provenance: SourceObservation,
        sender: Option<&Hash>,
    ) -> Result<(), Error> {
        if let Some(o) = auth.owner {
            self.contacts.get(o.contact)?;
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
        layout.check_signer(auth.public, auth.peer)?;
        if provenance.room != room_slot {
            return Err(Fault::Malformed.into());
        }
        if let SourceRole::ServiceSigner(peer) = provenance.role
            && (!self.is_own_signer(&peer) || auth.peer != Some(peer))
        {
            return Err(Fault::Authentication.into());
        }
        if let Some(sender) = sender {
            let expected = if let Some(peer) = auth.peer {
                gnunet_crypto::hash512(&peer)
            } else {
                gnunet_crypto::hash512(&auth.public)
            };
            if sender != &expected {
                return Err(Fault::Authentication.into());
            }
        }
        Ok(())
    }

    fn check_detached_record(
        &self,
        room_slot: Slot,
        room: &RoomRow<'_>,
        row: &MessageRecord<'_>,
    ) -> Result<(), Error> {
        if room
            .alias(&row.hash)
            .is_some_and(|epoch| epoch != row.epoch)
        {
            return Err(Fault::Malformed.into());
        }
        let auth = Authentication {
            owner: row.owner,
            session: row.session,
            public: row.public,
            peer: row.peer,
        };
        self.check_archive_attribution(
            room_slot,
            room,
            auth,
            row.layout,
            row.provenance,
            row.meta.sender_hash.as_ref(),
        )?;
        if let Some((_, raw)) = row.frame {
            let message = wire::message::Message::decode_with_profiles(
                raw,
                row.layout.body_profile(row.kind)?,
                row.layout.padding,
                row.padding,
            )?;
            if let wire::body::Body::Peer { peer } = message.body()
                && auth.peer.as_ref() != Some(peer)
            {
                return Err(Fault::Authentication.into());
            }
            check_original(
                message,
                SignedFacts {
                    hash: &row.hash,
                    kind: row.kind,
                    timestamp: row.timestamp,
                    parents: &row.parents,
                    references: &row.references,
                },
                auth,
            )?;
        }
        Ok(())
    }
}
