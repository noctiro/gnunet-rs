//! Read routing for an authenticated original SERVICE request.

use super::ServiceRequestAuthority;
use crate::{
    CommittedServiceOriginal, Core, Error, Hash, HistoryWorkspace, MessagePhase, MessageRef,
    archive::CommittedRoomHistory,
    graph::{epoch_kind, knows_sequence},
    room_history::{HistoryEntry, HistoryId, HistoryLocation, HistoryRead, LayeredHistory},
    state::{RoomRow, SessionRow},
    wire,
};
use core::num::NonZeroU64;
use gnunet_types::Error as Fault;

/// Authorized peer replay selected from the live room and its committed
/// history. Both original variants carry the same room sequence semantics.
pub enum ServiceHistoryItem<'a, 'id> {
    /// A readable original selected from the live room.
    Resident {
        /// Stable room sequence for suppressing duplicate replies.
        sequence: NonZeroU64,
        /// The current room's authenticated message.
        message: MessageRef<'a, 'id>,
    },
    /// A readable original lent by the exact committed checkpoint.
    Committed {
        /// Stable room sequence for suppressing duplicate replies.
        sequence: NonZeroU64,
        /// The authorized original with its retained decoder layout.
        original: CommittedServiceOriginal<'a>,
    },
    /// A hash for which an authenticated original has not resolved the request.
    Pending(Hash),
}

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    /// Visit authorized originals answering an admitted signed REQUEST.
    ///
    /// The original ingress and signing session must still be valid. The
    /// exact signed body supplies the first lookup. Live observations take
    /// precedence over committed records with the same hash. Only authenticated
    /// deletion records supply predecessor hashes. Returns whether any leaf
    /// resolved locally, even if its original could not be disclosed.
    ///
    /// The supplied view must belong to the confirmed checkpoint for this
    /// Core, not merely one with the same generation number. The caller
    /// keeps the exact storage receipt pinned for the entire read and must
    /// provide marks for both the working room and the committed directory.
    ///
    /// # Errors
    /// Refuses a different room or local peer, an inconsistent history
    /// watermark, insufficient marks, and missing or mismatched stored bytes.
    pub fn visit_service_request_history<'a>(
        &'a self,
        request: ServiceRequestAuthority<'id>,
        archive: Option<CommittedRoomHistory<'a, '_>>,
        workspace: &mut HistoryWorkspace<'_>,
        mut visit: impl FnMut(ServiceHistoryItem<'a, 'id>),
    ) -> Result<bool, Error> {
        let (original, hash) = self.resolve_request(request, archive)?;
        let row = self.rooms.get(request.source().room)?;
        let member = original.attribution().member.ok_or(Fault::Authentication)?;
        let session = row.sessions.get(member.slot)?;
        let resident = row.history_snapshot();
        let history = LayeredHistory::new(resident, archive)?;
        visit_request_leaves(history, session, hash, workspace, |leaf| {
            let item = match leaf {
                RequestLeaf::Pending(hash) => ServiceHistoryItem::Pending(hash),
                RequestLeaf::Readable { id, hash, sequence } => match history.location(id)? {
                    HistoryLocation::Resident(at) => {
                        let message = row.history_message(at, &self.frames, self.instance)?;
                        if message.hash() != &hash {
                            return Err(Error::AttributionConflict);
                        }
                        replay_resident(message, sequence, archive)?
                    }
                    HistoryLocation::Committed(at) => {
                        let original = archive
                            .ok_or(Fault::Conflict)?
                            .original(at)?
                            .ok_or(Fault::Conflict)?;
                        if original.hash() != &hash {
                            return Err(Error::AttributionConflict);
                        }
                        ServiceHistoryItem::Committed { sequence, original }
                    }
                },
            };
            visit(item);
            Ok(())
        })
    }
}

fn replay_resident<'a, 'id>(
    message: MessageRef<'a, 'id>,
    sequence: NonZeroU64,
    archive: Option<CommittedRoomHistory<'a, '_>>,
) -> Result<ServiceHistoryItem<'a, 'id>, Error> {
    let (Some(expected), Some(mut archive)) = (message.archived_original(), archive) else {
        return Ok(ServiceHistoryItem::Resident { sequence, message });
    };
    // The working row supplied the current facts and authorization. Use the
    // already-lent archive only to read that exact original, without another
    // storage checkout or a chance to resurrect an obsolete copy.
    let id = archive
        .locate(message.hash())?
        .ok_or(Fault::StaleGeneration)?;
    let original = archive.original(id)?.ok_or(Fault::StaleGeneration)?;
    if original.hash() != message.hash()
        || original.kind() != message.kind()
        || original.layout() != message.layout()
        || original.padding() != message.padding()
    {
        return Err(Error::AttributionConflict);
    }
    if expected.length() != original.bytes().len()
        || expected.digest() != gnunet_crypto::hash256(original.bytes())
    {
        return Err(Fault::Authentication.into());
    }
    Ok(ServiceHistoryItem::Committed { sequence, original })
}

pub(super) fn check_archive(
    room: &RoomRow<'_>,
    at: crate::Slot,
    local_peer: Option<crate::ShortHash>,
    archive: Option<CommittedRoomHistory<'_, '_>>,
) -> Result<(), Error> {
    if let Some(current) = archive {
        if current.room_key() != room.key || current.historical_peer() != local_peer {
            return Err(Error::Permission);
        }
        if current.room_position() != (at.index, at.generation)
            || current.room_sequence() != room.sequence
        {
            return Err(Fault::StaleGeneration.into());
        }
    }
    Ok(())
}

enum RequestLeaf {
    Readable {
        id: HistoryId,
        hash: Hash,
        sequence: NonZeroU64,
    },
    Pending(Hash),
}

/// Expand an authenticated request over one immutable history revision.
/// Resolving leaves does not require the retained originals or work rows.
fn visit_request_leaves(
    history: impl HistoryRead,
    session: &SessionRow,
    hash: &Hash,
    workspace: &mut HistoryWorkspace<'_>,
    mut visit: impl FnMut(RequestLeaf) -> Result<(), Error>,
) -> Result<bool, Error> {
    visit_history_leaves(history, hash, workspace, |leaf| match leaf {
        HistoryLeaf::Pending(hash) => visit(RequestLeaf::Pending(hash)),
        HistoryLeaf::Original {
            id,
            facts,
            sequence,
        } if facts.kind != wire::envelope::Kind::INFO
            && (epoch_kind(facts.kind) || knows_sequence(session, sequence.get())) =>
        {
            visit(RequestLeaf::Readable {
                id,
                hash: facts.hash,
                sequence,
            })
        }
        HistoryLeaf::Original { .. } => Ok(()),
    })
}

pub(super) enum HistoryLeaf {
    Original {
        id: HistoryId,
        facts: crate::room_history::AcceptedFacts,
        sequence: NonZeroU64,
    },
    Pending(Hash),
}

/// Expand only authenticated deletion links. The delivery boundary supplies
/// the authorization policy for each exact original.
pub(super) fn visit_history_leaves(
    mut history: impl HistoryRead,
    hash: &Hash,
    workspace: &mut HistoryWorkspace<'_>,
    mut visit: impl FnMut(HistoryLeaf) -> Result<(), Error>,
) -> Result<bool, Error> {
    if *hash == [0; 64] {
        return Ok(false);
    }
    let Some(root) = history.locate(hash)? else {
        visit(HistoryLeaf::Pending(*hash))?;
        return Ok(false);
    };
    let mut walk = workspace.start_history(history, root)?;
    let mut resolved = false;
    while let Some((id, entry)) = walk.pop()? {
        let facts = match entry {
            HistoryEntry::Accepted(facts) => facts,
            HistoryEntry::Pending(hash) => {
                visit(HistoryLeaf::Pending(hash))?;
                continue;
            }
        };
        if !facts.epoch_indexed
            || facts.phase == MessagePhase::Rejected
            || facts.kind == wire::envelope::Kind::JOIN && !facts.semantic_applied
        {
            visit(HistoryLeaf::Pending(facts.hash))?;
            continue;
        }
        if facts.phase == MessagePhase::Deleted {
            for parent in facts.parents.iter().rev() {
                if *parent == [0; 64] {
                    continue;
                }
                if let Some(id) = walk.locate(parent)? {
                    walk.schedule(id)?;
                } else {
                    visit(HistoryLeaf::Pending(*parent))?;
                }
            }
        } else if facts.has_original {
            resolved = true;
            let sequence = NonZeroU64::new(facts.sequence).ok_or(Fault::Conflict)?;
            visit(HistoryLeaf::Original {
                id,
                facts,
                sequence,
            })?;
        } else {
            visit(HistoryLeaf::Pending(facts.hash))?;
        }
    }
    Ok(resolved)
}

#[cfg(all(test, feature = "alloc"))]
mod request_history_tests {
    use super::*;
    use crate::{
        Brand, HistoryCell, Instance, Mode, OwnedBytes, SensitiveBuffer, Slot, SourceRole, crypto,
        model::{node, session, structural_core},
        room_history::AcceptedFacts,
        state::{Node, NodeOrigin},
    };
    use gnunet_identity::SecretKey;
    use gnunet_types::AbsoluteTime;
    use wire::{body::Body, envelope::Kind, message::Message, padding, profile::Profile};
    use zeroize::Zeroizing;

    #[derive(Clone, Copy)]
    struct FinalizedHistory<'a>(&'a [Option<AcceptedFacts>]);

    impl HistoryRead for FinalizedHistory<'_> {
        fn limit(&self) -> usize {
            self.0.len()
        }

        fn coordinate_revision(&self) -> Option<NonZeroU64> {
            None
        }

        fn locate(&mut self, hash: &Hash) -> Result<Option<HistoryId>, Error> {
            Ok(self
                .0
                .iter()
                .position(|facts| facts.is_some_and(|facts| facts.hash == *hash))
                .map(|index| HistoryId::new(index, NonZeroU64::MIN)))
        }

        fn read(&mut self, index: usize) -> Result<(HistoryId, HistoryEntry), Error> {
            let facts = self
                .0
                .get(index)
                .copied()
                .flatten()
                .ok_or(Fault::Conflict)?;
            Ok((
                HistoryId::new(index, NonZeroU64::MIN),
                HistoryEntry::Accepted(facts),
            ))
        }
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assert replay selection from independent finalized metadata"
    )]
    fn selects_originals_from_finalized_history_without_work_nodes() -> Result<(), Error> {
        let original = AcceptedFacts {
            hash: [1; 64],
            parents: [[0; 64]; 2],
            phase: MessagePhase::Applied,
            kind: Kind::TEXT,
            sequence: 7,
            complete: true,
            semantic_applied: true,
            epoch_indexed: true,
            has_original: true,
        };
        let deleted = |hash, parents| AcceptedFacts {
            hash,
            parents,
            phase: MessagePhase::Deleted,
            has_original: false,
            ..original
        };
        let mut records = [None; 8];
        records[2] = Some(deleted([4; 64], [[2; 64], [3; 64]]));
        records[4] = Some(deleted([2; 64], [[1; 64], [9; 64]]));
        records[6] = Some(deleted([3; 64], [[1; 64], [0; 64]]));
        records[7] = Some(original);
        let history = FinalizedHistory(&records);
        let mut member = session(1, 1);
        member.known_from = 7;
        let mut cells = [HistoryCell::EMPTY; 8];
        let mut workspace = HistoryWorkspace::from_cells(&mut cells)?;
        let mut readable = alloc::vec::Vec::new();
        let mut pending = alloc::vec::Vec::new();
        assert!(visit_request_leaves(
            history,
            &member,
            &[4; 64],
            &mut workspace,
            |leaf| {
                match leaf {
                    RequestLeaf::Readable { id, sequence, .. } => {
                        readable.push((id.index(), sequence.get()));
                    }
                    RequestLeaf::Pending(hash) => pending.push(hash),
                }
                Ok(())
            }
        )?);
        assert_eq!(readable, [(7, 7)]);
        assert_eq!(pending, [[9; 64]]);

        member.known_from = 8;
        assert!(visit_request_leaves(
            history,
            &member,
            &[4; 64],
            &mut workspace,
            |leaf| {
                assert!(matches!(leaf, RequestLeaf::Pending(hash) if hash == [9; 64]));
                Ok(())
            }
        )?);
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assert retained history follows current deletion and authorization"
    )]
    fn resident_tombstone_shadows_committed_original_and_reaches_committed_parent()
    -> Result<(), Error> {
        let original = AcceptedFacts {
            hash: [1; 64],
            parents: [[0; 64]; 2],
            phase: MessagePhase::Applied,
            kind: Kind::TEXT,
            sequence: 7,
            complete: true,
            semantic_applied: true,
            epoch_indexed: true,
            has_original: true,
        };
        let before_delete = AcceptedFacts {
            hash: [2; 64],
            kind: Kind::MERGE,
            sequence: 9,
            parents: [original.hash, [3; 64]],
            ..original
        };
        let current = AcceptedFacts {
            phase: MessagePhase::Deleted,
            has_original: false,
            ..before_delete
        };
        let second_branch = AcceptedFacts {
            hash: [3; 64],
            kind: Kind::TEXT,
            parents: [original.hash, [0; 64]],
            sequence: 8,
            ..current
        };
        let resident = [Some(current), Some(second_branch)];
        let committed = [Some(original), Some(before_delete)];
        let history = LayeredHistory::new(
            FinalizedHistory(&resident),
            Some(FinalizedHistory(&committed)),
        )?;
        let mut member = session(1, 1);
        member.known_from = 7;
        let mut cells = [HistoryCell::EMPTY; 4];
        let mut workspace = HistoryWorkspace::from_cells(&mut cells)?;
        let mut readable = alloc::vec::Vec::new();
        assert!(visit_request_leaves(
            history,
            &member,
            &current.hash,
            &mut workspace,
            |leaf| {
                let RequestLeaf::Readable { id, hash, sequence } = leaf else {
                    return Err(Fault::Conflict.into());
                };
                let HistoryLocation::Committed(at) = history.location(id)? else {
                    return Err(Fault::Conflict.into());
                };
                readable.push((at.index(), hash, sequence.get()));
                Ok(())
            }
        )?);
        assert_eq!(readable, [(0, original.hash, original.sequence)]);

        member.known_from = 8;
        assert!(visit_request_leaves(
            history,
            &member,
            &current.hash,
            &mut workspace,
            |_| Err(Fault::Conflict.into())
        )?);
        Ok(())
    }

    fn request(brand: Brand<'_>, member: Slot, seed: u8, target: &Hash) -> Result<Node, Error> {
        let mut key_bytes = Zeroizing::new([seed; 36]);
        key_bytes[..4].copy_from_slice(&wire::KeyType::Eddsa.value().to_be_bytes());
        let signer = SecretKey::from_serialized(&key_bytes[..])?;
        let public = signer.public_key()?;
        let profile = Profile::LITTLE_255;
        let mut original = SensitiveBuffer::<512>::new();
        original.encode_signed(
            &signer,
            crypto::signature::SigningHeader {
                timestamp: AbsoluteTime::UNIX_EPOCH,
                sender_id: &[seed; 32],
                previous: target,
            },
            Body::Request { hash: target },
            profile,
            padding::Encode::Absent,
        )?;
        let message = Message::decode(original.expose(), profile, padding::Decode::Absent)?;
        let verified = crypto::signature::verify_member(message, wire::PublicKey::new(&public)?)?;
        let mut req = node(brand, seed, 4, seed.into(), 1, seed.into())?;
        let auth = req.auth.as_mut().ok_or(Fault::Conflict)?;
        auth.public = public;
        auth.session = Some(member);
        req.hash = *verified.digest();
        req.kind = Kind::REQUEST;
        req.semantic_kind = Kind::REQUEST;
        req.frame = Some(OwnedBytes::copy_from(original.expose())?.into());
        Ok(req)
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assert exact replay originals and silent history denial"
    )]
    fn signed_request_replays_deletion_links_only_with_member_history() -> Result<(), Error> {
        let mut instance = Instance::new();
        let mut core = structural_core(&mut instance)?;
        core.mode = Mode::Service;
        let brand = core.instance;
        let room = core.room([8; 64], None)?;
        let role = SourceRole::Peer([1; 32]);
        let source = core.attach_source(room, role, padding::Decode::Absent, None)?;
        let other = core.attach_source(room, role, padding::Decode::Absent, None)?;
        let row = core.rooms.get_mut(room.slot)?;
        for (hash, parent) in [(1, 0), (2, 0), (3, 1), (4, 3)] {
            let mut original = node(brand, hash, parent, 1, 1, hash.into())?;
            if hash == 4 {
                original.parents[1] = [2; 64];
            }
            let slot = row.insert_node(original)?;
            if hash >= 3 {
                row.erase_message(&mut core.frames, slot, None)?;
            }
        }
        let mut requests = [[0; 64]; 3];
        for ((hash, known_from), seed) in requests.iter_mut().zip([1, 3, 5]).zip(5..=7) {
            let mut modeled = session(seed.into(), 1);
            // Distinct sender IDs produce distinct hashes; the signature is
            // excluded from the official message hash.
            modeled.id = [seed; 32];
            modeled.known_from = known_from;
            let member = row.sessions.insert(modeled).map_err(|(e, _)| e)?;
            let mut req = request(brand, member, seed, &[4; 64])?;
            req.origin = NodeOrigin::from_source(source, role);
            row.sessions.get_mut(member)?.public = req.auth.ok_or(Fault::Conflict)?.public;
            *hash = req.hash;
            row.insert_node(req)?;
        }
        let mut cells = [HistoryCell::EMPTY; 16];
        let mut workspace = HistoryWorkspace::from_cells(&mut cells)?;
        let mut answers = alloc::vec::Vec::new();
        let slot = row.find_node(&requests[0]).ok_or(Fault::NotFound)?;
        let pending = row.nodes.get_mut(slot)?;
        let sequence = core::mem::take(&mut pending.sequence);
        let authentication = pending.auth.take();
        pending.semantic_applied = false;
        pending.epoch_indexed = false;
        let first = core
            .service_request_authority(source, &requests[0])?
            .ok_or(Fault::NotFound)?;
        assert!(matches!(
            core.service_request_original(first, None),
            Err(Error::Protocol(Fault::NotReady))
        ));
        let applied = core.rooms.get_mut(room.slot)?.nodes.get_mut(slot)?;
        applied.sequence = sequence;
        applied.auth = authentication;
        applied.semantic_applied = true;
        applied.epoch_indexed = true;
        assert!(
            core.service_request_authority(other, &requests[0])?
                .is_none()
        );
        assert!(
            core.visit_service_request_history(first, None, &mut workspace, |item| {
                if let ServiceHistoryItem::Resident { sequence, message } = item {
                    answers.push((sequence.get(), *message.hash()));
                }
            })?
        );
        assert_eq!(answers.as_slice(), &[(1, [1; 64]), (2, [2; 64])]);
        for req in &requests[1..] {
            answers.clear();
            let req = core
                .service_request_authority(source, req)?
                .ok_or(Fault::NotFound)?;
            assert!(
                core.visit_service_request_history(req, None, &mut workspace, |item| {
                    if let ServiceHistoryItem::Resident { sequence, message } = item {
                        answers.push((sequence.get(), *message.hash()));
                    }
                })?
            );
            assert!(answers.is_empty());
        }
        core.source_stopped(source)?;
        assert!(matches!(
            core.service_request_original(first, None),
            Err(Error::Permission)
        ));
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assert the exact signed root and provenance of each pending leaf"
    )]
    fn signed_request_only_exposes_pending_hashes_proved_by_deletion_links() -> Result<(), Error> {
        let mut instance = Instance::new();
        let mut core = structural_core(&mut instance)?;
        core.mode = Mode::Service;
        let brand = core.instance;
        let room = core.room([8; 64], None)?;
        let role = SourceRole::Peer([1; 32]);
        let source = core.attach_source(room, role, padding::Decode::Absent, None)?;
        let row = core.rooms.get_mut(room.slot)?;
        for (hash, parent, other) in [(2, 99, 0), (3, 1, 2), (4, 3, 1)] {
            let mut vertex = node(brand, hash, parent, 1, 1, hash.into())?;
            vertex.parents[1] = [other; 64];
            let slot = row.insert_node(vertex)?;
            row.erase_message(&mut core.frames, slot, None)?;
            if hash == 2 {
                row.nodes.get_mut(slot)?.auth = None;
            }
        }
        let member = row.sessions.insert(session(1, 1)).map_err(|(e, _)| e)?;
        let mut exact_request = request(brand, member, 5, &[10; 64])?;
        exact_request.origin = NodeOrigin::from_source(source, role);
        let exact_hash = exact_request.hash;
        row.insert_node(exact_request)?;
        let mut branch_request = request(brand, member, 5, &[4; 64])?;
        branch_request.origin = NodeOrigin::from_source(source, role);
        let branch_hash = branch_request.hash;
        row.sessions.get_mut(member)?.public = branch_request.auth.ok_or(Fault::Conflict)?.public;
        row.insert_node(branch_request)?;

        let mut cells = [HistoryCell::EMPTY; 16];
        let mut workspace = HistoryWorkspace::from_cells(&mut cells)?;
        let mut pending = alloc::vec::Vec::new();
        let exact = core
            .service_request_authority(source, &exact_hash)?
            .ok_or(Fault::NotFound)?;
        let branch = core
            .service_request_authority(source, &branch_hash)?
            .ok_or(Fault::NotFound)?;
        assert!(
            !core.visit_service_request_history(exact, None, &mut workspace, |item| {
                if let ServiceHistoryItem::Pending(hash) = item {
                    pending.push(hash);
                }
            })?
        );
        assert_eq!(pending.as_slice(), &[[10; 64]]);

        pending.clear();
        assert!(
            !core.visit_service_request_history(branch, None, &mut workspace, |item| {
                if let ServiceHistoryItem::Pending(hash) = item {
                    pending.push(hash);
                }
            })?
        );
        pending.sort_unstable();
        pending.dedup();
        assert_eq!(pending.as_slice(), &[[1; 64], [2; 64]]);

        core.rooms
            .get_mut(room.slot)?
            .insert_node(node(brand, 1, 0, 1, 1, 1)?)?;
        let mut read = alloc::vec::Vec::new();
        pending.clear();
        assert!(
            core.visit_service_request_history(branch, None, &mut workspace, |item| {
                match item {
                    ServiceHistoryItem::Resident { message, .. } => read.push(*message.hash()),
                    ServiceHistoryItem::Pending(hash) => pending.push(hash),
                    ServiceHistoryItem::Committed { .. } => (),
                }
            })?
        );
        assert_eq!(read.as_slice(), &[[1; 64]]);
        assert_eq!(pending.as_slice(), &[[2; 64]]);
        Ok(())
    }
}
