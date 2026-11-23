//! Local SERVICE history permissions and delivery metadata.

use super::{
    ServiceAttribution, ServiceRequestAuthority,
    history::{HistoryLeaf, ServiceHistoryItem, check_archive, visit_history_leaves},
};
use crate::{
    CommittedServiceOriginal, Core, Error, Hash, HistoryWorkspace, MemberSession, MessagePhase,
    Mode, OriginalLayout, PublicKey, Room, ShortHash, Slot, Source,
    archive::{ArchivedLocalOriginal, CommittedRoomHistory},
    graph,
    room_history::LayeredHistory,
    state::{Authentication, Node, RoomRow},
    wire,
};
use core::num::NonZeroU64;
use gnunet_crypto::hash512;
use gnunet_types::Error as Fault;
use wire::{envelope::Kind, padding::Decode};

/// One exact signed original authorized for a local SERVICE client.
/// The original bytes remain borrowed from the resident room or its pinned
/// committed image. This view does not grant a member or transport lease.
pub struct ServiceLocalOriginal<'a, 'id> {
    hash: Hash,
    kind: Kind,
    layout: OriginalLayout,
    padding: Decode,
    bytes: &'a [u8],
    sequence: NonZeroU64,
    requested: bool,
    attribution: ServiceAttribution<'id>,
    is_sender: bool,
}

impl<'a, 'id> ServiceLocalOriginal<'a, 'id> {
    /// Exact signed message hash.
    pub const fn hash(&self) -> &Hash {
        &self.hash
    }

    /// Signed outer envelope kind.
    pub const fn kind(&self) -> Kind {
        self.kind
    }

    /// Admitted signed-body and outer-padding layouts.
    pub const fn layout(&self) -> OriginalLayout {
        self.layout
    }

    /// Original transport padding policy.
    pub const fn padding(&self) -> Decode {
        self.padding
    }

    /// Exact signed Messenger bytes, including stored outer padding.
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Stable acceptance order in this room.
    pub const fn sequence(&self) -> NonZeroU64 {
        self.sequence
    }

    /// Whether the original was admitted in response to a request.
    pub const fn requested(&self) -> bool {
        self.requested
    }

    /// Original signer and epoch with the current successor context.
    /// An archive-only row cannot produce a source or member capability.
    pub const fn attribution(&self) -> ServiceAttribution<'id> {
        self.attribution
    }

    /// Whether the client owns the actual current sender session.
    /// This is always false for an archive-only row.
    pub const fn is_sender(&self) -> bool {
        self.is_sender
    }
}

#[derive(Clone, Copy)]
enum Provenance<'id> {
    Resident(Option<Source<'id>>),
    Committed,
}

impl<'id> Provenance<'id> {
    const fn source(self) -> Option<Source<'id>> {
        match self {
            Self::Resident(source) => source,
            Self::Committed => None,
        }
    }
}

struct AttributionSubject<'id> {
    auth: Authentication,
    epoch: Hash,
    provenance: Provenance<'id>,
}

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    /// Exact original auth snapshot, with bounded successor traversal. It works
    /// for verified opaque PRIVATE/SECRET outer messages without decrypting them.
    /// Unknown or awaiting signatures remain NotReady.
    pub fn service_attribution(
        &self,
        room: Room<'id>,
        hash: &Hash,
    ) -> Result<ServiceAttribution<'id>, Error> {
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        let room = self.check_room(room)?;
        let row = self.rooms.get(room)?;
        let node = row.nodes.get(row.find_node(hash).ok_or(Fault::NotFound)?)?;
        self.attribute_original(room, row, self.resident_attribution(node)?)
    }

    /// Whether a local client has this authentic original message's history
    /// right. No current Contact.key is substituted for an old author snapshot.
    pub fn service_may_read(&self, source: Source<'id>, hash: &Hash) -> Result<bool, Error> {
        let principal = self.service_client(source)?;
        let row = self.rooms.get(source.room)?;
        let node = row.nodes.get(row.find_node(hash).ok_or(Fault::NotFound)?)?;
        Ok(client_may_read(
            row,
            principal,
            node.kind,
            node.auth.map(|_| node.sequence),
        ))
    }

    /// Actual current-session sender relation for the official SENT flag.
    /// Historical ownership and current Contact aliases do not manufacture it.
    pub fn service_is_sender(&self, source: Source<'id>, hash: &Hash) -> Result<bool, Error> {
        let Some(member) = self.service_member(source)? else {
            return Ok(false);
        };
        let room = self.rooms.get(source.room)?;
        let node = room
            .nodes
            .get(room.find_node(hash).ok_or(Fault::NotFound)?)?;
        Ok(sender_matches(node.auth, member))
    }

    /// Select authenticated originals for a local GET, following retained
    /// deletion links before checking the caller's current member lineage.
    /// A locally resolved leaf suppresses a missing notice even if the caller
    /// has no right to read it. Recheck delivery permission before sending;
    /// selection does not carry a lease across turns.
    ///
    /// If supplied, the archive must be pinned to the exact checkpoint, with
    /// workspace cells for both the working room and committed directory.
    ///
    /// # Errors
    /// Refuses an invalid client, a mismatched checkpoint or insufficient
    /// workspace, and propagates a visitor failure.
    pub fn visit_service_local_history(
        &self,
        source: Source<'id>,
        hash: &Hash,
        archive: Option<CommittedRoomHistory<'_, '_>>,
        workspace: &mut HistoryWorkspace<'_>,
        mut visit: impl FnMut(Hash) -> Result<(), Error>,
    ) -> Result<bool, Error> {
        let principal = self.service_client(source)?;
        let row = self.rooms.get(source.room)?;
        check_archive(row, source.room, self.local_peer, archive)?;
        let history = LayeredHistory::new(row.history_snapshot(), archive)?;
        visit_history_leaves(history, hash, workspace, |leaf| match leaf {
            HistoryLeaf::Original {
                facts, sequence, ..
            } if client_may_read(row, principal, facts.kind, Some(sequence.get())) => {
                visit(facts.hash)
            }
            _ => Ok(()),
        })
    }

    /// Read one original for local GET or RECENT after checking the client's
    /// current member lineage. A resident observation always takes precedence,
    /// including a tombstone or an original still awaiting authentication.
    ///
    /// The native owner must pin the exact committed checkpoint. An image
    /// with the same generation or watermark alone is not sufficient. Cold
    /// rows rely on the retained session table for current successor context;
    /// archive coordinates are never promoted to live capabilities.
    ///
    /// Returns no original when an observed row has no deliverable bytes or
    /// access is denied, including when a TALK falls outside the subscription.
    /// This method does not apply signed REQUEST permissions.
    ///
    /// # Errors
    /// Refuses an invalid client or checkpoint, a missing hash, and an
    /// incomplete or inconsistent original authentication or payload.
    pub fn service_local_original<'a>(
        &'a self,
        source: Source<'id>,
        hash: &Hash,
        archive: Option<CommittedRoomHistory<'a, '_>>,
    ) -> Result<Option<ServiceLocalOriginal<'a, 'id>>, Error> {
        let principal = self.service_client(source)?;
        let row = self.rooms.get(source.room)?;
        check_archive(row, source.room, self.local_peer, archive)?;
        if let Some(at) = row.find_node(hash) {
            let node = row.nodes.get(at)?;
            if !node.has_original()
                || matches!(node.phase, MessagePhase::Deleted | MessagePhase::Rejected)
                || !client_may_read(row, principal, node.kind, node.auth.map(|_| node.sequence))
            {
                return Ok(None);
            }
            let attribution =
                self.attribute_original(source.room, row, self.resident_attribution(node)?)?;
            let member = self.service_member(source)?;
            if node.kind == Kind::TALK {
                let Some(member) = member else {
                    return Ok(None);
                };
                let discourse = node.discourse.as_ref().ok_or(Fault::Conflict)?;
                if !self.may_deliver_talk(member, discourse, node.timestamp)? {
                    return Ok(None);
                }
            }
            let is_sender = member.is_some_and(|member| sender_matches(node.auth, member));
            let bytes = if let Some(range) = node.archived_original() {
                archive.ok_or(Fault::NotReady)?.retained_original(range)?
            } else {
                node.original(&self.frames)?.ok_or(Fault::Conflict)?
            };
            return Ok(Some(ServiceLocalOriginal {
                hash: node.hash,
                kind: node.kind,
                layout: node.layout,
                padding: node.padding,
                bytes,
                sequence: NonZeroU64::new(node.sequence).ok_or(Fault::Conflict)?,
                requested: node.requested,
                attribution,
                is_sender,
            }));
        }

        let Some(cold) = archive.ok_or(Fault::NotFound)?.local_original(hash)? else {
            return Ok(None);
        };
        let kind = cold.original.kind();
        if !client_may_read(row, principal, kind, Some(cold.sequence.get())) {
            return Ok(None);
        }
        self.committed_local_delivery(source.room, row, cold)
            .map(Some)
    }

    /// Read an absent working original for a previously selected signed REQUEST
    /// reply. The request must still be live on this exact client source, and
    /// the selected hash and sequence must still be authorized by its signed
    /// target. Current local GET permissions are separate.
    ///
    /// # Errors
    /// Rejects an invalid client, an inconsistent checkpoint or original, and
    /// a request whose signer or source cannot authorize this history.
    pub fn service_requested_detached_original<'a>(
        &'a self,
        request: ServiceRequestAuthority<'id>,
        (hash, sequence): (&Hash, NonZeroU64),
        archive: CommittedRoomHistory<'a, '_>,
        workspace: &mut HistoryWorkspace<'_>,
    ) -> Result<Option<ServiceLocalOriginal<'a, 'id>>, Error> {
        let source = request.source();
        self.service_client(source)?;
        let row = self.rooms.get(source.room)?;
        check_archive(row, source.room, self.local_peer, Some(archive))?;
        if row.find_node(hash).is_some() {
            return Ok(None);
        }
        let mut authorized = false;
        self.visit_service_request_history(request, Some(archive), workspace, |item| {
            if let ServiceHistoryItem::Committed {
                sequence: actual,
                original,
            } = item
            {
                authorized |= actual == sequence && original.hash() == hash;
            }
        })?;
        if !authorized {
            return Ok(None);
        }
        match archive.detached_local_original(hash)? {
            Some(cold) => self
                .committed_local_delivery(source.room, row, cold)
                .map(Some),
            None => Ok(None),
        }
    }

    /// Resolve an existing live publication notice after the durable owner has
    /// detached its original. The caller still owns the exact notice and may
    /// only forward it on a channel for its room, excluding its ingress.
    /// This cannot promote archived attribution into a live source.
    ///
    /// # Errors
    /// Rejects a foreign room or checkpoint and inconsistent archived signing
    /// information.
    pub fn service_detached_notice_original<'a>(
        &'a self,
        room: Room<'id>,
        hash: &Hash,
        archive: CommittedRoomHistory<'a, '_>,
    ) -> Result<Option<CommittedServiceOriginal<'a>>, Error> {
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        let at = self.check_room(room)?;
        let row = self.rooms.get(at)?;
        check_archive(row, at, self.local_peer, Some(archive))?;
        if row.find_node(hash).is_some() {
            return Ok(None);
        }
        let Some(cold) = archive
            .detached_local_original(hash)?
            .filter(|cold| !cold.requested && cold.original.kind() != Kind::REQUEST)
        else {
            return Ok(None);
        };
        self.committed_attribution(at, row, &cold)?;
        Ok(Some(cold.original))
    }

    fn committed_local_delivery<'a>(
        &self,
        room: Slot,
        row: &RoomRow<'id>,
        cold: ArchivedLocalOriginal<'a>,
    ) -> Result<ServiceLocalOriginal<'a, 'id>, Error> {
        let attribution = self.committed_attribution(room, row, &cold)?;
        Ok(ServiceLocalOriginal {
            hash: *cold.original.hash(),
            kind: cold.original.kind(),
            layout: cold.original.layout(),
            padding: cold.original.padding(),
            bytes: cold.original.bytes(),
            sequence: cold.sequence,
            requested: cold.requested,
            attribution,
            is_sender: false,
        })
    }

    pub(super) fn committed_attribution(
        &self,
        room: Slot,
        row: &RoomRow<'id>,
        cold: &ArchivedLocalOriginal<'_>,
    ) -> Result<ServiceAttribution<'id>, Error> {
        let kind = cold.original.kind();
        check_attribution_ready(kind, true, cold.semantic_applied)?;
        cold.original
            .layout()
            .check_signer(cold.auth.public, cold.auth.peer)?;
        self.attribute_original(
            room,
            row,
            AttributionSubject {
                auth: cold.auth,
                epoch: cold.epoch,
                provenance: Provenance::Committed,
            },
        )
    }

    fn resident_attribution(&self, node: &Node) -> Result<AttributionSubject<'id>, Error> {
        let auth = node.auth.ok_or(Fault::NotReady)?;
        check_attribution_ready(node.kind, node.epoch_indexed, node.semantic_applied)?;
        Ok(AttributionSubject {
            auth,
            epoch: node.epoch,
            provenance: Provenance::Resident(node.origin.live(self.instance)),
        })
    }

    fn attribute_original(
        &self,
        room: Slot,
        row: &RoomRow<'id>,
        subject: AttributionSubject<'id>,
    ) -> Result<ServiceAttribution<'id>, Error> {
        let AttributionSubject {
            auth,
            epoch,
            provenance,
        } = subject;
        let source = provenance.source();
        if let Some(peer) = auth.peer {
            if matches!(provenance, Provenance::Committed)
                && (auth.owner.is_some()
                    || auth.session.is_some()
                    || auth.public[..4] != wire::KeyType::Eddsa.value().to_be_bytes()
                    || auth.public[4..] != peer)
            {
                return Err(Fault::Authentication.into());
            }
            let sender = hash512(&peer);
            return Ok(ServiceAttribution {
                source,
                sender,
                context: sender,
                member: None,
                peer: true,
                epoch,
            });
        }
        let original = auth.session.ok_or(Fault::NotReady)?;
        if matches!(provenance, Provenance::Committed) {
            let session = row.sessions.get(original)?;
            if auth.owner != Some(graph::owner(session)) || auth.public != session.public {
                return Err(Fault::Authentication.into());
            }
        }
        let latest = latest_successor(row, original)?;
        let digest = hash512(&row.sessions.get(latest)?.id);
        let mut context = row.key;
        for (value, part) in context.iter_mut().zip(digest) {
            *value ^= part;
        }
        Ok(ServiceAttribution {
            source,
            sender: hash512(&auth.public),
            context,
            member: match provenance {
                Provenance::Resident(_) => Some(self.member_id(room, original)),
                Provenance::Committed => None,
            },
            peer: false,
            epoch,
        })
    }
}

pub(super) fn latest_successor(room: &RoomRow<'_>, mut slot: Slot) -> Result<Slot, Error> {
    for _ in 0..room.sessions.limit() {
        let Some(next) = room.sessions.get(slot)?.successor else {
            return Ok(slot);
        };
        slot = next;
    }
    Err(Fault::Malformed.into())
}

fn check_attribution_ready(
    kind: Kind,
    epoch_indexed: bool,
    semantic_applied: bool,
) -> Result<(), Error> {
    if !epoch_indexed || kind == Kind::JOIN && !semantic_applied {
        return Err(Fault::NotReady.into());
    }
    Ok(())
}

fn client_may_read(
    room: &RoomRow<'_>,
    (public, id): (PublicKey, ShortHash),
    kind: Kind,
    sequence: Option<u64>,
) -> bool {
    let current = room.sessions.iter().find_map(|(_, member)| {
        (member.public == public && member.id == id && member.has_live_authority())
            .then_some(member)
    });
    let Some(current) = current else {
        return false;
    };
    graph::epoch_kind(kind)
        || sequence.is_some_and(|sequence| {
            room.sessions.iter().any(|(_, old)| {
                old.contact == current.contact
                    && old.lineage == current.lineage
                    && old.generation <= current.generation
                    && graph::knows_sequence(old, sequence)
            })
        })
}

fn sender_matches(auth: Option<Authentication>, member: MemberSession<'_>) -> bool {
    auth.is_some_and(|auth| auth.peer.is_none() && auth.session == Some(member.slot))
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::{
        CommittedArchive, HistoryCell, Instance, OwnedBytes, SensitiveBuffer, SessionPhase,
        SourceRole,
        archive::ArchiveHistoryCell,
        crypto::signature::{SigningHeader, message_hash},
        model::{node, session, structural_core},
        state::NodeOrigin,
    };
    use alloc::vec::Vec;
    use gnunet_identity::SecretKey;
    use gnunet_types::AbsoluteTime;
    use wire::{
        body::{Body, Text},
        message::Message,
        padding::Encode,
        profile::Profile,
    };
    use zeroize::Zeroizing;

    struct Checkpoint(Zeroizing<Vec<u8>>);

    impl CommittedArchive for Checkpoint {
        fn generation(&self) -> u64 {
            1
        }

        fn expose_committed(&self) -> &[u8] {
            self.0.as_slice()
        }
    }

    fn signing_key(seed: u8) -> Result<SecretKey, Error> {
        let mut bytes = Zeroizing::new([seed; 36]);
        bytes[..4].copy_from_slice(&wire::KeyType::Eddsa.value().to_be_bytes());
        Ok(SecretKey::from_serialized(&bytes[..])?)
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assert the original signing snapshot and absence of live archived authority"
    )]
    fn cold_read_keeps_retired_signer_and_current_lineage_context() -> Result<(), Error> {
        const ROOM_KEY: Hash = [16; 64];
        const EPOCH: Hash = [11; 64];
        const MAXIMUM: usize = 8192;
        const HISTORICAL_ROWS: usize = 1;
        let mut instance = Instance::new();
        let mut core = structural_core(&mut instance)?;
        core.mode = Mode::Service;
        core.configure_local_peer([9; 32])?;
        let room = core.room(ROOM_KEY, None)?;
        let signer = signing_key(7)?;
        let public = signer.public_key()?;
        let successor_public = signing_key(8)?.public_key()?;
        let original_id = [4; 32];
        let successor_id = [5; 32];
        let unrelated_id = [6; 32];
        let author = core.attach_source(room, SourceRole::Client, Decode::Absent, Some(public))?;
        core.bind_service_client(author, public, original_id)?;
        let reader = core.attach_source(
            room,
            SourceRole::Client,
            Decode::Absent,
            Some(successor_public),
        )?;
        core.bind_service_client(reader, successor_public, successor_id)?;
        let unrelated = core.attach_source(
            room,
            SourceRole::Client,
            Decode::Absent,
            Some(successor_public),
        )?;
        core.bind_service_client(unrelated, successor_public, unrelated_id)?;

        let mut bytes = SensitiveBuffer::<512>::new();
        bytes.encode_signed(
            &signer,
            SigningHeader {
                timestamp: AbsoluteTime::UNIX_EPOCH,
                sender_id: &original_id,
                previous: &[0; 64],
            },
            Body::Text {
                text: Text::new(b"original member text")?,
            },
            Profile::LITTLE_255,
            Encode::Absent,
        )?;
        let hash = message_hash(Message::decode(
            bytes.expose(),
            Profile::LITTLE_255,
            Decode::Absent,
        )?);
        let brand = core.instance;
        let row = core.rooms.get_mut(room.slot)?;
        row.sequence = 2;
        row.lineage = 2;
        let mut previous = session(1, 1);
        previous.id = original_id;
        previous.public = public;
        previous.hpke = [0; 36];
        previous.phase = SessionPhase::Completed;
        previous.completed_at = Some(1);
        let owner = graph::owner(&previous);
        let original = row.sessions.insert(previous).map_err(|(error, _)| error)?;

        let mut latest = session(1, 2);
        latest.id = successor_id;
        latest.public = successor_public;
        latest.hpke = [0; 36];
        latest.known_from = 2;
        let later = row.sessions.insert(latest).map_err(|(error, _)| error)?;
        row.sessions.get_mut(original)?.successor = Some(later);

        let mut other = session(2, 1);
        other.id = unrelated_id;
        other.public = successor_public;
        other.hpke = [0; 36];
        other.known_from = 2;
        row.sessions.insert(other).map_err(|(error, _)| error)?;

        let mut original_node = node(brand, 1, 0, 1, 1, 1)?;
        original_node.hash = hash;
        original_node.origin = NodeOrigin::from_source(author, SourceRole::Client);
        original_node.epoch = EPOCH;
        original_node.frame = Some(OwnedBytes::copy_from(bytes.expose())?.into());
        original_node.auth = Some(Authentication {
            owner: Some(owner),
            session: Some(original),
            public,
            peer: None,
        });
        let at = row.insert_node(original_node)?;
        core.source_stopped(author)?;
        let expected = core.service_attribution(room, &hash)?;
        assert_eq!(expected.sender, hash512(&public));
        let successor_digest = hash512(&successor_id);
        assert_eq!(
            expected.context,
            core::array::from_fn(|index| ROOM_KEY[index] ^ successor_digest[index])
        );
        assert!(expected.member.is_some());
        assert!(core.service_may_read(reader, &hash)?);
        assert!(!core.service_may_read(unrelated, &hash)?);

        let checkpoint = Checkpoint(core.prepare_archive(MAXIMUM)?.into_body());
        let mut index = [ArchiveHistoryCell::EMPTY; HISTORICAL_ROWS];
        let committed = CommittedRoomHistory::from_committed(
            &checkpoint,
            core.limits,
            MAXIMUM,
            &ROOM_KEY,
            &mut index,
        )?
        .ok_or(Fault::NotFound)?;
        // Exercise a cold-only row without adding a production eviction path.
        let row = core.rooms.get_mut(room.slot)?;
        row.index.retain(|slot| slot != at);
        row.nodes.remove(at)?;
        let mut cells =
            alloc::vec![HistoryCell::EMPTY; core.limits.messages_per_room + HISTORICAL_ROWS];
        let mut workspace = HistoryWorkspace::from_cells(&mut cells)?;
        let mut answer = None;
        assert!(core.visit_service_local_history(
            reader,
            &hash,
            Some(committed),
            &mut workspace,
            |seen| {
                assert!(answer.replace(seen).is_none());
                Ok(())
            }
        )?);
        assert_eq!(answer, Some(hash));
        assert!(core.visit_service_local_history(
            unrelated,
            &hash,
            Some(committed),
            &mut workspace,
            |_| {
                panic!("an unrelated lineage must not learn the original hash");
            }
        )?);
        assert!(
            core.service_local_original(author, &hash, Some(committed))
                .is_err()
        );
        assert!(
            core.service_local_original(unrelated, &hash, Some(committed))?
                .is_none()
        );
        let delivered = core
            .service_local_original(reader, &hash, Some(committed))?
            .ok_or(Fault::NotFound)?;
        let actual = delivered.attribution();
        assert_eq!(actual.sender, expected.sender);
        assert_eq!(actual.context, expected.context);
        assert_eq!(actual.epoch, EPOCH);
        assert!(actual.source.is_none() && actual.member.is_none());
        assert!(!actual.peer && !delivered.is_sender());
        assert_eq!(delivered.sequence(), NonZeroU64::MIN);
        assert_eq!(delivered.bytes(), bytes.expose());
        Ok(())
    }
}
