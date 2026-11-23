//! Exact detached pages of canonical Messenger graph records.

use super::history::{hash_at, sequence_at, sort_unique};
use super::*;
use crate::room_history::{HistoryEntry, HistoryId, HistoryRead};
use core::num::NonZeroU64;
use gnunet_crypto::EddsaPublicKey;

mod deletion;
mod policy;
pub use deletion::DetachedDeletion;
pub(crate) use policy::DetachedKind;
pub(super) use policy::can_detach;

#[cfg(all(test, feature = "alloc"))]
mod tests;

const MAGIC: &[u8; 8] = b"GMSPAG01";

/// Upper bound on canonical graph rows in a payload extent. A row encodes
/// its hash, two parents, three references and two epochs even if zero.
pub const fn maximum_graph_page_rows(payload_bytes: usize) -> usize {
    let rows = payload_bytes / (8 * size_of::<Hash>());
    if rows > u8::MAX as usize {
        u8::MAX as usize
    } else {
        rows
    }
}

/// The logical identity of one detached page, independent of the native
/// lane, slot and byte commitment recorded by its storage owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GraphPageIdentity {
    namespace: [u8; 16],
    peer: EddsaPublicKey,
    room: Hash,
    emission: NonZeroU64,
    ordinal: u8,
}

impl GraphPageIdentity {
    /// Bind a page to its actual provisioning namespace, local peer, room and
    /// emission. The ordinal distinguishes pages from the same emission.
    #[must_use]
    pub const fn new(
        namespace: [u8; 16],
        peer: EddsaPublicKey,
        room: Hash,
        emission: NonZeroU64,
        ordinal: u8,
    ) -> Self {
        Self {
            namespace,
            peer,
            room,
            emission,
            ordinal,
        }
    }

    /// The original storage provisioning namespace.
    #[must_use]
    pub const fn namespace(&self) -> &[u8; 16] {
        &self.namespace
    }

    /// The local peer owning the emission.
    #[must_use]
    pub const fn peer(&self) -> EddsaPublicKey {
        self.peer
    }

    /// The exact Messenger room key.
    #[must_use]
    pub const fn room(&self) -> &Hash {
        &self.room
    }

    /// The nonzero emission that prepared the page, independent of message
    /// acceptance order and a later root that may keep referencing it.
    #[must_use]
    pub const fn emission(&self) -> NonZeroU64 {
        self.emission
    }

    /// The page's ordinal within its emission.
    #[must_use]
    pub const fn ordinal(&self) -> u8 {
        self.ordinal
    }

    /// Decode the identity prefix without authenticating or lending the page.
    ///
    /// # Errors
    /// Rejects a wrong format, truncated prefix or zero emission.
    pub fn read_prefix(bytes: &[u8]) -> Result<Self, Error> {
        Self::read(&mut Decoder::new(bytes))
    }

    fn read(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        if decoder.raw(MAGIC.len())? != MAGIC {
            return Err(Fault::Malformed.into());
        }
        let namespace = decoder.array()?;
        let peer = EddsaPublicKey::from_bytes(decoder.array()?);
        let room = decoder.array()?;
        let emission = NonZeroU64::new(decoder.u64()?).ok_or(Fault::Malformed)?;
        let ordinal = decoder.u8()?;
        Ok(Self::new(namespace, peer, room, emission, ordinal))
    }

    fn write(&self, encoder: &mut Encoder<impl ArchiveSink>) -> Result<(), Error> {
        encoder.raw(MAGIC)?;
        encoder.raw(self.namespace())?;
        encoder.raw(self.peer.as_bytes())?;
        encoder.raw(self.room())?;
        encoder.u64(self.emission.get())?;
        encoder.u8(self.ordinal)
    }
}

/// Native handoff of the exact immutable graph page selected by a committed
/// root. Implement only after verifying the original storage owner, lane,
/// slot and byte commitment; neither decoded identity nor a standalone write
/// grants this boundary.
pub trait CommittedGraphPageBytes {
    /// Borrow the selected page, excluding its storage envelope.
    fn expose_committed_page(&self) -> &[u8];
}

/// Borrowed graph facts and originals from one exact committed page. This
/// view never restores an original as a live event or verifies a signature.
#[derive(Clone, Copy)]
pub struct CommittedGraphPage<'page, 'index> {
    bytes: &'page [u8],
    index: &'index [ArchiveHistoryCell],
    identity: GraphPageIdentity,
    room: Slot,
    accepted_through: u64,
    limits: Limits,
    next_deletion: Option<(u64, usize)>,
}

impl<'page, 'index> CommittedGraphPage<'page, 'index> {
    /// Validate and index one nonempty immutable page. Callers supply one
    /// cell per row; no frame or graph vertex is restored into Core.
    ///
    /// # Errors
    /// Rejects an identity mismatch, malformed page, duplicate hash or
    /// acceptance order, or insufficient index cells.
    pub fn open(
        store: &'page impl CommittedGraphPageBytes,
        expected: GraphPageIdentity,
        limits: Limits,
        index: &'index mut [ArchiveHistoryCell],
    ) -> Result<Self, Error> {
        let bytes = store.expose_committed_page();
        u32::try_from(bytes.len()).map_err(|_| Fault::Capacity)?;
        let mut decoder = Decoder::new(bytes);
        let identity = GraphPageIdentity::read(&mut decoder)?;
        if identity != expected {
            return Err(Fault::StaleGeneration.into());
        }
        let room = decoder.slot(limits.rooms)?;
        let accepted_through = decoder.u64()?;
        let count = usize::from(decoder.u8()?);
        if count == 0 {
            return Err(Fault::Malformed.into());
        }
        let index = index.get_mut(..count).ok_or(Fault::Capacity)?;
        let mut previous = None;
        let mut next_deletion = None;
        for (position, cell) in index.iter_mut().enumerate() {
            let row = cell.read_row(&mut decoder, limits, accepted_through, room)?;
            DetachedKind::validate_record(&row)?;
            if row.phase == MessagePhase::Applied
                && let Some(deadline) = row.delete_at
            {
                let candidate = (deadline, position);
                next_deletion =
                    Some(next_deletion.map_or(candidate, |old: (u64, usize)| old.min(candidate)));
            }
            if previous.is_some_and(|hash| row.hash <= hash) {
                return Err(Fault::Conflict.into());
            }
            previous = Some(row.hash);
        }
        decoder.end()?;
        // The encoded directory order is by hash. Check the independent
        // sequence order in place and recover hash order using row positions.
        sort_unique(bytes, index, sequence_at)?;
        index.sort_unstable_by_key(|cell| cell.row);
        Ok(Self {
            bytes,
            index,
            identity,
            room,
            accepted_through,
            limits,
            next_deletion,
        })
    }

    /// The page's exact checked logical identity.
    #[must_use]
    pub const fn identity(&self) -> &GraphPageIdentity {
        &self.identity
    }

    /// The historical room slot and its generation, as encoded in every
    /// original source observation in this page.
    #[must_use]
    pub const fn room_position(&self) -> (usize, u64) {
        (self.room.index, self.room.generation)
    }

    /// The room's acceptance cursor at the emission, not a page revision.
    #[must_use]
    pub const fn accepted_through(&self) -> u64 {
        self.accepted_through
    }

    /// The number of indexed message records. A valid page is nonempty.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.index.len()
    }

    /// Whether this page contains no records.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Look up an exact message by hash without scanning other rows.
    ///
    /// # Errors
    /// Refuses an inconsistent index or a malformed row.
    pub fn get(&self, hash: &Hash) -> Result<Option<GraphPageMessage<'page>>, Error> {
        self.position(hash)
            .map(|index| self.entry(index))
            .transpose()
    }

    /// Read one record in the page's hash order. Its index is relative to
    /// this exact page; it cannot be compared across page publications.
    ///
    /// # Errors
    /// Refuses an out-of-bounds index or a malformed row.
    pub fn entry(&self, index: usize) -> Result<GraphPageMessage<'page>, Error> {
        let row = self.record(index)?;
        Ok(GraphPageMessage {
            sequence: NonZeroU64::new(row.sequence).ok_or(Fault::Malformed)?,
            row,
        })
    }

    pub(super) fn position(&self, hash: &[u8]) -> Option<usize> {
        self.index
            .binary_search_by(|cell| hash_at(self.bytes, *cell).cmp(hash))
            .ok()
    }

    pub(super) fn index_keys(&self) -> impl Iterator<Item = (&'page [u8], &'page [u8])> + '_ {
        self.index
            .iter()
            .map(|cell| (hash_at(self.bytes, *cell), sequence_at(self.bytes, *cell)))
    }

    pub(super) fn contains_key(&self, hash: &[u8], sequence: &[u8]) -> bool {
        self.position(hash).is_some()
            || self
                .index
                .iter()
                .any(|cell| sequence_at(self.bytes, *cell) == sequence)
    }

    pub(super) fn record(&self, index: usize) -> Result<MessageRecord<'page>, Error> {
        let offset = self.index.get(index).ok_or(Fault::InvalidInput)?.row as usize;
        MessageRecord::read(
            &mut Decoder::at(self.bytes, offset),
            self.limits,
            self.accepted_through,
        )
    }

    fn row_bytes(&self, index: usize) -> &[u8] {
        let start = self.index[index].row as usize;
        let end = self
            .index
            .get(index + 1)
            .map_or(self.bytes.len(), |cell| cell.row as usize);
        &self.bytes[start..end]
    }

    pub(super) fn deletion_reserve(&self) -> Result<usize, Error> {
        let mut reserved = 0;
        for position in 0..self.len() {
            let row = self.record(position)?;
            if row.phase == MessagePhase::Applied
                && row.delete_at.is_none()
                && DetachedKind::of(row.kind).is_some_and(DetachedKind::is_deletable)
            {
                reserved += DELETION_BYTES;
            }
        }
        Ok(reserved)
    }
}

pub(super) const DELETION_BYTES: usize = size_of::<u64>() + size_of::<Hash>();

impl HistoryRead for CommittedGraphPage<'_, '_> {
    fn coordinate_revision(&self) -> Option<NonZeroU64> {
        Some(self.identity.emission())
    }

    fn limit(&self) -> usize {
        self.len()
    }

    fn locate(&mut self, hash: &Hash) -> Result<Option<HistoryId>, Error> {
        Ok(self
            .position(hash)
            .map(|index| HistoryId::new(index, self.identity.emission())))
    }

    fn read(&mut self, index: usize) -> Result<(HistoryId, HistoryEntry), Error> {
        let row = self.record(index)?;
        Ok((
            HistoryId::new(index, self.identity.emission()),
            HistoryEntry::Accepted(row.graph_facts()),
        ))
    }
}

/// One historical row lent by the selected committed graph page. Its state
/// never establishes live membership, signing rights or delivery permission.
pub struct GraphPageMessage<'page> {
    row: MessageRecord<'page>,
    sequence: NonZeroU64,
}

impl<'page> GraphPageMessage<'page> {
    /// Exact message hash.
    #[must_use]
    pub const fn hash(&self) -> &Hash {
        &self.row.hash
    }

    /// Ordered original predecessor hashes, with zero marking absence.
    #[must_use]
    pub const fn parents(&self) -> &[Hash; 2] {
        &self.row.parents
    }

    /// Message kind from the accepted original.
    #[must_use]
    pub const fn kind(&self) -> wire::envelope::Kind {
        self.row.kind
    }

    /// Stable nonzero acceptance order in the original room.
    #[must_use]
    pub const fn sequence(&self) -> NonZeroU64 {
        self.sequence
    }

    /// Committed acceptance or deletion phase.
    #[must_use]
    pub const fn phase(&self) -> MessagePhase {
        self.row.phase
    }

    /// The retained original bytes, without a delivery or signature grant.
    /// Deleted rows have no bytes; rejected originals are not served.
    #[must_use]
    pub fn original(&self) -> Option<&'page [u8]> {
        self.row
            .frame
            .filter(|_| self.row.phase != MessagePhase::Rejected)
            .map(|(_, bytes)| bytes)
    }
}

/// A caller-owned encoded page awaiting native publication. Dropping it
/// erases the encoded prefix; it grants no durable receipt.
pub struct PreparedGraphPageRef<'output> {
    body: SliceSink<'output>,
}

impl PreparedGraphPageRef<'_> {
    /// Borrow the prepared page, without a storage envelope.
    pub fn expose(&self) -> &[u8] {
        self.body.expose()
    }

    /// Release the exact prefix to the original storage worker, which must
    /// erase the supplied output after publishing or discarding it.
    pub fn into_len_for_storage(self) -> usize {
        self.body.into_len_for_storage()
    }
}

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    /// Prepare settled public data or signed room routing controls for an
    /// exact detached page.
    /// Select a nonempty list of strictly increasing hashes. Keep any
    /// original with a pending deletion in the working set until its timer
    /// produces the final tombstone. Cold originals are checked against
    /// their exact retained range digests.
    ///
    /// # Errors
    /// Refuses other modes, mismatched room/peer, unavailable or nonarchivable
    /// rows/originals, unordered hashes, and insufficient output. Preparation
    /// never changes Core; the attempted prefix is erased on failure.
    pub fn prepare_graph_page_into<'output>(
        &self,
        room: Room<'id>,
        identity: GraphPageIdentity,
        hashes: &[Hash],
        output: &'output mut [u8],
        read_cold: impl FnMut(ArchiveOriginalRange, &mut [u8]) -> Result<(), Error>,
    ) -> Result<PreparedGraphPageRef<'output>, Error> {
        self.prepare_extended_graph_page(room, identity, None, hashes, output, read_cold)
    }

    pub(super) fn prepare_extended_graph_page<'output>(
        &self,
        room: Room<'id>,
        identity: GraphPageIdentity,
        prior: Option<&CommittedGraphPage<'_, '_>>,
        hashes: &[Hash],
        output: &'output mut [u8],
        read_cold: impl FnMut(ArchiveOriginalRange, &mut [u8]) -> Result<(), Error>,
    ) -> Result<PreparedGraphPageRef<'output>, Error> {
        if self.mode != Mode::Service || self.local_peer.as_ref() != Some(identity.peer.as_bytes())
        {
            return Err(Error::Permission);
        }
        let slot = self.check_room(room)?;
        let room = self.rooms.get(slot)?;
        if identity.room() != &room.key
            || hashes.is_empty()
            || hashes.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(Fault::InvalidInput.into());
        }
        if let Some(prior) = prior {
            let old = prior.identity;
            if old.room != identity.room
                || old.peer != identity.peer
                || old.namespace != identity.namespace
                || old.ordinal != identity.ordinal
                || old.emission >= identity.emission
                || prior.room != slot
                || prior.accepted_through > room.sequence
            {
                return Err(Fault::StaleGeneration.into());
            }
        }
        let count = u8::try_from(hashes.len() + prior.map_or(0, CommittedGraphPage::len))
            .map_err(|_| Fault::Capacity)?;
        u32::try_from(output.len()).map_err(|_| Fault::Capacity)?;
        let mut writer = Encoder::new(PageSink {
            output: SliceSink::new(output),
            read_cold,
        });
        identity.write(&mut writer)?;
        writer.slot(slot)?;
        writer.u64(room.sequence)?;
        writer.u8(count)?;
        let mut next_old = 0;
        for hash in hashes {
            if let Some(prior) = prior {
                while let Some(cell) = prior.index.get(next_old) {
                    match hash_at(prior.bytes, *cell).cmp(hash) {
                        core::cmp::Ordering::Less => {
                            writer.raw(prior.row_bytes(next_old))?;
                            next_old += 1;
                        }
                        core::cmp::Ordering::Equal => return Err(Fault::Conflict.into()),
                        core::cmp::Ordering::Greater => break,
                    }
                }
            }
            let at = room.find_node(hash).ok_or(Fault::NotFound)?;
            let node = room.nodes.get(at)?;
            if node.origin.provenance().room != slot {
                return Err(Fault::Conflict.into());
            }
            if !can_detach(node) {
                return Err(Fault::NotReady.into());
            }
            let row =
                AuthenticatedMessageRow::from_node(&room.key, at, node).ok_or(Fault::NotReady)?;
            row.write(&mut writer, &self.frames)?;
        }
        if let Some(prior) = prior {
            for index in next_old..prior.len() {
                writer.raw(prior.row_bytes(index))?;
            }
        }
        Ok(PreparedGraphPageRef {
            body: writer.finish().output,
        })
    }
}

struct PageSink<'output, R> {
    output: SliceSink<'output>,
    read_cold: R,
}

impl<R: FnMut(ArchiveOriginalRange, &mut [u8]) -> Result<(), Error>> ArchiveSink
    for PageSink<'_, R>
{
    fn append(&mut self, value: &[u8]) -> Result<(), Error> {
        self.output.append(value)
    }

    fn archived_original(
        &mut self,
        _room: &Hash,
        _hash: &Hash,
        range: ArchiveOriginalRange,
    ) -> Result<(), Error> {
        let read = &mut self.read_cold;
        self.output.append_from(range.length(), |bytes| {
            read(range, bytes)?;
            range.verify(bytes)
        })
    }
}
