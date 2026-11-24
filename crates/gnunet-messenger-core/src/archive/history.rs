//! Borrowed, revision-qualified graph facts without a resident message table.

use super::*;
use crate::room_history::{HistoryEntry, HistoryId, HistoryRead};
use core::num::NonZeroU64;

/// Caller-owned index cell for one committed message record. Its two byte
/// offsets grant no capability without their original archive.
#[derive(Clone, Copy)]
pub struct ArchiveHistoryCell {
    pub(super) row: u32,
    pub(super) sequence: u32,
}

impl ArchiveHistoryCell {
    /// Initialize a cell before lending it to [`CommittedRoomHistory`].
    pub const EMPTY: Self = Self {
        row: 0,
        sequence: 0,
    };

    pub(super) fn read_row<'a>(
        &mut self,
        decoder: &mut Decoder<'a>,
        limits: Limits,
        through: u64,
        room: Slot,
    ) -> Result<MessageRecord<'a>, Error> {
        let offset = decoder.position();
        let (row, sequence) = MessageRecord::read_indexed(decoder, limits, through)?;
        if row.provenance.room != room {
            return Err(Fault::Malformed.into());
        }
        *self = Self {
            row: u32::try_from(offset).map_err(|_| Fault::Overflow)?,
            sequence: u32::try_from(sequence).map_err(|_| Fault::Overflow)?,
        };
        Ok(row)
    }
}

/// Stable acceptance order in one room's retained history. The current
/// checkpoint generation, sorted lookup position, and resident slot are all
/// independent of this number. It is comparable within one room's continuing
/// history and does not serve as a global identifier or authorization.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CommittedGraphSequence(NonZeroU64);

impl CommittedGraphSequence {
    /// Return the nonzero acceptance order written to the committed row.
    #[must_use]
    pub const fn get(self) -> NonZeroU64 {
        self.0
    }
}

/// A read-only graph from one exact native checkpoint. This view does not
/// restore original frames, verify peer signatures again, or establish live
/// membership or signing authority. Network and IPC ingress cannot supply
/// the trusted [`CommittedArchive`] boundary.
#[derive(Clone, Copy)]
pub struct CommittedRoomHistory<'archive, 'index> {
    archive: &'archive [u8],
    offsets: &'index [ArchiveHistoryCell],
    detached: &'index [CommittedGraphPage<'archive, 'index>],
    width: usize,
    generation: NonZeroU64,
    coordinates: NonZeroU64,
    historical_peer: Option<ShortHash>,
    room_key: Hash,
    room_position: (usize, u64),
    limits: Limits,
    sequence: u64,
}

/// Only the immutable pages; checkpoints mirror the working room here.
#[derive(Clone, Copy)]
pub(crate) struct DetachedHistory<'view, 'archive, 'index> {
    room: &'view CommittedRoomHistory<'archive, 'index>,
    revision: Option<NonZeroU64>,
}

/// Facts lent to SERVICE after selecting the exact local checkpoint. The
/// archived authentication only describes the signer of these bytes.
pub(crate) struct ArchivedLocalOriginal<'archive> {
    pub(crate) original: crate::graph::CommittedServiceOriginal<'archive>,
    pub(crate) auth: Authentication,
    pub(crate) position: Slot,
    pub(crate) provenance: crate::SourceObservation,
    pub(crate) epoch: Hash,
    pub(crate) sequence: NonZeroU64,
    pub(crate) semantic_applied: bool,
    pub(crate) requested: bool,
}

pub(crate) struct DetachedParent {
    pub(crate) complete: bool,
    pub(crate) epoch: Hash,
}

impl<'archive, 'index> CommittedRoomHistory<'archive, 'index> {
    /// Select one room and index its immutable archived message records. A
    /// single scan reads the existing archive; only the selected room consumes
    /// caller cells. Original frames remain borrowed from the native guard.
    ///
    /// # Errors
    /// Rejects an invalid generation, oversized or malformed archive, and a
    /// selected room with more records than the supplied index can hold.
    pub fn from_committed(
        store: &'archive impl CommittedArchive,
        limits: Limits,
        maximum: usize,
        room: &Hash,
        index: &'index mut [ArchiveHistoryCell],
    ) -> Result<Option<Self>, Error> {
        let archive = store.expose_committed();
        let generation = NonZeroU64::new(store.generation()).ok_or(Fault::InvalidInput)?;
        if archive.len() > maximum || u32::try_from(archive.len()).is_err() {
            return Err(Fault::Capacity.into());
        }
        let mut r = Decoder::new(archive);
        let (peer, signers) = read_header(&mut r, limits)?;
        let contacts = r.size(limits.contacts)?;
        for _ in 0..contacts {
            ContactRecord::read(&mut r, limits)?;
        }
        let rooms = r.size(limits.rooms)?;
        if peer.is_none() && (contacts != 0 || rooms != 0 || !signers.is_empty()) {
            return Err(Fault::Malformed.into());
        }
        let mut found = None;
        for _ in 0..rooms {
            let record = RoomRecord::read(&mut r, limits)?;
            for _ in 0..r.size(limits.sessions_per_room)? {
                SessionRecord::read(&mut r, limits, &record)?;
            }
            let count = r.size(limits.messages_per_room)?;
            if record.key == *room {
                if found.is_some() {
                    return Err(Fault::Conflict.into());
                }
                let offsets = index.get_mut(..count).ok_or(Fault::Capacity)?;
                for cell in offsets.iter_mut() {
                    cell.read_row(&mut r, limits, record.sequence, record.at)?;
                }
                sort_unique(archive, offsets, sequence_at)?;
                sort_unique(archive, offsets, hash_at)?;
                found = Some((count, record.sequence, record.at));
            } else {
                for _ in 0..count {
                    MessageRecord::read(&mut r, limits, record.sequence)?;
                }
            }
            skip_room_tail(&mut r, limits)?;
        }
        r.end()?;
        Ok(found.map(|(count, sequence, at)| Self {
            archive,
            offsets: &index[..count],
            detached: &[],
            width: count,
            generation,
            coordinates: generation,
            historical_peer: peer,
            room_key: *room,
            room_position: (at.index, at.generation),
            limits,
            sequence,
        }))
    }

    /// Extend the exact working checkpoint with pages from its committed
    /// directory. The native owner supplies pages in stable directory order
    /// and changes `coordinates` whenever previously accepted indexes may
    /// move. An added or replaced page has an emission above every page in
    /// the previous directory. A live directory does not remove pages. Empty
    /// working history is valid; working room metadata still binds the pages
    /// to the actual room generation and acceptance cursor.
    ///
    /// # Errors
    /// Refuses foreign pages, pages past the working room's acceptance cursor,
    /// replacing attached pages, duplicate page identities, and repeated hashes
    /// or acceptance sequences across the selected working and detached rows.
    pub fn with_detached_pages(
        mut self,
        namespace: &[u8; 16],
        coordinates: NonZeroU64,
        pages: &'index [CommittedGraphPage<'archive, 'index>],
    ) -> Result<Self, Error> {
        if !self.detached.is_empty() {
            return Err(Fault::Conflict.into());
        }
        let mut width = self.width;
        for (index, page) in pages.iter().enumerate() {
            let id = page.identity();
            if id.namespace() != namespace
                || id.room() != &self.room_key
                || Some(id.peer().as_bytes()) != self.historical_peer.as_ref()
                || page.room_position() != self.room_position
                || page.accepted_through() > self.sequence
            {
                return Err(Fault::StaleGeneration.into());
            }
            let earlier = &pages[..index];
            if earlier.iter().any(|old| old.identity() == id) {
                return Err(Fault::Conflict.into());
            }
            width = width.checked_add(page.len()).ok_or(Fault::Overflow)?;
            for (hash, sequence) in page.index_keys() {
                if find_offset(self.archive, self.offsets, hash).is_some()
                    || self
                        .offsets
                        .iter()
                        .any(|offset| sequence_at(self.archive, *offset) == sequence)
                    || earlier.iter().any(|old| old.contains_key(hash, sequence))
                {
                    return Err(Fault::Conflict.into());
                }
            }
        }
        self.detached = pages;
        self.width = width;
        self.coordinates = coordinates;
        Ok(self)
    }

    /// The native checkpoint's generation. This is diagnostic; callers use
    /// the original storage receipt to select the exact committed image.
    #[must_use]
    pub const fn generation(self) -> NonZeroU64 {
        self.generation
    }

    /// Read the acceptance sequence of an exact message in this checkpoint.
    /// A deleted original keeps its sequence; a row still awaiting publication
    /// has no entry in this view.
    ///
    /// # Errors
    /// Refuses an inconsistent index or a malformed sequence in the image.
    pub fn sequence_for(self, hash: &Hash) -> Result<Option<CommittedGraphSequence>, Error> {
        self.find(hash)
            .map(|index| {
                let sequence =
                    NonZeroU64::new(self.record(index)?.sequence).ok_or(Fault::Malformed)?;
                Ok(CommittedGraphSequence(sequence))
            })
            .transpose()
    }

    pub(crate) const fn room_key(self) -> Hash {
        self.room_key
    }

    pub(crate) const fn room_position(self) -> (usize, u64) {
        self.room_position
    }

    pub(crate) const fn room_sequence(self) -> u64 {
        self.sequence
    }

    pub(crate) const fn historical_peer(self) -> Option<ShortHash> {
        self.historical_peer
    }

    /// Bind detached facts to the room's current incarnation. The native caller
    /// separately pins the exact committed receipt; the live cursor may advance.
    pub(crate) fn check_working_room(
        self,
        room: &RoomRow<'_>,
        at: Slot,
        local_peer: Option<ShortHash>,
    ) -> Result<(), Error> {
        if self.room_key != room.key || self.historical_peer != local_peer {
            return Err(Error::Permission);
        }
        if self.room_position != (at.index, at.generation) || self.sequence > room.sequence {
            return Err(Fault::StaleGeneration.into());
        }
        Ok(())
    }

    pub(crate) fn detached_parent(&self, hash: &Hash) -> Result<Option<DetachedParent>, Error> {
        Ok(self.detached_record(hash)?.map(|row| DetachedParent {
            complete: row.complete,
            epoch: row.epoch,
        }))
    }

    pub(crate) fn detached_history(&self) -> DetachedHistory<'_, 'archive, 'index> {
        // Routine working writes do not move a page. Restarting a walk on
        // every checkpoint could starve it across bounded service turns.
        let revision = self
            .detached
            .iter()
            .map(|page| page.identity().emission())
            .max();
        DetachedHistory {
            room: self,
            revision,
        }
    }

    pub(crate) fn detached_sequence(&self, hash: &Hash) -> Result<Option<u64>, Error> {
        Ok(self.detached_record(hash)?.map(|row| row.sequence))
    }

    // A found target is already deleted or has its authorized mutation
    // staged in the caller's original transaction slot.
    pub(crate) fn stage_detached_deletion(
        &self,
        target: &Hash,
        session: &SessionRow,
        deadline: u64,
        cause: Hash,
        now: u64,
        stage: impl FnOnce(DetachedDeletion) -> Result<(), Error>,
    ) -> Result<bool, Error> {
        for page in self.detached {
            if let Some(index) = page.position(target) {
                if let Some(mutation) = page.plan_deletion(index, session, deadline, cause, now)? {
                    stage(mutation)?;
                }
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The earliest admitted detached DELETE timer from the selected pages.
    /// The native owner combines this with the room's working deadline.
    #[must_use]
    pub fn next_detached_deletion(&self) -> Option<u64> {
        self.detached
            .iter()
            .filter_map(CommittedGraphPage::next_deletion)
            .min()
    }

    /// Plan expiry of at most one elapsed timer from the selected pages. This
    /// reuses the committed DELETE cause without granting membership or replaying
    /// the original semantic handler. The owner pins the exact page receipt.
    ///
    /// # Errors
    /// Refuses an inconsistent committed page or invalid timer row.
    pub fn expire_detached_deletion(&self, now: u64) -> Result<Option<DetachedDeletion>, Error> {
        let earliest = self
            .detached
            .iter()
            .filter_map(|page| page.next_deletion().map(|at| (at, page)))
            .min_by_key(|(at, _)| *at);
        match earliest {
            Some((_, page)) => page.expire_deletion(now),
            None => Ok(None),
        }
    }

    /// Prepare one authorized replacement from its original selected page.
    /// The current native receipt still controls publication and the caller
    /// cannot use a different page carrying the same message hash.
    ///
    /// # Errors
    /// Refuses a stale mutation, an invalid destination, or insufficient output.
    pub fn prepare_detached_deletion<'output>(
        &self,
        deletion: &DetachedDeletion,
        destination: GraphPageIdentity,
        output: &'output mut [u8],
    ) -> Result<PreparedGraphPageRef<'output>, Error> {
        let page = self
            .detached
            .iter()
            .find(|page| *page.identity() == deletion.page())
            .ok_or(Fault::StaleGeneration)?;
        deletion.prepare_into(page, destination, output)
    }

    /// The original signer of an exact detached row, including member
    /// tombstones. This lends no live source or session authority.
    pub(crate) fn detached_signer(
        self,
        hash: &Hash,
    ) -> Result<Option<(wire::envelope::Kind, OriginalSigner)>, Error> {
        self.detached_record(hash)?
            .map(|row| {
                let signer =
                    DetachedKind::of(row.kind)
                        .ok_or(Fault::Malformed)?
                        .signer(Authentication {
                            owner: row.owner,
                            session: row.session,
                            public: row.public,
                            peer: row.peer,
                        })?;
                row.layout.check_signer(row.public, row.peer)?;
                Ok((row.kind, signer))
            })
            .transpose()
    }

    fn detached_record(&self, hash: &Hash) -> Result<Option<MessageRecord<'archive>>, Error> {
        self.find_detached(hash)
            .map(|index| {
                let row = self.detached_at(index)?;
                if row.hash != *hash {
                    return Err(Fault::Conflict.into());
                }
                Ok(row)
            })
            .transpose()
    }

    fn find_detached(&self, hash: &Hash) -> Option<usize> {
        let mut start = 0;
        for page in self.detached {
            if let Some(index) = page.position(hash) {
                return Some(start + index);
            }
            start += page.len();
        }
        None
    }

    /// Lend the original for an authorized leaf from this same history view.
    /// A traversal coordinate is never an independent storage capability.
    pub(crate) fn original(
        self,
        id: HistoryId,
    ) -> Result<Option<crate::graph::CommittedServiceOriginal<'archive>>, Error> {
        if id != HistoryId::new(id.index(), self.coordinates) {
            return Err(Fault::StaleGeneration.into());
        }
        let row = self.record(id.index())?;
        Ok(self.original_from(&row))
    }

    pub(crate) fn local_original(
        self,
        hash: &Hash,
    ) -> Result<Option<ArchivedLocalOriginal<'archive>>, Error> {
        let row = self.record(self.find(hash).ok_or(Fault::NotFound)?)?;
        self.local_original_from(&row)
    }

    pub(crate) fn detached_local_original(
        self,
        hash: &Hash,
    ) -> Result<Option<ArchivedLocalOriginal<'archive>>, Error> {
        match self.detached_record(hash)? {
            Some(row) => self.local_original_from(&row),
            None => Ok(None),
        }
    }

    /// Select one committed original in acceptance order, independent of row
    /// placement. The caller checks delivery rights and request provenance.
    pub(crate) fn next_applied_original(
        self,
        after: u64,
        through: u64,
        mut select: impl FnMut(&ArchivedLocalOriginal<'archive>) -> Result<bool, Error>,
    ) -> Result<Option<ArchivedLocalOriginal<'archive>>, Error> {
        if after >= through {
            return Ok(None);
        }
        let working = (0..self.offsets.len()).map(|index| self.record(index));
        let detached = self
            .detached
            .iter()
            .flat_map(|page| (0..page.len()).map(move |index| page.record(index)));
        let mut next: Option<ArchivedLocalOriginal<'archive>> = None;
        for row in working.chain(detached) {
            let row = row?;
            if after < row.sequence
                && row.sequence <= through
                && next
                    .as_ref()
                    .is_none_or(|item| row.sequence < item.sequence.get())
                && !matches!(row.phase, MessagePhase::Deleted | MessagePhase::Rejected)
                && row.semantic_applied
                && !crate::graph::discourse_kind(row.kind)
                && let Some(original) = self.local_original_from(&row)?
                && select(&original)?
            {
                next = Some(original);
            }
        }
        Ok(next)
    }

    fn local_original_from(
        self,
        row: &MessageRecord<'archive>,
    ) -> Result<Option<ArchivedLocalOriginal<'archive>>, Error> {
        let Some(original) = self.original_from(row) else {
            return Ok(None);
        };
        if crate::graph::discourse_kind(row.kind) {
            return Err(Fault::Malformed.into());
        }
        Ok(Some(ArchivedLocalOriginal {
            original,
            auth: Authentication {
                owner: row.owner,
                session: row.session,
                public: row.public,
                peer: row.peer,
            },
            position: row.at,
            provenance: row.provenance,
            epoch: row.epoch,
            sequence: NonZeroU64::new(row.sequence).ok_or(Fault::Malformed)?,
            semantic_applied: row.semantic_applied,
            requested: row.requested,
        }))
    }

    pub(crate) fn retained_original(
        self,
        range: ArchiveOriginalRange,
    ) -> Result<&'archive [u8], Error> {
        let bytes = range.in_image(self.archive)?;
        range.verify(bytes)?;
        Ok(bytes)
    }

    fn original_from(
        self,
        row: &MessageRecord<'archive>,
    ) -> Option<crate::graph::CommittedServiceOriginal<'archive>> {
        if row.phase == MessagePhase::Rejected {
            return None;
        }
        row.frame
            .map(|(_, bytes)| crate::graph::CommittedServiceOriginal {
                hash: row.hash,
                kind: row.kind,
                layout: row.layout,
                padding: row.padding,
                bytes,
                generation: self.generation,
            })
    }

    fn find(self, hash: &Hash) -> Option<usize> {
        find_offset(self.archive, self.offsets, hash)
            .or_else(|| self.find_detached(hash).map(|at| self.offsets.len() + at))
    }

    fn record(self, index: usize) -> Result<MessageRecord<'archive>, Error> {
        if let Some(offset) = self.offsets.get(index) {
            let mut decoder = Decoder::at(self.archive, offset.row as usize);
            return MessageRecord::read(&mut decoder, self.limits, self.sequence);
        }
        self.detached_at(index - self.offsets.len())
    }

    fn detached_at(&self, mut at: usize) -> Result<MessageRecord<'archive>, Error> {
        for page in self.detached {
            if at < page.len() {
                return page.record(at);
            }
            at -= page.len();
        }
        Err(Fault::Conflict.into())
    }

    /// Whether a strictly earlier finalized vertex is reachable from the
    /// child via finalized records. A deleted payload still supplies its
    /// retained parents. A missing or unfinished vertex cannot prove a path.
    ///
    /// # Errors
    /// Refuses an insufficient traversal workspace or malformed metadata.
    pub fn is_ancestor(
        self,
        ancestor: &Hash,
        child: &Hash,
        workspace: &mut HistoryWorkspace<'_>,
    ) -> Result<bool, Error> {
        if ancestor == child {
            return Ok(false);
        }
        let Some(root) = self.find(child) else {
            return Ok(false);
        };
        let mut walk = workspace.start_history(self, HistoryId::new(root, self.coordinates))?;
        while let Some((_, HistoryEntry::Accepted(facts))) = walk.pop()? {
            if !facts.complete
                || !facts.semantic_applied
                || !facts.epoch_indexed
                || !matches!(facts.phase, MessagePhase::Applied | MessagePhase::Deleted)
            {
                continue;
            }
            if facts.hash == *ancestor {
                return Ok(true);
            }
            for parent in &facts.parents {
                if let Some(id) = walk.locate(parent)? {
                    walk.schedule(id)?;
                }
            }
        }
        Ok(false)
    }
}

impl HistoryRead for CommittedRoomHistory<'_, '_> {
    fn limit(&self) -> usize {
        self.width
    }

    fn coordinate_revision(&self) -> Option<NonZeroU64> {
        Some(self.coordinates)
    }

    fn locate(&mut self, hash: &Hash) -> Result<Option<HistoryId>, Error> {
        Ok(self
            .find(hash)
            .map(|index| HistoryId::new(index, self.coordinates)))
    }

    fn read(&mut self, index: usize) -> Result<(HistoryId, HistoryEntry), Error> {
        let row = self.record(index)?;
        Ok((
            HistoryId::new(index, self.coordinates),
            HistoryEntry::Accepted(row.graph_facts()),
        ))
    }
}

impl HistoryRead for DetachedHistory<'_, '_, '_> {
    fn limit(&self) -> usize {
        self.room.width - self.room.offsets.len()
    }

    fn coordinate_revision(&self) -> Option<NonZeroU64> {
        self.revision
    }

    fn locate(&mut self, hash: &Hash) -> Result<Option<HistoryId>, Error> {
        Ok(self
            .room
            .find_detached(hash)
            .zip(self.revision)
            .map(|(at, generation)| HistoryId::new(at, generation)))
    }

    fn read(&mut self, index: usize) -> Result<(HistoryId, HistoryEntry), Error> {
        Ok((
            HistoryId::new(index, self.revision.ok_or(Fault::Conflict)?),
            HistoryEntry::Accepted(self.room.detached_at(index)?.graph_facts()),
        ))
    }
}

fn find_offset(archive: &[u8], offsets: &[ArchiveHistoryCell], hash: &[u8]) -> Option<usize> {
    offsets
        .binary_search_by(|offset| hash_at(archive, *offset).cmp(hash))
        .ok()
}

pub(super) fn sort_unique<'archive>(
    archive: &'archive [u8],
    offsets: &mut [ArchiveHistoryCell],
    key: impl Fn(&'archive [u8], ArchiveHistoryCell) -> &'archive [u8],
) -> Result<(), Error> {
    offsets.sort_unstable_by(|a, b| key(archive, *a).cmp(key(archive, *b)));
    if offsets
        .windows(2)
        .any(|pair| key(archive, pair[0]) == key(archive, pair[1]))
    {
        return Err(Fault::Conflict.into());
    }
    Ok(())
}

pub(super) fn hash_at(archive: &[u8], offset: ArchiveHistoryCell) -> &[u8] {
    // The decoder checked the row before the private index became visible.
    // The message hash follows its encoded slot (index and generation).
    let start = offset.row as usize + 2 * core::mem::size_of::<u64>();
    &archive[start..start + core::mem::size_of::<Hash>()]
}

pub(super) fn sequence_at(archive: &[u8], offset: ArchiveHistoryCell) -> &[u8] {
    let start = offset.sequence as usize;
    &archive[start..start + core::mem::size_of::<u64>()]
}

fn skip_room_tail(r: &mut Decoder<'_>, limits: Limits) -> Result<(), Error> {
    const HASH_BYTES: usize = core::mem::size_of::<Hash>();
    let frontier = r.size(limits.messages_per_room)?;
    r.raw(frontier.checked_mul(HASH_BYTES).ok_or(Fault::Overflow)?)?;
    let aliases = alias_count(r, limits)?;
    r.raw(aliases.checked_mul(2 * HASH_BYTES).ok_or(Fault::Overflow)?)?;
    for _ in 0..r.size(limits.epochs_per_room)? {
        let record = EpochRecord::read(r, limits)?;
        for _ in 0..record.members {
            r.slot(limits.contacts)?;
        }
        record.finish(r)?;
    }
    no_subscriptions(r, limits)?;
    for _ in 0..r.size(limits.sources_per_room)? {
        let _ = read_peer(r)?;
    }
    Ok(())
}
