//! Exclusive message-history partitions, one per generational room slot.

use crate::{
    Brand, Error, Hash, HistorySlotCell, Limits, MessagePhase, MessageRef, Slot, Source,
    message_index::MessageIndex,
    slot_queue::SlotQueue,
    slots::{Entry, EntryCell, Table},
    state::{FrameStore, Node, RoomRow},
    storage::Backing,
    wire::envelope::Kind,
};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::num::NonZeroU64;
use gnunet_types::Error as Fault;

/// One message table cell in caller-owned room history storage.
pub struct HistoryNodeCell(Entry<Node>);

impl HistoryNodeCell {
    /// An unused message table cell.
    pub const fn empty() -> Self {
        Self(Entry::vacant())
    }
}

impl EntryCell<Node> for HistoryNodeCell {
    fn entry(&self) -> &Entry<Node> {
        &self.0
    }
    fn entry_mut(&mut self) -> &mut Entry<Node> {
        &mut self.0
    }
}

/// Caller-owned message metadata buffers. Each slice must contain exactly
/// `limits.rooms * limits.messages_per_room` cells. Storage is partitioned by
/// room index, so recovery and subsequent room generations use the same cells.
pub struct RoomHistoryStorage<'id> {
    nodes: &'id mut [HistoryNodeCell],
    index: &'id mut [HistorySlotCell],
    ready: &'id mut [HistorySlotCell],
}

impl<'id> RoomHistoryStorage<'id> {
    /// Supply separate message table, sorted index and ready queue buffers.
    pub const fn new(
        nodes: &'id mut [HistoryNodeCell],
        index: &'id mut [HistorySlotCell],
        ready: &'id mut [HistorySlotCell],
    ) -> Self {
        Self {
            nodes,
            index,
            ready,
        }
    }

    pub(crate) fn partitions(self, limits: Limits) -> Result<impl Iterator<Item = Self>, Error> {
        let width = limits.messages_per_room;
        let cells = limits.rooms.checked_mul(width).ok_or(Fault::Overflow)?;
        if width == 0
            || self.nodes.len() != cells
            || self.index.len() != cells
            || self.ready.len() != cells
        {
            return Err(Fault::Capacity.into());
        }
        self.nodes.fill_with(HistoryNodeCell::empty);
        Ok(self
            .nodes
            .chunks_exact_mut(width)
            .zip(self.index.chunks_exact_mut(width))
            .zip(self.ready.chunks_exact_mut(width))
            .map(|((nodes, index), ready)| Self::new(nodes, index, ready)))
    }
}

pub(crate) struct BorrowedNodes<'id>(&'id mut [HistoryNodeCell]);

impl<'id> BorrowedNodes<'id> {
    fn into_clean_cells(mut self) -> &'id mut [HistoryNodeCell] {
        let cells = core::mem::take(&mut self.0);
        cells.fill_with(HistoryNodeCell::empty);
        cells
    }
}

impl AsRef<[HistoryNodeCell]> for BorrowedNodes<'_> {
    fn as_ref(&self) -> &[HistoryNodeCell] {
        self.0
    }
}

impl AsMut<[HistoryNodeCell]> for BorrowedNodes<'_> {
    fn as_mut(&mut self) -> &mut [HistoryNodeCell] {
        self.0
    }
}

impl Drop for BorrowedNodes<'_> {
    fn drop(&mut self) {
        self.0.fill_with(HistoryNodeCell::empty);
    }
}

pub(crate) type HistoryNodes<'id> =
    Table<Node, Backing<HistoryNodeCell, BorrowedNodes<'id>>, HistoryNodeCell>;
pub(crate) type HistoryIndex<'id> = MessageIndex<Backing<Slot, &'id mut [Slot]>>;
pub(crate) type HistoryQueue<'id> = SlotQueue<Backing<Slot, &'id mut [Slot]>>;

pub(crate) struct RoomHistory<'id> {
    pub nodes: HistoryNodes<'id>,
    pub index: HistoryIndex<'id>,
    pub ready: HistoryQueue<'id>,
}

/// A vertex coordinate in one immutable room history revision. Only its
/// reader may resolve it to a working slot or a committed record.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct HistoryId {
    index: usize,
    generation: NonZeroU64,
}

impl HistoryId {
    pub(crate) const fn new(index: usize, generation: NonZeroU64) -> Self {
        Self { index, generation }
    }

    pub(crate) const fn index(self) -> usize {
        self.index
    }

    const fn with_index(self, index: usize) -> Self {
        Self { index, ..self }
    }

    fn from_resident(slot: Slot) -> Result<Self, Error> {
        let generation = NonZeroU64::new(slot.generation).ok_or(Fault::Conflict)?;
        Ok(Self::new(slot.index, generation))
    }

    const fn resident(self) -> Slot {
        Slot {
            index: self.index,
            generation: self.generation.get(),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum HistoryEntry {
    Pending(Hash),
    Accepted(AcceptedFacts),
}

/// Authenticated graph facts, without a work slot or access to original bytes.
#[derive(Clone, Copy)]
pub(crate) struct AcceptedFacts {
    pub hash: Hash,
    pub parents: [Hash; 2],
    pub phase: MessagePhase,
    pub kind: Kind,
    pub sequence: u64,
    pub complete: bool,
    pub semantic_applied: bool,
    pub epoch_indexed: bool,
    pub has_original: bool,
}

/// One immutable and integrity-checked room directory, whether supplied by
/// resident state or a committed image. Reading may use caller-owned scratch
/// or native I/O, but must not change the selected revision during a walk.
pub(crate) trait HistoryRead {
    /// Exclusive upper bound on logical indices in this revision.
    fn limit(&self) -> usize;
    /// Version of the index mapping for resumable walks. `None` means
    /// accepted positions cannot be moved or reused during the room lifetime.
    /// A mutable directory changes its version before any accepted index can
    /// be reassigned, including promotion from a working slot to a page.
    fn coordinate_revision(&self) -> Option<NonZeroU64>;
    fn locate(&mut self, hash: &Hash) -> Result<Option<HistoryId>, Error>;
    /// Resolve an index previously returned by `locate`. Facts and identity
    /// are returned together, so committed metadata only needs one fetch.
    fn read(&mut self, index: usize) -> Result<(HistoryId, HistoryEntry), Error>;

    fn get(&mut self, hash: &Hash) -> Result<Option<(HistoryId, HistoryEntry)>, Error> {
        let Some(id) = self.locate(hash)? else {
            return Ok(None);
        };
        let (resolved, entry) = self.read(id.index())?;
        if id != resolved {
            return Err(Fault::StaleGeneration.into());
        }
        let actual = match &entry {
            HistoryEntry::Pending(hash) => hash,
            HistoryEntry::Accepted(facts) => &facts.hash,
        };
        if actual != hash {
            return Err(Fault::Conflict.into());
        }
        Ok(Some((id, entry)))
    }
}

/// ID relative to its original reader, before composing graph coordinates.
pub(crate) enum HistoryLocation {
    Resident(HistoryId),
    Committed(HistoryId),
}

/// Read current room observations first and consult the exact committed room
/// only on a miss. A resident tombstone or pending observation also shadows
/// its historical twin. The two index ranges cannot share workspace marks.
#[derive(Clone, Copy)]
pub(crate) struct LayeredHistory<L, C> {
    resident: L,
    committed: Option<C>,
    resident_width: usize,
    width: usize,
}

impl<L: HistoryRead, C: HistoryRead> LayeredHistory<L, C> {
    pub(crate) fn new(resident: L, committed: Option<C>) -> Result<Self, Error> {
        // The committed directory owns relocation for the combined view.
        // The resident reader cannot independently renumber its indices.
        if resident.coordinate_revision().is_some() {
            return Err(Fault::InvalidInput.into());
        }
        let resident_width = resident.limit();
        let width = resident_width
            .checked_add(committed.as_ref().map_or(0, HistoryRead::limit))
            .ok_or(Fault::Overflow)?;
        Ok(Self {
            resident,
            committed,
            resident_width,
            width,
        })
    }

    pub(crate) fn location(&self, id: HistoryId) -> Result<HistoryLocation, Error> {
        if id.index() >= self.width {
            return Err(Fault::Conflict.into());
        }
        Ok(match id.index().checked_sub(self.resident_width) {
            None => HistoryLocation::Resident(id),
            Some(index) => HistoryLocation::Committed(id.with_index(index)),
        })
    }

    fn rebase(&self, id: HistoryId) -> Result<HistoryId, Error> {
        let index = self
            .resident_width
            .checked_add(id.index())
            .filter(|index| *index < self.width)
            .ok_or(Fault::Conflict)?;
        Ok(id.with_index(index))
    }
}

impl<L: HistoryRead, C: HistoryRead> HistoryRead for LayeredHistory<L, C> {
    fn limit(&self) -> usize {
        self.width
    }

    fn coordinate_revision(&self) -> Option<NonZeroU64> {
        self.committed
            .as_ref()
            .and_then(HistoryRead::coordinate_revision)
    }

    fn locate(&mut self, hash: &Hash) -> Result<Option<HistoryId>, Error> {
        if let Some(id) = self.resident.locate(hash)? {
            if id.index() >= self.resident_width {
                return Err(Fault::Conflict.into());
            }
            return Ok(Some(id));
        }
        let Some(committed) = &mut self.committed else {
            return Ok(None);
        };
        committed
            .locate(hash)?
            .map(|id| self.rebase(id))
            .transpose()
    }

    fn read(&mut self, index: usize) -> Result<(HistoryId, HistoryEntry), Error> {
        if index >= self.width {
            return Err(Fault::Conflict.into());
        }
        let (id, entry) = if let Some(at) = index.checked_sub(self.resident_width) {
            let (id, entry) = self.committed.as_mut().ok_or(Fault::Conflict)?.read(at)?;
            (self.rebase(id)?, entry)
        } else {
            self.resident.read(index)?
        };
        if id.index() != index {
            return Err(Fault::Conflict.into());
        }
        Ok((id, entry))
    }
}

/// Immutable directory of working records without a borrow of unrelated
/// room state. Bounded graph work can hold this directory and its separate
/// cursor at the same time.
#[derive(Clone, Copy)]
pub(crate) struct HistorySnapshot<'room, 'id> {
    nodes: &'room HistoryNodes<'id>,
    index: &'room HistoryIndex<'id>,
}

impl<'room, 'id> HistorySnapshot<'room, 'id> {
    pub(crate) const fn new(
        nodes: &'room HistoryNodes<'id>,
        index: &'room HistoryIndex<'id>,
    ) -> Self {
        Self { nodes, index }
    }

    fn id_at(self, index: usize) -> Result<HistoryId, Error> {
        let slot = self.nodes.slot_at(index).ok_or(Fault::Conflict)?;
        HistoryId::from_resident(slot)
    }

    fn entry(self, id: HistoryId) -> Result<HistoryEntry, Error> {
        let node = self.nodes.get(id.resident())?;
        if node.auth.is_none() {
            return Ok(HistoryEntry::Pending(node.hash));
        }
        Ok(HistoryEntry::Accepted(AcceptedFacts {
            hash: node.hash,
            parents: node.parents,
            phase: node.phase,
            kind: node.kind,
            sequence: node.sequence,
            complete: node.complete,
            semantic_applied: node.semantic_applied,
            epoch_indexed: node.epoch_indexed,
            has_original: node.has_original(),
        }))
    }
}

impl HistoryRead for HistorySnapshot<'_, '_> {
    fn limit(&self) -> usize {
        self.nodes.limit()
    }

    fn coordinate_revision(&self) -> Option<NonZeroU64> {
        None
    }

    fn locate(&mut self, hash: &Hash) -> Result<Option<HistoryId>, Error> {
        self.index
            .find(hash, |slot| self.nodes.get(slot).map(|node| &node.hash))
            .map(HistoryId::from_resident)
            .transpose()
    }

    fn read(&mut self, index: usize) -> Result<(HistoryId, HistoryEntry), Error> {
        let id = self.id_at(index)?;
        Ok((id, self.entry(id)?))
    }
}

impl<'id> RoomHistory<'id> {
    #[cfg(feature = "alloc")]
    pub fn owned(count: usize) -> Result<Self, Error> {
        fn reserve<T>(count: usize) -> Result<Vec<T>, Error> {
            let mut cells = Vec::new();
            cells
                .try_reserve_exact(count)
                .map_err(|_| Fault::Capacity)?;
            Ok(cells)
        }
        fn slots(count: usize) -> Result<Vec<Slot>, Error> {
            let mut cells = reserve(count)?;
            cells.resize(cells.capacity(), Slot::empty());
            Ok(cells)
        }
        let mut nodes = reserve(count)?;
        nodes.resize_with(count, HistoryNodeCell::empty);
        Ok(Self {
            nodes: Table::start(Backing::Owned(nodes)),
            index: MessageIndex::in_storage(Backing::Owned(slots(count)?)),
            ready: SlotQueue::in_storage(Backing::Owned(slots(count)?)),
        })
    }

    pub(crate) fn fixed(storage: RoomHistoryStorage<'id>) -> Self {
        Self {
            nodes: Table::start(Backing::fixed(BorrowedNodes(storage.nodes))),
            index: MessageIndex::in_storage(Backing::fixed(storage.index)),
            ready: SlotQueue::in_storage(Backing::fixed(storage.ready)),
        }
    }

    pub fn into_fixed(self) -> Option<RoomHistoryStorage<'id>> {
        Some(RoomHistoryStorage::new(
            self.nodes.into_storage().into_fixed()?.into_clean_cells(),
            self.index.into_storage().into_fixed()?,
            self.ready.into_storage().into_fixed()?,
        ))
    }
}

pub(crate) struct UnverifiedInputs<'room, 'id> {
    room: &'room mut RoomRow<'id>,
    source: Source<'id>,
    charge: usize,
}

impl<'id> RoomRow<'id> {
    pub(crate) const fn history_snapshot(&self) -> HistorySnapshot<'_, 'id> {
        HistorySnapshot::new(&self.nodes, &self.index)
    }

    /// Adapt a selected working coordinate after applying history rights.
    pub(crate) fn history_message<'room>(
        &'room self,
        id: HistoryId,
        frames: &'room FrameStore<'id>,
        brand: Brand<'id>,
    ) -> Result<MessageRef<'room, 'id>, Error> {
        let node = self.nodes.get(id.resident())?;
        if node.auth.is_none() {
            return Err(Fault::NotReady.into());
        }
        MessageRef::new(node, self, frames, brand)
    }

    /// Check frame custody and the absence of published graph facts before
    /// clearing observations and returning unused history slots.
    pub(crate) fn unverified_inputs(
        &mut self,
        source: Source<'id>,
        frames: &FrameStore<'id>,
    ) -> Result<Option<UnverifiedInputs<'_, 'id>>, Error> {
        let mut charge: Option<usize> = None;
        for (_, node) in self.nodes.iter() {
            if !unverified_from(node, source) {
                continue;
            }
            if node.sequence != 0
                || node.frontier_applied
                || node.semantic_applied
                || node.complete
                || node.phase == MessagePhase::Deleted
            {
                return Err(Fault::Conflict.into());
            }
            node.original(frames)?;
            charge = Some(
                charge
                    .unwrap_or_default()
                    .checked_add(node.payload_bytes())
                    .ok_or(Fault::Overflow)?,
            );
        }
        Ok(charge.map(|charge| UnverifiedInputs {
            room: self,
            source,
            charge,
        }))
    }
}

impl<'id> UnverifiedInputs<'_, 'id> {
    pub(crate) const fn charge(&self) -> usize {
        self.charge
    }

    pub(crate) fn contains(&self, hash: &Hash) -> bool {
        self.room
            .find_node(hash)
            .and_then(|slot| self.room.nodes.get(slot).ok())
            .is_some_and(|node| unverified_from(node, self.source))
    }

    pub(crate) fn reclaim(self, frames: &mut FrameStore<'id>) -> Result<(), Error> {
        // Compact each list once while every exact generation can still be
        // resolved. Authenticated nodes, including deleted and rejected ones,
        // keep their positions in the graph independently of their source.
        let Self { room, source, .. } = self;
        let nodes = &room.nodes;
        let keep = |slot| {
            !nodes
                .get(slot)
                .is_ok_and(|node| unverified_from(node, source))
        };
        room.index.retain(keep);
        room.ready.retain(keep);
        for index in 0..room.nodes.limit() {
            if let Some(slot) = room.nodes.slot_at(index)
                && room
                    .nodes
                    .get(slot)
                    .is_ok_and(|node| unverified_from(node, source))
            {
                let node = room.nodes.remove(slot)?;
                if let Some(frame) = node.frame {
                    frames.remove(frame)?;
                }
            }
        }
        Ok(())
    }
}

fn unverified_from(node: &Node, source: Source<'_>) -> bool {
    node.auth.is_none() && node.origin.live(source.core) == Some(source)
}
