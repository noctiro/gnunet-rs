//! Bounded per-room frontier, peer and completion state.

#[cfg(feature = "alloc")]
use crate::state::RecipientKey;
use crate::{
    Error, Hash, HistoryCell, HistorySlotCell, Limits, ServiceConnection, ShortHash, Slot,
    graph::completion::Completion,
    state::{PeerAnnouncement, PeerRow},
    storage::Backing,
};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::{iter::Map, mem::size_of, ops::Deref, slice};
use gnunet_types::Error as Fault;

/// One caller-owned cell for a room's observed peers.
pub struct RoomPeerCell(PeerRow);

impl RoomPeerCell {
    /// An unused peer cell.
    pub const fn empty() -> Self {
        Self(PeerRow::candidate([0; 32]))
    }

    fn row(&self) -> &PeerRow {
        &self.0
    }
}

/// Disjoint storage for service room frontiers, peer lists, completion marks
/// and completion queues, partitioned in room-index order.
pub struct RoomQueueStorage<'id> {
    frontier: &'id mut [Hash],
    peers: &'id mut [RoomPeerCell],
    completion_marks: &'id mut [HistoryCell],
    completion_queue: &'id mut [HistorySlotCell],
}

impl<'id> RoomQueueStorage<'id> {
    /// Supply each backing slice independently. For each room, the frontier
    /// gets one cell per working message, peers one per source, and the FIFO
    /// one per session. Completion marks divide evenly among rooms and each
    /// partition must fit the working messages and any detached history used
    /// for completion.
    pub const fn new(
        frontier: &'id mut [Hash],
        peers: &'id mut [RoomPeerCell],
        completion_marks: &'id mut [HistoryCell],
        completion_queue: &'id mut [HistorySlotCell],
    ) -> Self {
        Self {
            frontier,
            peers,
            completion_marks,
            completion_queue,
        }
    }

    pub(crate) fn partitions(self, limits: Limits) -> Result<impl Iterator<Item = Self>, Error> {
        let messages = limits.messages_per_room;
        let sources = limits.sources_per_room;
        let sessions = limits.sessions_per_room;
        let check = |width: usize, count: usize| -> Result<(), Error> {
            let expected = limits.rooms.checked_mul(width).ok_or(Fault::Overflow)?;
            if width == 0 || count != expected {
                return Err(Fault::Capacity.into());
            }
            Ok(())
        };
        check(messages, self.frontier.len())?;
        check(sources, self.peers.len())?;
        let marks = self
            .completion_marks
            .len()
            .checked_div(limits.rooms)
            .ok_or(Fault::Capacity)?;
        if marks < messages || !self.completion_marks.len().is_multiple_of(limits.rooms) {
            return Err(Fault::Capacity.into());
        }
        check(sessions, self.completion_queue.len())?;
        Ok(self
            .frontier
            .chunks_exact_mut(messages)
            .zip(self.peers.chunks_exact_mut(sources))
            .zip(self.completion_marks.chunks_exact_mut(marks))
            .zip(self.completion_queue.chunks_exact_mut(sessions))
            .map(|(((frontier, peers), marks), queue)| Self::new(frontier, peers, marks, queue)))
    }

    pub(crate) const fn completion_capacity(&self) -> usize {
        self.completion_marks.len()
    }
}

pub(crate) struct RoomQueues<'id> {
    pub frontier: BoundedList<'id, Hash>,
    pub peers: RoomPeers<'id>,
    #[cfg(feature = "alloc")]
    pub hpke_keys: RecipientKeys,
    pub completion: Completion<'id>,
}

impl<'id> RoomQueues<'id> {
    #[cfg(feature = "alloc")]
    pub(crate) fn owned(limits: Limits) -> Result<Self, Error> {
        Ok(Self {
            frontier: BoundedList::owned(limits.messages_per_room)?,
            peers: RoomPeers(BoundedList::owned(limits.sources_per_room)?),
            hpke_keys: RecipientKeys::owned(limits.sessions_per_room)?,
            completion: Completion::owned(limits.messages_per_room, limits.sessions_per_room)?,
        })
    }

    pub(crate) fn fixed(storage: RoomQueueStorage<'id>) -> Self {
        Self {
            frontier: BoundedList::fixed(storage.frontier),
            peers: RoomPeers(BoundedList::fixed(storage.peers)),
            #[cfg(feature = "alloc")]
            hpke_keys: RecipientKeys::default(),
            completion: Completion::fixed(storage.completion_marks, storage.completion_queue),
        }
    }

    pub(crate) fn into_fixed(self) -> Option<RoomQueueStorage<'id>> {
        let (marks, pending) = self.completion.into_fixed()?;
        Some(RoomQueueStorage::new(
            self.frontier.storage.into_fixed()?,
            self.peers.0.storage.into_fixed()?,
            marks,
            pending,
        ))
    }

    pub(crate) fn has_recipient_keys(&self) -> bool {
        #[cfg(feature = "alloc")]
        let present = !self.hpke_keys.cells.is_empty();
        #[cfg(not(feature = "alloc"))]
        let present = false;
        present
    }

    pub(crate) fn required_bytes(
        limits: Limits,
        fixed_marks: Option<usize>,
    ) -> Result<usize, Error> {
        let bytes = Self::bytes_for([
            limits.messages_per_room,
            limits.sources_per_room,
            fixed_marks.unwrap_or(limits.messages_per_room),
            limits.sessions_per_room,
        ])?;
        #[cfg(feature = "alloc")]
        let bytes = if fixed_marks.is_some() {
            bytes
        } else {
            bytes
                .checked_add(RecipientKeys::bytes_for(limits.sessions_per_room)?)
                .ok_or(Fault::Overflow)?
        };
        Ok(bytes)
    }

    pub(crate) fn bytes(&self) -> Result<usize, Error> {
        let [marks, pending] = self.completion.capacities();
        let bytes = Self::bytes_for([
            self.frontier.storage.capacity(),
            self.peers.0.storage.capacity(),
            marks,
            pending,
        ])?;
        #[cfg(feature = "alloc")]
        let bytes = bytes
            .checked_add(RecipientKeys::bytes_for(self.hpke_keys.cells.capacity())?)
            .ok_or(Fault::Overflow)?;
        Ok(bytes)
    }

    fn bytes_for(counts: [usize; 4]) -> Result<usize, Error> {
        [
            size_of::<Hash>(),
            size_of::<RoomPeerCell>(),
            size_of::<HistoryCell>(),
            size_of::<Slot>(),
        ]
        .into_iter()
        .zip(counts)
        .try_fold(0usize, |total, (width, count)| {
            let bytes = width.checked_mul(count).ok_or(Fault::Overflow)?;
            total
                .checked_add(bytes)
                .ok_or_else(|| Fault::Overflow.into())
        })
    }
}

#[cfg(feature = "alloc")]
fn reserve<T>(count: usize) -> Result<Vec<T>, Error> {
    let mut cells = Vec::new();
    cells
        .try_reserve_exact(count)
        .map_err(|_| Fault::Capacity)?;
    Ok(cells)
}

pub(crate) type BoundedList<'id, T> = List<T, &'id mut [T]>;

pub(crate) struct List<T, B> {
    storage: Backing<T, B>,
    limit: usize,
    fixed_len: usize,
}

impl<T, B: AsRef<[T]> + AsMut<[T]>> List<T, B> {
    #[cfg(feature = "alloc")]
    fn owned(count: usize) -> Result<Self, Error> {
        Ok(Self {
            storage: Backing::Owned(reserve(count)?),
            limit: count,
            fixed_len: 0,
        })
    }

    fn fixed(cells: B) -> Self {
        let limit = cells.as_ref().len();
        Self {
            storage: Backing::fixed(cells),
            limit,
            fixed_len: 0,
        }
    }

    fn length(&self) -> usize {
        match &self.storage {
            #[cfg(feature = "alloc")]
            Backing::Owned(cells) => cells.len(),
            Backing::Fixed(..) => self.fixed_len,
        }
    }

    pub(crate) fn as_slice(&self) -> &[T] {
        &self.storage.as_ref()[..self.length()]
    }

    fn as_mut_slice(&mut self) -> &mut [T] {
        let len = self.length();
        &mut self.storage.as_mut()[..len]
    }

    pub(crate) fn push(&mut self, value: T) -> Result<(), Error> {
        if self.length() == self.limit {
            return Err(Fault::Capacity.into());
        }
        match &mut self.storage {
            // The full logical limit was reserved at construction.
            #[cfg(feature = "alloc")]
            Backing::Owned(cells) => cells.push(value),
            Backing::Fixed(cells, _) => {
                cells.as_mut()[self.fixed_len] = value;
                self.fixed_len += 1;
            }
        }
        Ok(())
    }

    #[cfg(feature = "alloc")]
    pub(crate) fn swap_remove(&mut self, index: usize) -> Result<(), Error> {
        if index >= self.length() {
            return Err(Fault::NotFound.into());
        }
        self.remove_at(index);
        Ok(())
    }

    fn remove_at(&mut self, index: usize) {
        match &mut self.storage {
            #[cfg(feature = "alloc")]
            Backing::Owned(cells) => {
                cells.swap_remove(index);
            }
            Backing::Fixed(cells, _) => {
                self.fixed_len -= 1;
                cells.as_mut().swap(index, self.fixed_len);
            }
        }
    }
}

impl<T: Copy, B: AsRef<[T]> + AsMut<[T]>> List<T, B> {
    #[cfg(feature = "alloc")]
    pub(crate) fn clear(&mut self) {
        match &mut self.storage {
            #[cfg(feature = "alloc")]
            Backing::Owned(cells) => cells.clear(),
            Backing::Fixed(..) => self.fixed_len = 0,
        }
    }

    pub(crate) fn retain(&mut self, mut retain: impl FnMut(&T) -> bool) {
        match &mut self.storage {
            #[cfg(feature = "alloc")]
            Backing::Owned(cells) => cells.retain(retain),
            Backing::Fixed(cells, _) => {
                let cells = &mut cells.as_mut()[..self.fixed_len];
                let mut kept = 0;
                for index in 0..cells.len() {
                    if retain(&cells[index]) {
                        cells[kept] = cells[index];
                        kept += 1;
                    }
                }
                self.fixed_len = kept;
            }
        }
    }
}

impl<T, B: AsRef<[T]> + AsMut<[T]>> Deref for List<T, B> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<'a, T, B: AsRef<[T]> + AsMut<[T]>> IntoIterator for &'a List<T, B> {
    type Item = &'a T;
    type IntoIter = slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

pub(crate) struct RoomPeers<'id>(BoundedList<'id, RoomPeerCell>);

type PeerIter<'a> = Map<slice::Iter<'a, RoomPeerCell>, fn(&'a RoomPeerCell) -> &'a PeerRow>;
type PeerIterMut<'a> =
    Map<slice::IterMut<'a, RoomPeerCell>, fn(&'a mut RoomPeerCell) -> &'a mut PeerRow>;

impl RoomPeers<'_> {
    pub(crate) fn len(&self) -> usize {
        self.0.length()
    }

    #[cfg(all(test, feature = "alloc"))]
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn iter(&self) -> PeerIter<'_> {
        self.into_iter()
    }

    pub(crate) fn announcement(&self, peer: &ShortHash) -> Option<&PeerAnnouncement> {
        self.iter()
            .find(|row| &row.peer == peer)
            .and_then(PeerRow::announcement)
    }

    fn iter_mut(&mut self) -> PeerIterMut<'_> {
        self.0.as_mut_slice().iter_mut().map(|cell| &mut cell.0)
    }

    pub(crate) fn push(&mut self, peer: PeerRow) -> Result<(), Error> {
        self.0.push(RoomPeerCell(peer))
    }

    pub(crate) fn announce(
        &mut self,
        peer: ShortHash,
        announcement: PeerAnnouncement,
    ) -> Result<(), Error> {
        if let Some(row) = self.iter_mut().find(|row| row.peer == peer) {
            row.announce(announcement);
            return Ok(());
        }
        let mut row = PeerRow::candidate(peer);
        row.announce(announcement);
        self.push(row)
    }

    pub(crate) fn remove(&mut self, peer: &ShortHash) {
        let index = self.iter().position(|row| &row.peer == peer);
        if let Some(index) = index {
            self.0.remove_at(index);
        }
    }

    pub(crate) fn record_connection(&mut self, peer: &ShortHash, connection: ServiceConnection) {
        if let Some(row) = self.iter_mut().find(|row| &row.peer == peer) {
            row.record_connection(connection);
        }
    }
}

impl<'a> IntoIterator for &'a RoomPeers<'_> {
    type Item = &'a PeerRow;
    type IntoIter = PeerIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.as_slice().iter().map(RoomPeerCell::row)
    }
}

#[cfg(feature = "alloc")]
#[derive(Default)]
pub(crate) struct RecipientKeys {
    cells: Vec<RecipientKey>,
    limit: usize,
}

#[cfg(feature = "alloc")]
impl RecipientKeys {
    fn owned(limit: usize) -> Result<Self, Error> {
        Ok(Self {
            cells: reserve(limit)?,
            limit,
        })
    }

    fn bytes_for(count: usize) -> Result<usize, Error> {
        count
            .checked_mul(size_of::<RecipientKey>())
            .ok_or_else(|| Fault::Overflow.into())
    }

    pub(crate) fn iter(&self) -> slice::Iter<'_, RecipientKey> {
        self.cells.iter()
    }

    pub(crate) fn get_mut(&mut self, index: usize) -> Option<&mut RecipientKey> {
        self.cells.get_mut(index)
    }

    pub(crate) fn push(&mut self, key: RecipientKey) -> Result<(), Error> {
        if self.cells.len() == self.limit {
            return Err(Fault::Capacity.into());
        }
        self.cells.push(key);
        Ok(())
    }
}

#[cfg(feature = "alloc")]
impl<'a> IntoIterator for &'a RecipientKeys {
    type Item = &'a RecipientKey;
    type IntoIter = slice::Iter<'a, RecipientKey>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
