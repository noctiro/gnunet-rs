//! Index exact retained frame bytes while writing their owning checkpoint.

use super::{
    ArchiveSink, Core, Error, Fault, Hash, Mode, Node, RetainedFrame, Selection, SliceSink,
};
use gnunet_crypto::hash256;

/// The exact original bytes at one position in the prepared archive. The
/// digest covers the whole frame, including its signature and outer padding.
/// This location grants no signature, membership or storage authority.
#[derive(Clone, Copy)]
pub struct ArchiveOriginalRange {
    offset: usize,
    length: usize,
    digest: [u8; 32],
}

impl ArchiveOriginalRange {
    pub(super) fn at(offset: usize, value: &[u8]) -> Self {
        Self {
            offset,
            length: value.len(),
            digest: hash256(value),
        }
    }

    /// Byte offset within the archive body, excluding any medium envelope.
    pub const fn offset(self) -> usize {
        self.offset
    }

    /// Exact original frame length.
    pub const fn length(self) -> usize {
        self.length
    }

    /// SHA-256 commitment to every exact stored byte of this original.
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }

    pub(super) fn verify(self, bytes: &[u8]) -> Result<(), Error> {
        if self.length != bytes.len() || self.digest != hash256(bytes) {
            return Err(Fault::Authentication.into());
        }
        Ok(())
    }

    pub(super) fn same_bytes(self, other: Self) -> bool {
        self.length == other.length && self.digest == other.digest
    }

    pub(super) fn in_image(self, archive: &[u8]) -> Result<&[u8], Error> {
        let end = self
            .offset
            .checked_add(self.length)
            .ok_or(Fault::Malformed)?;
        archive
            .get(self.offset..end)
            .ok_or_else(|| Fault::Malformed.into())
    }
}

struct Original {
    room: Hash,
    hash: Hash,
    range: ArchiveOriginalRange,
}

/// Caller-owned cell for one retained original in a bounded archive index.
pub struct ArchiveOriginalCell(Option<Original>);

impl ArchiveOriginalCell {
    /// An unused archive index cell.
    pub const EMPTY: Self = Self(None);
}

/// Exact ranges in one prepared or recovered archive. The caller must keep the
/// index paired with the corresponding storage receipt when resolving a range.
pub struct ArchiveOriginals<'index> {
    cells: &'index mut [ArchiveOriginalCell],
    count: usize,
}

impl<'index> ArchiveOriginals<'index> {
    /// Initialize an index in caller-owned memory.
    pub fn new(cells: &'index mut [ArchiveOriginalCell]) -> Self {
        cells.fill_with(|| ArchiveOriginalCell::EMPTY);
        Self { cells, count: 0 }
    }

    pub(super) fn insert(
        &mut self,
        room: Hash,
        hash: Hash,
        offset: usize,
        value: &[u8],
    ) -> Result<(), Error> {
        self.insert_range(room, hash, ArchiveOriginalRange::at(offset, value))
    }

    fn insert_range(
        &mut self,
        room: Hash,
        hash: Hash,
        range: ArchiveOriginalRange,
    ) -> Result<(), Error> {
        let slot = self.cells.get_mut(self.count).ok_or(Fault::Capacity)?;
        *slot = ArchiveOriginalCell(Some(Original { room, hash, range }));
        self.count += 1;
        Ok(())
    }

    #[cfg(all(test, feature = "alloc"))]
    pub(super) fn get(&self, room: &Hash, hash: &Hash) -> Option<ArchiveOriginalRange> {
        self.cells[..self.count].iter().find_map(|cell| {
            let original = cell.0.as_ref()?;
            (original.room == *room && original.hash == *hash).then_some(original.range)
        })
    }

    /// Clear all currently indexed locations.
    pub fn clear(&mut self) {
        self.cells[..self.count].fill_with(|| ArchiveOriginalCell::EMPTY);
        self.count = 0;
    }
}

impl Drop for ArchiveOriginals<'_> {
    fn drop(&mut self) {
        self.clear();
    }
}

impl<const ROOMS: usize> Core<'_, ROOMS> {
    /// Install the exact ranges from the just-confirmed checkpoint. Eligible
    /// frames release their resident custody; previously cold frames move to
    /// the next committed image without claiming live authority.
    ///
    /// The original storage owner must confirm publication of the image used
    /// to build `originals` before calling this method and before permitting
    /// another Core transition. The prepared index alone proves no commit.
    ///
    /// # Errors
    /// Rejects an index that disagrees with the current originals or a broken
    /// custody invariant. A storage owner must retire the Core if settlement
    /// fails after an actual commit.
    pub fn settle_paged_archive(&mut self, originals: &ArchiveOriginals<'_>) -> Result<(), Error> {
        self.settle_projected_archive(originals, None)
    }

    pub(super) fn settle_projected_archive(
        &mut self,
        originals: &ArchiveOriginals<'_>,
        selection: Option<Selection<'_>>,
    ) -> Result<(), Error> {
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        let mut entries = originals.cells[..originals.count].iter();
        let mut released = 0usize;
        for (at, room) in self.rooms.iter() {
            for (_, node) in room.nodes.iter() {
                if selection.is_some_and(|selection| selection.contains(at, &node.hash)) {
                    continue;
                }
                let Some(next) = next_range(&mut entries, &room.key, node)? else {
                    continue;
                };
                if !node.can_archive_original() {
                    if node.archived_original().is_some() {
                        return Err(Fault::Conflict.into());
                    }
                    continue;
                }
                if let Some(previous) = node.archived_original() {
                    if !previous.same_bytes(next) {
                        return Err(Fault::Authentication.into());
                    }
                } else {
                    let frame = node.frame.as_ref().ok_or(Fault::Conflict)?;
                    next.verify(self.frames.expose(frame)?)?;
                    released = released
                        .checked_add(frame.capacity())
                        .ok_or(Fault::Overflow)?;
                }
            }
        }
        if entries.next().is_some() {
            return Err(Fault::Conflict.into());
        }
        let used = self.used.checked_sub(released).ok_or(Fault::Conflict)?;

        let mut entries = originals.cells[..originals.count].iter();
        for (at, room) in self.rooms.iter_mut() {
            for (_, node) in room.nodes.iter_mut() {
                if selection.is_some_and(|selection| selection.contains(at, &node.hash)) {
                    continue;
                }
                let Some(next) = next_range(&mut entries, &room.key, node)? else {
                    continue;
                };
                if node.can_archive_original() {
                    let previous = node.frame.replace(RetainedFrame::Archived(next));
                    self.frames.remove(previous.ok_or(Fault::Conflict)?)?;
                }
            }
        }
        self.used = used;
        Ok(())
    }
}

fn next_range<'cell>(
    entries: &mut impl Iterator<Item = &'cell ArchiveOriginalCell>,
    room: &Hash,
    node: &Node,
) -> Result<Option<ArchiveOriginalRange>, Error> {
    if node.auth.is_none() || !node.has_original() || crate::graph::discourse_kind(node.kind) {
        return Ok(None);
    }
    let entry = entries
        .next()
        .and_then(|cell| cell.0.as_ref())
        .ok_or(Fault::Conflict)?;
    if entry.room != *room || entry.hash != node.hash {
        return Err(Fault::Conflict.into());
    }
    Ok(Some(entry.range))
}

pub(super) struct IndexedSink<'output, 'borrow, 'index, R> {
    output: SliceSink<'output>,
    originals: &'borrow mut ArchiveOriginals<'index>,
    read: R,
}

impl<'output, 'borrow, 'index, R> IndexedSink<'output, 'borrow, 'index, R> {
    pub fn new(
        output: &'output mut [u8],
        originals: &'borrow mut ArchiveOriginals<'index>,
        read: R,
    ) -> Self {
        Self {
            output: SliceSink::new(output),
            originals,
            read,
        }
    }

    pub fn finish(self) -> SliceSink<'output> {
        self.output
    }
}

impl<R: FnMut(ArchiveOriginalRange, &mut [u8]) -> Result<(), Error>> ArchiveSink
    for IndexedSink<'_, '_, '_, R>
{
    fn append(&mut self, value: &[u8]) -> Result<(), Error> {
        self.output.append(value)
    }

    fn original(&mut self, room: &Hash, hash: &Hash, value: &[u8]) -> Result<(), Error> {
        let offset = self.output.position();
        self.output.append(value)?;
        self.originals.insert(*room, *hash, offset, value)
    }

    fn archived_original(
        &mut self,
        room: &Hash,
        hash: &Hash,
        mut range: ArchiveOriginalRange,
    ) -> Result<(), Error> {
        let offset = self.output.position();
        let read = &mut self.read;
        self.output.append_from(range.length, |bytes| {
            read(range, bytes)?;
            range.verify(bytes)
        })?;
        range.offset = offset;
        self.originals.insert_range(*room, *hash, range)
    }
}
