//! Recovery view joining working slots with the exact selected durable pages.

use super::super::{CommittedGraphPage, MessageRecord};
use crate::{Error, Hash, room_storage::RoomDirectory, state::RoomRow};
use gnunet_types::Error as Fault;

/// The immutable graph pages selected with one working checkpoint by the
/// native storage owner. The caller must have pinned the original committed
/// root and checked each page's exact storage receipt against that root.
#[derive(Clone, Copy)]
pub struct CommittedGraphPages<'archive, 'index> {
    namespace: [u8; 16],
    pages: &'index [CommittedGraphPage<'archive, 'index>],
}

impl<'archive, 'index> CommittedGraphPages<'archive, 'index> {
    /// Lend all selected pages, in stable root directory order. Recovery
    /// checks their identities and graph against the selected working image.
    pub const fn new(
        namespace: [u8; 16],
        pages: &'index [CommittedGraphPage<'archive, 'index>],
    ) -> Self {
        Self { namespace, pages }
    }

    pub(in crate::archive) const EMPTY: Self = Self::new([0; 16], &[]);

    pub(super) fn check_directory<const ROOMS: usize>(
        &self,
        historical_peer: Option<[u8; 32]>,
        rooms: &RoomDirectory<'_, ROOMS>,
    ) -> Result<(), Error> {
        for (i, page) in self.pages.iter().enumerate() {
            let id = page.identity();
            if id.namespace() != &self.namespace
                || Some(id.peer().as_bytes()) != historical_peer.as_ref()
            {
                return Err(Fault::Authentication.into());
            }
            let (slot, room) = rooms
                .iter()
                .find(|(_, room)| &room.key == id.room())
                .ok_or(Fault::StaleGeneration)?;
            if page.room_position() != (slot.index, slot.generation)
                || page.accepted_through() > room.sequence
            {
                return Err(Fault::StaleGeneration.into());
            }
            if self.pages[..i]
                .iter()
                .any(|previous| previous.identity() == id)
            {
                return Err(Fault::Conflict.into());
            }
        }
        Ok(())
    }
}

pub(super) struct RoomGraph<'room, 'id, 'archive, 'index> {
    room: &'room RoomRow<'id>,
    pages: CommittedGraphPages<'archive, 'index>,
    width: usize,
}

impl<'room, 'id, 'archive, 'index> RoomGraph<'room, 'id, 'archive, 'index> {
    pub(super) fn new(
        room: &'room RoomRow<'id>,
        pages: CommittedGraphPages<'archive, 'index>,
    ) -> Result<Self, Error> {
        let mut this = Self {
            room,
            pages,
            width: room.nodes.limit(),
        };
        let width = this.room_pages().try_fold(this.width, |width, page| {
            width.checked_add(page.len()).ok_or(Fault::Overflow)
        })?;
        this.width = width;
        Ok(this)
    }

    fn room_pages(&self) -> impl Iterator<Item = &CommittedGraphPage<'archive, 'index>> {
        self.pages
            .pages
            .iter()
            .filter(move |page| page.identity().room() == &self.room.key)
    }

    pub(super) const fn width(&self) -> usize {
        self.width
    }

    pub(super) fn detached_rows(
        &self,
    ) -> impl Iterator<Item = Result<(usize, MessageRecord<'archive>), Error>> {
        let base = self.room.nodes.limit();
        self.room_pages()
            .flat_map(|page| (0..page.len()).map(move |index| page.record(index)))
            .enumerate()
            .map(move |(index, record)| Ok((base + index, record?)))
    }

    pub(super) fn sequences(&self) -> impl Iterator<Item = Result<u64, Error>> {
        self.room
            .nodes
            .iter()
            .map(|(_, node)| Ok(node.sequence))
            .chain(self.room_pages().flat_map(|page| {
                page.index_keys().map(|(_, bytes)| {
                    let sequence = bytes.try_into().map_err(|_| Fault::Malformed)?;
                    Ok(u64::from_be_bytes(sequence))
                })
            }))
    }

    pub(super) fn locate(&self, hash: &Hash) -> Result<Option<(usize, bool)>, Error> {
        if let Some(slot) = self.room.find_node(hash) {
            return Ok(Some((slot.index, self.room.nodes.get(slot)?.complete)));
        }
        let mut base = self.room.nodes.limit();
        for page in self.room_pages() {
            if let Some(index) = page.position(hash) {
                // CommittedGraphPage only opens complete records.
                return Ok(Some((base + index, true)));
            }
            base += page.len();
        }
        Ok(None)
    }

    pub(super) fn parents(
        &self,
        hashes: &[Hash; 2],
        complete: bool,
    ) -> Result<[Option<usize>; 2], Error> {
        let mut parents = [None; 2];
        for (index, hash) in hashes.iter().enumerate() {
            if *hash == [0; 64] {
                continue;
            }
            match self.locate(hash)? {
                Some((at, ready)) if !complete || ready => parents[index] = Some(at),
                None if !complete => (),
                _ => return Err(Fault::Malformed.into()),
            }
        }
        Ok(parents)
    }

    pub(super) fn edges(&self) -> impl Iterator<Item = Result<(usize, [Option<usize>; 2]), Error>> {
        self.room
            .nodes
            .iter()
            .map(|(slot, node)| Ok((slot.index, self.parents(&node.parents, node.complete)?)))
            .chain(self.detached_rows().map(|entry| {
                let (index, row) = entry?;
                // Working rows and earlier pages win lookup. Any duplicate
                // would give this record somebody else's graph coordinate.
                if self.locate(&row.hash)? != Some((index, true)) {
                    return Err(Fault::Conflict.into());
                }
                Ok((index, self.parents(&row.parents, true)?))
            }))
    }
}
