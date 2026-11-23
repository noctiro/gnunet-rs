//! Project a settled working set into a page and a successor checkpoint.

use super::{page::can_detach, *};

#[derive(Clone, Copy)]
pub(super) struct Selection<'turn> {
    room: Slot,
    hashes: &'turn [Hash],
}

impl Selection<'_> {
    pub(super) fn contains(self, room: Slot, hash: &Hash) -> bool {
        room == self.room && self.hashes.binary_search(hash).is_ok()
    }
}

/// Exclusive working-state selection for one native graph-page publication.
/// Encoding or dropping the selection leaves the working graph unchanged.
/// Only the original storage owner can decide when the cutover is confirmed.
#[must_use]
pub struct GraphDetachment<'turn, 'id, const ROOMS: usize> {
    core: &'turn mut Core<'id, ROOMS>,
    room: Room<'id>,
    selection: Selection<'turn>,
    released: usize,
    deletable_originals: usize,
}

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    /// Enumerate working graph rows eligible to move into a durable page.
    /// The native owner must keep any rows needed by an operation that cannot
    /// read from the committed page after the move.
    ///
    /// # Errors
    /// Refuses non-service state or a foreign, stale or absent room.
    pub fn detachable_messages(
        &self,
        room: Room<'id>,
    ) -> Result<impl Iterator<Item = &Hash> + '_, Error> {
        let row = self.detachment_room(room)?;
        Ok(row
            .nodes
            .iter()
            .filter_map(|(_, node)| eligible(row, node).then_some(&node.hash)))
    }

    /// Preflight an exact sorted selection and lend exclusive mutation
    /// authority until it settles or is dropped. The room's acceptance cursor
    /// and all session, epoch and frontier anchors stay in the working image.
    ///
    /// # Errors
    /// Refuses missing, busy, unsettled, already detached or unordered rows,
    /// or an inconsistent original storage reference or byte charge.
    pub fn begin_graph_detachment<'turn>(
        &'turn mut self,
        room: Room<'id>,
        hashes: &'turn [Hash],
    ) -> Result<GraphDetachment<'turn, 'id, ROOMS>, Error> {
        if hashes.is_empty() || hashes.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(Fault::InvalidInput.into());
        }
        let _ = u8::try_from(hashes.len()).map_err(|_| Fault::Capacity)?;
        let row = self.detachment_room(room)?;
        let mut released = 0usize;
        let mut deletable_originals = 0usize;
        for hash in hashes {
            let node = row.nodes.get(row.find_node(hash).ok_or(Fault::NotFound)?)?;
            if !eligible(row, node) || row.alias(hash) != Some(node.epoch) {
                return Err(Fault::NotReady.into());
            }
            node.original(&self.frames)?;
            released = released
                .checked_add(node.payload_bytes())
                .ok_or(Fault::Overflow)?;
            if node.has_original()
                && DetachedKind::of(node.kind).is_some_and(DetachedKind::is_deletable)
            {
                deletable_originals += 1;
            }
        }
        self.used.checked_sub(released).ok_or(Fault::Conflict)?;
        Ok(GraphDetachment {
            core: self,
            room,
            selection: Selection {
                room: room.slot,
                hashes,
            },
            released,
            deletable_originals,
        })
    }

    fn detachment_room(&self, room: Room<'id>) -> Result<&RoomRow<'id>, Error> {
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        self.rooms.get(self.check_room(room)?)
    }
}

impl<const ROOMS: usize> GraphDetachment<'_, '_, ROOMS> {
    /// Encode the page from the exact selection. Keep space for each deletable
    /// original's optional deletion deadline and signed deletion hash.
    ///
    /// # Errors
    /// Refuses an invalid identity, altered original, or insufficient space.
    pub fn prepare_page_into<'output>(
        &self,
        identity: GraphPageIdentity,
        output: &'output mut [u8],
        read: impl FnMut(ArchiveOriginalRange, &mut [u8]) -> Result<(), Error>,
    ) -> Result<PreparedGraphPageRef<'output>, Error> {
        self.prepare_page(identity, None, output, read)
    }

    /// Keep every previously selected row, and merge the newly detached rows
    /// in canonical hash order under a newer identity for the same page slot.
    ///
    /// # Errors
    /// Refuses a stale or incompatible page, duplicate hashes, altered
    /// originals, or insufficient space including future deletion metadata.
    pub fn extend_page_into<'output>(
        &self,
        prior: &CommittedGraphPage<'_, '_>,
        identity: GraphPageIdentity,
        output: &'output mut [u8],
        read: impl FnMut(ArchiveOriginalRange, &mut [u8]) -> Result<(), Error>,
    ) -> Result<PreparedGraphPageRef<'output>, Error> {
        self.prepare_page(identity, Some(prior), output, read)
    }

    fn prepare_page<'output>(
        &self,
        identity: GraphPageIdentity,
        prior: Option<&CommittedGraphPage<'_, '_>>,
        output: &'output mut [u8],
        read: impl FnMut(ArchiveOriginalRange, &mut [u8]) -> Result<(), Error>,
    ) -> Result<PreparedGraphPageRef<'output>, Error> {
        let timer_bytes = self.deletable_originals * page::DELETION_BYTES
            + prior.map_or(Ok(0), CommittedGraphPage::deletion_reserve)?;
        let end = output
            .len()
            .checked_sub(timer_bytes)
            .ok_or(Fault::Capacity)?;
        self.core.prepare_extended_graph_page(
            self.room,
            identity,
            prior,
            self.selection.hashes,
            &mut output[..end],
            read,
        )
    }

    /// Encode the matching working checkpoint and its retained frame index.
    /// The selected hashes and their first-write aliases live only in the page.
    ///
    /// # Errors
    /// Refuses invalid checkpoint state, missing originals or a full output.
    pub fn prepare_checkpoint_into<'output>(
        &self,
        output: &'output mut [u8],
        originals: &mut ArchiveOriginals<'_>,
        read: impl FnMut(ArchiveOriginalRange, &mut [u8]) -> Result<(), Error>,
    ) -> Result<PreparedArchiveRef<'output>, Error> {
        self.core
            .prepare_projected_archive_into(output, originals, read, Some(self.selection))
    }

    /// Settle only after the exact page and checkpoint become authoritative
    /// together. Release the selected frame and graph slots and install the
    /// new working original offsets. An unknown outcome requires reopening.
    ///
    /// # Errors
    /// Rejects an inconsistent projection or custody state. If this happens
    /// after publication, retire the Core and recover from the selected root.
    pub fn settle(self, originals: &ArchiveOriginals<'_>) -> Result<(), Error> {
        let Self {
            core,
            selection,
            released,
            ..
        } = self;
        core.settle_projected_archive(originals, Some(selection))?;
        let used = core.used.checked_sub(released).ok_or(Fault::Conflict)?;
        let room = core.rooms.get_mut(selection.room)?;
        let nodes = &room.nodes;
        room.index.retain(|at| {
            nodes
                .get(at)
                .is_ok_and(|node| !selection.contains(selection.room, &node.hash))
        });
        for hash in selection.hashes {
            if !room.remove_alias(hash)? {
                return Err(Fault::Conflict.into());
            }
        }
        // Remove by generation-qualified table slot after the index no longer
        // has any path to the outgoing rows.
        for index in 0..room.nodes.limit() {
            if let Some(at) = room.nodes.slot_at(index)
                && selection.contains(selection.room, &room.nodes.get(at)?.hash)
            {
                let node = room.nodes.remove(at)?;
                if let Some(frame) = node.frame {
                    core.frames.remove(frame)?;
                }
            }
        }
        core.used = used;
        Ok(())
    }
}

fn eligible(room: &RoomRow<'_>, node: &Node) -> bool {
    let hash = node.hash;
    can_detach(node)
        && hash != room.last_message
        && hash != room.current_epoch
        && room.frontier_base != Some(hash)
        && room.frontier_control_hash != Some(hash)
        && !room.queues.frontier.contains(&hash)
        && !room
            .sessions
            .iter()
            .any(|(_, session)| session.first_bound == hash || session.last_bound == hash)
        && !room.missing.iter().any(|(_, missing)| missing.hash == hash)
        && !room.operations.iter().any(|(_, operation)| {
            operation.binding.message == hash
                || matches!(operation.job, Job::Sign { previous, .. } if previous == hash)
        })
}
