//! Slot-indexed cursors for an immutable room walk.

use crate::{
    Error,
    room_history::{HistoryEntry, HistoryId, HistoryRead},
    storage::Backing,
};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::num::NonZeroUsize;
use gnunet_types::Error as Fault;

/// One caller-supplied history mark. Contents are private to the workspace.
#[derive(Clone, Copy)]
pub struct HistoryCell {
    walk: u64,
    previous: Option<NonZeroUsize>,
}

impl HistoryCell {
    /// An unused mark for initializing caller-owned memory.
    pub const EMPTY: Self = Self {
        walk: 0,
        previous: None,
    };
}

/// Reusable workspace for an immutable room's history walk. It needs one cell
/// per configured message slot and holds no message payloads.
pub struct HistoryWorkspace<'memory> {
    cells: Backing<HistoryCell, &'memory mut [HistoryCell]>,
    marks: Marks,
}

#[cfg(feature = "alloc")]
impl HistoryWorkspace<'static> {
    /// Allocate a workspace once. Starting or walking history never allocates.
    pub fn new(message_slots: usize) -> Result<Self, Error> {
        if message_slots == 0 {
            return Err(Fault::InvalidInput.into());
        }
        let mut cells = Vec::new();
        cells
            .try_reserve_exact(message_slots)
            .map_err(|_| Fault::Capacity)?;
        cells.resize(message_slots, HistoryCell::EMPTY);
        Ok(Self {
            cells: Backing::Owned(cells),
            marks: Marks::EMPTY,
        })
    }

    /// Reserve bounded scratch without charging it as retained history.
    pub(crate) fn budgeted(message_slots: usize, remaining: usize) -> Result<Self, Error> {
        if Self::required_bytes(message_slots)? > remaining {
            return Err(Fault::Capacity.into());
        }
        let workspace = Self::new(message_slots)?;
        if workspace.bytes()? > remaining {
            return Err(Fault::Capacity.into());
        }
        Ok(workspace)
    }
}

impl<'memory> HistoryWorkspace<'memory> {
    /// Prepare memory provided by the caller without allocating. Cells may be
    /// reused from a previous workspace.
    pub fn from_cells(cells: &'memory mut [HistoryCell]) -> Result<Self, Error> {
        if cells.is_empty() {
            return Err(Fault::InvalidInput.into());
        }
        cells.fill(HistoryCell::EMPTY);
        Ok(Self {
            cells: Backing::fixed(cells),
            marks: Marks::EMPTY,
        })
    }

    pub(crate) fn required_bytes(message_slots: usize) -> Result<usize, Error> {
        message_slots
            .checked_mul(core::mem::size_of::<HistoryCell>())
            .ok_or_else(|| Fault::Overflow.into())
    }

    #[cfg(feature = "alloc")]
    pub(crate) fn bytes(&self) -> Result<usize, Error> {
        Self::required_bytes(self.cells.capacity())
    }

    pub(crate) fn start(&mut self, message_slots: usize, root: usize) -> Result<Walk<'_>, Error> {
        let cells = self.cells.as_mut();
        if message_slots > cells.len() {
            return Err(Fault::Capacity.into());
        }
        self.marks.restart(cells);
        let mut walk = Walk {
            cells: &mut cells[..message_slots],
            marks: &mut self.marks,
        };
        walk.schedule(root)?;
        Ok(walk)
    }

    pub(crate) fn start_history<R: HistoryRead>(
        &mut self,
        history: R,
        root: HistoryId,
    ) -> Result<HistoryWalk<'_, R>, Error> {
        let walk = self.start(history.limit(), root.index())?;
        Ok(HistoryWalk { history, walk })
    }
}

/// Typed traversal of one immutable logical directory. The compact marks
/// store indices; the reader owns generation resolution for each pop.
pub(crate) struct HistoryWalk<'work, R> {
    history: R,
    walk: Walk<'work>,
}

impl<R: HistoryRead> HistoryWalk<'_, R> {
    pub(crate) fn locate(&mut self, hash: &crate::Hash) -> Result<Option<HistoryId>, Error> {
        self.history.locate(hash)
    }

    pub(crate) fn schedule(&mut self, id: HistoryId) -> Result<(), Error> {
        self.walk.schedule(id.index())
    }

    pub(crate) fn pop(&mut self) -> Result<Option<(HistoryId, HistoryEntry)>, Error> {
        self.walk
            .pop()
            .map(|index| self.history.read(index))
            .transpose()
    }
}

/// Compact stack plus visited set. The owner can keep the cursor across turns
/// as long as logical indices keep their identity until the traversal ends.
pub(super) struct Marks {
    id: u64,
    head: Option<NonZeroUsize>,
}

impl Marks {
    pub(super) const EMPTY: Self = Self { id: 0, head: None };

    pub(super) fn restart(&mut self, cells: &mut [HistoryCell]) {
        self.id = self.id.checked_add(1).unwrap_or_else(|| {
            cells.fill(HistoryCell::EMPTY);
            1
        });
        self.clear();
    }

    pub(super) fn clear(&mut self) {
        self.head = None;
    }

    pub(super) fn front(&self) -> Option<usize> {
        self.head.map(|head| head.get() - 1)
    }

    fn contains(&self, cells: &[HistoryCell], index: usize) -> bool {
        cells.get(index).is_some_and(|cell| cell.walk == self.id)
    }

    pub(super) fn schedule(
        &mut self,
        cells: &mut [HistoryCell],
        index: usize,
    ) -> Result<(), Error> {
        let cell = cells.get_mut(index).ok_or(Fault::Conflict)?;
        if cell.walk != self.id {
            let head = NonZeroUsize::MIN
                .checked_add(index)
                .ok_or(Fault::Overflow)?;
            *cell = HistoryCell {
                walk: self.id,
                previous: self.head,
            };
            self.head = Some(head);
        }
        Ok(())
    }

    pub(super) fn pop(&mut self, cells: &[HistoryCell]) -> Option<usize> {
        let index = self.front()?;
        self.head = cells[index].previous;
        Some(index)
    }
}

pub(crate) struct Walk<'memory> {
    cells: &'memory mut [HistoryCell],
    marks: &'memory mut Marks,
}

impl Walk<'_> {
    pub(crate) fn contains(&self, index: usize) -> bool {
        self.marks.contains(self.cells, index)
    }

    pub(crate) fn schedule(&mut self, index: usize) -> Result<(), Error> {
        self.marks.schedule(self.cells, index)
    }

    pub(crate) fn pop(&mut self) -> Option<usize> {
        self.marks.pop(self.cells)
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "assertions check the fallible history workspace lifecycle"
    )]

    use super::*;

    #[test]
    fn borrowed_walk_visits_shared_ancestors_once_and_reuses_after_wrap() -> Result<(), Error> {
        let mut cells = [HistoryCell::EMPTY; 4];
        let mut workspace = HistoryWorkspace::from_cells(&mut cells)?;
        assert!(matches!(
            workspace.start(5, 0),
            Err(Error::Protocol(Fault::Capacity))
        ));
        workspace.marks.id = u64::MAX - 1;
        {
            let mut walk = workspace.start(4, 0)?;
            assert_eq!(walk.pop(), Some(0));
            walk.schedule(1)?;
            walk.schedule(2)?;
            assert_eq!(walk.pop(), Some(2));
            walk.schedule(3)?;
            assert_eq!(walk.pop(), Some(3));
            assert_eq!(walk.pop(), Some(1));
            walk.schedule(3)?;
            assert_eq!(walk.pop(), None);
        }
        let mut walk = workspace.start(4, 3)?;
        assert_eq!(walk.pop(), Some(3));
        assert_eq!(walk.pop(), None);
        Ok(())
    }
}
