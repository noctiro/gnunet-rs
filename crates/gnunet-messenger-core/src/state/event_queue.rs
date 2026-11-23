//! Bounded FIFO of original state observations.

use super::QueuedEvent;
use crate::{Error, storage::Backing};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use gnunet_types::Error as Fault;

/// One event queue cell in caller-owned service storage.
pub struct EventCell(Option<QueuedEvent>);

impl EventCell {
    /// An unused event queue cell.
    pub const fn empty() -> Self {
        Self(None)
    }
}

pub(crate) struct EventQueue<'id> {
    cells: Backing<EventCell, &'id mut [EventCell]>,
    head: usize,
    len: usize,
}

impl<'id> EventQueue<'id> {
    #[cfg(feature = "alloc")]
    pub fn new(limit: usize) -> Result<Self, Error> {
        let mut cells = Vec::new();
        cells
            .try_reserve_exact(limit)
            .map_err(|_| Fault::Capacity)?;
        cells.resize_with(limit, EventCell::empty);
        Ok(Self::start(Backing::Owned(cells)))
    }

    pub fn fixed(cells: &'id mut [EventCell], limit: usize) -> Result<Self, Error> {
        if cells.len() != limit {
            return Err(Fault::Capacity.into());
        }
        cells.fill_with(EventCell::empty);
        Ok(Self::start(Backing::fixed(cells)))
    }

    const fn start(cells: Backing<EventCell, &'id mut [EventCell]>) -> Self {
        Self {
            cells,
            head: 0,
            len: 0,
        }
    }

    pub fn required_bytes(limit: usize) -> Result<usize, Error> {
        limit
            .checked_mul(core::mem::size_of::<EventCell>())
            .ok_or_else(|| Fault::Overflow.into())
    }

    pub fn bytes(&self) -> Result<usize, Error> {
        Self::required_bytes(self.cells.capacity())
    }

    pub fn capacity(&self) -> usize {
        self.cells.as_ref().len()
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    #[cfg(all(test, feature = "alloc"))]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn reserve(&self, count: usize) -> Result<(), Error> {
        if count > self.capacity() - self.len() {
            return Err(Fault::WouldBlock.into());
        }
        Ok(())
    }

    fn physical(&self, offset: usize) -> usize {
        let tail = self.capacity() - self.head;
        if offset < tail {
            self.head + offset
        } else {
            offset - tail
        }
    }

    pub fn vacant(&mut self) -> Result<VacantEvent<'_>, Error> {
        self.reserve(1)?;
        let tail = self.physical(self.len);
        Ok(VacantEvent {
            cell: &mut self.cells.as_mut()[tail],
            len: &mut self.len,
        })
    }

    pub fn pop_front(&mut self) -> Option<QueuedEvent> {
        if self.len == 0 {
            return None;
        }
        let head = self.head;
        self.head = self.physical(1);
        self.len -= 1;
        self.cells.as_mut()[head].0.take()
    }

    pub fn retain(&mut self, mut keep: impl FnMut(&QueuedEvent) -> bool) {
        let mut len = 0;
        for offset in 0..self.len {
            let index = self.physical(offset);
            let cell = self.cells.as_mut()[index].0.take();
            if let Some(event) = cell
                && keep(&event)
            {
                let target = self.physical(len);
                self.cells.as_mut()[target].0 = Some(event);
                len += 1;
            }
        }
        self.len = len;
    }

    #[cfg(all(test, feature = "alloc"))]
    pub fn clear(&mut self) {
        while self.pop_front().is_some() {}
    }
}

impl Drop for EventQueue<'_> {
    fn drop(&mut self) {
        if let Some(cells) = self.cells.fixed_mut() {
            // Consumed cells are already empty. Release payloads still queued.
            let first = self.len.min(cells.len() - self.head);
            cells[self.head..self.head + first].fill_with(EventCell::empty);
            cells[..self.len - first].fill_with(EventCell::empty);
        }
    }
}

pub(crate) struct VacantEvent<'queue> {
    cell: &'queue mut EventCell,
    len: &'queue mut usize,
}

impl VacantEvent<'_> {
    pub fn insert(self, event: QueuedEvent) {
        self.cell.0 = Some(event);
        *self.len += 1;
    }
}
