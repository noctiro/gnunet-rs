//! FIFO for generational room references. Head and length track occupancy,
//! leaving exactly one `Slot` per entry in either form of backing storage.

use crate::{Error, Slot};
use gnunet_types::Error as Fault;

pub(crate) struct SlotQueue<S> {
    storage: S,
    head: usize,
    len: usize,
}

impl<S: AsRef<[Slot]> + AsMut<[Slot]>> SlotQueue<S> {
    pub(crate) const fn in_storage(storage: S) -> Self {
        Self {
            storage,
            head: 0,
            len: 0,
        }
    }

    pub(crate) fn into_storage(self) -> S {
        self.storage
    }

    pub(crate) fn capacity(&self) -> usize {
        self.storage.as_ref().len()
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn get(&self, offset: usize) -> Option<Slot> {
        (offset < self.len).then(|| self.storage.as_ref()[self.physical(offset)])
    }

    pub(crate) fn contains(&self, slot: Slot) -> bool {
        let storage = self.storage.as_ref();
        let remaining = self.len.min(storage.len() - self.head);
        storage[self.head..self.head + remaining].contains(&slot)
            || storage[..self.len - remaining].contains(&slot)
    }

    fn physical(&self, offset: usize) -> usize {
        let tail = self.capacity() - self.head;
        if offset < tail {
            self.head + offset
        } else {
            offset - tail
        }
    }

    /// Reserve the next FIFO position without changing the queue until insertion.
    pub(crate) fn vacant(&mut self) -> Result<Vacant<'_>, Error> {
        if self.len == self.capacity() {
            return Err(Fault::Capacity.into());
        }
        let tail = self.physical(self.len);
        Ok(Vacant {
            entry: &mut self.storage.as_mut()[tail],
            len: &mut self.len,
        })
    }

    pub(crate) fn push_back(&mut self, slot: Slot) -> Result<(), Error> {
        self.vacant()?.insert(slot);
        Ok(())
    }

    pub(crate) fn pop_front(&mut self) -> Option<Slot> {
        if self.is_empty() {
            return None;
        }
        let original = self.storage.as_ref()[self.head];
        self.head = self.physical(1);
        self.len -= 1;
        Some(original)
    }

    /// Keep surviving generations in FIFO order, including across wraparound.
    pub(crate) fn retain(&mut self, mut keep: impl FnMut(Slot) -> bool) {
        let mut len = 0;
        for offset in 0..self.len {
            let slot = self.storage.as_ref()[self.physical(offset)];
            if keep(slot) {
                if offset != len {
                    let target = self.physical(len);
                    self.storage.as_mut()[target] = slot;
                }
                len += 1;
            }
        }
        self.len = len;
    }
}

pub(crate) struct Vacant<'queue> {
    entry: &'queue mut Slot,
    len: &'queue mut usize,
}

impl Vacant<'_> {
    pub(crate) fn insert(self, slot: Slot) {
        *self.entry = slot;
        *self.len += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "verify FIFO wraparound and generational membership after backpressure"
    )]
    fn caller_backed_slot_queue_wraps_without_exceeding_capacity() -> Result<(), Error> {
        let first = Slot {
            index: 1,
            generation: 1,
        };
        let second = Slot {
            index: 2,
            generation: 1,
        };
        let replacement = Slot {
            index: 1,
            generation: 2,
        };
        let mut storage = [replacement; 2];
        let mut queue = SlotQueue::in_storage(&mut storage[..]);
        assert!(!queue.contains(replacement));
        queue.push_back(first)?;
        queue.push_back(second)?;
        assert_eq!(queue.push_back(replacement), Err(Fault::Capacity.into()));
        assert!(queue.pop_front() == Some(first));
        let _ = queue.vacant()?;
        assert!(!queue.contains(replacement));
        queue.vacant()?.insert(replacement);
        assert!(queue.contains(second));
        assert!(queue.contains(replacement));
        assert!(!queue.contains(first));
        queue.retain(|slot| slot != first && slot != second);
        assert!(queue.pop_front() == Some(replacement));
        assert!(queue.pop_front().is_none());

        let mut empty = SlotQueue::in_storage(&mut storage[..0]);
        assert_eq!(empty.push_back(first), Err(Fault::Capacity.into()));
        assert!(!empty.contains(first));
        assert!(empty.pop_front().is_none());
        Ok(())
    }
}
