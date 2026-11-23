//! Sorted slots for a room's exact message hashes. Hashes stay in the nodes.

use crate::{Error, Hash, Slot};
#[cfg(all(test, feature = "alloc"))]
use alloc::vec::Vec;
use core::{cmp::Ordering, ops::Deref};
use gnunet_types::Error as Fault;

pub(crate) struct MessageIndex<S> {
    storage: S,
    len: usize,
}

#[cfg(all(test, feature = "alloc"))]
pub(crate) type OwnedIndex = MessageIndex<Vec<Slot>>;

#[cfg(all(test, feature = "alloc"))]
impl OwnedIndex {
    pub(crate) fn new(capacity: usize) -> Result<Self, Error> {
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| Fault::Capacity)?;
        slots.resize(slots.capacity(), Slot::empty());
        Ok(Self::in_storage(slots))
    }
}

impl<S: AsRef<[Slot]>> Deref for MessageIndex<S> {
    type Target = [Slot];

    fn deref(&self) -> &Self::Target {
        &self.storage.as_ref()[..self.len]
    }
}

impl<S: AsRef<[Slot]> + AsMut<[Slot]>> MessageIndex<S> {
    pub(crate) const fn in_storage(storage: S) -> Self {
        Self { storage, len: 0 }
    }

    pub(crate) fn into_storage(self) -> S {
        self.storage
    }

    pub(crate) fn capacity(&self) -> usize {
        self.storage.as_ref().len()
    }

    fn locate<'node>(
        &self,
        hash: &Hash,
        hash_of: impl Fn(Slot) -> Result<&'node Hash, Error>,
    ) -> Result<Result<usize, usize>, Error> {
        let (mut first, mut end) = (0, self.len);
        while first < end {
            let at = first + (end - first) / 2;
            match hash_of(self[at])?.cmp(hash) {
                Ordering::Less => first = at + 1,
                Ordering::Greater => end = at,
                Ordering::Equal => return Ok(Ok(at)),
            }
        }
        Ok(Err(first))
    }

    pub(crate) fn find<'node>(
        &self,
        hash: &Hash,
        hash_of: impl Fn(Slot) -> Result<&'node Hash, Error>,
    ) -> Option<Slot> {
        self.locate(hash, hash_of).ok()?.ok().map(|at| self[at])
    }

    /// Reserve the exact insertion position without changing the visible index.
    /// Committing the new node to its table can still fail before `insert`.
    pub(crate) fn vacant<'node>(
        &mut self,
        hash: &Hash,
        hash_of: impl Fn(Slot) -> Result<&'node Hash, Error>,
    ) -> Result<Vacant<'_>, Error> {
        let Err(at) = self.locate(hash, hash_of)? else {
            return Err(Fault::Conflict.into());
        };
        let tail = self
            .storage
            .as_mut()
            .get_mut(at..=self.len)
            .ok_or(Fault::Capacity)?;
        Ok(Vacant {
            tail,
            len: &mut self.len,
        })
    }

    pub(crate) fn retain(&mut self, mut keep: impl FnMut(Slot) -> bool) {
        let slots = &mut self.storage.as_mut()[..self.len];
        let mut head = 0;
        for tail in 0..slots.len() {
            let slot = slots[tail];
            if keep(slot) {
                slots[head] = slot;
                head += 1;
            }
        }
        slots[head..].fill(Slot::empty());
        self.len = head;
    }
}

pub(crate) struct Vacant<'index> {
    tail: &'index mut [Slot],
    len: &'index mut usize,
}

impl Vacant<'_> {
    pub(crate) fn insert(self, slot: Slot) {
        self.tail.rotate_right(1);
        self.tail[0] = slot;
        *self.len += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exercise<S: AsRef<[Slot]> + AsMut<[Slot]>>(mut index: MessageIndex<S>) -> Result<(), Error> {
        let first = Slot {
            index: 0,
            generation: 2,
        };
        let second = Slot {
            index: 1,
            generation: 1,
        };
        let hashes = [[1; 64], [2; 64]];
        let hash_of = |slot| match slot {
            slot if slot == first => Ok(&hashes[0]),
            slot if slot == second => Ok(&hashes[1]),
            _ => Err(Fault::StaleGeneration.into()),
        };
        let _ = index.vacant(&hashes[0], hash_of)?;
        if !index.is_empty() {
            return Err(Fault::Conflict.into());
        }
        index.vacant(&hashes[1], hash_of)?.insert(second);
        index.vacant(&hashes[0], hash_of)?.insert(first);
        if *index != [first, second]
            || index.find(&hashes[1], hash_of) != Some(second)
            || index.find(&[0; 64], hash_of).is_some()
            || !matches!(
                index.vacant(&hashes[0], hash_of),
                Err(Error::Protocol(Fault::Conflict))
            )
            || !matches!(
                index.vacant(&[3; 64], hash_of),
                Err(Error::Protocol(Fault::Capacity))
            )
        {
            return Err(Fault::Conflict.into());
        }
        Ok(())
    }

    #[test]
    fn borrowed_message_index_keeps_atomic_sorted_admission() -> Result<(), Error> {
        let mut slots = [Slot::empty(); 2];
        exercise(MessageIndex::in_storage(&mut slots[..]))
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn owned_message_index_keeps_atomic_sorted_admission() -> Result<(), Error> {
        exercise(OwnedIndex::new(2)?)
    }
}
