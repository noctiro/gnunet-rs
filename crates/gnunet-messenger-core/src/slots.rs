//! Stable generational metadata tables. Slots retire when their generation
//! reaches the last value. Vacant entries carry the free list in place.

use crate::{Error, Slot};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::{
    marker::PhantomData,
    num::{NonZeroU64, NonZeroUsize},
};
use gnunet_types::Error as Fault;

#[derive(Clone, Copy)]
struct Index(NonZeroUsize);

impl Index {
    fn at(index: usize) -> Self {
        // An entry occupies multiple bytes, so a slice index is < usize::MAX.
        Self(NonZeroUsize::MIN.saturating_add(index))
    }

    const fn get(self) -> usize {
        self.0.get() - 1
    }
}

#[derive(Clone, Copy)]
struct FreeList {
    head: Index,
    tail: Index,
}

impl FreeList {
    fn prepend(head: Index, rest: Option<Self>) -> Self {
        Self {
            head,
            tail: rest.map_or(head, |free| free.tail),
        }
    }
}

#[derive(Clone, Copy)]
enum Allocation {
    Ready(Option<FreeList>),
    Restoring,
}

pub(crate) struct Entry<T>(EntryState<T>);

enum EntryState<T> {
    Vacant {
        generation: NonZeroU64,
        next: Option<Index>,
    },
    Live {
        generation: NonZeroU64,
        value: T,
    },
    Retired,
}

impl<T> Entry<T> {
    pub(crate) const fn vacant() -> Self {
        Self(EntryState::Vacant {
            generation: NonZeroU64::MIN,
            next: None,
        })
    }
}

pub(crate) trait EntryCell<T> {
    fn entry(&self) -> &Entry<T>;
    fn entry_mut(&mut self) -> &mut Entry<T>;
}

impl<T> EntryCell<T> for Entry<T> {
    fn entry(&self) -> &Self {
        self
    }
    fn entry_mut(&mut self) -> &mut Self {
        self
    }
}

pub(crate) struct Table<T, S, C = Entry<T>> {
    entries: S,
    allocation: Allocation,
    live: usize,
    row: PhantomData<(Entry<T>, C)>,
}

pub(crate) struct VacantSlot<'a, T> {
    entry: &'a mut EntryState<T>,
    allocation: &'a mut Allocation,
    live: &'a mut usize,
    index: usize,
    generation: NonZeroU64,
    next: Option<FreeList>,
}

impl<T> VacantSlot<'_, T> {
    pub fn insert(self, value: T) -> Slot {
        *self.allocation = Allocation::Ready(self.next);
        *self.entry = EntryState::Live {
            generation: self.generation,
            value,
        };
        *self.live += 1;
        Slot {
            index: self.index,
            generation: self.generation.get(),
        }
    }
}

#[cfg(feature = "alloc")]
pub(crate) type Slots<T> = Table<T, Vec<Entry<T>>>;

#[cfg(feature = "alloc")]
impl<T> Slots<T> {
    pub fn empty() -> Self {
        Self::start(Vec::new())
    }

    pub fn new(limit: usize) -> Result<Self, Error> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(limit)
            .map_err(|_| Fault::Capacity)?;
        entries.resize_with(limit, Entry::vacant);
        Ok(Self::start(entries))
    }

    pub fn bytes(&self) -> Result<usize, Error> {
        Self::required_bytes(self.entries.capacity())
    }

    pub fn required_bytes(limit: usize) -> Result<usize, Error> {
        limit
            .checked_mul(core::mem::size_of::<Entry<T>>())
            .ok_or_else(|| Fault::Overflow.into())
    }

    /// Grow without moving logical indices, keeping previously free slots at
    /// the head of the free list. Charge the additional retained capacity.
    pub fn grow_to(&mut self, limit: usize, budget: usize) -> Result<usize, Error> {
        let free = self.available()?;
        let old_limit = self.limit();
        let old_bytes = self.bytes()?;
        if limit <= old_limit {
            return Err(Fault::InvalidInput.into());
        }
        if Self::required_bytes(limit)?.saturating_sub(old_bytes) > budget {
            return Err(Fault::Capacity.into());
        }
        let mut expanded = Self::new(limit)?;
        let growth = expanded
            .bytes()?
            .checked_sub(old_bytes)
            .ok_or(Fault::Overflow)?;
        if growth > budget {
            return Err(Fault::Capacity.into());
        }
        let prefix = expanded
            .entries
            .get_mut(..old_limit)
            .ok_or(Fault::Conflict)?;
        let extension = Index::at(old_limit);
        let head = if let Some(free) = free {
            let Some(Entry(EntryState::Vacant { next, .. })) =
                self.entries.get_mut(free.tail.get())
            else {
                return Err(Fault::Conflict.into());
            };
            if next.is_some() {
                return Err(Fault::Conflict.into());
            }
            *next = Some(extension);
            free.head
        } else {
            extension
        };
        prefix.swap_with_slice(&mut self.entries);
        expanded.allocation = Allocation::Ready(Some(FreeList {
            head,
            tail: Index::at(limit - 1),
        }));
        expanded.live = self.live;
        *self = expanded;
        Ok(growth)
    }
}

impl<T, S, C> Table<T, S, C>
where
    S: AsRef<[C]> + AsMut<[C]>,
    C: EntryCell<T>,
{
    pub(crate) fn start(entries: S) -> Self {
        let mut table = Self {
            entries,
            allocation: Allocation::Restoring,
            live: 0,
            row: PhantomData,
        };
        table.finish_restore();
        table
    }

    pub(crate) fn storage(&self) -> &S {
        &self.entries
    }

    pub(crate) fn into_storage(self) -> S {
        self.entries
    }

    fn available(&self) -> Result<Option<FreeList>, Error> {
        match self.allocation {
            Allocation::Ready(free) => Ok(free),
            Allocation::Restoring => Err(Fault::Conflict.into()),
        }
    }

    fn first_free(&self) -> Result<FreeList, Error> {
        self.available()?.ok_or_else(|| Fault::Capacity.into())
    }

    pub fn limit(&self) -> usize {
        self.entries.as_ref().len()
    }

    pub fn len(&self) -> usize {
        self.live
    }

    pub fn slot_at(&self, index: usize) -> Option<Slot> {
        match &self.entries.as_ref().get(index)?.entry().0 {
            EntryState::Live { generation, .. } => Some(Slot {
                index,
                generation: generation.get(),
            }),
            _ => None,
        }
    }

    pub fn next_key(&self) -> Result<Slot, Error> {
        let index = self.first_free()?.head.get();
        let Some(Entry(EntryState::Vacant { generation, .. })) =
            self.entries.as_ref().get(index).map(C::entry)
        else {
            return Err(Fault::Conflict.into());
        };
        Ok(Slot {
            index,
            generation: generation.get(),
        })
    }

    pub fn vacant(&mut self) -> Result<VacantSlot<'_, T>, Error> {
        let free = self.first_free()?;
        let index = free.head.get();
        let Some(Entry(entry)) = self.entries.as_mut().get_mut(index).map(C::entry_mut) else {
            return Err(Fault::Conflict.into());
        };
        let EntryState::Vacant { generation, next } = *entry else {
            return Err(Fault::Conflict.into());
        };
        Ok(VacantSlot {
            entry,
            allocation: &mut self.allocation,
            live: &mut self.live,
            index,
            generation,
            next: next.map(|head| FreeList {
                head,
                tail: free.tail,
            }),
        })
    }

    pub fn insert(&mut self, value: T) -> Result<Slot, (Error, T)> {
        match self.vacant() {
            Ok(vacant) => Ok(vacant.insert(value)),
            Err(error) => Err((error, value)),
        }
    }

    pub fn get(&self, id: Slot) -> Result<&T, Error> {
        if let Some(Entry(EntryState::Live { generation, value })) =
            self.entries.as_ref().get(id.index).map(C::entry)
            && generation.get() == id.generation
        {
            return Ok(value);
        }
        Err(Fault::StaleGeneration.into())
    }

    pub fn get_mut(&mut self, id: Slot) -> Result<&mut T, Error> {
        if let Some(Entry(EntryState::Live { generation, value })) =
            self.entries.as_mut().get_mut(id.index).map(C::entry_mut)
            && generation.get() == id.generation
        {
            return Ok(value);
        }
        Err(Fault::StaleGeneration.into())
    }

    pub fn remove(&mut self, id: Slot) -> Result<T, Error> {
        let free = self.available()?;
        let Some(Entry(entry)) = self.entries.as_mut().get_mut(id.index).map(C::entry_mut) else {
            return Err(Fault::StaleGeneration.into());
        };
        let EntryState::Live { generation, .. } = *entry else {
            return Err(Fault::StaleGeneration.into());
        };
        if generation.get() != id.generation {
            return Err(Fault::StaleGeneration.into());
        }
        let old = core::mem::replace(entry, EntryState::Retired);
        let EntryState::Live { value, .. } = old else {
            *entry = old;
            return Err(Fault::Conflict.into());
        };
        if let Some(generation) = generation.checked_add(1) {
            *entry = EntryState::Vacant {
                generation,
                next: free.map(|list| list.head),
            };
            self.allocation = Allocation::Ready(Some(FreeList::prepend(Index::at(id.index), free)));
        }
        self.live -= 1;
        Ok(value)
    }

    pub fn iter(&self) -> impl Iterator<Item = (Slot, &T)> {
        self.entries
            .as_ref()
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| match &entry.entry().0 {
                EntryState::Live { generation, value } => Some((
                    Slot {
                        index,
                        generation: generation.get(),
                    },
                    value,
                )),
                _ => None,
            })
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (Slot, &mut T)> {
        self.entries
            .as_mut()
            .iter_mut()
            .enumerate()
            .filter_map(|(index, entry)| match &mut entry.entry_mut().0 {
                EntryState::Live { generation, value } => Some((
                    Slot {
                        index,
                        generation: generation.get(),
                    },
                    value,
                )),
                _ => None,
            })
    }

    /// Stage a live entry in a new owner; allocation stays disabled until the
    /// archive reader finishes rebuilding the free list.
    pub(crate) fn restore_entry(
        &mut self,
        index: usize,
        generation: u64,
        value: T,
    ) -> Result<(), Error> {
        let generation = NonZeroU64::new(generation).ok_or(Fault::Malformed)?;
        let entry = self
            .entries
            .as_mut()
            .get_mut(index)
            .map(C::entry_mut)
            .ok_or(Fault::Capacity)?;
        if !matches!(entry.0, EntryState::Vacant { generation, .. } if generation == NonZeroU64::MIN)
        {
            return Err(Fault::Malformed.into());
        }
        entry.0 = EntryState::Live { generation, value };
        self.allocation = Allocation::Restoring;
        self.live += 1;
        Ok(())
    }

    pub(crate) fn finish_restore(&mut self) {
        if !matches!(self.allocation, Allocation::Restoring) {
            return;
        }
        let mut free: Option<FreeList> = None;
        for (index, entry) in self.entries.as_mut().iter_mut().enumerate().rev() {
            if let EntryState::Vacant { next, .. } = &mut entry.entry_mut().0 {
                *next = free.map(|list| list.head);
                free = Some(FreeList::prepend(Index::at(index), free));
            }
        }
        self.allocation = Allocation::Ready(free);
    }
}

#[cfg(test)]
struct Borrowed<'storage, T>(&'storage mut [Entry<T>]);

#[cfg(test)]
impl<T> AsRef<[Entry<T>]> for Borrowed<'_, T> {
    fn as_ref(&self) -> &[Entry<T>] {
        self.0
    }
}

#[cfg(test)]
impl<T> AsMut<[Entry<T>]> for Borrowed<'_, T> {
    fn as_mut(&mut self) -> &mut [Entry<T>] {
        self.0
    }
}

#[cfg(test)]
impl<T> Drop for Borrowed<'_, T> {
    fn drop(&mut self) {
        self.0.fill_with(Entry::vacant);
    }
}

#[cfg(test)]
impl<'storage, T> Table<T, Borrowed<'storage, T>> {
    fn in_storage(entries: &'storage mut [Entry<T>]) -> Self {
        entries.fill_with(Entry::vacant);
        Self::start(Borrowed(entries))
    }
}

#[cfg(test)]
mod tests;
