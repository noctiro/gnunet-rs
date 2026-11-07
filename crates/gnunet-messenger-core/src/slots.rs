//! Fixed-capacity metadata tables. Insertion/removal allocates no memory and
//! every reused position gets a fresh generation. Payload allocation is separate.
use crate::{Error, Slot};
use alloc::vec::Vec;
use gnunet_types::Error as Fault;
struct Entry<T> {
    generation: u64,
    value: Option<T>,
}
pub(crate) struct Slots<T> {
    entries: Vec<Entry<T>>,
    free: Vec<usize>,
    live: usize,
}
impl<T> Slots<T> {
    pub fn new(limit: usize) -> Result<Self, Error> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(limit)
            .map_err(|_| Fault::Capacity)?;
        entries.resize_with(limit, || Entry {
            generation: 0,
            value: None,
        });
        let mut free = Vec::new();
        free.try_reserve_exact(limit).map_err(|_| Fault::Capacity)?;
        free.extend((0..limit).rev());
        Ok(Self {
            entries,
            free,
            live: 0,
        })
    }
    pub fn bytes(&self) -> Result<usize, Error> {
        self.entries
            .capacity()
            .checked_mul(core::mem::size_of::<Entry<T>>())
            .and_then(|n| {
                self.free
                    .capacity()
                    .checked_mul(core::mem::size_of::<usize>())
                    .and_then(|b| n.checked_add(b))
            })
            .ok_or_else(|| Fault::Overflow.into())
    }
    pub fn len(&self) -> usize {
        self.live
    }
    pub fn required_bytes(limit: usize) -> Result<usize, Error> {
        limit
            .checked_mul(core::mem::size_of::<Entry<T>>() + core::mem::size_of::<usize>())
            .ok_or_else(|| Fault::Overflow.into())
    }
    pub fn limit(&self) -> usize {
        self.entries.len()
    }
    pub fn slot_at(&self, index: usize) -> Option<Slot> {
        self.entries.get(index).and_then(|e| {
            e.value.as_ref().map(|_| Slot {
                index,
                generation: e.generation,
            })
        })
    }
    pub fn next_key(&self) -> Result<Slot, Error> {
        let index = *self.free.last().ok_or(Fault::Capacity)?;
        let generation = self.entries[index]
            .generation
            .checked_add(1)
            .ok_or(Fault::Overflow)?;
        Ok(Slot { index, generation })
    }
    pub fn insert(&mut self, value: T) -> Result<Slot, (Error, T)> {
        let Some(&index) = self.free.last() else {
            return Err((Fault::Capacity.into(), value));
        };
        let Some(generation) = self.entries[index].generation.checked_add(1) else {
            return Err((Fault::Overflow.into(), value));
        };
        self.free.pop();
        self.entries[index] = Entry {
            generation,
            value: Some(value),
        };
        self.live += 1;
        Ok(Slot { index, generation })
    }
    pub fn get(&self, id: Slot) -> Result<&T, Error> {
        self.entries
            .get(id.index)
            .filter(|e| e.generation == id.generation)
            .and_then(|e| e.value.as_ref())
            .ok_or_else(|| Fault::StaleGeneration.into())
    }
    pub fn get_mut(&mut self, id: Slot) -> Result<&mut T, Error> {
        self.entries
            .get_mut(id.index)
            .filter(|e| e.generation == id.generation)
            .and_then(|e| e.value.as_mut())
            .ok_or_else(|| Fault::StaleGeneration.into())
    }
    pub fn remove(&mut self, id: Slot) -> Result<T, Error> {
        let e = self
            .entries
            .get_mut(id.index)
            .filter(|e| e.generation == id.generation)
            .ok_or(Fault::StaleGeneration)?;
        let value = e.value.take().ok_or(Fault::StaleGeneration)?;
        self.free.push(id.index);
        self.live -= 1;
        Ok(value)
    }
    pub fn iter(&self) -> impl Iterator<Item = (Slot, &T)> {
        self.entries.iter().enumerate().filter_map(|(index, e)| {
            e.value.as_ref().map(|v| {
                (
                    Slot {
                        index,
                        generation: e.generation,
                    },
                    v,
                )
            })
        })
    }
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (Slot, &mut T)> {
        self.entries
            .iter_mut()
            .enumerate()
            .filter_map(|(index, e)| {
                e.value.as_mut().map(|v| {
                    (
                        Slot {
                            index,
                            generation: e.generation,
                        },
                        v,
                    )
                })
            })
    }
    /// Recovery-only staging into an invisible new owner. This issues no public
    /// handle/source and is finished before the recovered Core is returned.
    pub(crate) fn restore_entry(
        &mut self,
        index: usize,
        generation: u64,
        value: T,
    ) -> Result<(), Error> {
        let entry = self.entries.get_mut(index).ok_or(Fault::Capacity)?;
        if generation == 0 || entry.value.is_some() {
            return Err(Fault::Malformed.into());
        }
        entry.generation = generation;
        entry.value = Some(value);
        self.live += 1;
        Ok(())
    }
    /// Rebuild the fixed free index once, without reallocating or reissuing a
    /// previous Core's brand. Existing generation counters remain monotonic.
    pub(crate) fn finish_restore(&mut self) {
        self.free.clear();
        for (index, entry) in self.entries.iter().enumerate().rev() {
            if entry.value.is_none() {
                self.free.push(index)
            }
        }
    }
}
