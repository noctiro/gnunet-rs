//! Generation-checked finite object slots and complete checkpoints.
use gnunet_types::{Error, GenerationalId, Rejected};

struct Slot<T> {
    value: Option<T>,
    generation: u32,
    retired: bool,
}

/// One immutable checkpoint entry. Restoring it grants no external resource authority.
pub struct SlotCheckpoint<T> {
    /// Original generation, including the floor of an empty slot.
    pub generation: u32,
    /// A generation-exhausted slot is permanently unavailable.
    pub retired: bool,
    /// Original live value, absent for an empty or retired slot.
    pub value: Option<T>,
}

/// A finite object table rejecting stale asynchronous completions without tombstone growth.
pub struct SlotTable<T, const N: usize> {
    slots: [Slot<T>; N],
    len: usize,
}

impl<T, const N: usize> Default for SlotTable<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> SlotTable<T, N> {
    /// Borrow every slot, including empty generation floors, without changing ownership.
    pub fn checkpoint(&self) -> [SlotCheckpoint<&T>; N] {
        core::array::from_fn(|index| {
            let slot = &self.slots[index];
            SlotCheckpoint {
                generation: slot.generation,
                retired: slot.retired,
                value: slot.value.as_ref(),
            }
        })
    }
    /// Restore a complete finite table. Invalid entries reject the whole checkpoint.
    /// The caller must establish the provenance of values and any external capabilities.
    pub fn from_checkpoint(entries: [SlotCheckpoint<T>; N]) -> Result<Self, Error> {
        if N > u32::MAX as usize
            || entries.iter().any(|entry| {
                entry.generation == 0
                    || (entry.retired && (entry.generation != u32::MAX || entry.value.is_some()))
            })
        {
            return Err(Error::Malformed);
        }
        let len = entries.iter().filter(|entry| entry.value.is_some()).count();
        Ok(Self {
            slots: entries.map(|entry| Slot {
                generation: entry.generation,
                retired: entry.retired,
                value: entry.value,
            }),
            len,
        })
    }
    /// Create an empty table. Generation exhaustion permanently retires its individual slot.
    #[must_use]
    pub fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| Slot {
                value: None,
                generation: 1,
                retired: false,
            }),
            len: 0,
        }
    }
    /// Number of occupied objects.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }
    /// Whether the table has no live objects.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// Number of slots that can actually accept a value. Permanently retired generations
    /// are excluded even though they no longer contain a live object.
    #[must_use]
    pub fn insertion_capacity(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.value.is_none() && !slot.retired)
            .count()
    }
    /// Insert into an available non-retired slot, returning ownership on rejection.
    pub fn insert(&mut self, value: T) -> Result<GenerationalId, Rejected<T>> {
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if slot.value.is_none() && !slot.retired {
                let Ok(index) = u32::try_from(index) else {
                    return Err(Rejected {
                        value,
                        reason: Error::Overflow,
                    });
                };
                slot.value = Some(value);
                self.len += 1;
                return Ok(GenerationalId {
                    index,
                    generation: slot.generation,
                });
            }
        }
        Err(Rejected {
            value,
            reason: Error::Capacity,
        })
    }
    /// Borrow an object only when both its slot and generation still match.
    pub fn get(&self, id: GenerationalId) -> Result<&T, Error> {
        let index = usize::try_from(id.index).map_err(|_| Error::StaleGeneration)?;
        let slot = self.slots.get(index).ok_or(Error::StaleGeneration)?;
        if slot.generation != id.generation {
            return Err(Error::StaleGeneration);
        }
        slot.value.as_ref().ok_or(Error::StaleGeneration)
    }
    /// Exclusively borrow a matching live object.
    pub fn get_mut(&mut self, id: GenerationalId) -> Result<&mut T, Error> {
        let index = usize::try_from(id.index).map_err(|_| Error::StaleGeneration)?;
        let slot = self.slots.get_mut(index).ok_or(Error::StaleGeneration)?;
        if slot.generation != id.generation {
            return Err(Error::StaleGeneration);
        }
        slot.value.as_mut().ok_or(Error::StaleGeneration)
    }
    /// Remove an object and advance its generation before allowing any slot reuse.
    pub fn remove(&mut self, id: GenerationalId) -> Result<T, Error> {
        let index = usize::try_from(id.index).map_err(|_| Error::StaleGeneration)?;
        let slot = self.slots.get_mut(index).ok_or(Error::StaleGeneration)?;
        if slot.generation != id.generation {
            return Err(Error::StaleGeneration);
        }
        let value = slot.value.take().ok_or(Error::StaleGeneration)?;
        match slot.generation.checked_add(1) {
            Some(next) => slot.generation = next,
            None => slot.retired = true,
        }
        self.len -= 1;
        Ok(value)
    }
    /// Replace one exact live owner while advancing its generation. Rejection preserves
    /// both the old value and generation, including exhausted generations and a full table.
    pub fn replace(
        &mut self,
        id: GenerationalId,
        value: T,
    ) -> Result<(GenerationalId, T), Rejected<T>> {
        let next = match self
            .get(id)
            .and_then(|_| id.generation.checked_add(1).ok_or(Error::Overflow))
        {
            Ok(next) => next,
            Err(reason) => return Err(Rejected { value, reason }),
        };
        let Ok(index) = usize::try_from(id.index) else {
            return Err(Rejected {
                value,
                reason: Error::StaleGeneration,
            });
        };
        let slot = &mut self.slots[index];
        let Some(previous) = slot.value.as_mut() else {
            return Err(Rejected {
                value,
                reason: Error::StaleGeneration,
            });
        };
        let old = core::mem::replace(previous, value);
        slot.generation = next;
        Ok((
            GenerationalId {
                generation: next,
                ..id
            },
            old,
        ))
    }
    /// Borrow all live identifiers and values without allocation.
    pub fn iter(&self) -> impl Iterator<Item = (GenerationalId, &T)> {
        self.slots.iter().enumerate().filter_map(|(index, slot)| {
            let index = u32::try_from(index).ok()?;
            slot.value.as_ref().map(|value| {
                (
                    GenerationalId {
                        index,
                        generation: slot.generation,
                    },
                    value,
                )
            })
        })
    }
    /// Mutably borrow all live values in slot order, preserving their identifiers,
    /// generation floors and occupied-slot count.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (GenerationalId, &mut T)> {
        self.slots
            .iter_mut()
            .enumerate()
            .filter_map(|(index, slot)| {
                let index = u32::try_from(index).ok()?;
                let generation = slot.generation;
                slot.value
                    .as_mut()
                    .map(|value| (GenerationalId { index, generation }, value))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutable_iteration_preserves_holes_generations_and_retired_slots() -> Result<(), Error> {
        let mut table = SlotTable::from_checkpoint([
            SlotCheckpoint {
                generation: 7,
                retired: false,
                value: None,
            },
            SlotCheckpoint {
                generation: 3,
                retired: false,
                value: Some(11_u8),
            },
            SlotCheckpoint {
                generation: u32::MAX,
                retired: true,
                value: None,
            },
            SlotCheckpoint {
                generation: u32::MAX,
                retired: false,
                value: Some(13),
            },
        ])?;
        let expected = [
            (
                GenerationalId {
                    index: 1,
                    generation: 3,
                },
                11,
            ),
            (
                GenerationalId {
                    index: 3,
                    generation: u32::MAX,
                },
                13,
            ),
        ];
        let mut seen = 0;
        for (id, value) in table.iter_mut() {
            if expected.get(seen) != Some(&(id, *value)) {
                return Err(Error::Conflict);
            }
            *value += 10;
            seen += 1;
        }
        if seen != expected.len()
            || table.len() != 2
            || table.insertion_capacity() != 1
            || table.get(expected[0].0) != Ok(&21)
            || table.get(expected[1].0) != Ok(&23)
        {
            return Err(Error::Conflict);
        }
        let hole = table.insert(17).map_err(|r| r.reason)?;
        if hole
            != (GenerationalId {
                index: 0,
                generation: 7,
            })
            || table.remove(expected[0].0)? != 21
            || table.remove(expected[1].0)? != 23
        {
            return Err(Error::Conflict);
        }
        let reused = table.insert(19).map_err(|r| r.reason)?;
        if reused
            != (GenerationalId {
                index: 1,
                generation: 4,
            })
            || table.get(expected[0].0) != Err(Error::StaleGeneration)
            || table.get(expected[1].0) != Err(Error::StaleGeneration)
            || table.insertion_capacity() != 0
            || SlotTable::<u8, 0>::new().iter_mut().next().is_some()
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    #[test]
    fn complete_slot_checkpoint_keeps_empty_floors_and_generation_exhaustion() -> Result<(), Error>
    {
        let mut table = SlotTable::<u8, 1>::new();
        let old = table.insert(7).map_err(|r| r.reason)?;
        if table.remove(old)? != 7 {
            return Err(Error::Conflict);
        }
        let checkpoint = table.checkpoint().map(|entry| SlotCheckpoint {
            generation: entry.generation,
            retired: entry.retired,
            value: entry.value.copied(),
        });
        let mut restored = SlotTable::from_checkpoint(checkpoint)?;
        let next = restored.insert(8).map_err(|r| r.reason)?;
        if next.generation != old.generation + 1
            || restored.get(old).err() != Some(Error::StaleGeneration)
        {
            return Err(Error::Conflict);
        }
        let (replacement, retired) = restored.replace(next, 9).map_err(|r| r.reason)?;
        if retired != 8
            || replacement.generation != next.generation + 1
            || restored.get(next).err() != Some(Error::StaleGeneration)
            || restored.len() != 1
            || restored.get(replacement) != Ok(&9)
            || restored
                .replace(next, 10)
                .err()
                .map(|r| (r.value, r.reason))
                != Some((10, Error::StaleGeneration))
            || restored.get(replacement) != Ok(&9)
        {
            return Err(Error::Conflict);
        }
        let mut last = SlotTable::from_checkpoint([SlotCheckpoint {
            generation: u32::MAX,
            retired: false,
            value: Some(11_u8),
        }])?;
        let last_id = GenerationalId {
            index: 0,
            generation: u32::MAX,
        };
        if last.replace(last_id, 12).err().map(|r| (r.value, r.reason))
            != Some((12, Error::Overflow))
            || last.get(last_id) != Ok(&11)
            || last.len() != 1
        {
            return Err(Error::Conflict);
        }
        let mut exhausted = SlotTable::from_checkpoint([SlotCheckpoint::<u8> {
            generation: u32::MAX,
            retired: true,
            value: None,
        }])?;
        if exhausted.insertion_capacity() != 0
            || table.insertion_capacity() != 1
            || restored.insertion_capacity() != 0
            || exhausted.insert(9).err().map(|r| r.reason) != Some(Error::Capacity)
            || SlotTable::from_checkpoint([SlotCheckpoint::<u8> {
                generation: 0,
                retired: false,
                value: None,
            }])
            .err()
                != Some(Error::Malformed)
            || SlotTable::from_checkpoint([SlotCheckpoint {
                generation: u32::MAX,
                retired: true,
                value: Some(1_u8),
            }])
            .err()
                != Some(Error::Malformed)
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    #[test]
    fn stale_completion_cannot_access_reused_slot() -> Result<(), Error> {
        let mut table = SlotTable::<u8, 1>::new();
        let first = table.insert(1).map_err(|r| r.reason)?;
        table.remove(first)?;
        let next = table.insert(2).map_err(|r| r.reason)?;
        if first == next
            || table.get(first) != Err(Error::StaleGeneration)
            || table.get(next) != Ok(&2)
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }

    #[test]
    fn exhausted_generation_retires_slot() -> Result<(), Error> {
        let mut table = SlotTable::<u8, 1>::new();
        table.slots[0].generation = u32::MAX;
        let id = table.insert(1).map_err(|r| r.reason)?;
        table.remove(id)?;
        if table.insert(2).is_ok() || table.get(id).is_ok() {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}
