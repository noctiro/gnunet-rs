//! Direct slot lookup with non-reused opaque generations.
use core::num::NonZeroU64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Key(NonZeroU64);

impl Key {
    pub(super) const fn from_context(value: NonZeroU64) -> Self {
        Self(value)
    }

    pub(super) const fn context(self) -> NonZeroU64 {
        self.0
    }

    fn index(self) -> Option<usize> {
        (self.0.get() as u16).checked_sub(1).map(usize::from)
    }
}

struct Slot<T> {
    entry: Option<(Key, T)>,
    next_free: Option<u16>,
}

pub(super) struct Arena<T, const N: usize> {
    slots: [Slot<T>; N],
    virgin: usize,
    free: Option<u16>,
    sequence: u64,
}

impl<T, const N: usize> Arena<T, N> {
    pub(super) const fn new() -> Self {
        Self {
            slots: [const {
                Slot {
                    entry: None,
                    next_free: None,
                }
            }; N],
            virgin: 0,
            free: None,
            sequence: 1,
        }
    }

    pub(super) fn insert(&mut self, value: T) -> Option<Key> {
        let index = self.free.map_or(self.virgin, usize::from);
        let label = u64::from(u16::try_from(index.checked_add(1)?).ok()?);
        let slot = self.slots.get_mut(index)?;
        if self.sequence > u64::MAX >> 16 {
            return None;
        }
        let key = Key(NonZeroU64::new((self.sequence << 16) | label)?);
        if self.free.is_some() {
            self.free = slot.next_free.take();
        } else {
            self.virgin += 1;
        }
        self.sequence += 1;
        slot.entry = Some((key, value));
        Some(key)
    }

    pub(super) fn get(&self, key: Key) -> Option<&T> {
        let (owned, value) = self.slots.get(key.index()?)?.entry.as_ref()?;
        (*owned == key).then_some(value)
    }

    pub(super) fn get_mut(&mut self, key: Key) -> Option<&mut T> {
        let (owned, value) = self.slots.get_mut(key.index()?)?.entry.as_mut()?;
        (*owned == key).then_some(value)
    }

    pub(super) fn remove(&mut self, key: Key) -> Option<T> {
        let index = key.index()?;
        let slot = self.slots.get_mut(index)?;
        if slot.entry.as_ref()?.0 != key {
            return None;
        }
        slot.next_free = self.free.replace(u16::try_from(index).ok()?);
        slot.entry.take().map(|(_, value)| value)
    }

    pub(super) fn at(&self, index: usize) -> Option<(Key, &T)> {
        let (key, entry) = self.slots.get(index)?.entry.as_ref()?;
        Some((*key, entry))
    }

    pub(super) fn at_mut(&mut self, index: usize) -> Option<(Key, &mut T)> {
        let (key, entry) = self.slots.get_mut(index)?.entry.as_mut()?;
        Some((*key, entry))
    }

    pub(super) fn values(&self) -> impl Iterator<Item = &T> {
        self.slots[..self.virgin]
            .iter()
            .filter_map(|slot| slot.entry.as_ref().map(|(_, value)| value))
    }

    pub(super) fn values_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.slots[..self.virgin]
            .iter_mut()
            .filter_map(|slot| slot.entry.as_mut().map(|(_, value)| value))
    }
}
