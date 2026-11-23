//! Bounded resolver slot storage profiles.

use core::ops::{Deref, DerefMut};

mod sealed {
    pub trait Sealed {}
}

/// Allocation profile for a resolver handle's request table.
pub trait SlotStorage: sealed::Sealed {
    /// Backing for the fixed number of initialized slots.
    type Entries<T, const CAPACITY: usize>: AsRef<[T]> + AsMut<[T]>;
}

/// Store all request slots inline without allocating.
pub enum InlineSlots {}

impl sealed::Sealed for InlineSlots {}
impl SlotStorage for InlineSlots {
    type Entries<T, const CAPACITY: usize> = [T; CAPACITY];
}

/// Store all request slots on the heap.
#[cfg(feature = "alloc")]
pub enum HeapSlots {}

#[cfg(feature = "alloc")]
impl sealed::Sealed for HeapSlots {}
#[cfg(feature = "alloc")]
impl SlotStorage for HeapSlots {
    type Entries<T, const CAPACITY: usize> = alloc::vec::Vec<T>;
}

pub(super) struct Table<S: SlotStorage, T, const CAPACITY: usize>(S::Entries<T, CAPACITY>);

impl<S: SlotStorage, T, const CAPACITY: usize> Table<S, T, CAPACITY> {
    pub(super) fn new(entries: S::Entries<T, CAPACITY>) -> Self {
        Self(entries)
    }
}

impl<S: SlotStorage, T, const CAPACITY: usize> Deref for Table<S, T, CAPACITY> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        self.0.as_ref()
    }
}

impl<S: SlotStorage, T, const CAPACITY: usize> DerefMut for Table<S, T, CAPACITY> {
    fn deref_mut(&mut self) -> &mut [T] {
        self.0.as_mut()
    }
}
