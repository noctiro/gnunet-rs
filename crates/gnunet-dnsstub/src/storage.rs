//! Backing selected by the inline or heap query profile.

use core::ops::{Deref, DerefMut};

mod sealed {
    pub trait Sealed {}
}

/// Backing for the copied query bytes and the owner's fixed-capacity tables.
pub trait QueryStorage: sealed::Sealed + AsRef<[u8]> + AsMut<[u8]> {
    /// Backing for one bounded request or server table.
    type Table<T, const CAPACITY: usize>: AsRef<[T]> + AsMut<[T]>;
}

impl<const N: usize> sealed::Sealed for [u8; N] {}
impl<const N: usize> QueryStorage for [u8; N] {
    type Table<T, const CAPACITY: usize> = [T; CAPACITY];
}

#[cfg(feature = "alloc")]
impl sealed::Sealed for alloc::boxed::Box<[u8]> {}
#[cfg(feature = "alloc")]
impl QueryStorage for alloc::boxed::Box<[u8]> {
    type Table<T, const CAPACITY: usize> = alloc::vec::Vec<T>;
}

pub(super) struct Table<Q: QueryStorage, T, const CAPACITY: usize>(Q::Table<T, CAPACITY>);

impl<Q: QueryStorage, T, const CAPACITY: usize> Table<Q, T, CAPACITY> {
    pub(super) fn new(entries: Q::Table<T, CAPACITY>) -> Self {
        Self(entries)
    }
}

impl<Q: QueryStorage, T, const CAPACITY: usize> Deref for Table<Q, T, CAPACITY> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        self.0.as_ref()
    }
}

impl<Q: QueryStorage, T, const CAPACITY: usize> DerefMut for Table<Q, T, CAPACITY> {
    fn deref_mut(&mut self) -> &mut [T] {
        self.0.as_mut()
    }
}
