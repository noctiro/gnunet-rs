//! Shared fallible storage for the two compiler profiles.

use super::{BuildError, Limit};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};

pub(super) enum Buffer<'a, T> {
    Fixed {
        slots: &'a mut [T],
        len: usize,
    },
    #[cfg(feature = "alloc")]
    Heap(Vec<T>),
}

impl<'a, T> Buffer<'a, T> {
    pub(super) fn fixed(slots: &'a mut [T]) -> Self {
        Self::Fixed { slots, len: 0 }
    }

    #[cfg(feature = "alloc")]
    pub(super) fn heap() -> Self {
        Self::Heap(Vec::new())
    }

    fn reserve(&mut self, count: usize, max: usize, kind: Limit) -> Result<(), BuildError> {
        let end = self.len().checked_add(count).ok_or(BuildError::Overflow)?;
        if end > max {
            return Err(BuildError::Limit(kind));
        }
        match self {
            Self::Fixed { slots, .. } if end > slots.len() => Err(BuildError::Limit(kind)),
            Self::Fixed { .. } => Ok(()),
            #[cfg(feature = "alloc")]
            Self::Heap(items) => items.try_reserve(count).map_err(|_| BuildError::Allocation),
        }
    }

    pub(super) fn push(&mut self, value: T, max: usize, kind: Limit) -> Result<(), BuildError> {
        self.reserve(1, max, kind)?;
        match self {
            Self::Fixed { slots, len } => {
                slots[*len] = value;
                *len += 1;
            }
            #[cfg(feature = "alloc")]
            Self::Heap(items) => items.push(value),
        }
        Ok(())
    }

    pub(super) fn extend_from_slice(
        &mut self,
        source: &[T],
        max: usize,
        kind: Limit,
    ) -> Result<(), BuildError>
    where
        T: Copy,
    {
        self.reserve(source.len(), max, kind)?;
        match self {
            Self::Fixed { slots, len } => {
                let end = *len + source.len();
                slots[*len..end].copy_from_slice(source);
                *len = end;
            }
            #[cfg(feature = "alloc")]
            Self::Heap(items) => items.extend_from_slice(source),
        }
        Ok(())
    }

    pub(super) fn resize(
        &mut self,
        count: usize,
        value: T,
        max: usize,
        kind: Limit,
    ) -> Result<(), BuildError>
    where
        T: Clone,
    {
        self.reserve(count.saturating_sub(self.len()), max, kind)?;
        match self {
            Self::Fixed { slots, len } => {
                if count > *len {
                    slots[*len..count].fill(value);
                }
                *len = count;
            }
            #[cfg(feature = "alloc")]
            Self::Heap(items) => items.resize(count, value),
        }
        Ok(())
    }

    pub(super) fn pop(&mut self) -> Option<T>
    where
        T: Copy,
    {
        let value = self.last().copied()?;
        self.truncate(self.len() - 1);
        Some(value)
    }

    pub(super) fn clear(&mut self) {
        self.truncate(0);
    }

    pub(super) fn release(&mut self) {
        match self {
            Self::Fixed { len, .. } => *len = 0,
            #[cfg(feature = "alloc")]
            Self::Heap(items) => *items = Vec::new(),
        }
    }

    pub(super) fn truncate(&mut self, count: usize) {
        match self {
            Self::Fixed { len, .. } => *len = (*len).min(count),
            #[cfg(feature = "alloc")]
            Self::Heap(items) => items.truncate(count),
        }
    }
}

impl<T> Deref for Buffer<'_, T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        match self {
            Self::Fixed { slots, len } => &slots[..*len],
            #[cfg(feature = "alloc")]
            Self::Heap(items) => items,
        }
    }
}

impl<T> DerefMut for Buffer<'_, T> {
    fn deref_mut(&mut self) -> &mut [T] {
        match self {
            Self::Fixed { slots, len } => &mut slots[..*len],
            #[cfg(feature = "alloc")]
            Self::Heap(items) => items,
        }
    }
}
