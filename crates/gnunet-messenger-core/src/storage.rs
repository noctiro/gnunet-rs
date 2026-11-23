//! Shared owned and caller-owned contiguous storage.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::marker::PhantomData;

pub(crate) enum Backing<T, B> {
    #[cfg(feature = "alloc")]
    Owned(Vec<T>),
    Fixed(B, PhantomData<fn() -> T>),
}

impl<T, B> Backing<T, B> {
    pub const fn fixed(cells: B) -> Self {
        Self::Fixed(cells, PhantomData)
    }

    pub fn fixed_mut(&mut self) -> Option<&mut B> {
        match self {
            #[cfg(feature = "alloc")]
            Self::Owned(_) => None,
            Self::Fixed(cells, _) => Some(cells),
        }
    }

    pub fn into_fixed(self) -> Option<B> {
        match self {
            #[cfg(feature = "alloc")]
            Self::Owned(_) => None,
            Self::Fixed(cells, _) => Some(cells),
        }
    }
}

impl<T, B: AsRef<[T]>> Backing<T, B> {
    pub fn capacity(&self) -> usize {
        match self {
            #[cfg(feature = "alloc")]
            Self::Owned(cells) => cells.capacity(),
            Self::Fixed(cells, _) => cells.as_ref().len(),
        }
    }
}

impl<T, B: AsRef<[T]>> AsRef<[T]> for Backing<T, B> {
    fn as_ref(&self) -> &[T] {
        match self {
            #[cfg(feature = "alloc")]
            Self::Owned(cells) => cells,
            Self::Fixed(cells, _) => cells.as_ref(),
        }
    }
}

impl<T, B: AsMut<[T]>> AsMut<[T]> for Backing<T, B> {
    fn as_mut(&mut self) -> &mut [T] {
        match self {
            #[cfg(feature = "alloc")]
            Self::Owned(cells) => cells,
            Self::Fixed(cells, _) => cells.as_mut(),
        }
    }
}
