//! Private backing containers. Protocol state and commits stay in service.rs.
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use core::mem::size_of;
use core::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
};
use gnunet_types::Error;

pub(crate) enum Table<T, const N: usize> {
    Fixed([T; N]),
    #[cfg(feature = "alloc")]
    Allocated(Vec<T>),
}
pub(crate) struct Growth<T> {
    #[cfg(feature = "alloc")]
    replacement: Option<Vec<T>>,
    marker: PhantomData<T>,
}
impl<T> Growth<T> {
    pub(crate) fn capacity_after(&self, old: usize) -> usize {
        #[cfg(feature = "alloc")]
        if let Some(replacement) = &self.replacement {
            return replacement.capacity();
        }
        old
    }
    pub(crate) fn extra_bytes(&self, old: usize) -> Result<usize, Error> {
        #[cfg(feature = "alloc")]
        if let Some(replacement) = &self.replacement {
            return replacement
                .capacity()
                .checked_sub(old)
                .and_then(|n| n.checked_mul(size_of::<T>()))
                .ok_or(Error::Overflow);
        }
        let _ = old;
        Ok(0)
    }
}
impl<T, const N: usize> Table<T, N> {
    pub(crate) const fn fixed(value: [T; N]) -> Self {
        Self::Fixed(value)
    }
    #[cfg(feature = "alloc")]
    pub(crate) fn allocated() -> Self {
        Self::Allocated(Vec::new())
    }
    pub(crate) fn capacity(&self) -> usize {
        match self {
            Self::Fixed(_) => N,
            #[cfg(feature = "alloc")]
            Self::Allocated(v) => v.capacity(),
        }
    }
    pub(crate) fn retained_bytes(&self) -> Result<usize, Error> {
        match self {
            Self::Fixed(_) => Ok(0),
            #[cfg(feature = "alloc")]
            Self::Allocated(v) => v
                .capacity()
                .checked_mul(size_of::<T>())
                .ok_or(Error::Overflow),
        }
    }
    pub(crate) fn prepare(
        &self,
        needed: usize,
        maximum: usize,
        geometric: bool,
    ) -> Result<Growth<T>, Error> {
        #[cfg(feature = "alloc")]
        if let Self::Allocated(current) = self
            && needed > current.capacity()
        {
            // Allocate an unpublished replacement. An allocator rounding or
            // quota refusal never leaves an over-budget published table.
            let target = if geometric {
                current
                    .capacity()
                    .saturating_mul(2)
                    .max(needed)
                    .min(maximum)
            } else {
                needed
            };
            let mut replacement = Vec::new();
            replacement
                .try_reserve_exact(target)
                .map_err(|_| Error::Capacity)?;
            return Ok(Growth {
                replacement: Some(replacement),
                marker: PhantomData,
            });
        }
        let _ = (maximum, geometric);
        if needed > self.capacity() {
            return Err(Error::Capacity);
        }
        Ok(Growth {
            #[cfg(feature = "alloc")]
            replacement: None,
            marker: PhantomData,
        })
    }
    pub(crate) fn commit(&mut self, plan: Growth<T>, needed: usize, mut vacant: impl FnMut() -> T) {
        #[cfg(feature = "alloc")]
        if let Self::Allocated(current) = self {
            if let Some(mut replacement) = plan.replacement {
                replacement.append(current);
                *current = replacement;
            }
            current.resize_with(needed, &mut vacant);
            return;
        }
        let _fixed_plan = (plan, needed, &mut vacant);
    }
}
impl<T, const N: usize> Deref for Table<T, N> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        match self {
            Self::Fixed(v) => v,
            #[cfg(feature = "alloc")]
            Self::Allocated(v) => v,
        }
    }
}
impl<T, const N: usize> DerefMut for Table<T, N> {
    fn deref_mut(&mut self) -> &mut [T] {
        match self {
            Self::Fixed(v) => v,
            #[cfg(feature = "alloc")]
            Self::Allocated(v) => v,
        }
    }
}
pub(crate) enum Names<const N: usize> {
    Fixed([u8; N]),
    #[cfg(feature = "alloc")]
    Allocated(Vec<u8>),
}
impl<const N: usize> Names<N> {
    pub(crate) fn new(subsystem: &[u8], name: &[u8], allocated: bool) -> Result<Self, Error> {
        let needed = subsystem
            .len()
            .checked_add(name.len())
            .and_then(|n| n.checked_add(2))
            .ok_or(Error::Overflow)?;
        #[cfg(feature = "alloc")]
        if allocated {
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(needed)
                .map_err(|_| Error::Capacity)?;
            bytes.resize(needed, 0);
            bytes[..subsystem.len()].copy_from_slice(subsystem);
            bytes[subsystem.len() + 1..needed - 1].copy_from_slice(name);
            return Ok(Self::Allocated(bytes));
        }
        let _ = allocated;
        if needed > N {
            return Err(Error::Capacity);
        }
        let mut bytes = [0; N];
        bytes[..subsystem.len()].copy_from_slice(subsystem);
        bytes[subsystem.len() + 1..needed - 1].copy_from_slice(name);
        Ok(Self::Fixed(bytes))
    }
    pub(crate) fn retained_bytes(&self) -> usize {
        match self {
            Self::Fixed(_) => 0,
            #[cfg(feature = "alloc")]
            Self::Allocated(v) => v.capacity(),
        }
    }
}
impl<const N: usize> Deref for Names<N> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Self::Fixed(v) => v,
            #[cfg(feature = "alloc")]
            Self::Allocated(v) => v,
        }
    }
}
