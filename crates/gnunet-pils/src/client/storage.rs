//! Sealed owned byte storage shared by inline and native allocation profiles.
use core::ops::{Deref, DerefMut};
use gnunet_types::Error;
use zeroize::Zeroizing;
mod sealed {
    pub trait Sealed {}
}
/// Owned bytes erased on drop. The sealed implementations differ only in
/// storage placement; protocol state and request/epoch correlation are shared.
pub trait ByteStorage: sealed::Sealed + Deref<Target = [u8]> + DerefMut {
    /// Allocate/initialize the requested logical length without I/O. Inline
    /// storage retains its declared fixed capacity; native storage uses exact len.
    fn zeroed(length: usize) -> Result<Self, Error>
    where
        Self: Sized;
    /// Actual dynamic allocation capacity; inline storage is counted by its
    /// enclosing fixed owner and therefore contributes zero here.
    fn retained_storage_bytes(&self) -> usize;
}
/// Allocation-free fixed-capacity bytes, erased when the owner is dropped.
pub struct InlineBytes<const N: usize>(Zeroizing<[u8; N]>);
impl<const N: usize> sealed::Sealed for InlineBytes<N> {}
impl<const N: usize> ByteStorage for InlineBytes<N> {
    fn zeroed(length: usize) -> Result<Self, Error> {
        if length > N {
            return Err(Error::Capacity);
        }
        Ok(Self(Zeroizing::new([0; N])))
    }
    fn retained_storage_bytes(&self) -> usize {
        0
    }
}
impl<const N: usize> Deref for InlineBytes<N> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0[..]
    }
}
impl<const N: usize> DerefMut for InlineBytes<N> {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }
}
/// Native exact-length request/announcement storage. This optional backing does
/// not enable platform I/O or change any protocol rules. No Clone/Debug exists.
#[cfg(feature = "alloc")]
pub struct HeapBytes(Zeroizing<alloc::vec::Vec<u8>>);
#[cfg(feature = "alloc")]
impl sealed::Sealed for HeapBytes {}
#[cfg(feature = "alloc")]
impl ByteStorage for HeapBytes {
    fn zeroed(length: usize) -> Result<Self, Error> {
        let mut bytes = alloc::vec::Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| Error::Capacity)?;
        bytes.resize(length, 0);
        Ok(Self(Zeroizing::new(bytes)))
    }
    fn retained_storage_bytes(&self) -> usize {
        self.0.capacity()
    }
}
#[cfg(feature = "alloc")]
impl Deref for HeapBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}
#[cfg(feature = "alloc")]
impl DerefMut for HeapBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
