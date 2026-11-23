//! Exclusive storage of original Messenger frames, drafts and private payloads.

use crate::Error;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::{cell::Cell, fmt, mem};
use gnunet_types::Error as Fault;
#[cfg(feature = "alloc")]
use zeroize::Zeroizing;
use zeroize::{Zeroize, ZeroizeOnDrop};

mod pool;
pub(crate) use pool::LocalOriginal;
pub use pool::{OriginalId, OriginalPool, OriginalPoolInstance, OriginalSlot};

mod sealed {
    pub trait Sealed {}
}

/// A sealed backing that keeps one original payload and erases it on drop.
pub trait OriginalStorage: sealed::Sealed + ZeroizeOnDrop {
    /// Logical payload, without its unused storage.
    fn initialized(&self) -> &[u8];

    /// Total retained or exclusively reserved backing bytes.
    fn capacity(&self) -> usize;
}

/// Exclusive custody of original encoded bytes. Moving this value transfers
/// custody without copying. Access is explicit and debug output is redacted.
pub struct OriginalBytes<S: OriginalStorage>(S);

impl<S: OriginalStorage> OriginalBytes<S> {
    /// Read only the original payload. A separately made copy is the caller's
    /// responsibility to erase.
    pub fn expose(&self) -> &[u8] {
        self.0.initialized()
    }

    /// Actual capacity reserved while this owner is alive.
    pub fn capacity(&self) -> usize {
        self.0.capacity()
    }

    /// Length of the original payload.
    pub fn len(&self) -> usize {
        self.expose().len()
    }

    /// Whether the original payload is empty.
    pub fn is_empty(&self) -> bool {
        self.expose().is_empty()
    }
}

impl<S: OriginalStorage> fmt::Debug for OriginalBytes<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OriginalBytes([REDACTED])")
            .field("length", &self.len())
            .finish()
    }
}

impl<S: OriginalStorage> ZeroizeOnDrop for OriginalBytes<S> {}

/// Original bytes with exclusive heap ownership.
#[cfg(feature = "alloc")]
pub type OwnedBytes = OriginalBytes<HeapStorage>;

/// Heap backing for [`OwnedBytes`].
#[cfg(feature = "alloc")]
#[doc(hidden)]
pub struct HeapStorage(Zeroizing<Vec<u8>>);

#[cfg(feature = "alloc")]
impl sealed::Sealed for HeapStorage {}

#[cfg(feature = "alloc")]
impl ZeroizeOnDrop for HeapStorage {}

#[cfg(feature = "alloc")]
impl OriginalStorage for HeapStorage {
    fn initialized(&self) -> &[u8] {
        &self.0
    }

    fn capacity(&self) -> usize {
        self.0.capacity()
    }
}

#[cfg(feature = "alloc")]
impl OwnedBytes {
    /// Adopt independently owned zeroizing storage without copying.
    pub fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(HeapStorage(bytes))
    }

    /// Copy once into an independently owned erased allocation.
    ///
    /// # Errors
    ///
    /// Returns capacity exhaustion if the heap does not grant the allocation.
    pub fn copy_from(bytes: &[u8]) -> Result<Self, Error> {
        let mut storage = Zeroizing::new(Vec::new());
        storage
            .try_reserve_exact(bytes.len())
            .map_err(|_| Fault::Capacity)?;
        storage.extend_from_slice(bytes);
        Ok(Self::new(storage))
    }
}

/// Original bytes backed by one caller-supplied slot. Dropping this owner
/// erases the whole slot before allowing another payload to use it.
pub type BorrowedBytes<'slot, 'storage> = OriginalBytes<SlotStorage<'slot, 'storage>>;

/// One reusable byte region for a local task. Give separate slots disjoint
/// mutable slices to keep several originals alive at the same time.
pub struct ByteSlot<'storage> {
    available: Cell<Option<&'storage mut [u8]>>,
    capacity: usize,
}

impl<'storage> ByteSlot<'storage> {
    /// Erase and reserve the caller's initialized backing without allocating.
    pub fn new(storage: &'storage mut [u8]) -> Self {
        let capacity = storage.len();
        storage.zeroize();
        Self {
            available: Cell::new(Some(storage)),
            capacity,
        }
    }

    /// Total supplied bytes, including while the slot is checked out.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Copy one original payload into this slot.
    ///
    /// # Errors
    ///
    /// Returns capacity exhaustion when the slot is busy or too short.
    pub fn copy_from(&self, bytes: &[u8]) -> Result<BorrowedBytes<'_, 'storage>, Error> {
        self.write(bytes.len(), |destination| {
            destination.copy_from_slice(bytes);
            Ok(())
        })
    }

    /// Fill an initially erased region of exactly `len` bytes and transfer its
    /// custody. A failed writer erases the whole slot and returns it to reuse.
    ///
    /// # Errors
    ///
    /// Returns capacity exhaustion when the slot is busy or too short, or the
    /// writer's original error.
    pub fn write(
        &self,
        len: usize,
        write: impl FnOnce(&mut [u8]) -> Result<(), Error>,
    ) -> Result<BorrowedBytes<'_, 'storage>, Error> {
        if len > self.capacity {
            return Err(Fault::Capacity.into());
        }
        let storage = self.available.take().ok_or(Fault::Capacity)?;
        let owner = SlotStorage {
            slot: self,
            storage,
            len,
        };
        write(&mut owner.storage[..len])?;
        Ok(OriginalBytes(owner))
    }
}

impl fmt::Debug for ByteSlot<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ByteSlot")
            .field("capacity", &self.capacity())
            .finish_non_exhaustive()
    }
}

/// Caller-supplied backing for [`BorrowedBytes`].
#[doc(hidden)]
pub struct SlotStorage<'slot, 'storage> {
    slot: &'slot ByteSlot<'storage>,
    storage: &'storage mut [u8],
    len: usize,
}

impl sealed::Sealed for SlotStorage<'_, '_> {}

impl ZeroizeOnDrop for SlotStorage<'_, '_> {}

impl OriginalStorage for SlotStorage<'_, '_> {
    fn initialized(&self) -> &[u8] {
        &self.storage[..self.len]
    }

    fn capacity(&self) -> usize {
        self.storage.len()
    }
}

impl Drop for SlotStorage<'_, '_> {
    fn drop(&mut self) {
        let storage = mem::take(&mut self.storage);
        storage.zeroize();
        self.slot.available.set(Some(storage));
    }
}

#[cfg(test)]
mod tests;
