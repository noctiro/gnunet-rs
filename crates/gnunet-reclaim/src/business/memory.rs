use super::Limits;
use alloc::{rc::Rc, vec::Vec};
use core::{
    alloc::Layout,
    cell::Cell,
    fmt, mem,
    ops::{Deref, DerefMut},
};
use gnunet_types::Error;
use zeroize::Zeroizing;
pub(super) struct Quota {
    pub limits: Limits,
    pub used: Cell<usize>,
    pub jobs: Cell<usize>,
    pub sources: Cell<usize>,
    pub serial: Cell<u64>,
}
pub(super) struct Lease {
    quota: Rc<Quota>,
    bytes: usize,
}
impl Quota {
    pub fn reserve(self: &Rc<Self>, bytes: usize) -> Result<Lease, Error> {
        let next = self.used.get().checked_add(bytes).ok_or(Error::Overflow)?;
        if next > self.limits.bytes {
            return Err(Error::Capacity);
        }
        self.used.set(next);
        Ok(Lease {
            quota: self.clone(),
            bytes,
        })
    }
    pub fn next(&self) -> Result<u64, Error> {
        let n = self.serial.get().checked_add(1).ok_or(Error::Overflow)?;
        self.serial.set(n);
        Ok(n)
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.quota
            .used
            .set(self.quota.used.get().saturating_sub(self.bytes));
    }
}
/// One zeroizing immutable business payload; diagnostics expose only its size.
/// No Clone/Hash/Serialize or ownership extraction exposes private material.
pub struct Blob {
    bytes: Zeroizing<Vec<u8>>,
    _lease: Lease,
}
impl Blob {
    pub(super) fn encode(
        quota: &Rc<Quota>,
        len: usize,
        encode: impl FnOnce(&mut [u8]) -> Result<usize, Error>,
    ) -> Result<Self, Error> {
        if len > quota.limits.frame_bytes {
            return Err(Error::TooLarge);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.try_reserve_exact(len).map_err(|_| Error::Capacity)?;
        let lease = quota.reserve(
            bytes
                .capacity()
                .checked_add(mem::size_of::<Self>())
                .ok_or(Error::Overflow)?,
        )?;
        bytes.resize(len, 0);
        if encode(&mut bytes)? != len {
            return Err(Error::Malformed);
        }
        Ok(Self {
            bytes,
            _lease: lease,
        })
    }
    pub(super) fn copy(quota: &Rc<Quota>, bytes: &[u8]) -> Result<Self, Error> {
        Self::encode(quota, bytes.len(), |out| {
            out.copy_from_slice(bytes);
            Ok(bytes.len())
        })
    }
    /// Explicit sensitive borrow; neither payload nor key bytes enter Debug.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }
    /// Exact serialized length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    /// Whether the original serialization is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}
impl fmt::Debug for Blob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReclaimBlob")
            .field("bytes", &self.len())
            .finish_non_exhaustive()
    }
}
pub(super) struct Table<T> {
    values: Vec<T>,
    maximum: usize,
    quota: Rc<Quota>,
    _lease: Lease,
}
impl<T> Table<T> {
    pub fn new(quota: &Rc<Quota>, maximum: usize) -> Result<Self, Error> {
        let lease = quota.reserve(mem::size_of::<Self>())?;
        Ok(Self {
            values: Vec::new(),
            maximum,
            quota: quota.clone(),
            _lease: lease,
        })
    }
    pub fn push(&mut self, value: T) -> Result<(), Error> {
        if self.values.len() == self.maximum {
            return Err(Error::Capacity);
        }
        if self.values.len() == self.values.capacity() {
            let target = self
                .values
                .capacity()
                .saturating_mul(2)
                .max(4)
                .min(self.maximum);
            let mut values = Vec::new();
            values
                .try_reserve_exact(target)
                .map_err(|_| Error::Capacity)?;
            let lease = self.quota.reserve(
                values
                    .capacity()
                    .checked_mul(mem::size_of::<T>())
                    .and_then(|n| n.checked_add(mem::size_of::<Self>()))
                    .ok_or(Error::Overflow)?,
            )?;
            values.append(&mut self.values);
            self.values = values;
            self._lease = lease;
        }
        self.values.push(value);
        Ok(())
    }
    pub fn clear(&mut self) {
        self.values.clear();
    }
    /// Release phase-local values and allocation without reserving a replacement.
    /// This table still owns its fixed metadata lease and original count policy.
    pub fn release(&mut self) {
        self.values = Vec::new();
        let retained = mem::size_of::<Self>();
        let released = self._lease.bytes.saturating_sub(retained);
        self._lease.bytes -= released;
        self.quota
            .used
            .set(self.quota.used.get().saturating_sub(released));
    }
}
impl<T> Deref for Table<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.values
    }
}
impl<T> DerefMut for Table<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.values
    }
}

pub(super) fn rc_cost<T>() -> Result<usize, Error> {
    let (layout, _) = Layout::new::<[usize; 2]>()
        .extend(Layout::new::<T>())
        .map_err(|_| Error::Overflow)?;
    Ok(layout.pad_to_align().size())
}
