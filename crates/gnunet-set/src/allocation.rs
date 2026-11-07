//! Preclaimed allocation peaks for one sequential core turn. No protocol state.
use alloc::{collections::VecDeque, vec::Vec};
use gnunet_types::Error;

/// Additional allowance whose caller already charged every entry owner,
/// including buffers later taken into locals. Claims are never refunded within
/// the turn: replacement/transient buffers cannot hide an old live allocation.
pub(crate) struct Growth {
    remaining: usize,
}
impl Growth {
    pub const fn new(remaining: usize) -> Self {
        Self { remaining }
    }
    pub fn claim(&mut self, bytes: usize) -> Result<(), Error> {
        self.remaining = self.remaining.checked_sub(bytes).ok_or(Error::Capacity)?;
        Ok(())
    }
    pub fn vector<T>(&mut self, capacity: usize) -> Result<Vec<T>, Error> {
        self.claim(
            capacity
                .checked_mul(core::mem::size_of::<T>())
                .ok_or(Error::Overflow)?,
        )?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(capacity)
            .map_err(|_| Error::Capacity)?;
        if values.capacity() > capacity {
            return Err(Error::Capacity);
        }
        Ok(values)
    }
    pub fn copy(&mut self, source: &[u8]) -> Result<Vec<u8>, Error> {
        let mut bytes = self.vector(source.len())?;
        bytes.extend_from_slice(source);
        Ok(bytes)
    }
    pub fn grow_vec<T>(&mut self, values: &mut Vec<T>, additional: usize) -> Result<(), Error> {
        let needed = values
            .len()
            .checked_add(additional)
            .ok_or(Error::Overflow)?;
        if needed <= values.capacity() {
            return Ok(());
        }
        let target = values
            .capacity()
            .checked_mul(2)
            .ok_or(Error::Overflow)?
            .max(4)
            .max(needed);
        let mut next = self.vector(target)?;
        next.append(values);
        *values = next;
        Ok(())
    }
    pub fn grow_deque<T>(
        &mut self,
        values: &mut VecDeque<T>,
        additional: usize,
    ) -> Result<(), Error> {
        let needed = values
            .len()
            .checked_add(additional)
            .ok_or(Error::Overflow)?;
        if needed <= values.capacity() {
            return Ok(());
        }
        let target = values
            .capacity()
            .checked_mul(2)
            .ok_or(Error::Overflow)?
            .max(4)
            .max(needed);
        self.claim(
            target
                .checked_mul(core::mem::size_of::<T>())
                .ok_or(Error::Overflow)?,
        )?;
        let mut next = VecDeque::new();
        next.try_reserve_exact(target)
            .map_err(|_| Error::Capacity)?;
        if next.capacity() > target {
            return Err(Error::Capacity);
        }
        next.append(values);
        *values = next;
        Ok(())
    }
}
