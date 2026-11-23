//! Epoch hint buckets with the same layout in owned and caller-owned storage.

use super::EpochAlias;
use crate::{Error, storage::Backing};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::{
    fmt,
    mem::{self, size_of},
    ops::{Index, IndexMut},
};
use gnunet_types::Error as Fault;

// Each message can introduce three distinct hints. Leave one bucket of
// headroom per message to bound load without resizing and rehashing.
const BUCKETS_PER_MESSAGE: usize = 4;

/// One bucket in the caller-owned room epoch hint index.
pub struct EpochAliasCell(Option<EpochAlias>);

impl EpochAliasCell {
    /// A vacant bucket ready for caller-owned room storage.
    pub const fn empty() -> Self {
        Self(None)
    }
}

impl fmt::Debug for EpochAliasCell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EpochAliasCell([REDACTED])")
    }
}

pub(crate) struct AliasBuckets<'id>(Backing<EpochAliasCell, &'id mut [EpochAliasCell]>);

impl<'id> AliasBuckets<'id> {
    #[cfg(feature = "alloc")]
    pub const fn new() -> Self {
        Self(Backing::Owned(Vec::new()))
    }

    pub fn fixed(cells: &'id mut [EpochAliasCell]) -> Self {
        cells.fill_with(EpochAliasCell::empty);
        Self(Backing::fixed(cells))
    }

    pub fn into_fixed(mut self) -> Option<&'id mut [EpochAliasCell]> {
        let cells = mem::take(self.0.fixed_mut()?);
        cells.fill_with(EpochAliasCell::empty);
        Some(cells)
    }

    pub fn bucket_count(messages: usize) -> Result<usize, Error> {
        messages
            .checked_mul(BUCKETS_PER_MESSAGE)
            .ok_or_else(|| Fault::Overflow.into())
    }

    pub fn required_bytes(count: usize) -> Result<usize, Error> {
        count
            .checked_mul(size_of::<EpochAliasCell>())
            .ok_or_else(|| Fault::Overflow.into())
    }

    /// Allocate a lazy table if needed, returning only newly charged bytes.
    /// The table width stays fixed once selected.
    pub fn initialize(&mut self, count: usize, budget: usize) -> Result<usize, Error> {
        if self.len() == count {
            return Ok(0);
        }
        #[cfg(not(feature = "alloc"))]
        let _ = budget;
        match &mut self.0 {
            #[cfg(feature = "alloc")]
            Backing::Owned(existing) => Self::allocate(existing, count, budget),
            Backing::Fixed(..) => Err(Fault::Capacity.into()),
        }
    }

    #[cfg(feature = "alloc")]
    fn allocate(
        existing: &mut Vec<EpochAliasCell>,
        count: usize,
        budget: usize,
    ) -> Result<usize, Error> {
        if !existing.is_empty() || Self::required_bytes(count)? > budget {
            return Err(Fault::Capacity.into());
        }
        let mut cells = Vec::new();
        cells
            .try_reserve_exact(count)
            .map_err(|_| Fault::Capacity)?;
        let charged = Self::required_bytes(cells.capacity())?;
        if charged > budget {
            return Err(Fault::Capacity.into());
        }
        cells.resize_with(count, EpochAliasCell::empty);
        *existing = cells;
        Ok(charged)
    }

    pub fn capacity(&self) -> usize {
        self.0.capacity()
    }

    pub fn len(&self) -> usize {
        self.0.as_ref().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = &Option<EpochAlias>> {
        self.0.as_ref().iter().map(|cell| &cell.0)
    }
}

impl Index<usize> for AliasBuckets<'_> {
    type Output = Option<EpochAlias>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0.as_ref()[index].0
    }
}

impl IndexMut<usize> for AliasBuckets<'_> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0.as_mut()[index].0
    }
}

impl Drop for AliasBuckets<'_> {
    fn drop(&mut self) {
        if let Some(cells) = self.0.fixed_mut() {
            cells.fill_with(EpochAliasCell::empty);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "alloc")]
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Check that a rejected budget leaves the table empty"
    )]
    fn allocation_is_atomic() -> Result<(), Error> {
        let mut owned = AliasBuckets::new();
        let count = AliasBuckets::bucket_count(1)?;
        let bytes = AliasBuckets::required_bytes(count)?;
        assert!(matches!(
            owned.initialize(count, bytes - 1),
            Err(Error::Protocol(Fault::Capacity))
        ));
        assert!(owned.is_empty());
        let charged = owned.initialize(count, usize::MAX)?;
        assert_eq!(charged, AliasBuckets::required_bytes(owned.capacity())?);
        assert_eq!(owned.initialize(count, 0)?, 0);
        Ok(())
    }

    #[test]
    #[expect(clippy::panic_in_result_fn, reason = "Check partition reuse")]
    fn fixed_storage_is_reclaimed() -> Result<(), Error> {
        let count = AliasBuckets::bucket_count(1)?;
        let mut cells = [const { EpochAliasCell::empty() }; 4];
        let mut fixed = AliasBuckets::fixed(&mut cells);
        assert_eq!(fixed.initialize(count, 0)?, 0);
        assert!(matches!(
            fixed.initialize(count + 1, usize::MAX),
            Err(Error::Protocol(Fault::Capacity))
        ));
        fixed[0] = Some(EpochAlias {
            key: [1; 64],
            epoch: [2; 64],
        });
        assert_eq!(fixed.iter().flatten().count(), 1);
        let reclaimed = fixed.into_fixed().ok_or(Fault::Conflict)?;
        assert!(reclaimed.iter().all(|cell| cell.0.is_none()));
        Ok(())
    }
}
