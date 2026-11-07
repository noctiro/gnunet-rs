use crate::{Error, HashOrder, MAX_ROWS, Value};
use alloc::vec::Vec;
use core::mem::size_of;
use gnunet_types::Error as CoreError;
use zeroize::Zeroize;

/// One original private vector, whose keys alone are exported to SETI.
/// Values and ordering are never reloaded after the original operation starts.
pub struct MatchedVector {
    rows: Vec<Value>,
    active: Vec<u8>,
    order: HashOrder,
    sealed: bool,
    bytes: usize,
}
impl MatchedVector {
    /// Adopt actual allocations, reject duplicate keys before zero filtering,
    /// and sort by the explicit native-u32 C hash profile. Sorting is a finite
    /// admission operation, not a preemptible cryptographic work unit.
    pub fn new(
        mut rows: Vec<Value>,
        order: HashOrder,
        max_rows: usize,
        budget: usize,
    ) -> Result<Self, Error> {
        if max_rows == 0 || max_rows > MAX_ROWS || rows.len() > max_rows {
            return Err(CoreError::Capacity.into());
        }
        let row_bytes = rows
            .capacity()
            .checked_mul(size_of::<Value>())
            .ok_or(CoreError::Overflow)?;
        if row_bytes > budget {
            return Err(CoreError::Capacity.into());
        }
        rows.sort_unstable_by(|a, b| order.compare(a.key(), b.key()));
        if rows.windows(2).any(|pair| pair[0].key() == pair[1].key()) {
            return Err(CoreError::Conflict.into());
        }
        rows.retain(|row| row.value() != 0);
        let mut active = Vec::new();
        active
            .try_reserve_exact(rows.len())
            .map_err(|_| CoreError::Capacity)?;
        let bytes = row_bytes
            .checked_add(active.capacity())
            .ok_or(CoreError::Overflow)?;
        if bytes > budget {
            return Err(CoreError::Capacity.into());
        }
        active.resize(rows.len(), 1);
        Ok(Self {
            rows,
            active,
            order,
            sealed: false,
            bytes,
        })
    }
    /// Original nonzero keys still active in the real SETI operation.
    pub fn keys(&self) -> impl Iterator<Item = &[u8; 64]> {
        self.rows.iter().enumerate().filter_map(|(index, row)| {
            if self.sealed || self.active[index] != 0 {
                Some(row.key())
            } else {
                None
            }
        })
    }
    /// Borrow the original SETI population key by index in O(1), before DONE.
    /// Population finishes before the real evaluation/DEL_LOCAL phase starts.
    #[must_use]
    pub fn intersection_key(&self, index: usize) -> Option<&[u8; 64]> {
        if self.sealed {
            None
        } else {
            self.rows.get(index).map(Value::key)
        }
    }
    /// Apply one actual DEL_LOCAL from the original SETI operation.
    pub fn remove(&mut self, key: &[u8; 64]) -> Result<(), Error> {
        if self.sealed {
            return Err(Error::Phase);
        }
        let index = self
            .rows
            .binary_search_by(|row| self.order.compare(row.key(), key))
            .map_err(|_| CoreError::NotFound)?;
        if self.active[index] == 0 {
            return Err(CoreError::Replay.into());
        }
        self.active[index] = 0;
        Ok(())
    }
    /// Seal only after the original real SETI DONE and its actual final size.
    /// No synthetic callback or copied peer count is accepted as that evidence.
    pub fn seal(&mut self, count: u64) -> Result<(), Error> {
        if self.sealed {
            return Err(Error::Phase);
        }
        let actual = self.active.iter().filter(|flag| **flag != 0).count();
        if u64::try_from(actual).map_err(|_| CoreError::Overflow)? != count {
            return Err(CoreError::InvalidInput.into());
        }
        let row_bytes = self
            .rows
            .capacity()
            .checked_mul(size_of::<Value>())
            .ok_or(CoreError::Overflow)?;
        let mut index = 0;
        self.rows.retain(|_| {
            let keep = self.active[index] != 0;
            index += 1;
            keep
        });
        self.active.zeroize();
        self.active = Vec::new();
        self.bytes = row_bytes;
        self.sealed = true;
        Ok(())
    }
    /// Actual matched count; requires the original completed intersection.
    pub fn len(&self) -> Result<usize, Error> {
        if !self.sealed {
            return Err(Error::Phase);
        }
        Ok(self.rows.len())
    }
    /// Whether the original SETI operation has produced a real DONE.
    #[must_use]
    pub const fn is_sealed(&self) -> bool {
        self.sealed
    }
    /// Current original nonzero rows, before or after the original intersection.
    #[must_use]
    pub fn initial_rows(&self) -> usize {
        self.rows.len()
    }
    /// Whether the actual completed intersection is empty.
    pub fn is_empty(&self) -> Result<bool, Error> {
        self.len().map(|n| n == 0)
    }
    /// Original ordered private coefficient after the completed intersection.
    pub fn coefficient(&self, index: usize) -> Result<i64, Error> {
        if !self.sealed {
            return Err(Error::Phase);
        }
        self.rows
            .get(index)
            .map(Value::value)
            .ok_or_else(|| CoreError::InvalidInput.into())
    }
    /// Actual retained row and activity allocations, including spare capacity.
    #[must_use]
    pub const fn retained_bytes(&self) -> usize {
        self.bytes
    }
    /// Erase original coefficients and every retained allocation on cancellation.
    pub fn clear(&mut self) {
        self.rows.zeroize();
        self.rows = Vec::new();
        self.active.zeroize();
        self.active = Vec::new();
        self.bytes = 0;
        self.sealed = true;
    }
}
impl Drop for MatchedVector {
    fn drop(&mut self) {
        self.rows.zeroize();
        self.active.zeroize();
    }
}
