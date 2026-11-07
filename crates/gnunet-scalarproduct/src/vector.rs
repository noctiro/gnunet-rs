use alloc::vec::Vec;
use core::{cmp::Ordering, mem::size_of};
use gnunet_types::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The fixed C hash comparator reads native u32 words from word 15 to word 0.
/// This explicit profile is not raw byte lexicographic ordering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashOrder {
    /// Little-endian native u32 words, used by ordinary x86_64/aarch64 C builds.
    Little,
    /// Big-endian native u32 words.
    Big,
}
impl HashOrder {
    /// Local target C ABI profile. Remote heterogeneous ABI must be explicit.
    #[must_use]
    pub const fn native() -> Self {
        if cfg!(target_endian = "little") {
            Self::Little
        } else {
            Self::Big
        }
    }
    /// Compare the same sixteen native words as GNUNET_CRYPTO_hash_cmp.
    #[must_use]
    pub fn compare(self, left: &[u8; 64], right: &[u8; 64]) -> Ordering {
        let left = left.as_chunks::<4>().0;
        let right = right.as_chunks::<4>().0;
        for index in (0..16).rev() {
            let (a, b) = match self {
                Self::Little => (
                    u32::from_le_bytes(left[index]),
                    u32::from_le_bytes(right[index]),
                ),
                Self::Big => (
                    u32::from_be_bytes(left[index]),
                    u32::from_be_bytes(right[index]),
                ),
            };
            match a.cmp(&b) {
                Ordering::Equal => {}
                other => return other,
            }
        }
        Ordering::Equal
    }
}

/// One owned private coefficient; all-zero hash keys remain valid.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Value {
    key: [u8; 64],
    value: i64,
    retained: bool,
}
impl Value {
    /// Adopt a key and signed i64, including MIN and zero.
    #[must_use]
    pub const fn new(key: [u8; 64], value: i64) -> Self {
        Self {
            key,
            value,
            retained: true,
        }
    }
    /// Original match key, not proof of an authenticated peer.
    #[must_use]
    pub const fn key(&self) -> &[u8; 64] {
        &self.key
    }
    /// Private signed coefficient.
    #[must_use]
    pub const fn value(&self) -> i64 {
        self.value
    }
}

/// Adopted bounded vector, sorted once in the original explicit hash ABI.
/// Rows are never re-read from mutable native input after intersection begins.
pub struct Vector {
    values: Vec<Value>,
    order: HashOrder,
    sealed: bool,
}
impl Vector {
    /// Check duplicate keys (including zero coefficients), then remove zero
    /// coefficients exactly as the C producer. The all-zero key is not removed.
    /// Startup sorting is bounded O(max_rows log max_rows), without a second copy.
    pub fn new(
        mut values: Vec<Value>,
        order: HashOrder,
        max_rows: usize,
        retained_bytes: usize,
    ) -> Result<Self, Error> {
        if values.len() > max_rows
            || values
                .capacity()
                .checked_mul(size_of::<Value>())
                .ok_or(Error::Overflow)?
                > retained_bytes
        {
            return Err(Error::Capacity);
        }
        values.sort_unstable_by(|a, b| order.compare(&a.key, &b.key));
        if values.windows(2).any(|rows| rows[0].key == rows[1].key) {
            return Err(Error::Conflict);
        }
        values.retain(|value| value.value != 0);
        Ok(Self {
            values,
            order,
            sealed: false,
        })
    }
    /// Actual retained allocation, including spare capacity and zero-filter slots.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        self.values
            .capacity()
            .checked_mul(size_of::<Value>())
            .ok_or(Error::Overflow)
    }
    /// Nonzero initial SETI keys, or final matched keys after seal.
    pub fn keys(&self) -> impl Iterator<Item = &[u8; 64]> {
        self.values.iter().filter(|v| v.retained).map(|v| &v.key)
    }
    /// Number of active matched coefficients.
    #[must_use]
    pub fn len(&self) -> usize {
        if self.sealed {
            self.values.len()
        } else {
            self.values.iter().filter(|v| v.retained).count()
        }
    }
    /// Whether the actual current set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub(crate) fn remove(&mut self, key: &[u8; 64]) -> Result<(), Error> {
        if self.sealed {
            return Err(Error::Conflict);
        }
        let index = self
            .values
            .binary_search_by(|v| self.order.compare(&v.key, key))
            .map_err(|_| Error::NotFound)?;
        if !self.values[index].retained {
            return Err(Error::Replay);
        }
        self.values[index].retained = false;
        Ok(())
    }
    pub(crate) fn seal(&mut self) {
        self.values.retain(|v| v.retained);
        self.sealed = true;
    }
    pub(crate) fn coefficient(&self, index: usize) -> Result<i64, Error> {
        if !self.sealed {
            return Err(Error::NotReady);
        }
        self.values
            .get(index)
            .map(|v| v.value)
            .ok_or(Error::InvalidInput)
    }
    pub(crate) fn indexed_key(&self, index: usize) -> Option<&[u8; 64]> {
        self.values.get(index).map(|value| &value.key)
    }
    pub(crate) fn wipe(&mut self) {
        self.values.zeroize();
        self.values = Vec::new();
        self.sealed = true;
    }
}
impl Drop for Vector {
    fn drop(&mut self) {
        // zeroize's Vec implementation also clears retained spare storage.
        self.values.zeroize();
    }
}
