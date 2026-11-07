//! Official FS UBLOCK reply groups with bounded inline/optional heap state.
use super::Entropy;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use gnunet_block::{
    BlockType, GroupState,
    bloom::{BloomGroup, NativeEndian},
};
use gnunet_types::Error;
use gnunet_wire::official::fs_gap::{MAX_BLOOM_BYTES, MIN_BLOOM_BYTES};

/// Small groups stay inline. Larger official groups use only their actual size.
pub(super) const BYTES: usize = 1024;
pub(super) struct Group {
    bits: [u8; BYTES],
    #[cfg(feature = "alloc")]
    heap: Vec<u8>,
    len: usize,
    nonce: u32,
}
impl Group {
    pub const fn empty() -> Self {
        Self {
            bits: [0; BYTES],
            #[cfg(feature = "alloc")]
            heap: Vec::new(),
            len: 0,
            nonce: 0,
        }
    }
    /// Materialize only a new admitted route, after all metadata preflights.
    /// Wire nonce bytes and all supplied bits are preserved without folding.
    pub fn new(
        raw: Option<&[u8]>,
        seen: &[[u8; 64]],
        entropy: &mut impl Entropy,
        heap_budget: usize,
    ) -> Result<Self, Error> {
        let len = if let Some(raw) = raw {
            let len = raw.len().checked_sub(4).ok_or(Error::Malformed)?;
            if !(MIN_BLOOM_BYTES..=MAX_BLOOM_BYTES).contains(&len) || !len.is_power_of_two() {
                return Err(Error::Malformed);
            }
            len
        } else {
            BYTES
        };
        let requested = if len > BYTES { len } else { 0 };
        if requested > heap_budget {
            return Err(Error::Capacity);
        }
        let nonce = if let Some(raw) = raw {
            // C serializes/restores this field with memcpy. Decoding then using
            // the same native profile reproduces the exact incoming four bytes.
            u32::from_ne_bytes(raw[..4].try_into().map_err(|_| Error::Malformed)?)
        } else {
            let nonce = entropy.uniform(u32::MAX)?;
            if nonce == u32::MAX {
                return Err(Error::InvalidInput);
            }
            nonce
        };
        let mut group = Self {
            len,
            nonce,
            ..Self::empty()
        };
        if requested != 0 {
            #[cfg(not(feature = "alloc"))]
            return Err(Error::Capacity);
            #[cfg(feature = "alloc")]
            {
                group
                    .heap
                    .try_reserve_exact(len)
                    .map_err(|_| Error::Capacity)?;
                // Allocator capacity, not just the requested length, is charged.
                // A rejected temporary allocation drops before any route commit.
                if group.heap.capacity() > heap_budget || group.heap.capacity() > MAX_BLOOM_BYTES {
                    return Err(Error::Capacity);
                }
                group.heap.resize(len, 0);
            }
        }
        if let Some(raw) = raw {
            group.storage().copy_from_slice(&raw[4..]);
        }
        let mut view = BloomGroup::borrow_existing(
            group.storage(),
            BlockType::FS_UBLOCK,
            16,
            nonce,
            NativeEndian::native(),
        )?;
        let _marked = view.mark_seen(seen);
        Ok(group)
    }
    /// Actual additional heap capacity; the fixed inline array is separate.
    pub fn heap_bytes(&self) -> usize {
        #[cfg(feature = "alloc")]
        {
            self.heap.capacity()
        }
        #[cfg(not(feature = "alloc"))]
        {
            0
        }
    }
    fn storage(&mut self) -> &mut [u8] {
        #[cfg(feature = "alloc")]
        if self.len > BYTES {
            return self.heap.as_mut_slice();
        }
        &mut self.bits[..self.len]
    }
    pub fn duplicate(&mut self, hash: &[u8; 64]) -> Result<bool, Error> {
        if self.len == 0 {
            return Err(Error::NotReady);
        }
        let nonce = self.nonce;
        let view = BloomGroup::borrow_existing(
            self.storage(),
            BlockType::FS_UBLOCK,
            16,
            nonce,
            NativeEndian::native(),
        )?;
        Ok(view.contains(hash))
    }
    pub fn mark(&mut self, hash: &[u8; 64]) -> Result<(), Error> {
        let nonce = self.nonce;
        let mut view = BloomGroup::borrow_existing(
            self.storage(),
            BlockType::FS_UBLOCK,
            16,
            nonce,
            NativeEndian::native(),
        )?;
        let _duplicate = view.test_and_set(hash);
        Ok(())
    }
}
