//! Official FS UBLOCK reply groups with bounded inline, supplied or heap state.

use super::Entropy;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use gnunet_block::{
    BlockType, GroupState,
    bloom::{BloomGroup, NativeEndian},
};
use gnunet_types::Error;
use gnunet_wire::official::fs_gap::{MAX_BLOOM_BYTES, MIN_BLOOM_BYTES};

pub(super) const BYTES: usize = 1024;
const ROUNDS: u32 = 16;

/// Data needed to initialize one newly admitted group.
pub(super) enum Initial<'bytes, 'entropy> {
    Incoming {
        nonce: u32,
        bits: &'bytes [u8],
    },
    Local {
        seen: &'bytes [[u8; 64]],
        entropy: &'entropy mut dyn Entropy,
    },
}

impl<'bytes> Initial<'bytes, '_> {
    pub fn incoming(raw: &'bytes [u8]) -> Result<Self, Error> {
        let (nonce, bits) = raw.split_first_chunk::<4>().ok_or(Error::Malformed)?;
        if !(MIN_BLOOM_BYTES..=MAX_BLOOM_BYTES).contains(&bits.len())
            || !bits.len().is_power_of_two()
        {
            return Err(Error::Malformed);
        }
        // C uses memcpy for this nonce. Native decode preserves its original
        // byte order when the block group mingles candidate hashes.
        Ok(Self::Incoming {
            nonce: u32::from_ne_bytes(*nonce),
            bits,
        })
    }

    pub const fn len(&self) -> usize {
        match self {
            Self::Incoming { bits, .. } => bits.len(),
            Self::Local { .. } => BYTES,
        }
    }
}

pub(super) struct Group<'bytes> {
    inline: [u8; BYTES],
    supplied: &'bytes mut [u8],
    #[cfg(feature = "alloc")]
    heap: Vec<u8>,
    len: usize,
    nonce: u32,
}

impl<'bytes> Group<'bytes> {
    pub fn empty(supplied: &'bytes mut [u8]) -> Self {
        Self {
            inline: [0; BYTES],
            supplied,
            #[cfg(feature = "alloc")]
            heap: Vec::new(),
            len: 0,
            nonce: 0,
        }
    }

    pub fn fixed_capacity(&self) -> usize {
        self.supplied.len().clamp(BYTES, MAX_BLOOM_BYTES)
    }

    /// Initialize only the selected vacant route, without a full-width staging copy.
    pub fn initialize(
        &mut self,
        initial: Initial<'_, '_>,
        heap_budget: usize,
    ) -> Result<(), Error> {
        if self.len != 0 {
            return Err(Error::Conflict);
        }
        let len = initial.len();
        self.reserve(len, heap_budget)?;
        let nonce = match initial {
            Initial::Incoming { nonce, bits } => {
                self.storage(len)?.copy_from_slice(bits);
                nonce
            }
            Initial::Local { seen, entropy } => {
                let nonce = entropy.uniform(u32::MAX)?;
                if nonce == u32::MAX {
                    return Err(Error::InvalidInput);
                }
                let storage = self.storage(len)?;
                storage.fill(0);
                let mut group = Self::view(storage, nonce)?;
                let _marked = group.mark_seen(seen);
                nonce
            }
        };
        self.len = len;
        self.nonce = nonce;
        Ok(())
    }

    fn reserve(&mut self, len: usize, budget: usize) -> Result<(), Error> {
        if len <= self.fixed_capacity() {
            return Ok(());
        }
        #[cfg(not(feature = "alloc"))]
        {
            let _budget = budget;
            Err(Error::Capacity)
        }
        #[cfg(feature = "alloc")]
        {
            if len > budget {
                return Err(Error::Capacity);
            }
            let mut heap = Vec::new();
            heap.try_reserve_exact(len).map_err(|_| Error::Capacity)?;
            // Charge actual allocated capacity while retaining the exact bit width.
            if heap.capacity() > budget || heap.capacity() > MAX_BLOOM_BYTES {
                return Err(Error::Capacity);
            }
            heap.resize(len, 0);
            self.heap = heap;
            Ok(())
        }
    }

    /// Actual additional heap capacity, independent of caller-provided storage.
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

    fn storage(&mut self, len: usize) -> Result<&mut [u8], Error> {
        if len <= BYTES {
            return Ok(&mut self.inline[..len]);
        }
        if let Some(storage) = self.supplied.get_mut(..len) {
            return Ok(storage);
        }
        #[cfg(feature = "alloc")]
        return self.heap.get_mut(..len).ok_or(Error::Capacity);
        #[cfg(not(feature = "alloc"))]
        Err(Error::Capacity)
    }

    fn view(storage: &mut [u8], nonce: u32) -> Result<BloomGroup<'_>, Error> {
        BloomGroup::borrow_existing(
            storage,
            BlockType::FS_UBLOCK,
            ROUNDS,
            nonce,
            NativeEndian::native(),
        )
    }

    pub fn duplicate(&mut self, hash: &[u8; 64]) -> Result<bool, Error> {
        if self.len == 0 {
            return Err(Error::NotReady);
        }
        let nonce = self.nonce;
        Ok(Self::view(self.storage(self.len)?, nonce)?.contains(hash))
    }

    pub fn mark(&mut self, hash: &[u8; 64]) -> Result<(), Error> {
        let nonce = self.nonce;
        let _duplicate = Self::view(self.storage(self.len)?, nonce)?.test_and_set(hash);
        Ok(())
    }

    pub fn reset(&mut self) {
        if let Ok(storage) = self.storage(self.len) {
            storage.fill(0);
        }
        #[cfg(feature = "alloc")]
        {
            self.heap = Vec::new();
        }
        self.len = 0;
        self.nonce = 0;
    }
}
