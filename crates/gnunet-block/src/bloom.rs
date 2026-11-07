//! Exact native nonce and GNUnet container Bloom bit selection.
use crate::{BlockType, GroupState, Hash, ReturnValue};
use gnunet_crypto::{hash512, hash512_parts};
use gnunet_types::Error;
/// Native unsigned32 serialization profile; it is not network byte order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeEndian {
    /// Little-endian C process.
    Little,
    /// Big-endian C process.
    Big,
}
impl NativeEndian {
    /// Current Rust target's C-compatible unsigned32 byte order.
    #[must_use]
    pub const fn native() -> Self {
        if cfg!(target_endian = "little") {
            Self::Little
        } else {
            Self::Big
        }
    }
    fn encode(self, value: u32) -> [u8; 4] {
        match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        }
    }
    fn decode(self, value: [u8; 4]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes(value),
            Self::Big => u32::from_be_bytes(value),
        }
    }
}
/// SHA512(original64 || native packed uint32), exactly68 input bytes.
#[must_use]
pub fn mingle_hash(hash: &Hash, mingle: u32, profile: NativeEndian) -> Hash {
    hash512_parts(&[hash, &profile.encode(mingle)])
}
/// Source unsigned32 multiplication wraps before division; minimum8/max32768.
#[must_use]
pub fn compute_size(entry_count: u32, k: u32) -> usize {
    if entry_count > 32768 {
        return 32768;
    }
    let ideal = entry_count.wrapping_mul(k) / 4;
    let mut size = 8u32;
    while size < 32768 && size < ideal {
        size *= 2;
    }
    size as usize
}
/// A native Bloom-backed group borrowing only the caller's exact filter bytes.
/// k0 or size0 retains source's group-with-NULL-filter semantics. Values k above
/// INT32_MAX follow the observed two's-complement signed iteration profile:
/// zero rounds, test true, add no-op. No file-counter mode is used by BLOCK.
#[derive(Debug)]
pub struct BloomGroup<'a> {
    kind: BlockType,
    bytes: &'a mut [u8],
    nonce: u32,
    k: u32,
    profile: NativeEndian,
    active: bool,
}
impl<'a> BloomGroup<'a> {
    /// Restore optional serialized state or clear a fresh group. Short raw<4 is
    /// rejected before changing storage. Wrong raw filter length preserves nonce
    /// but creates a new empty filter, as bg_bf.c. Fresh nonce is caller-supplied;
    /// production entropy must sample0..UINT32_MAX, excluding UINT32_MAX.
    pub fn new(
        storage: &'a mut [u8],
        kind: BlockType,
        k: u32,
        raw: Option<&[u8]>,
        fresh_nonce: u32,
        profile: NativeEndian,
    ) -> Result<Self, Error> {
        let _size = u32::try_from(storage.len()).map_err(|_| Error::Capacity)?;
        let nonce = if let Some(raw) = raw {
            if raw.len() < 4 {
                return Err(Error::Truncated);
            }
            profile.decode(raw[..4].try_into().map_err(|_| Error::Truncated)?)
        } else {
            fresh_nonce
        };
        storage.fill(0);
        if let Some(raw) = raw
            && raw.len() - 4 == storage.len()
        {
            storage.copy_from_slice(&raw[4..]);
        }
        let active = k != 0 && !storage.is_empty();
        Ok(Self {
            kind,
            bytes: storage,
            nonce,
            k,
            profile,
            active,
        })
    }
    /// Borrow the current actual filter bits without clearing or restoring them.
    /// The caller owns these bounded bytes and the matching original native
    /// nonce; this creates no new group state and preserves prior admissions.
    pub fn borrow_existing(
        storage: &'a mut [u8],
        kind: BlockType,
        k: u32,
        nonce: u32,
        profile: NativeEndian,
    ) -> Result<Self, Error> {
        let _size = u32::try_from(storage.len()).map_err(|_| Error::Capacity)?;
        let active = k != 0 && !storage.is_empty();
        Ok(Self {
            kind,
            bytes: storage,
            nonce,
            k,
            profile,
            active,
        })
    }
    /// Imported or caller-selected native nonce.
    #[must_use]
    pub const fn nonce(&self) -> u32 {
        self.nonce
    }
    /// Exact current raw filter bytes, without the serialized native nonce prefix.
    #[must_use]
    pub fn bits(&self) -> &[u8] {
        self.bytes
    }
    /// Address count as the source unsigned C field.
    #[must_use]
    pub const fn rounds(&self) -> u32 {
        self.k
    }
    fn each_bit(&self, key: &Hash, mut visit: impl FnMut(usize) -> bool) {
        if !self.active {
            return;
        }
        let rounds = self.k as i32;
        if rounds <= 0 {
            return;
        }
        let mut hash = *key;
        let mut slot = 0;
        let mut left = rounds;
        while left > 0 {
            if slot == 16 {
                hash = hash512(&hash);
                slot = 0;
            }
            let start = slot * 4;
            let word = u32::from_be_bytes([
                hash[start],
                hash[start + 1],
                hash[start + 2],
                hash[start + 3],
            ]);
            let bit = (u64::from(word) % (self.bytes.len() as u64 * 8)) as usize;
            if !visit(bit) {
                return;
            }
            slot += 1;
            left -= 1;
        }
    }
    fn contains_mingled(&self, key: &Hash) -> bool {
        if !self.active {
            return true;
        }
        let mut yes = true;
        self.each_bit(key, |bit| {
            yes = self.bytes[bit / 8] & (1u8 << (bit % 8)) != 0;
            yes
        });
        yes
    }
    fn add_mingled(&mut self, key: &Hash) {
        // Copy only fixed public metadata so each bit can mutate disjoint storage.
        if !self.active {
            return;
        }
        let rounds = self.k as i32;
        if rounds <= 0 {
            return;
        }
        let mut hash = *key;
        let mut slot = 0;
        let mut left = rounds;
        while left > 0 {
            if slot == 16 {
                hash = hash512(&hash);
                slot = 0;
            }
            let s = slot * 4;
            let word = u32::from_be_bytes([hash[s], hash[s + 1], hash[s + 2], hash[s + 3]]);
            let bit = (u64::from(word) % (self.bytes.len() as u64 * 8)) as usize;
            self.bytes[bit / 8] |= 1u8 << (bit % 8);
            slot += 1;
            left -= 1;
        }
    }
    /// Test an actual whole-result hash without changing this group's bits.
    /// This uses the same native nonce mingling and bit addresses as insertion.
    #[must_use]
    pub fn contains(&self, hash: &Hash) -> bool {
        let key = mingle_hash(hash, self.nonce, self.profile);
        self.contains_mingled(&key)
    }
    /// A real group with NULL internal filter reports duplicate. A NULL group is
    /// a different state handled by test_and_set(None), which reports not seen.
    pub fn test_and_set(&mut self, hash: &Hash) -> bool {
        let key = mingle_hash(hash, self.nonce, self.profile);
        if self.contains_mingled(&key) {
            true
        } else {
            self.add_mingled(&key);
            false
        }
    }
}
impl GroupState for BloomGroup<'_> {
    fn block_type(&self) -> BlockType {
        self.kind
    }
    fn serialize_into(&self, output: &mut [u8]) -> Result<Option<usize>, Error> {
        if !self.active {
            return Err(Error::NotReady);
        }
        let len = self.bytes.len().checked_add(4).ok_or(Error::Overflow)?;
        if output.len() < len {
            return Err(Error::Capacity);
        }
        output[..4].copy_from_slice(&self.profile.encode(self.nonce));
        output[4..len].copy_from_slice(self.bytes);
        Ok(Some(len))
    }
    fn mark_seen(&mut self, hashes: &[Hash]) -> crate::MarkSeen {
        for hash in hashes {
            let key = mingle_hash(hash, self.nonce, self.profile);
            self.add_mingled(&key);
        }
        crate::MarkSeen::Marked
    }
    fn has_merge(&self) -> bool {
        true
    }
    fn merge_from(&mut self, other: &Self) -> Result<ReturnValue, Error> {
        if self.nonce != other.nonce || self.bytes.len() != other.bytes.len() {
            return Ok(ReturnValue::No);
        }
        if !self.active {
            return Ok(ReturnValue::Yes);
        }
        if !other.active {
            return Err(Error::InvalidInput);
        }
        for (a, b) in self.bytes.iter_mut().zip(other.bytes.iter()) {
            *a |= *b;
        }
        Ok(ReturnValue::Yes)
    }
}
/// A NULL group is definitively not a duplicate and stores no state.
pub fn test_and_set(group: Option<&mut BloomGroup<'_>>, hash: &Hash) -> bool {
    group.is_some_and(|g| g.test_and_set(hash))
}
