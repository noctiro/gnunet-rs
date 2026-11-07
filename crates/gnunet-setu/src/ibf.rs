//! Active v0.29.1 SETU invertible Bloom filter, with explicit source-native order.
//! All backing cells belong to the caller. Encoding is not a reconciliation ACK.
use gnunet_types::Error;
/// The reference memcpy-serializes keys and checksums, and hashes native words.
/// This is an explicit interoperability profile, not a new negotiated wire field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Order {
    /// Normal current little-endian C profile.
    Little,
    /// Explicit big-endian reference ABI profile.
    Big,
}
impl Order {
    /// Current target ABI, without runtime lookup or protocol negotiation.
    #[must_use]
    pub const fn native() -> Self {
        if cfg!(target_endian = "little") {
            Self::Little
        } else {
            Self::Big
        }
    }
    /// Reference-native u16 encoding, including element hash prefixes.
    #[must_use]
    pub const fn u16(self, value: u16) -> [u8; 2] {
        match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        }
    }
    /// Reference-native u32 encoding.
    #[must_use]
    pub const fn u32(self, value: u32) -> [u8; 4] {
        match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        }
    }
    /// Reference-native u64 encoding.
    #[must_use]
    pub const fn u64(self, value: u64) -> [u8; 8] {
        match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        }
    }
    /// Decode one reference-native u32 word.
    #[must_use]
    pub const fn read_u32(self, bytes: [u8; 4]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        }
    }
    /// Decode one reference-native u64 word.
    #[must_use]
    pub const fn read_u64(self, bytes: [u8; 8]) -> u64 {
        match self {
            Self::Little => u64::from_le_bytes(bytes),
            Self::Big => u64::from_be_bytes(bytes),
        }
    }
}
/// Native reference bucket allocation/stride is8 count+8 key+4 checksum bytes.
/// Actual packed counters can use less space; the remaining wire padding is ignored.
pub const BUCKET_WIRE_BYTES: usize = 20;
/// All possible nonzero u8 hash multiplicities fit this fixed local index scratch.
pub const MAX_HASHES: usize = 255;
/// Explicit local collision-search work bound, not a wire/protocol parameter.
pub const INDEX_TRIAL_LIMIT: u32 = 65_536;
/// A collision-prone reconciliation key, not an authenticated element hash.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Key(pub u64);
impl Key {
    /// Active `get_ibf_key`: HKDF-GNUnet salt=element SHA512, IKM=nativeu16 zero,
    /// context empty, output8 interpreted in the selected reference ABI order.
    pub fn from_element_hash(hash: &[u8; 64], order: Order) -> Result<Self, Error> {
        let mut bytes = [0; 8];
        gnunet_crypto::hkdf_gnunet(hash, &[0, 0], &[], &mut bytes)?;
        Ok(Self(order.read_u64(bytes)))
    }
    /// Reference `ibf_key_from_hashcode`, distinct from active element HKDF.
    #[must_use]
    pub fn from_hash_prefix(hash: &[u8; 64], order: Order) -> Self {
        Self(order.read_u64([
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
        ]))
    }
    /// Replicate the original native key eight times, as the reference map key.
    #[must_use]
    pub fn repeated_hash(self, order: Order) -> [u8; 64] {
        let mut out = [0; 64];
        for part in out.as_chunks_mut::<8>().0 {
            part.copy_from_slice(&order.u64(self.0));
        }
        out
    }
    /// Reference key salt is only rotate-right by (salt*7)%64.
    #[must_use]
    pub const fn salted(self, salt: u32) -> Self {
        Self(self.0.rotate_right(salt.wrapping_mul(7) % 64))
    }
    /// Inverse of `salted`, including the defined zero-rotation case.
    #[must_use]
    pub const fn unsalted(self, salt: u32) -> Self {
        Self(self.0.rotate_left(salt.wrapping_mul(7) % 64))
    }
    /// Reference checksum hashes only the first native4 bytes of the8-byte key.
    #[must_use]
    pub fn checksum(self, order: Order) -> u32 {
        crc32(&order.u64(self.0)[..4])
    }
    /// Generate the actual unique reference bucket indices into caller scratch.
    /// Scratch may change on failure; no logical filter is modified.
    pub fn indices(
        self,
        size: u32,
        hash_num: u8,
        order: Order,
        out: &mut [u32],
    ) -> Result<usize, Error> {
        if size == 0
            || hash_num == 0
            || u32::from(hash_num) > size
            || out.len() < usize::from(hash_num)
        {
            return Err(Error::InvalidInput);
        }
        let mut bucket = crc32(&order.u64(self.0));
        let mut filled = 0;
        for attempt in 0..INDEX_TRIAL_LIMIT {
            let index = bucket % size;
            if !out[..filled].contains(&index) {
                out[filled] = index;
                filled += 1;
                if filled == usize::from(hash_num) {
                    return Ok(filled);
                }
            }
            let mixed = (u64::from(bucket) << 32) | u64::from(attempt);
            bucket = crc32(&order.u64(mixed));
        }
        Err(Error::Capacity)
    }
}
/// Exact shared GNUnet checksum; this provides no authentication.
pub use gnunet_crypto::crc32_n as crc32;
/// Logical native bucket. Rust layout is deliberately unrelated to wire layout.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Cell {
    /// Signed multiplicity, negative after subtraction.
    pub count: i64,
    /// XOR of native reconciliation keys.
    pub key_xor: u64,
    /// XOR of reference CRC32 key checksums.
    pub hash_xor: u32,
}
/// One actual peel result; `Stalled` authorizes retry/full fallback, not success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decode {
    /// One key was really removed from the difference filter.
    Item {
        /// Exact recovered, still collision-prone key.
        key: Key,
        /// +1 exists in minuend, -1 in the subtracted filter.
        side: i8,
    },
    /// Every count, key and checksum is zero.
    Empty,
    /// Nonzero cells remain, with no valid pure bucket.
    Stalled,
}
/// Caller-owned IBF, with checked operations and no allocator/runtime.
pub struct Ibf<'a> {
    cells: &'a mut [Cell],
    hashes: u8,
    order: Order,
}
impl<'a> Ibf<'a> {
    /// Initialize caller cells after complete parameter validation.
    pub fn clear(cells: &'a mut [Cell], hashes: u8, order: Order) -> Result<Self, Error> {
        let mut view = Self::view(cells, hashes, order)?;
        view.reset();
        Ok(view)
    }
    /// Borrow existing cells without clearing them; explicit alias for caller
    /// state-machine receive/difference buffers.
    pub fn from_cells(cells: &'a mut [Cell], hashes: u8, order: Order) -> Result<Self, Error> {
        Self::view(cells, hashes, order)
    }
    /// Borrow existing cells without resetting their actual data.
    pub fn view(cells: &'a mut [Cell], hashes: u8, order: Order) -> Result<Self, Error> {
        if cells.is_empty()
            || cells.len() > u32::MAX as usize
            || hashes == 0
            || usize::from(hashes) > cells.len()
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            cells,
            hashes,
            order,
        })
    }
    /// Current actual cells, without serializing Rust layout.
    #[must_use]
    pub fn cells(&self) -> &[Cell] {
        self.cells
    }
    /// Actual number of buckets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cells.len()
    }
    /// Hash multiplicity used for all keys.
    #[must_use]
    pub const fn hashes(&self) -> u8 {
        self.hashes
    }
    /// Explicit source ABI profile.
    #[must_use]
    pub const fn order(&self) -> Order {
        self.order
    }
    /// Remove all content without altering backing capacity/profile.
    pub fn reset(&mut self) {
        self.cells.fill(Cell::default());
    }
    /// Whether every original count, key and checksum is zero.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cells.iter().all(|c| *c == Cell::default())
    }
    fn locations(&self, key: Key, indices: &mut [u32; MAX_HASHES]) -> Result<usize, Error> {
        key.indices(self.cells.len() as u32, self.hashes, self.order, indices)
    }
    /// Check one insertion/removal without changing any cell.
    pub fn check_change(&self, key: Key, side: i8) -> Result<(), Error> {
        if side != -1 && side != 1 {
            return Err(Error::InvalidInput);
        }
        let mut indices = [0; MAX_HASHES];
        let count = self.locations(key, &mut indices)?;
        for index in &indices[..count] {
            self.cells[*index as usize]
                .count
                .checked_add(i64::from(side))
                .ok_or(Error::Overflow)?;
        }
        Ok(())
    }
    fn change(&mut self, key: Key, side: i8) -> Result<(), Error> {
        if side != -1 && side != 1 {
            return Err(Error::InvalidInput);
        }
        let mut indices = [0; MAX_HASHES];
        let count = self.locations(key, &mut indices)?;
        for index in &indices[..count] {
            self.cells[*index as usize]
                .count
                .checked_add(i64::from(side))
                .ok_or(Error::Overflow)?;
        }
        let checksum = key.checksum(self.order);
        for index in &indices[..count] {
            let cell = &mut self.cells[*index as usize];
            cell.count += i64::from(side);
            cell.key_xor ^= key.0;
            cell.hash_xor ^= checksum;
        }
        Ok(())
    }
    /// Insert one original key; all overflow/work refusal precedes mutation.
    pub fn insert(&mut self, key: Key) -> Result<(), Error> {
        self.change(key, 1)
    }
    /// Remove one original key, the actual inverse of insertion.
    pub fn remove(&mut self, key: Key) -> Result<(), Error> {
        self.change(key, -1)
    }
    /// Subtract equal-shape/profile filter contents without mutating the other.
    pub fn subtract(&mut self, other: &Ibf<'_>) -> Result<(), Error> {
        if self.hashes != other.hashes || self.order != other.order {
            return Err(Error::InvalidInput);
        }
        self.subtract_cells(other.cells())
    }
    /// Subtract caller-provided cells of the same actual bucket shape.
    pub fn subtract_cells(&mut self, other: &[Cell]) -> Result<(), Error> {
        if self.cells.len() != other.len() {
            return Err(Error::InvalidInput);
        }
        for (left, right) in self.cells.iter().zip(other) {
            left.count.checked_sub(right.count).ok_or(Error::Overflow)?;
        }
        for (left, right) in self.cells.iter_mut().zip(other) {
            left.count -= right.count;
            left.key_xor ^= right.key_xor;
            left.hash_xor ^= right.hash_xor;
        }
        Ok(())
    }
    /// Scan at most the explicit cell count and peel at most one original key.
    /// A checksum match also has to hit its own real reference bucket index.
    pub fn peel(&mut self) -> Result<Decode, Error> {
        let mut indices = [0; MAX_HASHES];
        for index in 0..self.cells.len() {
            let cell = self.cells[index];
            if cell.count != 1 && cell.count != -1 {
                continue;
            }
            let key = Key(cell.key_xor);
            if key.checksum(self.order) != cell.hash_xor {
                continue;
            }
            let count = self.locations(key, &mut indices)?;
            if !indices[..count].contains(&(index as u32)) {
                continue;
            }
            let inverse = -cell.count;
            for location in &indices[..count] {
                self.cells[*location as usize]
                    .count
                    .checked_add(inverse)
                    .ok_or(Error::Overflow)?;
            }
            for location in &indices[..count] {
                let target = &mut self.cells[*location as usize];
                target.count += inverse;
                target.key_xor ^= key.0;
                target.hash_xor ^= cell.hash_xor;
            }
            return Ok(Decode::Item {
                key,
                side: cell.count as i8,
            });
        }
        Ok(if self.is_empty() {
            Decode::Empty
        } else {
            Decode::Stalled
        })
    }
    /// Minimal positive counter bit width. Empty filters use1 instead of the
    /// reference's undefined clz(0)/zero-width pack path. Negative filters cannot send.
    pub fn max_counter_bits(&self) -> Result<u8, Error> {
        let mut max = 0;
        for cell in self.cells.iter() {
            if cell.count < 0 {
                return Err(Error::InvalidInput);
            }
            max = max.max(cell.count as u64);
        }
        Ok((64 - max.leading_zeros()).max(1) as u8)
    }
    /// Counter-width value for the reference nativeu16 IBF header. Serialization
    /// of that header belongs to the official wire codec, with the same Order.
    pub fn counter_bits(&self) -> Result<u16, Error> {
        self.max_counter_bits().map(u16::from)
    }
    fn range(&self, start: usize, count: usize) -> Result<&[Cell], Error> {
        if count == 0 {
            return Err(Error::InvalidInput);
        }
        self.cells
            .get(start..start.checked_add(count).ok_or(Error::Overflow)?)
            .ok_or(Error::Capacity)
    }
    /// Reference actual frame payload size, including unused canonical-zero padding.
    pub fn wire_len(count: usize) -> Result<usize, Error> {
        count.checked_mul(BUCKET_WIRE_BYTES).ok_or(Error::Overflow)
    }
    /// Actual meaningful bytes before the ignored end padding.
    pub fn packed_len(count: usize, bits: u8) -> Result<usize, Error> {
        if bits == 0 || bits > 64 {
            return Err(Error::InvalidInput);
        }
        let counters = count
            .checked_mul(usize::from(bits))
            .and_then(|n| n.checked_add(7))
            .ok_or(Error::Overflow)?
            / 8;
        count
            .checked_mul(12)
            .and_then(|n| n.checked_add(counters))
            .ok_or(Error::Overflow)
    }
    /// Encode native keys, native CRC sums, then contiguous MSB-first counters.
    /// Preflight preserves output on error. Only original nonnegative counts send.
    pub fn encode_slice(
        &self,
        start: usize,
        count: usize,
        bits: u8,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        self.encode(start, count, bits, false, out)
    }
    pub(crate) fn encode_estimator_slice(
        &self,
        start: usize,
        count: usize,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        self.encode(start, count, 8, true, out)
    }
    fn encode(
        &self,
        start: usize,
        count: usize,
        bits: u8,
        truncate8: bool,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let cells = self.range(start, count)?;
        let len = Self::wire_len(count)?;
        let packed = Self::packed_len(count, bits)?;
        if out.len() < len || packed > len {
            return Err(Error::Capacity);
        }
        for cell in cells {
            if cell.count < 0 {
                return Err(Error::InvalidInput);
            }
            if !truncate8 && bits < 64 && (cell.count as u64) >= (1u64 << bits) {
                return Err(Error::Capacity);
            }
        }
        let output = &mut out[..len];
        output.fill(0);
        for (index, cell) in cells.iter().enumerate() {
            output[index * 8..index * 8 + 8].copy_from_slice(&self.order.u64(cell.key_xor));
            let at = count * 8 + index * 4;
            output[at..at + 4].copy_from_slice(&self.order.u32(cell.hash_xor));
            let value = if truncate8 {
                (cell.count as u64) & 255
            } else {
                cell.count as u64
            };
            put_bits(
                &mut output[count * 12..packed],
                index * usize::from(bits),
                bits,
                value,
            );
        }
        Ok(len)
    }
    /// Decode one exact native slice. Counter width and all i64 ranges validate
    /// before any actual cell changes. Ignored reference padding need not be zero.
    pub fn read_slice(
        &mut self,
        start: usize,
        count: usize,
        bits: u8,
        input: &[u8],
    ) -> Result<(), Error> {
        self.range(start, count)?;
        let len = Self::wire_len(count)?;
        let packed = Self::packed_len(count, bits)?;
        if input.len() != len || packed > len {
            return Err(Error::Malformed);
        }
        for index in 0..count {
            if get_bits(&input[count * 12..packed], index * usize::from(bits), bits)
                > i64::MAX as u64
            {
                return Err(Error::Overflow);
            }
        }
        for index in 0..count {
            let at = index * 8;
            let key = self
                .order
                .read_u64(input[at..at + 8].try_into().map_err(|_| Error::Truncated)?);
            let at = count * 8 + index * 4;
            let hash = self
                .order
                .read_u32(input[at..at + 4].try_into().map_err(|_| Error::Truncated)?);
            self.cells[start + index] = Cell {
                count: get_bits(&input[count * 12..packed], index * usize::from(bits), bits) as i64,
                key_xor: key,
                hash_xor: hash,
            };
        }
        Ok(())
    }
}
fn put_bits(out: &mut [u8], mut offset: usize, bits: u8, value: u64) {
    for bit in (0..usize::from(bits)).rev() {
        if value & (1u64 << bit) != 0 {
            out[offset / 8] |= 1u8 << (7 - offset % 8);
        }
        offset += 1;
    }
}
fn get_bits(input: &[u8], mut offset: usize, bits: u8) -> u64 {
    let mut value = 0;
    for _ in 0..bits {
        value = (value << 1) | u64::from((input[offset / 8] >> (7 - offset % 8)) & 1);
        offset += 1;
    }
    value
}
