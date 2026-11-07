//! Actual old SET IBF: four reference positions and13-byte native columns.
//! No SETU bit-width/20-byte frame or salt multiplication is substituted.
use crate::wire::{IbfSlice, Order};
use alloc::vec::Vec;
use gnunet_types::Error;
pub(crate) const HASHES: usize = 4;
pub(crate) const STRATA: usize = 32;
pub(crate) const STRATUM_BUCKETS: usize = 80;
pub(crate) const STRATUM_BYTES: usize = 1040;
pub(crate) const STRATA_BYTES: usize = 33280;
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub(crate) struct Cell {
    pub key: u64,
    pub checksum: u32,
    pub count: i8,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Peel {
    Item { key: u64, side: i8 },
    Empty,
    Stalled,
    Pending,
}
pub(crate) fn element_key(hash: &[u8; 64], order: Order) -> Result<u64, Error> {
    let mut bytes = [0; 8];
    gnunet_crypto::hkdf_gnunet(hash, &[0, 0], &[], &mut bytes)?;
    Ok(order.read64(bytes))
}
pub(crate) const fn salt(key: u64, salt: u32) -> u64 {
    key.rotate_right(salt % 64)
}
pub(crate) const fn unsalt(key: u64, salt: u32) -> u64 {
    key.rotate_left(salt % 64)
}
fn checksum(key: u64, order: Order) -> u32 {
    gnunet_crypto::crc32_n(&order.u64(key)[..4])
}
fn indices(key: u64, size: usize, order: Order) -> Result<[usize; HASHES], Error> {
    if size < HASHES || u32::try_from(size).is_err() {
        return Err(Error::InvalidInput);
    }
    let size = u32::try_from(size).map_err(|_| Error::TooLarge)?;
    let mut bucket = gnunet_crypto::crc32_n(&order.u64(key));
    let mut output = [0; HASHES];
    let mut filled = 0;
    // Old SET compares saved modulo positions with the unmodded next CRC.
    // Preserve that actual wire-profile multiplicity, including repeated modulo
    // positions. The Rust work bound replaces C's unbounded search, not its
    // ordinary hash choices. These are reconciliation positions, not authority.
    for attempt in 0..65536u32 {
        if !output[..filled].contains(&(bucket as usize)) {
            output[filled] = (bucket % size) as usize;
            filled += 1;
            if filled == HASHES {
                return Ok(output);
            }
        }
        let mixed = (u64::from(bucket) << 32) | u64::from(attempt);
        bucket = gnunet_crypto::crc32_n(&order.u64(mixed));
    }
    Err(Error::Capacity)
}
pub(crate) struct Ibf {
    pub cells: Vec<Cell>,
    order: Order,
    extent: usize,
}
impl Ibf {
    pub fn order(&self) -> Order {
        self.order
    }
    pub fn new(count: usize, limit: usize, order: Order) -> Result<Self, Error> {
        if count < HASHES || count > limit {
            return Err(Error::Capacity);
        }
        let mut cells = Vec::new();
        cells
            .try_reserve_exact(count)
            .map_err(|_| Error::Capacity)?;
        if cells.capacity() > count {
            return Err(Error::Capacity);
        }
        cells.resize(count, Cell::default());
        Ok(Self {
            cells,
            order,
            extent: count,
        })
    }
    pub fn sparse(count: usize, limit: usize, order: Order) -> Result<Self, Error> {
        if count < HASHES || count > limit {
            return Err(Error::Capacity);
        }
        let mut cells = Vec::new();
        cells
            .try_reserve_exact(count)
            .map_err(|_| Error::Capacity)?;
        if cells.capacity() > count {
            return Err(Error::Capacity);
        }
        Ok(Self {
            cells,
            order,
            extent: count,
        })
    }
    pub fn len(&self) -> usize {
        self.extent
    }
    pub fn initialized(&self) -> bool {
        self.cells.len() == self.extent
    }
    pub fn initialize_step(&mut self) -> bool {
        let n = self.cells.len().saturating_add(4096).min(self.extent);
        self.cells.resize(n, Cell::default());
        self.initialized()
    }
    pub fn add(&mut self, key: u64, side: i8) -> Result<(), Error> {
        if !matches!(side, -1 | 1) {
            return Err(Error::InvalidInput);
        }
        if !self.initialized() {
            return Err(Error::NotReady);
        }
        let positions = indices(key, self.extent, self.order)?;
        let hash = checksum(key, self.order);
        for i in positions {
            let c = &mut self.cells[i];
            c.count = c.count.wrapping_add(side);
            c.key ^= key;
            c.checksum ^= hash;
        }
        Ok(())
    }
    pub fn subtract(&mut self, other: &Self) -> Result<(), Error> {
        if !self.initialized() || !other.initialized() {
            return Err(Error::NotReady);
        }
        if self.order != other.order || self.extent != other.extent {
            return Err(Error::InvalidInput);
        }
        for (left, right) in self.cells.iter_mut().zip(&other.cells) {
            left.count = left.count.wrapping_sub(right.count);
            left.key ^= right.key;
            left.checksum ^= right.checksum;
        }
        Ok(())
    }
    pub fn receive_slice(&mut self, offset: usize, slice: IbfSlice<'_>) -> Result<(), Error> {
        let end = offset.checked_add(slice.len()).ok_or(Error::Overflow)?;
        if end > self.extent || offset > self.cells.len() {
            return Err(Error::Malformed);
        }
        if end > self.cells.len() {
            self.cells.resize(end, Cell::default());
        }
        let target = self.cells.get_mut(offset..end).ok_or(Error::Malformed)?;
        for (((cell, key), hash), count) in target
            .iter_mut()
            .zip(slice.keys())
            .zip(slice.hashes())
            .zip(slice.counts())
        {
            *cell = Cell {
                count: i8::from_ne_bytes([*count]),
                key: self.order.read64(*key),
                checksum: self.order.read32(*hash),
            };
        }
        Ok(())
    }
    pub fn encode_slice(&self, offset: usize, count: usize) -> Result<Vec<u8>, Error> {
        let end = offset.checked_add(count).ok_or(Error::Overflow)?;
        let cells = self.cells.get(offset..end).ok_or(Error::InvalidInput)?;
        let len = count.checked_mul(13).ok_or(Error::Overflow)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(len).map_err(|_| Error::Capacity)?;
        if bytes.capacity() > len {
            return Err(Error::Capacity);
        }
        bytes.resize(len, 0);
        let (keys, rest) = bytes.split_at_mut(count * 8);
        let (hashes, counts) = rest.split_at_mut(count * 4);
        for (i, cell) in cells.iter().enumerate() {
            keys[i * 8..i * 8 + 8].copy_from_slice(&self.order.u64(cell.key));
            hashes[i * 4..i * 4 + 4].copy_from_slice(&self.order.u32(cell.checksum));
            counts[i] = cell.count.to_ne_bytes()[0];
        }
        Ok(bytes)
    }
    pub fn peel_step(&mut self, cursor: &mut usize, nonzero: &mut bool) -> Result<Peel, Error> {
        if !self.initialized() {
            return Err(Error::NotReady);
        }
        let end = cursor.saturating_add(64).min(self.extent);
        while *cursor < end {
            let i = *cursor;
            let cell = self.cells[i];
            *cursor += 1;
            *nonzero |= cell != Cell::default();
            if matches!(cell.count, -1 | 1)
                && cell.checksum == checksum(cell.key, self.order)
                && indices(cell.key, self.extent, self.order)?.contains(&i)
            {
                self.add(cell.key, -cell.count)?;
                *cursor = 0;
                *nonzero = false;
                return Ok(Peel::Item {
                    key: cell.key,
                    side: cell.count,
                });
            }
        }
        if *cursor < self.extent {
            Ok(Peel::Pending)
        } else if *nonzero {
            Ok(Peel::Stalled)
        } else {
            Ok(Peel::Empty)
        }
    }
    pub fn peel(&mut self) -> Result<Peel, Error> {
        for i in 0..self.cells.len() {
            let cell = self.cells[i];
            if !matches!(cell.count, -1 | 1) || cell.checksum != checksum(cell.key, self.order) {
                continue;
            }
            if !indices(cell.key, self.cells.len(), self.order)?.contains(&i) {
                continue;
            }
            self.add(cell.key, -cell.count)?;
            return Ok(Peel::Item {
                key: cell.key,
                side: cell.count,
            });
        }
        Ok(if self.cells.iter().all(|c| *c == Cell::default()) {
            Peel::Empty
        } else {
            Peel::Stalled
        })
    }
}
