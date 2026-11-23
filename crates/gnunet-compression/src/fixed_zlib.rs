//! Allocation-free zlib with a fixed-Huffman DEFLATE encoder.

use crate::inflate::Inflater;
use gnunet_types::Error;
use miniz_oxide::{MZ_ADLER32_INIT, mz_adler32_oxide};

#[cfg(test)]
mod tests;

const WINDOW: usize = 32_768;
const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
const HASH_BITS: u32 = 11;
const HASH_BUCKETS: usize = 1 << HASH_BITS;
const ZLIB_HEADER: [u8; 2] = [0x78, 0x01];
const CHECKSUM_BYTES: usize = 4;

// RFC 1951 section 3.2.5. Indices are fixed-Huffman symbols starting at 257.
const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_BITS: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

/// Bounded reusable zlib state requiring no allocator.
///
/// The encoder uses the most recently seen offset for each three-byte hash
/// bucket. The decoder accepts standard stored, fixed and dynamic blocks.
pub struct FixedZlib {
    latest: [usize; HASH_BUCKETS],
    inflater: Inflater,
}

impl FixedZlib {
    /// Initialize fixed workspace, suitable for caller-owned static storage.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            latest: [0; HASH_BUCKETS],
            inflater: Inflater::new(),
        }
    }

    /// Encode one complete zlib member into caller storage.
    ///
    /// Capacity refusal may leave a partial prefix. Only success publishes
    /// a member, with its exact length and Adler-32 checksum.
    pub fn compress(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        let (header, tail) = output
            .split_at_mut_checked(ZLIB_HEADER.len())
            .ok_or(Error::Capacity)?;
        let body_capacity = tail
            .len()
            .checked_sub(CHECKSUM_BYTES)
            .ok_or(Error::Capacity)?;
        header.copy_from_slice(&ZLIB_HEADER);
        self.latest.fill(0);
        let deflate = self.deflate(input, &mut tail[..body_capacity])?;
        let checksum = mz_adler32_oxide(MZ_ADLER32_INIT, input).to_be_bytes();
        tail[deflate..deflate + CHECKSUM_BYTES].copy_from_slice(&checksum);
        Ok(ZLIB_HEADER.len() + deflate + CHECKSUM_BYTES)
    }

    /// Decode exactly one whole zlib member, including its checksum.
    /// The caller supplies the decompressed storage and all output capacity.
    pub fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        self.inflater.member(input, output)
    }

    /// Visit one complete zlib member using a caller-owned DEFLATE history.
    /// Returns the exact bytes decoded, bounded by `limit`. The visitor must
    /// keep effects provisional until the whole member and checksum pass.
    pub fn visit_decompressed(
        &mut self,
        input: &[u8],
        workspace: &mut [u8],
        limit: usize,
        visit: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<usize, Error> {
        self.inflater.visit_member(input, workspace, limit, visit)
    }

    fn deflate(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        let mut bits = Bits::new(output);
        // BFINAL=1, BTYPE=01, with the low bit transmitted first.
        bits.write(0b011, 3)?;
        let mut position = 0;
        while let Some(&byte) = input.get(position) {
            let candidate = prefix(&input[position..]).and_then(|key| {
                // Offset zero denotes no entry. Store positions one-based.
                let previous =
                    core::mem::replace(&mut self.latest[key], position + 1).checked_sub(1)?;
                Match::find(input, position, previous)
            });
            if let Some(found) = candidate {
                let end = position + usize::from(found.length);
                bits.encode_match(found)?;
                // Every consumed position stays available, including starts
                // within the just-emitted, possibly overlapping match.
                for index in position + 1..end {
                    if let Some(key) = prefix(&input[index..]) {
                        self.latest[key] = index + 1;
                    }
                }
                position = end;
            } else {
                bits.symbol(u16::from(byte))?;
                position += 1;
            }
        }
        bits.symbol(256)?;
        bits.finish()
    }
}

impl Default for FixedZlib {
    fn default() -> Self {
        Self::new()
    }
}

fn prefix(bytes: &[u8]) -> Option<usize> {
    let [a, b, c] = *bytes.first_chunk::<MIN_MATCH>()?;
    let key = u32::from_be_bytes([0, a, b, c]);
    Some((key.wrapping_mul(0x9e37_79b1) >> (u32::BITS - HASH_BITS)) as usize)
}

struct Match {
    length: u16,
    distance: u16,
}

impl Match {
    fn find(input: &[u8], position: usize, previous: usize) -> Option<Self> {
        let distance = position.checked_sub(previous)?;
        if !(1..=WINDOW).contains(&distance) {
            return None;
        }
        let available = (input.len() - position).min(MAX_MATCH);
        let read = &input[position..position + available];
        let source = &input[previous..previous + available];
        if read[..MIN_MATCH] != source[..MIN_MATCH] {
            return None;
        }
        let matched = read[MIN_MATCH..]
            .iter()
            .zip(&source[MIN_MATCH..])
            .position(|(left, right)| left != right)
            .map_or(available, |mismatch| MIN_MATCH + mismatch);
        Some(Self {
            length: u16::try_from(matched).ok()?,
            distance: u16::try_from(distance).ok()?,
        })
    }
}

struct Bits<'output> {
    output: &'output mut [u8],
    pending: u32,
    used: u8,
    written: usize,
}

impl<'output> Bits<'output> {
    const fn new(output: &'output mut [u8]) -> Self {
        Self {
            output,
            pending: 0,
            used: 0,
            written: 0,
        }
    }

    fn write(&mut self, value: u16, width: u8) -> Result<(), Error> {
        self.pending |= u32::from(value) << self.used;
        self.used += width;
        let bytes = self.used / 8;
        let end = self.written + usize::from(bytes);
        let target = self
            .output
            .get_mut(self.written..end)
            .ok_or(Error::Capacity)?;
        target.copy_from_slice(&self.pending.to_le_bytes()[..usize::from(bytes)]);
        self.pending >>= bytes * 8;
        self.used %= 8;
        self.written = end;
        Ok(())
    }

    fn huffman(&mut self, code: u16, width: u8) -> Result<(), Error> {
        self.write(code.reverse_bits() >> (u16::BITS as u8 - width), width)
    }

    fn symbol(&mut self, symbol: u16) -> Result<(), Error> {
        let (code, width) = match symbol {
            0..=143 => (symbol + 0x30, 8),
            144..=255 => (symbol - 144 + 0x190, 9),
            256..=279 => (symbol - 256, 7),
            280..=287 => (symbol - 280 + 0xc0, 8),
            _ => return Err(Error::InvalidInput),
        };
        self.huffman(code, width)
    }

    fn encode_match(&mut self, found: Match) -> Result<(), Error> {
        let index = LENGTH_BASE.partition_point(|&base| base <= found.length) - 1;
        self.symbol(257 + index as u16)?;
        self.write(found.length - LENGTH_BASE[index], LENGTH_BITS[index])?;
        let (symbol, width, extra) = distance_code(found.distance);
        self.huffman(symbol, 5)?;
        self.write(extra, width)
    }

    fn finish(mut self) -> Result<usize, Error> {
        self.write(0, (8 - self.used) % 8)?;
        Ok(self.written)
    }
}

fn distance_code(distance: u16) -> (u16, u8, u16) {
    let offset = distance - 1;
    if distance <= 4 {
        return (offset, 0, 0);
    }
    let width = (offset.ilog2() - 1) as u8;
    let high = offset >> width;
    let extra = offset & ((1 << width) - 1);
    (u16::from(width) * 2 + high, width, extra)
}
