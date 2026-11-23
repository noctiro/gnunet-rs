//! Foveon CAMF rolling XOR and predictive metadata encodings.

const COMPRESSED_HEADER_BYTES: usize = 32;
const CODE_BYTES: usize = 28;

pub(super) enum Encoding {
    Xor { key: u32 },
    Packed { bias: u16, columns: u32, rows: u32 },
    Bytes { bias: u8 },
}

impl Encoding {
    pub(super) fn decode(self, encoded: &[u8], size: usize) -> Option<Vec<u8>> {
        let mut decoded = Vec::new();
        match self {
            Self::Xor { mut key } => {
                decoded.try_reserve_exact(size).ok()?;
                for &byte in encoded {
                    key = key.wrapping_mul(1597).wrapping_add(51749) % 244944;
                    let reduced = ((u64::from(key) * 301593171) >> 24) as u32;
                    let mask = ((((key << 8) - reduced) >> 1) + reduced) >> 17;
                    decoded.push(byte ^ mask as u8);
                }
                Some(decoded)
            }
            Self::Packed {
                bias,
                columns,
                rows,
            } => {
                let mut differences = Differences::read(encoded)?;
                let samples = (size * 2).div_ceil(3);
                if u64::from(columns) * u64::from(rows) < samples as u64
                    || samples > differences.bits.remaining()
                {
                    return None;
                }
                decoded.try_reserve_exact(size).ok()?;
                let mut first = [[bias; 2]; 2];
                let mut previous = [0; 2];
                let mut pending = None;
                let mut columns = (0..columns).cycle();
                let mut row = 1;
                for _ in 0..samples {
                    let column = columns.next()?;
                    if column == 0 {
                        row ^= 1;
                    }
                    let lane = (column & 1) as usize;
                    let predictor = if column < 2 {
                        &mut first[row][lane]
                    } else {
                        &mut previous[lane]
                    };
                    let value = predictor.wrapping_add_signed(differences.next()? as i16);
                    *predictor = value;
                    previous[lane] = value;
                    if let Some(nibble) = pending.take() {
                        decoded.push(nibble | ((value >> 8) as u8 & 0x0f));
                        if decoded.len() < size {
                            decoded.push(value as u8);
                        }
                    } else {
                        decoded.push((value >> 4) as u8);
                        pending = Some((value << 4) as u8);
                    }
                }
                Some(decoded)
            }
            Self::Bytes { mut bias } => {
                let mut differences = Differences::read(encoded)?;
                if size > differences.bits.remaining() {
                    return None;
                }
                decoded.try_reserve_exact(size).ok()?;
                for _ in 0..size {
                    bias = bias.wrapping_add(differences.next()? as u8);
                    decoded.push(bias);
                }
                Some(decoded)
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Code {
    length: u8,
    magnitude: u8,
}

struct Differences<'a> {
    codes: [Option<Code>; 256],
    bits: Bits<'a>,
}

impl<'a> Differences<'a> {
    fn read(encoded: &'a [u8]) -> Option<Self> {
        let header = encoded.first_chunk::<COMPRESSED_HEADER_BYTES>()?;
        let length = u32::from_le_bytes(*header.last_chunk::<4>()?) as usize;
        let data =
            encoded.get(COMPRESSED_HEADER_BYTES..COMPRESSED_HEADER_BYTES.checked_add(length)?)?;
        let mut codes = [None; 256];
        let mut end = false;
        for (magnitude, &[length, code]) in
            header[..CODE_BYTES].as_chunks::<2>().0.iter().enumerate()
        {
            if length == 0 {
                end = true;
                break;
            }
            let free = 8_u8.checked_sub(length)?;
            let width = 1_usize << free;
            let start = usize::from(code) & !(width - 1);
            let entries = &mut codes[start..start + width];
            if entries.iter().any(Option::is_some) {
                return None;
            }
            entries.fill(Some(Code {
                length,
                magnitude: magnitude as u8,
            }));
        }
        if !end || codes.iter().all(Option::is_none) {
            return None;
        }
        Some(Self {
            codes,
            bits: Bits { data, offset: 0 },
        })
    }

    fn next(&mut self) -> Option<i32> {
        let code = self.codes[usize::from(self.bits.prefix()?)]?;
        self.bits.advance(usize::from(code.length))?;
        if code.magnitude == 0 {
            return Some(0);
        }
        let bits = u32::from(code.magnitude);
        let value = i32::from(self.bits.read(code.magnitude)?);
        Some(if value >= 1 << (bits - 1) {
            value
        } else {
            value + 1 - (1 << bits)
        })
    }
}

struct Bits<'a> {
    data: &'a [u8],
    offset: usize,
}

impl Bits<'_> {
    fn remaining(&self) -> usize {
        self.data.len() * 8 - self.offset
    }

    fn advance(&mut self, length: usize) -> Option<()> {
        if length > self.remaining() {
            return None;
        }
        self.offset += length;
        Some(())
    }

    fn prefix(&self) -> Option<u8> {
        let offset = self.offset / 8;
        let shift = self.offset % 8;
        let first = *self.data.get(offset)?;
        if shift == 0 {
            return Some(first);
        }
        let next = self.data.get(offset + 1).copied().unwrap_or(0);
        Some((first << shift) | (next >> (8 - shift)))
    }

    fn read(&mut self, length: u8) -> Option<u16> {
        let mut remainder = length;
        let mut value = 0;
        while remainder != 0 {
            let width = remainder.min(8);
            let prefix = self.prefix()?;
            self.advance(usize::from(width))?;
            value = (value << width) | u16::from(prefix >> (8 - width));
            remainder -= width;
        }
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_rolling_xor() {
        assert_eq!(
            (Encoding::Xor { key: 1234 })
                .decode(b"\x02\x0a\xd5\xb9\x9e\xa6\x9f\xe1", 8)
                .as_deref(),
            Some(b"CMbM\0\0\x02\0".as_slice())
        );
    }

    #[test]
    fn decodes_signed_differences_and_packs_the_two_sample_lanes() {
        let packed = Encoding::Packed {
            bias: 0x123,
            columns: 4,
            rows: 2,
        };
        assert_eq!(
            packed.decode(&stream(&[0xdc, 0x98]), 12).as_deref(),
            Some(b"\x12\x41\x23\x12\x51\x22\x12\x31\x22\x12\x31\x23".as_slice())
        );
        assert_eq!(
            (Encoding::Bytes { bias: 255 })
                .decode(&stream(&[0xd4]), 4)
                .as_deref(),
            Some(&[0, 0, 255, 254][..])
        );
    }

    #[test]
    fn refuses_overlapping_codes_and_truncated_payloads() {
        let mut corrupt = stream(&[0xff]);
        corrupt[3] = 0; // Both symbols claim the same prefix.
        assert!((Encoding::Bytes { bias: 0 }).decode(&corrupt, 1).is_none());
        assert!(
            (Encoding::Bytes { bias: 0 })
                .decode(&stream(&[0xff]), 5)
                .is_none()
        );
        let mut truncated = stream(&[0xff]);
        assert_eq!(truncated.pop(), Some(0xff));
        assert!(
            (Encoding::Bytes { bias: 0 })
                .decode(&truncated, 1)
                .is_none()
        );
    }

    fn stream(payload: &[u8]) -> Vec<u8> {
        let mut encoded = vec![0; COMPRESSED_HEADER_BYTES];
        encoded[..4].copy_from_slice(&[1, 0, 1, 0x80]);
        encoded[28..].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        encoded.extend_from_slice(payload);
        encoded
    }
}
