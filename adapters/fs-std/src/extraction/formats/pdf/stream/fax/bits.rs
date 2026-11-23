//! A positioned MSB-first cursor for CCITT codes and line markers.

use ::fax::BitReader;

#[derive(Clone, Copy)]
pub(super) struct Bits<'a> {
    bytes: &'a [u8],
    position: usize,
    end: usize,
}

impl<'a> Bits<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Option<Self> {
        Some(Self {
            bytes,
            position: 0,
            end: bytes.len().checked_mul(8)?,
        })
    }

    pub(super) fn bit(&mut self) -> Option<bool> {
        let bit = self.peek(1)?;
        self.consume(1).ok()?;
        Some(bit != 0)
    }

    pub(super) fn marker(&mut self, width: u8, code: u16) -> bool {
        self.peek(width) == Some(code) && self.consume(width).is_ok()
    }

    pub(super) fn align(&mut self) -> Option<()> {
        let padding = self.bits_to_byte_boundary();
        (padding == 0 || self.marker(padding, 0)).then_some(())
    }

    pub(super) fn is_aligned(self) -> bool {
        self.bits_to_byte_boundary() == 0
    }

    pub(super) fn is_padding(self) -> bool {
        let remaining = self.end - self.position;
        remaining == 0 || (remaining < 8 && self.peek(remaining as u8) == Some(0))
    }

    pub(super) fn eol(&mut self) -> bool {
        let mut cursor = *self;
        while cursor.marker(8, 0) {}
        for _ in 0..=11 {
            match cursor.bit() {
                Some(true) => {
                    if cursor.position - self.position >= 12 {
                        *self = cursor;
                        return true;
                    }
                    return false;
                }
                Some(false) => {}
                None => return false,
            }
        }
        false
    }

    pub(super) fn find_eol(&mut self) -> Option<()> {
        while self.end - self.position >= 12 {
            if self.peek(12) == Some(1) {
                return Some(());
            }
            self.position += 1;
        }
        None
    }
}

impl BitReader for Bits<'_> {
    type Error = ();

    fn peek(&self, count: u8) -> Option<u16> {
        if count > 16 || self.position == self.end {
            return None;
        }
        let mut word = 0_u32;
        let at = self.position / 8;
        // The cached Huffman table can peek past a short final code. Any
        // selected code must still consume only physically present bits.
        for index in 0..3 {
            word = (word << 8) | u32::from(self.bytes.get(at + index).copied().unwrap_or(0));
        }
        let width = usize::from(count);
        let shift = 24 - self.position % 8 - width;
        Some(((word >> shift) & ((1 << width) - 1)) as u16)
    }

    fn consume(&mut self, count: u8) -> Result<(), Self::Error> {
        let end = self.position.checked_add(usize::from(count)).ok_or(())?;
        if end > self.end {
            return Err(());
        }
        self.position = end;
        Ok(())
    }

    fn bits_to_byte_boundary(&self) -> u8 {
        ((8 - self.position % 8) % 8) as u8
    }
}
