//! The coded size, optional intrinsic size, and orientation of a JPEG XL image.

use super::super::{Dimensions, IMAGE_ORIENTATION, ORIENTATION_LABELS};
use super::CODESTREAM;

// Marker, two SizeHeaders, and ImageMetadata through the intrinsic-size flag.
pub(super) const MAX_BYTES: usize = (16usize + 2 * 68 + 6).div_ceil(8);

pub(super) struct Header {
    dimensions: Dimensions,
    orientation: &'static str,
    pub(super) may_have_icc: bool,
}

pub(super) enum Prefix {
    Complete(Header),
    IntrinsicPending(Header),
}

impl Header {
    pub(super) fn parse(bytes: &[u8]) -> Option<Prefix> {
        let mut bits = Bits {
            bytes: bytes.strip_prefix(CODESTREAM)?,
            at: 0,
        };
        let mut header = Self {
            dimensions: bits.size()?,
            orientation: ORIENTATION_LABELS[0],
            may_have_icc: bits.read(1)? == 0,
        };
        // Only non-default ImageMetadata can signal an embedded ICC profile.
        if !header.may_have_icc || bits.read(1)? == 0 {
            return Some(Prefix::Complete(header));
        }
        header.orientation = ORIENTATION_LABELS[bits.read(3)? as usize];
        let intrinsic = match bits.read(1) {
            Some(0) => return Some(Prefix::Complete(header)),
            Some(_) => bits.size(),
            None => None,
        };
        let Some(intrinsic) = intrinsic else {
            return Some(Prefix::IntrinsicPending(header));
        };
        header.dimensions = intrinsic;
        Some(Prefix::Complete(header))
    }

    pub(super) fn emit<E>(
        &self,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        self.dimensions.emit(emit)?;
        emit(IMAGE_ORIENTATION, self.orientation.as_bytes())
    }
}

struct Bits<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Bits<'_> {
    fn size(&mut self) -> Option<Dimensions> {
        let small = self.read(1)? != 0;
        let height = self.dimension(small)?;
        let ratio = self.read(3)?;
        let width = if ratio == 0 {
            self.dimension(small)?
        } else {
            let (numerator, denominator) =
                [(1, 1), (12, 10), (4, 3), (3, 2), (16, 9), (5, 4), (2, 1)][(ratio - 1) as usize];
            u32::try_from(u64::from(height) * numerator / denominator).ok()?
        };
        Dimensions::new(width, height)
    }

    fn read(&mut self, count: usize) -> Option<u32> {
        let end = self.at + count;
        let window = self.bytes.get(self.at / 8..end.div_ceil(8))?;
        let mut value = 0;
        for (i, byte) in window.iter().copied().enumerate() {
            value |= u64::from(byte) << (8 * i);
        }
        value >>= self.at % 8;
        self.at = end;
        Some((value & ((1 << count) - 1)) as u32)
    }

    fn dimension(&mut self, small: bool) -> Option<u32> {
        if small {
            return Some((self.read(5)? + 1) * 8);
        }
        let count = [9, 13, 18, 30][self.read(2)? as usize];
        Some(self.read(count)? + 1)
    }
}
