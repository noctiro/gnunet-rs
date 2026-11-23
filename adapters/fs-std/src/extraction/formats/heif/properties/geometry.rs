//! Exact crop and scale arithmetic for HEIF item properties.

use std::num::{NonZeroU16, NonZeroU32};

use super::Dimensions;

pub(super) struct Aperture {
    horizontal: ApertureAxis,
    vertical: ApertureAxis,
}

impl Aperture {
    pub(super) fn parse(bytes: &[u8]) -> Option<Self> {
        let (fields, remainder) = bytes.as_chunks::<4>();
        let &[wn, wd, hn, hd, xn, xd, yn, yd] = fields else {
            return None;
        };
        if !remainder.is_empty() {
            return None;
        }
        Some(Self {
            horizontal: ApertureAxis::new(wn, wd, xn, xd)?,
            vertical: ApertureAxis::new(hn, hd, yn, yd)?,
        })
    }

    pub(super) fn apply(self, size: Dimensions) -> Option<Dimensions> {
        Dimensions::new(
            self.horizontal.pixels(size.width)?,
            self.vertical.pixels(size.height)?,
        )
    }
}

struct ApertureAxis {
    extent: NonZeroU32,
    extent_denominator: NonZeroU32,
    offset: i32,
    offset_denominator: NonZeroU32,
}

impl ApertureAxis {
    fn new(
        extent: [u8; 4],
        denominator: [u8; 4],
        offset: [u8; 4],
        offset_denominator: [u8; 4],
    ) -> Option<Self> {
        Some(Self {
            extent: NonZeroU32::new(u32::from_be_bytes(extent))?,
            extent_denominator: NonZeroU32::new(u32::from_be_bytes(denominator))?,
            offset: i32::from_be_bytes(offset),
            offset_denominator: NonZeroU32::new(u32::from_be_bytes(offset_denominator))?,
        })
    }

    fn pixels(self, input: NonZeroU32) -> Option<u32> {
        let extent = u128::from(self.extent.get());
        let denominator = u128::from(self.extent_denominator.get());
        let margins = (u128::from(input.get()) * denominator).checked_sub(extent)?;
        // One side of the centered aperture must absorb the absolute offset.
        // Test 2 * |offset| <= input - aperture without rounding either edge.
        let displacement = 2 * u128::from(self.offset.unsigned_abs()) * denominator;
        if displacement > margins * u128::from(self.offset_denominator.get()) {
            return None;
        }
        u32::try_from((extent + denominator / 2) / denominator).ok()
    }
}

pub(super) struct Scaling {
    horizontal: ScaleFactor,
    vertical: ScaleFactor,
}

impl Scaling {
    pub(super) fn parse(bytes: &[u8]) -> Option<Self> {
        let (&[0, 0, 0, 0], rest) = bytes.split_first_chunk()? else {
            return None;
        };
        let (fields, remainder) = rest.as_chunks::<2>();
        let &[wn, wd, hn, hd] = fields else {
            return None;
        };
        if !remainder.is_empty() {
            return None;
        }
        Some(Self {
            horizontal: ScaleFactor::new(wn, wd)?,
            vertical: ScaleFactor::new(hn, hd)?,
        })
    }

    pub(super) fn apply(self, size: Dimensions) -> Option<Dimensions> {
        Dimensions::new(
            self.horizontal.pixels(size.width)?,
            self.vertical.pixels(size.height)?,
        )
    }
}

struct ScaleFactor {
    numerator: NonZeroU16,
    denominator: NonZeroU16,
}

impl ScaleFactor {
    fn new(numerator: [u8; 2], denominator: [u8; 2]) -> Option<Self> {
        Some(Self {
            numerator: NonZeroU16::new(u16::from_be_bytes(numerator))?,
            denominator: NonZeroU16::new(u16::from_be_bytes(denominator))?,
        })
    }

    fn pixels(self, input: NonZeroU32) -> Option<u32> {
        let scaled = u64::from(input.get()) * u64::from(self.numerator.get());
        u32::try_from(scaled.div_ceil(u64::from(self.denominator.get()))).ok()
    }
}
