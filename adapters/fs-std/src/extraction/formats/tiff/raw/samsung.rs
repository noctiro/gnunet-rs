//! Samsung SRW camera identity and sensor-directory framing.

use super::{
    super::{
        maker::{MAKE, MODEL},
        primary,
        reader::{Entry, Kind, Row},
    },
    Compression, Selection, Tiff,
};

pub(in crate::extraction::formats::tiff) const MAKE_BYTES: usize = 48;
const STRIP_OFFSETS: u16 = 0x0111;
const STRIP_BYTE_COUNTS: u16 = 0x0117;
const CFA_DIMENSIONS: u16 = 0x828d;
const CFA_PATTERN: u16 = 0x828e;

pub(in crate::extraction::formats::tiff) enum Camera {
    Standard,
    ByteAlignedChildren,
}

impl Camera {
    pub(in crate::extraction::formats::tiff) fn read<E>(
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        root: &Selection,
    ) -> Result<Option<Self>, E> {
        let Some(make) = ascii_field(root, MAKE, MAKE_BYTES) else {
            return Ok(None);
        };
        if tiff.read_field(make)?.and_then(make_token).is_none() {
            return Ok(None);
        }
        let special = if let Some(model) = ascii_field(root, MODEL, 32) {
            tiff.read_field(model)?
                .and_then(|entry| terminated_ascii(entry.bytes()))
                .is_some_and(|model| {
                    ["NX1100", "NX300", "NX500"]
                        .iter()
                        .any(|name| model.eq_ignore_ascii_case(name))
                })
        } else {
            false
        };
        Ok(Some(if special {
            Self::ByteAlignedChildren
        } else {
            Self::Standard
        }))
    }
}

// Some SRW files declare a Make field that extends past the terminated string.
pub(in crate::extraction::formats::tiff) fn make_token(entry: Entry<'_>) -> Option<&str> {
    if entry.kind() != Kind::Ascii || entry.bytes().len() > MAKE_BYTES {
        return None;
    }
    let make = terminated_ascii(entry.bytes())?;
    make.eq_ignore_ascii_case("Samsung").then_some(make)
}

fn terminated_ascii(bytes: &[u8]) -> Option<&str> {
    let end = bytes.iter().position(|&byte| byte == 0)?;
    let text = bytes[..end].trim_ascii();
    if !text.is_ascii() {
        return None;
    }
    std::str::from_utf8(text).ok()
}

fn ascii_field(image: &Selection, tag: u16, max: usize) -> Option<&Row> {
    image
        .find(tag)
        .filter(|field| {
            !field.duplicate && field.row.kind() == Kind::Ascii && field.row.len() <= max
        })
        .map(|field| &field.row)
}

pub(in crate::extraction::formats::tiff) const fn is_sensor_tag(tag: u16) -> bool {
    matches!(
        tag,
        STRIP_OFFSETS | STRIP_BYTE_COUNTS | CFA_DIMENSIONS | CFA_PATTERN
    )
}

pub(in crate::extraction::formats::tiff) fn is_sensor<E>(
    tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    image: &Selection,
) -> Result<bool, E> {
    if !Compression::is_samsung(tiff, image)?
        || !matches!(primary::bits_per_sample(tiff, image)?, Some(12 | 14))
    {
        return Ok(false);
    }
    let Some(offset) = strip_value(tiff, image, STRIP_OFFSETS)? else {
        return Ok(false);
    };
    let Some(length) = strip_value(tiff, image, STRIP_BYTE_COUNTS)? else {
        return Ok(false);
    };
    if !tiff.contains_data(offset, length) {
        return Ok(false);
    }
    match primary::photometric(tiff, image)? {
        Some(32803) => Ok(true),
        None => has_bayer_pattern(tiff, image),
        _ => Ok(false),
    }
}

fn strip_value<E>(
    tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    image: &Selection,
    tag: u16,
) -> Result<Option<u64>, E> {
    let Some(field) = image.find(tag).filter(|field| {
        !field.duplicate
            && matches!(field.row.kind(), Kind::Short | Kind::Long)
            && field.row.count() == 1
    }) else {
        return Ok(None);
    };
    Ok(tiff
        .read_field(&field.row)?
        .and_then(|entry| entry.unsigned(0)))
}

fn has_bayer_pattern<E>(
    tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    image: &Selection,
) -> Result<bool, E> {
    let Some(dimensions) = image.find(CFA_DIMENSIONS).filter(|field| {
        !field.duplicate && field.row.kind() == Kind::Short && field.row.count() == 2
    }) else {
        return Ok(false);
    };
    if !tiff
        .read_field(&dimensions.row)?
        .is_some_and(|entry| entry.unsigned(0) == Some(2) && entry.unsigned(1) == Some(2))
    {
        return Ok(false);
    }
    let Some(pattern) = image.find(CFA_PATTERN).filter(|field| {
        !field.duplicate && field.row.kind() == Kind::Byte && field.row.count() == 4
    }) else {
        return Ok(false);
    };
    Ok(tiff.read_field(&pattern.row)?.is_some_and(|entry| {
        matches!(
            entry.bytes(),
            [0, 1, 1, 2] | [1, 0, 2, 1] | [1, 2, 0, 1] | [2, 1, 1, 0]
        )
    }))
}
