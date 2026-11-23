//! Primary RAW image selection within TIFF-based camera files.

use std::collections::{HashSet, VecDeque};

use super::{
    Selection,
    raw::{self, Compression, Cr2Header, Subtype, samsung},
    reader::{Kind, Tiff},
};

const NEW_SUBFILE_TYPE: u16 = 0x00fe;
const IMAGE_WIDTH: u16 = 0x0100;
const IMAGE_LENGTH: u16 = 0x0101;
pub(super) const BITS_PER_SAMPLE: u16 = 0x0102;
const PHOTOMETRIC_INTERPRETATION: u16 = 0x0106;
const SUB_IFDS: u16 = 0x014a;
pub(super) const JPEG_INTERCHANGE_FORMAT: u16 = 0x0201;
pub(super) const JPEG_INTERCHANGE_LENGTH: u16 = 0x0202;
const MAX_DEPTH: u8 = 32;

#[derive(Clone, Copy)]
pub(super) enum Family {
    Tiff,
    Dng,
    Cr2(Cr2Header),
    NikonCoolpix5700,
}

pub(super) enum Alternate {
    Standard(Selection),
    SamsungSensor(Selection),
}

impl Alternate {
    pub(super) const fn image(&self) -> &Selection {
        match self {
            Self::Standard(image) | Self::SamsungSensor(image) => image,
        }
    }

    pub(super) const fn subtype(&self) -> Option<Subtype> {
        match self {
            Self::Standard(_) => None,
            Self::SamsungSensor(_) => Some(Subtype::Srw),
        }
    }
}

impl Family {
    pub(super) fn full_image<E>(
        self,
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        image: &Selection,
    ) -> Result<bool, E> {
        if image.find(JPEG_INTERCHANGE_FORMAT).is_some() {
            return Ok(false);
        }
        if let Some(field) = image.find(NEW_SUBFILE_TYPE) {
            if field.duplicate || field.row.kind() != Kind::Long || field.row.count() != 1 {
                return Ok(false);
            }
            match tiff
                .read_field(&field.row)?
                .and_then(|entry| entry.unsigned(0))
            {
                Some(0) => {}
                // The Coolpix 5700 writes this invalid flag on a 12-bit RAW
                // directory. Preserve normal selection for its RGB TIFFs.
                Some(value)
                    if matches!(self, Self::NikonCoolpix5700)
                        && value == u64::from(u32::MAX)
                        && photometric(tiff, image)? == Some(32803)
                        && bits_per_sample(tiff, image)? == Some(12) => {}
                _ => return Ok(false),
            }
        }
        for tag in [IMAGE_WIDTH, IMAGE_LENGTH] {
            if image.find(tag).is_none_or(|field| field.duplicate)
                || image.dimension(tiff, tag)?.is_none_or(|value| value == 0)
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

pub(super) const fn is_image_tag(tag: u16) -> bool {
    matches!(
        tag,
        NEW_SUBFILE_TYPE
            | IMAGE_WIDTH
            | IMAGE_LENGTH
            | BITS_PER_SAMPLE
            | PHOTOMETRIC_INTERPRETATION
            | SUB_IFDS
            | JPEG_INTERCHANGE_FORMAT
            | JPEG_INTERCHANGE_LENGTH
    ) || raw::is_identity_tag(tag)
}

/// Only an alternate image is returned. Exif, IPTC and XMP still belong
/// to the root TIFF directory and its designated metadata children.
pub(super) fn select<E>(
    tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    root: &Selection,
    family: Family,
) -> Result<Option<Alternate>, E> {
    let root_offset = tiff.first_offset();
    if let Family::Cr2(header) = family {
        let Some(offset) = header.raw_ifd().filter(|&offset| offset != root_offset) else {
            return Ok(None);
        };
        let Some(image) = Selection::read(tiff, offset, is_image_tag)? else {
            return Ok(None);
        };
        return Ok(family
            .full_image(tiff, &image)?
            .then_some(Alternate::Standard(image)));
    }

    if root.find(SUB_IFDS).is_none() {
        return Ok(None);
    }
    let root_raw = raw_image(tiff, root)?;
    let family_is_raw = root_raw || matches!(family, Family::Dng);
    let root_primary = family_is_raw && family.full_image(tiff, root)?;
    if root_primary && root_raw {
        return Ok(None);
    }
    let mut directories = Directories::default();
    if directories.seen.try_reserve(1).is_err() {
        return Ok(None);
    }
    directories.seen.insert(root_offset);
    directories.push_children(tiff, root, 1)?;
    let samsung = if matches!(family, Family::Tiff) {
        samsung::Camera::read(tiff, root)?
    } else {
        None
    };
    let mut fallback = None;
    while let Some((offset, depth)) = directories.pending.pop_front() {
        let word_aligned = offset.is_multiple_of(2);
        let directory = if word_aligned {
            tiff.directory(offset)?
        } else if depth == 1 && matches!(samsung, Some(samsung::Camera::ByteAlignedChildren)) {
            tiff.byte_aligned_child(offset)?
        } else {
            None
        };
        let Some(directory) = directory else {
            continue;
        };
        let Some(image) = Selection::read_directory(tiff, directory, |tag| {
            is_image_tag(tag) || samsung.is_some() && samsung::is_sensor_tag(tag)
        })?
        else {
            continue;
        };
        let full_image = family.full_image(tiff, &image)?;
        if full_image && samsung.is_some() && samsung::is_sensor(tiff, &image)? {
            return Ok(Some(Alternate::SamsungSensor(image)));
        }
        if !word_aligned {
            continue;
        }
        if full_image {
            if raw_image(tiff, &image)? {
                return Ok(Some(Alternate::Standard(image)));
            }
            if !root_primary && family_is_raw && fallback.is_none() {
                directories.push_children(tiff, &image, depth + 1)?;
                fallback = Some(image);
                continue;
            }
        }
        directories.push_children(tiff, &image, depth + 1)?;
    }
    Ok(fallback.map(Alternate::Standard))
}

fn raw_image<E>(
    tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    image: &Selection,
) -> Result<bool, E> {
    Ok(Compression::read(tiff, image)?.is_raw()
        || matches!(photometric(tiff, image)?, Some(32803 | 34892))) // CFA or LinearRaw
}

pub(super) fn photometric<E>(
    tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    image: &Selection,
) -> Result<Option<u64>, E> {
    short_value(tiff, image, PHOTOMETRIC_INTERPRETATION)
}

pub(super) fn bits_per_sample<E>(
    tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    image: &Selection,
) -> Result<Option<u64>, E> {
    short_value(tiff, image, BITS_PER_SAMPLE)
}

fn short_value<E>(
    tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    image: &Selection,
    tag: u16,
) -> Result<Option<u64>, E> {
    let Some(field) = image.find(tag).filter(|field| {
        !field.duplicate && field.row.kind() == Kind::Short && field.row.count() == 1
    }) else {
        return Ok(None);
    };
    Ok(tiff
        .read_field(&field.row)?
        .and_then(|entry| entry.unsigned(0)))
}

#[derive(Default)]
struct Directories {
    pending: VecDeque<(u64, u8)>,
    seen: HashSet<u64>,
}

impl Directories {
    fn push_children<E>(
        &mut self,
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        image: &Selection,
        depth: u8,
    ) -> Result<(), E> {
        if depth > MAX_DEPTH {
            return Ok(());
        }
        let Some(field) = image.find(SUB_IFDS).filter(|field| {
            !field.duplicate
                && matches!(
                    field.row.kind(),
                    Kind::Long | Kind::Ifd | Kind::Long8 | Kind::Ifd8
                )
        }) else {
            return Ok(());
        };
        let Some(children) = tiff.read_field(&field.row)? else {
            return Ok(());
        };
        // Visit each level in TIFF order before following descendants.
        for index in 0..children.count() {
            let Some(offset) = children.unsigned(index).filter(|&offset| offset != 0) else {
                continue;
            };
            if self.seen.contains(&offset) {
                continue;
            }
            if self.seen.try_reserve(1).is_err() || self.pending.try_reserve(1).is_err() {
                break;
            }
            self.seen.insert(offset);
            self.pending.push_back((offset, depth));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extraction::formats::{
        Input,
        tiff::{Container, ProfileKind},
    };
    use std::convert::Infallible;

    #[test]
    fn chooses_real_raw_subifd_without_replacing_ordinary_tiff_primary() {
        for (photometric, family, expected) in [
            (32803, Family::Tiff, Some((4000, 2500))),
            (2, Family::Tiff, None),
            (2, Family::Dng, Some((4000, 2500))),
        ] {
            let mut bytes = b"II*\0\x08\0\0\0".to_vec();
            add_ifd(
                &mut bytes,
                8,
                &[
                    (IMAGE_WIDTH, 4, 1, 320),
                    (IMAGE_LENGTH, 4, 1, 200),
                    (NEW_SUBFILE_TYPE, 4, 1, 1),
                    (SUB_IFDS, 4, 2, 64),
                ],
            );
            bytes.resize(64, 0);
            bytes.extend_from_slice(&80_u32.to_le_bytes());
            bytes.extend_from_slice(&128_u32.to_le_bytes());
            add_ifd(
                &mut bytes,
                80,
                &[
                    (IMAGE_WIDTH, 4, 1, 1024),
                    (IMAGE_LENGTH, 4, 1, 768),
                    (JPEG_INTERCHANGE_FORMAT, 4, 1, 208),
                ],
            );
            add_ifd(
                &mut bytes,
                128,
                &[
                    (IMAGE_WIDTH, 4, 1, 4000),
                    (IMAGE_LENGTH, 4, 1, 2500),
                    (PHOTOMETRIC_INTERPRETATION, 3, 1, photometric),
                    (SUB_IFDS, 4, 1, 8),
                ],
            );
            assert_eq!(dimensions(&bytes, family), expected);
        }
    }

    fn add_ifd(bytes: &mut Vec<u8>, at: usize, rows: &[(u16, u16, u32, u32)]) {
        bytes.resize(at, 0);
        bytes.extend_from_slice(&(rows.len() as u16).to_le_bytes());
        for &(tag, kind, count, value) in rows {
            bytes.extend_from_slice(&tag.to_le_bytes());
            bytes.extend_from_slice(&kind.to_le_bytes());
            bytes.extend_from_slice(&count.to_le_bytes());
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&[0; 4]);
    }

    fn dimensions(bytes: &[u8], family: Family) -> Option<(u32, u32)> {
        let input = Input::new(bytes, bytes.len() as u64, &mut [], |_, _: &mut [u8]| {
            Ok::<(), Infallible>(())
        });
        let mut tiff = Tiff::open(input, ProfileKind::Standalone(Container::Tiff)).ok()??;
        let root_offset = tiff.first_offset();
        let root = Selection::read(&mut tiff, root_offset, is_image_tag).ok()??;
        let primary = select(&mut tiff, &root, family).ok()??;
        let primary = primary.image();
        Some((
            primary.dimension(&mut tiff, IMAGE_WIDTH).ok()??,
            primary.dimension(&mut tiff, IMAGE_LENGTH).ok()??,
        ))
    }
}
