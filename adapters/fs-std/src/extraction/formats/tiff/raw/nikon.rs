//! Nikon TIFF RAW identification using sensor directories and camera metadata.

use super::{Compression, Subtype};
use crate::extraction::formats::tiff::{
    LinkedPhoto, Selection, Tiff, maker, primary, reader::Kind,
};

const COLOR_FILTER_ARRAY: u64 = 32803;

#[derive(Clone, Copy)]
pub(in crate::extraction::formats::tiff) enum Camera {
    Coolpix5700,
    Standard,
}

impl Camera {
    pub(in crate::extraction::formats::tiff) fn read<E>(
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        root: &Selection,
    ) -> Result<Option<Self>, E> {
        let Some(make) = camera_field(tiff, root, maker::MAKE)? else {
            return Ok(None);
        };
        if !matches!(make, "NIKON" | "NIKON CORPORATION") {
            return Ok(None);
        }
        let model = camera_field(tiff, root, maker::MODEL)?;
        Ok(Some(if matches!(model, Some("E5700" | "COOLPIX 5700")) {
            Self::Coolpix5700
        } else {
            Self::Standard
        }))
    }

    pub(in crate::extraction::formats::tiff) const fn family(self) -> primary::Family {
        match self {
            Self::Coolpix5700 => primary::Family::NikonCoolpix5700,
            Self::Standard => primary::Family::Tiff,
        }
    }

    pub(in crate::extraction::formats::tiff) fn candidate<E>(
        self,
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        raw: &Selection,
        compression: Compression,
    ) -> Result<bool, E> {
        if !matches!(compression.value(), Some(1 | 32769 | 34713))
            || primary::photometric(tiff, raw)? != Some(COLOR_FILTER_ARRAY)
            || !matches!(primary::bits_per_sample(tiff, raw)?, Some(12 | 14 | 16))
        {
            return Ok(false);
        }
        self.family().full_image(tiff, raw)
    }
}

fn camera_field<'a, E>(
    tiff: &'a mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    root: &'a Selection,
    tag: u16,
) -> Result<Option<&'a str>, E> {
    let Some(field) = root.find(tag).filter(|field| {
        !field.duplicate && field.row.kind() == Kind::Ascii && field.row.len() <= 32
    }) else {
        return Ok(None);
    };
    Ok(tiff
        .read_field(&field.row)?
        .and_then(|entry| entry.string())
        .map(str::trim_ascii_end))
}

pub(in crate::extraction::formats::tiff) fn subtype<E>(
    tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    root: &Selection,
    photo: Option<&LinkedPhoto>,
    sensor_compression: Compression,
) -> Result<Option<Subtype>, E> {
    let Some(note) = photo
        .and_then(|photo| photo.fields.find(maker::TAG))
        .filter(|note| !note.duplicate)
    else {
        return Ok(None);
    };
    use maker::nikon::RawIdentity;
    Ok(match maker::nikon::raw_identity(tiff, note.row)? {
        Some(RawIdentity::Nrw) => Some(Subtype::Nrw),
        Some(RawIdentity::Nikon)
            if matches!(sensor_compression.value(), Some(1 | 32769))
                && has_ifd0_thumbnail(tiff, root)? =>
        {
            Some(Subtype::Nrw)
        }
        Some(RawIdentity::Nikon) => Some(Subtype::Nef),
        None => None,
    })
}

/// NRW carries an old-style JPEG thumbnail directly in IFD0.
fn has_ifd0_thumbnail<E>(
    tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    root: &Selection,
) -> Result<bool, E> {
    let thumbnail_field = |tag| {
        root.find(tag).filter(|field| {
            !field.duplicate && field.row.kind() == Kind::Long && field.row.count() == 1
        })
    };
    let (Some(offset), Some(length)) = (
        thumbnail_field(primary::JPEG_INTERCHANGE_FORMAT),
        thumbnail_field(primary::JPEG_INTERCHANGE_LENGTH),
    ) else {
        return Ok(false);
    };
    if Compression::read(tiff, root)?.value() != Some(6) {
        return Ok(false);
    }
    let offset = tiff
        .read_field(&offset.row)?
        .and_then(|entry| entry.unsigned(0));
    let length = tiff
        .read_field(&length.row)?
        .and_then(|entry| entry.unsigned(0));
    let (Some(offset), Some(length)) = (offset, length) else {
        return Ok(false);
    };
    let Some(mut thumbnail) = tiff.section(offset, length) else {
        return Ok(false);
    };
    Ok(thumbnail
        .range(0, 4)?
        .is_some_and(|prefix| prefix.starts_with(b"\xff\xd8\xff")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extraction::formats::{Format, IMAGE_DIMENSIONS, Input, MIME_TYPE};
    use primary::BITS_PER_SAMPLE;
    use std::convert::Infallible;

    #[test]
    fn distinguishes_nikon_raw_from_tiff_using_sensor_and_camera_evidence() {
        let camera_note = note(b"Data");
        let nrw_note = note(b"NRW ");
        for (compression, photometric, bits, maker_note, expected) in [
            (1, 32803, 12, camera_note.as_slice(), Subtype::Nef.mime()),
            (1, 32803, 16, nrw_note.as_slice(), Subtype::Nrw.mime()),
            (32769, 32803, 12, nrw_note.as_slice(), Subtype::Nrw.mime()),
            (34713, 32803, 14, &[][..], Subtype::Nef.mime()),
            (1, 2, 16, camera_note.as_slice(), b"image/tiff"),
            (1, 32803, 16, &[][..], b"image/tiff"),
            (1, 32803, 8, camera_note.as_slice(), b"image/tiff"),
            (1, 32803, 16, &nrw_note[..16], b"image/tiff"),
        ] {
            let fields = extract(&file(compression, photometric, bits, maker_note, None));
            assert!(
                fields
                    .iter()
                    .any(|(kind, bytes)| *kind == MIME_TYPE && bytes == expected),
                "wrong MIME for {compression}/{photometric}/{bits}/{maker_note:?}: {fields:?}"
            );
            if expected != b"image/tiff" {
                assert!(
                    fields
                        .iter()
                        .any(|(kind, bytes)| *kind == IMAGE_DIMENSIONS && bytes == b"4000x3000")
                );
            }
        }
    }

    #[test]
    fn does_not_read_a_makernote_value_beyond_its_owner() {
        let mut nrw_note = note(b"NRW ");
        // The location is valid in the outer TIFF and invalid in the note.
        nrw_note[28..32].copy_from_slice(&48_u32.to_be_bytes());
        let mut bytes = file(1, 32803, 12, &nrw_note, None);
        bytes.resize(256 + 10 + 48, 0);
        bytes.extend_from_slice(b"NRW xyz\0");
        let fields = extract(&bytes);
        assert!(
            fields
                .iter()
                .any(|(kind, bytes)| *kind == MIME_TYPE && bytes == Subtype::Nef.mime())
        );
    }

    #[test]
    fn identifies_nrw_by_the_ifd0_jpeg_only_with_qualified_raw_evidence() {
        let note = note(b"Data");
        const JPEG: &[u8] = b"\xff\xd8\xff\xd9";
        for (sensor_compression, photo, preview_compression, length, payload, expected) in [
            (1, 32803, 6, 4, JPEG, Subtype::Nrw.mime()),
            (32769, 32803, 6, 4, JPEG, Subtype::Nrw.mime()),
            (34713, 32803, 6, 4, JPEG, Subtype::Nef.mime()),
            (1, 32803, 6, 8, JPEG, Subtype::Nef.mime()),
            (1, 32803, 6, 4, b"JPEG", Subtype::Nef.mime()),
            (1, 32803, 7, 4, JPEG, Subtype::Nef.mime()),
            (1, 2, 6, 4, JPEG, b"image/tiff"),
        ] {
            let bytes = file_with_thumbnail(
                sensor_compression,
                photo,
                12,
                &note,
                None,
                Some(Thumbnail {
                    compression: preview_compression,
                    length,
                    payload,
                }),
            );
            let fields = extract(&bytes);
            assert_eq!(
                fields
                    .first()
                    .map(|(kind, bytes)| (*kind, bytes.as_slice())),
                Some((MIME_TYPE, expected))
            );
        }
    }

    #[test]
    fn qualifies_the_invalid_subfile_flag_only_on_a_coolpix_5700_sensor() {
        let camera_note = note(b"Data");
        for (model, bits, photo, expected, dimensions) in [
            (
                b"E5700\0",
                12,
                32803,
                b"image/x-nikon-nef".as_slice(),
                b"4000x3000".as_slice(),
            ),
            (b"E5700\0", 12, 2, b"image/tiff", b"320x200"),
            (b"E5700\0", 8, 32803, b"image/tiff", b"320x200"),
            (b"E5400\0", 12, 32803, b"image/tiff", b"320x200"),
        ] {
            let fields = extract(&file(1, photo, bits, &camera_note, Some((model, u32::MAX))));
            assert!(
                fields
                    .iter()
                    .any(|(kind, bytes)| *kind == MIME_TYPE && bytes == expected)
            );
            assert!(
                fields
                    .iter()
                    .any(|(kind, bytes)| *kind == IMAGE_DIMENSIONS && bytes == dimensions)
            );
        }
    }

    fn note(prefix: &[u8; 4]) -> Vec<u8> {
        // A big-endian Nikon type-3 TIFF within a little-endian image.
        let mut note = b"Nikon\0\x02\0\0\0MM\0*\0\0\0\x08".to_vec();
        note.extend_from_slice(b"\0\x01\0\x14\0\x07\0\0\0\x08\0\0\0\x1a\0\0\0\0");
        note.extend_from_slice(prefix);
        note.extend_from_slice(b"0100");
        note
    }

    fn file(
        compression: u16,
        photometric: u16,
        bits: u16,
        note: &[u8],
        legacy: Option<(&[u8; 6], u32)>,
    ) -> Vec<u8> {
        file_with_thumbnail(compression, photometric, bits, note, legacy, None)
    }

    struct Thumbnail<'a> {
        compression: u16,
        length: u32,
        payload: &'a [u8],
    }

    fn file_with_thumbnail(
        compression: u16,
        photometric: u16,
        bits: u16,
        note: &[u8],
        legacy: Option<(&[u8; 6], u32)>,
        thumbnail: Option<Thumbnail<'_>>,
    ) -> Vec<u8> {
        const MODEL: u32 = 104;
        const PHOTO: u32 = 112;
        const SENSOR: u32 = 144;
        const MAKE: u32 = 224;
        const NOTE: u32 = 256;
        const THUMBNAIL: u32 = 1024;
        const MAKER: &[u8] = b"NIKON CORPORATION\0";
        let mut bytes = b"II*\0\x08\0\0\0".to_vec();
        let mut root = vec![
            (256, 4, 1, 320),
            (257, 4, 1, 200),
            (271, 2, MAKER.len() as u32, MAKE),
            (330, 4, 1, SENSOR),
            (0x8769, 4, 1, PHOTO),
        ];
        if legacy.is_some() {
            root.insert(3, (272, 2, 6, MODEL));
        }
        if let Some(thumbnail) = &thumbnail {
            root.extend([
                (0x0103, 3, 1, u32::from(thumbnail.compression)),
                (primary::JPEG_INTERCHANGE_FORMAT, 4, 1, THUMBNAIL),
                (primary::JPEG_INTERCHANGE_LENGTH, 4, 1, thumbnail.length),
            ]);
            root.sort_unstable_by_key(|&(tag, ..)| tag);
        }
        add_ifd(&mut bytes, 8, &root);
        if let Some((model, _)) = legacy {
            bytes.resize(MODEL as usize, 0);
            bytes.extend_from_slice(model);
        }
        let note_row = [(maker::TAG, 7, note.len() as u32, NOTE)];
        let photo = if note.is_empty() { &[][..] } else { &note_row };
        add_ifd(&mut bytes, PHOTO, photo);
        add_ifd(
            &mut bytes,
            SENSOR,
            &[
                (0x00fe, 4, 1, legacy.map_or(0, |(_, flag)| flag)),
                (256, 4, 1, 4000),
                (257, 4, 1, 3000),
                (BITS_PER_SAMPLE, 3, 1, u32::from(bits)),
                (0x0103, 3, 1, u32::from(compression)),
                (0x0106, 3, 1, u32::from(photometric)),
            ],
        );
        bytes.resize(MAKE as usize, 0);
        bytes.extend_from_slice(MAKER);
        bytes.resize(NOTE as usize, 0);
        bytes.extend_from_slice(note);
        if let Some(thumbnail) = thumbnail {
            bytes.resize(THUMBNAIL as usize, 0);
            bytes.extend_from_slice(thumbnail.payload);
        }
        bytes
    }

    fn add_ifd(bytes: &mut Vec<u8>, at: u32, rows: &[(u16, u16, u32, u32)]) {
        bytes.resize(at as usize, 0);
        bytes.extend_from_slice(&(rows.len() as u16).to_le_bytes());
        for &(tag, kind, count, value) in rows {
            bytes.extend_from_slice(&tag.to_le_bytes());
            bytes.extend_from_slice(&kind.to_le_bytes());
            bytes.extend_from_slice(&count.to_le_bytes());
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&[0; 4]);
    }

    fn extract(bytes: &[u8]) -> Vec<(u32, Vec<u8>)> {
        let mut fields = Vec::new();
        if let Some(format) = Format::detect(bytes) {
            let input = Input::new(bytes, bytes.len() as u64, &mut [], |_, _| {
                Ok::<_, Infallible>(())
            });
            let result = format.visit_text(input, 128, &mut |kind, bytes| {
                fields.push((kind, bytes.to_vec()));
                Ok(())
            });
            assert_eq!(result, Ok(()));
        }
        fields
    }
}
