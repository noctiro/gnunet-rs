//! Hasselblad 3FR identity and embedded TIFF metadata.

use super::super::{Kind, Row, Selection, Tiff, maker, visit_embedded};

pub(super) const ROOT_TAG: u16 = 0xc51b;

// PRONOM fmt/1062 locates this fragment at offsets 1 to 2047.
const FRAGMENT: &[u8] = b"\0\x05\0\x04\0\x01";
const LAST_FRAGMENT_OFFSET: usize = 2047;
const MAXIMUM_MAKE_BYTES: usize = 32;

pub(in crate::extraction::formats::tiff) struct Metadata {
    exif: Option<Row>,
}

impl Metadata {
    pub(in crate::extraction::formats::tiff) fn read<E>(
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        root: &Selection,
    ) -> Result<Option<Self>, E> {
        let Some(make) = root.find(maker::MAKE).filter(|field| {
            !field.duplicate
                && field.row.kind() == Kind::Ascii
                && field.row.len() <= MAXIMUM_MAKE_BYTES
        }) else {
            return Ok(None);
        };
        let maker = tiff.read_field(&make.row)?.and_then(|entry| entry.string());
        if maker.is_none_or(|maker| maker.trim_ascii_end() != "Hasselblad") {
            return Ok(None);
        }
        let Some(prefix) = tiff.prefix(LAST_FRAGMENT_OFFSET + FRAGMENT.len())? else {
            return Ok(None);
        };
        if !prefix.starts_with(b"II*\0")
            || !prefix[1..]
                .windows(FRAGMENT.len())
                .any(|bytes| bytes == FRAGMENT)
        {
            return Ok(None);
        }

        let exif = root.find(ROOT_TAG).filter(|field| {
            !field.duplicate && matches!(field.row.kind(), Kind::Byte | Kind::Undefined)
        });
        Ok(Some(Self {
            exif: exif.map(|field| field.row),
        }))
    }

    pub(in crate::extraction::formats::tiff) fn emit<E>(
        self,
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        limit: usize,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        if let Some(input) = self.exif.and_then(|row| tiff.section_for_field(row)) {
            visit_embedded(input, limit, emit)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ROOT_TAG;
    use crate::extraction::formats::{Format, Input, MIME_TYPE};

    #[test]
    fn identifies_3fr_from_both_markers_and_respects_the_scan_window() {
        for (maker, offset, expected) in [
            (
                b"Hasselblad\0".as_slice(),
                Some(2047),
                b"image/x-hasselblad-3fr".as_slice(),
            ),
            (b"Hasselblad\0", Some(2048), b"image/tiff"),
            (b"Hasselblad\0", None, b"image/tiff"),
            (b"Other\0", Some(1024), b"image/tiff"),
        ] {
            let bytes = file(maker, offset);
            let fields = extract(&bytes);
            assert_eq!(
                fields
                    .first()
                    .map(|(kind, bytes)| (*kind, bytes.as_slice())),
                Some((MIME_TYPE, expected))
            );
            assert_eq!(
                fields
                    .iter()
                    .any(|(kind, bytes)| *kind == 130 && bytes == b"Sam"),
                expected == b"image/x-hasselblad-3fr",
            );
        }
    }

    #[test]
    fn embedded_exif_cannot_read_outside_its_owning_tiff_field() {
        let mut bytes = file(b"Hasselblad\0", Some(1024));
        // Convert the embedded Artist to an external value outside c51b.
        bytes[256 + 14..256 + 18].copy_from_slice(&8_u32.to_le_bytes());
        bytes[256 + 18..256 + 22].copy_from_slice(&32_u32.to_le_bytes());
        bytes[256 + 32..256 + 40].copy_from_slice(b"Outside\0");
        let fields = extract(&bytes);
        assert_eq!(
            fields
                .first()
                .map(|(kind, bytes)| (*kind, bytes.as_slice())),
            Some((MIME_TYPE, b"image/x-hasselblad-3fr".as_slice())),
        );
        assert!(!fields.iter().any(|(kind, _)| *kind == 130));
    }

    fn file(maker: &[u8], offset: Option<usize>) -> Vec<u8> {
        const EXIF: &[u8] = b"II*\0\x08\0\0\0\x01\0\x3b\x01\x02\0\x04\0\0\0Sam\0\0\0\0\0";
        let mut bytes = b"II*\0\x08\0\0\0\x02\0".to_vec();
        for (tag, kind, count, value) in [
            (0x010f_u16, 2_u16, maker.len() as u32, 128_u32),
            (ROOT_TAG, 7, EXIF.len() as u32, 256),
        ] {
            bytes.extend_from_slice(&tag.to_le_bytes());
            bytes.extend_from_slice(&kind.to_le_bytes());
            bytes.extend_from_slice(&count.to_le_bytes());
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&[0; 4]);
        bytes.resize(128, 0);
        bytes.extend_from_slice(maker);
        bytes.resize(256, 0);
        bytes.extend_from_slice(EXIF);
        bytes.resize(2100, 0);
        if let Some(offset) = offset {
            bytes[offset..offset + super::FRAGMENT.len()].copy_from_slice(super::FRAGMENT);
        }
        bytes
    }

    fn extract(bytes: &[u8]) -> Vec<(u32, Vec<u8>)> {
        let mut fields = Vec::new();
        if let Some(format) = Format::detect(bytes) {
            let result = format.visit_text(
                Input::new(bytes, bytes.len() as u64, &mut [], |_, _| {
                    Err("unexpected read")
                }),
                128,
                &mut |kind, bytes| {
                    fields.push((kind, bytes.to_vec()));
                    Ok(())
                },
            );
            assert_eq!(result, Ok(()));
        }
        fields
    }
}
