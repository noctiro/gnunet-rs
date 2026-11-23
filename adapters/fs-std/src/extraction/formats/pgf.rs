//! PGF dimensions and metadata stored in its user data area.

use super::{
    Dimensions, Field, FieldLimits, Format, IMAGE_DIMENSIONS, Input, MIME_TYPE, jpeg, png,
};

pub(super) const SIGNATURE: &[u8; 3] = b"PGF";

const VERSION_6: u8 = 0x20;
const MAIN_HEADER_BYTES: usize = 16;
const MAX_LEVELS: u8 = 30;
const INDEXED_COLOR: u8 = 2;
const PALETTE_BYTES: u64 = 256 * 4;
const EXIV2_PALETTE_BYTES: u64 = 256 * 3;
const CARRIER_PROBE_BYTES: usize = 64;

pub(super) fn visit<E>(
    mut input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    limits: FieldLimits,
    emit: &mut impl FnMut(Field<'_>) -> Result<(), E>,
) -> Result<(), E> {
    let Some(header) = Header::read(&mut input)? else {
        return Ok(());
    };
    header
        .dimensions
        .emit(&mut |kind, bytes| emit(Field::Text(kind, bytes)))?;

    let mut base = 0;
    let mut user_data = header.user_data;
    'nested: while let Some(data) = user_data {
        for start in data.carrier_starts().into_iter().flatten() {
            let Some(length) = data.end.checked_sub(start) else {
                continue;
            };
            let Some(mut child) = input.section(base + start, length) else {
                continue;
            };
            let mut cache = [0; CARRIER_PROBE_BYTES];
            let Some(format) = child.probe(&mut cache)? else {
                continue;
            };
            match format {
                Format::Pgf => {
                    if let Some(nested) = Header::read(&mut child)? {
                        base += start;
                        user_data = nested.user_data;
                        continue 'nested;
                    }
                }
                Format::Png => {
                    if let Some(image) = png::Image::read(&mut child, 0..length)? {
                        return image.visit_metadata(child, limits, emit);
                    }
                }
                Format::Jpeg => {
                    return jpeg::visit_preview(
                        child,
                        limits.text,
                        jpeg::Profiles::Metadata,
                        &mut |kind, bytes| emit(Field::Text(kind, bytes)),
                    );
                }
                Format::Exv => {
                    return jpeg::visit_exv(
                        child,
                        limits.text,
                        jpeg::Profiles::Metadata,
                        &mut |kind, bytes| emit(Field::Text(kind, bytes)),
                    );
                }
                Format::Pdf | Format::Id3 => continue,
                Format::Jpeg2000(_)
                | Format::JpegXl
                | Format::CompressedBmff
                | Format::Cr3
                | Format::Crw
                | Format::Heif(_)
                | Format::Tiff(_)
                | Format::Raf
                | Format::Mrw
                | Format::X3f
                | Format::Psd
                | Format::WebP
                | Format::Gif => {
                    return format.visit_leaf(child, limits, &mut |field| match field {
                        Field::Text(MIME_TYPE | IMAGE_DIMENSIONS, _) => Ok(()),
                        field => emit(field),
                    });
                }
            }
        }
        break;
    }
    Ok(())
}

struct Header {
    dimensions: Dimensions,
    user_data: Option<UserData>,
}

impl Header {
    fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    ) -> Result<Option<Self>, E> {
        let Some(&[b'P', b'G', b'F', version]) = input.range(0, 4)? else {
            return Ok(None);
        };
        let long_header = version & VERSION_6 != 0;
        let (offset, size) = if long_header {
            let Some(&[a, b, c, d]) = input.range(4, 4)? else {
                return Ok(None);
            };
            (8, u64::from(u32::from_le_bytes([a, b, c, d])))
        } else {
            let Some(&[a, b]) = input.range(4, 2)? else {
                return Ok(None);
            };
            (6, u64::from(u16::from_le_bytes([a, b])))
        };
        let end = offset + size;
        if size < MAIN_HEADER_BYTES as u64 || end > input.extent {
            return Ok(None);
        }
        let Some(&[w0, w1, w2, w3, h0, h1, h2, h3, levels, _, _, _, mode, ..]) =
            input.range(offset, MAIN_HEADER_BYTES)?
        else {
            return Ok(None);
        };
        if levels > MAX_LEVELS || (version != 0 && end + u64::from(levels) * 4 > input.extent) {
            return Ok(None);
        }
        let Some(dimensions) = Dimensions::new(
            u32::from_le_bytes([w0, w1, w2, w3]),
            u32::from_le_bytes([h0, h1, h2, h3]),
        ) else {
            return Ok(None);
        };
        let user_data = (version != 0).then_some(UserData {
            start: offset + MAIN_HEADER_BYTES as u64,
            end,
            indexed: mode == INDEXED_COLOR,
            long_header,
        });
        Ok(Some(Self {
            dimensions,
            user_data,
        }))
    }
}

struct UserData {
    start: u64,
    end: u64,
    indexed: bool,
    long_header: bool,
}

impl UserData {
    fn carrier_starts(&self) -> [Option<u64>; 2] {
        let palette = if self.indexed { PALETTE_BYTES } else { 0 };
        [
            Some(self.start + palette),
            // Exiv2 stores indexed palettes using three bytes per color.
            (self.indexed && self.long_header).then_some(self.start + EXIV2_PALETTE_BYTES),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::{EXIV2_PALETTE_BYTES, INDEXED_COLOR, PALETTE_BYTES, SIGNATURE, visit};
    use crate::extraction::formats::{FieldLimits, IMAGE_DIMENSIONS, Input, text_only};
    use std::convert::Infallible;

    // PNG metadata is written in the same user data area as Exiv2's PNG carrier.
    const PNG_PARTS: &[&[u8]] = &[
        b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR\0\0\0\x01\0\0\0\x01\x08\x06\0\0\0\x1f\x15\xc4\x89",
        b"\0\0\0\xa7iTXtXML:com.adobe.xmp\0\0\0\0\0",
        br#"<r:RDF xmlns:r="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><r:Description xmlns:p="http://ns.adobe.com/photoshop/1.0/" p:City="Quito"/></r:RDF>"#,
        b"\x18\xec\xf8\xd1\0\0\0\x0bIDAT\x78\x9c\x63\x60\0\x02\0\0\x05\0\x01\x7a\x5e\xab\x3f",
        b"\0\0\0\0IEND\xae\x42\x60\x82",
    ];

    #[test]
    fn nested_pgf_uses_the_outer_geometry_and_the_jpeg_profiles() {
        fn pgf(width: u32, height: u32, carrier: &[u8]) -> Vec<u8> {
            let mut bytes = b"PGF\x36".to_vec();
            bytes.extend_from_slice(&(16 + carrier.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&width.to_le_bytes());
            bytes.extend_from_slice(&height.to_le_bytes());
            bytes.extend_from_slice(&[0, 0, 8, 1, 0, 0, 0, 0]);
            bytes.extend_from_slice(carrier);
            bytes
        }

        let jpeg = [
            b"\xff\xd8\xff\xfe\0\x07hello".as_slice(),
            b"\xff\xe1\0\x22Exif\0\0",
            b"II*\0\x08\0\0\0\x01\0\x0f\x01\x02\0\x04\0\0\0Cam\0\0\0\0\0",
            b"\xff\xc0\0\x0b\x08\0\x21\0\x40\x01\x01\x11\0",
        ]
        .concat();
        let mut image = pgf(50, 20, &pgf(5, 2, &jpeg));
        let data_end = image.len();
        image.extend_from_slice(b"\xff\xfe\0\x05bad");
        for cached in [false, true] {
            let mut scratch = [0; 512];
            let (prefix, scratch) = if cached {
                (image.as_slice(), &mut scratch[..0])
            } else {
                (SIGNATURE.as_slice(), scratch.as_mut_slice())
            };
            let mut metadata = Vec::new();
            let input = Input::new(prefix, image.len() as u64, scratch, |offset, out| {
                let offset = offset as usize;
                assert!(!cached && offset + out.len() <= data_end);
                out.copy_from_slice(&image[offset..offset + out.len()]);
                Ok::<_, Infallible>(())
            });
            let Ok(()) = visit(
                input,
                FieldLimits::text_only(64),
                &mut text_only(&mut |kind, value| {
                    metadata.push((kind, value.to_vec()));
                    Ok(())
                }),
            );
            assert_eq!(
                metadata,
                [(IMAGE_DIMENSIONS, b"50x20".to_vec()), (95, b"Cam".to_vec())]
            );
        }
    }

    #[test]
    fn indexed_pgf_keeps_nested_metadata_within_the_user_data_extent() {
        for palette in [PALETTE_BYTES as usize, EXIV2_PALETTE_BYTES as usize] {
            let png_start = 24 + palette;
            let mut image = vec![0; png_start];
            image[..4].copy_from_slice(b"PGF\x36");
            image[8..12].copy_from_slice(&50_u32.to_le_bytes());
            image[12..16].copy_from_slice(&20_u32.to_le_bytes());
            image[18] = 8;
            image[19] = 1;
            image[20] = INDEXED_COLOR;
            for bytes in PNG_PARTS {
                image.extend_from_slice(bytes);
            }
            for complete in [true, false] {
                let data_end = if complete {
                    image.len()
                } else {
                    png_start + PNG_PARTS[0].len()
                };
                image[4..8].copy_from_slice(&((data_end - 8) as u32).to_le_bytes());
                let mut scratch = [0; 512];
                let mut metadata = Vec::new();
                let input = Input::new(
                    SIGNATURE,
                    image.len() as u64,
                    &mut scratch,
                    |offset, destination| {
                        let offset = offset as usize;
                        let end = offset + destination.len();
                        assert!(end <= 24 || (png_start..=data_end).contains(&offset));
                        assert!(end <= data_end);
                        destination.copy_from_slice(&image[offset..end]);
                        Ok::<_, Infallible>(())
                    },
                );
                let Ok(()) = visit(
                    input,
                    FieldLimits::text_only(64),
                    &mut text_only(&mut |kind, value| {
                        metadata.push((kind, value.to_vec()));
                        Ok(())
                    }),
                );
                let mut expected = vec![(IMAGE_DIMENSIONS, b"50x20".to_vec())];
                if complete {
                    expected.push((41, b"Quito".to_vec()));
                }
                assert_eq!(metadata, expected);
            }
        }
    }
}
