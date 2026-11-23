//! Positioned metadata extraction from a WebP RIFF container.

use super::{Dimensions, Field, FieldLimits, Input, icc, tiff, xmp};

pub(super) const HEADER_BYTES: usize = 12;
const CHUNK_HEADER_BYTES: usize = 8;
const VP8X_FIELDS: usize = 10;
const MAX_RIFF_SIZE: u32 = u32::MAX - 9;
const HAS_ICC: u8 = 0x20;
const HAS_EXIF: u8 = 0x08;
const HAS_XMP: u8 = 0x04;

pub(super) fn is_webp(prefix: &[u8]) -> bool {
    riff_end(prefix).is_some()
}

pub(super) fn visit<E>(
    mut input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    limits: FieldLimits,
    emit: &mut impl FnMut(Field<'_>) -> Result<(), E>,
) -> Result<(), E> {
    let Some(end) = input.range(0, HEADER_BYTES)?.and_then(riff_end) else {
        return Ok(());
    };
    if end > input.extent {
        return Ok(());
    }

    let Some(first) = Chunk::read(&mut input, HEADER_BYTES as u64, end)? else {
        return Ok(());
    };
    let Some(header) = ImageHeader::read(&mut input, first)? else {
        return Ok(());
    };
    header
        .dimensions
        .emit(&mut |kind, data| emit(Field::Text(kind, data)))?;
    let mut pending = header.metadata;
    if limits.icc < icc::MIN_BYTES {
        pending &= !HAS_ICC;
    }
    let mut offset = first.next;
    while pending != 0 {
        let Some(chunk) = Chunk::read(&mut input, offset, end)? else {
            break;
        };
        offset = chunk.next;
        match &chunk.kind {
            b"ICCP" if pending & HAS_ICC != 0 => {
                pending &= !HAS_ICC;
                if chunk.length <= limits.icc
                    && let Some(bytes) = input.range(chunk.data, chunk.length)?
                    && let Some(profile) = icc::Profile::parse(bytes, limits.icc)
                {
                    emit(Field::ColorProfile(profile))?;
                }
            }
            b"ANIM" | b"ANMF" | b"ALPH" | b"VP8 " | b"VP8L" => pending &= !HAS_ICC,
            b"EXIF" if pending & HAS_EXIF != 0 => {
                pending &= !HAS_EXIF;
                if let Some(profile) = input.range(chunk.data, chunk.length)? {
                    let tiff = profile.strip_prefix(b"Exif\0\0").unwrap_or(profile);
                    tiff::visit_exif(tiff, limits.text, &mut |kind, data| {
                        emit(Field::Text(kind, data))
                    })?;
                }
            }
            b"XMP " if pending & HAS_XMP != 0 => {
                pending &= !HAS_XMP;
                if let Some(packet) = input.range(chunk.data, chunk.length)? {
                    xmp::visit(packet, limits.text, &mut |kind, data| {
                        emit(Field::Text(kind, data))
                    })?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn riff_end(prefix: &[u8]) -> Option<u64> {
    let [b'R', b'I', b'F', b'F', a, b, c, d, b'W', b'E', b'B', b'P'] = *prefix.first_chunk()?
    else {
        return None;
    };
    let size = u32::from_le_bytes([a, b, c, d]);
    ((4..=MAX_RIFF_SIZE).contains(&size) && size.is_multiple_of(2)).then_some(u64::from(size) + 8)
}

#[derive(Clone, Copy)]
struct Chunk {
    kind: [u8; 4],
    data: u64,
    length: usize,
    next: u64,
}

impl Chunk {
    fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        offset: u64,
        riff_end: u64,
    ) -> Result<Option<Self>, E> {
        let data = offset + CHUNK_HEADER_BYTES as u64;
        if data > riff_end {
            return Ok(None);
        }
        let Some(&[k0, k1, k2, k3, a, b, c, d]) = input.range(offset, CHUNK_HEADER_BYTES)? else {
            return Ok(None);
        };
        let length = u32::from_le_bytes([a, b, c, d]);
        let end = data + u64::from(length);
        let padding = u64::from(length % 2);
        let next = end + padding;
        if next > riff_end || (padding != 0 && input.range(end, 1)? != Some([0].as_slice())) {
            return Ok(None);
        }
        Ok(Some(Self {
            kind: [k0, k1, k2, k3],
            data,
            length: length as usize,
            next,
        }))
    }
}

struct ImageHeader {
    dimensions: Dimensions,
    metadata: u8,
}

impl ImageHeader {
    fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        first: Chunk,
    ) -> Result<Option<Self>, E> {
        let width = match &first.kind {
            b"VP8X" => VP8X_FIELDS,
            b"VP8 " => 10,
            b"VP8L" => 5,
            _ => return Ok(None),
        };
        if first.length < width {
            return Ok(None);
        }
        let Some(bytes) = input.range(first.data, width)? else {
            return Ok(None);
        };
        Ok(match &first.kind {
            b"VP8X" => canvas(bytes).map(|dimensions| Self {
                dimensions,
                metadata: bytes[0] & (HAS_ICC | HAS_EXIF | HAS_XMP),
            }),
            b"VP8 " => lossy_dimensions(bytes).map(Self::simple),
            b"VP8L" => lossless_dimensions(bytes).map(Self::simple),
            _ => None,
        })
    }

    const fn simple(dimensions: Dimensions) -> Self {
        Self {
            dimensions,
            metadata: 0,
        }
    }
}

fn canvas(bytes: &[u8]) -> Option<Dimensions> {
    let [_, _, _, _, w0, w1, w2, h0, h1, h2] = *bytes.first_chunk()?;
    let width = u32::from_le_bytes([w0, w1, w2, 0]) + 1;
    let height = u32::from_le_bytes([h0, h1, h2, 0]) + 1;
    width.checked_mul(height)?;
    Dimensions::new(width, height)
}

fn lossy_dimensions(bytes: &[u8]) -> Option<Dimensions> {
    let [tag, _, _, 0x9d, 0x01, 0x2a, w0, w1, h0, h1] = *bytes.first_chunk()? else {
        return None;
    };
    if tag & 1 != 0 {
        return None;
    }
    let width = u16::from_le_bytes([w0, w1]) & 0x3fff;
    let height = u16::from_le_bytes([h0, h1]) & 0x3fff;
    Dimensions::new(width.into(), height.into())
}

fn lossless_dimensions(bytes: &[u8]) -> Option<Dimensions> {
    let [0x2f, a, b, c, d] = *bytes.first_chunk()? else {
        return None;
    };
    let header = u32::from_le_bytes([a, b, c, d]);
    if header >> 29 != 0 {
        return None;
    }
    Dimensions::new((header & 0x3fff) + 1, ((header >> 14) & 0x3fff) + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extraction::formats::text_only;
    use std::convert::Infallible;

    #[test]
    fn reads_late_xmp_without_reading_the_image_payload() {
        const IMAGE_BYTES: u32 = 256 * 1024;
        const PACKET: &[u8] = br#"<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:xmp="http://ns.adobe.com/xap/1.0/"><rdf:Description xmp:CreatorTool="Canvas"/></rdf:RDF>"#;
        const METADATA_BYTES: usize = CHUNK_HEADER_BYTES + PACKET.len() + PACKET.len() % 2;
        let mut prefix = b"RIFF\0\0\0\0WEBPVP8X\x0a\0\0\0\x04\0\0\0\x03\0\0\x02\0\0VP8 ".to_vec();
        prefix.extend_from_slice(&IMAGE_BYTES.to_le_bytes());
        let metadata_at = prefix.len() as u64 + u64::from(IMAGE_BYTES);
        let extent = metadata_at + METADATA_BYTES as u64;
        prefix[4..8].copy_from_slice(&((extent - 8) as u32).to_le_bytes());

        let mut metadata = b"XMP ".to_vec();
        metadata.extend_from_slice(&(PACKET.len() as u32).to_le_bytes());
        metadata.extend_from_slice(PACKET);
        metadata.resize(METADATA_BYTES, 0);
        let mut scratch = [0; METADATA_BYTES];
        let input = Input::new(&prefix, extent, &mut scratch, |offset, out: &mut [u8]| {
            assert!(offset >= metadata_at);
            let start = (offset - metadata_at) as usize;
            out.copy_from_slice(&metadata[start..start + out.len()]);
            Ok(())
        });
        let mut fields = Vec::new();
        let Ok(()) = visit(
            input,
            FieldLimits::text_only(64),
            &mut text_only(&mut |kind, value| -> Result<(), Infallible> {
                fields.push((kind, value.to_vec()));
                Ok(())
            }),
        );
        assert_eq!(fields, [(112, b"4x3".to_vec()), (56, b"Canvas".to_vec())]);
    }

    #[test]
    fn reads_the_uncompressed_geometry_of_both_simple_bitstream_headers() {
        let lossless = (5_u32 << 14) | 10 | (1 << 28);
        let mut packed = [0x2f; 5];
        packed[1..].copy_from_slice(&lossless.to_le_bytes());
        for (chunk, frame) in [
            (b"VP8 ", b"\x10\0\0\x9d\x01\x2a\x0b\0\x06\xc0".as_slice()),
            (b"VP8L", &packed),
        ] {
            let mut webp = b"RIFF\0\0\0\0WEBP".to_vec();
            webp.extend_from_slice(chunk);
            webp.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            webp.extend_from_slice(frame);
            webp.resize(webp.len().next_multiple_of(2), 0);
            let length = webp.len() as u32 - 8;
            webp[4..8].copy_from_slice(&length.to_le_bytes());
            let mut fields = Vec::new();
            let input = Input::new(&webp, webp.len() as u64, &mut [], |_, _: &mut [u8]| Ok(()));
            let Ok(()) = visit(
                input,
                FieldLimits::text_only(64),
                &mut text_only(&mut |kind, value| -> Result<(), Infallible> {
                    fields.push((kind, value.to_vec()));
                    Ok(())
                }),
            );
            assert_eq!(fields, [(112, b"11x6".to_vec())]);
        }
    }
}
