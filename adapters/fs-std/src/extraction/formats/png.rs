//! Positioned PNG metadata scans skip image data inside the original extent.

mod profile;

use super::{
    Dimensions, Field, FieldLimits, Input,
    compression::{Decompression, Encoding as Compression},
    icc, tiff, xmp,
};
use std::ops::Range;

const SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
const HEADER_BYTES: u64 = SIGNATURE.len() as u64 + 8 + 13 + 4;
const MAX_PNG_INTEGER: u32 = 0x7fff_ffff;
const MODIFICATION_DATE: u32 = 59;
const LANGUAGE: u32 = 27;
const KEYWORDS: u32 = 49;
const COMMENT: u32 = 3;

pub(super) fn visit<E>(
    mut input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    limits: FieldLimits,
    emit: &mut impl FnMut(Field<'_>) -> Result<(), E>,
) -> Result<(), E> {
    let extent = input.extent;
    let Some(image) = Image::read(&mut input, 0..extent)? else {
        return Ok(());
    };
    image
        .dimensions
        .emit(&mut |kind, bytes| emit(Field::Text(kind, bytes)))?;
    image.visit_metadata(input, limits, emit)
}

pub(super) struct Image {
    region: Range<u64>,
    dimensions: Dimensions,
}

impl Image {
    pub(super) fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        region: Range<u64>,
    ) -> Result<Option<Self>, E> {
        if region.end > input.extent
            || region.end.saturating_sub(region.start) < HEADER_BYTES
            || input.range(region.start, SIGNATURE.len())? != Some(SIGNATURE.as_slice())
        {
            return Ok(None);
        }
        let offset = region.start + SIGNATURE.len() as u64;
        let Some(header) = ChunkHeader::read(input, offset)? else {
            return Ok(None);
        };
        if header.kind != *b"IHDR" || header.len != 13 {
            return Ok(None);
        }
        Ok(header
            .read_body(input)?
            .and_then(dimensions)
            .map(|dimensions| Self { region, dimensions }))
    }

    pub(super) fn visit_metadata<E>(
        self,
        mut input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        limits: FieldLimits,
        emit: &mut impl FnMut(Field<'_>) -> Result<(), E>,
    ) -> Result<(), E> {
        if let Some(input) = input.section(self.region.start, self.region.end - self.region.start) {
            visit_chunks(input, limits, emit)?;
        }
        Ok(())
    }
}

fn visit_chunks<E>(
    mut input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    limits: FieldLimits,
    emit: &mut impl FnMut(Field<'_>) -> Result<(), E>,
) -> Result<(), E> {
    let max_text_bytes = limits.text;
    let mut compressed = Decompression::new(max_text_bytes.max(limits.icc));
    let mut converted = Vec::new();
    let mut accepts_exif = true;
    let mut accepts_icc = limits.icc >= icc::MIN_BYTES;
    let mut accepts_iptc = true;
    let mut accepts_xmp = true;
    let mut offset = HEADER_BYTES;
    while let Some(header) = ChunkHeader::read(&mut input, offset)? {
        offset = header.next;
        match &header.kind {
            b"IEND" | b"IHDR" => break,
            b"IDAT" => {
                accepts_exif = false;
                accepts_icc = false;
            }
            b"PLTE" => accepts_icc = false,
            b"iCCP" if accepts_icc => {
                accepts_icc = false;
                if let Some(chunk) = header.read_body(&mut input)?
                    && let Some((name, [0, encoded @ ..])) = split_string(chunk.data)
                    && valid_keyword(name)
                    && let Some(bytes) =
                        compressed.decode_limited(Compression::Zlib, encoded, limits.icc)
                    && let Some(profile) = icc::Profile::parse(bytes, limits.icc)
                {
                    emit(Field::ColorProfile(profile))?;
                }
            }
            b"eXIf" if accepts_exif => {
                // PNG carries one raw TIFF profile before its first IDAT.
                accepts_exif = false;
                if let Some(chunk) = header.read_body(&mut input)? {
                    tiff::visit_exif(chunk.data, max_text_bytes, &mut |kind, bytes| {
                        emit(Field::Text(kind, bytes))
                    })?;
                }
            }
            b"tIME" if header.len == 7 => {
                let Some(chunk) = header.read_body(&mut input)? else {
                    continue;
                };
                if let Some(date) = modification_date(chunk.data) {
                    emit(Field::Text(MODIFICATION_DATE, date.as_bytes()))?;
                }
            }
            b"tEXt" | b"zTXt" | b"iTXt" => {
                let Some(chunk) = header.read_body(&mut input)? else {
                    continue;
                };
                let Some(text) = Text::parse(chunk) else {
                    continue;
                };
                let emit = &mut |kind, bytes: &[u8]| emit(Field::Text(kind, bytes));
                if matches!(text.kind, TextKind::RawIptc) && !accepts_iptc
                    || matches!(text.kind, TextKind::Xmp | TextKind::RawXmp) && !accepts_xmp
                {
                    continue;
                }
                let bytes = if text.compressed {
                    let Some(bytes) =
                        compressed.decode_limited(Compression::Zlib, text.bytes, max_text_bytes)
                    else {
                        continue;
                    };
                    bytes
                } else {
                    text.bytes
                };
                let kind = match text.kind {
                    TextKind::Metadata(kind) => kind,
                    TextKind::RawIptc => {
                        accepts_iptc =
                            !profile::visit_iptc(bytes, &mut converted, max_text_bytes, emit)?;
                        continue;
                    }
                    TextKind::Xmp => {
                        accepts_xmp = !xmp::visit(bytes, max_text_bytes, emit)?;
                        continue;
                    }
                    TextKind::RawXmp => {
                        if let Some(packet) = profile::decode_raw_profile(bytes, &mut converted) {
                            accepts_xmp = !xmp::visit(packet, max_text_bytes, emit)?;
                        }
                        continue;
                    }
                };
                let Some(value) = text.encoding.decode(bytes, &mut converted, max_text_bytes)
                else {
                    continue;
                };
                for (kind, auxiliary) in [(LANGUAGE, text.language), (KEYWORDS, text.translation)] {
                    if !auxiliary.is_empty() && auxiliary.len() <= max_text_bytes {
                        emit(kind, auxiliary)?;
                    }
                }
                if !value.is_empty() {
                    emit(kind, value)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ChunkHeader {
    kind: [u8; 4],
    data: u64,
    len: usize,
    next: u64,
}

impl ChunkHeader {
    fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        offset: u64,
    ) -> Result<Option<Self>, E> {
        let Some(&[a, b, c, d, k1, k2, k3, k4]) = input.range(offset, 8)? else {
            return Ok(None);
        };
        let len = u32::from_be_bytes([a, b, c, d]);
        let data = offset + 8;
        let Some(next) = data.checked_add(u64::from(len) + 4) else {
            return Ok(None);
        };
        if len > MAX_PNG_INTEGER || next > input.extent {
            return Ok(None);
        }
        Ok(Some(Self {
            kind: [k1, k2, k3, k4],
            data,
            len: len as usize,
            next,
        }))
    }

    fn read_body<'a, E>(
        self,
        input: &'a mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    ) -> Result<Option<Chunk<'a>>, E> {
        let Some(bytes) = input.range(self.data, self.len + 4)? else {
            return Ok(None);
        };
        let Some((data, crc)) = bytes.split_last_chunk::<4>() else {
            return Ok(None);
        };
        Ok(
            (checksum(&self.kind, data) == u32::from_be_bytes(*crc)).then_some(Chunk {
                kind: self.kind,
                data,
            }),
        )
    }
}

struct Chunk<'a> {
    kind: [u8; 4],
    data: &'a [u8],
}

fn dimensions(chunk: Chunk<'_>) -> Option<Dimensions> {
    let [w0, w1, w2, w3, h0, h1, h2, h3, depth, color, 0, 0, 0 | 1] = chunk.data else {
        return None;
    };
    let supported = match color {
        0 => matches!(depth, 1 | 2 | 4 | 8 | 16),
        3 => matches!(depth, 1 | 2 | 4 | 8),
        2 | 4 | 6 => matches!(depth, 8 | 16),
        _ => false,
    };
    let width = u32::from_be_bytes([*w0, *w1, *w2, *w3]);
    let height = u32::from_be_bytes([*h0, *h1, *h2, *h3]);
    if !supported || width > MAX_PNG_INTEGER || height > MAX_PNG_INTEGER {
        return None;
    }
    Dimensions::new(width, height)
}

fn modification_date(bytes: &[u8]) -> Option<String> {
    let [
        hi,
        lo,
        month @ 1..=12,
        day @ 1..=31,
        hour @ 0..=23,
        minute @ 0..=59,
        second @ 0..=60,
    ] = bytes
    else {
        return None;
    };
    let year = u16::from_be_bytes([*hi, *lo]);
    Some(format!(
        "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}"
    ))
}

#[derive(Clone, Copy)]
enum Encoding {
    Latin1,
    Utf8,
}

impl Encoding {
    fn decode<'b>(
        self,
        input: &'b [u8],
        output: &'b mut Vec<u8>,
        limit: usize,
    ) -> Option<&'b [u8]> {
        if input.len() > limit || input.contains(&0) {
            return None;
        }
        match self {
            Self::Utf8 => std::str::from_utf8(input).ok().map(str::as_bytes),
            Self::Latin1 => {
                let length = input
                    .len()
                    .checked_add(input.iter().filter(|byte| !byte.is_ascii()).count())?;
                if length > limit {
                    return None;
                }
                if length == input.len() {
                    return Some(input);
                }
                output.clear();
                output.try_reserve_exact(length).ok()?;
                let mut utf8 = [0; 4];
                for &byte in input {
                    output.extend_from_slice(char::from(byte).encode_utf8(&mut utf8).as_bytes());
                }
                Some(output)
            }
        }
    }
}

enum TextKind {
    Metadata(u32),
    RawIptc,
    Xmp,
    RawXmp,
}

struct Text<'a> {
    kind: TextKind,
    bytes: &'a [u8],
    encoding: Encoding,
    compressed: bool,
    language: &'a [u8],
    translation: &'a [u8],
}

impl<'a> Text<'a> {
    fn parse(chunk: Chunk<'a>) -> Option<Self> {
        let (keyword, remainder) = split_string(chunk.data)?;
        if !valid_keyword(keyword) {
            return None;
        }
        let fallback = if chunk.kind == *b"tEXt" {
            KEYWORDS
        } else {
            COMMENT
        };
        let kind = match keyword {
            b"Raw profile type iptc" => TextKind::RawIptc,
            b"XML:com.adobe.xmp" => TextKind::Xmp,
            b"Raw profile type xmp" => TextKind::RawXmp,
            _ => TextKind::Metadata(metadata_type(keyword).unwrap_or(fallback)),
        };
        let mut value = Self {
            kind,
            bytes: remainder,
            encoding: Encoding::Latin1,
            compressed: false,
            language: &[],
            translation: &[],
        };
        match &chunk.kind {
            b"tEXt" => {}
            b"zTXt" => {
                value.bytes = remainder.strip_prefix(&[0])?;
                value.compressed = true;
            }
            b"iTXt" => {
                let ([flag, method], after_method) = remainder.split_first_chunk::<2>()?;
                value.compressed = match (flag, method) {
                    (0, _) => false,
                    (1, 0) => true,
                    _ => return None,
                };
                let (language, after_language) = split_string(after_method)?;
                let (translation, bytes) = split_string(after_language)?;
                if !language
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
                    || std::str::from_utf8(translation).is_err()
                {
                    return None;
                }
                value.language = language;
                value.translation = translation;
                value.bytes = bytes;
                value.encoding = Encoding::Utf8;
            }
            _ => return None,
        }
        Some(value)
    }
}

fn split_string(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let end = input.iter().position(|byte| *byte == 0)?;
    Some((&input[..end], &input[end + 1..]))
}

fn valid_keyword(keyword: &[u8]) -> bool {
    (1..=79).contains(&keyword.len())
        && keyword.first() != Some(&b' ')
        && keyword.last() != Some(&b' ')
        && keyword
            .iter()
            .all(|byte| matches!(byte, 32..=126 | 161..=255))
        && !keyword.windows(2).any(|bytes| bytes == b"  ")
}

fn metadata_type(keyword: &[u8]) -> Option<u32> {
    // GNU libextractor's PNG names projected into its public metadata registry.
    Some(match keyword {
        b"Title" => 4,
        b"Author" => 13,
        b"Description" => 46,
        b"Copyright" => 47,
        b"Creation Time" => 58,
        b"Software" => 113,
        b"Source" => 143,
        b"Disclaimer" => 144,
        b"Warning" => 145,
        b"Signature" => 45,
        b"Comment" => COMMENT,
        _ => return None,
    })
}

const CRC_TABLE: [u32; 256] = {
    let mut table = [0; 256];
    let mut index = 0;
    while index < 256 {
        let mut value = index as u32;
        let mut bit = 0;
        while bit < 8 {
            value = (value >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(value & 1));
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
};

fn checksum(kind: &[u8; 4], bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in kind.iter().chain(bytes) {
        crc = (crc >> 8) ^ CRC_TABLE[usize::from((crc as u8) ^ byte)];
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extraction::formats::text_only;
    use std::convert::Infallible;

    const HEADER: &[u8] = b"\0\0\0\x01\0\0\0\x01\x08\x06\0\0\0";
    // Independent zlib members for `PNG cafe\xe9` and UTF-8 `星光`.
    const LATIN1_ZLIB: &[u8] =
        b"\x78\x9c\x0b\xf0\x73\x57\x48\x4e\x4c\x4b\x7d\x09\x00\x0e\x52\x03\x7e";
    const UTF8_ZLIB: &[u8] = b"\x78\x9c\x7b\x36\x63\xfe\xd3\xd6\x4e\x00\x0f\x20\x04\x11";
    const IIM_PROFILE_TEXT: &[u8] =
        b"\niptc\n      31\n1c015a00031b25471c0200000200041c0219000b436166c3a9205363656e65\n";
    // ImageMagick raw profile text with the same IIM packet in a Photoshop block.
    const IPTC_IRB_ZLIB: &[u8] = b"\x78\x9c\x3d\x89\x39\x0e\x80\x40\x0c\x03\xfb\xbc\x82\x27\xe4\x70\x02\xfb\x9c\x3d\x40\xa2\xa3\xe0\xff\x22\xbb\x05\xb6\x64\xcd\xc8\x74\x3f\x6f\xa7\x6d\x05\x20\x3b\xa0\x28\x18\x8c\xec\x1f\xb9\xa4\xb3\x78\x4d\x34\x69\xea\xd8\xd3\x75\x5d\x73\x31\x4d\x4a\x52\x83\x85\x44\x74\xab\x45\xd9\x2d\x2c\x3c\xce\x70\x66\xfa\x00\x8d\xf4\x16\x65";

    fn append(png: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
        png.extend_from_slice(&(data.len() as u32).to_be_bytes());
        png.extend_from_slice(kind);
        png.extend_from_slice(data);
        png.extend_from_slice(&checksum(kind, data).to_be_bytes());
    }

    fn prefix() -> Vec<u8> {
        let mut png = SIGNATURE.to_vec();
        append(&mut png, b"IHDR", HEADER);
        png
    }

    fn visit_text<E>(
        input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        limit: usize,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        visit(input, FieldLimits::text_only(limit), &mut text_only(emit))
    }

    #[test]
    fn png_embedded_profile_uses_the_checked_chunk_and_output_bound() {
        // Independent zlib encoding of the ICC envelope fixture.
        const PROFILE: &[u8] = b"Profile\0\0\x78\x9c\x63\x60\x60\x98\xc3\x00\x04\x2c\x40\x9c\x9b\x57\x52\x14\xe4\xee\xa4\x10\x11\x19\xa5\xc0\x80\x04\x12\x93\x8b\x0b\x18\x68\x07\x18\x93\x0b\x8a\x4a\x80\xf4\x04\x20\xe6\x29\x49\xad\x00\xb1\x19\x3c\x9d\x9d\x19\x00\x89\x57\x0b\x19";
        let profile = icc::fixture();
        for (limit, late, bad_crc, found) in [
            (profile.len(), false, false, true),
            (profile.len() - 1, false, false, false),
            (profile.len(), true, false, false),
            (profile.len(), false, true, false),
        ] {
            let mut png = prefix();
            if late {
                append(&mut png, b"IDAT", b"unused");
            }
            append(&mut png, b"iCCP", PROFILE);
            if bad_crc && let Some(byte) = png.last_mut() {
                *byte ^= 1;
            }
            let input = Input::new(&png, png.len() as u64, &mut [], |_, _: &mut [u8]| Ok(()));
            let mut seen = None;
            let Ok(()) = visit(
                input,
                FieldLimits {
                    text: 256,
                    icc: limit,
                },
                &mut |field| {
                    if let Field::ColorProfile(value) = field {
                        seen = Some(value.bytes().to_vec());
                    }
                    Ok::<_, Infallible>(())
                },
            );
            assert_eq!(seen.as_deref(), found.then_some(profile.as_slice()));
        }
    }

    fn metadata(png: &[u8], limit: usize) -> Vec<(u32, String)> {
        let mut values = Vec::new();
        let input = Input::new(png, png.len() as u64, &mut [], |_, _: &mut [u8]| Ok(()));
        let Ok(()) = visit_text(input, limit, &mut |kind, value| -> Result<(), Infallible> {
            values.push((kind, String::from_utf8_lossy(value).into_owned()));
            Ok(())
        });
        values
    }

    #[test]
    fn png_exif_requires_a_checked_chunk_before_image_data() {
        const PROFILE: &[u8] = b"II*\0\x08\0\0\0\x01\0\x0f\x01\x02\0\x04\0\0\0Cam\0\0\0\0\0";
        let mut png = prefix();
        append(&mut png, b"eXIf", PROFILE);
        append(&mut png, b"IDAT", b"");
        append(&mut png, b"IEND", b"");
        assert_eq!(
            metadata(&png, 64),
            [(112, "1x1".into()), (95, "Cam".into())]
        );

        let mut png = prefix();
        append(&mut png, b"eXIf", PROFILE);
        let checksum = png.len() - 1;
        png[checksum] ^= 1;
        append(&mut png, b"IEND", b"");
        assert_eq!(metadata(&png, 64), [(112, "1x1".into())]);

        let mut png = prefix();
        append(&mut png, b"IDAT", b"");
        append(&mut png, b"eXIf", PROFILE);
        append(&mut png, b"IEND", b"");
        assert_eq!(metadata(&png, 64), [(112, "1x1".into())]);
    }

    #[test]
    fn reads_late_text_within_one_budget_without_reading_image_data() {
        let mut png = prefix();
        let image_data = png.len() + 8;
        append(&mut png, b"IDAT", &[0; 128 * 1024]);
        let after_image = png.len();
        append(&mut png, b"tEXt", b"Title\0After image data");
        append(&mut png, b"IEND", b"");
        append(&mut png, b"tEXt", b"Title\0After IEND");

        let mut scratch = [0; 96];
        let mut bytes_read = 0;
        let mut fields = Vec::new();
        let input = Input::new(
            SIGNATURE,
            png.len() as u64,
            &mut scratch,
            |offset, out: &mut [u8]| {
                let offset = offset as usize;
                let end = offset + out.len();
                assert!(end <= image_data || offset >= after_image);
                bytes_read += out.len();
                out.copy_from_slice(&png[offset..end]);
                Ok(())
            },
        );
        let Ok(()) = visit_text(input, 64, &mut |kind, value| -> Result<(), Infallible> {
            fields.push((kind, value.to_vec()));
            Ok(())
        });
        assert_eq!(
            fields,
            [(112, b"1x1".to_vec()), (4, b"After image data".to_vec())]
        );
        assert!(bytes_read <= scratch.len());
    }

    #[test]
    fn image_magick_iptc_uses_checked_text_chunks() {
        for (kind, control, profile) in [
            (b"tEXt", b"".as_slice(), IIM_PROFILE_TEXT),
            (b"zTXt", b"\0".as_slice(), IPTC_IRB_ZLIB),
            (b"iTXt", b"\x01\0\0\0".as_slice(), IPTC_IRB_ZLIB),
        ] {
            let mut png = prefix();
            append(&mut png, b"IDAT", b"");
            append(&mut png, b"tEXt", b"Raw profile type iptc\0\niptc\n1\n00ff");
            let text = [b"Raw profile type iptc\0".as_slice(), control, profile].concat();
            append(&mut png, kind, &text);
            let crc_end = png.len() - 1;
            append(&mut png, b"IEND", b"");
            assert_eq!(
                metadata(&png, 128),
                [(112, "1x1".into()), (49, "Café Scene".into())]
            );

            png[crc_end] ^= 1;
            assert_eq!(metadata(&png, 128), [(112, "1x1".into())]);
        }
    }

    #[test]
    fn direct_and_legacy_xmp_use_checked_text_chunks() {
        const XML: &[u8] = br#"<r:RDF xmlns:r="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><r:Description xmlns:p="http://ns.adobe.com/photoshop/1.0/" p:City="Quito"/></r:RDF>"#;
        let mut raw = format!("Raw profile type xmp\0\nxmp\n{}\n", XML.len()).into_bytes();
        for &byte in XML {
            let digits = b"0123456789abcdef";
            raw.push(digits[usize::from(byte >> 4)]);
            raw.push(digits[usize::from(byte & 15)]);
        }
        let standard = [b"XML:com.adobe.xmp\0\0\0\0\0".as_slice(), XML].concat();
        for (carrier, packet) in [(b"iTXt", standard), (b"tEXt", raw)] {
            let mut png = prefix();
            append(&mut png, b"IDAT", b"");
            append(&mut png, carrier, &packet);
            let crc_at = png.len() - 1;
            append(&mut png, b"IEND", b"");
            assert_eq!(
                metadata(&png, 128),
                [(112, "1x1".into()), (41, "Quito".into())]
            );
            png[crc_at] ^= 1;
            assert_eq!(metadata(&png, 128), [(112, "1x1".into())]);
        }
    }

    #[test]
    fn extracts_png_dimensions_text_dates_and_international_metadata() {
        assert_eq!(checksum(b"IHDR", HEADER), 0x1f15_c489);
        let mut png = prefix();
        append(&mut png, b"tEXt", b"Unregistered\0fallback");
        let mut compressed = b"Description\0\0".to_vec();
        compressed.extend_from_slice(LATIN1_ZLIB);
        append(&mut png, b"zTXt", &compressed);
        let mut international = b"Title\0\x01\0zh\0".to_vec();
        international.extend_from_slice("标题".as_bytes());
        international.push(0);
        international.extend_from_slice(UTF8_ZLIB);
        append(&mut png, b"iTXt", &international);
        append(&mut png, b"tIME", &[7, 234, 2, 9, 18, 31, 47]);
        append(&mut png, b"IEND", b"");
        append(&mut png, b"tEXt", b"Title\0outside PNG");

        let values = metadata(&png, 50);
        assert_eq!(
            values
                .iter()
                .map(|(kind, value)| (*kind, value.as_str()))
                .collect::<Vec<_>>(),
            [
                (112, "1x1"),
                (49, "fallback"),
                (46, "PNG cafeé"),
                (27, "zh"),
                (49, "标题"),
                (4, "星光"),
                (59, "2026-02-09 18:31:47"),
            ]
        );
    }

    #[test]
    fn malformed_png_metadata_cannot_restart_the_inflate_allowance() {
        let mut png = prefix();
        let mut compressed = b"Title\0\0".to_vec();
        compressed.extend_from_slice(LATIN1_ZLIB);
        for _ in 0..3 {
            append(&mut png, b"zTXt", &compressed);
        }
        append(&mut png, b"tEXt", b"Title\0bad crc");
        let crc_end = png.len() - 1;
        png[crc_end] ^= 1;
        append(&mut png, b"iTXt", b"Author\0\0\xde\0\0Ada");
        // An incomplete chunk at the file-prefix boundary supplies no text.
        append(&mut png, b"tEXt", b"Title\0truncated");
        png.truncate(png.len() - 2);

        assert_eq!(
            metadata(&png, 14),
            [
                (112, "1x1".into()),
                (4, "PNG cafeé".into()),
                (13, "Ada".into())
            ]
        );
        assert!(metadata(&png[..SIGNATURE.len() + 5], 14).is_empty());
    }
}
