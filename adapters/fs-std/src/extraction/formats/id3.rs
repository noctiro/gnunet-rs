//! Bounded textual ID3v2.2, v2.3 and v2.4 metadata from a complete leading tag.

use std::borrow::Cow;

const HEADER_BYTES: usize = 10;
const MAX_PREFIX_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Version {
    V22,
    V23,
    V24,
}

impl Version {
    fn flags(self) -> u8 {
        match self {
            Self::V22 => 0x80, // Whole-tag compression is not supported.
            Self::V23 => 0xe0,
            Self::V24 => 0xf0,
        }
    }

    fn id_len(self) -> usize {
        if self == Self::V22 { 3 } else { 4 }
    }
}

struct Tag<'a> {
    version: Version,
    flags: u8,
    body: Cow<'a, [u8]>,
}

impl<'a> Tag<'a> {
    fn parse(data: &'a [u8]) -> Option<Self> {
        let header = data.get(..HEADER_BYTES)?;
        if &header[..3] != b"ID3" || header[4] == 0xff {
            return None;
        }
        let version = match header[3] {
            2 => Version::V22,
            3 => Version::V23,
            4 => Version::V24,
            _ => return None,
        };
        let flags = header[5];
        if flags & !version.flags() != 0 {
            return None;
        }
        let end = HEADER_BYTES + synchsafe(&header[6..])?;
        let has_footer = version == Version::V24 && flags & 0x10 != 0;
        if end + usize::from(has_footer) * HEADER_BYTES > MAX_PREFIX_BYTES {
            return None;
        }
        if has_footer {
            let footer = data.get(end..end + HEADER_BYTES)?;
            if &footer[..3] != b"3DI" || footer[3..] != header[3..] {
                return None;
            }
        }
        let body = data.get(HEADER_BYTES..end)?;
        // Before v2.4, unsynchronisation applies to the complete tag,
        // including the frame headers. v2.4 reverses it per frame body.
        let body = if version != Version::V24 && flags & 0x80 != 0 {
            unescape(body)?
        } else {
            Cow::Borrowed(body)
        };
        Some(Self {
            version,
            flags,
            body,
        })
    }

    fn frames(&self) -> Option<Frames<'_>> {
        let mut bytes = self.body.as_ref();
        if self.flags & 0x40 != 0 {
            bytes = match self.version {
                Version::V22 => return None,
                Version::V23 => extended_v23(bytes)?,
                Version::V24 => extended_v24(bytes)?,
            };
        }
        Some(Frames {
            version: self.version,
            remaining: bytes,
            padding_allowed: self.version != Version::V24 || self.flags & 0x10 == 0,
        })
    }
}

fn big_endian(data: &[u8]) -> Option<usize> {
    Some(u32::from_be_bytes(data.get(..4)?.try_into().ok()?) as usize)
}

fn synchsafe(data: &[u8]) -> Option<usize> {
    let bytes = data.get(..4)?;
    bytes.iter().try_fold(0, |value, &byte| {
        (byte < 0x80).then_some((value << 7) | usize::from(byte))
    })
}

fn extended_v23(data: &[u8]) -> Option<&[u8]> {
    let size = big_endian(data)?;
    let fields = data.get(4..4usize.checked_add(size)?)?;
    let crc = match fields.get(..2)? {
        [0, 0] => false,
        [0x80, 0] => true,
        _ => return None,
    };
    if size != if crc { 10 } else { 6 } {
        return None;
    }
    let bytes = data.get(4 + size..)?;
    let padding = big_endian(fields.get(2..6)?)?;
    let (frames, padding) = bytes.split_at_checked(bytes.len().checked_sub(padding)?)?;
    padding.iter().all(|&byte| byte == 0).then_some(frames)
}

fn extended_v24(data: &[u8]) -> Option<&[u8]> {
    let size = synchsafe(data)?;
    let extended = data.get(..size)?;
    let [1, flags, fields @ ..] = extended.get(4..)? else {
        return None;
    };
    let mut fields = fields;
    if flags & !0x70 != 0 {
        return None;
    }
    for (flag, size) in [(0x40, 0), (0x20, 5), (0x10, 1)] {
        if flags & flag == 0 {
            continue;
        }
        let (&length, tail) = fields.split_first()?;
        if usize::from(length) != size {
            return None;
        }
        let (field, tail) = tail.split_at_checked(size)?;
        if flag == 0x20 && (field[0] > 0x0f || field.iter().any(|&byte| byte >= 0x80)) {
            return None;
        }
        fields = tail;
    }
    fields.is_empty().then_some(data.get(size..)?)
}

fn unescape(data: &[u8]) -> Option<Cow<'_, [u8]>> {
    let Some(first) = data.windows(2).position(|pair| pair == [0xff, 0]) else {
        return Some(Cow::Borrowed(data));
    };
    let mut output = Vec::new();
    output.try_reserve_exact(data.len() - 1).ok()?;
    output.extend_from_slice(&data[..first]);
    let mut remaining = &data[first..];
    while let Some((&byte, tail)) = remaining.split_first() {
        output.push(byte);
        remaining = if byte == 0xff {
            tail.strip_prefix(&[0]).unwrap_or(tail)
        } else {
            tail
        };
    }
    Some(Cow::Owned(output))
}

#[derive(Clone, Copy)]
struct Frames<'a> {
    version: Version,
    remaining: &'a [u8],
    padding_allowed: bool,
}

struct Frame<'a> {
    id: &'a [u8],
    flags: [u8; 2],
    body: &'a [u8],
}

impl<'a> Frames<'a> {
    fn parse(&mut self, data: &'a [u8]) -> Option<Frame<'a>> {
        let (id, data) = data.split_at_checked(self.version.id_len())?;
        if !id
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        {
            return None;
        }
        let (size, flags, data) = match self.version {
            Version::V22 => {
                let ([a, b, c], data) = data.split_first_chunk::<3>()?;
                let size = u32::from_be_bytes([0, *a, *b, *c]) as usize;
                (size, [0; 2], data)
            }
            version => {
                let (length, data) = data.split_at_checked(4)?;
                let (flags, data) = data.split_first_chunk::<2>()?;
                let size = if version == Version::V24 {
                    synchsafe(length)?
                } else {
                    big_endian(length)?
                };
                (size, *flags, data)
            }
        };
        let (body, remaining) = data.split_at_checked(size)?;
        if body.is_empty() {
            return None;
        }
        self.remaining = remaining;
        Some(Frame { id, flags, body })
    }
}

impl<'a> Iterator for Frames<'a> {
    type Item = Result<Frame<'a>, ()>;

    fn next(&mut self) -> Option<Self::Item> {
        let data = std::mem::take(&mut self.remaining);
        match data.first()? {
            0 if self.padding_allowed && data.iter().all(|&byte| byte == 0) => None,
            _ => Some(self.parse(data).ok_or(())),
        }
    }
}

impl Frame<'_> {
    // GNU libextractor extractor.h metadata kinds.
    fn kind(&self) -> Option<(u32, bool)> {
        let kind = match self.id {
            b"TT2" | b"TIT2" => 4,
            b"TP1" | b"TPE1" => 130,
            b"TP2" | b"TPE2" => 134,
            b"TP3" | b"TPE3" => 157,
            b"TP4" | b"TPE4" => 158,
            b"TAL" | b"TALB" => 129,
            b"TCO" | b"TCON" => 131,
            b"TRK" | b"TRCK" => 132,
            b"TPA" | b"TPOS" => 133,
            b"TYE" | b"TYER" => 21,
            b"TDRC" => 28,
            b"TDRL" => 24,
            b"TCM" | b"TCOM" => 159,
            b"TBP" | b"TBPM" => 160,
            b"TEN" | b"TENC" => 161,
            b"TOA" | b"TOPE" => 163,
            b"TOT" | b"TOAL" => 162,
            b"TOL" | b"TOLY" => 164,
            b"TOR" | b"TORY" | b"TDOR" => 165,
            b"TPB" | b"TPUB" => 16,
            b"TLA" | b"TLAN" => 27,
            b"TRC" | b"TSRC" => 31,
            b"TCR" | b"TCOP" => 47,
            b"COM" | b"COMM" => return Some((3, true)),
            b"ULT" | b"USLT" => return Some((167, true)),
            _ => return None,
        };
        Some((kind, false))
    }

    fn payload(&self, tag: &Tag<'_>) -> Option<(Cow<'_, [u8]>, usize)> {
        let [status, format] = self.flags;
        let body = self.body;
        let (body, group, length) = match tag.version {
            Version::V22 => (Cow::Borrowed(body), false, false),
            Version::V23 if status & !0xe0 == 0 && format & !0x20 == 0 => {
                (Cow::Borrowed(body), format & 0x20 != 0, false)
            }
            Version::V24 if status & !0x70 == 0 && format & !0x43 == 0 => {
                let body = if (format & 0x02 != 0) || (tag.flags & 0x80 != 0) {
                    unescape(body)?
                } else {
                    Cow::Borrowed(body)
                };
                (body, format & 0x40 != 0, format & 0x01 != 0)
            }
            // Reserved flags, compression and encryption are unsupported.
            _ => return None,
        };
        let mut offset = usize::from(group);
        if length {
            let expected = synchsafe(body.get(offset..)?)?;
            offset += 4;
            if body.len().checked_sub(offset) != Some(expected) {
                return None;
            }
        }
        (offset < body.len()).then_some((body, offset))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ByteOrder {
    Little,
    Big,
}

#[derive(Clone, Copy)]
enum Encoding {
    Latin1,
    Utf8,
    Utf16,
    Utf16Be,
}

impl Encoding {
    fn parse(version: Version, id: u8) -> Option<Self> {
        match id {
            0 => Some(Self::Latin1),
            1 => Some(Self::Utf16),
            2 if version == Version::V24 => Some(Self::Utf16Be),
            3 if version == Version::V24 => Some(Self::Utf8),
            _ => None,
        }
    }

    fn width(self) -> usize {
        match self {
            Self::Latin1 | Self::Utf8 => 1,
            Self::Utf16 | Self::Utf16Be => 2,
        }
    }

    fn value(self, data: &[u8]) -> (&[u8], Option<&[u8]>) {
        let width = self.width();
        if let Some(index) = data
            .chunks_exact(width)
            .position(|unit| unit.iter().all(|&b| b == 0))
        {
            let index = index * width;
            (&data[..index], Some(&data[index + width..]))
        } else {
            (data, None)
        }
    }

    fn decode<'a>(
        self,
        data: &'a [u8],
        order: &mut Option<ByteOrder>,
        limit: usize,
    ) -> Option<Cow<'a, str>> {
        match self {
            Self::Utf8 => {
                if data.len() > limit {
                    return None;
                }
                std::str::from_utf8(data).ok().map(Cow::Borrowed)
            }
            Self::Latin1 => {
                if data.len() > limit {
                    return None;
                }
                if data.is_ascii() {
                    return std::str::from_utf8(data).ok().map(Cow::Borrowed);
                }
                bounded_chars(data.iter().map(|&b| Some(char::from(b))), data.len(), limit)
                    .map(Cow::Owned)
            }
            Self::Utf16 => {
                let (data, order) = observe_bom(data, order)?;
                decode_utf16(data, order, limit).map(Cow::Owned)
            }
            Self::Utf16Be => decode_utf16(data, ByteOrder::Big, limit).map(Cow::Owned),
        }
    }

    fn valid_description(self, data: &[u8], order: &mut Option<ByteOrder>) -> bool {
        if data.is_empty() {
            return true;
        }
        let utf16 = match self {
            Self::Latin1 => return true,
            Self::Utf8 => return std::str::from_utf8(data).is_ok(),
            Self::Utf16 => observe_bom(data, order),
            Self::Utf16Be => Some((data, ByteOrder::Big)),
        };
        utf16
            .and_then(|(data, order)| utf16_chars(data, order))
            .is_some_and(|mut chars| chars.all(|character| character.is_ok()))
    }
}

fn observe_bom<'a>(data: &'a [u8], order: &mut Option<ByteOrder>) -> Option<(&'a [u8], ByteOrder)> {
    let (bom, text) = data.split_first_chunk::<2>()?;
    let observed = match bom {
        [0xff, 0xfe] => ByteOrder::Little,
        [0xfe, 0xff] => ByteOrder::Big,
        _ => return Some((data, (*order)?)),
    };
    if order.is_some_and(|previous| previous != observed) {
        return None;
    }
    *order = Some(observed);
    Some((text, observed))
}

fn bounded_chars(
    chars: impl Iterator<Item = Option<char>>,
    source_len: usize,
    limit: usize,
) -> Option<String> {
    let mut text = String::new();
    text.try_reserve_exact(source_len.saturating_mul(2).min(limit))
        .ok()?;
    for character in chars {
        let character = character?;
        if text.len() + character.len_utf8() > limit {
            return None;
        }
        text.push(character);
    }
    Some(text)
}

fn decode_utf16(data: &[u8], order: ByteOrder, limit: usize) -> Option<String> {
    if data.len() / 2 > limit {
        return None;
    }
    bounded_chars(utf16_chars(data, order)?.map(Result::ok), data.len(), limit)
}

fn utf16_chars(
    data: &[u8],
    order: ByteOrder,
) -> Option<impl Iterator<Item = Result<char, std::char::DecodeUtf16Error>>> {
    let (units, rest) = data.as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    let unit = match order {
        ByteOrder::Little => u16::from_le_bytes,
        ByteOrder::Big => u16::from_be_bytes,
    };
    Some(char::decode_utf16(units.iter().copied().map(unit)))
}

fn visit_frame<E>(
    frame: Frame<'_>,
    tag: &Tag<'_>,
    max_text_bytes: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let Some((kind, described)) = frame.kind() else {
        return Ok(());
    };
    let Some((body, offset)) = frame.payload(tag) else {
        return Ok(());
    };
    let Some((&encoding, mut text)) = body[offset..].split_first() else {
        return Ok(());
    };
    let Some(encoding) = Encoding::parse(tag.version, encoding) else {
        return Ok(());
    };
    let mut order = None;
    if described {
        // Comments and unsynchronised lyrics start with a language and a
        // terminated description. Only the actual content is metadata.
        let Some((language, description)) = text.split_at_checked(3) else {
            return Ok(());
        };
        if !language.iter().all(u8::is_ascii_alphabetic) {
            return Ok(());
        }
        let (description, Some(value)) = encoding.value(description) else {
            return Ok(());
        };
        if !encoding.valid_description(description, &mut order) {
            return Ok(());
        }
        text = value;
    }
    while !text.is_empty() {
        let (value, rest) = encoding.value(text);
        if let Some(value) = encoding.decode(value, &mut order, max_text_bytes)
            && !value.is_empty()
        {
            emit(kind, value.as_bytes())?;
        }
        if described || tag.version != Version::V24 {
            break;
        }
        text = rest.unwrap_or_default();
    }
    Ok(())
}

/// Visit supported tag text as UTF-8 using GNU libextractor metadata identifiers.
pub(super) fn visit<E>(
    data: &[u8],
    max_text_bytes: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    if max_text_bytes == 0 {
        return Ok(());
    }
    let Some(tag) = Tag::parse(data) else {
        return Ok(());
    };
    let Some(frames) = tag.frames() else {
        return Ok(());
    };
    // Reject broken frame boundaries before any metadata leaves the parser.
    let mut verification = frames;
    if verification.any(|frame| frame.is_err()) {
        return Ok(());
    }
    for frame in frames.flatten() {
        visit_frame(frame, &tag, max_text_bytes, emit)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::visit;
    use std::convert::Infallible;

    fn values(data: &[u8], limit: usize) -> Vec<(u32, Vec<u8>)> {
        let mut result = Vec::new();
        assert_eq!(
            visit(data, limit, &mut |kind, value| {
                result.push((kind, value.to_vec()));
                Ok::<(), Infallible>(())
            }),
            Ok(())
        );
        result
    }

    #[test]
    fn versions_decode_native_text_without_decoding_other_frames() {
        let v22 = b"ID3\x02\0\0\0\0\0\x0dTT2\0\0\x07\0Fran\xe7a";
        assert_eq!(values(v22, 16), [(4, "França".as_bytes().to_vec())]);
        assert!(values(v22, 6).is_empty());

        let v23 = b"ID3\x03\0\x80\0\0\0\x12TALB\0\0\0\x07\0\0\x01\xff\0\xfeB\0\xe9\0";
        assert_eq!(values(v23, 16), [(129, "Bé".as_bytes().to_vec())]);

        let v24 = b"ID3\x04\0\x50\0\0\0\x1a\0\0\0\x06\x01\0TPE1\0\0\0\x0a\0\x41\x01\0\0\0\x05\x03A\0B\0\x33DI\x04\0\x50\0\0\0\x1a";
        assert_eq!(
            values(v24, 16),
            [(130, b"A".to_vec()), (130, b"B".to_vec())]
        );
        assert!(values(&v24[..v24.len() - 1], 16).is_empty());
    }

    #[test]
    fn broken_frame_boundary_emits_no_partial_tag() {
        let tag = b"ID3\x04\0\0\0\0\0\x16TIT2\0\0\0\x02\0\0\x03aTPE1\0\0\0\x01\0\0";
        assert!(values(tag, 16).is_empty());
    }
}
