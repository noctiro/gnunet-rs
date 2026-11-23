//! Bounded BER framing for CMS and strict DER framing for RSA public keys.

use std::borrow::Cow;

use super::{INTEGER, OCTETS, SEQUENCE};

const CONSTRUCTED: u8 = 0x20;
const BITS: u8 = 0x03;
const MAX_NESTING: usize = 32;
const MAX_ITEMS: usize = 8192;

#[derive(Clone, Copy)]
pub(super) struct Item<'a> {
    pub(super) tag: u8,
    pub(super) data: &'a [u8],
    pub(super) encoded: &'a [u8],
}

impl<'a> Item<'a> {
    pub(super) fn positive_integer(self) -> Option<&'a [u8]> {
        (self.tag == INTEGER).then_some(())?;
        Ber::unsigned(self.data)
    }

    pub(super) fn uint(self) -> Option<u64> {
        let magnitude = self.positive_integer()?;
        if magnitude.len() > 8 {
            return None;
        }
        Some(
            magnitude
                .iter()
                .fold(0, |acc, &byte| (acc << 8) | u64::from(byte)),
        )
    }

    pub(super) fn octets(self, primitive_tag: u8, max_bytes: usize) -> Option<Cow<'a, [u8]>> {
        self.string(primitive_tag, OCTETS, max_bytes, Some)
    }

    pub(super) fn byte_aligned_bits(self, max_bytes: usize) -> Option<Cow<'a, [u8]>> {
        self.string(BITS, BITS, max_bytes, |data| data.strip_prefix(b"\0"))
    }

    fn string(
        self,
        outer_tag: u8,
        part_tag: u8,
        max_bytes: usize,
        decode: impl Fn(&'a [u8]) -> Option<&'a [u8]>,
    ) -> Option<Cow<'a, [u8]>> {
        if self.tag == outer_tag {
            let bytes = decode(self.data)?;
            return (bytes.len() <= max_bytes).then_some(Cow::Borrowed(bytes));
        }
        if self.tag != (outer_tag | CONSTRUCTED) {
            return None;
        }

        // An IMPLICIT outer tag changes only the outer identifier. Its
        // components keep the underlying universal string identifier.
        let mut frames = [Ber(&[]); MAX_NESTING];
        frames[0] = Ber(self.data);
        let mut depth = 1;
        let mut scanned = 0;
        let mut bytes = Vec::new();
        while depth != 0 {
            let frame = &mut frames[depth - 1];
            if frame.0.is_empty() {
                depth -= 1;
                continue;
            }
            scanned += 1;
            if scanned > MAX_ITEMS {
                return None;
            }
            let component = frame.read()?;
            if component.tag == part_tag {
                let part = decode(component.data)?;
                if part.len() > max_bytes - bytes.len() {
                    return None;
                }
                bytes.try_reserve(part.len()).ok()?;
                bytes.extend_from_slice(part);
            } else if component.tag == (part_tag | CONSTRUCTED) {
                *frames.get_mut(depth)? = Ber(component.data);
                depth += 1;
            } else {
                return None;
            }
        }
        Some(Cow::Owned(bytes))
    }
}

#[derive(Clone, Copy)]
pub(super) struct Ber<'a>(pub(super) &'a [u8]);

impl<'a> Ber<'a> {
    pub(super) fn sequence(bytes: &'a [u8]) -> Option<Self> {
        Some(Self(sequence::<false>(bytes)?))
    }

    pub(super) fn der_sequence(bytes: &'a [u8]) -> Option<Der<'a>> {
        Some(Der(sequence::<true>(bytes)?))
    }

    pub(super) fn read(&mut self) -> Option<Item<'a>> {
        consume::<false>(&mut self.0)
    }

    pub(super) fn take(&mut self, tag: u8) -> Option<Item<'a>> {
        (self.0.first() == Some(&tag)).then_some(())?;
        self.read()
    }

    pub(super) fn optional(&mut self, tag: u8) -> Option<Option<Item<'a>>> {
        if self.0.first() == Some(&tag) {
            self.read().map(Some)
        } else {
            Some(None)
        }
    }

    pub(super) fn finish(&self) -> Option<()> {
        self.0.is_empty().then_some(())
    }

    pub(super) fn unsigned(data: &[u8]) -> Option<&[u8]> {
        match data {
            [] => None,
            [0, next, ..] if next & 0x80 != 0 => Some(&data[1..]),
            [0, ..] if data.len() > 1 => None,
            [first, ..] if first & 0x80 != 0 => None,
            _ => Some(data),
        }
    }
}

pub(super) struct Der<'a>(&'a [u8]);

impl<'a> Der<'a> {
    pub(super) fn single(mut bytes: &'a [u8], tag: u8) -> Option<Item<'a>> {
        let item = consume::<true>(&mut bytes)?;
        (item.tag == tag && bytes.is_empty()).then_some(item)
    }

    pub(super) fn take(&mut self, tag: u8) -> Option<Item<'a>> {
        (self.0.first() == Some(&tag)).then_some(())?;
        consume::<true>(&mut self.0)
    }

    pub(super) fn finish(&self) -> Option<()> {
        self.0.is_empty().then_some(())
    }
}

fn sequence<const STRICT: bool>(mut input: &[u8]) -> Option<&[u8]> {
    let item = consume::<STRICT>(&mut input)?;
    (item.tag == SEQUENCE && input.is_empty()).then_some(item.data)
}

fn consume<'a, const STRICT: bool>(input: &mut &'a [u8]) -> Option<Item<'a>> {
    let (header, contents) = Header::read::<STRICT>(input)?;
    let (data, rest) = match header.length {
        Length::Definite(bytes) => contents.split_at_checked(bytes)?,
        Length::Indefinite => indefinite_contents(contents)?,
    };
    let encoded = &input[..input.len() - rest.len()];
    *input = rest;
    Some(Item {
        tag: header.tag,
        data,
        encoded,
    })
}

enum Length {
    Definite(usize),
    Indefinite,
}

struct Header {
    tag: u8,
    length: Length,
}

impl Header {
    fn read<const STRICT: bool>(input: &[u8]) -> Option<(Self, &[u8])> {
        let (&tag, identifier) = input.split_first()?;
        if tag == 0 {
            return None;
        }
        let identifier = if tag & 0x1f == 0x1f {
            after_high_tag(identifier)?
        } else {
            identifier
        };
        let (&width, contents) = identifier.split_first()?;
        let (length, contents) = match width {
            0x00..=0x7f => (Length::Definite(usize::from(width)), contents),
            0x80 if !STRICT && tag & CONSTRUCTED != 0 => (Length::Indefinite, contents),
            0x80 | 0xff => return None,
            _ => {
                let (encoded, contents) = contents.split_at_checked(usize::from(width & 0x7f))?;
                let length = encoded.iter().try_fold(0usize, |length, &byte| {
                    length.checked_mul(256)?.checked_add(usize::from(byte))
                })?;
                if STRICT && (length < 128 || encoded.first() == Some(&0)) {
                    return None;
                }
                (Length::Definite(length), contents)
            }
        };
        Some((Self { tag, length }, contents))
    }
}

fn after_high_tag(bytes: &[u8]) -> Option<&[u8]> {
    let (&first, _) = bytes.split_first()?;
    if first & 0x7f == 0 || first < 31 {
        return None;
    }
    let end = bytes.iter().position(|&byte| byte & 0x80 == 0)?;
    bytes.get(end + 1..)
}

fn indefinite_contents(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut remaining = input;
    let mut depth = 1;
    for _ in 0..MAX_ITEMS {
        if let Some(after_end) = remaining.strip_prefix(b"\0\0") {
            depth -= 1;
            if depth == 0 {
                return Some((&input[..input.len() - remaining.len()], after_end));
            }
            remaining = after_end;
            continue;
        }
        let (header, contents) = Header::read::<false>(remaining)?;
        remaining = match header.length {
            Length::Definite(bytes) => contents.get(bytes..)?,
            Length::Indefinite if depth < MAX_NESTING => {
                depth += 1;
                contents
            }
            Length::Indefinite => return None,
        };
    }
    None
}

pub(super) fn valid_oid(bytes: &[u8]) -> bool {
    let mut starts_arc = true;
    for &byte in bytes {
        if starts_arc && byte == 0x80 {
            return false;
        }
        starts_arc = byte & 0x80 == 0;
    }
    !bytes.is_empty() && starts_arc
}

#[cfg(test)]
mod tests {
    use super::{Ber, MAX_ITEMS, MAX_NESTING};
    use std::borrow::Cow;

    #[test]
    fn indefinite_values_hold_the_exact_envelope_and_skip_primitive_zeroes() {
        let bytes =
            b"\x30\x80\x9f\x81\x00\x02\x00\x00\x30\x80\x02\x01\x05\x00\x00\x00\x00\x02\x01\x06";
        let mut input = Ber(bytes);
        let value = input.take(0x30);
        assert_eq!(value.map(|item| item.encoded), Some(&bytes[..17]));
        let contents = value.map(|item| item.data);
        assert_eq!(contents, Some(&bytes[2..15]));
        assert_eq!(input.take(0x02).and_then(|item| item.uint()), Some(6));
        assert!(input.finish().is_some());
    }

    #[test]
    fn implicit_and_universal_octet_string_parts_share_the_output_budget() {
        let primitive = Ber(b"\x80\x03abc")
            .read()
            .and_then(|item| item.octets(0x80, 3));
        assert!(matches!(primitive, Some(Cow::Borrowed(bytes)) if bytes == b"abc"));
        let mut input = Ber(b"\xa0\x80\x04\x01a\x24\x07\x04\x01b\x04\x02cd\x00\x00");
        let item = input.read();
        assert_eq!(
            item.and_then(|item| item.octets(0x80, 4)).as_deref(),
            Some(b"abcd".as_slice()),
        );
        assert!(item.and_then(|item| item.octets(0x80, 3)).is_none());
        assert!(item.and_then(|item| item.octets(0x04, 4)).is_none());
        assert!(input.finish().is_some());

        let mixed = Ber(b"\x24\x04\x04\x00\x05\x00").read();
        assert!(mixed.and_then(|item| item.octets(0x04, 32)).is_none());
    }

    #[test]
    fn bit_string_components_require_byte_alignment() {
        let borrows = Ber(b"\x03\x02\x00\x04")
            .read()
            .and_then(|item| item.byte_aligned_bits(1));
        assert!(matches!(borrows, Some(Cow::Borrowed(bytes)) if bytes == b"\x04"));
        let joined = Ber(b"\x23\x80\x03\x02\x00\x04\x03\x02\x00\x08\x00\x00")
            .read()
            .and_then(|item| item.byte_aligned_bits(2));
        assert_eq!(joined.as_deref(), Some(b"\x04\x08".as_slice()));
        assert!(
            Ber(b"\x23\x04\x03\x02\x03\x08")
                .read()
                .and_then(|item| item.byte_aligned_bits(1))
                .is_none()
        );
    }

    #[test]
    fn der_rejects_nonminimal_lengths_at_both_spki_levels() {
        let nonminimal_sequence = b"\x30\x82\x00\x03\x02\x01\x01";
        assert!(Ber::sequence(nonminimal_sequence).is_some());
        assert!(Ber::der_sequence(nonminimal_sequence).is_none());
        let nonminimal_integer = b"\x30\x04\x02\x81\x01\x01";
        let mut ber = Ber::sequence(nonminimal_integer);
        assert_eq!(
            ber.as_mut()
                .and_then(|value| value.take(2))
                .and_then(|item| item.uint()),
            Some(1)
        );
        let der = Ber::der_sequence(nonminimal_integer).and_then(|mut value| value.take(2));
        assert!(der.is_none());
        assert!(Ber::der_sequence(b"\x30\x80\x02\x01\x01\x00\x00").is_none());
    }

    #[test]
    fn malformed_lengths_and_excessive_indefinite_work_leave_the_cursor_unchanged() {
        for malformed in [
            b"\x30\x80\x02\x01\x05".as_slice(),
            b"\x30\x80\x04\x80\x00\x00\x00\x00",
            b"\x30\x80\x00\x01\x00\x00\x00",
            b"\x30\xff",
            b"\x1f\x1e\x00",
        ] {
            let mut input = Ber(malformed);
            assert!(input.read().is_none());
            assert_eq!(input.0, malformed);
        }

        let mut nested = b"\x30\x80".repeat(MAX_NESTING + 1);
        nested.extend_from_slice(&b"\x00\x00".repeat(MAX_NESTING + 1));
        assert!(Ber::sequence(&nested).is_none());

        let mut too_many_items = b"\x30\x80".to_vec();
        too_many_items.extend_from_slice(&b"\x05\x00".repeat(MAX_ITEMS));
        too_many_items.extend_from_slice(b"\x00\x00");
        assert!(Ber::sequence(&too_many_items).is_none());
    }
}
