//! The active NAMESTORE record-line interchange grammar, independent of IO.
//!
//! Headers select an existing IDENTITY owner. Values use the normal active
//! record text codec; this module never interprets keys or authorizes records.
use crate::{Error, RecordType, helpers::Writer, type_name, typename_to_number};
use gnunet_gnsrecord::RecordFlags;

/// One borrowed physical line, without its CR/LF terminator.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Line<'a> {
    /// Empty or ASCII-whitespace-only line.
    Empty,
    /// `<label>.<owner>:`; the first dot separates the literal label and owner.
    Header {
        /// Literal NAMESTORE label; `@` denotes the apex.
        label: &'a str,
        /// Existing ego name or standard typed public-key text.
        owner: &'a str,
    },
    /// `TYPE EXPIRATION [flags] VALUE`, optionally indented.
    Record {
        /// Active record text type.
        record_type: RecordType,
        /// Raw absolute microseconds or relative duration, according to flags.
        expiration_time: u64,
        /// Standard flags exactly expressible by this grammar.
        flags: RecordFlags,
        /// Original remaining text, including additional leading/trailing spaces.
        value: &'a str,
    },
}

impl core::fmt::Debug for Line<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => f.write_str("Empty"),
            Self::Header { label, owner } => f
                .debug_struct("Header")
                .field("label", label)
                .field("owner", owner)
                .finish(),
            Self::Record {
                record_type,
                expiration_time,
                flags,
                value,
            } => f
                .debug_struct("Record")
                .field("record_type", record_type)
                .field("expiration_time", expiration_time)
                .field("flags", flags)
                .field("value_bytes", &value.len())
                .finish_non_exhaustive(),
        }
    }
}

/// Flags represented by the fixed public record-line parser. Maintenance and
/// unknown bits have no spelling and must not be silently discarded on export.
pub const FLAGS: RecordFlags = RecordFlags::PRIVATE
    .union(RecordFlags::SUPPLEMENTAL)
    .union(RecordFlags::RELATIVE_EXPIRATION)
    .union(RecordFlags::SHADOW)
    .union(RecordFlags::CRITICAL);

fn header(label: &str, owner: &str) -> Result<(), Error> {
    if label.is_empty()
        || label.len() > 255
        || label.contains('.')
        || owner.is_empty()
        || owner.len() > 255
        || label
            .bytes()
            .chain(owner.bytes())
            .any(|b| matches!(b, 0 | b'\r' | b'\n'))
        || label.as_bytes()[0].is_ascii_whitespace()
    {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
fn token(text: &str) -> Result<(&str, &str), Error> {
    let text = text.trim_start_matches(|c: char| c.is_ascii_whitespace());
    if text.is_empty() {
        return Err(Error::Malformed);
    }
    let end = text
        .find(|c: char| c.is_ascii_whitespace())
        .unwrap_or(text.len());
    Ok((&text[..end], &text[end..]))
}
/// Decode a single bounded caller-owned line. No comment/escape/private syntax
/// is added. A record without a preceding header is rejected by its stream owner.
pub fn parse(text: &str) -> Result<Line<'_>, Error> {
    if text.bytes().any(|b| matches!(b, 0 | b'\r' | b'\n')) {
        return Err(Error::Malformed);
    }
    if text.bytes().all(|b| b.is_ascii_whitespace()) {
        return Ok(Line::Empty);
    }
    if !text.as_bytes()[0].is_ascii_whitespace()
        && let Some(text) = text.strip_suffix(':')
    {
        let (label, owner) = text.split_once('.').ok_or(Error::Malformed)?;
        header(label, owner)?;
        return Ok(Line::Header { label, owner });
    }
    let (kind, rest) = token(text)?;
    let record_type = typename_to_number(kind).ok_or(Error::Unsupported)?;
    let (expiration, rest) = token(rest)?;
    let expiration_time = crate::helpers::number(expiration, u64::MAX)?;
    let (flag_text, rest) = token(rest)?;
    let inside = flag_text
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or(Error::Malformed)?;
    let mut flags = RecordFlags::PRIVATE;
    for flag in inside.bytes() {
        flags = match flag {
            b'p' => flags.without(RecordFlags::PRIVATE),
            b'S' => flags.union(RecordFlags::SUPPLEMENTAL),
            b'r' => flags.union(RecordFlags::RELATIVE_EXPIRATION),
            b's' => flags.union(RecordFlags::SHADOW),
            b'C' => flags.union(RecordFlags::CRITICAL),
            _ => return Err(Error::Unsupported),
        };
    }
    // The first separator belongs to the grammar; further spaces belong to the
    // plugin value. An explicit final separator can represent an empty value.
    let value = rest.get(1..).ok_or(Error::Malformed)?;
    Ok(Line::Record {
        record_type,
        expiration_time,
        flags,
        value,
    })
}

/// Format a standard header including LF. Unrepresentable labels are refused,
/// rather than emitting a header that would select a different label on import.
pub fn format_header(label: &str, owner: &str, output: &mut [u8]) -> Result<usize, Error> {
    header(label, owner)?;
    let needed = label
        .len()
        .checked_add(owner.len())
        .and_then(|n| n.checked_add(3))
        .ok_or(Error::Overflow)?;
    if output.len() < needed {
        return Err(Error::Capacity);
    }
    let mut out = Writer::new(output);
    out.bytes(label.as_bytes())?;
    out.byte(b'.')?;
    out.bytes(owner.as_bytes())?;
    out.bytes(b":\n")?;
    Ok(out.len())
}
/// Format one already-converted plugin value with LF. The lowercase `s` is the
/// fixed C importer's actual SHADOW spelling; its exporter incorrectly emits S.
/// No flag or value byte that cannot round-trip through the grammar is dropped.
pub fn format_record(
    record_type: RecordType,
    expiration_time: u64,
    flags: RecordFlags,
    value: &str,
    output: &mut [u8],
) -> Result<usize, Error> {
    let kind = type_name(record_type).ok_or(Error::Unsupported)?;
    if flags.bits() & !FLAGS.bits() != 0 {
        return Err(Error::Unsupported);
    }
    if value.bytes().any(|b| matches!(b, 0 | b'\r' | b'\n')) {
        return Err(Error::Unsupported);
    }
    let mut digits = 1usize;
    let mut n = expiration_time;
    while n >= 10 {
        digits += 1;
        n /= 10;
    }
    let flag_bytes = [
        (!flags.contains(RecordFlags::PRIVATE), b'p'),
        (flags.contains(RecordFlags::SUPPLEMENTAL), b'S'),
        (flags.contains(RecordFlags::RELATIVE_EXPIRATION), b'r'),
        (flags.contains(RecordFlags::SHADOW), b's'),
        (flags.contains(RecordFlags::CRITICAL), b'C'),
    ];
    let needed = kind
        .len()
        .checked_add(digits)
        .and_then(|n| n.checked_add(flag_bytes.iter().filter(|(yes, _)| *yes).count()))
        .and_then(|n| n.checked_add(value.len()))
        .and_then(|n| n.checked_add(8))
        .ok_or(Error::Overflow)?;
    if output.len() < needed {
        return Err(Error::Capacity);
    }
    let mut out = Writer::new(output);
    out.bytes(b"  ")?;
    out.bytes(kind.as_bytes())?;
    out.byte(b' ')?;
    out.number(expiration_time)?;
    out.bytes(b" [")?;
    for (yes, byte) in flag_bytes {
        if yes {
            out.byte(byte)?;
        }
    }
    out.bytes(b"] ")?;
    out.bytes(value.as_bytes())?;
    out.byte(b'\n')?;
    Ok(out.len())
}
