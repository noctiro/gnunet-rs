//! Unicode coding systems designated by ISO 2022 DOCS in IIM DataSet 1:90.

use gnunet_fs::metadata::c_prefix;

use super::{append_text, trim_leading_space};

const RETURN: &[u8] = b"\x1b%@";

pub(super) fn take_returning<'a>(bytes: &mut &'a [u8]) -> Option<&'a str> {
    let end = bytes
        .iter()
        .position(|&byte| byte == 0x1b)
        .unwrap_or(bytes.len());
    let (run, rest) = bytes.split_at(end);
    *bytes = if rest.is_empty() {
        rest
    } else {
        rest.strip_prefix(RETURN)?
    };
    let run = run.strip_prefix(b"\xef\xbb\xbf").unwrap_or(run);
    plain_utf8(run)
}

#[derive(Clone, Copy)]
pub(super) enum Coding {
    Utf8,
    Ucs2,
    Utf16,
    Ucs4,
}

impl Coding {
    pub(super) fn designated(controls: &[u8]) -> Option<Self> {
        // ISO/IEC 10646 uses the former implementation-level-3 designators.
        Some(match controls {
            // IIM 1:90 requires UTF-8 to be the sole declaration and forbids
            // designation and invocation functions in the following records.
            b"\x1b%G" | b"\x1b%/I" => Self::Utf8, // ISO-IR 196 and 192
            b"\x1b%/E" => Self::Ucs2,             // ISO-IR 176
            b"\x1b%/F" => Self::Ucs4,             // ISO-IR 177
            b"\x1b%/L" => Self::Utf16,            // ISO-IR 195
            _ => return None,
        })
    }

    pub(super) fn decode<'a>(
        self,
        bytes: &'a [u8],
        out: &'a mut String,
        limit: usize,
    ) -> Option<&'a [u8]> {
        match self {
            Self::Utf8 => {
                let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
                let text = trim_leading_space(c_prefix(bytes));
                if text.is_empty() || text.len() > limit {
                    return None;
                }
                plain_utf8(text).map(str::as_bytes)
            }
            Self::Ucs2 | Self::Utf16 => {
                let (bytes, decode): (_, fn([u8; 2]) -> u16) = match bytes {
                    [0xfe, 0xff, rest @ ..] => (rest, u16::from_be_bytes),
                    [0xff, 0xfe, rest @ ..] => (rest, u16::from_le_bytes),
                    _ => (bytes, u16::from_be_bytes),
                };
                let (units, []) = bytes.as_chunks::<2>() else {
                    return None;
                };
                let words = units.iter().copied().map(decode);
                match self {
                    Self::Ucs2 => collect(
                        words.map(|word| char::from_u32(u32::from(word))),
                        out,
                        limit,
                    ),
                    _ => collect(char::decode_utf16(words).map(Result::ok), out, limit),
                }
            }
            Self::Ucs4 => {
                let (bytes, decode): (_, fn([u8; 4]) -> u32) = match bytes {
                    [0x00, 0x00, 0xfe, 0xff, rest @ ..] => (rest, u32::from_be_bytes),
                    [0xff, 0xfe, 0x00, 0x00, rest @ ..] => (rest, u32::from_le_bytes),
                    _ => (bytes, u32::from_be_bytes),
                };
                let (units, []) = bytes.as_chunks::<4>() else {
                    return None;
                };
                collect(
                    units.iter().copied().map(decode).map(char::from_u32),
                    out,
                    limit,
                )
            }
        }
    }
}

fn plain_utf8(bytes: &[u8]) -> Option<&str> {
    if bytes.iter().any(|&byte| !plain_character(char::from(byte))) {
        return None;
    }
    std::str::from_utf8(bytes).ok()
}

fn collect(
    characters: impl Iterator<Item = Option<char>>,
    out: &mut String,
    limit: usize,
) -> Option<&[u8]> {
    out.clear();
    for character in characters {
        let character = character?;
        if !plain_character(character) {
            return None;
        }
        append_text(out, character, limit)?;
    }
    (!out.is_empty()).then_some(out.as_bytes())
}

fn plain_character(character: char) -> bool {
    !matches!(character, '\0' | '\x0e' | '\x0f' | '\x1b')
}
