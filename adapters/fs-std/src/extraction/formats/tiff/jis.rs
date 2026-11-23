//! Exif's ISO-2022-JP user comment profile.

use encoding_rs::ISO_2022_JP;
use std::borrow::Cow;

pub(super) fn decode(bytes: &[u8], limit: usize) -> Option<Cow<'_, str>> {
    let end = bytes.iter().rposition(|&byte| byte != 0)? + 1;
    let bytes = &bytes[..end];
    if bytes.contains(&0) {
        return None;
    }

    let mut segments = bytes.split(|&byte| byte == 0x1b);
    segments.next()?;
    let mut ascii = true;
    for segment in segments {
        let (designation, characters) = segment.split_first_chunk::<2>()?;
        ascii = match designation {
            b"(B" => true,
            b"(J" => false,
            b"$@" | b"$B" => {
                // Exclude the NEC and IBM extension rows in the WHATWG table.
                let (pairs, tail) = characters.as_chunks::<2>();
                if !tail.is_empty()
                    || pairs
                        .iter()
                        .any(|pair| matches!(pair[0], 0x2d | 0x79..=0x7c))
                {
                    return None;
                }
                false
            }
            _ => return None,
        };
    }
    if !ascii {
        return None;
    }

    let decoded = ISO_2022_JP.decode_without_bom_handling_and_without_replacement(bytes)?;
    // Use JIS X 0208 symbol mappings for the six Windows-compatible variants.
    let decoded = if decoded.contains(['～', '∥', '－', '￠', '￡', '￢']) {
        let mut text = String::new();
        text.try_reserve_exact(decoded.len()).ok()?;
        text.extend(decoded.chars().map(|character| match character {
            '～' => '〜',
            '∥' => '‖',
            '－' => '−',
            '￠' => '¢',
            '￡' => '£',
            '￢' => '¬',
            _ => character,
        }));
        Cow::Owned(text)
    } else {
        decoded
    };
    (!decoded.is_empty() && decoded.len() <= limit).then_some(decoded)
}
