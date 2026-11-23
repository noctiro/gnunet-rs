//! ImageMagick profiles carried by PNG text chunks.

use super::super::{iptc, photoshop};

pub(super) fn visit_iptc<E>(
    text: &[u8],
    output: &mut Vec<u8>,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<bool, E> {
    let Some(bytes) = decode_raw_profile(text, output) else {
        return Ok(false);
    };
    if let Some(profile) = iptc::Profile::parse(bytes, 0) {
        profile.emit(limit, emit)?;
        return Ok(true);
    }
    photoshop::visit_iptc(bytes, limit, emit)
}

pub(super) fn decode_raw_profile<'a>(text: &[u8], output: &'a mut Vec<u8>) -> Option<&'a [u8]> {
    let text = text
        .strip_prefix(b"\n")
        .or_else(|| text.strip_prefix(b"\r\n"))?;
    let mut lines = text.splitn(3, |&byte| byte == b'\n');
    let _description = lines.next()?;
    let decimal = lines.next()?.trim_ascii();
    let encoded = lines.next()?;
    let length = decimal.iter().try_fold(0_usize, |length, &byte| {
        if !byte.is_ascii_digit() {
            return None;
        }
        length
            .checked_mul(10)?
            .checked_add(usize::from(byte - b'0'))
    })?;
    if length == 0 || length > encoded.len() / 2 {
        return None;
    }
    output.clear();
    output.try_reserve_exact(length).ok()?;
    let mut high = None;
    let mut line_start = true;
    for &byte in encoded {
        let first_column = line_start;
        line_start = byte == b'\n';
        if byte.is_ascii_whitespace() || (first_column && byte == b'=') {
            continue;
        }
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        if let Some(previous) = high.take() {
            if output.len() == length {
                return None;
            }
            output.push((previous << 4) | nibble);
        } else {
            high = Some(nibble);
        }
    }
    (output.len() == length && high.is_none()).then_some(output)
}
