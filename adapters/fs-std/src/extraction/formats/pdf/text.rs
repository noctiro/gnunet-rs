//! PDF text strings and UTC document dates.

use time::{Date, Month, PrimitiveDateTime, Time, UtcOffset};

pub(super) fn metadata(bytes: &[u8], limit: usize) -> Option<String> {
    let mut text = decode(bytes)?;
    text.truncate(
        text.trim_end_matches([' ', '\t', '\r', '\n', '\u{000b}', '\u{000c}'])
            .len(),
    );
    valid(text, limit)
}

pub(super) fn file_name(bytes: &[u8], limit: usize) -> Option<String> {
    valid(decode(bytes)?, limit)
}

fn valid(text: String, limit: usize) -> Option<String> {
    (!text.is_empty() && text.len() <= limit && !text.contains('\0')).then_some(text)
}

fn decode(bytes: &[u8]) -> Option<String> {
    let mut text = String::new();
    if let Some(utf8) = bytes.strip_prefix(b"\xef\xbb\xbf") {
        text.push_str(std::str::from_utf8(utf8).ok()?);
    } else if let Some(utf16) = bytes.strip_prefix(b"\xfe\xff") {
        let (pairs, tail) = utf16.as_chunks::<2>();
        if !tail.is_empty() {
            return None;
        }
        for scalar in char::decode_utf16(pairs.iter().copied().map(u16::from_be_bytes)) {
            text.push(scalar.ok()?);
        }
    } else {
        for byte in bytes.iter().copied() {
            text.push(pdf_doc_character(byte)?);
        }
    }
    Some(text)
}

fn pdf_doc_character(byte: u8) -> Option<char> {
    const DIACRITICS: [char; 8] = ['˘', 'ˇ', 'ˆ', '˙', '˝', '˛', '˚', '˜'];
    const SYMBOLS: [char; 31] = [
        '•', '†', '‡', '…', '—', '–', 'ƒ', '⁄', '‹', '›', '−', '‰', '„', '“', '”', '‘', '’', '‚',
        '™', 'ﬁ', 'ﬂ', 'Ł', 'Œ', 'Š', 'Ÿ', 'Ž', 'ı', 'ł', 'œ', 'š', 'ž',
    ];
    Some(match byte {
        0x18..=0x1f => DIACRITICS[usize::from(byte - 0x18)],
        0x80..=0x9e => SYMBOLS[usize::from(byte - 0x80)],
        0xa0 => '€',
        0x7f | 0x9f | 0xad => return None,
        _ => char::from(byte),
    })
}

pub(super) fn date(bytes: &[u8], limit: usize) -> Option<String> {
    if limit < 19 {
        return None;
    }
    let mut remaining = bytes.trim_ascii();
    remaining = remaining.strip_prefix(b"D:").unwrap_or(remaining);
    let year = take_number(&mut remaining, 4)?;
    let mut components = [1, 1, 0, 0, 0];
    for component in &mut components {
        if !remaining.first().is_some_and(u8::is_ascii_digit) {
            break;
        }
        *component = take_number(&mut remaining, 2)?;
    }
    let [month, day, hour, minute, second] = components.map(|n| n as u8);
    let offset = timezone(remaining)?;
    let date = Date::from_calendar_date(i32::from(year), Month::try_from(month).ok()?, day).ok()?;
    let time = Time::from_hms(hour, minute, second).ok()?;
    let utc = PrimitiveDateTime::new(date, time)
        .assume_offset(offset)
        .checked_to_offset(UtcOffset::UTC)?;
    let (year, month, day) = utc.date().to_calendar_date();
    if !(0..=9999).contains(&year) || matches!(utc.unix_timestamp(), -1 | 0) {
        return None;
    }
    let (hour, minute, second) = utc.time().as_hms();
    Some(format!(
        "{year:04}-{:02}-{day:02} {hour:02}:{minute:02}:{second:02}",
        u8::from(month)
    ))
}

fn take_number(bytes: &mut &[u8], width: usize) -> Option<u16> {
    let (digits, remaining) = bytes.split_at_checked(width)?;
    let value = digits.iter().try_fold(0_u16, |value, digit| {
        digit
            .is_ascii_digit()
            .then(|| value * 10 + u16::from(digit - b'0'))
    })?;
    *bytes = remaining;
    Some(value)
}

fn timezone(mut bytes: &[u8]) -> Option<UtcOffset> {
    let sign = match bytes.first() {
        None | Some(b'Z') if matches!(bytes, b"" | b"Z" | b"Z00'00'" | b"Z00'00") => {
            return Some(UtcOffset::UTC);
        }
        Some(b'+') => 1,
        Some(b'-') => -1,
        _ => return None,
    };
    bytes = &bytes[1..];
    let hour = i8::try_from(take_number(&mut bytes, 2)?).ok()?;
    bytes = bytes.strip_prefix(b"'").unwrap_or(bytes);
    let minute = if bytes.is_empty() {
        0
    } else {
        i8::try_from(take_number(&mut bytes, 2)?).ok()?
    };
    if !matches!(bytes, b"" | b"'") {
        return None;
    }
    UtcOffset::from_hms(hour * sign, minute * sign, 0).ok()
}
