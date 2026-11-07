//! Official scalar conversion conventions from configuration.c and strings.c.
use crate::{CaseSnapshot, Error, LocaleSnapshot};

fn number_prefix(input: &[u8], profile: &CaseSnapshot) -> Result<(u64, usize), Error> {
    let native_scan = match profile {
        CaseSnapshot::Native(locale) => Some(locale.scan_number(input)),
        CaseSnapshot::CurrentThread(locale) => Some(locale.scan_number(input)),
        CaseSnapshot::C => None,
    };
    if let Some(scan) = native_scan {
        let scan = scan.map_err(native_value_error)?;
        if scan.range_error {
            return Err(Error::Overflow);
        }
        if scan.consumed == 0 {
            return Err(Error::InvalidValue);
        }
        return Ok((scan.value, scan.consumed));
    }
    let mut offset = input
        .iter()
        .position(|b| !profile.is_space(*b))
        .ok_or(Error::InvalidValue)?;
    let negative = input[offset] == b'-';
    if matches!(input[offset], b'+' | b'-') {
        offset += 1;
    }
    let start = offset;
    let mut number = 0u64;
    while let Some(byte) = input.get(offset).filter(|b| b.is_ascii_digit()) {
        number = number
            .checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(*byte - b'0')))
            .ok_or(Error::Overflow)?;
        offset += 1;
    }
    if start == offset {
        return Err(Error::InvalidValue);
    }
    Ok((
        if negative {
            number.wrapping_neg()
        } else {
            number
        },
        offset,
    ))
}

/// Decimal unsigned configuration number, including C's optional signed prefix.
/// Trailing ASCII whitespace is allowed; suffixes and overflowing magnitudes fail.
pub fn parse_number(input: &[u8]) -> Result<u64, Error> {
    parse_number_in(input, &CaseSnapshot::C)
}
pub(crate) fn parse_number_in(input: &[u8], profile: &CaseSnapshot) -> Result<u64, Error> {
    let (number, offset) = number_prefix(input, profile)?;
    if input[offset..].iter().any(|b| !profile.is_space(*b)) {
        return Err(Error::InvalidValue);
    }
    Ok(number)
}

#[derive(Clone, Copy)]
enum Arithmetic {
    OfficialWrapping,
    Checked,
}
impl Arithmetic {
    fn add(self, left: u64, right: u64) -> Result<u64, Error> {
        match self {
            Self::OfficialWrapping => Ok(left.wrapping_add(right)),
            Self::Checked => left.checked_add(right).ok_or(Error::Overflow),
        }
    }
    fn multiply(self, left: u64, right: u64) -> Result<u64, Error> {
        match self {
            Self::OfficialWrapping => Ok(left.wrapping_mul(right)),
            Self::Checked => left.checked_mul(right).ok_or(Error::Overflow),
        }
    }
}
fn convert(
    input: &[u8],
    table: &[(&[u8], u64)],
    profile: &CaseSnapshot,
    arithmetic: Arithmetic,
) -> Result<u64, Error> {
    if input.contains(&0) {
        return Err(Error::InvalidInput);
    }
    let mut total = 0u64;
    let mut last = 0u64;
    for part in input.split(|b| *b == b' ').filter(|p| !p.is_empty()) {
        let mut token = part;
        loop {
            if let Some((_, factor)) = table.iter().find(|(name, _)| profile.equals(name, token)) {
                last = arithmetic.multiply(last, *factor)?;
                break;
            }
            total = arithmetic.add(total, last)?;
            if matches!(arithmetic, Arithmetic::Checked)
                && token.iter().find(|b| !profile.is_space(**b)) == Some(&b'-')
            {
                return Err(Error::InvalidValue);
            }
            let (number, end) = number_prefix(token, profile)?;
            last = number;
            if end == token.len() {
                break;
            }
            token = &token[end..];
        }
    }
    arithmetic.add(total, last)
}

/// Official fancy-size parser. Units and unsigned wrapping match the pinned C
/// table, including its historical 1024 factor in decimal TB/PB/EB entries.
pub fn parse_size(input: &[u8]) -> Result<u64, Error> {
    parse_size_in(input, &CaseSnapshot::C)
}
pub(crate) fn parse_size_in(input: &[u8], profile: &CaseSnapshot) -> Result<u64, Error> {
    convert(
        input,
        &[
            (b"B", 1),
            (b"KiB", 1024),
            (b"kB", 1000),
            (b"MiB", 1024 * 1024),
            (b"MB", 1000 * 1000),
            (b"GiB", 1024 * 1024 * 1024),
            (b"GB", 1000 * 1000 * 1000),
            (b"TiB", 1024u64.pow(4)),
            (b"TB", 1000u64.pow(3) * 1024),
            (b"PiB", 1024u64.pow(5)),
            (b"PB", 1000u64.pow(4) * 1024),
            (b"EiB", 1024u64.pow(6)),
            (b"EB", 1000u64.pow(5) * 1024),
        ],
        profile,
        Arithmetic::OfficialWrapping,
    )
}

/// Official relative microseconds; `forever` is UINT64_MAX. Multiple numbers
/// and units use the original unsigned sum/product behavior.
pub fn parse_relative_time(input: &[u8]) -> Result<u64, Error> {
    parse_relative_time_in(input, &CaseSnapshot::C)
}
pub(crate) fn parse_relative_time_in(input: &[u8], profile: &CaseSnapshot) -> Result<u64, Error> {
    if profile.equals(input, b"forever") {
        return Ok(u64::MAX);
    }
    convert(input, TIME_UNITS, profile, Arithmetic::OfficialWrapping)
}

const SECOND: u64 = 1_000_000;
const MINUTE: u64 = 60 * SECOND;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;
const TIME_UNITS: &[(&[u8], u64)] = &[
    (b"us", 1),
    (b"ms", 1000),
    (b"s", SECOND),
    (b"second", SECOND),
    (b"seconds", SECOND),
    (b"\"", SECOND),
    (b"m", MINUTE),
    (b"min", MINUTE),
    (b"minute", MINUTE),
    (b"minutes", MINUTE),
    (b"'", MINUTE),
    (b"h", HOUR),
    (b"hour", HOUR),
    (b"hours", HOUR),
    (b"d", DAY),
    (b"day", DAY),
    (b"days", DAY),
    (b"w", 7 * DAY),
    (b"week", 7 * DAY),
    (b"weeks", 7 * DAY),
    (b"year", 365 * DAY),
    (b"years", 365 * DAY),
    (b"y", 365 * DAY),
    (b"a", 365 * DAY),
];

/// Parse the same relative-time token/unit grammar for a checked Rust policy.
/// Only explicit `forever` (ASCII case-insensitive, surrounding whitespace
/// allowed) is infinite. Negative values, finite UINT64_MAX and any unit-product
/// or accumulated-sum overflow fail. The official configuration parser keeps
/// its original signed/wrapping semantics independently.
pub fn parse_relative_time_checked(input: &[u8]) -> Result<u64, Error> {
    if input.trim_ascii().eq_ignore_ascii_case(b"forever") {
        return Ok(u64::MAX);
    }
    if input.trim_ascii().is_empty() {
        return Err(Error::InvalidValue);
    }
    let value = convert(input, TIME_UNITS, &CaseSnapshot::C, Arithmetic::Checked)?;
    if value == u64::MAX {
        return Err(Error::Overflow);
    }
    Ok(value)
}

pub(crate) fn native_value_error(error: std::io::Error) -> Error {
    match error.kind() {
        std::io::ErrorKind::OutOfMemory => Error::Capacity,
        std::io::ErrorKind::Unsupported => Error::Unsupported,
        _ => Error::InvalidValue,
    }
}
pub(crate) fn parse_float(input: &[u8], case: &CaseSnapshot) -> Result<f32, Error> {
    if let CaseSnapshot::CurrentThread(locale) = case {
        let result = locale
            .configuration_float(input)
            .map_err(native_value_error)?;
        if result.range_error {
            return Err(Error::Overflow);
        }
        return if result.matched {
            Ok(result.value)
        } else {
            Err(Error::InvalidValue)
        };
    }

    // Explicit immutable/pure-C profiles use stable C conversion rules. The
    // CurrentThread branch above implements the source's actual native mixed
    // locale and failure effect, including ABI-specific NULL-base categories.
    // Global comma numeric conventions never silently replace numeric C.
    let profile = LocaleSnapshot::named(b"C").map_err(native_value_error)?;
    let scan = profile.scan_float(input).map_err(native_value_error)?;
    if scan.range_error {
        return Err(Error::Overflow);
    }
    if scan.consumed == 0
        || input[scan.consumed..]
            .iter()
            .any(|&value| !matches!(value, b' ' | b'\t'..=b'\r'))
    {
        return Err(Error::InvalidValue);
    }
    Ok(scan.value)
}

pub(crate) fn decode_data(input: &[u8], output: &mut [u8]) -> Result<(), Error> {
    let bits = output.len().checked_mul(8).ok_or(Error::Overflow)?;
    if input.len() != bits.div_ceil(5) {
        return Err(Error::InvalidValue);
    }
    let mut accumulator = 0u32;
    let mut pending = 0;
    let mut index = 0;
    for byte in input {
        let value = match byte.to_ascii_uppercase() {
            b'O' => b'0',
            b'I' | b'L' => b'1',
            b'U' => b'V',
            b => b,
        };
        let value = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"
            .iter()
            .position(|b| *b == value)
            .ok_or(Error::InvalidValue)? as u32;
        accumulator = (accumulator << 5) | value;
        pending += 5;
        if pending >= 8 {
            pending -= 8;
            output[index] = (accumulator >> pending) as u8;
            index += 1;
        }
    }
    Ok(())
}

#[cfg(test)]
mod checked_time_tests {
    use super::*;
    #[test]
    fn checked_intervals_share_the_original_units_and_explicit_infinity() {
        for (text, value) in [
            (b"1h 2min 3s 4ms 5us".as_slice(), 3_723_004_005),
            (b"1' 2\"".as_slice(), 62_000_000),
            (b"1w 1y".as_slice(), 32_140_800_000_000),
            (b"0".as_slice(), 0),
        ] {
            assert!(matches!(parse_relative_time_checked(text), Ok(actual) if actual == value));
            assert!(matches!(parse_relative_time(text), Ok(actual) if actual == value));
        }
        assert!(matches!(
            parse_relative_time_checked(b" \tFoReVeR\n"),
            Ok(u64::MAX)
        ));
        assert!(matches!(parse_relative_time(b"forever"), Ok(u64::MAX)));
        assert!(matches!(parse_relative_time(b"s"), Ok(0)));
        assert!(matches!(parse_relative_time(b""), Ok(0)));
        assert!(parse_relative_time_checked(b"").is_err());
        assert!(parse_relative_time_checked(b"forever\0").is_err());
    }
    #[test]
    fn finite_wrapping_cannot_become_a_short_interval_or_infinite_policy() {
        assert!(matches!(parse_relative_time(b"-1 us"), Ok(u64::MAX)));
        assert!(matches!(
            parse_relative_time_checked(b"-1 us"),
            Err(Error::InvalidValue)
        ));
        assert!(matches!(
            parse_relative_time(b"18446744073709551614us 2us"),
            Ok(0)
        ));
        for text in [
            b"18446744073709551615us".as_slice(),
            b"18446744073709551615 s".as_slice(),
            b"18446744073709551614us 2us".as_slice(),
            b"18446744073709551616us".as_slice(),
        ] {
            assert!(matches!(
                parse_relative_time_checked(text),
                Err(Error::Overflow)
            ));
        }
    }
}
