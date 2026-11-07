use crate::Error;
/// Lower-case output, without a C terminator. Refusal changes no destination.
pub fn encode_hex_lower(input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    let n = input.len().checked_mul(2).ok_or(Error::Overflow)?;
    if n > output.len() {
        return Err(Error::Capacity);
    }
    let digits = b"0123456789abcdef";
    for (i, b) in input.iter().enumerate() {
        output[2 * i] = digits[usize::from(b >> 4)];
        output[2 * i + 1] = digits[usize::from(b & 15)];
    }
    Ok(n)
}
/// GNUnet pair-wise scanf semantics: mixed case, partial pair, whitespace/sign,
/// odd final nibble ignored, stop at first non-converting pair. Literal NUL ends
/// the native C string. Destination capacity is checked before any conversion.
pub fn decode_hex_native(input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    let input = input.split(|b| *b == 0).next().unwrap_or(&[]);
    if input.len() / 2 > output.len() {
        return Err(Error::Capacity);
    }
    let mut written = 0;
    for pair in input.as_chunks::<2>().0 {
        let Some(byte) = pair_value(pair) else {
            break;
        };
        output[written] = byte;
        written += 1;
    }
    Ok(written)
}
fn digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
fn pair_value(mut input: &[u8]) -> Option<u8> {
    while input
        .first()
        .is_some_and(|b| *b == b' ' || (9..=13).contains(b))
    {
        input = &input[1..];
    }
    let negative = input.first() == Some(&b'-');
    if negative || input.first() == Some(&b'+') {
        input = &input[1..];
    }
    let first = digit(*input.first()?)?;
    let value = if let Some(second) = input.get(1).and_then(|b| digit(*b)) {
        first * 16 + second
    } else {
        first
    };
    Some(if negative {
        0_u8.wrapping_sub(value)
    } else {
        value
    })
}
