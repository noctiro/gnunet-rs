//! Common allocation-free Base32GNS, with the official Crockford aliases and
//! ignored low padding bits. No hash, crypto or key interpretation occurs.
use gnunet_types::Error;
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Complete unpadded Base32GNS length, checked before any output changes.
pub fn base32_encoded_len(bytes: usize) -> Result<usize, Error> {
    Ok(bytes
        .checked_mul(8)
        .and_then(|n| n.checked_add(4))
        .ok_or(Error::Overflow)?
        / 5)
}
/// Encode raw bytes using canonical uppercase Base32GNS, without a terminator.
/// Insufficient output leaves the whole destination unchanged.
pub fn encode_base32(input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    let n = base32_encoded_len(input.len())?;
    if output.len() < n {
        return Err(Error::Capacity);
    }
    let (mut bits, mut available, mut pos) = (0u16, 0u32, 0usize);
    for byte in input {
        bits = ((bits & ((1u16 << available) - 1)) << 8) | u16::from(*byte);
        available += 8;
        while available >= 5 {
            available -= 5;
            output[pos] = ALPHABET[usize::from((bits >> available) & 31)];
            pos += 1;
        }
    }
    if available > 0 {
        output[pos] = ALPHABET[usize::from((bits << (5 - available)) & 31)];
    }
    Ok(n)
}
fn digit(byte: u8) -> Result<u8, Error> {
    let canonical = match byte.to_ascii_uppercase() {
        b'O' => b'0',
        b'I' | b'L' => b'1',
        b'U' => b'V',
        v => v,
    };
    ALPHABET
        .iter()
        .position(|b| *b == canonical)
        .map(|n| n as u8)
        .ok_or(Error::Malformed)
}
/// Decode complete unpadded Base32GNS into a caller buffer. The exact encoded
/// length must correspond to whole bytes. Case and O/I/L/U aliases match C;
/// unused low bits of the final symbol are ignored. All digits and capacity are
/// preflighted, so errors preserve the complete output slice.
pub fn decode_base32(input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    let n = input.len().checked_mul(5).ok_or(Error::Overflow)? / 8;
    if base32_encoded_len(n)? != input.len() {
        return Err(Error::Malformed);
    }
    if output.len() < n {
        return Err(Error::Capacity);
    }
    for byte in input {
        digit(*byte)?;
    }
    let (mut bits, mut available, mut pos) = (0u16, 0u32, 0usize);
    for byte in input {
        bits = ((bits & ((1u16 << available) - 1)) << 5) | u16::from(digit(*byte)?);
        available += 5;
        if available >= 8 {
            available -= 8;
            output[pos] = (bits >> available) as u8;
            pos += 1;
        }
    }
    Ok(n)
}
