//! RFC4648 bytes used by the active OAuth producer, with explicit alphabet/pad.
use gnunet_types::Error;
/// Exact encoded byte count, excluding any C terminator.
pub fn encoded_len(n: usize, padded: bool) -> Result<usize, Error> {
    if padded {
        n.checked_add(2)
            .and_then(|n| n.checked_div(3))
            .and_then(|n| n.checked_mul(4))
            .ok_or(Error::Overflow)
    } else {
        n.checked_mul(8)
            .and_then(|n| n.checked_add(5))
            .map(|n| n / 6)
            .ok_or(Error::Overflow)
    }
}
/// Encode in caller memory after whole capacity preflight.
pub fn encode(input: &[u8], out: &mut [u8], url: bool, padded: bool) -> Result<usize, Error> {
    const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let alphabet = if url { URL } else { STANDARD };
    let n = encoded_len(input.len(), padded)?;
    let out = out.get_mut(..n).ok_or(Error::Capacity)?;
    let mut accumulator = 0u32;
    let mut bits = 0;
    let mut at = 0;
    for b in input {
        accumulator = (accumulator << 8) | u32::from(*b);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            out[at] = alphabet[((accumulator >> bits) & 63) as usize];
            at += 1;
        }
        accumulator &= (1 << bits) - 1;
    }
    if bits != 0 {
        out[at] = alphabet[((accumulator << (6 - bits)) & 63) as usize];
        at += 1;
    }
    while at < n {
        out[at] = b'=';
        at += 1;
    }
    Ok(n)
}
/// Validate complete alphabet/padding and compute decoded size before output.
/// Both padded and canonical unpadded inputs are accepted; unused bits mustzero.
pub fn decoded_len(input: &[u8], url: bool) -> Result<usize, Error> {
    let padding = input.iter().rev().take_while(|b| **b == b'=').count();
    if padding > 2 {
        return Err(Error::Malformed);
    }
    let data = input.len() - padding;
    if data % 4 == 1
        || padding != 0 && (!input.len().is_multiple_of(4) || padding != (4 - data % 4) % 4)
    {
        return Err(Error::Malformed);
    }
    for b in &input[..data] {
        digit(*b, url)?;
    }
    let n = data.checked_mul(6).ok_or(Error::Overflow)? / 8;
    let unused = (data * 6) % 8;
    if unused != 0 && data != 0 && digit(input[data - 1], url)? & ((1 << unused) - 1) != 0 {
        return Err(Error::Malformed);
    }
    Ok(n)
}
/// Decode atomically with respect to validation/capacity failures.
pub fn decode(input: &[u8], out: &mut [u8], url: bool) -> Result<usize, Error> {
    let n = decoded_len(input, url)?;
    let out = out.get_mut(..n).ok_or(Error::Capacity)?;
    let mut accumulator = 0u32;
    let mut bits = 0;
    let mut at = 0;
    for b in input.iter().take_while(|b| **b != b'=') {
        accumulator = (accumulator << 6) | u32::from(digit(*b, url)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out[at] = (accumulator >> bits) as u8;
            at += 1;
        }
        accumulator &= (1 << bits) - 1;
    }
    Ok(at)
}
fn digit(b: u8, url: bool) -> Result<u8, Error> {
    match b {
        b'A'..=b'Z' => Ok(b - b'A'),
        b'a'..=b'z' => Ok(b - b'a' + 26),
        b'0'..=b'9' => Ok(b - b'0' + 52),
        b'-' if url => Ok(62),
        b'_' if url => Ok(63),
        b'+' if !url => Ok(62),
        b'/' if !url => Ok(63),
        _ => Err(Error::Malformed),
    }
}
