//! Generic GNUnet Crockford Base32 text, with no key import/crypto/provider call.
//! Typed identity/identifier owners validate decoded lengths and tags afterwards.
use gnunet_types::Error;
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Required unpadded official Base32 text bytes, checked without allocation.
pub fn encoded_len(bytes: usize) -> Result<usize, Error> {
    bytes
        .checked_mul(8)
        .and_then(|n| n.checked_add(4))
        .map(|n| n / 5)
        .ok_or(Error::Overflow)
}
/// Encode raw bytes exactly, leaving output unchanged on refusal. Caller erases
/// input/output storage if these are private typed-key or capability bytes.
pub fn encode(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let n = encoded_len(input.len())?;
    let out = out.get_mut(..n).ok_or(Error::Capacity)?;
    let (mut acc, mut bits, mut at) = (0u16, 0u32, 0usize);
    for b in input {
        acc = (acc << 8) | u16::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out[at] = ALPHABET[usize::from((acc >> bits) & 31)];
            at += 1;
        }
        acc &= (1 << bits) - 1;
    }
    if bits != 0 {
        out[at] = ALPHABET[usize::from((acc << (5 - bits)) & 31)];
    }
    Ok(n)
}
/// Decode an exact caller-selected byte length. Ambiguous Crockford O/I/L and
/// lower-case letters match the public GNUnet alphabet. Nonzero unused bits and
/// wrong lengths are refused. Validation/capacity failure changes no output.
pub fn decode(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if input.len() != encoded_len(out.len())? {
        return Err(Error::Malformed);
    }
    for b in input {
        digit(*b)?;
    }
    let used = out.len().checked_mul(8).ok_or(Error::Overflow)?;
    let trailing = input.len() * 5 - used;
    if trailing != 0 && digit(*input.last().ok_or(Error::Malformed)?)? & ((1 << trailing) - 1) != 0
    {
        return Err(Error::Malformed);
    }
    let (mut acc, mut bits, mut at) = (0u16, 0u32, 0usize);
    for b in input {
        acc = (acc << 5) | u16::from(digit(*b)?);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out[at] = ((acc >> bits) & 255) as u8;
            at += 1;
        }
        acc &= (1 << bits) - 1;
    }
    Ok(at)
}
fn digit(b: u8) -> Result<u8, Error> {
    let b = b.to_ascii_uppercase();
    match b {
        b'O' => Ok(0),
        b'I' | b'L' => Ok(1),
        b'U' => Ok(27),
        _ => ALPHABET
            .iter()
            .position(|x| *x == b)
            .map(|n| n as u8)
            .ok_or(Error::Malformed),
    }
}
