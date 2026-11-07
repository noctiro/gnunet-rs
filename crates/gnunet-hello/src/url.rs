use crate::{Hello, HelloBuilder, Limits, address::check_scheme};
use gnunet_crypto::{EddsaPublicKey, EddsaSignature};
use gnunet_types::Error;
use gnunet_wire::official::AbsoluteTime;
const PREFIX: &[u8] = b"gnunet://hello/";
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const HEX: &[u8; 16] = b"0123456789ABCDEF";

pub(crate) fn parse<'a>(
    input: &[u8],
    storage: &'a mut [u8],
    limits: Limits,
) -> Result<Hello<'a>, Error> {
    limits.check_input(input)?;
    if input.contains(&0) {
        return Err(Error::Malformed);
    }
    if !input
        .get(..PREFIX.len())
        .is_some_and(|s| s.eq_ignore_ascii_case(PREFIX))
    {
        return Err(Error::Malformed);
    }
    let rest = &input[PREFIX.len()..];
    let first = rest
        .iter()
        .position(|b| *b == b'/')
        .ok_or(Error::Malformed)?;
    let after = &rest[first + 1..];
    let second = after
        .iter()
        .position(|b| *b == b'/')
        .ok_or(Error::Malformed)?;
    let mut peer = [0; 32];
    let mut signature = [0; 64];
    decode_base32(&rest[..first], &mut peer)?;
    decode_base32(&after[..second], &mut signature)?;
    let tail = &after[second + 1..];
    let (expiration, consumed) = decimal(tail)?;
    let mut builder = HelloBuilder::new(storage, limits);
    if consumed < tail.len() {
        if tail[consumed] != b'?' {
            return Err(Error::Malformed);
        }
        let query = &tail[consumed + 1..];
        if query.is_empty() {
            return Err(Error::Malformed);
        }
        for part in query.split(|b| *b == b'&') {
            let eq = part
                .iter()
                .position(|b| *b == b'=')
                .ok_or(Error::Malformed)?;
            add_url_address(&mut builder, &part[..eq], &part[eq + 1..])?;
        }
    }
    Ok(builder.finish(
        EddsaPublicKey::from_bytes(peer),
        EddsaSignature::from_bytes(signature),
        AbsoluteTime::from_micros(expiration),
    ))
}
fn decimal(bytes: &[u8]) -> Result<(u64, usize), Error> {
    let mut pos = 0;
    while bytes.get(pos).is_some_and(|b| ascii_space(*b)) {
        pos += 1;
    }
    let negative = bytes.get(pos) == Some(&b'-');
    if negative || bytes.get(pos) == Some(&b'+') {
        pos += 1;
    }
    let start = pos;
    let mut value = 0_u64;
    while let Some(b) = bytes.get(pos).filter(|b| b.is_ascii_digit()) {
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(*b - b'0')))
            .ok_or(Error::Overflow)?;
        pos += 1;
    }
    if pos == start {
        return Err(Error::Malformed);
    }
    if negative {
        value = 0_u64.wrapping_sub(value);
    }
    Ok((value, pos))
}
fn add_url_address(
    builder: &mut HelloBuilder<'_>,
    scheme: &[u8],
    value: &[u8],
) -> Result<(), Error> {
    check_scheme(scheme)?;
    let mut decoded = 0_usize;
    let mut terminated = false;
    for byte in PercentBytes::new(value) {
        let byte = byte?;
        if byte == 0 {
            terminated = true;
        }
        if !terminated {
            decoded = decoded.checked_add(1).ok_or(Error::Overflow)?;
        }
    }
    if decoded == 0 {
        return Err(Error::Malformed);
    }
    let size = scheme
        .len()
        .checked_add(4)
        .and_then(|v| v.checked_add(decoded))
        .ok_or(Error::Overflow)?;
    let end = builder.preflight(size)?;
    let start = builder.used;
    builder.storage[start..start + scheme.len()].copy_from_slice(scheme);
    builder.storage[start + scheme.len()..start + scheme.len() + 3].copy_from_slice(b"://");
    for (pos, byte) in (start + scheme.len() + 3..).zip(PercentBytes::new(value)) {
        let byte = byte?;
        if byte == 0 {
            break;
        }
        builder.storage[pos] = byte;
    }
    builder.storage[end - 1] = 0;
    builder.commit_staged(size)
}
struct PercentBytes<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> PercentBytes<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
}
impl Iterator for PercentBytes<'_> {
    type Item = Result<u8, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        let byte = *self.bytes.get(self.pos)?;
        if byte != b'%' {
            self.pos += 1;
            return Some(Ok(byte));
        }
        if self.bytes.len() - self.pos < 3 {
            self.pos = self.bytes.len();
            return Some(Err(Error::Malformed));
        }
        // C sscanf("%2x") accepts a partial hexadecimal pair and skips leading
        // whitespace. The decoder always consumes exactly three original bytes.
        if let Some(value) = scan_hex(&self.bytes[self.pos + 1..]) {
            self.pos += 3;
            Some(Ok(value))
        } else {
            self.pos += 1;
            Some(Ok(b'%'))
        }
    }
}
fn scan_hex(mut bytes: &[u8]) -> Option<u8> {
    while bytes.first().is_some_and(|b| ascii_space(*b)) {
        bytes = &bytes[1..];
    }
    let field = &bytes[..bytes.len().min(2)];
    let negative = field.first() == Some(&b'-');
    let digits = if negative || field.first() == Some(&b'+') {
        &field[1..]
    } else {
        field
    };
    let first = hex(*digits.first()?)?;
    let value = if let Some(second) = digits.get(1).and_then(|b| hex(*b)) {
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
fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
const fn ascii_space(byte: u8) -> bool {
    byte == b' ' || (byte >= 9 && byte <= 13)
}
fn digit(byte: u8) -> Result<u8, Error> {
    let b = match byte.to_ascii_uppercase() {
        b'O' => b'0',
        b'I' | b'L' => b'1',
        b'U' => b'V',
        b => b,
    };
    ALPHABET
        .iter()
        .position(|v| *v == b)
        .map(|p| p as u8)
        .ok_or(Error::Malformed)
}
fn decode_base32(text: &[u8], output: &mut [u8]) -> Result<(), Error> {
    if text.len() != (output.len() * 8).div_ceil(5) {
        return Err(Error::Malformed);
    }
    let mut bits = 0_u16;
    let mut available = 0_u32;
    let mut position = 0;
    for b in text {
        bits = ((bits & ((1_u16 << available) - 1)) << 5) | u16::from(digit(*b)?);
        available += 5;
        if available >= 8 {
            available -= 8;
            *output.get_mut(position).ok_or(Error::Malformed)? = (bits >> available) as u8;
            position += 1;
        }
    }
    Ok(())
}
pub(crate) fn length(hello: Hello<'_>) -> Result<usize, Error> {
    let mut n = PREFIX.len() + 52 + 1 + 103 + 1 + decimal_len(hello.expiration.as_micros());
    for a in hello.addresses() {
        let body_size = body_len(a.body())?;
        n = n
            .checked_add(a.scheme().len())
            .and_then(|v| v.checked_add(2))
            .and_then(|v| v.checked_add(body_size))
            .ok_or(Error::Overflow)?;
    }
    Ok(n)
}
fn body_len(body: &[u8]) -> Result<usize, Error> {
    let mut pos = 0;
    let mut size = 0_usize;
    while pos < body.len() {
        let byte = body[pos];
        if byte < 128 {
            size = size
                .checked_add(if plain(byte) || byte == b' ' { 1 } else { 3 })
                .ok_or(Error::Overflow)?;
            pos += 1;
        } else {
            let width = match byte {
                0xc0..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf7 => 4,
                0xf8..=0xfb => 5,
                0xfc..=0xfd => 6,
                _ => return Err(Error::Malformed),
            };
            let end = pos.checked_add(width).ok_or(Error::Overflow)?;
            let group = body.get(pos..end).ok_or(Error::Malformed)?;
            if group.contains(&0) {
                return Err(Error::Malformed);
            }
            size = size.checked_add(width * 3).ok_or(Error::Overflow)?;
            pos = end;
        }
    }
    Ok(size)
}
fn plain(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
}
const fn decimal_len(mut value: u64) -> usize {
    let mut n = 1;
    while value >= 10 {
        value /= 10;
        n += 1;
    }
    n
}
struct Writer<'a> {
    output: &'a mut [u8],
    pos: usize,
}
impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) {
        self.output[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
    }
    fn byte(&mut self, byte: u8) {
        self.output[self.pos] = byte;
        self.pos += 1;
    }
    fn escaped(&mut self, byte: u8) {
        self.byte(b'%');
        self.byte(HEX[usize::from(byte >> 4)]);
        self.byte(HEX[usize::from(byte & 15)]);
    }
    fn base32(&mut self, bytes: &[u8]) {
        let mut bits = 0_u16;
        let mut available = 0_u32;
        for b in bytes {
            bits = ((bits & ((1_u16 << available) - 1)) << 8) | u16::from(*b);
            available += 8;
            while available >= 5 {
                available -= 5;
                self.byte(ALPHABET[usize::from((bits >> available) & 31)]);
            }
        }
        if available != 0 {
            self.byte(ALPHABET[usize::from((bits << (5 - available)) & 31)]);
        }
    }
    fn decimal(&mut self, mut value: u64) {
        let mut digits = [0; 20];
        let mut pos = digits.len();
        loop {
            pos -= 1;
            digits[pos] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        self.put(&digits[pos..]);
    }
    fn body(&mut self, bytes: &[u8]) {
        let mut pos = 0;
        while pos < bytes.len() {
            let byte = bytes[pos];
            if byte < 128 {
                if plain(byte) {
                    self.byte(byte);
                } else if byte == b' ' {
                    self.byte(b'+');
                } else {
                    self.escaped(byte);
                }
                pos += 1;
            } else {
                let width = match byte {
                    0xc0..=0xdf => 2,
                    0xe0..=0xef => 3,
                    0xf0..=0xf7 => 4,
                    0xf8..=0xfb => 5,
                    _ => 6,
                };
                for b in &bytes[pos..pos + width] {
                    self.escaped(*b);
                }
                pos += width;
            }
        }
    }
}
pub(crate) fn write<'a>(hello: Hello<'_>, output: &'a mut [u8]) -> Result<&'a str, Error> {
    let n = length(hello)?;
    if output.len() < n {
        return Err(Error::Capacity);
    }
    let mut writer = Writer {
        output: &mut output[..n],
        pos: 0,
    };
    writer.put(PREFIX);
    writer.base32(hello.peer.as_bytes());
    writer.byte(b'/');
    writer.base32(hello.signature.as_bytes());
    writer.byte(b'/');
    writer.decimal(hello.expiration.as_micros());
    let mut sep = b'?';
    for address in hello.addresses() {
        writer.byte(sep);
        writer.put(address.scheme());
        writer.byte(b'=');
        writer.body(address.body());
        sep = b'&';
    }
    core::str::from_utf8(&output[..n]).map_err(|_| Error::Malformed)
}
