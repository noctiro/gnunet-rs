use gnunet_types::Error;
const BASE32: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const HEX: &[u8; 16] = b"0123456789ABCDEF";

pub(crate) fn base32<const N: usize>(input: &[u8]) -> Result<[u8; N], Error> {
    if input.len() != N.checked_mul(8).ok_or(Error::Overflow)?.div_ceil(5) {
        return Err(Error::Malformed);
    }
    let mut output = [0; N];
    let mut bits = 0_u16;
    let mut available = 0;
    let mut position = 0;
    for byte in input {
        let canonical = match byte.to_ascii_uppercase() {
            b'O' => b'0',
            b'I' | b'L' => b'1',
            b'U' => b'V',
            b => b,
        };
        let digit = BASE32
            .iter()
            .position(|b| *b == canonical)
            .ok_or(Error::Malformed)?;
        bits = ((bits & ((1 << available) - 1)) << 5) | digit as u16;
        available += 5;
        if available >= 8 {
            available -= 8;
            *output.get_mut(position).ok_or(Error::Malformed)? = (bits >> available) as u8;
            position += 1;
        }
    }
    // GNUnet ignores the unused low bits in the final Crockford digit.
    Ok(output)
}

pub(crate) fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

pub(crate) fn decimal(input: &[u8]) -> Result<u64, Error> {
    let mut p = 0;
    while input.get(p).is_some_and(|b| matches!(*b, 9..=13 | 32)) {
        p += 1;
    }
    let negative = input.get(p) == Some(&b'-');
    if negative || input.get(p) == Some(&b'+') {
        p += 1;
    }
    let first = p;
    let mut value = 0_u64;
    let mut overflow = false;
    while let Some(b) = input.get(p).filter(|b| b.is_ascii_digit()) {
        if let Some(next) = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(*b - b'0')))
        {
            value = next;
        } else {
            overflow = true;
        }
        p += 1;
    }
    if p == first {
        return Err(Error::Malformed);
    }
    // The pinned parser uses unsigned scanf: suffixes are ignored, a negative
    // in-range value wraps, and a decimal overflow saturates at ULLONG_MAX.
    Ok(if overflow {
        u64::MAX
    } else if negative {
        value.wrapping_neg()
    } else {
        value
    })
}

pub(crate) const fn decimal_len(mut value: u64) -> usize {
    let mut n = 1;
    while value >= 10 {
        value /= 10;
        n += 1;
    }
    n
}

pub(crate) fn plain(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
}

pub(crate) struct Writer<'a> {
    out: &'a mut [u8],
    position: usize,
}
impl<'a> Writer<'a> {
    pub(crate) fn new(out: &'a mut [u8]) -> Self {
        Self { out, position: 0 }
    }
    pub(crate) fn put(&mut self, bytes: &[u8]) {
        let end = self.position + bytes.len();
        self.out[self.position..end].copy_from_slice(bytes);
        self.position = end;
    }
    pub(crate) fn byte(&mut self, byte: u8) {
        self.out[self.position] = byte;
        self.position += 1;
    }
    pub(crate) fn encoded(&mut self, bytes: &[u8]) {
        let mut bits = 0_u16;
        let mut available = 0;
        for byte in bytes {
            bits = ((bits & ((1 << available) - 1)) << 8) | u16::from(*byte);
            available += 8;
            while available >= 5 {
                available -= 5;
                self.byte(BASE32[usize::from((bits >> available) & 31)]);
            }
        }
        if available != 0 {
            self.byte(BASE32[usize::from((bits << (5 - available)) & 31)]);
        }
    }
    pub(crate) fn decimal(&mut self, mut value: u64) {
        let mut bytes = [0; 20];
        let mut p = bytes.len();
        loop {
            p -= 1;
            bytes[p] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        self.put(&bytes[p..]);
    }
    pub(crate) fn escaped(&mut self, byte: u8) {
        if plain(byte) {
            self.byte(byte);
        } else {
            self.byte(b'%');
            self.byte(HEX[usize::from(byte >> 4)]);
            self.byte(HEX[usize::from(byte & 15)]);
        }
    }
}
