use crate::Error;
use core::fmt;
pub(crate) struct Writer<'a> {
    out: &'a mut [u8],
    at: usize,
}
impl<'a> Writer<'a> {
    pub fn new(out: &'a mut [u8]) -> Self {
        Self { out, at: 0 }
    }
    pub fn len(&self) -> usize {
        self.at
    }
    pub fn tail(&mut self) -> &mut [u8] {
        &mut self.out[self.at..]
    }
    pub fn fixed(&mut self, n: usize) -> Result<&mut [u8], Error> {
        let start = self.at;
        self.advance(n)?;
        let out = &mut self.out[start..self.at];
        out.fill(0);
        Ok(out)
    }
    pub fn advance(&mut self, n: usize) -> Result<(), Error> {
        self.at = self
            .at
            .checked_add(n)
            .filter(|n| *n <= self.out.len())
            .ok_or(Error::Capacity)?;
        Ok(())
    }
    pub fn bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self.at.checked_add(bytes.len()).ok_or(Error::Overflow)?;
        self.out
            .get_mut(self.at..end)
            .ok_or(Error::Capacity)?
            .copy_from_slice(bytes);
        self.at = end;
        Ok(())
    }
    pub fn byte(&mut self, byte: u8) -> Result<(), Error> {
        self.bytes(&[byte])
    }
    pub fn number(&mut self, mut value: u64) -> Result<(), Error> {
        let mut tmp = [0; 20];
        let mut start = tmp.len();
        loop {
            start -= 1;
            tmp[start] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        self.bytes(&tmp[start..])
    }
    pub fn b32(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let n = gnunet_gnsrecord::encode_base32(bytes, self.tail())?;
        self.advance(n)
    }
    pub fn hex(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let n = gnunet_dns::encode_hex_lower(bytes, self.tail())?;
        self.advance(n)
    }
}
impl fmt::Write for Writer<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.bytes(s.as_bytes()).map_err(|_| fmt::Error)
    }
}
pub(crate) struct Fields<'a> {
    rest: &'a str,
}
impl<'a> Fields<'a> {
    pub fn new(text: &'a str) -> Self {
        Self { rest: text }
    }
    pub fn next(&mut self) -> Result<&'a str, Error> {
        let s = self
            .rest
            .trim_start_matches(|c: char| c.is_ascii_whitespace());
        if s.is_empty() {
            return Err(Error::Malformed);
        }
        let end = s.find(|c: char| c.is_ascii_whitespace()).unwrap_or(s.len());
        self.rest = &s[end..];
        Ok(&s[..end])
    }
    pub fn rest(&self) -> &'a str {
        self.rest
            .trim_start_matches(|c: char| c.is_ascii_whitespace())
    }
    pub fn end(&self) -> Result<(), Error> {
        if self.rest().is_empty() {
            Ok(())
        } else {
            Err(Error::Malformed)
        }
    }
    pub fn number(&mut self, maximum: u64) -> Result<u64, Error> {
        number(self.next()?, maximum)
    }
    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.number(u8::MAX.into())? as u8)
    }
    pub fn u16(&mut self) -> Result<u16, Error> {
        Ok(self.number(u16::MAX.into())? as u16)
    }
    pub fn u32(&mut self) -> Result<u32, Error> {
        Ok(self.number(u32::MAX.into())? as u32)
    }
}
pub(crate) fn number(text: &str, maximum: u64) -> Result<u64, Error> {
    let text = text.strip_prefix('+').unwrap_or(text);
    if text.is_empty() {
        return Err(Error::Malformed);
    }
    let mut value = 0u64;
    for b in text.bytes() {
        if !b.is_ascii_digit() {
            return Err(Error::Malformed);
        }
        value = value
            .checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(b - b'0')))
            .filter(|n| *n <= maximum)
            .ok_or(Error::Malformed)?;
    }
    Ok(value)
}
pub(crate) fn u16_at(bytes: &[u8], at: usize) -> Result<u16, Error> {
    Ok(u16::from_be_bytes(
        bytes
            .get(at..at + 2)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}
pub(crate) fn u32_at(bytes: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(
        bytes
            .get(at..at + 4)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}
pub(crate) fn cstr(bytes: &[u8]) -> &[u8] {
    bytes.split(|b| *b == 0).next().unwrap_or(&[])
}
pub(crate) fn terminated(bytes: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let at = bytes.iter().position(|b| *b == 0).ok_or(Error::Malformed)?;
    Ok((&bytes[..at], &bytes[at + 1..]))
}
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
pub(crate) fn encode_b64(data: &[u8], out: &mut Writer<'_>) -> Result<(), Error> {
    for part in data.chunks(3) {
        let a = part[0];
        let b = part.get(1).copied().unwrap_or(0);
        let c = part.get(2).copied().unwrap_or(0);
        out.bytes(&[
            B64[usize::from(a >> 2)],
            B64[usize::from(((a & 3) << 4) | (b >> 4))],
            if part.len() > 1 {
                B64[usize::from(((b & 15) << 2) | (c >> 6))]
            } else {
                b'='
            },
            if part.len() > 2 {
                B64[usize::from(c & 63)]
            } else {
                b'='
            },
        ])?;
    }
    Ok(())
}
fn b64_digit(byte: u8) -> Result<u8, Error> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(Error::Malformed),
    }
}
pub(crate) fn decode_b64(text: &str, out: &mut Writer<'_>) -> Result<(), Error> {
    let raw = text.trim_end_matches('=');
    let padding = text.len() - raw.len();
    if raw.len() % 4 == 1
        || padding > 2
        || (padding > 0 && (!text.len().is_multiple_of(4) || padding != 4 - raw.len() % 4))
    {
        return Err(Error::Malformed);
    }
    let mut bits = 0u16;
    let mut count = 0u32;
    for b in raw.bytes() {
        bits = ((bits & ((1u16 << count) - 1)) << 6) | u16::from(b64_digit(b)?);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.byte((bits >> count) as u8)?;
        }
    }
    Ok(())
}
