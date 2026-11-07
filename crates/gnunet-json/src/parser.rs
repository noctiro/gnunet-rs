//! Bounded private JSON workspace. No recursively allocated Value or unerasable
//! JSON parser scratch is created for sensitive credentials.
use core::fmt;
use gnunet_types::Error;
use zeroize::Zeroize;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Kind {
    Empty,
    Object,
    Array,
    String,
    Number,
    True,
    False,
    Null,
}
/// Caller-owned JSON metadata slot, containing offsets only and redacted Debug.
#[derive(Clone, Copy)]
pub struct Token {
    pub(crate) kind: Kind,
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) next: usize,
}
impl Token {
    /// Empty reusable metadata slot.
    pub const EMPTY: Self = Self {
        kind: Kind::Empty,
        start: 0,
        end: 0,
        next: 0,
    };
}
impl Zeroize for Token {
    fn zeroize(&mut self) {
        self.kind = Kind::Empty;
        self.start.zeroize();
        self.end.zeroize();
        self.next.zeroize();
    }
}
impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token([REDACTED])")
    }
}
/// Caller-owned explicit JSON nesting slot. Nesting never uses parser recursion.
#[derive(Clone, Copy)]
pub struct Nest {
    token: usize,
    state: u8,
}
impl Nest {
    /// Empty reusable nesting slot.
    pub const EMPTY: Self = Self { token: 0, state: 0 };
}
impl Zeroize for Nest {
    fn zeroize(&mut self) {
        self.token.zeroize();
        self.state.zeroize();
    }
}
impl fmt::Debug for Nest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Nest([REDACTED])")
    }
}
struct Parser<'a> {
    b: &'a [u8],
    text: &'a str,
    tokens: &'a mut [Token],
    stack: &'a mut [Nest],
    at: usize,
    count: usize,
    depth: usize,
    work: usize,
}
impl Parser<'_> {
    fn tick(&mut self, n: usize) -> Result<(), Error> {
        self.work = self.work.checked_sub(n).ok_or(Error::Capacity)?;
        Ok(())
    }
    fn ws(&mut self) -> Result<(), Error> {
        while self
            .b
            .get(self.at)
            .is_some_and(|b| matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.tick(1)?;
            self.at += 1;
        }
        Ok(())
    }
    fn token(&mut self, kind: Kind, start: usize, end: usize) -> Result<usize, Error> {
        self.tick(1)?;
        let n = self.count;
        let slot = self.tokens.get_mut(n).ok_or(Error::Capacity)?;
        *slot = Token {
            kind,
            start,
            end,
            next: n + 1,
        };
        self.count = n + 1;
        Ok(n)
    }
    fn string(&mut self) -> Result<usize, Error> {
        let start = self.at;
        self.at += 1;
        loop {
            self.tick(1)?;
            let b = *self.b.get(self.at).ok_or(Error::Malformed)?;
            if b == b'"' {
                self.at += 1;
                break;
            }
            if b == b'\\' {
                self.at += 1;
                let e = *self.b.get(self.at).ok_or(Error::Malformed)?;
                self.at += 1;
                match e {
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {}
                    b'u' => {
                        let cp = hex4(self.b, self.at)?;
                        self.at += 4;
                        if (0xd800..=0xdbff).contains(&cp) {
                            if self.b.get(self.at..self.at + 2) != Some(b"\\u") {
                                return Err(Error::Malformed);
                            }
                            self.at += 2;
                            let low = hex4(self.b, self.at)?;
                            self.at += 4;
                            if !(0xdc00..=0xdfff).contains(&low) {
                                return Err(Error::Malformed);
                            }
                        } else if cp == 0 || (0xdc00..=0xdfff).contains(&cp) {
                            return Err(Error::Malformed);
                        }
                    }
                    _ => return Err(Error::Malformed),
                }
            } else {
                if b < 0x20 {
                    return Err(Error::Malformed);
                }
                self.at += 1;
            }
        }
        self.token(Kind::String, start, self.at)
    }
    fn number(&mut self) -> Result<usize, Error> {
        let start = self.at;
        if self.b.get(self.at) == Some(&b'-') {
            self.at += 1;
        }
        match self.b.get(self.at) {
            Some(b'0') => self.at += 1,
            Some(b'1'..=b'9') => {
                self.at += 1;
                while self.b.get(self.at).is_some_and(u8::is_ascii_digit) {
                    self.at += 1;
                }
            }
            _ => return Err(Error::Malformed),
        }
        if self.b.get(self.at) == Some(&b'.') {
            self.at += 1;
            let first = self.at;
            while self.b.get(self.at).is_some_and(u8::is_ascii_digit) {
                self.at += 1;
            }
            if first == self.at {
                return Err(Error::Malformed);
            }
        }
        if self
            .b
            .get(self.at)
            .is_some_and(|b| matches!(b, b'e' | b'E'))
        {
            self.at += 1;
            if self
                .b
                .get(self.at)
                .is_some_and(|b| matches!(b, b'+' | b'-'))
            {
                self.at += 1;
            }
            let first = self.at;
            while self.b.get(self.at).is_some_and(u8::is_ascii_digit) {
                self.at += 1;
            }
            if first == self.at {
                return Err(Error::Malformed);
            }
        }
        self.tick(self.at - start)?;
        let raw = core::str::from_utf8(&self.b[start..self.at]).map_err(|_| Error::Malformed)?;
        if raw.bytes().any(|b| matches!(b, b'.' | b'e' | b'E')) {
            if !raw
                .parse::<f64>()
                .map_err(|_| Error::Malformed)?
                .is_finite()
            {
                return Err(Error::Overflow);
            }
        } else {
            raw.parse::<i64>().map_err(|_| Error::Overflow)?;
        }
        self.token(Kind::Number, start, self.at)
    }
    fn value(&mut self) -> Result<(), Error> {
        self.ws()?;
        let start = self.at;
        match self.b.get(self.at) {
            Some(b'{') | Some(b'[') => {
                let object = self.b[self.at] == b'{';
                self.at += 1;
                let token =
                    self.token(if object { Kind::Object } else { Kind::Array }, start, 0)?;
                let frame = self.stack.get_mut(self.depth).ok_or(Error::Capacity)?;
                *frame = Nest {
                    token,
                    state: if object { 0 } else { 5 },
                };
                self.depth += 1;
            }
            Some(b'"') => {
                self.string()?;
            }
            Some(b'-' | b'0'..=b'9') => {
                self.number()?;
            }
            Some(b't') => self.literal(b"true", Kind::True)?,
            Some(b'f') => self.literal(b"false", Kind::False)?,
            Some(b'n') => self.literal(b"null", Kind::Null)?,
            _ => return Err(Error::Malformed),
        }
        Ok(())
    }
    fn literal(&mut self, raw: &[u8], kind: Kind) -> Result<(), Error> {
        let end = self.at.checked_add(raw.len()).ok_or(Error::Overflow)?;
        if self.b.get(self.at..end) != Some(raw) {
            return Err(Error::Malformed);
        }
        self.token(kind, self.at, end)?;
        self.at = end;
        Ok(())
    }
    fn close(&mut self) -> Result<(), Error> {
        self.at += 1;
        self.depth -= 1;
        let frame = self.stack[self.depth];
        let token = self.tokens.get_mut(frame.token).ok_or(Error::Malformed)?;
        token.end = self.at;
        token.next = self.count;
        Ok(())
    }
    fn duplicate(&mut self, object: usize, key: usize) -> Result<(), Error> {
        let current = string_at(self.text, self.tokens[key])?;
        let mut i = object + 1;
        while i < key {
            self.tick(1)?;
            let old = string_at(self.text, self.tokens[i])?;
            let mut a = current.chars();
            let mut b = old.chars();
            let same = loop {
                self.tick(1)?;
                match (a.next(), b.next()) {
                    (None, None) => break true,
                    (Some(a), Some(b)) if a == b => {}
                    _ => break false,
                }
            };
            if same {
                return Err(Error::Conflict);
            }
            i = self.tokens.get(i + 1).ok_or(Error::Malformed)?.next;
        }
        Ok(())
    }
    fn run(&mut self) -> Result<usize, Error> {
        self.value()?;
        while self.depth != 0 {
            self.tick(1)?;
            self.ws()?;
            let d = self.depth - 1;
            let frame = self.stack[d];
            match frame.state {
                0 | 1 => {
                    if self.b.get(self.at) == Some(&b'}') && frame.state == 0 {
                        self.close()?;
                        continue;
                    }
                    if self.b.get(self.at) != Some(&b'"') {
                        return Err(Error::Malformed);
                    }
                    let key = self.string()?;
                    self.duplicate(frame.token, key)?;
                    self.stack[d].state = 2;
                }
                2 => {
                    if self.b.get(self.at) != Some(&b':') {
                        return Err(Error::Malformed);
                    }
                    self.at += 1;
                    self.stack[d].state = 3;
                }
                3 => {
                    self.stack[d].state = 4;
                    self.value()?;
                }
                4 => match self.b.get(self.at) {
                    Some(b',') => {
                        self.at += 1;
                        self.stack[d].state = 1;
                    }
                    Some(b'}') => self.close()?,
                    _ => return Err(Error::Malformed),
                },
                5 | 6 => {
                    if self.b.get(self.at) == Some(&b']') && frame.state == 5 {
                        self.close()?;
                        continue;
                    }
                    self.stack[d].state = 7;
                    self.value()?;
                }
                7 => match self.b.get(self.at) {
                    Some(b',') => {
                        self.at += 1;
                        self.stack[d].state = 6;
                    }
                    Some(b']') => self.close()?,
                    _ => return Err(Error::Malformed),
                },
                _ => return Err(Error::Malformed),
            }
        }
        self.ws()?;
        if self.at != self.b.len() {
            return Err(Error::Malformed);
        }
        Ok(self.count)
    }
}
pub(crate) fn parse(
    bytes: &[u8],
    tokens: &mut [Token],
    stack: &mut [Nest],
    work: usize,
) -> Result<usize, Error> {
    let text = core::str::from_utf8(bytes).map_err(|_| Error::Malformed)?;
    Parser {
        b: bytes,
        text,
        tokens,
        stack,
        at: 0,
        count: 0,
        depth: 0,
        work,
    }
    .run()
}
fn hex4(b: &[u8], at: usize) -> Result<u32, Error> {
    let b = b.get(at..at + 4).ok_or(Error::Malformed)?;
    let mut n = 0u32;
    for b in b {
        n = (n << 4)
            | u32::from(match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return Err(Error::Malformed),
            });
    }
    Ok(n)
}
/// Validated borrowed JSON string. Explicit decode methods preserve its owner.
#[derive(Clone, Copy)]
pub struct JsonString<'a> {
    raw: &'a str,
}
impl<'a> JsonString<'a> {
    /// Decoded Unicode scalar iterator, with no allocation or normalization.
    pub fn chars(self) -> Chars<'a> {
        Chars {
            raw: self.raw,
            at: 0,
        }
    }
    /// Compare decoded bytes with a public ASCII field name.
    pub fn eq_ascii(self, ascii: &[u8]) -> bool {
        self.chars().eq(ascii.iter().map(|b| char::from(*b)))
    }
    /// Required UTF-8 bytes after JSON unescaping.
    pub fn decoded_len(self) -> Result<usize, Error> {
        self.chars().try_fold(0usize, |n, c| {
            n.checked_add(c.len_utf8()).ok_or(Error::Overflow)
        })
    }
    /// Decode in caller-owned storage, unchanged on insufficient capacity.
    pub fn decode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.decoded_len()?;
        let out = out.get_mut(..n).ok_or(Error::Capacity)?;
        let mut at = 0;
        for c in self.chars() {
            let mut b = [0; 4];
            let s = c.encode_utf8(&mut b).as_bytes();
            out[at..at + s.len()].copy_from_slice(s);
            at += s.len();
        }
        Ok(n)
    }
}
impl fmt::Debug for JsonString<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JsonString([REDACTED])")
    }
}
/// No-allocation iterator over validated/unescaped scalar values.
pub struct Chars<'a> {
    raw: &'a str,
    at: usize,
}
impl Iterator for Chars<'_> {
    type Item = char;
    fn next(&mut self) -> Option<char> {
        let b = *self.raw.as_bytes().get(self.at)?;
        if b != b'\\' {
            let c = self.raw.get(self.at..)?.chars().next()?;
            self.at += c.len_utf8();
            return Some(c);
        }
        self.at += 2;
        let c = match *self.raw.as_bytes().get(self.at - 1)? {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let high = hex4(self.raw.as_bytes(), self.at).ok()?;
                self.at += 4;
                let cp = if (0xd800..=0xdbff).contains(&high) {
                    self.at += 2;
                    let low = hex4(self.raw.as_bytes(), self.at).ok()?;
                    self.at += 4;
                    0x10000 + ((high - 0xd800) << 10) + (low - 0xdc00)
                } else {
                    high
                };
                char::from_u32(cp)?
            }
            _ => return None,
        };
        Some(c)
    }
}
pub(crate) fn string_at(bytes: &str, token: Token) -> Result<JsonString<'_>, Error> {
    if token.kind != Kind::String || token.end <= token.start + 1 {
        return Err(Error::Malformed);
    }
    Ok(JsonString {
        raw: bytes
            .get(token.start + 1..token.end - 1)
            .ok_or(Error::Malformed)?,
    })
}
