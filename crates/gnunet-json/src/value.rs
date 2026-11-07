//! Borrowed claim views and bounded JSON-derived STRING attribute formatting.
use crate::parser::{self, JsonString, Kind, Token};
use core::{fmt, fmt::Write};
use gnunet_types::Error;

/// Explicit JSON text rendering policy; neither variant alters original input.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Format {
    /// Shortest round-trip reals and lowercase hexadecimal control escapes.
    #[default]
    Shortest,
    /// Jansson default dump profile:17 significant real digits, normalized
    /// exponents and uppercase hexadecimal control escapes.
    Jansson,
}

/// Actual JSON value category; no credential authenticity is implied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueKind {
    /// JSON object, with its complete nested members retained.
    Object,
    /// JSON array, with all members retained.
    Array,
    /// Decoded JSON string.
    String,
    /// Finite JSON integer/real number.
    Number,
    /// JSON true.
    True,
    /// JSON false.
    False,
    /// JSON null.
    Null,
}
/// One validated value borrowing its original decoded secret payload/workspace.
#[derive(Clone, Copy)]
pub struct Value<'a> {
    pub(crate) payload: &'a str,
    pub(crate) tokens: &'a [Token],
    pub(crate) index: usize,
}
impl<'a> Value<'a> {
    /// Category without allocating a generic recursive JSON value.
    pub fn kind(self) -> ValueKind {
        match self.tokens[self.index].kind {
            Kind::Object => ValueKind::Object,
            Kind::Array => ValueKind::Array,
            Kind::String => ValueKind::String,
            Kind::Number => ValueKind::Number,
            Kind::True => ValueKind::True,
            Kind::False => ValueKind::False,
            Kind::Null | Kind::Empty => ValueKind::Null,
        }
    }
    /// Explicit original JSON value bytes, including original escape/number form.
    pub fn expose_json(self) -> &'a [u8] {
        let t = self.tokens[self.index];
        &self.payload.as_bytes()[t.start..t.end]
    }
    /// Borrow a decoded string view, refusing all other JSON types.
    pub fn string(self) -> Result<JsonString<'a>, Error> {
        parser::string_at(self.payload, self.tokens[self.index])
    }
    /// Extract an i64 integer. A JSON real such as1.0 is not an integer claim,
    /// matching the official get_expiration json_is_integer check.
    pub fn integer(self) -> Result<i64, Error> {
        if self.tokens[self.index].kind != Kind::Number {
            return Err(Error::Malformed);
        }
        let raw = core::str::from_utf8(self.expose_json()).map_err(|_| Error::Malformed)?;
        if raw.bytes().any(|b| matches!(b, b'.' | b'e' | b'E')) {
            return Err(Error::Malformed);
        }
        raw.parse().map_err(|_| Error::Overflow)
    }
    /// Object member lookup using an exact decoded public ASCII key.
    pub fn get(self, key: &[u8]) -> Option<Self> {
        lookup(self.payload, self.tokens, self.index, key)
    }
    /// Borrow complete insertion-order object members.
    pub fn members(self) -> Result<Members<'a>, Error> {
        if self.kind() != ValueKind::Object {
            return Err(Error::Malformed);
        }
        Ok(Members {
            payload: self.payload,
            tokens: self.tokens,
            at: self.index + 1,
            end: self.tokens[self.index].next,
        })
    }
    /// Borrow complete array elements.
    pub fn elements(self) -> Result<Elements<'a>, Error> {
        if self.kind() != ValueKind::Array {
            return Err(Error::Malformed);
        }
        Ok(Elements {
            payload: self.payload,
            tokens: self.tokens,
            at: self.index + 1,
            end: self.tokens[self.index].next,
        })
    }
    /// Decode a JSON boolean, refusing implicit numeric/string coercion.
    pub fn boolean(self) -> Result<bool, Error> {
        match self.kind() {
            ValueKind::True => Ok(true),
            ValueKind::False => Ok(false),
            _ => Err(Error::Malformed),
        }
    }
    /// Required full JSON encoding using shortest finite real round-trip text.
    pub fn encoded_len(self) -> Result<usize, Error> {
        self.encoded_len_with(Format::Shortest)
    }
    /// Required complete JSON bytes under one explicit rendering policy.
    pub fn encoded_len_with(self, format: Format) -> Result<usize, Error> {
        let mut w = Output { out: None, at: 0 };
        render(self.payload, self.tokens, self.index, &mut w, 0, format)?;
        Ok(w.at)
    }
    /// Encode complete JSON after capacity preflight, unchanged on refusal.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        self.encode_with(out, Format::Shortest)
    }
    /// Encode every nested value with the selected policy after full preflight.
    /// Raw document bytes and borrowed original values remain unchanged.
    pub fn encode_with(self, out: &mut [u8], format: Format) -> Result<usize, Error> {
        let n = self.encoded_len_with(format)?;
        let out = out.get_mut(..n).ok_or(Error::Capacity)?;
        let mut w = Output {
            out: Some(out),
            at: 0,
        };
        render(self.payload, self.tokens, self.index, &mut w, 0, format)?;
        Ok(n)
    }
}
impl fmt::Debug for Value<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Value([REDACTED])")
    }
}
/// One immutable borrowed object member.
#[derive(Clone, Copy, Debug)]
pub struct Member<'a> {
    /// Decoded immutable key.
    pub name: JsonString<'a>,
    /// Original immutable value subtree.
    pub value: Value<'a>,
}
/// Exact insertion-order object-member iterator, allocating nothing.
pub struct Members<'a> {
    payload: &'a str,
    tokens: &'a [Token],
    at: usize,
    end: usize,
}
impl<'a> Iterator for Members<'a> {
    type Item = Member<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.at >= self.end {
            return None;
        }
        let name = parser::string_at(self.payload, *self.tokens.get(self.at)?).ok()?;
        let index = self.at.checked_add(1)?;
        self.at = self.tokens.get(index)?.next;
        Some(Member {
            name,
            value: Value {
                payload: self.payload,
                tokens: self.tokens,
                index,
            },
        })
    }
}
impl core::iter::FusedIterator for Members<'_> {}
/// Exact insertion-order array-element iterator, allocating nothing.
pub struct Elements<'a> {
    payload: &'a str,
    tokens: &'a [Token],
    at: usize,
    end: usize,
}
impl<'a> Iterator for Elements<'a> {
    type Item = Value<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.at >= self.end {
            return None;
        }
        let index = self.at;
        self.at = self.tokens.get(index)?.next;
        Some(Value {
            payload: self.payload,
            tokens: self.tokens,
            index,
        })
    }
}
impl core::iter::FusedIterator for Elements<'_> {}
pub(crate) fn lookup<'a>(
    payload: &'a str,
    tokens: &'a [Token],
    root: usize,
    key: &[u8],
) -> Option<Value<'a>> {
    if tokens.get(root)?.kind != Kind::Object {
        return None;
    }
    let end = tokens[root].next;
    let mut at = root + 1;
    while at < end {
        let name = parser::string_at(payload, *tokens.get(at)?).ok()?;
        let index = at.checked_add(1)?;
        if name.eq_ascii(key) {
            return Some(Value {
                payload,
                tokens,
                index,
            });
        }
        at = tokens.get(index)?.next;
    }
    None
}
struct Output<'a> {
    out: Option<&'a mut [u8]>,
    at: usize,
}
impl Output<'_> {
    fn bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self.at.checked_add(bytes.len()).ok_or(Error::Overflow)?;
        if let Some(out) = self.out.as_mut() {
            out.get_mut(self.at..end)
                .ok_or(Error::Capacity)?
                .copy_from_slice(bytes);
        }
        self.at = end;
        Ok(())
    }
}
impl fmt::Write for Output<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.bytes(s.as_bytes()).map_err(|_| fmt::Error)
    }
}
fn escaped(
    text: JsonString<'_>,
    out: &mut Output<'_>,
    quoted: bool,
    format: Format,
) -> Result<(), Error> {
    escaped_chars(text.chars(), out, quoted, format)
}
fn escaped_chars(
    chars: impl Iterator<Item = char>,
    out: &mut Output<'_>,
    quoted: bool,
    format: Format,
) -> Result<(), Error> {
    if quoted {
        out.bytes(b"\"")?;
    }
    for c in chars {
        match c {
            '"' => out.bytes(b"\\\"")?,
            '\\' => out.bytes(b"\\\\")?,
            '\u{8}' => out.bytes(b"\\b")?,
            '\u{c}' => out.bytes(b"\\f")?,
            '\n' => out.bytes(b"\\n")?,
            '\r' => out.bytes(b"\\r")?,
            '\t' => out.bytes(b"\\t")?,
            c if u32::from(c) < 0x20 => {
                let cp = u32::from(c) as u8;
                let h = match format {
                    Format::Shortest => b"0123456789abcdef",
                    Format::Jansson => b"0123456789ABCDEF",
                };
                out.bytes(&[
                    b'\\',
                    b'u',
                    b'0',
                    b'0',
                    h[usize::from(cp >> 4)],
                    h[usize::from(cp & 15)],
                ])?;
            }
            c => {
                let mut b = [0; 4];
                out.bytes(c.encode_utf8(&mut b).as_bytes())?;
            }
        }
    }
    if quoted {
        out.bytes(b"\"")?;
    }
    Ok(())
}
fn render(
    payload: &str,
    tokens: &[Token],
    index: usize,
    out: &mut Output<'_>,
    depth: usize,
    format: Format,
) -> Result<(), Error> {
    // Workspace parser admits at most64 nested containers. This explicitly
    // checked bound also caps formatter call-stack use; traversal is linear.
    if depth > 64 {
        return Err(Error::Capacity);
    }
    let token = *tokens.get(index).ok_or(Error::Malformed)?;
    match token.kind {
        Kind::Object => {
            out.bytes(b"{")?;
            let mut at = index + 1;
            let mut first = true;
            while at < token.next {
                if !first {
                    out.bytes(b", ")?;
                }
                first = false;
                escaped(parser::string_at(payload, tokens[at])?, out, true, format)?;
                out.bytes(b": ")?;
                let value = at + 1;
                render(payload, tokens, value, out, depth + 1, format)?;
                at = tokens[value].next;
            }
            out.bytes(b"}")
        }
        Kind::Array => {
            out.bytes(b"[")?;
            let mut at = index + 1;
            let mut first = true;
            while at < token.next {
                if !first {
                    out.bytes(b", ")?;
                }
                first = false;
                render(payload, tokens, at, out, depth + 1, format)?;
                at = tokens[at].next;
            }
            out.bytes(b"]")
        }
        Kind::String => escaped(parser::string_at(payload, token)?, out, true, format),
        Kind::Number => {
            let raw = payload
                .get(token.start..token.end)
                .ok_or(Error::Malformed)?;
            if raw.bytes().any(|b| matches!(b, b'.' | b'e' | b'E')) {
                let number = raw.parse::<f64>().map_err(|_| Error::Malformed)?;
                if !number.is_finite() {
                    return Err(Error::Overflow);
                }
                match format {
                    Format::Shortest => write!(out, "{number:?}").map_err(|_| Error::Overflow),
                    Format::Jansson => crate::real::write(number, |bytes| out.bytes(bytes)),
                }
            } else {
                let number = raw.parse::<i64>().map_err(|_| Error::Overflow)?;
                write!(out, "{number}").map_err(|_| Error::Overflow)
            }
        }
        Kind::True => out.bytes(b"true"),
        Kind::False => out.bytes(b"false"),
        Kind::Null => out.bytes(b"null"),
        Kind::Empty => Err(Error::Malformed),
    }
}

impl JsonString<'_> {
    /// Required escaped JSON string bytes, with optional surrounding quotes.
    pub fn encoded_len(self, quoted: bool) -> Result<usize, Error> {
        self.encoded_len_with(quoted, Format::Shortest)
    }
    /// Required escaped string bytes under the selected rendering policy.
    pub fn encoded_len_with(self, quoted: bool, format: Format) -> Result<usize, Error> {
        let mut w = Output { out: None, at: 0 };
        escaped(self, &mut w, quoted, format)?;
        Ok(w.at)
    }
    /// Encode JSON escaping after full preflight, preserving output on refusal.
    pub fn encode(self, out: &mut [u8], quoted: bool) -> Result<usize, Error> {
        self.encode_with(out, quoted, Format::Shortest)
    }
    /// Encode with one explicit hexadecimal escape policy after full preflight.
    pub fn encode_with(self, out: &mut [u8], quoted: bool, format: Format) -> Result<usize, Error> {
        let n = self.encoded_len_with(quoted, format)?;
        let out = out.get_mut(..n).ok_or(Error::Capacity)?;
        let mut w = Output {
            out: Some(out),
            at: 0,
        };
        escaped(self, &mut w, quoted, format)?;
        Ok(n)
    }
}

/// Required complete quoted JSON string bytes for caller UTF-8, allocating nothing.
pub fn string_len(input: &str) -> Result<usize, Error> {
    let mut out = Output { out: None, at: 0 };
    escaped_chars(input.chars(), &mut out, true, Format::Shortest)?;
    Ok(out.at)
}
/// Encode a complete escaped/quoted UTF-8 string after preflight. Capacity error
/// leaves output unchanged; no sensitive intermediate String/Vec is constructed.
pub fn write_string(input: &str, out: &mut [u8]) -> Result<usize, Error> {
    let n = string_len(input)?;
    let out = out.get_mut(..n).ok_or(Error::Capacity)?;
    let mut writer = Output {
        out: Some(out),
        at: 0,
    };
    escaped_chars(input.chars(), &mut writer, true, Format::Shortest)?;
    Ok(n)
}
