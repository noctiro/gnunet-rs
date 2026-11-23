//! Borrowed PDF object syntax over an explicitly bounded byte range.

use std::borrow::Cow;

const MAX_NESTING: u8 = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ParseError {
    Incomplete,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct ObjectId {
    pub number: u32,
    pub generation: u16,
}

#[derive(Clone, Copy)]
pub(super) enum Value<'a> {
    Unsigned(u64),
    Signed(i64),
    Boolean(bool),
    Name(Name<'a>),
    Array(Array<'a>),
    Dict(Dict<'a>),
    Reference(ObjectId),
    String(PdfString<'a>),
    Null,
    Other,
}

#[derive(Clone, Copy)]
pub(super) struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
    complete: bool,
}

impl<'a> Cursor<'a> {
    /// The caller can append bytes if a token meets the end of the window.
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            position: 0,
            complete: false,
        }
    }

    /// The supplied extent ends at a known token boundary.
    pub(super) const fn complete(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            position: 0,
            complete: true,
        }
    }

    pub(super) const fn position(&self) -> usize {
        self.position
    }

    pub(super) fn take_keyword(&mut self, expected: &[u8]) -> Result<(), ParseError> {
        self.skip_trivia();
        let remaining = &self.bytes[self.position..];
        if !remaining.starts_with(expected) {
            return if !self.complete && expected.starts_with(remaining) {
                Err(ParseError::Incomplete)
            } else {
                Err(ParseError::Invalid)
            };
        }
        match remaining.get(expected.len()).copied() {
            Some(byte) if !is_boundary(byte) => return Err(ParseError::Invalid),
            None if !self.complete => return Err(ParseError::Incomplete),
            _ => (),
        }
        self.position += expected.len();
        Ok(())
    }

    pub(super) fn unsigned(&mut self) -> Result<u64, ParseError> {
        let word = self.word()?;
        match number(word)? {
            Some(Integer::Unsigned(value)) => Ok(value),
            _ => Err(ParseError::Invalid),
        }
    }

    pub(super) fn value(&mut self) -> Result<Value<'a>, ParseError> {
        self.object(0)
    }

    pub(super) fn one_value(mut self) -> Result<Value<'a>, ParseError> {
        let value = self.value()?;
        self.finish()?;
        Ok(value)
    }

    pub(super) fn finish(mut self) -> Result<(), ParseError> {
        self.skip_trivia();
        if self.position != self.bytes.len() {
            return Err(ParseError::Invalid);
        }
        Ok(())
    }

    fn object(&mut self, depth: u8) -> Result<Value<'a>, ParseError> {
        self.skip_trivia();
        let Some(byte) = self.peek() else {
            return Err(self.end());
        };
        match byte {
            b'/' => self.name().map(Value::Name),
            b'(' => self.string(StringKind::Literal).map(Value::String),
            b'[' => self.compound(depth, false),
            b'<' => match self.bytes.get(self.position + 1) {
                Some(b'<') => self.compound(depth, true),
                Some(_) => self.string(StringKind::Hex).map(Value::String),
                None => Err(self.end()),
            },
            _ => match self.word()? {
                b"null" => Ok(Value::Null),
                b"true" => Ok(Value::Boolean(true)),
                b"false" => Ok(Value::Boolean(false)),
                token => match number(token)? {
                    Some(Integer::Unsigned(value)) => self.integer_or_reference(value),
                    Some(Integer::Signed(value)) => Ok(Value::Signed(value)),
                    None => Ok(Value::Other),
                },
            },
        }
    }

    fn integer_or_reference(&mut self, number: u64) -> Result<Value<'a>, ParseError> {
        let Ok(object) = u32::try_from(number) else {
            return Ok(Value::Unsigned(number));
        };
        let mut lookahead = *self;
        let result = lookahead.unsigned().and_then(|generation| {
            let generation = u16::try_from(generation).map_err(|_| ParseError::Invalid)?;
            lookahead.take_keyword(b"R")?;
            Ok(generation)
        });
        match result {
            Ok(generation) => {
                *self = lookahead;
                Ok(Value::Reference(ObjectId {
                    number: object,
                    generation,
                }))
            }
            Err(ParseError::Invalid) => Ok(Value::Unsigned(number)),
            Err(ParseError::Incomplete) => Err(ParseError::Incomplete),
        }
    }

    fn compound(&mut self, depth: u8, dictionary: bool) -> Result<Value<'a>, ParseError> {
        if depth == MAX_NESTING {
            return Err(ParseError::Invalid);
        }
        self.position += if dictionary { 2 } else { 1 };
        let start = self.position;
        loop {
            self.skip_trivia();
            let end = self.position;
            match (dictionary, self.peek()) {
                (_, None) => return Err(self.end()),
                (true, Some(b'>')) => {
                    self.position += 1;
                    match self.peek() {
                        Some(b'>') => self.position += 1,
                        Some(_) => return Err(ParseError::Invalid),
                        None => return Err(self.end()),
                    }
                    return Ok(Value::Dict(Dict(&self.bytes[start..end])));
                }
                (false, Some(b']')) => {
                    self.position += 1;
                    return Ok(Value::Array(Array(&self.bytes[start..end])));
                }
                _ => (),
            }
            if dictionary {
                self.name()?;
            }
            self.object(depth + 1)?;
        }
    }

    fn name(&mut self) -> Result<Name<'a>, ParseError> {
        self.skip_trivia();
        match self.peek() {
            Some(b'/') => self.position += 1,
            Some(_) => return Err(ParseError::Invalid),
            None => return Err(self.end()),
        }
        let name = Name(self.regular_bytes()?);
        if name.decoded().any(|byte| byte.is_none_or(|byte| byte == 0)) {
            return Err(ParseError::Invalid);
        }
        Ok(name)
    }

    fn string(&mut self, kind: StringKind) -> Result<PdfString<'a>, ParseError> {
        self.position += 1;
        let start = self.position;
        let mut level = 0_usize;
        while let Some(byte) = self.peek() {
            self.position += 1;
            match (kind, byte) {
                (StringKind::Literal, b'\\') => {
                    if self.peek().is_none() {
                        return Err(self.end());
                    }
                    self.position += 1;
                }
                (StringKind::Literal, b'(') => level += 1,
                (StringKind::Literal, b')') if level != 0 => level -= 1,
                (StringKind::Literal, b')') | (StringKind::Hex, b'>') => {
                    return Ok(PdfString {
                        data: &self.bytes[start..self.position - 1],
                        kind,
                    });
                }
                (StringKind::Hex, byte) if !is_space(byte) && hex(byte).is_none() => {
                    return Err(ParseError::Invalid);
                }
                _ => (),
            }
        }
        Err(self.end())
    }

    fn word(&mut self) -> Result<&'a [u8], ParseError> {
        self.skip_trivia();
        let word = self.regular_bytes()?;
        if word.is_empty() {
            Err(ParseError::Invalid)
        } else {
            Ok(word)
        }
    }

    fn regular_bytes(&mut self) -> Result<&'a [u8], ParseError> {
        let start = self.position;
        while self.peek().is_some_and(|byte| !is_boundary(byte)) {
            self.position += 1;
        }
        if self.peek().is_none() && !self.complete {
            return Err(ParseError::Incomplete);
        }
        Ok(&self.bytes[start..self.position])
    }

    fn skip_trivia(&mut self) {
        loop {
            match self.peek() {
                Some(byte) if is_space(byte) => self.position += 1,
                Some(b'%') => {
                    while self
                        .peek()
                        .is_some_and(|byte| !matches!(byte, b'\r' | b'\n'))
                    {
                        self.position += 1;
                    }
                }
                _ => return,
            }
        }
    }

    fn peek(self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    const fn end(self) -> ParseError {
        if self.complete {
            ParseError::Invalid
        } else {
            ParseError::Incomplete
        }
    }
}

enum Integer {
    Unsigned(u64),
    Signed(i64),
}

fn number(word: &[u8]) -> Result<Option<Integer>, ParseError> {
    let (negative, digits) = match word {
        [b'-', rest @ ..] => (true, rest),
        [b'+', rest @ ..] => (false, rest),
        rest => (false, rest),
    };
    let mut value = Some(0_u64);
    let mut has_digit = false;
    let mut decimal = false;
    for &digit in digits {
        match digit {
            b'0'..=b'9' => {
                has_digit = true;
                value = value.and_then(|n| n.checked_mul(10)?.checked_add(u64::from(digit - b'0')));
            }
            b'.' if !decimal => decimal = true,
            _ => return Err(ParseError::Invalid),
        }
    }
    if !has_digit {
        return Err(ParseError::Invalid);
    }
    Ok(value.filter(|_| !decimal).and_then(|magnitude| {
        if negative && magnitude != 0 {
            i64::try_from(-i128::from(magnitude))
                .ok()
                .map(Integer::Signed)
        } else {
            Some(Integer::Unsigned(magnitude))
        }
    }))
}

#[derive(Clone, Copy)]
pub(super) struct Name<'a>(&'a [u8]);

impl Name<'_> {
    pub(super) fn bytes(self, limit: usize) -> Option<Box<[u8]>> {
        let bytes = self
            .decoded()
            .take(limit.saturating_add(1))
            .collect::<Option<Vec<_>>>()?;
        (bytes.len() <= limit).then(|| bytes.into_boxed_slice())
    }
    pub(super) fn is(self, decoded: &[u8]) -> bool {
        self.decoded().eq(decoded.iter().copied().map(Some))
    }

    fn decoded(self) -> impl Iterator<Item = Option<u8>> {
        let mut bytes = self.0.iter().copied();
        std::iter::from_fn(move || {
            Some(match bytes.next()? {
                b'#' => bytes
                    .next()
                    .and_then(hex)
                    .zip(bytes.next().and_then(hex))
                    .map(|(high, low)| (high << 4) | low),
                byte => Some(byte),
            })
        })
    }
}

#[derive(Clone, Copy)]
pub(super) struct Dict<'a>(&'a [u8]);

impl<'a> Dict<'a> {
    pub(super) fn unique(self, key: &[u8]) -> Result<Option<Value<'a>>, ParseError> {
        let mut matching = self.entries().filter(|(name, _)| name.is(key));
        let first = matching.next().map(|(_, value)| value);
        if matching.next().is_some() {
            return Err(ParseError::Invalid);
        }
        Ok(first)
    }

    pub(super) fn entries(self) -> impl Iterator<Item = (Name<'a>, Value<'a>)> {
        let mut cursor = Cursor::complete(self.0);
        std::iter::from_fn(move || Some((cursor.name().ok()?, cursor.value().ok()?)))
    }
}

#[derive(Clone, Copy)]
pub(super) struct Array<'a>(&'a [u8]);

impl<'a> Array<'a> {
    pub(super) fn values(self) -> impl Iterator<Item = Value<'a>> {
        let mut cursor = Cursor::complete(self.0);
        std::iter::from_fn(move || cursor.value().ok())
    }
}

#[derive(Clone, Copy)]
enum StringKind {
    Literal,
    Hex,
}

#[derive(Clone, Copy)]
pub(super) struct PdfString<'a> {
    data: &'a [u8],
    kind: StringKind,
}

impl<'a> PdfString<'a> {
    pub(super) fn bytes(self, limit: usize) -> Option<Cow<'a, [u8]>> {
        if matches!(self.kind, StringKind::Literal)
            && !self.data.iter().any(|&byte| matches!(byte, b'\\' | b'\r'))
        {
            return (self.data.len() <= limit).then_some(Cow::Borrowed(self.data));
        }
        let mut decoded = Vec::new();
        match self.kind {
            StringKind::Literal => {
                let mut source = self.data.iter().copied().peekable();
                while let Some(byte) = source.next() {
                    let byte = match byte {
                        b'\r' => {
                            source.next_if_eq(&b'\n');
                            b'\n'
                        }
                        b'\\' => match source.next()? {
                            b'\r' => {
                                source.next_if_eq(&b'\n');
                                continue;
                            }
                            b'\n' => continue,
                            b'n' => b'\n',
                            b'r' => b'\r',
                            b't' => b'\t',
                            b'b' => 8,
                            b'f' => 12,
                            digit @ b'0'..=b'7' => {
                                let mut value = digit - b'0';
                                for _ in 0..2 {
                                    let Some(next) = source.next_if(|d| matches!(d, b'0'..=b'7'))
                                    else {
                                        break;
                                    };
                                    value = (value << 3) | (next - b'0');
                                }
                                value
                            }
                            byte => byte,
                        },
                        byte => byte,
                    };
                    if decoded.len() == limit {
                        return None;
                    }
                    decoded.push(byte);
                }
            }
            StringKind::Hex => {
                let mut digits = self.data.iter().copied().filter_map(hex);
                while let Some(high) = digits.next() {
                    if decoded.len() == limit {
                        return None;
                    }
                    decoded.push((high << 4) | digits.next().unwrap_or(0));
                }
            }
        }
        Some(Cow::Owned(decoded))
    }
}

pub(super) const fn is_space(byte: u8) -> bool {
    matches!(byte, 0 | b'\t' | b'\n' | 12 | b'\r' | b' ')
}

const fn is_boundary(byte: u8) -> bool {
    is_space(byte)
        || matches!(
            byte,
            b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
        )
}

pub(super) const fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_references_keep_their_object_boundaries() -> Result<(), &'static str> {
        let mut cursor = Cursor::new(b"<<%comment\r/A#42 [11 12 0 R false null 4.2] >>stream\n");
        let Ok(Value::Dict(dict)) = cursor.value() else {
            return Err("expected a dictionary");
        };
        let Ok(Some(Value::Array(array))) = dict.unique(b"AB") else {
            return Err("expected an array under the escaped name");
        };
        let values = array.values().collect::<Vec<_>>();
        if !matches!(
            values.as_slice(),
            [
                Value::Unsigned(11),
                Value::Reference(ObjectId {
                    number: 12,
                    generation: 0
                }),
                Value::Boolean(false),
                Value::Null,
                Value::Other
            ]
        ) {
            return Err("unexpected values in the array");
        }
        cursor
            .take_keyword(b"stream")
            .map_err(|_| "expected a stream keyword")
    }

    #[test]
    fn string_decoding_preserves_lexical_escapes_and_caps_output() -> Result<(), &'static str> {
        for (input, expected) in [
            (
                b"(a\\053(b)\\)c\r\nd\\\r\ne\\x)".as_slice(),
                b"a+(b))c\ndex".as_slice(),
            ),
            (b"<41 424 >".as_slice(), b"AB@".as_slice()),
        ] {
            let Ok(Value::String(value)) = Cursor::complete(input).value() else {
                return Err("expected a string");
            };
            if value.bytes(expected.len()).as_deref() != Some(expected) {
                return Err("unexpected decoded string");
            }
            if value.bytes(expected.len() - 1).is_some() {
                return Err("decoded string exceeded the byte limit");
            }
        }
        Ok(())
    }

    #[test]
    fn growing_windows_distinguish_partial_tokens_from_malformed_values() {
        assert!(matches!(
            Cursor::new(b"7 0 R").value(),
            Err(ParseError::Incomplete)
        ));
        assert!(matches!(
            Cursor::complete(b"7 0 R").value(),
            Ok(Value::Reference(_))
        ));
        assert!(matches!(
            Cursor::new(b"<4 % 2>").value(),
            Err(ParseError::Invalid)
        ));
        assert!(matches!(
            Cursor::new(&[b'['; MAX_NESTING as usize + 1]).value(),
            Err(ParseError::Invalid)
        ));
    }
}
