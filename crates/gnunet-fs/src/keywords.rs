use crate::{
    Limits,
    codec::{self, Writer},
};
use gnunet_types::Error;

#[derive(Clone, Copy, Debug)]
enum Text<'a> {
    Plain(&'a [u8]),
    Encoded(&'a [u8]),
    User(&'a [u8]),
}

/// One keyword and its mandatory-search flag. Text is opaque bytes; no locale,
/// Unicode normalization, metadata extraction or search execution is implicit.
#[derive(Clone, Copy, Debug)]
pub struct Keyword<'a> {
    text: Text<'a>,
    mandatory: bool,
}
impl<'a> Keyword<'a> {
    /// Borrow a representable literal keyword. Empty mandatory text represents
    /// the official marker-only `%2B` term. Optional empty text, an optional
    /// leading plus, quotes and NUL cannot round-trip through the URI syntax.
    pub fn new(text: &'a [u8], mandatory: bool) -> Result<Self, Error> {
        if (text.is_empty() && !mandatory)
            || text.contains(&0)
            || text.contains(&b'"')
            || (!mandatory && text.first() == Some(&b'+'))
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            text: Text::Plain(text),
            mandatory,
        })
    }
    /// Whether this keyword is mandatory rather than optional in a search.
    #[must_use]
    pub const fn mandatory(self) -> bool {
        self.mandatory
    }
    /// Iterate decoded keyword bytes, excluding the mandatory marker and quote
    /// syntax. A percent-encoded NUL has the pinned C-string truncation effect.
    pub fn bytes(self) -> KeywordBytes<'a> {
        let mut bytes = KeywordBytes {
            input: match self.text {
                Text::Plain(b) | Text::Encoded(b) | Text::User(b) => b,
            },
            position: 0,
            encoded: matches!(self.text, Text::Encoded(_)),
            strip_quotes: matches!(self.text, Text::User(_)),
            ended: false,
        };
        if matches!(self.text, Text::Encoded(_)) && self.mandatory {
            let _marker = bytes.next();
        }
        bytes
    }
    /// Number of decoded payload bytes; no mandatory marker is included.
    #[must_use]
    pub fn len(self) -> usize {
        self.bytes().count()
    }
    /// Whether the payload is empty. A marker-only mandatory term has no payload
    /// bytes but still counts as one term in its keyword URI.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.bytes().next().is_none()
    }
    /// Write decoded payload atomically with respect to capacity rejection.
    pub fn write(self, output: &mut [u8]) -> Result<usize, Error> {
        let n = self.len();
        if output.len() < n {
            return Err(Error::Capacity);
        }
        for (slot, byte) in output.iter_mut().zip(self.bytes()) {
            *slot = byte;
        }
        Ok(n)
    }
    fn user(input: &'a [u8]) -> Self {
        let mandatory = input.first() == Some(&b'+');
        Self {
            text: Text::User(if mandatory { &input[1..] } else { input }),
            mandatory,
        }
    }
    fn parsed(input: &'a [u8]) -> Self {
        let mandatory = KeywordBytes {
            input,
            position: 0,
            encoded: true,
            strip_quotes: false,
            ended: false,
        }
        .next()
            == Some(b'+');
        Self {
            text: Text::Encoded(input),
            mandatory,
        }
    }
}

/// Validated, allocation-free decoded keyword iterator.
#[derive(Clone)]
pub struct KeywordBytes<'a> {
    input: &'a [u8],
    position: usize,
    encoded: bool,
    strip_quotes: bool,
    ended: bool,
}
impl Iterator for KeywordBytes<'_> {
    type Item = u8;
    fn next(&mut self) -> Option<u8> {
        while !self.ended {
            let mut byte = *self.input.get(self.position)?;
            self.position += 1;
            if self.encoded && byte == b'%' {
                // All encoded slices are validated before this iterator exists.
                let a = codec::hex(*self.input.get(self.position)?)?;
                let b = codec::hex(*self.input.get(self.position + 1)?)?;
                self.position += 2;
                byte = a * 16 + b;
                if byte == b'"' {
                    continue;
                }
            }
            if self.strip_quotes && byte == b'"' {
                continue;
            }
            if byte == 0 {
                self.ended = true;
                return None;
            }
            return Some(byte);
        }
        None
    }
}

#[derive(Clone, Copy, Debug)]
enum Terms<'a> {
    Literal(&'a [Keyword<'a>]),
    Encoded(&'a [u8]),
    UserText(&'a [u8]),
    UserArgs(&'a [&'a [u8]]),
}

/// Ordered keyword artifact view. Serialization retains order and duplicates;
/// interpreting the search's optional/mandatory sets belongs to the FS owner.
#[derive(Clone, Copy, Debug)]
pub struct Keywords<'a> {
    terms: Terms<'a>,
    count: usize,
}
impl<'a> Keywords<'a> {
    /// Borrow explicit keywords without copying or allocating storage.
    pub fn new(terms: &'a [Keyword<'a>]) -> Result<Self, Error> {
        if terms.is_empty() {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            terms: Terms::Literal(terms),
            count: terms.len(),
        })
    }
    /// Borrow a user-entered keyword string without an allocation. ASCII space,
    /// tab, newline, vertical tab, form feed and carriage return separate terms
    /// outside balanced double quotes. All quotes are removed from the payload;
    /// only a literal initial plus before quote removal makes a term mandatory.
    /// Percent signs and non-ASCII bytes retain their literal original meaning.
    ///
    /// Unlike URI parsing, quoted empty or optional leading-plus terms are valid
    /// search input. They cannot round-trip through the official URI grammar, so
    /// URI serialization refuses them instead of changing their search meaning.
    pub fn from_user_text(input: &'a [u8], limits: Limits) -> Result<Self, Error> {
        if input.len() > limits.max_input_bytes {
            return Err(Error::Capacity);
        }
        if input.contains(&0) {
            return Err(Error::InvalidInput);
        }
        let mut position = 0;
        let mut count = 0_usize;
        while let Some((raw, next)) = user_token(input, position)? {
            let keyword = Keyword::user(raw);
            if keyword.len() > limits.max_keyword_bytes {
                return Err(Error::Capacity);
            }
            count = count.checked_add(1).ok_or(Error::Overflow)?;
            if count > limits.max_keywords {
                return Err(Error::Capacity);
            }
            position = next;
        }
        if count == 0 {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            terms: Terms::UserText(input),
            count,
        })
    }
    /// Borrow already-separated user arguments. Each argument is one term even
    /// if it contains whitespace, and all double quotes are stripped; unlike
    /// `from_user_text`, argument quotes need not be balanced. An initial plus
    /// before stripping quotes marks a mandatory term. Empty arguments remain
    /// actual optional empty terms. No locale or Unicode normalization is applied.
    ///
    /// This explicit keyword constructor does not interpret an argument as a URI;
    /// callers choosing a URI use `Uri::parse` separately. Total raw input bytes,
    /// term count and decoded term bytes are checked before yielding the view.
    pub fn from_user_args(input: &'a [&'a [u8]], limits: Limits) -> Result<Self, Error> {
        if input.is_empty() {
            return Err(Error::InvalidInput);
        }
        if input.len() > limits.max_keywords {
            return Err(Error::Capacity);
        }
        let mut bytes = 0_usize;
        for raw in input {
            bytes = bytes.checked_add(raw.len()).ok_or(Error::Overflow)?;
            if bytes > limits.max_input_bytes {
                return Err(Error::Capacity);
            }
            if raw.contains(&0) {
                return Err(Error::InvalidInput);
            }
            if Keyword::user(raw).len() > limits.max_keyword_bytes {
                return Err(Error::Capacity);
            }
        }
        Ok(Self {
            terms: Terms::UserArgs(input),
            count: input.len(),
        })
    }
    pub(crate) fn parse(body: &'a [u8], limits: Limits) -> Result<Self, Error> {
        if body.is_empty()
            || body.contains(&b'"')
            || body.first() == Some(&b'+')
            || body.last() == Some(&b'+')
        {
            return Err(Error::Malformed);
        }
        let mut count = 0;
        let mut position = 0;
        loop {
            let (token, next) = token(body, position)?;
            let keyword = Keyword::parsed(token);
            if keyword.is_empty() && !keyword.mandatory() {
                return Err(Error::Malformed);
            }
            if keyword.len() > limits.max_keyword_bytes {
                return Err(Error::Capacity);
            }
            count += 1;
            if count > limits.max_keywords {
                return Err(Error::Capacity);
            }
            let Some(p) = next else {
                break;
            };
            position = p;
        }
        Ok(Self {
            terms: Terms::Encoded(body),
            count,
        })
    }
    /// Number of terms, including duplicates explicitly present in the artifact.
    #[must_use]
    pub const fn len(self) -> usize {
        self.count
    }
    /// A successfully constructed keyword URI always has at least one term.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.count == 0
    }
    /// Iterate without allocating a decoded keyword list.
    pub fn iter(self) -> KeywordsIter<'a> {
        KeywordsIter {
            terms: self.terms,
            position: 0,
            ended: false,
        }
    }
    pub(crate) fn encoded_len(self) -> Result<usize, Error> {
        let mut length = self.count - 1;
        for keyword in self.iter() {
            if !keyword.mandatory && (keyword.is_empty() || keyword.bytes().next() == Some(b'+')) {
                return Err(Error::InvalidInput);
            }
            if keyword.mandatory {
                length = length.checked_add(3).ok_or(Error::Overflow)?;
            }
            for byte in keyword.bytes() {
                length = length
                    .checked_add(if codec::plain(byte) { 1 } else { 3 })
                    .ok_or(Error::Overflow)?;
            }
        }
        Ok(length)
    }
    pub(crate) fn encode(self, writer: &mut Writer<'_>) {
        for (i, keyword) in self.iter().enumerate() {
            if i != 0 {
                writer.byte(b'+');
            }
            if keyword.mandatory {
                writer.escaped(b'+');
            }
            for byte in keyword.bytes() {
                writer.escaped(byte);
            }
        }
    }
}

/// Iterator over validated literal or parsed keyword views.
pub struct KeywordsIter<'a> {
    terms: Terms<'a>,
    position: usize,
    ended: bool,
}
impl<'a> Iterator for KeywordsIter<'a> {
    type Item = Keyword<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.ended {
            return None;
        }
        match self.terms {
            Terms::Literal(terms) => {
                let term = *terms.get(self.position)?;
                self.position += 1;
                Some(term)
            }
            Terms::UserText(input) => {
                let (bytes, next) = user_token(input, self.position).ok()??;
                self.position = next;
                Some(Keyword::user(bytes))
            }
            Terms::UserArgs(input) => {
                let bytes = *input.get(self.position)?;
                self.position += 1;
                Some(Keyword::user(bytes))
            }
            Terms::Encoded(body) => {
                let (bytes, next) = token(body, self.position).ok()?;
                match next {
                    Some(p) => self.position = p,
                    None => self.ended = true,
                }
                Some(Keyword::parsed(bytes))
            }
        }
    }
}

fn token(body: &[u8], start: usize) -> Result<(&[u8], Option<usize>), Error> {
    let mut position = start;
    let mut quoted = false;
    while let Some(byte) = body.get(position) {
        if *byte == b'%' {
            let high = codec::hex(*body.get(position + 1).ok_or(Error::Malformed)?)
                .ok_or(Error::Malformed)?;
            let low = codec::hex(*body.get(position + 2).ok_or(Error::Malformed)?)
                .ok_or(Error::Malformed)?;
            if high * 16 + low == b'"' {
                quoted = !quoted;
            }
            position += 3;
        } else if *byte == b'+' && !quoted {
            if position == start {
                return Err(Error::Malformed);
            }
            return Ok((&body[start..position], Some(position + 1)));
        } else {
            position += 1;
        }
    }
    if quoted {
        return Err(Error::Malformed);
    }
    Ok((&body[start..], None))
}

fn user_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn user_token(input: &[u8], mut position: usize) -> Result<Option<(&[u8], usize)>, Error> {
    while input.get(position).is_some_and(|byte| user_space(*byte)) {
        position += 1;
    }
    if position == input.len() {
        return Ok(None);
    }
    let start = position;
    let mut quoted = false;
    while let Some(byte) = input.get(position) {
        if *byte == b'"' {
            quoted = !quoted;
        } else if !quoted && user_space(*byte) {
            break;
        }
        position += 1;
    }
    if quoted {
        return Err(Error::Malformed);
    }
    Ok(Some((&input[start..position], position)))
}
