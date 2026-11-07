//! Bounded no-allocation NAMESTORE zonefile text reader.
//!
//! Parsing neither creates an ego nor authorizes a record-set write. Events
//! borrow this reader's caller-owned scratch/name storage until the next call.
//! The caller synchronously converts `Record::value` through the existing Codec
//! before awaiting any original IDENTITY/NAMESTORE operation. A later error
//! does not roll back earlier events or turn the whole zonefile into a transaction.
use crate::{Error, RecordType, typename_to_number};
use core::{fmt, ops::Range};
const NAME_BYTES: usize = 256;
/// Explicit finite work/retention limits, independent of service queue capacity.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum complete input bytes inspected, including comments and blank lines.
    pub input_bytes: usize,
    /// Maximum bytes on one physical line, excluding CR/LF delimiters.
    pub line_bytes: usize,
    /// Maximum assembled logical record/directive, including header and payload.
    pub record_bytes: usize,
    /// Maximum emitted records across all origins and names.
    pub records: usize,
    /// Maximum adjacent records for one original origin/name group.
    pub records_per_name: usize,
    /// Maximum UTF-8 origin ego or relative owner bytes, at most255.
    pub name_bytes: usize,
    /// Maximum unquoted grouping-parenthesis depth, at most64.
    pub depth: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            input_bytes: 16 * 1024 * 1024,
            line_bytes: 4096,
            record_bytes: 65535,
            records: 65536,
            records_per_name: 50,
            name_bytes: 255,
            depth: 64,
        }
    }
}
impl Limits {
    fn valid(self) -> bool {
        self.input_bytes != 0
            && self.line_bytes != 0
            && self.record_bytes != 0
            && self.records != 0
            && self.records_per_name != 0
            && (1..NAME_BYTES).contains(&self.name_bytes)
            && (1..=64).contains(&self.depth)
    }
}
/// Starting physical source line and original bounded syntax/resource refusal.
/// No record payload or private material enters this printable diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    /// One-based starting physical line of this logical record, or0 for constructor errors.
    pub line: usize,
    /// Original protocol/resource classification; never a service receipt.
    pub cause: Error,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "zonefile line {}: {}", self.line, self.cause)
    }
}
impl core::error::Error for Failure {}
/// An origin boundary. Flush the old actual name group before selecting this ego.
#[derive(Clone, Copy, Debug)]
pub struct Origin<'a> {
    /// Literal ego name, without its one canonical final dot; not an identity.
    pub name: &'a str,
    /// Same origin with a final dot, used for FQDN owner suffix matching.
    pub fqdn: &'a str,
    /// True only for the optional initial `--zone` origin. Its existing-ego
    /// requirement is the caller's responsibility; `$ORIGIN` events are false.
    pub initial: bool,
}
/// One text record, still requiring the actual existing type-specific Codec.
#[derive(Clone, Copy, Debug)]
pub struct Record<'a> {
    /// Current literal ego name without final dot; never a key/authorization.
    pub origin: &'a str,
    /// Relative NAMESTORE owner or `@`; no origin is added to RDATA domains.
    pub owner: &'a str,
    /// Current `$TTL` decimal seconds converted to relative microseconds.
    /// Starts at0 and must be paired with RELATIVE_EXPIRATION by the caller.
    pub ttl_micros: u64,
    /// Existing active type registry result, not an invented numeric alias.
    pub record_type: RecordType,
    /// Original record text after comments/header removal. Quotes, parentheses
    /// and backslashes remain; physical continuations are joined by a space.
    pub value: &'a str,
}
/// Pull result. No event itself proves a successful conversion or remote write.
#[derive(Clone, Copy, Debug)]
pub enum Event<'a> {
    /// Initial origin or each explicit `$ORIGIN`, including repeated names.
    Origin(Origin<'a>),
    /// One original logical record for the caller's current bounded group.
    Record(Record<'a>),
    /// Real legal EOF, exactly once. Flush the last actual group after this event.
    End,
}
enum Parsed {
    Origin(bool),
    Record {
        kind: RecordType,
        value: Range<usize>,
    },
    End,
    Finished,
}
/// Whole-input reader with exclusively borrowed logical-line scratch and two
/// small fixed name arrays. No OS, allocation, IDNA backend, clock or worker is
/// hidden here. Initial validation is resource/UTF-8/NUL only, not a syntax pass.
pub struct Parser<'input, 'scratch> {
    input: &'input str,
    scratch: &'scratch mut [u8],
    limits: Limits,
    offset: usize,
    line: usize,
    current_line: usize,
    used: usize,
    origin: [u8; NAME_BYTES],
    origin_len: usize,
    owner: [u8; NAME_BYTES],
    owner_len: usize,
    ttl: u64,
    records: usize,
    group_records: usize,
    initial: bool,
    finished: bool,
    failed: bool,
}
impl<'input, 'scratch> Parser<'input, 'scratch> {
    /// Bind one complete bounded UTF-8 input and caller scratch of at least
    /// `limits.record_bytes`. Optional initial ego is literal (a final dot is part of its name). No
    /// syntax or record conversion beyond that initial origin is performed here.
    pub fn new(
        input: &'input str,
        initial_origin: Option<&str>,
        scratch: &'scratch mut [u8],
        limits: Limits,
    ) -> Result<Self, Failure> {
        let fault = |cause| Failure { line: 0, cause };
        if !limits.valid() {
            return Err(fault(Error::InvalidInput));
        }
        if input.len() > limits.input_bytes {
            return Err(fault(Error::TooLarge));
        }
        if input.as_bytes().contains(&0) {
            return Err(fault(Error::Malformed));
        }
        if scratch.len() < limits.record_bytes {
            return Err(fault(Error::Capacity));
        }
        let mut parser = Self {
            input,
            scratch,
            limits,
            offset: 0,
            line: 1,
            current_line: 1,
            used: 0,
            origin: [0; NAME_BYTES],
            origin_len: 0,
            owner: [0; NAME_BYTES],
            owner_len: 0,
            ttl: 0,
            records: 0,
            group_records: 0,
            initial: initial_origin.is_some(),
            finished: false,
            failed: false,
        };
        if let Some(origin) = initial_origin {
            parser.origin_len =
                set_origin(origin, &mut parser.origin, limits.name_bytes, false).map_err(fault)?;
        }
        Ok(parser)
    }
    /// Return one borrowed event. Convert/copy it before another call; the
    /// caller may await on its own retained group afterward. Syntax errors fence
    /// this parser permanently. After the single End event, returns None.
    pub fn next_event(&mut self) -> Result<Option<Event<'_>>, Failure> {
        if self.failed {
            return Err(Failure {
                line: self.current_line,
                cause: Error::Closed,
            });
        }
        let parsed = match self.advance() {
            Ok(value) => value,
            Err(cause) => {
                self.failed = true;
                return Err(Failure {
                    line: self.current_line,
                    cause,
                });
            }
        };
        let failure = Failure {
            line: self.current_line,
            cause: Error::Malformed,
        };
        match parsed {
            Parsed::Finished => Ok(None),
            Parsed::End => Ok(Some(Event::End)),
            Parsed::Origin(initial) => {
                let fqdn =
                    core::str::from_utf8(&self.origin[..self.origin_len]).map_err(|_| failure)?;
                let name = &fqdn[..fqdn.len() - 1];
                Ok(Some(Event::Origin(Origin {
                    name,
                    fqdn,
                    initial,
                })))
            }
            Parsed::Record { kind, value } => {
                let origin = core::str::from_utf8(&self.origin[..self.origin_len - 1])
                    .map_err(|_| failure)?;
                let owner =
                    core::str::from_utf8(&self.owner[..self.owner_len]).map_err(|_| failure)?;
                let value = core::str::from_utf8(&self.scratch[value]).map_err(|_| failure)?;
                Ok(Some(Event::Record(Record {
                    origin,
                    owner,
                    ttl_micros: self.ttl,
                    record_type: kind,
                    value,
                })))
            }
        }
    }
    fn advance(&mut self) -> Result<Parsed, Error> {
        if self.finished {
            return Ok(Parsed::Finished);
        }
        if self.initial {
            self.initial = false;
            return Ok(Parsed::Origin(true));
        }
        loop {
            self.current_line = self.line;
            if !self.logical()? {
                self.finished = true;
                return Ok(Parsed::End);
            }
            let text =
                core::str::from_utf8(&self.scratch[..self.used]).map_err(|_| Error::Malformed)?;
            let mut cursor = 0;
            let Some(first) = token(text, &mut cursor) else {
                continue;
            };
            let head = &text[first.clone()];
            if head.eq_ignore_ascii_case("$ORIGIN") {
                let value = token(text, &mut cursor).ok_or(Error::Malformed)?;
                if token(text, &mut cursor).is_some() {
                    return Err(Error::Malformed);
                }
                self.origin_len =
                    set_origin(&text[value], &mut self.origin, self.limits.name_bytes, true)?;
                // Every origin directive is a real flush boundary. The C owner
                // inheritance string survives it; only this contiguous set resets.
                self.group_records = 0;
                return Ok(Parsed::Origin(false));
            }
            if head.eq_ignore_ascii_case("$TTL") {
                let value = token(text, &mut cursor).ok_or(Error::Malformed)?;
                if token(text, &mut cursor).is_some() {
                    return Err(Error::Malformed);
                }
                self.ttl = ttl(&text[value])?;
                continue;
            }
            if head.starts_with('$') {
                return Err(Error::Unsupported);
            }
            if self.origin_len == 0 {
                return Err(Error::InvalidInput);
            }
            let mut same = true;
            if !head.eq_ignore_ascii_case("IN") {
                let origin = core::str::from_utf8(&self.origin[..self.origin_len - 1])
                    .map_err(|_| Error::Malformed)?;
                let owner = relative_owner(head, origin)?;
                if owner.is_empty() || owner.len() > self.limits.name_bytes {
                    return Err(Error::TooLarge);
                }
                same = &self.owner[..self.owner_len] == owner.as_bytes();
                self.owner[..owner.len()].copy_from_slice(owner.as_bytes());
                self.owner_len = owner.len();
                let class = token(text, &mut cursor).ok_or(Error::Malformed)?;
                if !text[class].eq_ignore_ascii_case("IN") {
                    return Err(Error::Unsupported);
                }
            } else if self.owner_len == 0 {
                return Err(Error::InvalidInput);
            }
            let kind = token(text, &mut cursor).ok_or(Error::Malformed)?;
            let kind = typename_to_number(&text[kind]).ok_or(Error::Unsupported)?;
            skip(text, &mut cursor);
            let end = text
                .trim_end_matches(|c: char| c.is_ascii_whitespace())
                .len();
            let value = cursor.min(end)..end;
            let group_records = if same {
                self.group_records.checked_add(1).ok_or(Error::Overflow)?
            } else {
                1
            };
            if group_records > self.limits.records_per_name || self.records >= self.limits.records {
                return Err(Error::Capacity);
            }
            self.group_records = group_records;
            self.records += 1;
            return Ok(Parsed::Record { kind, value });
        }
    }
    fn byte(&mut self, byte: u8) -> Result<(), Error> {
        if self.used >= self.limits.record_bytes {
            return Err(Error::Capacity);
        }
        self.scratch[self.used] = byte;
        self.used += 1;
        Ok(())
    }
    fn logical(&mut self) -> Result<bool, Error> {
        self.used = 0;
        let mut quoted = false;
        let mut escaped = false;
        let mut depth = 0usize;
        let mut comment = false;
        let mut physical = 0usize;
        let mut started = false;
        let mut physical_start = true;
        while self.offset < self.input.len() {
            let byte = self.input.as_bytes()[self.offset];
            self.offset += 1;
            if byte == b'\n' {
                self.line = self.line.checked_add(1).ok_or(Error::Overflow)?;
                physical = 0;
                comment = false;
                escaped = false;
                physical_start = true;
                if depth == 0 {
                    if quoted {
                        return Err(Error::Malformed);
                    }
                    return Ok(true);
                }
                self.byte(b' ')?;
                continue;
            }
            if byte == b'\r' && self.input.as_bytes().get(self.offset) == Some(&b'\n') {
                continue;
            }
            physical = physical.checked_add(1).ok_or(Error::Overflow)?;
            if physical > self.limits.line_bytes {
                return Err(Error::Capacity);
            }
            started = true;
            if physical_start && !quoted && byte.is_ascii_whitespace() {
                continue;
            }
            physical_start = false;
            if comment {
                continue;
            }
            if escaped {
                self.byte(byte)?;
                escaped = false;
                continue;
            }
            if byte == b'\\' {
                self.byte(byte)?;
                escaped = true;
                continue;
            }
            if byte == b'"' {
                quoted = !quoted;
                self.byte(byte)?;
                continue;
            }
            if !quoted {
                if byte == b';' {
                    comment = true;
                    continue;
                }
                if byte == b'(' {
                    depth = depth.checked_add(1).ok_or(Error::Overflow)?;
                    if depth > self.limits.depth {
                        return Err(Error::Capacity);
                    }
                } else if byte == b')' {
                    depth = depth.checked_sub(1).ok_or(Error::Malformed)?;
                }
            }
            self.byte(byte)?;
        }
        if quoted || depth != 0 {
            return Err(Error::Malformed);
        }
        Ok(started)
    }
}
fn skip(text: &str, cursor: &mut usize) {
    while text
        .as_bytes()
        .get(*cursor)
        .is_some_and(u8::is_ascii_whitespace)
    {
        *cursor += 1;
    }
}
fn token(text: &str, cursor: &mut usize) -> Option<Range<usize>> {
    skip(text, cursor);
    let start = *cursor;
    while text
        .as_bytes()
        .get(*cursor)
        .is_some_and(|b| !b.is_ascii_whitespace())
    {
        *cursor += 1;
    }
    (start != *cursor).then_some(start..*cursor)
}
fn ttl(text: &str) -> Result<u64, Error> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Malformed);
    }
    let seconds = text.bytes().try_fold(0u64, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
            .ok_or(Error::Overflow)
    })?;
    seconds
        .checked_mul(1_000_000)
        .filter(|value| *value < u64::MAX)
        .ok_or(Error::Overflow)
}
fn set_origin(
    text: &str,
    output: &mut [u8; NAME_BYTES],
    limit: usize,
    directive: bool,
) -> Result<usize, Error> {
    let name = if directive {
        text.strip_suffix('.').unwrap_or(text)
    } else {
        text
    };
    if name.is_empty() || name.len() > limit || name.as_bytes().contains(&0) {
        return Err(Error::InvalidInput);
    }
    output[..name.len()].copy_from_slice(name.as_bytes());
    output[name.len()] = b'.';
    Ok(name.len() + 1)
}
fn relative_owner<'a>(owner: &'a str, origin: &str) -> Result<&'a str, Error> {
    if owner == "@" || !owner.ends_with('.') {
        return Ok(owner);
    }
    let absolute = &owner[..owner.len() - 1];
    if absolute.eq_ignore_ascii_case(origin) {
        return Ok("@");
    }
    let Some(start) = absolute.len().checked_sub(origin.len()) else {
        return Err(Error::InvalidInput);
    };
    if start == 0
        || absolute.as_bytes()[start - 1] != b'.'
        || !absolute.as_bytes()[start..].eq_ignore_ascii_case(origin.as_bytes())
    {
        return Err(Error::InvalidInput);
    }
    Ok(&absolute[..start - 1])
}
