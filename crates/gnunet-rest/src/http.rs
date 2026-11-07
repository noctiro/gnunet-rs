//! Checked HTTP/1.0 and HTTP/1.1 request framing and finite whole responses.
//! Truncated input consumes nothing: retain it on its ORIGINAL connection.
use gnunet_types::Error;

/// Explicit finite request framing resources.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Complete header prefix maximum, including final CRLFCRLF.
    pub header_bytes: usize,
    /// Maximum request target bytes, including raw query.
    pub target_bytes: usize,
    /// Maximum individual request/header/chunk-size line bytes.
    pub line_bytes: usize,
    /// Maximum ordinary header fields or trailing fields.
    pub headers: usize,
    /// Maximum complete encoded request prefix, including chunk metadata.
    pub wire_bytes: usize,
    /// Maximum decoded body bytes.
    pub body_bytes: usize,
    /// Maximum transfer chunks, including the terminating zero chunk.
    pub chunks: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            header_bytes: 32768,
            wire_bytes: 131072,
            target_bytes: 2048,
            line_bytes: 8192,
            headers: 64,
            body_bytes: 65535,
            chunks: 1024,
        }
    }
}
impl Limits {
    fn validate(self) -> Result<(), Error> {
        if self.wire_bytes < self.header_bytes
            || self.header_bytes < 4
            || self.target_bytes == 0
            || self.line_bytes == 0
            || self.headers == 0
            || self.chunks == 0
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}
/// Validated borrowed request header field. Debug never prints credentials.
#[derive(Clone, Copy)]
pub struct Header<'a> {
    /// Original field name with valid HTTP token syntax.
    pub name: &'a [u8],
    /// Original field value with surrounding OWS removed.
    pub value: &'a [u8],
}
impl core::fmt::Debug for Header<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Header([REDACTED])")
    }
}
/// Immutable original body framing. The caller controls any erase/copy policy.
#[derive(Clone, Copy)]
pub struct Body<'a> {
    wire: &'a [u8],
    bytes: usize,
    chunked: bool,
    limits: Limits,
}
impl<'a> Body<'a> {
    /// Exact decoded byte count established by complete preflight.
    pub const fn len(self) -> usize {
        self.bytes
    }
    /// Whether there is no decoded body.
    pub const fn is_empty(self) -> bool {
        self.bytes == 0
    }
    /// Zero-copy body for Content-Length/no-body messages. Chunked messages
    /// require decode into separate caller-owned storage on this original source.
    pub const fn contiguous(self) -> Option<&'a [u8]> {
        if self.chunked { None } else { Some(self.wire) }
    }
    /// Decode after whole-body capacity preflight. It never exposes a chunk
    /// suffix as a new request or an unvalidated incomplete body as complete.
    pub fn decode(self, out: &mut [u8]) -> Result<usize, Error> {
        let out = out.get_mut(..self.bytes).ok_or(Error::Capacity)?;
        if !self.chunked {
            out.copy_from_slice(self.wire);
            return Ok(self.bytes);
        }
        let mut at = 0usize;
        chunks(self.wire, self.limits, |part| {
            out[at..at + part.len()].copy_from_slice(part);
            at += part.len();
        })?;
        Ok(at)
    }
}
impl core::fmt::Debug for Body<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Body")
            .field("bytes", &self.bytes)
            .field("chunked", &self.chunked)
            .finish_non_exhaustive()
    }
}
/// Original parsed Expect field, independent of body completeness or authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Expectation {
    /// No expectation field was supplied.
    None,
    /// Only case-insensitive 100-continue members were supplied.
    Continue,
    /// An unknown member or parameter cannot be met by this server.
    Unsupported,
}
/// A complete checked original header prefix. It grants no body completeness,
/// route authorization, native admission or successful HTTP operation.
pub struct RequestHead<'a> {
    method: &'a [u8],
    target: &'a [u8],
    headers: &'a [u8],
    length: usize,
    chunked: bool,
    http11: bool,
    end: usize,
    expectation: Expectation,
}
impl<'a> RequestHead<'a> {
    /// Share the complete request's one bounded header/framing preflight.
    /// Known Content-Length oversize is rejected without waiting for that body.
    pub fn parse(input: &'a [u8], limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        let scan = &input[..input.len().min(limits.header_bytes)];
        let end = scan
            .windows(4)
            .position(|b| b == b"\r\n\r\n")
            .map(|n| n + 4)
            .ok_or(if input.len() >= limits.header_bytes {
                Error::TooLarge
            } else {
                Error::Truncated
            })?;
        let first = scan
            .windows(2)
            .position(|b| b == b"\r\n")
            .ok_or(Error::Malformed)?;
        if first > limits.line_bytes {
            return Err(Error::TooLarge);
        }
        let line = &input[..first];
        let mut words = line.split(|b| *b == b' ');
        let method = words.next().ok_or(Error::Malformed)?;
        let target = words.next().ok_or(Error::Malformed)?;
        let version = words.next().ok_or(Error::Malformed)?;
        if words.next().is_some()
            || method.is_empty()
            || !method.iter().copied().all(token)
            || target.is_empty()
            || target[0] != b'/'
            || target.iter().any(|b| *b < 0x21 || *b > 0x7e || *b == b'#')
        {
            return Err(Error::Malformed);
        }
        if target.len() > limits.target_bytes {
            return Err(Error::TooLarge);
        }
        let http11 = match version {
            b"HTTP/1.1" => true,
            b"HTTP/1.0" => false,
            _ => return Err(Error::Unsupported),
        };
        let headers = &input[first + 2..end - 2];
        if headers
            .split(|b| *b == b'\n')
            .any(|line| line.len() > limits.line_bytes.saturating_add(1))
        {
            return Err(Error::TooLarge);
        }
        let mut count = 0usize;
        let mut content = None;
        let mut chunked = false;
        let mut host = false;
        let mut expectation = Expectation::None;
        for field in (Headers { raw: headers }) {
            let field = field?;
            count = count.checked_add(1).ok_or(Error::Overflow)?;
            if count > limits.headers
                || field.name.len() + field.value.len() + 1 > limits.line_bytes
            {
                return Err(Error::TooLarge);
            }
            if field.name.eq_ignore_ascii_case(b"content-length") {
                if content.is_some() {
                    return Err(Error::Malformed);
                }
                content = Some(decimal(field.value)?);
            } else if field.name.eq_ignore_ascii_case(b"transfer-encoding") {
                if chunked || !field.value.eq_ignore_ascii_case(b"chunked") {
                    return Err(Error::Unsupported);
                }
                chunked = true;
            } else if field.name.eq_ignore_ascii_case(b"expect") {
                // Repeated known list members do not add multiple handshakes.
                // Unknown/mixed expectations remain explicit for a 417 response.
                for member in field.value.split(|byte| *byte == b',') {
                    let member = trim(member);
                    if member.is_empty() {
                        continue;
                    }
                    if !member.eq_ignore_ascii_case(b"100-continue") {
                        expectation = Expectation::Unsupported;
                    } else if expectation == Expectation::None {
                        expectation = Expectation::Continue;
                    }
                }
            } else if field.name.eq_ignore_ascii_case(b"host") {
                if host || field.value.is_empty() {
                    return Err(Error::Malformed);
                }
                host = true;
            }
        }
        if http11 && !host {
            return Err(Error::Malformed);
        }
        if content.is_some() && chunked {
            return Err(Error::Malformed);
        }
        if !http11 && chunked {
            return Err(Error::Malformed);
        }
        let content = content.unwrap_or(0);
        if !chunked
            && (content > limits.body_bytes || content > limits.wire_bytes.saturating_sub(end))
        {
            return Err(Error::TooLarge);
        }
        Ok(Self {
            method,
            target,
            headers,
            length: content,
            chunked,
            http11,
            end,
            expectation,
        })
    }
    /// Original method token; no backend operation is implied.
    pub const fn method(&self) -> &'a [u8] {
        self.method
    }
    /// Original origin-form target, including raw query.
    pub const fn target(&self) -> &'a [u8] {
        self.target
    }
    /// Exact complete original header byte extent, including CRLFCRLF.
    pub const fn header_len(&self) -> usize {
        self.end
    }
    /// Exact original validated header fields; body/trailers are not included.
    pub const fn headers(&self) -> Headers<'a> {
        Headers { raw: self.headers }
    }
    /// The original expectation classification. Unsupported is not acceptance.
    pub const fn expectation(&self) -> Expectation {
        self.expectation
    }
    /// Whether header framing calls for 100 before content. HTTP/1.0 ignores
    /// known 100-continue; no/zero-length content never requires an interim.
    /// The native owner must also check that no body bytes were already read.
    pub const fn continue_expected(&self) -> bool {
        self.http11
            && matches!(self.expectation, Expectation::Continue)
            && (self.chunked || self.length != 0)
    }
}
impl core::fmt::Debug for RequestHead<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RequestHead")
            .field("header_bytes", &self.end)
            .field("expectation", &self.expectation)
            .finish_non_exhaustive()
    }
}
/// One complete original HTTP request. Extra pipelined bytes are reported by
/// consumed(), not accepted as part of the body or moved to a different source.
pub struct Request<'a> {
    method: &'a [u8],
    target: &'a [u8],
    headers: &'a [u8],
    body: Body<'a>,
    consumed: usize,
    http11: bool,
}
impl<'a> Request<'a> {
    /// Parse exactly one complete header/body prefix with bounded framing.
    pub fn parse(input: &'a [u8], limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        match Self::parse_inner(&input[..input.len().min(limits.wire_bytes)], limits) {
            Err(Error::Truncated) if input.len() >= limits.wire_bytes => Err(Error::TooLarge),
            other => other,
        }
    }
    fn parse_inner(input: &'a [u8], limits: Limits) -> Result<Self, Error> {
        let head = RequestHead::parse(input, limits)?;
        if head.expectation == Expectation::Unsupported {
            return Err(Error::Unsupported);
        }
        let end = head.end;
        let chunked = head.chunked;
        let (wire_len, bytes) = if chunked {
            chunks(&input[end..], limits, |_| {})?
        } else {
            let n = head.length;
            if input.len() - end < n {
                return Err(Error::Truncated);
            }
            (n, n)
        };
        let consumed = end.checked_add(wire_len).ok_or(Error::Overflow)?;
        Ok(Self {
            method: head.method,
            target: head.target,
            headers: head.headers,
            body: Body {
                wire: &input[end..consumed],
                bytes,
                chunked,
                limits,
            },
            consumed,
            http11: head.http11,
        })
    }
    /// Original HTTP token; official route matching is case-insensitive like C.
    pub const fn method(&self) -> &'a [u8] {
        self.method
    }
    /// Original origin-form target, including raw query if present.
    pub const fn target(&self) -> &'a [u8] {
        self.target
    }
    /// Exact original decoded body plan; no JSON parsing/authority is inferred.
    pub const fn body(&self) -> Body<'a> {
        self.body
    }
    /// Complete bytes consumed from this connection's retained original input.
    pub const fn consumed(&self) -> usize {
        self.consumed
    }
    /// Whether this is HTTP/1.1 rather than HTTP/1.0.
    pub const fn http11(&self) -> bool {
        self.http11
    }
    /// Iterate checked ordinary headers; this does not include ignored trailers.
    pub const fn headers(&self) -> Headers<'a> {
        Headers { raw: self.headers }
    }
    /// Case-insensitive ordinary header lookup. Framing-critical duplicates
    /// were refused; callers must define their own duplicate auth/header policy.
    pub fn header(&self, name: &[u8]) -> Option<&'a [u8]> {
        self.headers()
            .filter_map(Result::ok)
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value)
    }
}
impl core::fmt::Debug for Request<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Request")
            .field("body", &self.body)
            .finish_non_exhaustive()
    }
}
/// Header traversal over immutable validated input; malformed construction is
/// still reported rather than assuming unchecked ASCII or C-string termination.
pub struct Headers<'a> {
    raw: &'a [u8],
}
impl<'a> Iterator for Headers<'a> {
    type Item = Result<Header<'a>, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.raw.is_empty() || self.raw == b"\r\n" {
            self.raw = &[];
            return None;
        }
        let Some(end) = self.raw.windows(2).position(|b| b == b"\r\n") else {
            self.raw = &[];
            return Some(Err(Error::Malformed));
        };
        let line = &self.raw[..end];
        self.raw = &self.raw[end + 2..];
        Some(field(line))
    }
}
fn field(line: &[u8]) -> Result<Header<'_>, Error> {
    let colon = line
        .iter()
        .position(|b| *b == b':')
        .ok_or(Error::Malformed)?;
    if colon == 0 || !line[..colon].iter().copied().all(token) {
        return Err(Error::Malformed);
    }
    let value = trim(&line[colon + 1..]);
    if value
        .iter()
        .any(|b| (*b < 0x20 && *b != b'\t') || *b == 0x7f)
    {
        return Err(Error::Malformed);
    }
    Ok(Header {
        name: &line[..colon],
        value,
    })
}
fn token(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}
fn trim(mut b: &[u8]) -> &[u8] {
    while b.first().is_some_and(|b| matches!(b, b' ' | b'\t')) {
        b = &b[1..]
    }
    while b.last().is_some_and(|b| matches!(b, b' ' | b'\t')) {
        b = &b[..b.len() - 1]
    }
    b
}
fn decimal(b: &[u8]) -> Result<usize, Error> {
    if b.is_empty() {
        return Err(Error::Malformed);
    }
    let mut n = 0usize;
    for b in b {
        if !b.is_ascii_digit() {
            return Err(Error::Malformed);
        }
        n = n
            .checked_mul(10)
            .and_then(|n| n.checked_add(usize::from(b - b'0')))
            .ok_or(Error::Overflow)?;
    }
    Ok(n)
}
fn chunks(
    input: &[u8],
    limits: Limits,
    mut observe: impl FnMut(&[u8]),
) -> Result<(usize, usize), Error> {
    let (mut at, mut total, mut count) = (0usize, 0usize, 0usize);
    loop {
        count = count.checked_add(1).ok_or(Error::Overflow)?;
        if count > limits.chunks {
            return Err(Error::TooLarge);
        }
        let end = line_end(input, at, limits.line_bytes)?;
        let size_line = &input[at..end];
        let split = size_line
            .iter()
            .position(|b| *b == b';')
            .unwrap_or(size_line.len());
        let raw = &size_line[..split];
        if raw.is_empty() {
            return Err(Error::Malformed);
        }
        let mut size = 0usize;
        for b in raw {
            let v = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return Err(Error::Malformed),
            };
            size = size
                .checked_mul(16)
                .and_then(|n| n.checked_add(usize::from(v)))
                .ok_or(Error::Overflow)?;
        }
        extensions(&size_line[split..])?;
        at = end + 2;
        if size == 0 {
            let start = at;
            let mut trailers = 0usize;
            loop {
                let end = line_end(input, at, limits.line_bytes)?;
                if end + 2 - start > limits.header_bytes {
                    return Err(Error::TooLarge);
                }
                if end == at {
                    return Ok((end + 2, total));
                }
                trailers += 1;
                if trailers > limits.headers || end + 2 - start > limits.header_bytes {
                    return Err(Error::TooLarge);
                }
                let h = field(&input[at..end])?;
                if [
                    b"content-length".as_slice(),
                    b"transfer-encoding",
                    b"host",
                    b"authorization",
                    b"connection",
                    b"content-type",
                ]
                .iter()
                .any(|n| h.name.eq_ignore_ascii_case(n))
                {
                    return Err(Error::Malformed);
                }
                at = end + 2;
            }
        }
        total = total.checked_add(size).ok_or(Error::Overflow)?;
        if total > limits.body_bytes {
            return Err(Error::TooLarge);
        }
        let end = at.checked_add(size).ok_or(Error::Overflow)?;
        let data = input.get(at..end).ok_or(Error::Truncated)?;
        if input.get(end..end + 2) != Some(b"\r\n") {
            return Err(if input.len() < end + 2 {
                Error::Truncated
            } else {
                Error::Malformed
            });
        }
        observe(data);
        at = end + 2;
    }
}
fn line_end(input: &[u8], at: usize, maximum: usize) -> Result<usize, Error> {
    let rest = input.get(at..).ok_or(Error::Truncated)?;
    let cap = rest.len().min(maximum.saturating_add(2));
    let pos = rest[..cap].windows(2).position(|b| b == b"\r\n").ok_or(
        if rest.len() > maximum.saturating_add(1) {
            Error::TooLarge
        } else {
            Error::Truncated
        },
    )?;
    if pos > maximum {
        return Err(Error::TooLarge);
    }
    Ok(at + pos)
}
fn extensions(mut b: &[u8]) -> Result<(), Error> {
    while !b.is_empty() {
        if b[0] != b';' {
            return Err(Error::Malformed);
        }
        b = &b[1..];
        let n = b.iter().take_while(|b| token(**b)).count();
        if n == 0 {
            return Err(Error::Malformed);
        }
        b = &b[n..];
        if b.first() != Some(&b'=') {
            continue;
        }
        b = &b[1..];
        if b.first() == Some(&b'"') {
            b = &b[1..];
            loop {
                let c = *b.first().ok_or(Error::Malformed)?;
                b = &b[1..];
                if c == b'"' {
                    break;
                }
                if c == b'\\' {
                    let c = *b.first().ok_or(Error::Malformed)?;
                    b = &b[1..];
                    if c < 0x20 && c != b'\t' {
                        return Err(Error::Malformed);
                    }
                } else if (c < 0x20 && c != b'\t') || c == 0x7f {
                    return Err(Error::Malformed);
                }
            }
        } else {
            let n = b.iter().take_while(|b| token(**b)).count();
            if n == 0 {
                return Err(Error::Malformed);
            }
            b = &b[n..];
        }
    }
    Ok(())
}
/// Complete nonstreaming JSON/empty HTTP response. Caller retains this original
/// immutable output through whole write or actual HTTP-source retirement.
pub struct Response<'a> {
    /// Actual selected final HTTP status,200..599 (interim responses are separate).
    pub status: u16,
    /// Actual body bytes. Successful mutation responses commonly have zero bytes.
    pub body: &'a [u8],
    /// Validated ASCII media type, normally application/json.
    pub content_type: &'a [u8],
    /// Suppress transmitted body for an actual HEAD request while retaining length.
    pub head_only: bool,
    /// Additional validated response headers, e.g. official CORS methods. Framing
    /// Content-Length/Content-Type/Transfer-Encoding/Connection cannot be replaced.
    pub headers: &'a [Header<'a>],
}
impl Response<'_> {
    /// Required complete wire bytes with Content-Length and Connection: close.
    pub fn encoded_len(&self) -> Result<usize, Error> {
        self.write(None)
    }
    /// Encode after complete preflight; no partial output on refusal. HTTP host
    /// sockets/listener/persistence are intentionally outside this pure codec.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        let out = out.get_mut(..n).ok_or(Error::Capacity)?;
        self.write(Some(out))
    }
    fn write(&self, mut out: Option<&mut [u8]>) -> Result<usize, Error> {
        if !(200..600).contains(&self.status)
            || self.content_type.iter().any(|b| *b < 0x20 || *b > 0x7e)
        {
            return Err(Error::InvalidInput);
        }
        if (self.status < 200 || self.status == 204 || self.status == 304) && !self.body.is_empty()
        {
            return Err(Error::InvalidInput);
        }
        for h in self.headers {
            if h.name.is_empty()
                || !h.name.iter().copied().all(token)
                || h.value
                    .iter()
                    .any(|b| (*b < 0x20 && *b != b'\t') || *b == 0x7f)
                || [
                    b"content-length".as_slice(),
                    b"content-type",
                    b"transfer-encoding",
                    b"connection",
                ]
                .iter()
                .any(|name| h.name.eq_ignore_ascii_case(name))
            {
                return Err(Error::InvalidInput);
            }
        }
        let (mut status, mut length) = ([0u8; 3], [0u8; 20]);
        let mut value = self.status;
        for i in (0..3).rev() {
            status[i] = b'0' + (value % 10) as u8;
            value /= 10;
        }
        let mut value = self.body.len();
        let mut begin = length.len();
        loop {
            begin -= 1;
            length[begin] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        let reason = match self.status {
            200 => b"OK".as_slice(),
            201 => b"Created",
            204 => b"No Content",
            400 => b"Bad Request",
            401 => b"Unauthorized",
            403 => b"Forbidden",
            404 => b"Not Found",
            405 => b"Method Not Allowed",
            409 => b"Conflict",
            413 => b"Content Too Large",
            415 => b"Unsupported Media Type",
            417 => b"Expectation Failed",
            431 => b"Request Header Fields Too Large",
            500 => b"Internal Server Error",
            501 => b"Not Implemented",
            502 => b"Bad Gateway",
            503 => b"Service Unavailable",
            504 => b"Gateway Timeout",
            _ => b"",
        };
        let mut at = 0usize;
        for part in [
            b"HTTP/1.1 ".as_slice(),
            &status,
            b" ",
            reason,
            b"\r\nContent-Type: ",
            self.content_type,
            b"\r\n",
        ] {
            append(&mut out, &mut at, part)?;
        }
        for h in self.headers {
            for part in [h.name, b": ", h.value, b"\r\n"] {
                append(&mut out, &mut at, part)?;
            }
        }
        if self.status != 204 {
            for part in [b"Content-Length: ".as_slice(), &length[begin..], b"\r\n"] {
                append(&mut out, &mut at, part)?;
            }
        }
        for part in [
            b"Connection: close\r\n\r\n".as_slice(),
            if self.head_only { b"" } else { self.body },
        ] {
            append(&mut out, &mut at, part)?;
        }
        Ok(at)
    }
}
impl core::fmt::Debug for Response<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

fn append(out: &mut Option<&mut [u8]>, at: &mut usize, part: &[u8]) -> Result<(), Error> {
    let end = at.checked_add(part.len()).ok_or(Error::Overflow)?;
    if let Some(out) = out.as_mut() {
        out.get_mut(*at..end)
            .ok_or(Error::Capacity)?
            .copy_from_slice(part);
    }
    *at = end;
    Ok(())
}
