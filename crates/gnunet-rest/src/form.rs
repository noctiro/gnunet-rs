//! Bounded actual MHD form contracts: urlencoded and multipart/form-data fields.
//! The complete original HTTP body is already framed; no upload/socket is owned.
use gnunet_types::Error;
/// Finite original body, metadata, part/value and scanning bounds.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Complete input body bytes, including boundaries/preamble/epilogue.
    pub bytes: usize,
    /// Maximum number of fields, including ignored file-named fields.
    pub fields: usize,
    /// Maximum headers per multipart part.
    pub headers: usize,
    /// Maximum complete header block per part.
    pub header_bytes: usize,
    /// Maximum decoded bytes in one field value.
    pub value_bytes: usize,
    /// Maximum delimiter/header comparison/scanning work.
    pub work: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            bytes: 65535,
            fields: 64,
            headers: 16,
            header_bytes: 8192,
            value_bytes: 65535,
            work: 8_388_608,
        }
    }
}
#[derive(Clone, Copy)]
enum Kind {
    Urlencoded,
    Multipart { boundary: [u8; 70], len: usize },
}
/// Complete validated original form, borrowing its source body and MIME type.
#[derive(Clone, Copy)]
pub struct Form<'a> {
    body: &'a [u8],
    kind: Kind,
    limits: Limits,
}
impl<'a> Form<'a> {
    /// Check a complete form before any field escapes. Unknown media types are
    /// Unsupported. Duplicated boundary parameters, NUL and truncated parts fail.
    pub fn new(content_type: &[u8], body: &'a [u8], limits: Limits) -> Result<Self, Error> {
        if limits.fields == 0 || limits.headers == 0 || limits.header_bytes == 0 || limits.work == 0
        {
            return Err(Error::InvalidInput);
        }
        if body.len() > limits.bytes {
            return Err(Error::TooLarge);
        }
        let split = content_type
            .iter()
            .position(|b| *b == b';')
            .unwrap_or(content_type.len());
        let media = trim(&content_type[..split]);
        let kind = if media.eq_ignore_ascii_case(b"application/x-www-form-urlencoded") {
            Kind::Urlencoded
        } else if media.eq_ignore_ascii_case(b"multipart/form-data") {
            let mut boundary = None;
            for parameter in Parameters::new(&content_type[split..]) {
                let (name, value) = parameter?;
                if name.eq_ignore_ascii_case(b"boundary") {
                    if boundary.is_some() {
                        return Err(Error::Conflict);
                    }
                    let mut bytes = [0u8; 70];
                    let mut len = 0usize;
                    let mut escape = false;
                    for b in value.raw {
                        if value.escaped && *b == b'\\' && !escape {
                            escape = true;
                            continue;
                        }
                        if !b.is_ascii_alphanumeric()
                            && !matches!(
                                b,
                                b' ' | b'\''
                                    | b'('
                                    | b')'
                                    | b'+'
                                    | b'_'
                                    | b','
                                    | b'-'
                                    | b'.'
                                    | b'/'
                                    | b':'
                                    | b'='
                                    | b'?'
                            )
                        {
                            return Err(Error::Malformed);
                        }
                        *bytes.get_mut(len).ok_or(Error::TooLarge)? = *b;
                        len += 1;
                        escape = false;
                    }
                    if escape || len == 0 || bytes[len - 1] == b' ' {
                        return Err(Error::Malformed);
                    }
                    boundary = Some((bytes, len));
                }
            }
            let (boundary, len) = boundary.ok_or(Error::Malformed)?;
            Kind::Multipart { boundary, len }
        } else {
            return Err(Error::Unsupported);
        };
        let form = Self { body, kind, limits };
        match kind {
            Kind::Urlencoded => {
                let mut work = limits.work;
                let mut count = 0;
                for field in body.split(|b| *b == b'&').filter(|b| !b.is_empty()) {
                    count += 1;
                    if count > limits.fields {
                        return Err(Error::Capacity);
                    }
                    let equal = field.iter().position(|b| *b == b'=').unwrap_or(field.len());
                    component(&field[..equal], limits.header_bytes, &mut work)?;
                    component(
                        if equal < field.len() {
                            &field[equal + 1..]
                        } else {
                            &[]
                        },
                        limits.value_bytes,
                        &mut work,
                    )?;
                }
            }
            Kind::Multipart { .. } => {
                for field in form.parts() {
                    field?;
                }
            }
        }
        Ok(form)
    }
    /// Read one exact field into caller scratch/output. Duplicated requested field
    /// names are Conflict, including across file/form parts. Capacity changes no
    /// output. URL form '+' decodes to space; multipart '+' remains literal.
    pub fn get(
        self,
        key: &[u8],
        key_scratch: &mut [u8],
        out: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        match self.kind {
            Kind::Urlencoded => {
                crate::route::Query::new(self.body).get_bytes(key, key_scratch, out)
            }
            Kind::Multipart { .. } => {
                let mut value = None;
                for field in self.parts() {
                    let field = field?;
                    if !field.name.equals(key) {
                        continue;
                    }
                    if value.is_some() {
                        return Err(Error::Conflict);
                    }
                    value = Some(field.value);
                }
                let Some(value) = value else { return Ok(None) };
                let output = out.get_mut(..value.len()).ok_or(Error::Capacity)?;
                output.copy_from_slice(value);
                Ok(Some(value.len()))
            }
        }
    }
    fn parts(self) -> Parts<'a> {
        Parts {
            body: self.body,
            boundary: match self.kind {
                Kind::Multipart { boundary, .. } => boundary,
                Kind::Urlencoded => [0; 70],
            },
            boundary_len: match self.kind {
                Kind::Multipart { len, .. } => len,
                Kind::Urlencoded => 0,
            },
            at: 0,
            first: true,
            ended: false,
            count: 0,
            limits: self.limits,
            work: self.limits.work,
        }
    }
}
impl core::fmt::Debug for Form<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Form([REDACTED])")
    }
}
#[derive(Clone, Copy)]
struct Parameter<'a> {
    raw: &'a [u8],
    escaped: bool,
}
impl Parameter<'_> {
    fn equals(self, expected: &[u8]) -> bool {
        let mut at = 0;
        let mut escape = false;
        for b in self.raw {
            if self.escaped && *b == b'\\' && !escape {
                escape = true;
                continue;
            }
            if expected.get(at) != Some(b) {
                return false;
            }
            at += 1;
            escape = false;
        }
        at == expected.len() && !escape
    }
}
struct Parameters<'a> {
    rest: &'a [u8],
    failed: bool,
}
impl<'a> Parameters<'a> {
    fn new(rest: &'a [u8]) -> Self {
        Self {
            rest,
            failed: false,
        }
    }
    fn next_parameter(&mut self) -> Result<Option<(&'a [u8], Parameter<'a>)>, Error> {
        let rest = trim_start(self.rest);
        if rest.is_empty() {
            self.rest = &[];
            return Ok(None);
        }
        let rest = rest.strip_prefix(b";").ok_or(Error::Malformed)?;
        let rest = trim_start(rest);
        let equal = rest
            .iter()
            .position(|b| *b == b'=')
            .ok_or(Error::Malformed)?;
        let name = trim(&rest[..equal]);
        if name.is_empty() || !name.iter().all(|b| token(*b)) {
            return Err(Error::Malformed);
        }
        let rest = trim_start(&rest[equal + 1..]);
        if rest.first() == Some(&b'"') {
            let mut at = 1;
            let mut escaped = false;
            let mut any = false;
            while at < rest.len() {
                let b = rest[at];
                if b < 32 || b == 127 {
                    return Err(Error::Malformed);
                }
                if escaped {
                    escaped = false
                } else if b == b'\\' {
                    escaped = true;
                    any = true
                } else if b == b'"' {
                    let value = Parameter {
                        raw: &rest[1..at],
                        escaped: any,
                    };
                    self.rest = &rest[at + 1..];
                    let tail = trim_start(self.rest);
                    if !tail.is_empty() && tail[0] != b';' {
                        return Err(Error::Malformed);
                    }
                    return Ok(Some((name, value)));
                }
                at += 1;
            }
            Err(Error::Truncated)
        } else {
            let end = rest.iter().position(|b| *b == b';').unwrap_or(rest.len());
            let value = trim(&rest[..end]);
            if value.is_empty() || !value.iter().all(|b| token(*b)) {
                return Err(Error::Malformed);
            }
            self.rest = &rest[end..];
            Ok(Some((
                name,
                Parameter {
                    raw: value,
                    escaped: false,
                },
            )))
        }
    }
}
impl<'a> Iterator for Parameters<'a> {
    type Item = Result<(&'a [u8], Parameter<'a>), Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        match self.next_parameter() {
            Ok(Some(pair)) => Some(Ok(pair)),
            Ok(None) => None,
            Err(error) => {
                self.failed = true;
                Some(Err(error))
            }
        }
    }
}
struct Field<'a> {
    name: Parameter<'a>,
    value: &'a [u8],
}
struct Parts<'a> {
    body: &'a [u8],
    boundary: [u8; 70],
    boundary_len: usize,
    at: usize,
    first: bool,
    ended: bool,
    count: usize,
    limits: Limits,
    work: usize,
}
impl<'a> Parts<'a> {
    fn tick(&mut self, n: usize) -> Result<(), Error> {
        self.work = self.work.checked_sub(n).ok_or(Error::Capacity)?;
        Ok(())
    }
    fn delimiter(&mut self, start: usize, first: bool) -> Result<usize, Error> {
        for at in start..self.body.len() {
            self.tick(1)?;
            if self.body[at] != b'-'
                || (!first || at != 0) && self.body.get(at.saturating_sub(2)..at) != Some(b"\r\n")
            {
                continue;
            }
            self.tick(self.boundary_len + 2)?;
            if !self.body[at..].starts_with(b"--")
                || !self.body[at + 2..].starts_with(&self.boundary[..self.boundary_len])
            {
                continue;
            }
            let end = at + 2 + self.boundary_len;
            if self.body.get(end..end + 2) == Some(b"\r\n")
                || self.body.get(end..end + 2) == Some(b"--")
            {
                return Ok(at);
            }
        }
        Err(Error::Truncated)
    }
    fn field(&mut self) -> Result<Option<Field<'a>>, Error> {
        if self.ended {
            return Ok(None);
        }
        let marker = self.delimiter(self.at, self.first)?;
        self.first = false;
        let after = marker + 2 + self.boundary_len;
        if self.body.get(after..after + 2) == Some(b"--") {
            let rest = &self.body[after + 2..];
            if !rest.is_empty() && !rest.starts_with(b"\r\n") {
                return Err(Error::Malformed);
            }
            self.ended = true;
            return Ok(None);
        }
        let start = after + 2;
        let bound = self
            .body
            .len()
            .min(start.saturating_add(self.limits.header_bytes));
        let end = self.body[start..bound]
            .windows(4)
            .position(|b| b == b"\r\n\r\n")
            .map(|n| start + n)
            .ok_or(if bound == self.body.len() {
                Error::Truncated
            } else {
                Error::TooLarge
            })?;
        self.tick((end - start + 4).checked_mul(4).ok_or(Error::Overflow)?)?;
        let mut disposition = None;
        let mut count = 0;
        for line in self.body[start..end].split_inclusive(|b| *b == b'\n') {
            let line = if line.ends_with(b"\n") {
                line.strip_suffix(b"\r\n").ok_or(Error::Malformed)?
            } else {
                line
            };
            count += 1;
            if count > self.limits.headers {
                return Err(Error::Capacity);
            }
            let colon = line
                .iter()
                .position(|b| *b == b':')
                .ok_or(Error::Malformed)?;
            let name = &line[..colon];
            let value = trim(&line[colon + 1..]);
            if name.is_empty()
                || !name.iter().all(|b| token(*b))
                || value.iter().any(|b| (*b < 32 && *b != b'\t') || *b == 127)
            {
                return Err(Error::Malformed);
            }
            if name.eq_ignore_ascii_case(b"content-disposition") {
                if disposition.is_some() {
                    return Err(Error::Conflict);
                }
                disposition = Some(value);
            }
        }
        let disposition = disposition.ok_or(Error::Malformed)?;
        let split = disposition
            .iter()
            .position(|b| *b == b';')
            .unwrap_or(disposition.len());
        if !trim(&disposition[..split]).eq_ignore_ascii_case(b"form-data") {
            return Err(Error::Malformed);
        }
        let mut name = None;
        for parameter in Parameters::new(&disposition[split..]) {
            let (key, value) = parameter?;
            if key.eq_ignore_ascii_case(b"name") {
                if name.is_some() {
                    return Err(Error::Conflict);
                }
                name = Some(value);
            }
        }
        let name = name.ok_or(Error::Malformed)?;
        let value_start = end + 4;
        let next = self.delimiter(value_start, false)?;
        let value_end = next.checked_sub(2).ok_or(Error::Malformed)?;
        if value_end < value_start {
            return Err(Error::Malformed);
        }
        let value = &self.body[value_start..value_end];
        if value.len() > self.limits.value_bytes || value.contains(&0) {
            return Err(Error::TooLarge);
        }
        self.tick(value.len())?;
        self.count = self.count.checked_add(1).ok_or(Error::Overflow)?;
        if self.count > self.limits.fields {
            return Err(Error::Capacity);
        }
        self.at = next;
        Ok(Some(Field { name, value }))
    }
}
impl<'a> Iterator for Parts<'a> {
    type Item = Result<Field<'a>, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.field() {
            Ok(Some(field)) => Some(Ok(field)),
            Ok(None) => None,
            Err(error) => {
                self.ended = true;
                Some(Err(error))
            }
        }
    }
}
fn component(input: &[u8], maximum: usize, work: &mut usize) -> Result<(), Error> {
    let mut at = 0;
    let mut n = 0;
    while at < input.len() {
        *work = work.checked_sub(1).ok_or(Error::Capacity)?;
        let byte = if input[at] == b'%' {
            let h = hex(*input.get(at + 1).ok_or(Error::Malformed)?)?;
            let l = hex(*input.get(at + 2).ok_or(Error::Malformed)?)?;
            at += 3;
            (h << 4) | l
        } else {
            let b = input[at];
            at += 1;
            b
        };
        if byte == 0 {
            return Err(Error::Malformed);
        }
        n += 1;
        if n > maximum {
            return Err(Error::Capacity);
        }
    }
    Ok(())
}
fn trim_start(mut b: &[u8]) -> &[u8] {
    while b.first().is_some_and(|b| matches!(b, b' ' | b'\t')) {
        b = &b[1..]
    }
    b
}
fn trim(mut b: &[u8]) -> &[u8] {
    b = trim_start(b);
    while b.last().is_some_and(|b| matches!(b, b' ' | b'\t')) {
        b = &b[..b.len() - 1]
    }
    b
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
fn hex(b: u8) -> Result<u8, Error> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(Error::Malformed),
    }
}
