//! h3 ALPN profile over a mature HTTP/3/QPACK implementation's decoded
//! header/data callbacks. This does not encode HTTP/1 or QUIC frames.
use crate::{ClaimedPeer, Epoch, Instance, Role, Scope, Stream, request_stream};
use gnunet_types::{Error, MonoInstant};
use gnunet_wire::official::Frame;
use zeroize::Zeroize;
/// Exact HTTP/3 ALPN; raw quic ALPNs are intentionally not accepted here.
pub const ALPN: &[u8] = b"h3";
/// Original communicator address prefix.
pub const ADDRESS_PREFIX: &str = "http3";
/// Original C advertised communicator queue MTU (not UDP packet MTU).
pub const ADVERTISED_MTU: usize = 1080;
/// Pinned client's number of concurrently maintained GET long polls.
pub const LONG_POLLS: usize = 16;
/// Bounded decoded field count, including zero-length/unknown headers.
pub const MAX_HEADERS: usize = 64;
/// One decoded HTTP/3 header; values are borrowed and never reformatted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header<'a> {
    /// Lowercase HTTP/3/QPACK header name.
    pub name: &'a [u8],
    /// Exact header value.
    pub value: &'a [u8],
}
const EMPTY: Header<'static> = Header {
    name: b"",
    value: b"",
};
/// Fixed bounded canonical header list, submitted to an actual HTTP/3 library.
pub struct HeaderBlock<'a> {
    fields: [Header<'a>; 7],
    len: usize,
}
impl HeaderBlock<'_> {
    /// Actual initialized decoded header list; no H1 bytes.
    pub fn as_slice(&self) -> &[Header<'_>] {
        &self.fields[..self.len]
    }
}
/// Actual wire method/original request purpose. Identity and Message both POST
/// the same canonical headers and are distinguished by the original stream job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Initiator's first POST (client bidi stream0), raw32 public id.
    IdentityPost,
    /// Subsequent POST containing one complete GNUnet frame.
    MessagePost,
    /// Bodyless GET; original finite long-poll response owner.
    Get,
}
/// Decimal content length, without NUL. Capacity failure leaves output intact.
pub fn decimal(mut number: usize, out: &mut [u8]) -> Result<&[u8], Error> {
    let mut digits = [0u8; 20];
    let mut begin = digits.len();
    loop {
        begin -= 1;
        digits[begin] = b'0' + (number % 10) as u8;
        number /= 10;
        if number == 0 {
            break;
        }
    }
    let len = digits.len() - begin;
    let dst = out.get_mut(..len).ok_or(Error::Capacity)?;
    dst.copy_from_slice(&digits[begin..]);
    Ok(dst)
}
/// Canonical official request fields. authority is the original peer address
/// string supplied by the caller, never a new DNS resolution or peer proof.
pub fn request_headers<'a>(
    kind: Kind,
    authority: &'a [u8],
    body_len: usize,
    length: &'a mut [u8],
) -> Result<HeaderBlock<'a>, Error> {
    if authority.is_empty() || authority.iter().any(|b| *b <= 32 || *b == 127) {
        return Err(Error::InvalidInput);
    }
    if kind == Kind::Get && body_len != 0
        || kind == Kind::IdentityPost && body_len != 32
        || kind == Kind::MessagePost && !(4..=65535).contains(&body_len)
    {
        return Err(Error::InvalidInput);
    }
    let mut fields = [EMPTY; 7];
    fields[0] = Header {
        name: b":method",
        value: if kind == Kind::Get { b"GET" } else { b"POST" },
    };
    fields[1] = Header {
        name: b":scheme",
        value: b"https",
    };
    fields[2] = Header {
        name: b":authority",
        value: authority,
    };
    fields[3] = Header {
        name: b":path",
        value: b"/",
    };
    fields[4] = Header {
        name: b"user-agent",
        value: b"gnunet-rs",
    };
    let len = if kind == Kind::Get {
        5
    } else {
        fields[5] = Header {
            name: b"content-type",
            value: b"application/octet-stream",
        };
        fields[6] = Header {
            name: b"content-length",
            value: decimal(body_len, length)?,
        };
        7
    };
    Ok(HeaderBlock { fields, len })
}
/// Canonical response headers:200 with optional one-frame body, or204 empty
/// GET timeout. status/body validity is checked before caller output is changed.
pub fn response_headers<'a>(
    status: u16,
    body_len: Option<usize>,
    length: &'a mut [u8],
) -> Result<HeaderBlock<'a>, Error> {
    if !matches!(status, 200 | 204)
        || body_len.is_some_and(|n| n > 65535)
        || status == 204 && body_len.is_some_and(|n| n != 0)
    {
        return Err(Error::InvalidInput);
    }
    let mut fields = [EMPTY; 7];
    fields[0] = Header {
        name: b":status",
        value: if status == 200 { b"200" } else { b"204" },
    };
    fields[1] = Header {
        name: b"server",
        value: b"gnunet-rs",
    };
    let len = if let Some(n) = body_len {
        if status == 204 {
            2
        } else {
            fields[2] = Header {
                name: b"content-type",
                value: b"application/octet-stream",
            };
            fields[3] = Header {
                name: b"content-length",
                value: decimal(n, length)?,
            };
            4
        }
    } else {
        2
    };
    Ok(HeaderBlock { fields, len })
}
fn content_length(bytes: &[u8]) -> Result<usize, Error> {
    if bytes.is_empty() {
        return Err(Error::Malformed);
    }
    bytes.iter().try_fold(0usize, |n, b| {
        if !b.is_ascii_digit() {
            return Err(Error::Malformed);
        }
        n.checked_mul(10)
            .and_then(|n| n.checked_add(usize::from(*b - b'0')))
            .ok_or(Error::Overflow)
    })
}
fn checked_headers(headers: &[Header<'_>], budget: usize) -> Result<(), Error> {
    if headers.len() > MAX_HEADERS {
        return Err(Error::TooLarge);
    }
    let mut bytes = 0usize;
    for h in headers {
        bytes = bytes
            .checked_add(h.name.len())
            .and_then(|n| n.checked_add(h.value.len()))
            .ok_or(Error::Overflow)?;
        if bytes > budget {
            return Err(Error::TooLarge);
        }
    }
    Ok(())
}
fn single<'a>(headers: &[Header<'a>], name: &[u8]) -> Result<Option<&'a [u8]>, Error> {
    let mut found = None;
    for h in headers {
        if h.name == name {
            if found.is_some() {
                return Err(Error::Conflict);
            }
            found = Some(h.value)
        }
    }
    Ok(found)
}
/// Canonical parsed request contract. Unknown ordinary headers remain caller
/// input; no authentication/peer claim is extracted from authority/user-agent.
#[derive(Clone, Copy, Debug)]
pub struct RequestHead<'a> {
    /// Exact GET or POST method.
    pub method: &'a [u8],
    /// Original authority metadata.
    pub authority: &'a [u8],
    /// Optional actual declared body bytes.
    pub length: Option<usize>,
}
/// Parse actual decoded HTTP3 request headers, bounded by total name/value bytes.
/// The mature HTTP3 stack remains responsible for HTTP3/QPACK pseudoheader rules.
pub fn parse_request<'a>(headers: &[Header<'a>], budget: usize) -> Result<RequestHead<'a>, Error> {
    checked_headers(headers, budget)?;
    let method = single(headers, b":method")?.ok_or(Error::Malformed)?;
    if method != b"POST" && method != b"GET" {
        return Err(Error::Unsupported);
    }
    if single(headers, b":scheme")? != Some(b"https") || single(headers, b":path")? != Some(b"/") {
        return Err(Error::Unsupported);
    }
    let authority = single(headers, b":authority")?.ok_or(Error::Malformed)?;
    if authority.is_empty() {
        return Err(Error::Malformed);
    }
    if let Some(kind) = single(headers, b"content-type")?
        && kind != b"application/octet-stream"
    {
        return Err(Error::Unsupported);
    }
    let length = single(headers, b"content-length")?
        .map(content_length)
        .transpose()?;
    if method == b"GET" && length.is_some_and(|n| n != 0) {
        return Err(Error::Malformed);
    }
    Ok(RequestHead {
        method,
        authority,
        length,
    })
}
/// Parsed response status/body contract; no200 network/application success claim.
#[derive(Clone, Copy, Debug)]
pub struct ResponseHead {
    /// Official application response status,200 or204.
    pub status: u16,
    /// Optional actual body length.
    pub length: Option<usize>,
}
/// Parse actual decoded HTTP3 response headers. Every unknown status remains an
/// explicit unsupported result; it is not converted into successful empty data.
pub fn parse_response(headers: &[Header<'_>], budget: usize) -> Result<ResponseHead, Error> {
    checked_headers(headers, budget)?;
    let status = match single(headers, b":status")? {
        Some(b"200") => 200,
        Some(b"204") => 204,
        _ => return Err(Error::Unsupported),
    };
    if let Some(kind) = single(headers, b"content-type")?
        && kind != b"application/octet-stream"
    {
        return Err(Error::Unsupported);
    }
    let length = single(headers, b"content-length")?
        .map(content_length)
        .transpose()?;
    if status == 204 && length.is_some_and(|n| n != 0) {
        return Err(Error::Malformed);
    }
    Ok(ResponseHead { status, length })
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Empty,
    Identity,
    Frame,
    OptionalFrame,
}
/// One caller-owned stream body slab. Construct fresh before Session::new;
/// a slot is reusable only after its original token is explicitly released.
pub struct Slot<'id, 'buf> {
    token: Option<Stream<'id>>,
    buffer: &'buf mut [u8],
    used: usize,
    kind: Kind,
    mode: Mode,
    declared: Option<usize>,
    until: MonoInstant,
    headers: bool,
    ended: bool,
    consumed: bool,
    response_started: bool,
}
impl<'buf> Slot<'_, 'buf> {
    /// Fresh empty caller-owned stream storage.
    pub fn new(buffer: &'buf mut [u8]) -> Self {
        Self {
            token: None,
            buffer,
            used: 0,
            kind: Kind::Get,
            mode: Mode::Empty,
            declared: None,
            until: MonoInstant(0),
            headers: false,
            ended: false,
            consumed: false,
            response_started: false,
        }
    }
    fn clear(&mut self) {
        self.buffer[..self.used].zeroize();
        self.used = 0;
        self.token = None;
        self.headers = false;
        self.ended = false;
        self.consumed = false;
        self.response_started = false;
    }
}
impl Drop for Slot<'_, '_> {
    fn drop(&mut self) {
        self.buffer.zeroize()
    }
}
/// Explicit caller quotas. Slabs need only max_body bytes, not64KiB per stream.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum one-frame/identity body,32..65535.
    pub max_body: usize,
    /// Decoded header bytes per original stream.
    pub header_bytes: usize,
    /// Active GET slots,1..16 for official profile.
    pub polls: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body: 1452,
            header_bytes: 4096,
            polls: LONG_POLLS,
        }
    }
}
/// Explicit original source bounds/role and caller resource policy.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Original local source role, not remote authentication.
    pub role: Role,
    /// Original fixed finite source deadline.
    pub until: MonoInstant,
    /// Independent bounded stream/header/body quotas.
    pub limits: Limits,
}
/// One completed original body. Peer is only public claimed/requested metadata.
pub struct Delivery<'a, 'id> {
    /// Exact local original stream/source.
    pub stream: Stream<'id>,
    /// Unverified expected/received peer proposal.
    pub peer: ClaimedPeer,
    /// Exactly one complete original GNUnet frame.
    pub frame: &'a [u8],
}
/// Bounded HTTP3 application owner over real runtime-supplied decoded callbacks.
/// It neither opens a socket nor implements/claims QPACK, QUIC or TLS success.
pub struct Session<'id, 'slots, 'buf> {
    scope: Scope<'id>,
    role: Role,
    peer: Option<ClaimedPeer>,
    slots: &'slots mut [Slot<'id, 'buf>],
    limits: Limits,
    cursor: usize,
    identity_opened: bool,
}
impl<'id, 'slots, 'buf> Session<'id, 'slots, 'buf> {
    /// Validate actual negotiated h3 ALPN and all caller storage before source
    /// allocation. Original native/TLS lifecycle remains with the future host.
    pub fn new(
        instance: &'id Instance,
        now: MonoInstant,
        alpn: &[u8],
        slots: &'slots mut [Slot<'id, 'buf>],
        options: Options,
    ) -> Result<Self, Error> {
        Self::new_in(instance, now, alpn, &mut Some(slots), options)
    }
    /// Validate the original source and slot slabs before taking their loan.
    /// Every failed admission leaves the caller's exact slot slice available;
    /// no parsing, clock allocation failure or capacity refusal loses a pool row.
    pub fn new_in(
        instance: &'id Instance,
        now: MonoInstant,
        alpn: &[u8],
        loan: &mut Option<&'slots mut [Slot<'id, 'buf>]>,
        options: Options,
    ) -> Result<Self, Error> {
        let Options {
            role,
            until,
            limits,
        } = options;
        if alpn != ALPN {
            return Err(Error::Unsupported);
        }
        let slots = loan.as_ref().ok_or(Error::InvalidInput)?;
        if !(32..=65535).contains(&limits.max_body)
            || limits.header_bytes == 0
            || !(1..=LONG_POLLS).contains(&limits.polls)
            || slots.is_empty()
        {
            return Err(Error::InvalidInput);
        }
        if slots.iter().any(|s| s.token.is_some()) {
            return Err(Error::Conflict);
        }
        if slots.iter().any(|s| s.buffer.len() < limits.max_body) {
            return Err(Error::Capacity);
        }
        let scope = Scope::new(instance, until, now)?;
        // All fallible validation and checked source allocation is complete.
        // The remaining construction cannot fail after consuming this loan.
        let slots = loan.take().ok_or(Error::InvalidInput)?;
        let peer = match role {
            Role::Initiator { expected } => Some(ClaimedPeer(expected)),
            Role::Acceptor => None,
        };
        Ok(Self {
            scope,
            role,
            peer,
            slots,
            limits,
            cursor: 0,
            identity_opened: false,
        })
    }
    fn index(&self, stream: Stream<'id>) -> Result<usize, Error> {
        if stream.epoch != self.scope.epoch {
            return Err(Error::Stale);
        }
        self.slots
            .iter()
            .position(|s| s.token == Some(stream))
            .ok_or(Error::Stale)
    }
    fn live_index(&self, stream: Stream<'id>, now: MonoInstant) -> Result<usize, Error> {
        self.scope.live(now)?;
        let i = self.index(stream)?;
        if now.0 >= self.slots[i].until.0 {
            return Err(Error::Deadline);
        }
        Ok(i)
    }
    fn open(
        &mut self,
        id: u64,
        kind: Kind,
        until: MonoInstant,
        now: MonoInstant,
    ) -> Result<Stream<'id>, Error> {
        self.scope.live(now)?;
        request_stream(id)?;
        let until = MonoInstant(until.0.min(self.scope.until.0));
        if now.0 >= until.0 {
            return Err(Error::Deadline);
        }
        if self
            .slots
            .iter()
            .any(|s| s.token.is_some_and(|t| t.id == id))
        {
            return Err(Error::Conflict);
        }
        if id == 0 && kind != Kind::IdentityPost {
            return Err(Error::InvalidInput);
        }
        if kind == Kind::IdentityPost && (id != 0 || self.identity_opened) {
            return Err(Error::Conflict);
        }
        if kind == Kind::Get
            && self
                .slots
                .iter()
                .filter(|s| s.token.is_some() && s.kind == Kind::Get)
                .count()
                == self.limits.polls
        {
            return Err(Error::Capacity);
        }
        let i = self
            .slots
            .iter()
            .position(|s| s.token.is_none())
            .ok_or(Error::Capacity)?;
        let token = Stream {
            epoch: self.scope.epoch,
            serial: self.scope.epoch.instance.allocate()?,
            id,
        };
        let slot = &mut self.slots[i];
        slot.token = Some(token);
        slot.kind = kind;
        slot.until = until;
        if kind == Kind::IdentityPost {
            self.identity_opened = true
        }
        Ok(token)
    }
    /// Original initiator request was assigned this actual bidi stream id.
    /// Header submission/QUIC plaintext acceptance remain separate runtime facts.
    pub fn open_request(
        &mut self,
        id: u64,
        kind: Kind,
        until: MonoInstant,
        now: MonoInstant,
    ) -> Result<Stream<'id>, Error> {
        if self.role == Role::Acceptor {
            return Err(Error::Unsupported);
        }
        if kind != Kind::IdentityPost && !self.identity_opened {
            return Err(Error::NotReady);
        }
        self.open(id, kind, until, now)
    }
    /// Acceptor admits actual decoded original request headers. Stream0 is the
    /// canonical first identity POST; following requests may arrive out of order
    /// but frames cannot be delivered until that identity body actually completes.
    pub fn accept_request(
        &mut self,
        id: u64,
        headers: &[Header<'_>],
        until: MonoInstant,
        now: MonoInstant,
    ) -> Result<Stream<'id>, Error> {
        if self.role != Role::Acceptor {
            return Err(Error::Unsupported);
        }
        let head = parse_request(headers, self.limits.header_bytes)?;
        let kind = if head.method == b"GET" {
            Kind::Get
        } else if id == 0 {
            Kind::IdentityPost
        } else {
            Kind::MessagePost
        };
        let mode = match kind {
            Kind::Get => Mode::Empty,
            Kind::IdentityPost => Mode::Identity,
            Kind::MessagePost => Mode::Frame,
        };
        if head.length.is_some_and(|n| n > self.limits.max_body) {
            return Err(Error::TooLarge);
        }
        if mode == Mode::Identity && head.length.is_some_and(|n| n != 32) {
            return Err(Error::Malformed);
        }
        let token = self.open(id, kind, until, now)?;
        let i = self.index(token)?;
        let slot = &mut self.slots[i];
        slot.mode = mode;
        slot.declared = head.length;
        slot.headers = true;
        Ok(token)
    }
    /// Bind actual response headers to the exact original request lease, never a
    /// reused numeric stream.200 may piggyback one frame on a POST response.
    pub fn accept_response(
        &mut self,
        token: Stream<'id>,
        headers: &[Header<'_>],
        now: MonoInstant,
    ) -> Result<(), Error> {
        if self.role == Role::Acceptor {
            return Err(Error::Unsupported);
        }
        let i = self.live_index(token, now)?;
        if self.slots[i].headers {
            return Err(Error::Conflict);
        }
        let head = parse_response(headers, self.limits.header_bytes)?;
        if head.status == 204 && self.slots[i].kind != Kind::Get {
            return Err(Error::Malformed);
        }
        if head.length.is_some_and(|n| n > self.limits.max_body) {
            return Err(Error::TooLarge);
        }
        let slot = &mut self.slots[i];
        slot.mode = if head.status == 204 {
            Mode::Empty
        } else if slot.kind == Kind::Get {
            Mode::Frame
        } else {
            Mode::OptionalFrame
        };
        slot.declared = head.length;
        slot.headers = true;
        Ok(())
    }
    /// Copy only actual HTTP3 DATA bytes. Zero/partial callbacks are normal.
    /// No complete-body/communicator admission is claimed before actual FIN.
    pub fn push_body(
        &mut self,
        token: Stream<'id>,
        bytes: &[u8],
        now: MonoInstant,
    ) -> Result<usize, Error> {
        let i = self.live_index(token, now)?;
        let slot = &mut self.slots[i];
        if !slot.headers || slot.ended {
            return Err(Error::NotReady);
        }
        let next = slot.used.checked_add(bytes.len()).ok_or(Error::Overflow)?;
        let max = match slot.mode {
            Mode::Empty => 0,
            Mode::Identity => 32,
            _ => self.limits.max_body,
        };
        if next > max || slot.declared.is_some_and(|n| next > n) {
            return Err(Error::TooLarge);
        }
        slot.buffer[slot.used..next].copy_from_slice(bytes);
        slot.used = next;
        Ok(bytes.len())
    }
    /// Actual end-of-body callback; validate the entire original canonical body.
    /// No dropped suffix, callback-sized frame assumption, or read past DATA.
    pub fn finish_body(&mut self, token: Stream<'id>, now: MonoInstant) -> Result<(), Error> {
        let i = self.live_index(token, now)?;
        let slot = &mut self.slots[i];
        if !slot.headers || slot.ended {
            return Err(Error::Conflict);
        }
        if slot.declared.is_some_and(|n| n != slot.used) {
            return Err(Error::Truncated);
        }
        match slot.mode {
            Mode::Empty => {
                if slot.used != 0 {
                    return Err(Error::Malformed);
                }
            }
            Mode::Identity => {
                let bytes: [u8; 32] = slot.buffer[..slot.used]
                    .try_into()
                    .map_err(|_| Error::Truncated)?;
                self.peer = Some(ClaimedPeer(bytes));
            }
            Mode::Frame => {
                Frame::decode(&slot.buffer[..slot.used])?;
            }
            Mode::OptionalFrame => {
                if slot.used != 0 {
                    Frame::decode(&slot.buffer[..slot.used])?;
                }
            }
        }
        slot.ended = true;
        Ok(())
    }
    /// One complete actual body, only after original FIN and original peer
    /// proposal availability. Empty replies/identity are not fabricated frames.
    pub fn delivery(
        &self,
        token: Stream<'id>,
        now: MonoInstant,
    ) -> Result<Option<Delivery<'_, 'id>>, Error> {
        let i = self.live_index(token, now)?;
        let slot = &self.slots[i];
        if !slot.ended || slot.consumed {
            return Err(Error::NotReady);
        }
        if slot.mode == Mode::Identity || slot.used == 0 {
            return Ok(None);
        }
        Ok(Some(Delivery {
            stream: token,
            peer: self.peer.ok_or(Error::NotReady)?,
            frame: &slot.buffer[..slot.used],
        }))
    }
    /// Actual original body was handled/copied by caller; reclaim its local
    /// storage while keeping this original stream available for its response.
    /// Returned bytes may inform actual QUIC credit, but are not wire ACK.
    pub fn consume(&mut self, token: Stream<'id>) -> Result<usize, Error> {
        let i = self.index(token)?;
        let slot = &mut self.slots[i];
        if !slot.ended || slot.consumed {
            return Err(Error::NotReady);
        }
        let bytes = slot.used;
        slot.buffer[..bytes].zeroize();
        slot.used = 0;
        slot.consumed = true;
        Ok(bytes)
    }
    /// Fair original GET ready for one server response. A mature runtime can
    /// bind a real queued frame to this token; no message is dequeued here.
    pub fn next_poll(&mut self, now: MonoInstant) -> Result<Option<Stream<'id>>, Error> {
        self.scope.live(now)?;
        if self.peer.is_none() {
            return Ok(None);
        }
        let n = self.slots.len();
        for _ in 0..n {
            let i = self.cursor % n;
            self.cursor = self.cursor.wrapping_add(1);
            let s = &self.slots[i];
            if s.token.is_some()
                && s.kind == Kind::Get
                && s.ended
                && !s.response_started
                && now.0 < s.until.0
            {
                return Ok(s.token);
            }
        }
        Ok(None)
    }
    /// Exact server response contract before real HTTP3 submission. A frame
    /// remains caller-owned immutable bytes; no provider/write ACK is inferred.
    pub fn start_response(
        &mut self,
        token: Stream<'id>,
        body: Option<&[u8]>,
        now: MonoInstant,
    ) -> Result<u16, Error> {
        if self.role != Role::Acceptor {
            return Err(Error::Unsupported);
        }
        self.scope.live(now)?;
        let i = self.index(token)?;
        let s = &self.slots[i];
        if !s.ended || !s.consumed || s.response_started {
            return Err(Error::NotReady);
        }
        let status = if let Some(bytes) = body {
            if self.peer.is_none() {
                return Err(Error::NotReady);
            }
            if now.0 >= s.until.0 {
                return Err(Error::Deadline);
            }
            if bytes.len() > self.limits.max_body {
                return Err(Error::TooLarge);
            }
            Frame::decode(bytes)?;
            200
        } else if s.kind == Kind::Get {
            if now.0 < s.until.0 {
                return Err(Error::NotReady);
            }
            204
        } else {
            if now.0 >= s.until.0 {
                return Err(Error::Deadline);
            }
            200
        };
        self.slots[i].response_started = true;
        Ok(status)
    }
    /// Original actual stream completion/reset/connection-loss cleanup. Clears
    /// only that original token; cancellation never implies unsent bytes.
    pub fn release(&mut self, token: Stream<'id>) -> Result<(), Error> {
        let i = self.index(token)?;
        self.slots[i].clear();
        Ok(())
    }
    /// One original finite stream timeout; caller must enact actual stream
    /// cancellation/204 response and preserve any independently exposed TX debt.
    pub fn expired(&self, now: MonoInstant) -> Option<Stream<'id>> {
        // This is an actual time observation, even though the returned token
        // grants cleanup only. Never revive a reported expired stream by later
        // passing a smaller timestamp to a fresh response/body submission.
        let observed = self.scope.last.get().max(now.0);
        self.scope.last.set(observed);
        self.slots
            .iter()
            .find(|s| s.token.is_some() && observed >= s.until.0)
            .and_then(|s| s.token)
    }
    /// Readonly original source/peer metadata; no TLS authentication statement.
    pub const fn peer(&self) -> Option<ClaimedPeer> {
        self.peer
    }
    /// Exact original source identity, not a wire epoch.
    pub const fn epoch(&self) -> Epoch<'id> {
        self.scope.epoch
    }
    /// Check this original fixed source deadline and greatest time observation.
    /// Success grants no handshake, identity, stream or provider-admission proof.
    pub fn check_live(&self, now: MonoInstant) -> Result<(), Error> {
        self.scope.live(now)
    }
    /// Consume this local application owner, wipe every whole caller body slab
    /// and return its original slot slice. This grants no stream reset, socket
    /// close, IPC-FC or peer-processing receipt; those remain native obligations.
    pub fn recycle(mut self) -> &'slots mut [Slot<'id, 'buf>] {
        self.retire();
        for slot in self.slots.iter_mut() {
            slot.buffer.zeroize();
        }
        core::mem::take(&mut self.slots)
    }
    /// Clock-free retirement; actual stream reset/connection teardown must still
    /// be performed by the runtime before it reports physical source closed.
    pub fn retire(&mut self) {
        self.scope.closed = true;
        for slot in self.slots.iter_mut() {
            slot.clear()
        }
        self.peer = None;
    }
}
