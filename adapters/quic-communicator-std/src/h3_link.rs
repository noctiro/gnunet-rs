//! Actual bounded HTTP/3 application IO on the original established Quinn
//! connection. No background task, self-borrowing future, protocol retry or
//! authenticated peer constructor is hidden in this owner.
use crate::raw::{SendId, Step};
use bytes::{Buf, Bytes};
use gnunet_transport_quic::{Instance, Role, Stream, h3 as profile};
use gnunet_types::{Error as Protocol, MonoInstant};
use std::{
    cell::Cell,
    fmt,
    future::Future,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
use zeroize::Zeroizing;

type Backend = h3_quinn::Connection;
type Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type ClientDriver = h3::client::Connection<Backend, Bytes>;
type ServerDriver = h3::server::Connection<Backend, Bytes>;
type Resolver = h3::server::RequestResolver<Backend, Bytes>;
type ClientRequest = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type ClientReceive = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;
type ClientSend = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type ServerRequest = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type ServerReceive = h3::server::RequestStream<h3_quinn::RecvStream, Bytes>;
type ServerSend = h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type Task<T> = Pin<Box<dyn Future<Output = Result<T, Failure>> + 'static>>;
type AcceptTask = Pin<Box<dyn Future<Output = Accepted> + 'static>>;
// Keep our original immutable payload allocation erased even when h3/Quinn
// retain Bytes slices/clones after a local future completes or is cancelled.
// This does not make claims about independent copies in the mature backend.
struct Erased(Zeroizing<Vec<u8>>);
impl AsRef<[u8]> for Erased {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}
fn owned_bytes(bytes: Vec<u8>) -> Bytes {
    Bytes::from_owner(Erased(Zeroizing::new(bytes)))
}
fn copy_body(bytes: &[u8]) -> Result<Bytes, Failure> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| Protocol::Capacity)?;
    owned.extend_from_slice(bytes);
    Ok(owned_bytes(owned))
}

/// Actual original HTTP/QUIC/protocol refusal, without body/key diagnostics.
#[derive(Debug)]
pub enum Failure {
    /// Original local quota, source or canonical profile refusal.
    Protocol(Protocol),
    /// Actual original Quinn connection error.
    Connection(quinn::ConnectionError),
    /// Actual HTTP/3 connection/control error.
    Http3Connection(h3::error::ConnectionError),
    /// Actual HTTP/3 original stream error.
    Http3Stream(h3::error::StreamError),
    /// Actual checked HTTP request/response construction error.
    Http(http::Error),
    /// Actual checked ordinary header-name construction error.
    HeaderName(http::header::InvalidHeaderName),
    /// Actual checked ordinary header-value construction error.
    HeaderValue(http::header::InvalidHeaderValue),
    /// The original admitted SEND has no whole provider acceptance. h3's public
    /// send_data API cannot report its accepted partial prefix; even known=0
    /// confers no Unsent proof. The original future is not reconstructed/replayed.
    SendOutcomeUnknown {
        /// Exact original local SEND, never a newly minted callback token.
        id: SendId,
        /// Only positively known body bytes; zero may still have been exposed.
        known: usize,
        /// Original immutable application frame size.
        total: usize,
        /// Original source/deadline/stream failure.
        cause: Box<Failure>,
    },
}
impl From<Protocol> for Failure {
    fn from(error: Protocol) -> Self {
        Self::Protocol(error)
    }
}
impl From<h3::error::StreamError> for Failure {
    fn from(error: h3::error::StreamError) -> Self {
        Self::Http3Stream(error)
    }
}
impl From<h3::error::ConnectionError> for Failure {
    fn from(error: h3::error::ConnectionError) -> Self {
        Self::Http3Connection(error)
    }
}
impl From<http::Error> for Failure {
    fn from(error: http::Error) -> Self {
        Self::Http(error)
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "HTTP3 application: {error}"),
            Self::Connection(error) => write!(f, "HTTP3 original QUIC: {error}"),
            Self::Http3Connection(error) => write!(f, "HTTP3 control: {error}"),
            Self::Http3Stream(error) => write!(f, "HTTP3 stream: {error}"),
            Self::Http(error) => write!(f, "HTTP3 request/response: {error}"),
            Self::HeaderName(error) => write!(f, "HTTP3 header name: {error}"),
            Self::HeaderValue(error) => write!(f, "HTTP3 header value: {error}"),
            Self::SendOutcomeUnknown {
                id,
                known,
                total,
                cause,
            } => write!(
                f,
                "HTTP3 original SEND {id:?} outcome unknown known={known}/{total}: {cause}"
            ),
        }
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connection(error) => Some(error),
            Self::Http3Connection(error) => Some(error),
            Self::Http3Stream(error) => Some(error),
            Self::Http(error) => Some(error),
            Self::HeaderName(error) => Some(error),
            Self::HeaderValue(error) => Some(error),
            Self::SendOutcomeUnknown { cause, .. } => Some(cause.as_ref()),
            Self::Protocol(_) => None,
        }
    }
}
impl Failure {
    /// Exact original uncertain SEND attribution. Ordinary unrelated failures do
    /// not manufacture an application SEND identity or a zero-prefix success.
    pub fn send_unknown(&self) -> Option<(SendId, usize, usize)> {
        match self {
            Self::SendOutcomeUnknown {
                id, known, total, ..
            } => Some((*id, *known, *total)),
            _ => None,
        }
    }
}
/// Original source role, fixed independent native lifetime and resource policy.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Options {
    pub(crate) local: [u8; 32],
    pub(crate) profile: profile::Options,
    pub(crate) hard: Instant,
    pub(crate) request_timeout: Duration,
    pub(crate) max_requests: u64,
}
/// Private original pure stream/source token; numeric HTTP stream IDs alone
/// cannot complete a newer delivery or a different source's retained FC debt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FrameId<'id>(Stream<'id>);
pub(crate) struct FrameView<'a, 'id> {
    pub(crate) id: FrameId<'id>,
    pub(crate) bytes: &'a [u8],
}
#[derive(Default)]
struct Acceptance {
    known: Cell<usize>,
    polled: Cell<bool>,
}
struct Sending {
    id: SendId,
    body: Option<Bytes>,
    total: usize,
    hard: Instant,
    marks: Rc<Acceptance>,
    reported: bool,
}
struct Accepted {
    server: ServerDriver,
    request: Result<Option<Resolver>, h3::error::ConnectionError>,
}
enum Built {
    Client(ClientDriver, Sender),
    Server(ServerDriver),
}
enum Mode {
    Build(Task<Built>),
    Client {
        driver: ClientDriver,
        sender: Sender,
    },
    Server {
        idle: Option<ServerDriver>,
        accepting: Option<AcceptTask>,
    },
}
enum Receive {
    Opening(Task<ClientRequest>),
    Resolving(Task<(http::Request<()>, ServerRequest)>),
    Response(Task<(http::Response<()>, ClientReceive)>),
    Client(ClientReceive),
    Server(ServerReceive),
    ClientTrailers(Task<(Option<http::HeaderMap>, ClientReceive)>),
    ServerTrailers(Task<(Option<http::HeaderMap>, ServerReceive)>),
    Done,
}
#[expect(
    clippy::large_enum_variant,
    reason = "Each bounded HTTP row retains its original stream owner inline rather than allocating a separate wrapper"
)]
enum Send {
    None,
    Server(ServerSend),
    Writing(Task<()>),
    Done,
}
struct Row<'id> {
    token: Option<Stream<'id>>,
    kind: Option<profile::Kind>,
    until: MonoInstant,
    hard: Instant,
    ordinary_hard: Instant,
    terminal_hard: Instant,
    response_body: usize,
    alarm: Pin<Box<Sleep>>,
    alarm_at: Instant,
    receive: Receive,
    send: Send,
    outgoing: Option<Bytes>,
    marks: Option<Rc<Acceptance>>,
    body_done: bool,
    consumed: bool,
}
impl Row<'_> {
    fn expired(&mut self, cx: &mut Context<'_>, now: MonoInstant, role: Role) -> bool {
        let server_request_get = role == Role::Acceptor && self.kind == Some(profile::Kind::Get);
        let server_get = server_request_get && self.body_done && self.consumed;
        let body_accepted = self.response_body == 0
            || self
                .marks
                .as_ref()
                .is_some_and(|marks| marks.known.get() == self.response_body);
        let waiting = server_get && matches!(self.send, Send::Server(_));
        let wait_phase = server_request_get && (!self.body_done || waiting || !body_accepted);
        // Both targets were captured once at original request admission. An
        // idle empty GET needs its wait wake before its later 204 terminal hard;
        // otherwise no network event need arrive in time to actually write204.
        let target = if wait_phase {
            self.ordinary_hard
        } else {
            self.hard
        };
        if self.alarm_at != target {
            self.alarm.as_mut().reset(target);
            self.alarm_at = target;
        }
        let native_wait_expired = wait_phase && Instant::now() >= self.ordinary_hard;
        // If native wait elapsed while caller logical time has not reached its
        // original waitUntil, do not invent a later sample to authorize204.
        let expired = (now.0 >= self.until.0 && !(server_get && body_accepted))
            || (native_wait_expired && (!waiting || now.0 < self.until.0))
            || Instant::now() >= self.hard;
        let _actual_alarm = self.alarm.as_mut().poll(cx);
        expired
    }
}
/// One actual h3 connection and a fixed number of caller body slots. There is
/// one original application SEND debt; completed body acceptance does not erase
/// it until the parent actually records its original MQ Sent acknowledgement.
pub(crate) struct Link<'id, 'slots, 'buf> {
    connection: quinn::Connection,
    profile: Option<profile::Session<'id, 'slots, 'buf>>,
    options: Options,
    authority: String,
    mode: Option<Mode>,
    rows: Vec<Option<Row<'id>>>,
    cursor: usize,
    requests: u64,
    source_alarm: Pin<Box<Sleep>>,
    tx: Option<Sending>,
    identity: Rc<Acceptance>,
    identity_opened: bool,
    identity_reported: bool,
    claim_reported: bool,
    closed: bool,
    fin: bool,
    pending_failure: Option<Failure>,
}
impl<'id, 'slots, 'buf> Link<'id, 'slots, 'buf> {
    pub(crate) fn adopt(
        connection: &quinn::Connection,
        instance: &'id Instance,
        now: MonoInstant,
        loan: &mut Option<&'slots mut [profile::Slot<'id, 'buf>]>,
        options: Options,
    ) -> Result<Self, Failure> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(Protocol::NotReady.into());
        }
        if let Some(error) = connection.close_reason() {
            return Err(Failure::Connection(error));
        }
        if Instant::now() >= options.hard
            || options.request_timeout.is_zero()
            || options.max_requests == 0
            || options.max_requests > (1_u64 << 60)
        {
            return Err(Protocol::InvalidInput.into());
        }
        let micros =
            u64::try_from(options.request_timeout.as_micros()).map_err(|_| Protocol::Overflow)?;
        if micros == 0
            || micros == u64::MAX
            || Instant::now()
                .checked_add(options.request_timeout)
                .is_none()
        {
            return Err(Protocol::InvalidInput.into());
        }
        let doubled = options
            .request_timeout
            .checked_mul(2)
            .ok_or(Protocol::Overflow)?;
        u64::try_from(doubled.as_micros()).map_err(|_| Protocol::Overflow)?;
        if Instant::now().checked_add(doubled).is_none() {
            return Err(Protocol::Overflow.into());
        }
        let capacity = loan.as_ref().ok_or(Protocol::InvalidInput)?.len();
        if capacity
            < options
                .profile
                .limits
                .polls
                .checked_add(2)
                .ok_or(Protocol::Overflow)?
            || capacity > 1024
        {
            return Err(Protocol::Capacity.into());
        }
        let minimum = u64::try_from(
            options
                .profile
                .limits
                .polls
                .checked_add(2)
                .ok_or(Protocol::Overflow)?,
        )
        .map_err(|_| Protocol::Overflow)?;
        if options.max_requests < minimum {
            return Err(Protocol::InvalidInput.into());
        }
        let mut rows = Vec::new();
        rows.try_reserve_exact(capacity)
            .map_err(|_| Protocol::Capacity)?;
        rows.resize_with(capacity, || None);
        let handshake = connection.handshake_data().ok_or(Protocol::NotReady)?;
        let handshake = handshake
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .map_err(|_| Protocol::Unsupported)?;
        let alpn = handshake.protocol.as_deref().ok_or(Protocol::Unsupported)?;
        let authority = connection.remote_address().to_string();
        // Validate all configuration/caller storage before taking the slot loan.
        let conn = h3_quinn::Connection::new(connection.clone());
        let header_bytes = options.profile.limits.header_bytes as u64;
        let mode = match options.profile.role {
            Role::Initiator { .. } => Mode::Build(Box::pin(async move {
                let mut builder = h3::client::builder();
                builder
                    .max_field_section_size(header_bytes)
                    .send_grease(false);
                let (driver, sender) = builder.build::<_, _, Bytes>(conn).await?;
                Ok(Built::Client(driver, sender))
            })),
            Role::Acceptor => Mode::Build(Box::pin(async move {
                let mut builder = h3::server::builder();
                builder
                    .max_field_section_size(header_bytes)
                    .send_grease(false);
                Ok(Built::Server(builder.build::<_, Bytes>(conn).await?))
            })),
        };
        let source_alarm = Box::pin(tokio::time::sleep_until(options.hard));
        let identity = Rc::new(Acceptance::default());
        let session = profile::Session::new_in(instance, now, alpn, loan, options.profile)?;
        Ok(Self {
            connection: connection.clone(),
            profile: Some(session),
            options,
            authority,
            mode: Some(mode),
            rows,
            cursor: 0,
            requests: 0,
            source_alarm,
            tx: None,
            identity,
            identity_opened: false,
            identity_reported: false,
            claim_reported: false,
            closed: false,
            fin: false,
            pending_failure: None,
        })
    }
    pub(crate) fn peer(&self) -> Option<[u8; 32]> {
        self.profile
            .as_ref()
            .and_then(|session| session.peer().map(|peer| peer.0))
    }
    pub(crate) fn may_send(&self, now: MonoInstant) -> Result<bool, Failure> {
        if self.closed || self.fin {
            return Err(Protocol::Closed.into());
        }
        self.profile
            .as_ref()
            .ok_or(Protocol::Closed)?
            .check_live(now)?;
        Ok(match self.options.profile.role {
            Role::Initiator { .. } => self.identity.known.get() == 32,
            Role::Acceptor => self.peer().is_some(),
        })
    }
    /// A completed DATA write can leave its HTTP request awaiting a response.
    /// That original row still owns its slot after the local SENT completes.
    pub(crate) fn send_capacity(&self, now: MonoInstant) -> Result<bool, Failure> {
        Ok(self.may_send(now)?
            && self.tx.is_none()
            && (matches!(self.options.profile.role, Role::Acceptor) || self.free().is_some()))
    }
    fn bounds(
        &self,
        now: MonoInstant,
        hard: Option<Instant>,
        long: bool,
    ) -> Result<(MonoInstant, Instant, Instant), Failure> {
        let first = Instant::now();
        let duration = self.options.request_timeout;
        let total = duration.checked_mul(2).ok_or(Protocol::Overflow)?;
        let ordinary = first
            .checked_add(duration)
            .ok_or(Protocol::Overflow)?
            .min(self.options.hard)
            .min(hard.unwrap_or(self.options.hard));
        let terminal = first
            .checked_add(if long { total } else { duration })
            .ok_or(Protocol::Overflow)?
            .min(self.options.hard)
            .min(hard.unwrap_or(self.options.hard));
        let logical = if long && matches!(self.options.profile.role, Role::Initiator { .. }) {
            total
        } else {
            duration
        };
        let micros = u64::try_from(logical.as_micros()).map_err(|_| Protocol::Overflow)?;
        let until = MonoInstant(
            now.0
                .checked_add(micros)
                .ok_or(Protocol::Overflow)?
                .min(self.options.profile.until.0),
        );
        if now.0 >= until.0 || Instant::now() >= ordinary {
            return Err(Protocol::Deadline.into());
        }
        Ok((until, ordinary, terminal))
    }
    fn admit_number(&mut self) -> Result<(), Failure> {
        let next = self.requests.checked_add(1).ok_or(Protocol::Overflow)?;
        if next > self.options.max_requests {
            return Err(Protocol::Capacity.into());
        }
        self.requests = next;
        Ok(())
    }
    fn free(&self) -> Option<usize> {
        self.rows.iter().position(Option::is_none)
    }
    pub(crate) fn queue(
        &mut self,
        id: SendId,
        bytes: &[u8],
        hard: Instant,
        now: MonoInstant,
    ) -> Result<(), Failure> {
        if Instant::now() >= hard || Instant::now() >= self.options.hard {
            return Err(Protocol::Deadline.into());
        }
        if !self.may_send(now)? {
            return Err(Protocol::NotReady.into());
        }
        if self.tx.is_some() {
            return Err(Protocol::Capacity.into());
        }
        gnunet_wire::official::Frame::decode(bytes)?;
        if bytes.len() > profile::ADVERTISED_MTU
            || bytes.len() > self.options.profile.limits.max_body
        {
            return Err(Protocol::TooLarge.into());
        }
        let client = matches!(self.options.profile.role, Role::Initiator { .. });
        let vacant = if client {
            Some(self.free().ok_or(Protocol::Capacity)?)
        } else {
            None
        };
        let (until, hard, terminal_hard) = self.bounds(now, Some(hard), false)?;
        let request = if client {
            Some(request(
                profile::Kind::MessagePost,
                &self.authority,
                bytes.len(),
            )?)
        } else {
            None
        };
        // Fallible immutable payload copy precedes all logical SEND admission.
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| Protocol::Capacity)?;
        owned.extend_from_slice(bytes);
        let owned = owned_bytes(owned);
        let marks = Rc::new(Acceptance::default());
        if let (Some(index), Some(request)) = (vacant, request) {
            let sender = match self.mode.as_ref() {
                Some(Mode::Client { sender, .. }) => sender.clone(),
                _ => return Err(Protocol::NotReady.into()),
            };
            self.admit_number()?;
            let mut sender = sender;
            self.rows[index] = Some(Row {
                token: None,
                kind: Some(profile::Kind::MessagePost),
                until,
                hard,
                ordinary_hard: hard,
                terminal_hard,
                response_body: 0,
                alarm: Box::pin(tokio::time::sleep_until(hard)),
                alarm_at: hard,
                receive: Receive::Opening(Box::pin(async move {
                    Ok(sender.send_request(request).await?)
                })),
                send: Send::None,
                outgoing: Some(owned),
                marks: Some(marks.clone()),
                body_done: false,
                consumed: false,
            });
            self.tx = Some(Sending {
                id,
                body: None,
                total: bytes.len(),
                hard,
                marks,
                reported: false,
            });
        } else {
            self.tx = Some(Sending {
                id,
                body: Some(owned),
                total: bytes.len(),
                hard,
                marks,
                reported: false,
            });
        }
        Ok(())
    }
    pub(crate) fn pending_send(&self) -> Option<(SendId, usize, usize)> {
        self.tx
            .as_ref()
            .map(|sending| (sending.id, sending.marks.known.get(), sending.total))
    }
    /// Original application HTTP future was actually polled and may have
    /// exposed bytes, but send_data has not returned whole acceptance. This
    /// survives unrelated receive errors/close so the MQ owner can retain its
    /// exact original uncertainty without changing the independent RX cause.
    pub(crate) fn pending_send_unknown(&self) -> Option<SendId> {
        self.tx
            .as_ref()
            .filter(|sending| {
                sending.marks.polled.get() && sending.marks.known.get() < sending.total
            })
            .map(|sending| sending.id)
    }
    pub(crate) fn take_accepted(&mut self, id: SendId) -> Result<(), Failure> {
        let actual = self.tx.as_ref().ok_or(Protocol::Stale)?;
        if actual.id != id {
            return Err(Protocol::Stale.into());
        }
        if actual.marks.known.get() != actual.total {
            return Err(Protocol::NotReady.into());
        }
        self.tx = None;
        Ok(())
    }
    pub(crate) fn frame(&self, now: MonoInstant) -> Result<Option<FrameView<'_, 'id>>, Failure> {
        if self.closed {
            return Ok(None);
        }
        let session = self.profile.as_ref().ok_or(Protocol::Closed)?;
        session.check_live(now)?;
        for row in self.rows.iter().flatten() {
            if row.body_done
                && !row.consumed
                && let Some(token) = row.token
            {
                match session.delivery(token, now) {
                    Ok(Some(delivery)) => {
                        return Ok(Some(FrameView {
                            id: FrameId(token),
                            bytes: delivery.frame,
                        }));
                    }
                    Ok(None) | Err(Protocol::NotReady) => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        Ok(None)
    }
    /// Only the exact original Incoming/FC completion releases this body. This
    /// cleanup works without clock, including after physical close was requested.
    pub(crate) fn release_frame(&mut self, id: FrameId<'id>) -> Result<usize, Failure> {
        let row = self
            .rows
            .iter_mut()
            .flatten()
            .find(|row| row.token == Some(id.0))
            .ok_or(Protocol::Stale)?;
        if !row.body_done || row.consumed {
            return Err(Protocol::NotReady.into());
        }
        let n = if self.closed {
            0
        } else {
            self.profile
                .as_mut()
                .ok_or(Protocol::Closed)?
                .consume(id.0)?
        };
        row.consumed = true;
        Ok(n)
    }
    fn unknown(&self, cause: Failure) -> Failure {
        if cause.send_unknown().is_some() {
            return cause;
        }
        if let Some(sending) = &self.tx
            && sending.marks.polled.get()
            && sending.marks.known.get() < sending.total
        {
            return Failure::SendOutcomeUnknown {
                id: sending.id,
                known: sending.marks.known.get(),
                total: sending.total,
                cause: Box::new(cause),
            };
        }
        cause
    }
    fn acceptance(&mut self) -> Option<Step> {
        if let Some(sending) = &mut self.tx
            && !sending.reported
            && sending.marks.known.get() == sending.total
        {
            sending.reported = true;
            return Some(Step::ProviderAccepted {
                id: sending.id,
                bytes: sending.total,
                complete: true,
            });
        }
        if !self.identity_reported && self.identity.known.get() == 32 {
            self.identity_reported = true;
            return Some(Step::IdentityAccepted(32));
        }
        None
    }
    /// Poll retained original futures only after original native guards. A
    /// completed send_data fact is returned before a later finish/control error,
    /// without converting that error into success or replaying its old POST.
    pub(crate) fn poll(&mut self, cx: &mut Context<'_>, now: MonoInstant) -> Result<Step, Failure> {
        if let Some(error) = self.pending_failure.take() {
            return Err(error);
        }
        if self.closed {
            return Err(Protocol::Closed.into());
        }
        let result = self.poll_inner(cx, now);
        match result {
            Err(cause) => {
                let error = cause;
                self.close();
                if let Some(actual) = self.acceptance() {
                    self.pending_failure = Some(error);
                    Ok(actual)
                } else {
                    Err(error)
                }
            }
            Ok(step) => {
                if let Some(actual) = self.acceptance() {
                    return Ok(actual);
                }
                if matches!(step, Step::Claim(_)) {
                    self.claim_reported = true;
                }
                Ok(step)
            }
        }
    }
    fn poll_inner(&mut self, cx: &mut Context<'_>, now: MonoInstant) -> Result<Step, Failure> {
        if Instant::now() >= self.options.hard {
            return Err(self.unknown(Protocol::Deadline.into()));
        }
        let _source = self.source_alarm.as_mut().poll(cx);
        if let Some(error) = self.connection.close_reason() {
            return Err(self.unknown(Failure::Connection(error)));
        }
        self.profile
            .as_ref()
            .ok_or(Protocol::Closed)?
            .check_live(now)?;
        if let Some(sending) = &self.tx
            && sending.marks.known.get() < sending.total
            && Instant::now() >= sending.hard
        {
            return Err(self.unknown(Protocol::Deadline.into()));
        }
        if !self.claim_reported
            && matches!(self.options.profile.role, Role::Acceptor)
            && let Some(peer) = self.peer()
        {
            return Ok(Step::Claim(peer));
        }
        if self.poll_mode(cx, now)? {
            return Ok(Step::StreamsReady);
        }
        let scheduled = self.start_client(now)? || self.start_server_response(now)?;
        for _ in 0..self.rows.len() {
            let index = self.cursor % self.rows.len();
            self.cursor = self.cursor.wrapping_add(1);
            if self.rows[index].is_some()
                && let Some(step) = self.poll_row(index, cx, now)?
            {
                return Ok(step);
            }
        }
        if scheduled {
            return Ok(Step::Activity { read: 0 });
        }
        if self.fin && self.rows.iter().all(Option::is_none) {
            return Ok(Step::Fin);
        }
        Ok(Step::Pending)
    }
    fn poll_mode(&mut self, cx: &mut Context<'_>, now: MonoInstant) -> Result<bool, Failure> {
        if Instant::now() >= self.options.hard {
            return Err(Protocol::Deadline.into());
        }
        let mut built = None;
        if let Some(Mode::Build(future)) = &mut self.mode {
            match future.as_mut().poll(cx) {
                Poll::Pending => return Ok(false),
                Poll::Ready(result) => built = Some(result?),
            }
        }
        if let Some(built) = built {
            self.mode = Some(match built {
                Built::Client(driver, sender) => Mode::Client { driver, sender },
                Built::Server(server) => Mode::Server {
                    idle: Some(server),
                    accepting: None,
                },
            });
            return Ok(true);
        }
        let vacant = self.free();
        let mut accepted = None;
        match self.mode.as_mut().ok_or(Protocol::NotReady)? {
            Mode::Client { driver, .. } => {
                if let Poll::Ready(error) = driver.poll_close(cx) {
                    return Err(Failure::Http3Connection(error));
                }
            }
            Mode::Server { idle, accepting } => {
                if accepting.is_none()
                    && vacant.is_some()
                    && let Some(mut server) = idle.take()
                {
                    *accepting = Some(Box::pin(async move {
                        let request = server.accept().await;
                        Accepted { server, request }
                    }));
                }
                if let Some(future) = accepting {
                    match future.as_mut().poll(cx) {
                        Poll::Pending => {}
                        Poll::Ready(value) => accepted = Some(value),
                    }
                }
            }
            Mode::Build(_) => {}
        }
        if let Some(Accepted { server, request }) = accepted {
            let request = request.map_err(|error| {
                close_failure(&self.connection, Failure::Http3Connection(error))
            })?;
            if let Some(Mode::Server { idle, accepting }) = &mut self.mode {
                *accepting = None;
                *idle = Some(server);
            }
            let Some(resolver) = request else {
                self.fin = true;
                return Ok(false);
            };
            let index =
                vacant.ok_or_else(|| close_failure(&self.connection, Protocol::Capacity.into()))?;
            let (until, hard, terminal_hard) = self
                .bounds(now, None, true)
                .map_err(|error| close_failure(&self.connection, error))?;
            self.admit_number()
                .map_err(|error| close_failure(&self.connection, error))?;
            self.rows[index] = Some(Row {
                token: None,
                kind: None,
                until,
                hard,
                ordinary_hard: hard,
                terminal_hard,
                response_body: 0,
                alarm: Box::pin(tokio::time::sleep_until(hard)),
                alarm_at: hard,
                receive: Receive::Resolving(Box::pin(async move {
                    Ok(resolver.resolve_request().await?)
                })),
                send: Send::None,
                outgoing: None,
                marks: None,
                body_done: false,
                consumed: false,
            });
        }
        Ok(false)
    }
    fn start_client(&mut self, now: MonoInstant) -> Result<bool, Failure> {
        if self.fin {
            return Ok(false);
        }
        let Some(index) = self.free() else {
            return Ok(false);
        };
        let Some(Mode::Client { sender, .. }) = &self.mode else {
            return Ok(false);
        };
        let kind = if !self.identity_opened {
            if self
                .rows
                .iter()
                .flatten()
                .any(|row| row.kind == Some(profile::Kind::IdentityPost))
            {
                return Ok(false);
            }
            profile::Kind::IdentityPost
        } else {
            if self.identity.known.get() != 32 {
                return Ok(false);
            }
            let polls = self
                .rows
                .iter()
                .flatten()
                .filter(|row| row.kind == Some(profile::Kind::Get))
                .count();
            if polls >= self.options.profile.limits.polls {
                return Ok(false);
            }
            profile::Kind::Get
        };
        let mut sender = sender.clone();
        let body = if kind == profile::Kind::IdentityPost {
            Some(copy_body(&self.options.local)?)
        } else {
            None
        };
        let request = request(kind, &self.authority, body.as_ref().map_or(0, Bytes::len))?;
        let (until, ordinary_hard, terminal_hard) =
            self.bounds(now, None, kind == profile::Kind::Get)?;
        let hard = if kind == profile::Kind::Get {
            terminal_hard
        } else {
            ordinary_hard
        };
        self.admit_number()?;
        // Never open GETs until the actual identity POST has returned stream0;
        // a merely polled send_request future is not a stream-id assignment.
        self.rows[index] = Some(Row {
            token: None,
            kind: Some(kind),
            until,
            hard,
            ordinary_hard,
            terminal_hard,
            response_body: 0,
            alarm: Box::pin(tokio::time::sleep_until(hard)),
            alarm_at: hard,
            receive: Receive::Opening(Box::pin(
                async move { Ok(sender.send_request(request).await?) },
            )),
            send: Send::None,
            outgoing: body,
            marks: (kind == profile::Kind::IdentityPost).then(|| self.identity.clone()),
            body_done: false,
            consumed: false,
        });
        Ok(true)
    }
    fn start_server_response(&mut self, now: MonoInstant) -> Result<bool, Failure> {
        if !matches!(self.options.profile.role, Role::Acceptor) {
            return Ok(false);
        }
        let session = self.profile.as_mut().ok_or(Protocol::Closed)?;
        let has_tx = self
            .tx
            .as_ref()
            .is_some_and(|sending| sending.body.is_some());
        let poll = if has_tx {
            session.next_poll(now)?
        } else {
            None
        };
        let index = if let Some(token) = poll {
            self.rows
                .iter()
                .position(|row| row.as_ref().is_some_and(|row| row.token == Some(token)))
        } else {
            self.rows.iter().position(|row| {
                row.as_ref().is_some_and(|row| {
                    row.body_done
                        && row.consumed
                        && matches!(row.send, Send::Server(_))
                        && (row.kind != Some(profile::Kind::Get) || now.0 >= row.until.0)
                })
            })
        };
        let Some(index) = index else {
            return Ok(false);
        };
        let row = self.rows[index].as_mut().ok_or(Protocol::Stale)?;
        let token = row.token.ok_or(Protocol::Stale)?;
        let attach = has_tx && now.0 < row.until.0;
        let body = if attach {
            self.tx
                .as_ref()
                .and_then(|sending| sending.body.as_ref())
                .map(Bytes::as_ref)
        } else {
            None
        };
        let status = session.start_response(token, body, now)?;
        let response = response(status, body.map_or(0, <[u8]>::len))?;
        let send = match std::mem::replace(&mut row.send, Send::None) {
            Send::Server(send) => send,
            other => {
                self.connection.close(quinn::VarInt::from_u32(0), b"");
                drop(other);
                return Err(Protocol::Conflict.into());
            }
        };
        let (body, marks) = if attach {
            let sending = self.tx.as_mut().ok_or(Protocol::Stale)?;
            (sending.body.take(), Some(sending.marks.clone()))
        } else {
            (None, None)
        };
        row.response_body = body.as_ref().map_or(0, Bytes::len);
        row.marks = marks.clone();
        let body_hard = if row.kind == Some(profile::Kind::Get) && row.response_body > 0 {
            row.ordinary_hard
        } else {
            row.hard
        };
        row.send = Send::Writing(write_server(
            send,
            response,
            body,
            marks,
            body_hard,
            row.hard,
            self.connection.clone(),
        ));
        Ok(true)
    }
    fn poll_row(
        &mut self,
        index: usize,
        cx: &mut Context<'_>,
        now: MonoInstant,
    ) -> Result<Option<Step>, Failure> {
        let row = self.rows[index].as_mut().ok_or(Protocol::Stale)?;
        if row.expired(cx, now, self.options.profile.role) {
            return Err(send_error(
                Protocol::Deadline.into(),
                self.tx.as_ref(),
                row.marks.as_ref(),
            ));
        }
        // Poll original output first. Its full DATA acceptance marker is always
        // observed before unrelated receive/control work can fail this turn.
        if let Send::Writing(future) = &mut row.send {
            if let Some(marks) = &row.marks {
                marks.polled.set(true);
            }
            match future.as_mut().poll(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(error)) => {
                    return Err(send_error(error, self.tx.as_ref(), row.marks.as_ref()));
                }
                Poll::Ready(Ok(())) => row.send = Send::Done,
            }
            if row
                .marks
                .as_ref()
                .is_some_and(|marks| marks.known.get() > 0)
                && let Some(actual) = self.acceptance()
            {
                return Ok(Some(actual));
            }
        }
        // Futures own their HTTP stream/sender by value. The borrow of Link
        // ends after each bounded poll; no future refers into this row/session.
        #[expect(
            clippy::large_enum_variant,
            reason = "This transient poll result moves the original HTTP stream on the stack without a heap allocation"
        )]
        enum Head {
            Client(ClientRequest),
            Server(http::Request<()>, ServerRequest),
            Response(http::Response<()>, ClientReceive),
            ClientTrailers(Option<http::HeaderMap>, ClientReceive),
            ServerTrailers(Option<http::HeaderMap>, ServerReceive),
        }
        let row = self.rows[index].as_mut().ok_or(Protocol::Stale)?;
        if Instant::now() >= self.options.hard || Instant::now() >= row.hard {
            return Err(Protocol::Deadline.into());
        }
        let head = match &mut row.receive {
            Receive::Opening(future) => {
                if let Some(marks) = &row.marks {
                    marks.polled.set(true);
                }
                match future.as_mut().poll(cx) {
                    Poll::Ready(result) => Some(Head::Client(result.map_err(|error| {
                        send_error(error, self.tx.as_ref(), row.marks.as_ref())
                    })?)),
                    Poll::Pending => None,
                }
            }
            Receive::Resolving(future) => match future.as_mut().poll(cx) {
                Poll::Ready(result) => {
                    let (head, stream) = result?;
                    Some(Head::Server(head, stream))
                }
                Poll::Pending => None,
            },
            Receive::Response(future) => match future.as_mut().poll(cx) {
                Poll::Ready(result) => {
                    let (head, stream) = result?;
                    Some(Head::Response(head, stream))
                }
                Poll::Pending => None,
            },
            Receive::ClientTrailers(future) => match future.as_mut().poll(cx) {
                Poll::Ready(result) => {
                    let (head, stream) = result?;
                    Some(Head::ClientTrailers(head, stream))
                }
                Poll::Pending => None,
            },
            Receive::ServerTrailers(future) => match future.as_mut().poll(cx) {
                Poll::Ready(result) => {
                    let (head, stream) = result?;
                    Some(Head::ServerTrailers(head, stream))
                }
                Poll::Pending => None,
            },
            _ => None,
        };
        let session = self.profile.as_mut().ok_or(Protocol::Closed)?;
        if let Some(head) = head {
            // Resolve/header completion cannot extend the original phase's
            // native budget. Close before this local owned handle may drop.
            if Instant::now() >= row.hard || Instant::now() >= self.options.hard {
                self.connection.close(quinn::VarInt::from_u32(0), b"");
                return Err(send_error(
                    Protocol::Deadline.into(),
                    self.tx.as_ref(),
                    row.marks.as_ref(),
                ));
            }
            match head {
                Head::Client(stream) => {
                    let kind = row.kind.ok_or(Protocol::Stale)?;
                    let token = session
                        .open_request(stream.id().into_inner(), kind, row.until, now)
                        .map_err(|error| close_failure(&self.connection, error.into()))?;
                    if kind == profile::Kind::IdentityPost {
                        self.identity_opened = true;
                    }
                    row.token = Some(token);
                    let (send, mut recv) = stream.split();
                    row.send = Send::Writing(write_client(
                        send,
                        row.outgoing.take(),
                        row.marks.clone(),
                        row.hard,
                        self.connection.clone(),
                    ));
                    row.receive = Receive::Response(Box::pin(async move {
                        let response = recv.recv_response().await?;
                        Ok((response, recv))
                    }));
                }
                Head::Server(head, stream) => {
                    let token = with_request_headers(&head, |fields| {
                        session.accept_request(stream.id().into_inner(), fields, row.until, now)
                    })
                    .map_err(|error| close_failure(&self.connection, error))?;
                    row.kind = Some(if head.method() == http::Method::GET {
                        profile::Kind::Get
                    } else if token.id() == 0 {
                        profile::Kind::IdentityPost
                    } else {
                        profile::Kind::MessagePost
                    });
                    row.hard = if row.kind == Some(profile::Kind::Get) {
                        row.terminal_hard
                    } else {
                        row.ordinary_hard
                    };
                    row.alarm.as_mut().reset(row.hard);
                    row.alarm_at = row.hard;
                    if Instant::now() >= row.hard {
                        return Err(close_failure(&self.connection, Protocol::Deadline.into()));
                    }
                    row.token = Some(token);
                    let (send, recv) = stream.split();
                    row.send = Send::Server(send);
                    row.receive = Receive::Server(recv);
                }
                Head::Response(head, recv) => {
                    let token = row.token.ok_or(Protocol::Stale)?;
                    with_response_headers(&head, |fields| {
                        session.accept_response(token, fields, now)
                    })
                    .map_err(|error| close_failure(&self.connection, error))?;
                    row.receive = Receive::Client(recv);
                }
                Head::ClientTrailers(trailers, _recv) => {
                    check_trailers(trailers.as_ref(), self.options.profile.limits.header_bytes)?;
                    session.finish_body(row.token.ok_or(Protocol::Stale)?, now)?;
                    row.receive = Receive::Done;
                    row.body_done = true;
                    let token = row.token.ok_or(Protocol::Stale)?;
                    if matches!(session.delivery(token, now), Ok(None)) {
                        session.consume(token)?;
                        row.consumed = true;
                    }
                }
                Head::ServerTrailers(trailers, _recv) => {
                    check_trailers(trailers.as_ref(), self.options.profile.limits.header_bytes)?;
                    session.finish_body(row.token.ok_or(Protocol::Stale)?, now)?;
                    row.receive = Receive::Done;
                    row.body_done = true;
                    let token = row.token.ok_or(Protocol::Stale)?;
                    if matches!(session.delivery(token, now), Ok(None)) {
                        session.consume(token)?;
                        row.consumed = true;
                    }
                }
            }
            return Ok(Some(Step::Activity { read: 0 }));
        }
        let row = self.rows[index].as_mut().ok_or(Protocol::Stale)?;
        let token = row.token;
        if Instant::now() >= self.options.hard || Instant::now() >= row.hard {
            return Err(Protocol::Deadline.into());
        }
        let mut end = false;
        let mut read = 0_usize;
        match &mut row.receive {
            Receive::Client(stream) => match stream.poll_recv_data(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(error)) => return Err(error.into()),
                Poll::Ready(Ok(None)) => end = true,
                Poll::Ready(Ok(Some(mut bytes))) => {
                    while bytes.has_remaining() {
                        let chunk = bytes.chunk();
                        if chunk.is_empty() {
                            return Err(Protocol::Conflict.into());
                        }
                        read = read
                            .checked_add(session.push_body(
                                token.ok_or(Protocol::Stale)?,
                                chunk,
                                now,
                            )?)
                            .ok_or(Protocol::Overflow)?;
                        let n = chunk.len();
                        bytes.advance(n);
                    }
                }
            },
            Receive::Server(stream) => match stream.poll_recv_data(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(error)) => return Err(error.into()),
                Poll::Ready(Ok(None)) => end = true,
                Poll::Ready(Ok(Some(mut bytes))) => {
                    while bytes.has_remaining() {
                        let chunk = bytes.chunk();
                        if chunk.is_empty() {
                            return Err(Protocol::Conflict.into());
                        }
                        read = read
                            .checked_add(session.push_body(
                                token.ok_or(Protocol::Stale)?,
                                chunk,
                                now,
                            )?)
                            .ok_or(Protocol::Overflow)?;
                        let n = chunk.len();
                        bytes.advance(n);
                    }
                }
            },
            _ => {}
        }
        if end {
            row.receive = match std::mem::replace(&mut row.receive, Receive::Done) {
                Receive::Client(mut recv) => Receive::ClientTrailers(Box::pin(async move {
                    let trailers = recv.recv_trailers().await?;
                    Ok((trailers, recv))
                })),
                Receive::Server(mut recv) => Receive::ServerTrailers(Box::pin(async move {
                    let trailers = recv.recv_trailers().await?;
                    Ok((trailers, recv))
                })),
                _ => return Err(Protocol::Conflict.into()),
            };
            return Ok(Some(Step::Activity { read: 0 }));
        }
        if read > 0 {
            return Ok(Some(Step::Activity { read }));
        }
        if row.body_done && !row.consumed {
            let token = row.token.ok_or(Protocol::Stale)?;
            match session.delivery(token, now) {
                Ok(Some(_)) => return Ok(Some(Step::Frame)),
                Ok(None) => {
                    session.consume(token)?;
                    row.consumed = true;
                }
                Err(Protocol::NotReady) => {}
                Err(error) => return Err(error.into()),
            }
        }
        if row.body_done && row.consumed && matches!(row.send, Send::Done) {
            session.release(row.token.ok_or(Protocol::Stale)?)?;
            self.rows[index] = None;
            return Ok(Some(Step::Activity { read: 0 }));
        }
        Ok(None)
    }
    /// Actual original Quinn close precedes cancellation/drop of any HTTP/3
    /// future or stream. Old FrameIds remain metadata for clock-free FC cleanup.
    pub(crate) fn close(&mut self) {
        if !self.closed {
            self.connection.close(quinn::VarInt::from_u32(0), b"");
            self.closed = true;
        }
        if let Some(session) = &mut self.profile {
            session.retire();
        }
    }
    /// Caller first retires original driver/connection/Incoming/FC/MQ debts.
    /// Returning erased caller slabs is not a physical drain/completion receipt.
    pub(crate) fn recycle(mut self) -> Result<&'slots mut [profile::Slot<'id, 'buf>], Failure> {
        self.close();
        self.mode = None;
        self.rows.clear();
        self.tx = None;
        self.profile
            .take()
            .map(profile::Session::recycle)
            .ok_or_else(|| Protocol::Stale.into())
    }
}
impl Drop for Link<'_, '_, '_> {
    fn drop(&mut self) {
        self.close();
    }
}
fn write_client(
    mut stream: ClientSend,
    body: Option<Bytes>,
    marks: Option<Rc<Acceptance>>,
    hard: Instant,
    connection: quinn::Connection,
) -> Task<()> {
    Box::pin(async move {
        native_guard(&connection, hard)?;
        if let Some(body) = body {
            let n = body.len();
            if let Err(error) = stream.send_data(body).await {
                return Err(close_failure(&connection, error.into()));
            }
            if let Some(marks) = marks {
                marks.known.set(n);
            }
        }
        native_guard(&connection, hard)?;
        if let Err(error) = stream.finish().await {
            return Err(close_failure(&connection, error.into()));
        }
        Ok(())
    })
}
fn write_server(
    mut stream: ServerSend,
    response: http::Response<()>,
    body: Option<Bytes>,
    marks: Option<Rc<Acceptance>>,
    body_hard: Instant,
    hard: Instant,
    connection: quinn::Connection,
) -> Task<()> {
    Box::pin(async move {
        native_guard(&connection, body_hard)?;
        if let Err(error) = stream.send_response(response).await {
            return Err(close_failure(&connection, error.into()));
        }
        if let Some(body) = body {
            native_guard(&connection, body_hard)?;
            let n = body.len();
            if let Err(error) = stream.send_data(body).await {
                return Err(close_failure(&connection, error.into()));
            }
            if let Some(marks) = marks {
                marks.known.set(n);
            }
        }
        native_guard(&connection, hard)?;
        if let Err(error) = stream.finish().await {
            return Err(close_failure(&connection, error.into()));
        }
        Ok(())
    })
}
fn native_guard(connection: &quinn::Connection, hard: Instant) -> Result<(), Failure> {
    if Instant::now() >= hard {
        Err(close_failure(connection, Protocol::Deadline.into()))
    } else {
        Ok(())
    }
}
fn request(kind: profile::Kind, authority: &str, len: usize) -> Result<http::Request<()>, Failure> {
    let mut digits = [0u8; 20];
    let fields = profile::request_headers(kind, authority.as_bytes(), len, &mut digits)?;
    let method = if kind == profile::Kind::Get {
        http::Method::GET
    } else {
        http::Method::POST
    };
    let mut request = http::Request::builder()
        .method(method)
        .uri(format!("https://{authority}/"))
        .body(())?;
    ordinary_headers(request.headers_mut(), fields.as_slice())?;
    Ok(request)
}
fn response(status: u16, len: usize) -> Result<http::Response<()>, Failure> {
    let mut digits = [0u8; 20];
    let fields = profile::response_headers(status, Some(len), &mut digits)?;
    let mut response = http::Response::builder().status(status).body(())?;
    ordinary_headers(response.headers_mut(), fields.as_slice())?;
    Ok(response)
}
fn ordinary_headers(
    output: &mut http::HeaderMap,
    fields: &[profile::Header<'_>],
) -> Result<(), Failure> {
    for field in fields {
        if field.name.first() == Some(&b':') {
            continue;
        }
        let name = http::header::HeaderName::from_bytes(field.name).map_err(Failure::HeaderName)?;
        let value =
            http::header::HeaderValue::from_bytes(field.value).map_err(Failure::HeaderValue)?;
        output.append(name, value);
    }
    Ok(())
}
fn with_request_headers<T>(
    request: &http::Request<()>,
    apply: impl FnOnce(&[profile::Header<'_>]) -> Result<T, Protocol>,
) -> Result<T, Failure> {
    let empty = profile::Header {
        name: b"",
        value: b"",
    };
    let mut fields = [empty; profile::MAX_HEADERS];
    fields[0] = profile::Header {
        name: b":method",
        value: request.method().as_str().as_bytes(),
    };
    fields[1] = profile::Header {
        name: b":scheme",
        value: request
            .uri()
            .scheme_str()
            .ok_or(Protocol::Malformed)?
            .as_bytes(),
    };
    fields[2] = profile::Header {
        name: b":authority",
        value: request
            .uri()
            .authority()
            .ok_or(Protocol::Malformed)?
            .as_str()
            .as_bytes(),
    };
    fields[3] = profile::Header {
        name: b":path",
        value: request
            .uri()
            .path_and_query()
            .ok_or(Protocol::Malformed)?
            .as_str()
            .as_bytes(),
    };
    let n = decoded_headers(&mut fields, 4, request.headers())?;
    Ok(apply(&fields[..n])?)
}
fn with_response_headers<T>(
    response: &http::Response<()>,
    apply: impl FnOnce(&[profile::Header<'_>]) -> Result<T, Protocol>,
) -> Result<T, Failure> {
    let empty = profile::Header {
        name: b"",
        value: b"",
    };
    let mut fields = [empty; profile::MAX_HEADERS];
    let status = response.status();
    fields[0] = profile::Header {
        name: b":status",
        value: status.as_str().as_bytes(),
    };
    let n = decoded_headers(&mut fields, 1, response.headers())?;
    Ok(apply(&fields[..n])?)
}
fn decoded_headers<'a>(
    output: &mut [profile::Header<'a>],
    mut n: usize,
    headers: &'a http::HeaderMap,
) -> Result<usize, Failure> {
    for (name, value) in headers {
        let next = output.get_mut(n).ok_or(Protocol::TooLarge)?;
        *next = profile::Header {
            name: name.as_str().as_bytes(),
            value: value.as_bytes(),
        };
        n = n.checked_add(1).ok_or(Protocol::Overflow)?;
    }
    Ok(n)
}
fn check_trailers(headers: Option<&http::HeaderMap>, budget: usize) -> Result<(), Failure> {
    let Some(headers) = headers else {
        return Ok(());
    };
    let mut bytes = 0usize;
    let mut count = 0usize;
    for (name, value) in headers {
        count = count.checked_add(1).ok_or(Protocol::Overflow)?;
        bytes = bytes
            .checked_add(name.as_str().len())
            .and_then(|n| n.checked_add(value.len()))
            .ok_or(Protocol::Overflow)?;
        if count > profile::MAX_HEADERS || bytes > budget {
            return Err(Protocol::TooLarge.into());
        }
        if matches!(name.as_str(), "content-length" | "content-type") {
            return Err(Protocol::Malformed.into());
        }
    }
    Ok(())
}

fn close_failure(connection: &quinn::Connection, error: Failure) -> Failure {
    connection.close(quinn::VarInt::from_u32(0), b"");
    error
}

fn send_error(
    cause: Failure,
    sending: Option<&Sending>,
    original: Option<&Rc<Acceptance>>,
) -> Failure {
    if cause.send_unknown().is_some() {
        return cause;
    }
    if let Some(sending) = sending
        && original.is_some_and(|marks| Rc::ptr_eq(marks, &sending.marks))
        && sending.marks.polled.get()
        && sending.marks.known.get() < sending.total
    {
        Failure::SendOutcomeUnknown {
            id: sending.id,
            known: sending.marks.known.get(),
            total: sending.total,
            cause: Box::new(cause),
        }
    } else {
        cause
    }
}
