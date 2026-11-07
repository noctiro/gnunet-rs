// Root fresh DNSSEC seam; original ordinary operations retain their own flags.
//! DNS-only recursive owner. No DNS response is redirected back into GNS.
//! AD never grants authentication; required security uses an explicit real provider.
pub mod dnssec;
use crate::{
    Bounds, Close, Operation, Value,
    native::{Error as NativeError, Report},
};
use gnunet_dns::{Arena, Header, Name, Packet, Query as DnsQuestion, RData};
use gnunet_gns::{Origin, Record, RecordFlags, RecordType};
use gnunet_service_runtime::clock::{ClockSample, ClockSubscription, Deadline, RuntimeClock};
use gnunet_types::{AbsoluteTime, Error as CoreError};
use std::{
    cell::RefCell,
    future::{Future, poll_fn},
    io,
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::{Instant, Sleep},
};

/// Exact original DNS cause. It is never a fabricated empty answer.
#[derive(Debug)]
pub enum Cause {
    /// Protocol/resource/work error.
    Protocol(CoreError),
    /// Actual complete response code, including EDNS extended bits.
    ResponseCode(u16),
    /// Actual allocation refusal.
    Allocation(std::collections::TryReserveError),
    /// Actual socket IO failure.
    Io(io::Error),
    /// Original unavailable nameserver configuration, not an empty DNS answer.
    Bootstrap(Arc<Error>),
    /// Exact canonical clock refusal.
    Clock(CoreError),
    /// Actual entropy-provider refusal.
    Entropy(getrandom::Error),
    /// Exact authenticated denial proof failure, never an empty answer.
    Denial(gnunet_dns::dnssec::denial::Failure),
    /// Security records require a real installed validator.
    SecurityUnavailable {
        /// Actual supplied security record count requiring a real verifier.
        records: usize,
    },
}
/// Owned original cause plus actually charged recursive work.
#[derive(Debug)]
pub struct Error {
    cause: Cause,
    spent: u32,
}
impl Error {
    /// Exact original cause, independent of budget accounting.
    pub fn cause(&self) -> &Cause {
        &self.cause
    }
    /// Actual DNS exchange/TCP-fallback work, charged even on failure.
    pub const fn spent(&self) -> u32 {
        self.spent
    }
    fn with_spent(mut self, spent: u32) -> Self {
        self.spent = spent;
        self
    }
    fn clock(error: CoreError) -> Self {
        Self {
            cause: Cause::Clock(error),
            spent: 0,
        }
    }
    fn allocation(error: std::collections::TryReserveError) -> Self {
        Self {
            cause: Cause::Allocation(error),
            spent: 0,
        }
    }
    fn entropy(error: getrandom::Error) -> Self {
        Self {
            cause: Cause::Entropy(error),
            spent: 0,
        }
    }
    fn response_code(code: u16) -> Self {
        Self {
            cause: Cause::ResponseCode(code),
            spent: 0,
        }
    }
    fn security_unavailable(records: usize) -> Self {
        Self {
            cause: Cause::SecurityUnavailable { records },
            spent: 0,
        }
    }
    /// Classification for the pure effect; the full original cause stays owned.
    pub fn reason(&self) -> CoreError {
        match &self.cause {
            Cause::Protocol(error) | Cause::Clock(error) => *error,
            Cause::ResponseCode(_) => CoreError::NotFound,
            Cause::Allocation(_) => CoreError::Capacity,
            Cause::Io(_) => CoreError::Io,
            Cause::Bootstrap(error) => error.reason(),
            Cause::Entropy(_) => CoreError::EntropyUnavailable,
            Cause::SecurityUnavailable { .. } => CoreError::Unavailable,
            Cause::Denial(error) => match error {
                gnunet_dns::dnssec::denial::Failure::Capacity
                | gnunet_dns::dnssec::denial::Failure::WorkLimit => CoreError::Capacity,
                gnunet_dns::dnssec::denial::Failure::IterationLimit => CoreError::Unsupported,
                gnunet_dns::dnssec::denial::Failure::Hash(error) => *error,
                _ => CoreError::Authentication,
            },
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.cause {
            Cause::Protocol(error) => write!(f, "DNS protocol/resource: {error}"),
            Cause::Clock(error) => write!(f, "DNS clock: {error}"),
            Cause::ResponseCode(code) => write!(f, "DNS response code {code}"),
            Cause::Allocation(error) => write!(f, "DNS allocation: {error}"),
            Cause::Io(error) => write!(f, "DNS IO: {error}"),
            Cause::Bootstrap(error) => write!(f, "DNS bootstrap unavailable: {error}"),
            Cause::Entropy(_) => f.write_str("DNS entropy provider failed"),
            Cause::Denial(error) => write!(f, "DNS denial: {error}"),
            Cause::SecurityUnavailable { .. } => {
                f.write_str("GNS2DNS security validation unavailable")
            }
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.cause {
            Cause::Protocol(error) | Cause::Clock(error) => Some(error),
            Cause::Allocation(error) => Some(error),
            Cause::Io(error) => Some(error),
            Cause::Bootstrap(error) => Some(error.as_ref()),
            Cause::Denial(error) => Some(error),
            _ => None,
        }
    }
}
impl From<gnunet_dns::dnssec::denial::Failure> for Error {
    fn from(error: gnunet_dns::dnssec::denial::Failure) -> Self {
        Self {
            cause: Cause::Denial(error),
            spent: 0,
        }
    }
}
impl From<CoreError> for Error {
    fn from(error: CoreError) -> Self {
        Self {
            cause: Cause::Protocol(error),
            spent: 0,
        }
    }
}
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self {
            cause: Cause::Io(error),
            spent: 0,
        }
    }
}

/// Actual original operation IO; source matching is not DNSSEC authentication.
#[derive(Debug)]
pub struct DnsReport {
    /// Same original request bounds, never rebuilt after UDP/TCP/referral.
    pub bounds: Bounds,
    /// Actual UDP exchange attempts.
    pub exchanges: u32,
    /// Actual shared recursive work (UDP exchange plus TCP fallback).
    pub work_spent: u32,
    /// Successful native UDP bindings.
    pub udp_bindings: u32,
    /// Successful native TCP connections.
    pub tcp_connections: u32,
    /// Actual received socket bytes, including DNS/TCP framing.
    pub read_bytes: u64,
    /// Actual written socket bytes, including DNS/TCP framing.
    pub written_bytes: u64,
    /// Actual unrelated/oversize/mismatching UDP datagrams consumed.
    pub rejected_datagrams: u64,
    /// Genuine final DNS answer/negative observation was converted.
    pub completed: bool,
    /// Original owner explicitly canceled before completion.
    pub cancelled: bool,
    /// All native socket-owning futures were actually relinquished.
    /// No worker or detached task is created by this implementation.
    pub closed: bool,
    /// This ordinary owner does not claim DNSSEC verification.
    pub dnssec_verified: bool,
    /// A real authenticated parent-chain proof established an unsigned
    /// delegation. This never sets dnssec_verified or trusts a response AD bit.
    pub dnssec_insecure: bool,
    /// Actual last complete DNS response code, including EDNS extended bits.
    pub last_response_code: Option<u16>,
    /// Actual last flags. AD is untrusted and does not set dnssec_verified.
    pub last_flags: Option<u16>,
    /// First actual failure recovered by retry/fallback, separately retained.
    pub first_recovered_error: Option<Error>,
    /// Later recovered errors omitted from the bounded one-error inventory.
    pub omitted_recovered_errors: u64,
    /// Address-only result has one successful family and another actual error.
    pub partial_addresses: bool,
}
struct Shared {
    clock: Arc<dyn RuntimeClock>,
    bootstrap: Vec<SocketAddr>,
    bootstrap_error: Option<Arc<Error>>,
    limits: DnsLimits,
    active: AtomicUsize,
    closing: AtomicBool,
}
impl Shared {
    fn unavailable_bootstrap(&self) -> Error {
        match &self.bootstrap_error {
            Some(error) => Error {
                cause: Cause::Bootstrap(error.clone()),
                spent: 0,
            },
            None => CoreError::NotReady.into(),
        }
    }
}
/// Explicit DNS-only factory with numeric bootstrap servers.
#[derive(Clone)]
pub struct RecursiveDns {
    shared: Arc<Shared>,
    security: Option<Arc<dyn Secure>>,
}
struct Permit(Arc<Shared>);
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}
/// Borrowed current pure GNS2DNS effect. No additional wire or policy state.
pub struct Request<'r> {
    /// Original IDNA question.
    pub name: &'r str,
    /// Original IDNA delegated authority.
    pub authority: &'r str,
    /// Original desired type.
    pub record_type: RecordType,
    /// Selected original server.
    pub server: IpAddr,
    /// Original authenticated GNS security records.
    pub security: &'r [Record],
    /// Remaining original work.
    pub remaining_steps: u32,
}
/// Full owned secured request, including the original delegation namespace.
pub struct SecuredRequest {
    /// Original IDNA question.
    pub name: String,
    /// Original GNS2DNS DNS authority before prepending unresolved labels.
    pub authority: String,
    /// Original requested type.
    pub record_type: RecordType,
    /// Actual selected server.
    pub server: IpAddr,
    /// Actual authenticated GNS security records.
    pub security: Vec<Record>,
    /// Original remaining recursion/work.
    pub remaining_steps: u32,
}
/// A real security-capable DNS resolver. It must validate the actual DNS chain,
/// use the same original budget/clock, and never trust AD or create a GNS loop.
/// No implementation or fake-success validator is installed by default.
pub trait Secure {
    /// Exact clock source used by the secured owner.
    fn clock(&self) -> Arc<dyn RuntimeClock>;
    /// Admit a genuine owned secured operation. Required security may not be
    /// silently downgraded. Its native retirement is part of the returned owner.
    fn query<'id>(
        &self,
        request: SecuredRequest,
        bounds: Bounds,
    ) -> Result<
        Box<dyn Operation<Error = NativeError<'id>, Report = Report<'id>> + 'id>,
        NativeError<'id>,
    >;
}
#[derive(Clone)]
struct Run {
    shared: Arc<Shared>,
    bounds: Bounds,
    trace: Rc<RefCell<DnsReport>>,
}
type OperationFuture = Pin<Box<dyn Future<Output = Result<Value, Error>>>>;
struct OwnedQuery<'id> {
    future: Option<OperationFuture>,
    permit: Option<Permit>,
    bounds: Bounds,
    alarm: Option<Pin<Box<Sleep>>>,
    trace: Option<Rc<RefCell<DnsReport>>>,
    closing: bool,
    lifetime: PhantomData<&'id ()>,
}
enum Inner<'id> {
    Owned(OwnedQuery<'id>),
    Secured {
        operation: Box<dyn Operation<Error = NativeError<'id>, Report = Report<'id>> + 'id>,
        permit: Option<Permit>,
    },
}
/// Original native DNS operation; secured providers remain original owned ports.
pub struct Query<'id> {
    inner: Inner<'id>,
}

/// Explicit native DNS resources, independent of protocol limits.
#[derive(Clone, Copy, Debug)]
pub struct DnsLimits {
    /// Simultaneous operations shared by every clone of this backend.
    pub operations: usize,
    /// Maximum actual UDP/TCP exchanges, including retries and NS children.
    pub exchanges: u32,
    /// Maximum nested nameserver address lookups.
    pub depth: usize,
    /// Maximum candidates retained at one referral.
    pub servers: usize,
    /// Maximum counted records in a packet and final record set.
    pub records: usize,
    /// Maximum input packet and final record payload bytes.
    pub bytes: usize,
    /// Arena for decompressed packet names and payloads.
    pub arena_bytes: usize,
    /// Maximum unrelated/malformed UDP datagrams consumed per exchange.
    pub rejected_packets: usize,
    /// Explicit finite attempts against each server.
    pub attempts: usize,
    /// Per-exchange canonical logical timeout, in microseconds.
    pub timeout_micros: u64,
    /// Ask explicit bootstrap recursive resolvers for recursion. Referrals use RD0.
    pub bootstrap_recursion_desired: bool,
    /// Standard production port53; alternate ports are explicit local policy.
    pub port: u16,
}
impl Default for DnsLimits {
    fn default() -> Self {
        Self {
            operations: 16,
            exchanges: 128,
            depth: 16,
            servers: 16,
            records: 256,
            bytes: 65535,
            arena_bytes: 262144,
            rejected_packets: 64,
            attempts: 2,
            timeout_micros: 2_000_000,
            port: 53,
            bootstrap_recursion_desired: true,
        }
    }
}

struct Budget {
    initial: u32,
    left: u32,
    trace: Rc<RefCell<DnsReport>>,
}
impl Budget {
    fn spend(&mut self) -> Result<(), Error> {
        self.left = self.left.checked_sub(1).ok_or(CoreError::Capacity)?;
        self.trace.borrow_mut().work_spent = self.spent();
        Ok(())
    }
    fn spent(&self) -> u32 {
        self.initial - self.left
    }
}
#[derive(Clone)]
struct OwnedRecord {
    signed: Option<Vec<u8>>,
    ttl: u32,
    name: Vec<u8>,
    kind: u16,
    class: u16,
    expiration: u64,
    data: Vec<u8>,
    target: Option<Vec<u8>>,
}
struct Reply {
    at: u64,
    code: u16,
    answers: Vec<OwnedRecord>,
    authority: Vec<OwnedRecord>,
    additional: Vec<OwnedRecord>,
}
enum Decision {
    Answer(Vec<OwnedRecord>),
    Alias(Vec<u8>, u64),
    Referral {
        zone: Vec<u8>,
        names: Vec<Vec<u8>>,
        glue: Vec<SocketAddr>,
        missing: Vec<Vec<u8>>,
    },
    Negative,
    Lame,
}
#[derive(Clone, Copy)]
struct QueryFlags {
    recursion_desired: bool,
    dnssec: bool,
}
struct Question {
    name: Vec<u8>,
    kind: u16,
    recursion_desired: bool,
}
type ResolveFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<Record>, Error>> + 'a>>;

impl RecursiveDns {
    /// Validate policy without network, configuration reads or detached work.
    pub fn new(
        clock: Arc<dyn RuntimeClock>,
        bootstrap: &[SocketAddr],
        limits: DnsLimits,
    ) -> Result<Self, Error> {
        Self::prepare(clock, bootstrap, limits, None)
    }
    /// Keep direct numeric GNS2DNS usable when system nameserver preparation
    /// failed. Any operation which actually needs bootstrap returns this same
    /// original cause, rather than a successful empty result or a registry miss.
    pub fn without_bootstrap(
        clock: Arc<dyn RuntimeClock>,
        error: Error,
        limits: DnsLimits,
    ) -> Result<Self, Error> {
        Self::prepare(clock, &[], limits, Some(Arc::new(error)))
    }
    /// Original preparation failure, if this factory lacks nameserver data.
    pub fn bootstrap_error(&self) -> Option<&Arc<Error>> {
        self.shared.bootstrap_error.as_ref()
    }
    fn prepare(
        clock: Arc<dyn RuntimeClock>,
        bootstrap: &[SocketAddr],
        limits: DnsLimits,
        bootstrap_error: Option<Arc<Error>>,
    ) -> Result<Self, Error> {
        if limits.operations == 0
            || limits.operations > 65_535
            || limits.exchanges == 0
            || limits.exchanges > 1_000_000
            || limits.depth == 0
            || limits.depth > 1024
            || limits.servers == 0
            || limits.servers > 65_535
            || limits.records == 0
            || limits.records > 5957
            || !(17..=65535).contains(&limits.bytes)
            || limits.arena_bytes < 255
            || limits.arena_bytes > 16 * 1024 * 1024
            || limits.rejected_packets == 0
            || limits.rejected_packets > 65_535
            || limits.attempts == 0
            || limits.attempts > 65_535
            || limits.timeout_micros == 0
            || limits.timeout_micros == u64::MAX
            || Instant::now()
                .checked_add(std::time::Duration::from_micros(limits.timeout_micros))
                .is_none()
            || limits.port == 0
            || bootstrap.len() > limits.servers
        {
            return Err(CoreError::InvalidInput.into());
        }
        for address in bootstrap {
            valid_server(*address)?;
        }
        Ok(Self {
            shared: Arc::new(Shared {
                clock,
                bootstrap: copy_slice(bootstrap)?,
                bootstrap_error,
                limits,
                active: AtomicUsize::new(0),
                closing: AtomicBool::new(false),
            }),
            security: None,
        })
    }
    /// Read explicit resolv.conf configuration with a hard byte limit. This
    /// factory performs file I/O, never name-service lookup or network I/O.
    pub fn from_resolv_conf(
        clock: Arc<dyn RuntimeClock>,
        path: &std::path::Path,
        maximum_bytes: usize,
        limits: DnsLimits,
    ) -> Result<Self, Error> {
        if maximum_bytes == 0 || maximum_bytes > 1_048_576 {
            return Err(CoreError::InvalidInput.into());
        }
        let file = std::fs::File::open(path)?;
        let mut reader = std::io::Read::take(
            file,
            u64::try_from(maximum_bytes).map_err(|_| CoreError::Overflow)? + 1,
        );
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(maximum_bytes.min(4096))
            .map_err(Error::allocation)?;
        std::io::Read::read_to_end(&mut reader, &mut bytes)?;
        if bytes.len() > maximum_bytes {
            return Err(CoreError::Capacity.into());
        }
        let servers = Self::resolvers_from_bytes(&bytes, limits.port, limits.servers)?;
        Self::new(clock, &servers, limits)
    }
    /// Parse numeric system DNS endpoints. Unknown options are ignored, while
    /// a malformed nameserver is explicit; no hostname/NSS fallback is made.
    pub fn resolvers_from_bytes(
        input: &[u8],
        default_port: u16,
        maximum_servers: usize,
    ) -> Result<Vec<SocketAddr>, Error> {
        if default_port == 0 || maximum_servers == 0 || input.len() > 1_048_576 {
            return Err(CoreError::InvalidInput.into());
        }
        let text = std::str::from_utf8(input).map_err(|_| CoreError::Malformed)?;
        let mut result = Vec::new();
        for line in text.lines() {
            let line = line.split(['#', ';']).next().unwrap_or("");
            let mut words = line.split_whitespace();
            if !words
                .next()
                .is_some_and(|key| key.eq_ignore_ascii_case("nameserver"))
            {
                continue;
            }
            let value = words.next().ok_or(CoreError::Malformed)?;
            let address = if let Ok(ip) = value.parse::<IpAddr>() {
                SocketAddr::new(ip, default_port)
            } else {
                value
                    .parse::<SocketAddr>()
                    .or_else(|_| format!("[{value}]:{default_port}").parse::<SocketAddr>())
                    .map_err(|_| CoreError::InvalidInput)?
            };
            push_server(&mut result, address, maximum_servers)?;
        }
        if result.is_empty() {
            return Err(CoreError::NotReady.into());
        }
        Ok(result)
    }
}
impl Run {
    fn retain(&self, error: Error) {
        let mut trace = self.trace.borrow_mut();
        if trace.first_recovered_error.is_none() {
            trace.first_recovered_error = Some(error);
        } else {
            trace.omitted_recovered_errors = trace.omitted_recovered_errors.saturating_add(1);
        }
    }
    fn budget(&self, allowance: u32) -> Result<Budget, Error> {
        let n = allowance.min(self.shared.limits.exchanges);
        if n == 0 {
            return Err(CoreError::Capacity.into());
        }
        Ok(Budget {
            initial: n,
            left: n,
            trace: self.trace.clone(),
        })
    }
    fn native(&self, hard: Instant) -> Result<(), Error> {
        if Instant::now() >= self.bounds.hard().min(hard) {
            return Err(CoreError::Timeout.into());
        }
        Ok(())
    }
    fn now(&self, deadline: AbsoluteTime) -> Result<AbsoluteTime, Error> {
        self.native(self.bounds.hard())?;
        let now = self.shared.clock.sample().map_err(Error::clock)?.now;
        self.native(self.bounds.hard())?;
        if now >= deadline || now >= self.bounds.until() {
            return Err(CoreError::Timeout.into());
        }
        Ok(now)
    }
    async fn bounded<T>(
        &self,
        deadline: AbsoluteTime,
        hard: Instant,
        future: impl Future<Output = Result<T, Error>>,
    ) -> Result<(T, u64), Error> {
        self.native(hard)?;
        self.now(deadline)?;
        let native = tokio::time::sleep_until(hard.min(self.bounds.hard()));
        let mut native = std::pin::pin!(native);
        // Deadline is a wake source. Its Pending is not a stable-clock receipt.
        let mut observation = self.shared.clock.subscribe().map_err(Error::clock)?;
        let mut revision = 0;
        let timer = Deadline::at(self.shared.clock.clone(), deadline).map_err(Error::clock)?;
        let mut timer = std::pin::pin!(timer);
        let mut future = std::pin::pin!(future);
        poll_fn(|cx| {
            if Instant::now() >= hard.min(self.bounds.hard()) || native.as_mut().poll(cx).is_ready()
            {
                return Poll::Ready(Err(CoreError::Timeout.into()));
            }
            match timer.as_mut().poll(cx) {
                Poll::Ready(Err(e)) => return Poll::Ready(Err(Error::clock(e))),
                Poll::Ready(Ok(())) => return Poll::Ready(Err(CoreError::Timeout.into())),
                Poll::Pending => {}
            }
            let sample = match stable_clock(
                self.shared.clock.as_ref(),
                observation.as_mut(),
                &mut revision,
                cx,
            ) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(sample)) => sample,
            };
            if sample.now >= deadline
                || sample.now >= self.bounds.until()
                || Instant::now() >= hard.min(self.bounds.hard())
            {
                return Poll::Ready(Err(CoreError::Timeout.into()));
            }
            future
                .as_mut()
                .poll(cx)
                .map(|result| result.map(|value| (value, sample.now.as_micros())))
        })
        .await
    }
    async fn exchange(
        &self,
        name: &[u8],
        kind: u16,
        server: SocketAddr,
        budget: &mut Budget,
        deadline: AbsoluteTime,
        flags: QueryFlags,
    ) -> Result<Reply, Error> {
        valid_server(server)?;
        budget.spend()?;
        cooperate().await;
        // Capture this exchange's native cap before sampling/setup. UDP and its
        // TCP fallback share both this cap and the original whole-query bounds.
        let native_hard = Instant::now()
            .checked_add(std::time::Duration::from_micros(
                self.shared.limits.timeout_micros,
            ))
            .ok_or(CoreError::Overflow)?
            .min(self.bounds.hard());
        let now = self.now(deadline)?;
        let end = AbsoluteTime::from_micros(
            deadline
                .as_micros()
                .min(self.bounds.until().as_micros())
                .min(
                    now.as_micros()
                        .saturating_add(self.shared.limits.timeout_micros),
                ),
        );
        self.native(native_hard)?;
        let mut id = [0; 2];
        getrandom::fill(&mut id).map_err(Error::entropy)?;
        self.native(native_hard)?;
        self.trace.borrow_mut().exchanges += 1;
        let mut query = query_bytes(name, kind, id, flags.recursion_desired)?;
        if flags.dnssec {
            // EDNS0 with DO, and CD so a forwarding server cannot discard the
            // original evidence before this independent validator sees it.
            query[3] |= 0x10;
            query[11] = 1;
            query.try_reserve_exact(11).map_err(Error::allocation)?;
            let advertised = u16::try_from(self.shared.limits.bytes.min(1232))
                .map_err(|_| CoreError::Overflow)?;
            query.extend_from_slice(&[0, 0, 41]);
            query.extend_from_slice(&advertised.to_be_bytes());
            query.extend_from_slice(&[0, 0, 128, 0, 0, 0]);
        }
        let (data, received) = self
            .bounded(end, native_hard, async {
                let bind = match server.ip() {
                    IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
                };
                self.native(native_hard)?;
                let socket = UdpSocket::bind(bind).await?;
                self.trace.borrow_mut().udp_bindings += 1;
                self.native(native_hard)?;
                let sent = socket.send_to(&query, server).await?;
                self.trace.borrow_mut().written_bytes += sent as u64;
                if sent != query.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "DNS UDP datagram incomplete",
                    )
                    .into());
                }
                let mut input = zeroes(self.shared.limits.bytes + 1)?;
                let mut rejected = 0;
                loop {
                    self.native(native_hard)?;
                    let (n, source) = socket.recv_from(&mut input).await?;
                    self.trace.borrow_mut().read_bytes += n as u64;
                    self.native(native_hard)?;
                    if source == server
                        && n <= self.shared.limits.bytes
                        && matches_question(&input[..n], name, kind, id)
                    {
                        input.truncate(n);
                        break Ok(input);
                    }
                    rejected += 1;
                    self.trace.borrow_mut().rejected_datagrams += 1;
                    if rejected == self.shared.limits.rejected_packets {
                        return Err(CoreError::Malformed.into());
                    }
                    cooperate().await;
                }
            })
            .await?;
        if Header::decode(&data)?.flags.message_truncated() {
            budget.spend()?;
            cooperate().await;
            self.native(native_hard)?;
            let (data, received) = self
                .bounded(end, native_hard, async {
                    self.native(native_hard)?;
                    let mut socket = TcpStream::connect(server).await?;
                    self.trace.borrow_mut().tcp_connections += 1;
                    self.native(native_hard)?;
                    let n = u16::try_from(query.len()).map_err(|_| CoreError::TooLarge)?;
                    self.write(&mut socket, &n.to_be_bytes(), native_hard)
                        .await?;
                    self.write(&mut socket, &query, native_hard).await?;
                    let mut prefix = [0; 2];
                    self.read(&mut socket, &mut prefix, native_hard).await?;
                    let n = usize::from(u16::from_be_bytes(prefix));
                    if n < 12 || n > self.shared.limits.bytes {
                        return Err(CoreError::Capacity.into());
                    }
                    let mut bytes = zeroes(n)?;
                    self.read(&mut socket, &mut bytes, native_hard).await?;
                    if !matches_question(&bytes, name, kind, id)
                        || Header::decode(&bytes)?.flags.message_truncated()
                    {
                        return Err(CoreError::Malformed.into());
                    }
                    Ok(bytes)
                })
                .await?;
            self.parse(&data, received, flags.dnssec)
        } else {
            self.parse(&data, received, flags.dnssec)
        }
    }
    async fn write(
        &self,
        socket: &mut TcpStream,
        mut input: &[u8],
        hard: Instant,
    ) -> Result<(), Error> {
        while !input.is_empty() {
            self.native(hard)?;
            let n = socket.write(input).await?;
            self.trace.borrow_mut().written_bytes += n as u64;
            if n == 0 {
                return Err(io::Error::from(io::ErrorKind::WriteZero).into());
            }
            input = &input[n..];
            cooperate().await;
        }
        self.native(hard)
    }
    async fn read(
        &self,
        socket: &mut TcpStream,
        mut output: &mut [u8],
        hard: Instant,
    ) -> Result<(), Error> {
        while !output.is_empty() {
            self.native(hard)?;
            let n = socket.read(output).await?;
            self.trace.borrow_mut().read_bytes += n as u64;
            if n == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
            }
            let (_, tail) = output.split_at_mut(n);
            output = tail;
            cooperate().await;
        }
        self.native(hard)
    }
    fn parse(&self, input: &[u8], now: u64, dnssec: bool) -> Result<Reply, Error> {
        let mut bytes = input.len().max(255).min(self.shared.limits.arena_bytes);
        loop {
            self.native(self.bounds.hard())?;
            match self.parse_in(input, now, bytes, dnssec) {
                Err(Error {
                    cause: Cause::Protocol(CoreError::Capacity),
                    ..
                }) if bytes < self.shared.limits.arena_bytes => {
                    bytes = bytes
                        .checked_mul(2)
                        .ok_or(CoreError::Overflow)?
                        .min(self.shared.limits.arena_bytes);
                }
                result => return result,
            }
        }
    }
    fn parse_in(
        &self,
        input: &[u8],
        now: u64,
        arena_bytes: usize,
        dnssec: bool,
    ) -> Result<Reply, Error> {
        let limits = self.shared.limits;
        let header = Header::decode(input)?;
        let count = usize::from(header.counts.answers)
            .checked_add(usize::from(header.counts.authority))
            .and_then(|n| n.checked_add(usize::from(header.counts.additional)))
            .ok_or(CoreError::Overflow)?;
        if header.counts.queries != 1 || count > limits.records {
            return Err(CoreError::Capacity.into());
        }
        let mut storage = zeroes(arena_bytes)?;
        let mut arena = Arena::new(&mut storage);
        let mut queries = [DnsQuestion::EMPTY; 1];
        let mut records = Vec::new();
        records
            .try_reserve_exact(count)
            .map_err(Error::allocation)?;
        records.resize(count, gnunet_dns::Record::EMPTY);
        let packet = Packet::parse(
            input,
            AbsoluteTime::from_micros(now),
            &mut arena,
            &mut queries,
            &mut records,
            gnunet_dns::Limits {
                maximum_packet_bytes: limits.bytes,
                maximum_queries: 1,
                maximum_records: limits.records,
                maximum_compression_hops: 33,
                maximum_work: limits
                    .arena_bytes
                    .checked_mul(16)
                    .ok_or(CoreError::Overflow)?,
                maximum_text_input_bytes: 255,
            },
        )?;
        if packet.consumed != input.len() {
            return Err(CoreError::Malformed.into());
        }
        let convert = |rs: &[gnunet_dns::Record<'_>]| -> Result<Vec<OwnedRecord>, Error> {
            let mut out = Vec::new();
            out.try_reserve_exact(rs.len()).map_err(Error::allocation)?;
            for r in rs {
                let mut data = zeroes(r.data_len()?)?;
                r.data.encode(&mut data)?;
                let signed = if dnssec {
                    let mut canonical = zeroes(data.len())?;
                    gnunet_dns::dnssec::canonical_rdata(r.kind.0, &data, &mut canonical)?;
                    Some(canonical)
                } else {
                    None
                };
                if r.kind.0 == 16 {
                    data = txt(&data)?;
                }
                let target = if let RData::Hostname(name) = r.data {
                    Some(canonical(name.wire())?)
                } else {
                    None
                };
                // RFC2181 TTL high bit is not a 136-year caching authority.
                let expiration =
                    if r.expiration.as_micros().saturating_sub(now) / 1_000_000 > i32::MAX as u64 {
                        now
                    } else {
                        r.expiration.as_micros()
                    };
                out.push(OwnedRecord {
                    signed,
                    ttl: u32::try_from(expiration.saturating_sub(now) / 1_000_000)
                        .map_err(|_| CoreError::Overflow)?,
                    name: canonical(r.name.wire())?,
                    kind: r.kind.0,
                    class: r.class,
                    expiration,
                    data,
                    target,
                });
            }
            Ok(out)
        };
        let code = response_code(input, limits.records)?;
        self.trace.borrow_mut().last_response_code = Some(code);
        self.trace.borrow_mut().last_flags = Some(packet.flags);
        Ok(Reply {
            at: now,
            code,
            answers: convert(packet.answers)?,
            authority: convert(packet.authority)?,
            additional: convert(packet.additional)?,
        })
    }
    fn decision(
        &self,
        reply: Reply,
        name: &[u8],
        kind: u16,
        zone: &[u8],
    ) -> Result<Decision, Error> {
        let code = reply.code;
        if code != 0 && code != 3 {
            return Err(Error::response_code(code));
        }
        let answers: Vec<_> = reply.answers.into_iter().filter(|r| r.class == 1).collect();
        if let Some(alias) = answers.iter().find(|r| r.name == name && r.kind == 5) {
            let target = alias.target.as_ref().ok_or(CoreError::Malformed)?;
            if answers.iter().any(|r| {
                r.name == name
                    && ((r.kind == 5 && r.target.as_ref() != Some(target))
                        || !matches!(r.kind, 5 | 24 | 25 | 30 | 46 | 47 | 50))
            }) {
                return Err(CoreError::Malformed.into());
            }
        }
        let direct: Vec<_> = answers
            .iter()
            .filter(|r| r.name == name && (kind == 255 || r.kind == kind))
            .cloned()
            .collect();
        if !direct.is_empty() && code == 0 {
            return Ok(Decision::Answer(direct));
        }
        // A matching DNS response may already carry the complete CNAME chain.
        // Consume its actual target RRset instead of requiring a new external
        // lookup that can fail for the selected server's legitimate split view.
        if let Some((target, expiration)) = inline_target(&answers, name, kind)? {
            let count = answers
                .iter()
                .filter(|r| r.name == target && (kind == 255 || r.kind == kind))
                .count();
            let mut direct = Vec::new();
            direct.try_reserve_exact(count).map_err(Error::allocation)?;
            for mut record in answers {
                if record.name == target && (kind == 255 || record.kind == kind) {
                    record.expiration = record.expiration.min(expiration);
                    direct.push(record);
                }
            }
            return Ok(Decision::Answer(direct));
        }
        let cnames: Vec<_> = answers
            .iter()
            .filter(|r| r.name == name && r.kind == 5)
            .collect();
        if let Some(first) = cnames.first() {
            let target = first.target.as_ref().ok_or(CoreError::Malformed)?;
            if cnames.iter().any(|r| r.target.as_ref() != Some(target)) {
                return Err(CoreError::Malformed.into());
            }
            return Ok(Decision::Alias(
                copy_slice(target)?,
                cnames
                    .iter()
                    .map(|r| r.expiration)
                    .min()
                    .ok_or(CoreError::Malformed)?,
            ));
        }
        if let Some(dname) = answers
            .iter()
            .filter(|r| r.kind == 39 && r.name != name && suffix(name, &r.name))
            .max_by_key(|r| r.name.len())
        {
            let target = dname.target.as_ref().ok_or(CoreError::Malformed)?;
            let prefix = name
                .len()
                .checked_sub(dname.name.len())
                .ok_or(CoreError::Malformed)?;
            let mut result = copy_slice(&name[..prefix])?;
            result
                .try_reserve_exact(target.len())
                .map_err(Error::allocation)?;
            result.extend_from_slice(target);
            Name::from_wire(&result)?;
            return Ok(Decision::Alias(result, dname.expiration));
        }
        let negative = reply
            .authority
            .iter()
            .any(|r| r.class == 1 && r.kind == 6 && suffix(name, &r.name) && suffix(&r.name, zone));
        if negative {
            return Ok(Decision::Negative);
        }
        if code == 3 {
            return Ok(Decision::Lame);
        }
        let closest = reply
            .authority
            .iter()
            .filter(|r| {
                r.class == 1
                    && r.kind == 2
                    && suffix(name, &r.name)
                    && suffix(&r.name, zone)
                    && r.name.len() > zone.len()
            })
            .map(|r| r.name.len())
            .max();
        let Some(closest) = closest else {
            return Ok(Decision::Lame);
        };
        let mut names = Vec::new();
        let mut next_zone = None;
        for r in reply.authority.iter().filter(|r| {
            r.class == 1 && r.kind == 2 && r.name.len() == closest && suffix(name, &r.name)
        }) {
            let target = r.target.as_ref().ok_or(CoreError::Malformed)?;
            if !names.contains(target) {
                if names.len() == self.shared.limits.servers {
                    return Err(CoreError::Capacity.into());
                }
                names.push(copy_slice(target)?);
            }
            next_zone = Some(copy_slice(&r.name)?);
        }
        let zone = next_zone.ok_or(CoreError::Malformed)?;
        let mut glue = Vec::new();
        let mut missing = Vec::new();
        for ns in &names {
            let mut found = false;
            if suffix(ns, &zone) {
                for r in reply
                    .additional
                    .iter()
                    .filter(|r| r.class == 1 && r.name == *ns)
                {
                    if let Some(ip) = address(r)? {
                        push_server(
                            &mut glue,
                            SocketAddr::new(ip, self.shared.limits.port),
                            self.shared.limits.servers,
                        )?;
                        found = true;
                    }
                }
            }
            if !found {
                missing.push(copy_slice(ns)?);
            }
        }
        Ok(Decision::Referral {
            zone,
            names,
            glue,
            missing,
        })
    }
    fn resolve<'a>(
        &'a self,
        question: Question,
        mut servers: Vec<SocketAddr>,
        mut zone: Vec<u8>,
        budget: &'a mut Budget,
        depth: usize,
        deadline: AbsoluteTime,
    ) -> ResolveFuture<'a> {
        Box::pin(async move {
            let Question {
                mut name,
                kind,
                mut recursion_desired,
            } = question;
            if depth >= self.shared.limits.depth {
                return Err(CoreError::Capacity.into());
            }
            let mut seen = Vec::new();
            seen.push(copy_slice(&name)?);
            let mut alias_expiration = u64::MAX;
            let mut missing = Vec::new();
            loop {
                self.now(deadline)?;
                if budget.left == 0 {
                    return Err(CoreError::Capacity.into());
                }
                let mut next = None;
                let mut last = None;
                'servers: for server in &servers {
                    for _ in 0..self.shared.limits.attempts {
                        let reply = match self
                            .exchange(
                                &name,
                                kind,
                                *server,
                                budget,
                                deadline,
                                QueryFlags {
                                    recursion_desired,
                                    dnssec: false,
                                },
                            )
                            .await
                        {
                            Ok(reply) => reply,
                            Err(error) => {
                                if terminal(&error, budget) {
                                    return Err(error);
                                }
                                if let Some(previous) = last.replace(error) {
                                    self.retain(previous);
                                }
                                continue;
                            }
                        };
                        let received = reply.at;
                        match match self.decision(reply, &name, kind, &zone) {
                            Ok(decision) => decision,
                            Err(error) => {
                                if terminal(&error, budget) {
                                    return Err(error);
                                }
                                if let Some(previous) = last.replace(error) {
                                    self.retain(previous);
                                }
                                continue;
                            }
                        } {
                            Decision::Answer(rs) => {
                                let now = received;
                                let mut result = Vec::new();
                                let mut rrset_times: Vec<(u16, u64)> = Vec::new();
                                rrset_times
                                    .try_reserve_exact(rs.len())
                                    .map_err(Error::allocation)?;
                                for r in &rs {
                                    if let Some((_, time)) =
                                        rrset_times.iter_mut().find(|(kind, _)| *kind == r.kind)
                                    {
                                        *time = (*time).min(r.expiration);
                                    } else {
                                        rrset_times.push((r.kind, r.expiration));
                                    }
                                }

                                let mut bytes = 0_usize;
                                for r in rs {
                                    bytes = bytes
                                        .checked_add(r.data.len())
                                        .ok_or(CoreError::Overflow)?;
                                    if result.len() == self.shared.limits.records
                                        || bytes > self.shared.limits.bytes
                                    {
                                        return Err(CoreError::Capacity.into());
                                    }
                                    let expires = rrset_times
                                        .iter()
                                        .find(|(kind, _)| *kind == r.kind)
                                        .ok_or(CoreError::Stale)?
                                        .1
                                        .min(alias_expiration);
                                    let (flags, expiration) = if expires <= now {
                                        (RecordFlags::RELATIVE_EXPIRATION, 0)
                                    } else {
                                        (RecordFlags::NONE, expires)
                                    };
                                    let record = Record {
                                        origin: Origin::Dns(server.ip()),
                                        expiration_time: expiration,
                                        record_type: RecordType::new(u32::from(r.kind)),
                                        flags,
                                        data: r.data,
                                    };
                                    record.as_data().validate_fixed_size()?;
                                    result.push(record);
                                }
                                if let Some(error) = last.take() {
                                    self.retain(error);
                                }
                                return Ok(result);
                            }
                            Decision::Negative => {
                                if let Some(error) = last.take() {
                                    self.retain(error);
                                }
                                return Ok(Vec::new());
                            }
                            Decision::Alias(target, expiration) => {
                                if seen.contains(&target) {
                                    if let Some(previous) =
                                        last.replace(CoreError::Malformed.into())
                                    {
                                        self.retain(previous);
                                    }
                                    continue;
                                }
                                if !suffix(&target, &zone) && self.shared.bootstrap.is_empty() {
                                    if let Some(previous) =
                                        last.replace(self.shared.unavailable_bootstrap())
                                    {
                                        self.retain(previous);
                                    }
                                    continue;
                                }
                                seen.try_reserve(1).map_err(Error::allocation)?;
                                seen.push(copy_slice(&target)?);
                                alias_expiration = alias_expiration.min(expiration);
                                next = Some((target, None));
                                break 'servers;
                            }
                            Decision::Referral {
                                zone: target,
                                names,
                                glue,
                                missing: unresolved,
                            } => {
                                drop(names);
                                missing = unresolved;
                                next = Some((copy_slice(&name)?, Some((target, glue))));
                                break 'servers;
                            }
                            Decision::Lame => {
                                if let Some(previous) = last.replace(CoreError::NotFound.into()) {
                                    self.retain(previous);
                                }
                                break;
                            }
                        }
                    }
                }
                if let Some((target, referral)) = next {
                    if let Some((target_zone, glue)) = referral {
                        zone = target_zone;
                        servers = glue;
                        recursion_desired = false;
                    } else {
                        if !suffix(&target, &zone) {
                            if self.shared.bootstrap.is_empty() {
                                return Err(self.shared.unavailable_bootstrap());
                            }
                            servers = copy_slice(&self.shared.bootstrap)?;
                            zone = vec![0];
                            recursion_desired = self.shared.limits.bootstrap_recursion_desired;
                        }
                        missing.clear();
                        name = target;
                    }
                    if !servers.is_empty() {
                        if let Some(error) = last.take() {
                            self.retain(error);
                        }
                        continue;
                    }
                }
                if !missing.is_empty() {
                    let ns = missing.remove(0);
                    if self.shared.bootstrap.is_empty() {
                        return Err(self.shared.unavailable_bootstrap());
                    }
                    let mut addresses = Vec::new();
                    for family in [1, 28] {
                        match self
                            .resolve(
                                Question {
                                    name: copy_slice(&ns)?,
                                    kind: family,
                                    recursion_desired: self
                                        .shared
                                        .limits
                                        .bootstrap_recursion_desired,
                                },
                                copy_slice(&self.shared.bootstrap)?,
                                vec![0],
                                budget,
                                depth + 1,
                                deadline,
                            )
                            .await
                        {
                            Ok(rs) => {
                                for r in rs {
                                    if let Some(ip) = address_data(r.record_type.value(), &r.data)?
                                    {
                                        push_server(
                                            &mut addresses,
                                            SocketAddr::new(ip, self.shared.limits.port),
                                            self.shared.limits.servers,
                                        )?;
                                    }
                                }
                            }
                            Err(error) => {
                                if terminal(&error, budget) {
                                    return Err(error);
                                }
                                if let Some(previous) = last.replace(error) {
                                    self.retain(previous);
                                }
                            }
                        }
                    }
                    servers = addresses;
                    if !servers.is_empty() {
                        if let Some(error) = last.take() {
                            self.retain(error);
                        }
                        continue;
                    }
                    if !missing.is_empty() {
                        continue;
                    }
                }
                return Err(last.unwrap_or_else(|| CoreError::NotFound.into()));
            }
        })
    }
}
fn terminal(error: &Error, budget: &Budget) -> bool {
    budget.left == 0
        || matches!(
            &error.cause,
            Cause::Clock(_)
                | Cause::Allocation(_)
                | Cause::Entropy(_)
                | Cause::SecurityUnavailable { .. }
                | Cause::Protocol(
                    CoreError::Capacity
                        | CoreError::TooLarge
                        | CoreError::Overflow
                        | CoreError::Entropy
                )
        )
}

fn kind(value: RecordType) -> Result<u16, Error> {
    match value.value() {
        0 => Ok(255),
        251 | 252 => Err(CoreError::Unsupported.into()),
        n => u16::try_from(n).map_err(|_| CoreError::Unsupported.into()),
    }
}
fn valid_server(a: SocketAddr) -> Result<(), Error> {
    if a.port() == 0
        || a.ip().is_unspecified()
        || a.ip().is_multicast()
        || matches!(a.ip(),IpAddr::V4(ip)if ip.is_broadcast())
    {
        Err(CoreError::InvalidInput.into())
    } else {
        Ok(())
    }
}
fn push_server(out: &mut Vec<SocketAddr>, value: SocketAddr, max: usize) -> Result<(), Error> {
    valid_server(value)?;
    if !out.contains(&value) {
        if out.len() == max {
            return Err(CoreError::Capacity.into());
        }
        out.try_reserve(1).map_err(Error::allocation)?;
        out.push(value);
    }
    Ok(())
}
fn copy_slice<T: Clone>(input: &[T]) -> Result<Vec<T>, Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(input.len())
        .map_err(Error::allocation)?;
    out.extend_from_slice(input);
    Ok(out)
}
fn zeroes(n: usize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(n).map_err(Error::allocation)?;
    out.resize(n, 0);
    Ok(out)
}
fn canonical(input: &[u8]) -> Result<Vec<u8>, Error> {
    Name::from_wire(input)?;
    let mut out = copy_slice(input)?;
    out.make_ascii_lowercase();
    Ok(out)
}
fn wire_name(input: &str) -> Result<Vec<u8>, Error> {
    if !input.is_ascii() {
        return Err(CoreError::InvalidInput.into());
    }
    let mut b = [0; 255];
    let mut a = Arena::new(&mut b);
    let name = Name::from_dotted(input.as_bytes(), &mut a)?;
    canonical(name.wire())
}
fn suffix(name: &[u8], zone: &[u8]) -> bool {
    let mut at = 0;
    loop {
        if name.get(at..) == Some(zone) {
            return true;
        }
        let Some(&n) = name.get(at) else {
            return false;
        };
        if n == 0 {
            return false;
        }
        at += usize::from(n) + 1;
    }
}
fn query_bytes(
    name: &[u8],
    kind: u16,
    id: [u8; 2],
    recursion_desired: bool,
) -> Result<Vec<u8>, Error> {
    Name::from_wire(name)?;
    let mut out = zeroes(12)?;
    out[..2].copy_from_slice(&id);
    if recursion_desired {
        out[2] = 1;
    }
    out[5] = 1;
    out.try_reserve_exact(name.len() + 4)
        .map_err(Error::allocation)?;
    out.extend_from_slice(name);
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&1_u16.to_be_bytes());
    Ok(out)
}
fn matches_question(input: &[u8], name: &[u8], kind: u16, id: [u8; 2]) -> bool {
    let Ok(header) = Header::decode(input) else {
        return false;
    };
    if header.id != id || header.flags.bits() & 0xf800 != 0x8000 || header.counts.queries != 1 {
        return false;
    }
    let mut b = [0; 255];
    let mut a = Arena::new(&mut b);
    let Ok(mut reader) = gnunet_dns::Reader::at(
        input,
        12,
        input.len(),
        gnunet_dns::Limits {
            maximum_queries: 1,
            maximum_records: 0,
            ..gnunet_dns::Limits::DNS
        },
    ) else {
        return false;
    };
    let Ok(q) = reader.query(&mut a) else {
        return false;
    };
    q.class == 1 && q.kind.0 == kind && q.name.wire().eq_ignore_ascii_case(name)
}
fn address(record: &OwnedRecord) -> Result<Option<IpAddr>, Error> {
    address_data(u32::from(record.kind), &record.data)
}
fn address_data(kind: u32, data: &[u8]) -> Result<Option<IpAddr>, Error> {
    match kind {
        1 => Ok(Some(IpAddr::from(
            <[u8; 4]>::try_from(data).map_err(|_| CoreError::Malformed)?,
        ))),
        28 => Ok(Some(IpAddr::from(
            <[u8; 16]>::try_from(data).map_err(|_| CoreError::Malformed)?,
        ))),
        _ => Ok(None),
    }
}
async fn cooperate() {
    let mut first = true;
    poll_fn(|cx| {
        if first {
            first = false;
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await
}

fn stable_clock(
    clock: &dyn RuntimeClock,
    subscription: &mut dyn ClockSubscription,
    revision: &mut u64,
    cx: &mut Context<'_>,
) -> Poll<Result<ClockSample, Error>> {
    match subscription.poll_changed(cx, *revision) {
        Poll::Ready(Err(e)) => return Poll::Ready(Err(Error::clock(e))),
        Poll::Ready(Ok(sample)) => *revision = sample.revision,
        Poll::Pending => {}
    }
    let sample = match clock.sample() {
        Ok(sample) => sample,
        Err(e) => return Poll::Ready(Err(Error::clock(e))),
    };
    match subscription.poll_changed(cx, sample.revision) {
        Poll::Ready(Err(e)) => Poll::Ready(Err(Error::clock(e))),
        Poll::Ready(Ok(_)) => {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
        Poll::Pending => {
            *revision = sample.revision;
            Poll::Ready(Ok(sample))
        }
    }
}

fn txt(input: &[u8]) -> Result<Vec<u8>, Error> {
    if input.is_empty() {
        return Err(CoreError::Malformed.into());
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(input.len())
        .map_err(Error::allocation)?;
    let mut at = 0usize;
    while at < input.len() {
        let n = usize::from(input[at]);
        at += 1;
        let end = at.checked_add(n).ok_or(CoreError::Overflow)?;
        output.extend_from_slice(input.get(at..end).ok_or(CoreError::Truncated)?);
        at = end;
    }
    Ok(output)
}

impl DnsReport {
    fn new(bounds: Bounds) -> Self {
        Self {
            bounds,
            exchanges: 0,
            work_spent: 0,
            udp_bindings: 0,
            tcp_connections: 0,
            read_bytes: 0,
            written_bytes: 0,
            rejected_datagrams: 0,
            completed: false,
            cancelled: false,
            closed: false,
            dnssec_verified: false,
            dnssec_insecure: false,
            last_response_code: None,
            last_flags: None,
            first_recovered_error: None,
            omitted_recovered_errors: 0,
            partial_addresses: false,
        }
    }
}
impl RecursiveDns {
    /// Same real clock used by this factory and its original operations.
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.shared.clock.clone()
    }
    /// Install a genuine full security provider. It must own no native work
    /// outside returned operations; cloning this port starts no task or worker.
    pub fn with_security(mut self, security: Arc<dyn Secure>) -> Result<Self, Error> {
        if !Arc::ptr_eq(&self.shared.clock, &security.clock()) {
            return Err(CoreError::InvalidInput.into());
        }
        self.security = Some(security);
        Ok(self)
    }
    fn permit(&self) -> Result<Permit, Error> {
        if self.shared.closing.load(Ordering::Acquire) {
            return Err(CoreError::Closed.into());
        }
        self.shared
            .active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < self.shared.limits.operations).then(|| count + 1)
            })
            .map_err(|_| CoreError::WouldBlock)?;
        let permit = Permit(self.shared.clone());
        if self.shared.closing.load(Ordering::Acquire) {
            return Err(CoreError::Closed.into());
        }
        Ok(permit)
    }
    fn ordinary<'id>(
        &self,
        bounds: Bounds,
        permit: Permit,
        run: Run,
        future: impl Future<Output = Result<Value, Error>> + 'static,
    ) -> Query<'id> {
        Query {
            inner: Inner::Owned(OwnedQuery {
                future: Some(Box::pin(future)),
                permit: Some(permit),
                bounds,
                alarm: None,
                trace: Some(run.trace),
                closing: false,
                lifetime: PhantomData,
            }),
        }
    }
    /// Genuine GNS2DNS query to the selected server. Ordinary resolution never
    /// interprets a subsequent DNS name as GNS. Required security is delegated
    /// to a real installed provider or explicitly fails, never trusts AD.
    pub fn query<'id>(
        &self,
        request: Request<'_>,
        bounds: Bounds,
    ) -> Result<Query<'id>, NativeError<'id>> {
        let Request {
            name,
            authority,
            record_type,
            server,
            security,
            remaining_steps,
        } = request;
        super::guard(bounds)?;
        let permit = self.permit().map_err(NativeError::Dns)?;
        if !security.is_empty() {
            let provider = self
                .security
                .as_ref()
                .ok_or_else(|| NativeError::Dns(Error::security_unavailable(security.len())))?;
            let mut records = Vec::new();
            records
                .try_reserve_exact(security.len())
                .map_err(Error::allocation)
                .map_err(NativeError::Dns)?;
            for record in security {
                records.push(Record {
                    origin: record.origin,
                    expiration_time: record.expiration_time,
                    record_type: record.record_type,
                    flags: record.flags,
                    data: copy_slice(&record.data).map_err(NativeError::Dns)?,
                });
            }
            let request = SecuredRequest {
                name: owned(name).map_err(NativeError::Dns)?,
                authority: owned(authority).map_err(NativeError::Dns)?,
                record_type,
                server,
                security: records,
                remaining_steps,
            };
            super::guard(bounds)?;
            let operation = provider.query(request, bounds)?;
            return Ok(Query {
                inner: Inner::Secured {
                    operation,
                    permit: Some(permit),
                },
            });
        }
        let kind = kind(record_type).map_err(NativeError::Dns)?;
        let name = wire_name(name).map_err(NativeError::Dns)?;
        let authority = wire_name(authority).map_err(NativeError::Dns)?;
        if !suffix(&name, &authority) {
            return Err(CoreError::InvalidInput.into());
        }
        if name.len() + 16 > self.shared.limits.bytes {
            return Err(CoreError::Capacity.into());
        }
        let server = SocketAddr::new(server, self.shared.limits.port);
        valid_server(server).map_err(NativeError::Dns)?;
        let trace = Rc::new(RefCell::new(DnsReport::new(bounds)));
        let run = Run {
            shared: self.shared.clone(),
            bounds,
            trace,
        };
        let mut budget = run.budget(remaining_steps).map_err(NativeError::Dns)?;
        let work = run.clone();
        super::guard(bounds)?;
        Ok(self.ordinary(bounds, permit, run, async move {
            let records = work
                .resolve(
                    Question {
                        name,
                        kind,
                        recursion_desired: false,
                    },
                    vec![server],
                    authority,
                    &mut budget,
                    0,
                    bounds.until(),
                )
                .await?;
            Ok(Value::Records {
                records,
                spent: budget.spent(),
            })
        }))
    }
    /// DNS-only address resolution against explicit numeric bootstrap servers.
    /// This does not call the process GNS client, NSS or a second Resolver.
    pub fn addresses<'id>(
        &self,
        name: &str,
        remaining_steps: u32,
        bounds: Bounds,
    ) -> Result<Query<'id>, NativeError<'id>> {
        super::guard(bounds)?;
        let permit = self.permit().map_err(NativeError::Dns)?;
        let name = wire_name(name).map_err(NativeError::Dns)?;
        if name.len() + 16 > self.shared.limits.bytes {
            return Err(CoreError::Capacity.into());
        }
        if self.shared.bootstrap.is_empty() {
            return Err(NativeError::Dns(self.shared.unavailable_bootstrap()));
        }
        let trace = Rc::new(RefCell::new(DnsReport::new(bounds)));
        let run = Run {
            shared: self.shared.clone(),
            bounds,
            trace,
        };
        let mut budget = run.budget(remaining_steps).map_err(NativeError::Dns)?;
        let work = run.clone();
        super::guard(bounds)?;
        Ok(self.ordinary(bounds, permit, run, async move {
            let mut addresses = Vec::new();
            let mut last = None;
            for family in [1, 28] {
                if budget.left == 0 && !addresses.is_empty() {
                    break;
                }
                match work
                    .resolve(
                        Question {
                            name: copy_slice(&name)?,
                            kind: family,
                            recursion_desired: work.shared.limits.bootstrap_recursion_desired,
                        },
                        copy_slice(&work.shared.bootstrap)?,
                        vec![0],
                        &mut budget,
                        0,
                        bounds.until(),
                    )
                    .await
                {
                    Ok(records) => {
                        for record in records {
                            if let Some(ip) =
                                address_data(record.record_type.value(), &record.data)?
                                && !addresses.contains(&ip)
                            {
                                if addresses.len() == work.shared.limits.servers {
                                    return Err(CoreError::Capacity.into());
                                }
                                addresses.try_reserve(1).map_err(Error::allocation)?;
                                addresses.push(ip);
                            }
                        }
                    }
                    Err(error) => {
                        if terminal(&error, &budget) {
                            return Err(error);
                        }
                        if let Some(previous) = last.replace(error) {
                            work.retain(previous);
                        }
                    }
                }
            }
            if let Some(error) = last {
                if addresses.is_empty() {
                    return Err(error);
                }
                work.trace.borrow_mut().partial_addresses = true;
                work.retain(error);
            }
            Ok(Value::Addresses {
                addresses,
                spent: budget.spent(),
            })
        }))
    }
    /// Fence future operations only. Existing native owners remain in Manager.
    pub fn begin_close(&self) {
        self.shared.closing.store(true, Ordering::Release);
    }
    /// Local DNS socket scope, not a whole foreground/broker retirement proof.
    pub fn is_closed(&self) -> bool {
        self.shared.closing.load(Ordering::Acquire)
            && self.shared.active.load(Ordering::Acquire) == 0
    }
}
impl OwnedQuery<'_> {
    fn retire(&mut self, cancelled: bool) {
        // This future owns every UDP socket/TCP stream; it spawns no work.
        // Taking it physically relinquishes those original FD owners, with no
        // asserted remote delivery or unobservable close errno.
        let had_work = self.future.take().is_some();
        self.alarm = None;
        self.closing = true;
        if let Some(trace) = &self.trace {
            let mut trace = trace.borrow_mut();
            trace.cancelled |= cancelled && had_work;
            trace.closed = true;
        }
    }
}
impl<'id> Operation for Query<'id> {
    type Error = NativeError<'id>;
    type Report = Report<'id>;
    fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Self::Error> {
        match &mut self.inner {
            Inner::Secured { operation, .. } => operation.poll_native_guard(cx),
            Inner::Owned(owner) => {
                if owner.future.is_none() || owner.closing {
                    return None;
                }
                let alarm = owner
                    .alarm
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(owner.bounds.hard())));
                if Instant::now() >= owner.bounds.hard() || alarm.as_mut().poll(cx).is_ready() {
                    owner.retire(true);
                    let spent = owner
                        .trace
                        .as_ref()
                        .map_or(0, |trace| trace.borrow().work_spent);
                    return Some(NativeError::Dns(
                        Error::from(CoreError::Timeout).with_spent(spent),
                    ));
                }
                None
            }
        }
    }
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        now: AbsoluteTime,
    ) -> Poll<Result<Value, Self::Error>> {
        if let Some(error) = self.poll_native_guard(cx) {
            return Poll::Ready(Err(error));
        }
        match &mut self.inner {
            Inner::Secured { operation, .. } => operation.poll(cx, now),
            Inner::Owned(owner) => {
                let Some(future) = &mut owner.future else {
                    return Poll::Pending;
                };
                match future.as_mut().poll(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(result) => {
                        if let Some(trace) = &owner.trace {
                            trace.borrow_mut().completed = result.is_ok();
                        }
                        let spent = owner
                            .trace
                            .as_ref()
                            .map_or(0, |trace| trace.borrow().work_spent);
                        owner.retire(false);
                        Poll::Ready(
                            result.map_err(|error| NativeError::Dns(error.with_spent(spent))),
                        )
                    }
                }
            }
        }
    }
    fn begin_close(&mut self) -> Option<Self::Error> {
        match &mut self.inner {
            Inner::Secured { operation, .. } => operation.begin_close(),
            Inner::Owned(owner) => {
                owner.retire(true);
                None
            }
        }
    }
    fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<Close<Self::Report, Self::Error>> {
        match &mut self.inner {
            Inner::Secured { operation, permit } => {
                let result = operation.poll_close(cx);
                if matches!(&result, Poll::Ready(Close::Closed(_))) {
                    *permit = None;
                }
                result
            }
            Inner::Owned(owner) => {
                if !owner.closing || owner.future.is_some() {
                    return Poll::Pending;
                }
                let Some(trace) = owner.trace.take() else {
                    return Poll::Pending;
                };
                let report =
                    std::mem::replace(&mut *trace.borrow_mut(), DnsReport::new(owner.bounds));
                owner.permit = None;
                Poll::Ready(Close::Closed(Report::Dns(report)))
            }
        }
    }
}
fn owned(input: &str) -> Result<String, Error> {
    let mut value = String::new();
    value
        .try_reserve_exact(input.len())
        .map_err(Error::allocation)?;
    value.push_str(input);
    Ok(value)
}

// Packet already checked every counted object. Reuse the public name reader
// only to locate original RR control words, which Record.expiration translates
// into time and therefore cannot faithfully expose for EDNS extended RCODE.
fn response_code(input: &[u8], maximum_records: usize) -> Result<u16, Error> {
    let header = Header::decode(input)?;
    let limits = gnunet_dns::Limits {
        maximum_packet_bytes: 65535,
        maximum_queries: 1,
        maximum_records,
        maximum_compression_hops: 33,
        maximum_work: 65535 * 16,
        maximum_text_input_bytes: 255,
    };
    let mut bytes = [0; 255];
    let mut arena = Arena::new(&mut bytes);
    let mut reader = gnunet_dns::Reader::at(input, 12, input.len(), limits)?;
    let _question = reader.query(&mut arena)?;
    let mut at = reader.position();
    let before_additional = usize::from(header.counts.answers)
        .checked_add(usize::from(header.counts.authority))
        .ok_or(CoreError::Overflow)?;
    let count = before_additional
        .checked_add(usize::from(header.counts.additional))
        .ok_or(CoreError::Overflow)?;
    if count > maximum_records {
        return Err(CoreError::Capacity.into());
    }
    let mut extension = None;
    for index in 0..count {
        let mut bytes = [0; 255];
        let mut arena = Arena::new(&mut bytes);
        let mut reader = gnunet_dns::Reader::at(input, at, input.len(), limits)?;
        let name = reader.name(&mut arena)?;
        at = reader.position();
        let tail = at.checked_add(10).ok_or(CoreError::Overflow)?;
        let control = input.get(at..tail).ok_or(CoreError::Truncated)?;
        let kind = u16::from_be_bytes([control[0], control[1]]);
        let ttl = u32::from_be_bytes([control[4], control[5], control[6], control[7]]);
        let length = usize::from(u16::from_be_bytes([control[8], control[9]]));
        if kind == 41 {
            if index < before_additional || name.wire() != [0] || extension.is_some() {
                return Err(CoreError::Malformed.into());
            }
            extension = Some((ttl >> 24) as u16);
        }
        at = tail.checked_add(length).ok_or(CoreError::Overflow)?;
        if at > input.len() {
            return Err(CoreError::Truncated.into());
        }
    }
    if at != input.len() {
        return Err(CoreError::Malformed.into());
    }
    Ok((extension.unwrap_or(0) << 4) | u16::from(header.flags.return_code()))
}

fn inline_target(
    answers: &[OwnedRecord],
    name: &[u8],
    kind: u16,
) -> Result<Option<(Vec<u8>, u64)>, Error> {
    let mut current = copy_slice(name)?;
    let mut seen = Vec::new();
    seen.try_reserve(1).map_err(Error::allocation)?;
    seen.push(copy_slice(name)?);
    let mut expiration = u64::MAX;
    for _ in 0..answers.len() {
        let mut aliases = answers.iter().filter(|r| r.name == current && r.kind == 5);
        let first = aliases.next();
        if let Some(first) = first {
            let target = first.target.as_ref().ok_or(CoreError::Malformed)?;
            if answers
                .iter()
                .any(|r| r.name == current && !matches!(r.kind, 5 | 24 | 25 | 30 | 46 | 47 | 50))
                || aliases.any(|r| r.target.as_ref() != Some(target))
            {
                return Err(CoreError::Malformed.into());
            }
        }
        if current != name
            && answers
                .iter()
                .any(|r| r.name == current && (kind == 255 || r.kind == kind))
        {
            return Ok(Some((current, expiration)));
        }
        let Some(first) = first else {
            return Ok(None);
        };
        let target = first.target.as_ref().ok_or(CoreError::Malformed)?;
        expiration = expiration.min(
            answers
                .iter()
                .filter(|r| r.name == current && r.kind == 5)
                .map(|r| r.expiration)
                .min()
                .ok_or(CoreError::Malformed)?,
        );
        if seen.contains(target) {
            return Err(CoreError::Malformed.into());
        }
        seen.try_reserve(1).map_err(Error::allocation)?;
        seen.push(copy_slice(target)?);
        current = copy_slice(target)?;
    }
    Ok(None)
}
