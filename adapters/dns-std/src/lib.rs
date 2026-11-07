//! Caller-driven UDP host for the official raw GNUnet DNSSTUB API.
//!
//! Construction and configuration perform no network I/O. `resolve` copies the
//! query and draws OS entropy explicitly; it neither opens a socket nor sends.
//! `drive` requires a Tokio runtime with I/O and time enabled. No detached task,
//! ambient DNS configuration, DNS-ID/QR validation or request timeout is added.
//! Datagram callbacks remain live, and retries continue, until cancel or stop.
#![forbid(unsafe_code)]

use gnunet_dnsstub::{Action, DnsStub as Core};
pub use gnunet_dnsstub::{
    Admission, DropReason, Family, RequestId, ServerId, SocketId, Stopped, UnverifiedDatagram,
};
use gnunet_types::{Duration, Error, MonoInstant};
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use std::{
    fmt,
    future::Future,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
    time::Duration as StdDuration,
};
use tokio::{
    io::ReadBuf,
    net::UdpSocket,
    time::{Instant, Sleep},
};

/// Host admission or clock failure. UDP syscall outcomes are observable events,
/// and do not become synthetic terminal DNS request failures.
#[derive(Debug)]
pub enum HostError {
    /// The bounded pure owner rejected an operation.
    Core(Error),
    /// System entropy was unavailable before admission mutated the owner.
    Entropy(getrandom::Error),
}
impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(e) => write!(f, "DNSSTUB owner: {e}"),
            Self::Entropy(e) => write!(f, "DNSSTUB system entropy: {e}"),
        }
    }
}
impl std::error::Error for HostError {}
impl From<Error> for HostError {
    fn from(e: Error) -> Self {
        Self::Core(e)
    }
}

/// Whether callback dispatch should keep driving or return to its caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Flow {
    /// Continue waiting for responses/retries within the same caller budget.
    Continue,
    /// Return immediately after this event; all owner state remains live.
    Return,
}
/// Why a drive operation returned. Caller budget expiry is never a DNS timeout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// The callback requested an early return after a real effect/datagram.
    Activity,
    /// Only the caller's drive wait budget elapsed; no result was fabricated.
    WaitDeadline,
    /// Stop invalidated all requests and closed both cached socket families.
    Stopped,
}
/// A local datagram discard, with no terminal result callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Discard {
    /// Raw official source/minimum-header/read-interest filter.
    Core(DropReason),
    /// At least limit+1 bytes arrived; truncated data is never delivered.
    Oversize {
        /// Configured maximum response length.
        limit: usize,
    },
}
/// Synchronous actual I/O observations, borrowing response data for one callback.
#[derive(Debug)]
pub enum Event<'a> {
    /// The lazy bind/registration really completed or failed.
    SocketOpened {
        /// Exact original cache generation.
        socket: SocketId,
        /// Bound address on success; original error on failure.
        result: io::Result<SocketAddr>,
    },
    /// One real nonblocking send syscall was attempted. Failure retains both
    /// this request and its cached socket; the already scheduled retry continues.
    Sent {
        /// Original request using this send.
        request: RequestId,
        /// Exact original cached socket.
        socket: SocketId,
        /// Actual destination passed to sendto.
        destination: SocketAddr,
        /// Actual syscall byte count or error, never a response acknowledgement.
        result: io::Result<usize>,
    },
    /// Raw source-matching data, without DNS-ID/QR validation or completion.
    Datagram(UnverifiedDatagram<'a>),
    /// One consumed packet was ignored; its truncated bytes are not exposed.
    Discarded {
        /// Original cache generation that consumed the datagram.
        socket: SocketId,
        /// Actual sender.
        source: SocketAddr,
        /// Exact local rejection reason.
        reason: Discard,
    },
    /// A receive syscall failed and only its socket generation was closed.
    ReceiveFailed {
        /// Invalidated cached socket generation.
        socket: SocketId,
        /// Actual receive error.
        error: io::Error,
    },
}
struct Cached {
    id: SocketId,
    local: SocketAddr,
    socket: UdpSocket,
}
type Caches<const R: usize> = [[Option<Cached>; 2]; R];
#[derive(Default)]
struct RetryTimer {
    at: Option<MonoInstant>,
    sleep: Option<Pin<Box<Sleep>>>,
}
fn family_index(f: Family) -> usize {
    match f {
        Family::V4 => 0,
        Family::V6 => 1,
    }
}
fn clock(epoch: Instant) -> Result<MonoInstant, Error> {
    u64::try_from(epoch.elapsed().as_micros())
        .map(MonoInstant)
        .map_err(|_| Error::Overflow)
}
fn unbiased_with(
    bound: u32,
    mut draw: impl FnMut() -> Result<u32, getrandom::Error>,
) -> Result<u32, getrandom::Error> {
    // Bound is nonzero because Core::start validates the request pool.
    let threshold = bound.wrapping_neg() % bound;
    loop {
        let n = draw()?;
        if n >= threshold {
            return Ok(n % bound);
        }
    }
}
fn admit<const R: usize, const N: usize, const S: usize>(
    core: &mut Core<R, N, S>,
    epoch: Instant,
    query: &[u8],
) -> Result<Admission, HostError> {
    let mut error = None;
    let result = core.resolve(query, clock(epoch)?, |bound| {
        unbiased_with(bound, getrandom::u32).map_err(|e| {
            error = Some(e);
            Error::Io
        })
    });
    if let Some(e) = error {
        return Err(HostError::Entropy(e));
    }
    result.map_err(Into::into)
}
fn stop<const R: usize, const N: usize, const S: usize>(
    core: &mut Core<R, N, S>,
    caches: &mut Caches<R>,
    timer: &mut RetryTimer,
) -> Stopped {
    let stopped = core.stop();
    for pair in caches {
        for cached in pair {
            *cached = None;
        }
    }
    timer.at = None;
    timer.sleep = None;
    stopped
}
/// Restricted synchronous callback operations. Mutations take effect before the
/// next packet/effect is polled. Stop immediately drops every actual socket.
/// Resolve returns its evicted failure token explicitly, even within callbacks.
pub struct CallbackContext<'a, const R: usize, const N: usize, const S: usize> {
    core: &'a mut Core<R, N, S>,
    caches: &'a mut Caches<R>,
    timer: &'a mut RetryTimer,
    epoch: Instant,
}
impl<const R: usize, const N: usize, const S: usize> CallbackContext<'_, R, N, S> {
    /// Add a literal IP at port53 without hostname/system-DNS lookup.
    pub fn add_dns_ip(&mut self, ip: &str) -> Result<ServerId, Error> {
        self.core.add_dns_ip(ip)
    }
    /// Add an explicit copied endpoint at the configured list head.
    pub fn add_dns_sa(&mut self, endpoint: SocketAddr) -> Result<ServerId, Error> {
        self.core.add_dns_sa(endpoint)
    }
    /// Change future retry periods without moving the previously due retry.
    pub fn set_retry(&mut self, retry: Duration) -> Result<(), Error> {
        self.core.set_retry(retry)
    }
    /// Copy a new request and draw OS entropy, without network I/O. A replaced
    /// request's explicit failure is Admission.evicted; it is not silently lost.
    #[must_use = "Inspect Admission.evicted and notify that original request of replacement failure."]
    pub fn resolve(&mut self, query: &[u8]) -> Result<Admission, HostError> {
        admit(self.core, self.epoch, query)
    }
    /// Retained packet for this exact active request, used by the UDP runtime.
    /// This read proves neither transmission nor response validity.
    pub fn query(&self, request: RequestId) -> Result<&[u8], Error> {
        self.core.query(request)
    }
    /// Cancel one current request, retaining both cached sockets for reuse.
    pub fn resolve_cancel(&mut self, request: RequestId) -> Result<(), Error> {
        self.core.resolve_cancel(request)
    }
    /// Invalidate all callbacks and immediately close every actual cached socket.
    pub fn stop(&mut self) -> Stopped {
        stop(self.core, self.caches, self.timer)
    }
    /// Whether the exact original request token is still active.
    #[must_use]
    pub fn owns_request(&self, request: RequestId) -> bool {
        self.core.owns_request(request)
    }
    /// Count of real cached sockets, including canceled request slots.
    #[must_use]
    pub fn cached_socket_count(&self) -> usize {
        self.caches.iter().flatten().filter(|v| v.is_some()).count()
    }
}
/// All seven official stub operations with a caller-driven UDP runtime.
/// R bounds request slots, N copied query bytes and S explicit server entries.
/// At most two actual sockets are retained per slot, independently by family.
pub struct DnsStub<const R: usize, const N: usize, const S: usize> {
    core: Core<R, N, S>,
    caches: Caches<R>,
    buffer: Vec<u8>,
    max_response: usize,
    epoch: Instant,
    timer: RetryTimer,
    read_cursor: usize,
    action_first: bool,
}
impl<const R: usize, const N: usize, const S: usize> DnsStub<R, N, S> {
    /// Construct outside or inside Tokio, without opening sockets. Responses are
    /// limited explicitly (12..=65535); receive storage is limit+1, so oversize
    /// datagrams cannot be mistaken for complete packets.
    pub fn start(num_sockets: usize, max_response: usize) -> Result<Self, Error> {
        if !(12..=65535).contains(&max_response) {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            core: Core::start(num_sockets)?,
            caches: std::array::from_fn(|_| [None, None]),
            buffer: vec![0; max_response + 1],
            max_response,
            epoch: Instant::now(),
            timer: RetryTimer::default(),
            read_cursor: 0,
            action_first: true,
        })
    }
    /// Add an explicit numeric IP at port53. No hostname lookup is performed.
    pub fn add_dns_ip(&mut self, ip: &str) -> Result<ServerId, Error> {
        self.core.add_dns_ip(ip)
    }
    /// Add an explicit endpoint at the configured list head, retaining duplicates.
    pub fn add_dns_sa(&mut self, endpoint: SocketAddr) -> Result<ServerId, Error> {
        self.core.add_dns_sa(endpoint)
    }
    /// Change future retry periods without resetting already scheduled work.
    pub fn set_retry(&mut self, retry: Duration) -> Result<(), Error> {
        self.core.set_retry(retry)
    }
    /// Copy a query and use OS entropy for unbiased slot selection. No network
    /// I/O occurs until drive; evicted is a required original failure notification.
    #[must_use = "Inspect Admission.evicted and notify that original request of replacement failure."]
    pub fn resolve(&mut self, query: &[u8]) -> Result<Admission, HostError> {
        admit(&mut self.core, self.epoch, query)
    }
    /// Retained packet for this exact active request, used by the UDP runtime.
    /// This read proves neither transmission nor response validity.
    pub fn query(&self, request: RequestId) -> Result<&[u8], Error> {
        self.core.query(request)
    }
    /// Cancel without callback or network message, retaining both cached sockets.
    pub fn resolve_cancel(&mut self, request: RequestId) -> Result<(), Error> {
        self.core.resolve_cancel(request)
    }
    /// Stop all logical work and close even canceled slots' real socket owners.
    pub fn stop(&mut self) -> Stopped {
        stop(&mut self.core, &mut self.caches, &mut self.timer)
    }
    /// Whether this exact request remains active.
    #[must_use]
    pub fn owns_request(&self, request: RequestId) -> bool {
        self.core.owns_request(request)
    }
    /// Active requests, independent of duplicate response datagrams.
    #[must_use]
    pub fn pending_requests(&self) -> usize {
        self.core.pending_requests()
    }
    /// Whether stop permanently closed this owner.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.core.is_stopped()
    }
    /// Current retry setting, not the caller's drive budget.
    #[must_use]
    pub fn retry(&self) -> Duration {
        self.core.retry()
    }
    /// Existing absolute owner retry time in microseconds from construction.
    #[must_use]
    pub fn next_wakeup(&self) -> Option<MonoInstant> {
        self.core.next_wakeup()
    }
    /// Number of actual sockets retained, including canceled request slots.
    #[must_use]
    pub fn cached_socket_count(&self) -> usize {
        self.caches.iter().flatten().filter(|v| v.is_some()).count()
    }
    /// Actual bound address and exact cache token, without an extra syscall.
    #[must_use]
    pub fn cached_socket(&self, slot: usize, family: Family) -> Option<(SocketId, SocketAddr)> {
        self.caches.get(slot)?[family_index(family)]
            .as_ref()
            .map(|c| (c.id, c.local))
    }
    fn bind(socket: SocketId) -> io::Result<Cached> {
        let (domain, address) = match socket.family() {
            Family::V4 => (Domain::IPV4, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))),
            Family::V6 => (Domain::IPV6, SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))),
        };
        let raw = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        if socket.family() == Family::V6 {
            raw.set_only_v6(true)?;
        }
        raw.set_nonblocking(true)?;
        raw.bind(&address.into())?;
        let standard: std::net::UdpSocket = raw.into();
        let local = standard.local_addr()?;
        let socket_io = UdpSocket::from_std(standard)?;
        Ok(Cached {
            id: socket,
            local,
            socket: socket_io,
        })
    }
    fn context(&mut self) -> CallbackContext<'_, R, N, S> {
        CallbackContext {
            core: &mut self.core,
            caches: &mut self.caches,
            timer: &mut self.timer,
            epoch: self.epoch,
        }
    }
    fn action(
        &mut self,
        action: Action,
        callback: &mut impl FnMut(Event<'_>, &mut CallbackContext<'_, R, N, S>) -> Flow,
    ) -> Result<Flow, HostError> {
        let event = match action {
            Action::OpenSocket { socket } => {
                let cached = Self::bind(socket);
                self.core.socket_opened(socket, cached.is_ok())?;
                let result = match cached {
                    Ok(cached) => {
                        let local = cached.local;
                        self.caches[socket.slot() as usize][family_index(socket.family())] =
                            Some(cached);
                        Ok(local)
                    }
                    Err(e) => Err(e),
                };
                Event::SocketOpened { socket, result }
            }
            Action::Send {
                attempt,
                request,
                socket,
                destination,
                len,
            } => {
                let cached = self.caches[socket.slot() as usize][family_index(socket.family())]
                    .as_ref()
                    .filter(|c| c.id == socket)
                    .ok_or(Error::StaleGeneration)?;
                let bytes = self.core.query(request)?;
                if bytes.len() != len {
                    return Err(Error::InvalidInput.into());
                }
                // Exactly one real syscall, bypassing Tokio's initial readiness
                // cache. All send errors keep the request/socket and its retry.
                let result = SockRef::from(&cached.socket).send_to(bytes, &destination.into());
                self.core.sent(attempt)?;
                Event::Sent {
                    request,
                    socket,
                    destination,
                    result,
                }
            }
        };
        Ok(callback(event, &mut self.context()))
    }
    fn receive_failed(
        &mut self,
        socket: SocketId,
        error: io::Error,
        callback: &mut impl FnMut(Event<'_>, &mut CallbackContext<'_, R, N, S>) -> Flow,
    ) -> Result<Flow, HostError> {
        // Validate the original core generation before dropping any real owner.
        // A stale read result cannot close its replacement cache generation.
        self.core.socket_failed(socket)?;
        self.caches[socket.slot() as usize][family_index(socket.family())] = None;
        Ok(callback(
            Event::ReceiveFailed { socket, error },
            &mut self.context(),
        ))
    }
    fn poll_receive(
        &mut self,
        context: &mut Context<'_>,
        callback: &mut impl FnMut(Event<'_>, &mut CallbackContext<'_, R, N, S>) -> Flow,
    ) -> Result<Option<Flow>, HostError> {
        let total = self.core.slot_count() * 2;
        for offset in 0..total {
            let index = (self.read_cursor + offset) % total;
            let slot = index / 2;
            let family = if index.is_multiple_of(2) {
                Family::V4
            } else {
                Family::V6
            };
            let Some(id) = self.core.readable_socket_at(slot, family) else {
                continue;
            };
            let Some(cached) = self.caches[slot][family_index(family)]
                .as_ref()
                .filter(|c| c.id == id)
            else {
                return Err(Error::StaleGeneration.into());
            };
            let mut buffer = ReadBuf::new(&mut self.buffer);
            match cached.socket.poll_recv_from(context, &mut buffer) {
                Poll::Pending => {}
                Poll::Ready(Ok(source)) => {
                    let len = buffer.filled().len();
                    self.read_cursor = (index + 1) % total;
                    let event = if len > self.max_response {
                        Event::Discarded {
                            socket: id,
                            source,
                            reason: Discard::Oversize {
                                limit: self.max_response,
                            },
                        }
                    } else {
                        match self.core.receive(id, source, &self.buffer[..len]) {
                            Ok(data) => Event::Datagram(data),
                            Err(reason) => Event::Discarded {
                                socket: id,
                                source,
                                reason: Discard::Core(reason),
                            },
                        }
                    };
                    let mut callback_context = CallbackContext {
                        core: &mut self.core,
                        caches: &mut self.caches,
                        timer: &mut self.timer,
                        epoch: self.epoch,
                    };
                    return Ok(Some(callback(event, &mut callback_context)));
                }
                Poll::Ready(Err(error)) => {
                    self.read_cursor = (index + 1) % total;
                    return self.receive_failed(id, error, callback).map(Some);
                }
            }
        }
        Ok(None)
    }
    fn poll_retry(&mut self, context: &mut Context<'_>) -> Result<Poll<()>, HostError> {
        let next = self.core.next_wakeup();
        if next != self.timer.at {
            self.timer.at = next;
            if let Some(at) = next {
                let deadline = self
                    .epoch
                    .checked_add(StdDuration::from_micros(at.0))
                    .ok_or(Error::Overflow)?;
                if let Some(sleep) = self.timer.sleep.as_mut() {
                    sleep.as_mut().reset(deadline);
                } else {
                    self.timer.sleep = Some(Box::pin(tokio::time::sleep_until(deadline)));
                }
            } else {
                self.timer.sleep = None;
            }
        }
        Ok(self
            .timer
            .sleep
            .as_mut()
            .map_or(Poll::Pending, |sleep| sleep.as_mut().poll(context)))
    }
    fn poll_drive(
        &mut self,
        context: &mut Context<'_>,
        budget: &mut Option<Pin<Box<Sleep>>>,
        callback: &mut impl FnMut(Event<'_>, &mut CallbackContext<'_, R, N, S>) -> Flow,
    ) -> Poll<Result<Progress, HostError>> {
        for _ in 0..32 {
            if self.core.is_stopped() {
                return Poll::Ready(Ok(Progress::Stopped));
            }
            if budget
                .as_mut()
                .is_some_and(|sleep| sleep.as_mut().poll(context).is_ready())
            {
                return Poll::Ready(Ok(Progress::WaitDeadline));
            }
            let flow = if self.action_first {
                if let Some(action) = self.core.next_action(clock(self.epoch)?)? {
                    self.action_first = false;
                    Some(self.action(action, callback)?)
                } else if let Some(flow) = self.poll_receive(context, callback)? {
                    self.action_first = true;
                    Some(flow)
                } else {
                    None
                }
            } else if let Some(flow) = self.poll_receive(context, callback)? {
                self.action_first = true;
                Some(flow)
            } else if let Some(action) = self.core.next_action(clock(self.epoch)?)? {
                self.action_first = false;
                Some(self.action(action, callback)?)
            } else {
                None
            };
            if let Some(flow) = flow {
                if self.core.is_stopped() {
                    return Poll::Ready(Ok(Progress::Stopped));
                }
                if flow == Flow::Return {
                    return Poll::Ready(Ok(Progress::Activity));
                }
                continue;
            }
            if self.poll_retry(context)?.is_ready() {
                continue;
            }
            return Poll::Pending;
        }
        context.waker().wake_by_ref();
        Poll::Pending
    }
    /// Wait and dispatch real events until Flow::Return, stop, or the caller's
    /// wait deadline. Dropping this future retains socket owners, copied query,
    /// absolute retry schedule and pending work; it never cancels a DNS request.
    /// Effects are committed synchronously within one poll, with no await gap.
    pub async fn drive(
        &mut self,
        deadline: Option<Instant>,
        mut callback: impl FnMut(Event<'_>, &mut CallbackContext<'_, R, N, S>) -> Flow,
    ) -> Result<Progress, HostError> {
        let mut budget = deadline.map(|at| Box::pin(tokio::time::sleep_until(at)));
        std::future::poll_fn(|context| self.poll_drive(context, &mut budget, &mut callback)).await
    }
}
impl<const R: usize, const N: usize, const S: usize> Drop for DnsStub<R, N, S> {
    fn drop(&mut self) {
        let _stopped = self.stop();
    }
}
#[cfg(test)]
mod tests {
    use super::unbiased_with;
    #[test]
    fn unbiased_sampling_rejects_low_residue_instead_of_modulo_bias() {
        let mut draws = [0_u32, 1, 5, 6].into_iter();
        let result = unbiased_with(10, || Ok(draws.next().unwrap_or(100)));
        assert_eq!(result, Ok(6)); // 2^32 mod10=6: all smaller samples rejected.
        assert_eq!(draws.next(), None);
        assert_eq!(unbiased_with(1, || Ok(u32::MAX)), Ok(0));
        assert_eq!(unbiased_with(u32::MAX, || Ok(u32::MAX)), Ok(0));
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "The host error seam test asserts cached socket identity and independently closes/rebinds actual UDP sockets."
    )]
    fn injected_receive_failure_reopens_only_its_generation_and_rejects_old_result()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::{DnsStub, Event, Family, Flow, HostError};
        use gnunet_types::{Duration, Error};
        use std::{
            io,
            net::{Ipv4Addr, Ipv6Addr},
            time::Duration as StdDuration,
        };
        use tokio::{net::UdpSocket, time::Instant};
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let four = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
                let six = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await?;
                let mut h = DnsStub::<1, 32, 4>::start(1, 64)?;
                h.add_dns_sa(four.local_addr()?)?;
                h.add_dns_sa(six.local_addr()?)?;
                h.set_retry(Duration(0))?;
                let request = h.resolve(b"reopen")?.request;
                for _ in 0..2 {
                    let mut sent = false;
                    h.drive(
                        Some(Instant::now() + StdDuration::from_secs(1)),
                        |event, _| {
                            if let Event::Sent { result, .. } = event {
                                assert!(result.is_ok());
                                sent = true;
                                Flow::Return
                            } else {
                                Flow::Continue
                            }
                        },
                    )
                    .await?;
                    assert!(sent);
                }
                let old6 = h.cached_socket(0, Family::V6).ok_or("no v6 cache")?;
                let old4 = h.cached_socket(0, Family::V4).ok_or("no v4 cache")?;
                let mut failed = 0;
                // Inject only the receive syscall error seam, never pretend an OS
                // receive actually returned this error. Both caches above are real.
                h.receive_failed(
                    old6.0,
                    io::Error::from(io::ErrorKind::ConnectionReset),
                    &mut |event, ctx| {
                        if let Event::ReceiveFailed { socket, error } = event {
                            assert_eq!(socket, old6.0);
                            assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
                            failed += 1;
                        }
                        assert_eq!(ctx.cached_socket_count(), 1);
                        Flow::Return
                    },
                )?;
                assert_eq!(failed, 1);
                assert_eq!(h.cached_socket(0, Family::V6), None);
                assert_eq!(h.cached_socket(0, Family::V4), Some(old4));
                assert!(h.owns_request(request));
                // The invalidated actual socket was dropped synchronously.
                let raw = socket2::Socket::new(
                    socket2::Domain::IPV6,
                    socket2::Type::DGRAM,
                    Some(socket2::Protocol::UDP),
                )?;
                raw.set_only_v6(true)?;
                raw.bind(&old6.1.into())?;
                drop(raw);
                let mut seen = None;
                h.drive(
                    Some(Instant::now() + StdDuration::from_secs(1)),
                    |event, _| {
                        if let Event::Sent { socket, result, .. } = event {
                            assert!(result.is_ok());
                            seen = Some(socket);
                            Flow::Return
                        } else {
                            Flow::Continue
                        }
                    },
                )
                .await?;
                let new = h
                    .cached_socket(0, Family::V6)
                    .ok_or("v6 was not reopened")?;
                assert_eq!(seen, Some(new.0));
                assert_eq!(new.0.generation(), old6.0.generation() + 1);
                assert_eq!(h.cached_socket(0, Family::V4), Some(old4));
                let stale = h.receive_failed(
                    old6.0,
                    io::Error::from(io::ErrorKind::ConnectionReset),
                    &mut |_, _| {
                        failed += 1;
                        Flow::Return
                    },
                );
                assert!(matches!(
                    stale,
                    Err(HostError::Core(Error::StaleGeneration))
                ));
                assert_eq!(failed, 1);
                assert_eq!(h.cached_socket(0, Family::V6), Some(new));
                assert_eq!(h.cached_socket(0, Family::V4), Some(old4));
                Ok::<(), Box<dyn std::error::Error>>(())
            })
    }
}
