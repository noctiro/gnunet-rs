//! Caller-driven production PILS service over common canonical Unix/TCP framing.
//! Every connection subscribes immediately. Output ordering binds DH/KEM replies
//! to the actual announcement on that original MQ; physical writes are not ACKs.
use crate::identity::KeyLease;
use gnunet_pils::{Action, Service};
use gnunet_service_runtime::{
    accepted::{AcceptState, AcceptedConnection, SocketEvent},
    clock::RuntimeClock,
    credentials::UnixAccess,
    framing::{Accounting, Budget, Class, Framed, Limits as FrameLimits, ReadStep},
    service::{Listener, PeerAddress, ServiceOptions},
};
use gnunet_types::Error as ProtocolError;
use gnunet_wire::official::{Frame, MessageType, message_type as mt};
use std::{
    collections::VecDeque,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};
use zeroize::{Zeroize, Zeroizing};
/// Local explicit resource bounds; none are new protocol fields.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum admitted physical streams, including subscribers making no requests.
    pub clients: usize,
    /// Maximum input/output frame bytes, through the official65535 limit.
    pub frame_bytes: usize,
    /// Per-stream retained immutable output records and bytes.
    pub output: Budget,
    /// Shared public canonical-address scratch bytes.
    pub address_bytes: usize,
    /// Maximum distinct public addresses in a FEED.
    pub addresses: usize,
    /// Maximum bytes offered in one native read/write syscall.
    pub io_slice_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            clients: 64,
            frame_bytes: 65535,
            output: Budget {
                frames: 8,
                bytes: 262140,
            },
            address_bytes: 65535,
            addresses: 4096,
            io_slice_bytes: 65535,
        }
    }
}
impl Limits {
    fn framing(self) -> FrameLimits {
        FrameLimits {
            frame_bytes: self.frame_bytes,
            ordinary: self.output,
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.io_slice_bytes,
        }
    }
    /// Validate bounds before private-file or listener initialization.
    pub fn validate(self) -> Result<(), ProtocolError> {
        self.framing().validate()?;
        if self.clients == 0 || self.frame_bytes < 104 || self.address_bytes > 65535 {
            return Err(ProtocolError::Capacity);
        }
        self.clients.checked_add(1).ok_or(ProtocolError::Capacity)?;
        Ok(())
    }
}
/// Actual local service cause; never a remote processing/durability claim.
#[derive(Debug)]
pub enum Error {
    /// Original protocol or resource refusal.
    Protocol(ProtocolError),
    /// Original native connection or admission cause.
    Io(io::Error),
    /// Original canonical absolute-clock refusal.
    Clock(ProtocolError),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(e) => write!(f, "PILS service protocol: {e}"),
            Self::Io(e) => e.fmt(f),
            Self::Clock(e) => write!(f, "PILS service clock: {e}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<ProtocolError> for Error {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
/// Diagnostic identity minted only after admission of one actual stream.
/// It is not a wire RID, peer identity or cross-host authorization capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientId(u64);
impl ClientId {
    /// Diagnostic generation, never accepted as operation/completion authority.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}
/// Why this original admitted stream was physically retired.
#[derive(Debug)]
pub enum CloseCause {
    /// Actual clean native EOF.
    Eof,
    /// Original native read/write error, including partial-frame EOF.
    Io(io::Error),
    /// Original malformed/unsupported known frame or protocol failure.
    Protocol(ProtocolError),
    /// Original immutable output allocation/queue refusal.
    Output {
        /// Original immutable queue/allocation refusal.
        error: ProtocolError,
        /// Original crypto failure, if this refused response encoded one.
        crypto_error: Option<ProtocolError>,
    },
    /// Explicit permanent local shutdown or clock-failure cleanup.
    Shutdown,
}
/// Result of one actual complete original request; no remote acknowledgement.
#[derive(Clone, Copy, Debug)]
pub enum Handled {
    /// An immutable response was admitted only to its original physical MQ.
    Reply {
        /// Original crypto failure; the pure owner encodes the reference zero result.
        crypto_error: Option<ProtocolError>,
    },
    /// Every remaining original MQ was queued the new announcement in FIFO order.
    /// Slow/refused MQs are physically closed with separate original-cause events.
    Broadcast {
        /// Whether the actual public identity changed under the selected profile.
        identity_changed: bool,
    },
    /// The explicit conditional profile suppressed an unchanged address set.
    Unchanged,
    /// An unregistered message was ignored only under configured TOLERANT.
    Ignored,
}
/// One bounded actual service event.
#[derive(Debug)]
pub enum Progress {
    /// Actual canonical stream admitted and initial announcement queued.
    Admitted {
        /// Original diagnostic stream identity.
        id: ClientId,
        /// Actual original peer address.
        peer: PeerAddress,
    },
    /// Actual unadmitted stream closed by the address/kernel-credential policy.
    Rejected {
        /// Actual original peer address.
        peer: PeerAddress,
    },
    /// Actual unadmitted stream closed; existing MQs keep running.
    AdmissionFailed {
        /// Actual original peer address.
        peer: PeerAddress,
        /// Original admission cause.
        error: Error,
    },
    /// Actual positive native read, without claiming request processing.
    Read {
        /// Original stream identity.
        id: ClientId,
        /// Actual transferred byte count.
        bytes: usize,
    },
    /// Actual positive native output; completion means only local full write.
    Written {
        /// Original stream identity.
        id: ClientId,
        /// Actual transferred byte count.
        bytes: usize,
        /// Whether this original frame was fully written.
        complete: bool,
    },
    /// One original request was processed under the service's actual current key.
    Request {
        /// Original stream identity.
        id: ClientId,
        /// Exact original registered/unregistered message type.
        message: MessageType,
        /// Concrete local handling result.
        handled: Handled,
    },
    /// This exact original admitted stream has already been physically closed.
    ClientClosed {
        /// Original stream identity.
        id: ClientId,
        /// Actual original peer address.
        peer: PeerAddress,
        /// Concrete original retirement cause.
        cause: CloseCause,
    },
    /// One actual listener failure was delivered to the socket observer.
    Socket,
    /// This caller wait's native deadline expired; sockets/partial cursors remain.
    WaitDeadline,
    /// All actual streams and secret service keys are permanently retired.
    Closed,
}
/// Actual local counts, not request ACKs or remote observations.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report {
    /// Actually admitted physical streams.
    pub admitted: u64,
    /// Actually denied unadmitted streams.
    pub rejected: u64,
    /// Actual errors while admitting a stream.
    pub admission_failures: u64,
    /// Complete registered requests with successful pure actions, including
    /// locally refused output (which has a separate actual close cause).
    pub requests: u64,
    /// Actual address-feed broadcasts produced by the pure owner.
    pub broadcasts: u64,
    /// Actual public-key changes produced by the selected explicit profile.
    pub identity_changes: u64,
    /// Real crypto failures encoded as reference zero results.
    pub crypto_failures: u64,
    /// Unregistered messages ignored by configured policy.
    pub ignored: u64,
    /// Bytes actually transferred to native stream writes.
    pub written_bytes: u64,
    /// Original frames actually fully written.
    pub written_frames: u64,
    /// Admitted streams physically closed, including explicit shutdown.
    pub closed: u64,
}
struct Client {
    id: ClientId,
    peer: PeerAddress,
    framed: Framed<()>,
}
struct Root<const H: usize> {
    // Declaration order erases the secret owner before releasing its fence on
    // successful shutdown and every fallible construction/drop path.
    service: Box<Service<H>>,
    lease: KeyLease,
}
/// One bounded caller-driven service. No hidden loop, per-peer task or disk I/O.
/// The native writer lease outlives all physical MQs and the pure secret owner.
pub struct Host<const H: usize = 65535> {
    clients: Vec<Option<Client>>,
    root: Option<Root<H>>,
    clock: Arc<dyn RuntimeClock>,
    limits: Limits,
    options: ServiceOptions,
    unix: UnixAccess,
    scratch: Vec<u8>,
    reply: Zeroizing<Vec<u8>>,
    events: VecDeque<Progress>,
    next: u64,
    phase: usize,
    yield_due: bool,
    read_cursor: usize,
    write_cursor: usize,
    listener_cursor: usize,
    accept: AcceptState,
    wait: Option<Pin<Box<Sleep>>>,
    report: Report,
}
fn storage<T>(len: usize) -> Result<Vec<T>, ProtocolError> {
    let mut value = Vec::new();
    value
        .try_reserve_exact(len)
        .map_err(|_| ProtocolError::Capacity)?;
    Ok(value)
}
impl<const H: usize> Host<H> {
    /// Adopt an already durable private-root owner, before runtime polling.
    /// All filesystem work, including this fence check, occurs synchronously at
    /// this explicit startup boundary; `drive` performs no private-file I/O.
    pub fn new(
        service: Box<Service<H>>,
        lease: KeyLease,
        clock: Arc<dyn RuntimeClock>,
        limits: Limits,
        options: ServiceOptions,
        unix: UnixAccess,
    ) -> Result<Self, Error> {
        let root = Root { service, lease };
        limits.validate()?;
        if root.service.announcement().len() > limits.frame_bytes
            || root.service.announcement().len() > limits.output.bytes
        {
            return Err(ProtocolError::Capacity.into());
        }
        root.lease.verify_fence()?;
        let mut clients = storage(limits.clients)?;
        clients.resize_with(limits.clients, || None);
        let mut scratch = storage(limits.address_bytes)?;
        scratch.resize(limits.address_bytes, 0);
        let mut reply = storage(104)?;
        reply.resize(104, 0);
        let mut events = VecDeque::new();
        events
            .try_reserve_exact(
                limits
                    .clients
                    .checked_add(1)
                    .ok_or(ProtocolError::Capacity)?,
            )
            .map_err(|_| ProtocolError::Capacity)?;
        Ok(Self {
            clients,
            root: Some(root),
            clock,
            limits,
            options,
            unix,
            scratch,
            reply: Zeroizing::new(reply),
            events,
            next: 0,
            phase: 0,
            yield_due: false,
            read_cursor: 0,
            write_cursor: 0,
            listener_cursor: 0,
            accept: AcceptState::default(),
            wait: None,
            report: Report::default(),
        })
    }
    /// Actually active public identity; absence means the secret owner is retired.
    #[must_use]
    pub fn identity(&self) -> Option<[u8; 32]> {
        self.root
            .as_ref()
            .map(|root| *root.service.identity().public_key().as_bytes())
    }
    /// Actual admitted streams, including those making no requests.
    #[must_use]
    pub fn clients(&self) -> usize {
        self.clients
            .iter()
            .filter(|client| client.is_some())
            .count()
    }
    /// Local physical/protocol counts.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.report
    }
    /// Drain an original retained event, including cleanup events after close.
    pub fn next_event(&mut self) -> Option<Progress> {
        self.events.pop_front()
    }
    /// Admit one actual canonically initialized stream. Refusal closes only this
    /// unadmitted stream; it never resumes an EMFILE-suspended listener.
    pub fn admit(
        &mut self,
        accepted: AcceptedConnection,
        observe: &mut impl FnMut(SocketEvent),
    ) -> Result<Option<ClientId>, Error> {
        let (connection, peer, diagnostics) = accepted.into_parts();
        for diagnostic in diagnostics {
            observe(SocketEvent::Diagnostic(diagnostic));
        }
        let result = (|| -> Result<Option<ClientId>, Error> {
            let service = &self.root.as_ref().ok_or(ProtocolError::Closed)?.service;
            if !self.events.is_empty() {
                return Err(ProtocolError::WouldBlock.into());
            }
            let allowed = match peer {
                PeerAddress::Unix => self.unix.allows(&connection)?,
                PeerAddress::Tcp(address) => self.options.access.allows(address.ip()),
            };
            if !allowed {
                drop(connection);
                self.report.rejected = self.report.rejected.saturating_add(1);
                return Ok(None);
            }
            let index = self
                .clients
                .iter()
                .position(Option::is_none)
                .ok_or(ProtocolError::Capacity)?;
            let generation = self.next.checked_add(1).ok_or(ProtocolError::Overflow)?;
            let mut framed = Framed::new(connection, self.limits.framing())?;
            framed.enqueue_copy(service.announcement(), (), Class::Ordinary)?;
            let id = ClientId(generation);
            self.clients[index] = Some(Client { id, peer, framed });
            self.next = generation;
            self.report.admitted = self.report.admitted.saturating_add(1);
            Ok(Some(id))
        })();
        if result.is_err() {
            self.report.admission_failures = self.report.admission_failures.saturating_add(1);
        }
        result
    }
    fn retire(&mut self, index: usize, cause: CloseCause) {
        if let Some(client) = self.clients[index].take() {
            let id = client.id;
            let peer = client.peer;
            drop(client);
            self.accept.client_closed();
            self.report.closed = self.report.closed.saturating_add(1);
            // No new admission or request occurs before retained events drain.
            // One request plus each original slot's one retirement bounds this
            // queue by clients+1, reserved before any stream can be admitted.
            self.events
                .push_back(Progress::ClientClosed { id, peer, cause });
        }
    }
    /// Permanently close actual streams before erasing the service and releasing
    /// its native writer lease. No sync/worker or delayed callback can survive.
    pub fn close(&mut self) {
        for index in 0..self.clients.len() {
            self.retire(index, CloseCause::Shutdown);
        }
        self.reply.as_mut_slice().zeroize();
        // Root declaration order erases the secret service before its fence.
        let retired = self.root.take();
        drop(retired);
        self.wait = None;
    }
    fn event(&mut self) -> Result<Progress, Error> {
        self.next_event()
            .ok_or_else(|| ProtocolError::NotReady.into())
    }
    fn dispatch(&mut self, index: usize) -> Result<Progress, Error> {
        let now = match self.clock.sample() {
            Ok(sample) => sample.now.as_micros(),
            Err(error) => {
                self.close();
                return Err(Error::Clock(error));
            }
        };
        let (id, message, action) = {
            let client = self.clients[index].as_mut().ok_or(ProtocolError::Stale)?;
            let frame = client.framed.frame().ok_or(ProtocolError::NotReady)?;
            let message = Frame::decode(frame)?.header().message_type();
            let registered = matches!(
                message,
                mt::PILS_SIGN_REQUEST
                    | mt::PILS_FEED_ADDRESSES
                    | mt::PILS_KEM_DECAPS
                    | mt::PILS_ECDH
            );
            if !registered {
                if self.options.tolerant {
                    let id = client.id;
                    let _released = client.framed.release_frame();
                    self.report.ignored = self.report.ignored.saturating_add(1);
                    return Ok(Progress::Request {
                        id,
                        message,
                        handled: Handled::Ignored,
                    });
                }
                self.retire(index, CloseCause::Protocol(ProtocolError::Unsupported));
                return self.event();
            }
            let service = &mut self.root.as_mut().ok_or(ProtocolError::Closed)?.service;
            (
                client.id,
                message,
                service.receive(frame, &mut self.scratch, now, &mut self.reply),
            )
        };
        if action.is_ok() {
            self.report.requests = self.report.requests.saturating_add(1);
        }
        let handled = match action {
            Err(error) => {
                self.reply.as_mut_slice().zeroize();
                self.retire(index, CloseCause::Protocol(error));
                return self.event();
            }
            Ok(Action::Reply { len, crypto_error }) => {
                if crypto_error.is_some() {
                    self.report.crypto_failures = self.report.crypto_failures.saturating_add(1);
                }
                let queued = self.clients[index]
                    .as_mut()
                    .ok_or(ProtocolError::Stale)?
                    .framed
                    .enqueue_copy(&self.reply[..len], (), Class::Ordinary);
                self.reply.as_mut_slice().zeroize();
                if let Err(error) = queued {
                    self.retire(
                        index,
                        CloseCause::Output {
                            error,
                            crypto_error,
                        },
                    );
                    return self.event();
                }
                Handled::Reply { crypto_error }
            }
            Ok(Action::Broadcast { identity_changed }) => {
                self.reply.as_mut_slice().zeroize();
                for target in 0..self.clients.len() {
                    let queued = match &mut self.clients[target] {
                        None => continue,
                        Some(client) => client.framed.enqueue_copy(
                            self.root
                                .as_ref()
                                .ok_or(ProtocolError::Closed)?
                                .service
                                .announcement(),
                            (),
                            Class::Ordinary,
                        ),
                    };
                    if let Err(error) = queued {
                        self.retire(
                            target,
                            CloseCause::Output {
                                error,
                                crypto_error: None,
                            },
                        );
                    }
                }
                self.report.broadcasts = self.report.broadcasts.saturating_add(1);
                if identity_changed {
                    self.report.identity_changes = self.report.identity_changes.saturating_add(1);
                }
                Handled::Broadcast { identity_changed }
            }
            Ok(Action::Unchanged) => {
                self.reply.as_mut_slice().zeroize();
                Handled::Unchanged
            }
        };
        if let Some(client) = &mut self.clients[index] {
            let _released = client.framed.release_frame();
        }
        self.events.push_back(Progress::Request {
            id,
            message,
            handled,
        });
        self.event()
    }
    fn poll_output(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
        let len = self.clients.len();
        for offset in 0..len {
            let index = (self.write_cursor + offset) % len;
            let Some(client) = &mut self.clients[index] else {
                continue;
            };
            let id = client.id;
            match client.framed.poll_write(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(error)) => {
                    self.write_cursor = (index + 1) % len;
                    self.retire(index, CloseCause::Io(error));
                    return Poll::Ready(self.event());
                }
                Poll::Ready(Ok(progress)) => {
                    self.write_cursor = (index + 1) % len;
                    self.report.written_bytes = self
                        .report
                        .written_bytes
                        .saturating_add(progress.bytes as u64);
                    if progress.complete {
                        self.report.written_frames = self.report.written_frames.saturating_add(1);
                    }
                    return Poll::Ready(Ok(Progress::Written {
                        id,
                        bytes: progress.bytes,
                        complete: progress.complete,
                    }));
                }
            }
        }
        Poll::Pending
    }
    fn poll_input(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
        let len = self.clients.len();
        for offset in 0..len {
            let index = (self.read_cursor + offset) % len;
            let Some(client) = &mut self.clients[index] else {
                continue;
            };
            let id = client.id;
            if client.framed.frame().is_some() {
                self.read_cursor = (index + 1) % len;
                return Poll::Ready(self.dispatch(index));
            }
            match client.framed.poll_read(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(error)) => {
                    self.read_cursor = (index + 1) % len;
                    self.retire(index, CloseCause::Io(error));
                    return Poll::Ready(self.event());
                }
                Poll::Ready(Ok(ReadStep::Eof)) => {
                    self.read_cursor = (index + 1) % len;
                    self.retire(index, CloseCause::Eof);
                    return Poll::Ready(self.event());
                }
                Poll::Ready(Ok(ReadStep::Progress { bytes, .. })) => {
                    self.read_cursor = (index + 1) % len;
                    return Poll::Ready(Ok(Progress::Read { id, bytes }));
                }
            }
        }
        Poll::Pending
    }
    fn poll_accept(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        observe: &mut impl FnMut(SocketEvent),
    ) -> Poll<Result<Progress, Error>> {
        if !self.accept.ready() || self.clients.iter().all(Option::is_some) {
            return Poll::Pending;
        }
        for offset in 0..listeners.len() {
            let index = (self.listener_cursor + offset) % listeners.len();
            match listeners[index].poll_canonical_connection(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(error)) => {
                    self.listener_cursor = (index + 1) % listeners.len();
                    observe(self.accept.failed(error));
                    return Poll::Ready(Ok(Progress::Socket));
                }
                Poll::Ready(Ok(accepted)) => {
                    let peer = accepted.peer();
                    self.listener_cursor = (index + 1) % listeners.len();
                    let progress = match self.admit(accepted, observe) {
                        Ok(Some(id)) => Progress::Admitted { id, peer },
                        Ok(None) => Progress::Rejected { peer },
                        Err(error) => Progress::AdmissionFailed { peer, error },
                    };
                    return Poll::Ready(Ok(progress));
                }
            }
        }
        Poll::Pending
    }
    fn poll_step(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        observe: &mut impl FnMut(SocketEvent),
        deadline: Option<Instant>,
    ) -> Poll<Result<Progress, Error>> {
        if let Some(event) = self.next_event() {
            return Poll::Ready(Ok(event));
        }
        if self.root.is_none() {
            return Poll::Ready(Ok(Progress::Closed));
        }
        if let Some(deadline) = deadline {
            if self
                .wait
                .as_ref()
                .is_none_or(|wait| wait.deadline() != deadline)
            {
                self.wait = Some(Box::pin(tokio::time::sleep_until(deadline)));
            }
            if self
                .wait
                .as_mut()
                .is_some_and(|wait| wait.as_mut().poll(cx).is_ready())
            {
                return Poll::Ready(Ok(Progress::WaitDeadline));
            }
        } else {
            self.wait = None;
        }
        for offset in 0..3 {
            let phase = (self.phase + offset) % 3;
            let progress = match phase {
                0 => self.poll_output(cx),
                1 => self.poll_input(cx),
                _ => self.poll_accept(cx, listeners, observe),
            };
            if progress.is_ready() {
                self.phase = (phase + 1) % 3;
                return progress;
            }
        }
        Poll::Pending
    }
    fn poll_drive(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        observe: &mut impl FnMut(SocketEvent),
        deadline: Option<Instant>,
    ) -> Poll<Result<Progress, Error>> {
        if self.yield_due {
            self.yield_due = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let progress = self.poll_step(cx, listeners, observe, deadline);
        if matches!(&progress, Poll::Ready(Ok(event)) if !matches!(event, Progress::Closed | Progress::WaitDeadline))
        {
            self.yield_due = true;
        }
        progress
    }
    /// Wait for one bounded actual action on the caller's current task. Dropping
    /// this future retains every immutable partial RX/TX and original FIFO.
    /// There is no periodic identity/HELLO task in the active reference service;
    /// only actual FEEDs generate updates. A deadline limits this wait alone.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        observe: &mut impl FnMut(SocketEvent),
        deadline: Option<Instant>,
    ) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll_drive(cx, listeners, observe, deadline)).await
    }
}
impl<const H: usize> Drop for Host<H> {
    fn drop(&mut self) {
        self.close();
    }
}
