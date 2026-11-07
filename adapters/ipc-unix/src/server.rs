//! Bounded Unix host for the official STATISTICS service core.
//!
//! GNUnet v0.29.1's `gnunet-service-statistics.c:415,589,732,800` dispatches
//! GET, SET, WATCH and DISCONNECT respectively. DISCONNECT is a processing
//! barrier, not EOF or a durable commit. This adapter adds no wire protocol.
//! The application binds and removes the socket and owns persistent storage.

use crate::IpcError;
use gnunet_service_runtime::acl::AccessPolicy;
use gnunet_service_runtime::connection::Connection;
/// Shared host-owned listener and service policy types used by this IPC adapter.
pub use gnunet_service_runtime::service::{Listener, PeerAddress, ServiceOptions, ShutdownMode};
use gnunet_service_runtime::{clock::RuntimeClock, credentials::UnixAccess};
use gnunet_statistics::{
    ClientId, Notification, Request, SnapshotId, Statistics, encode_disconnect_confirmation,
};
use gnunet_types::Error;
use gnunet_wire::official::MessageHeader;
use std::{
    collections::VecDeque,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::UnixListener,
    time::Instant,
};

use gnunet_service_runtime::accepted::{AcceptError, AcceptState, AcceptedConnection, SocketEvent};
/// Explicit host resource and inactivity limits, in addition to core capacities.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Simultaneously admitted sockets, between one and the core client capacity.
    pub max_connections: usize,
    /// Complete incoming or encoded outgoing frame bytes, between 4 and 65535.
    pub max_frame_bytes: usize,
    /// Pending outgoing bytes per socket, including partially written frames
    /// and deferred WATCH tails charged by their official24-byte encoding.
    /// A streamed GET is not limited by its aggregate encoded listing size;
    /// its frozen metadata is charged to the core's retained-byte quota.
    pub max_pending_bytes: usize,
    /// Maximum interval without successful socket read/write progress.
    /// `Duration::MAX` disables this optional resource policy, as in the
    /// reference service's indefinite monitoring connections.
    pub idle_timeout: Duration,
}

/// Why an individual socket was closed; other clients continue to run.
#[derive(Debug)]
pub enum CloseReason {
    /// Orderly EOF between complete requests.
    Eof,
    /// Rejected by the configured official address policy, before core admission.
    AccessDenied(PeerAddress),
    /// Actual I/O, protocol, frame or queue capacity failure.
    Failure(IpcError),
    /// No successful socket progress before its inactivity deadline.
    IdleTimeout,
    /// The caller's explicit shutdown future completed.
    Shutdown,
}

/// A synchronous, unqueued closure notification supplied to the application.
#[derive(Debug)]
pub struct SessionClosed {
    /// Core generation, or none when the incoming socket was never admitted.
    pub client: Option<ClientId>,
    /// Actual outcome; a failed peer is never reported as a successful operation.
    pub reason: CloseReason,
}

/// Synchronous physical socket or service-client lifetime observation.
#[derive(Debug)]
pub enum ServiceEvent {
    /// An admitted client or refused admission was physically closed.
    Closed(SessionClosed),
    /// Native acceptance diagnostics, before any core client is allocated.
    Socket(SocketEvent),
    /// Original soft-shutdown grace elapsed; remaining original sockets were
    /// actually closed. No unprocessed request was acknowledged.
    ForcedShutdown,
}

/// Exact checked counters returned after explicit shutdown.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Report {
    /// Accepted OS sockets, including sockets refused admission.
    pub accepted: u64,
    /// Sockets admitted to the core.
    pub admitted: u64,
    /// Sockets refused admission without allocating a core client ID.
    pub rejected: u64,
    /// Previously admitted sockets released, including shutdown.
    pub closed: u64,
    /// Complete requests successfully dispatched to the core.
    pub requests: u64,
    /// WATCH_VALUE effects admitted to bounded host send queues.
    pub notifications: u64,
    /// Accepted relative SETs with the reference C service's overflow diagnostic.
    pub positive_relative_overflows: u64,
}

fn increment(value: &mut u64) -> Result<(), IpcError> {
    *value = value.checked_add(1).ok_or(Error::Overflow)?;
    Ok(())
}
fn idle_deadline(timeout: Duration) -> Result<Option<Instant>, IpcError> {
    if timeout == Duration::MAX {
        Ok(None)
    } else {
        Instant::now()
            .checked_add(timeout)
            .map(Some)
            .ok_or_else(|| Error::Overflow.into())
    }
}
fn buffer(capacity: usize, initialized: bool) -> Result<Vec<u8>, IpcError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| Error::Capacity)?;
    if initialized {
        bytes.resize(capacity, 0);
    }
    Ok(bytes)
}

struct Session {
    stream: Connection,
    client: ClientId,
    input: Vec<u8>,
    used: usize,
    expected: usize,
    output: Vec<u8>,
    written: usize,
    deadline: Option<Instant>,
    monitor: bool,
    get: Option<SnapshotId>,
    deferred: VecDeque<Notification>,
}
impl Session {
    fn retained_bytes(&self) -> Result<usize, IpcError> {
        self.input
            .capacity()
            .checked_add(self.output.capacity())
            .and_then(|n| {
                self.deferred
                    .capacity()
                    .checked_mul(core::mem::size_of::<Notification>())
                    .and_then(|m| n.checked_add(m))
            })
            .ok_or_else(|| Error::Overflow.into())
    }
    fn queue_parts(
        output: &mut Vec<u8>,
        written: &mut usize,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<(), IpcError> {
        let remaining = output.len() - *written;
        if bytes.len() > maximum.saturating_sub(remaining) {
            return Err(Error::Capacity.into());
        }
        if *written != 0 {
            output.copy_within(*written.., 0);
            output.truncate(remaining);
            *written = 0;
        }
        output.extend_from_slice(bytes);
        Ok(())
    }
    fn progress(&mut self, idle_timeout: Duration) -> Result<(), IpcError> {
        self.deadline = idle_deadline(idle_timeout)?;
        Ok(())
    }
    fn poll(
        &mut self,
        context: &mut Context<'_>,
        limits: Limits,
    ) -> Poll<Result<bool, CloseReason>> {
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Poll::Ready(Err(CloseReason::IdleTimeout));
        }
        if self.written < self.output.len() {
            match Pin::new(&mut self.stream).poll_write(context, &self.output[self.written..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(CloseReason::Failure(
                        io::Error::from(io::ErrorKind::WriteZero).into(),
                    )));
                }
                Poll::Ready(Ok(count)) => {
                    self.written += count;
                    if self.written == self.output.len() {
                        self.output.clear();
                        self.written = 0;
                    }
                    return Poll::Ready(
                        self.progress(limits.idle_timeout)
                            .map(|()| false)
                            .map_err(CloseReason::Failure),
                    );
                }
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err(CloseReason::Failure(error.into())));
                }
                Poll::Pending => {}
            }
        }
        if self.get.is_some() || !self.deferred.is_empty() {
            return Poll::Pending;
        }
        let mut buffer = ReadBuf::new(&mut self.input[self.used..self.expected]);
        match Pin::new(&mut self.stream).poll_read(context, &mut buffer) {
            Poll::Ready(Ok(())) => {
                let count = buffer.filled().len();
                if count == 0 {
                    return Poll::Ready(Err(if self.used == 0 {
                        CloseReason::Eof
                    } else {
                        CloseReason::Failure(Error::Truncated.into())
                    }));
                }
                self.used += count;
                if let Err(error) = self.progress(limits.idle_timeout) {
                    return Poll::Ready(Err(CloseReason::Failure(error)));
                }
                if self.used == 4 {
                    let header = match MessageHeader::decode(&self.input[..4]) {
                        Ok(header) => header,
                        Err(error) => return Poll::Ready(Err(CloseReason::Failure(error.into()))),
                    };
                    if header.size() > limits.max_frame_bytes {
                        return Poll::Ready(Err(CloseReason::Failure(Error::Capacity.into())));
                    }
                    self.expected = header.size();
                }
                Poll::Ready(Ok(self.used == self.expected))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(CloseReason::Failure(error.into()))),
            Poll::Pending => Poll::Pending,
        }
    }
}

enum Event {
    Accept(AcceptedConnection),
    AcceptFailure(AcceptError),
    Activity,
    Frame(usize),
    Close(usize, CloseReason),
    Tick,
    Shutdown,
    ForceShutdown,
    SourceFailure(IpcError),
}

struct State<'a, const R: usize, const N: usize, const C: usize, const W: usize, const E: usize> {
    core: &'a mut Statistics<R, N, C, W, E>,
    sessions: Vec<Option<Session>>,
    scratch: Vec<u8>,
    limits: Limits,
    cursor: usize,
    report: Report,
    accepting: AcceptState,
    tolerant: bool,
    unix_access: UnixAccess,
    external: usize,
    baseline: usize,
}
impl<const R: usize, const N: usize, const C: usize, const W: usize, const E: usize> Drop
    for State<'_, R, N, C, W, E>
{
    fn drop(&mut self) {
        // The owned state lives inside the serve future. External cancellation
        // therefore retires every socket and generation without detached tasks.
        for session in self.sessions.iter_mut().filter_map(Option::take) {
            match self.core.disconnect(session.client) {
                Ok(()) | Err(_) => {}
            }
        }
        match self.core.set_external_retained_bytes(self.baseline) {
            Ok(()) | Err(_) => {}
        }
    }
}
impl<const R: usize, const N: usize, const C: usize, const W: usize, const E: usize>
    State<'_, R, N, C, W, E>
{
    fn close(
        &mut self,
        index: usize,
        reason: CloseReason,
        closed: &mut impl FnMut(ServiceEvent),
    ) -> Result<(), IpcError> {
        let session = self.sessions[index].take().ok_or(Error::Stale)?;
        let client = session.client;
        self.core.disconnect(client)?;
        let bytes = session.retained_bytes()?;
        drop(session);
        self.external = self.external.checked_sub(bytes).ok_or(Error::Overflow)?;
        self.core.set_external_retained_bytes(self.external)?;
        increment(&mut self.report.closed)?;
        self.accepting.client_closed();
        closed(ServiceEvent::Closed(SessionClosed {
            client: Some(client),
            reason,
        }));
        Ok(())
    }
    fn account(&mut self, old: usize, new: usize) -> Result<(), IpcError> {
        let total = self
            .external
            .checked_sub(old)
            .and_then(|n| n.checked_add(new))
            .ok_or(Error::Overflow)?;
        self.core.set_external_retained_bytes(total)?;
        self.external = total;
        Ok(())
    }
    fn reserve_host<T>(
        &mut self,
        old: usize,
        needed: usize,
        maximum: usize,
    ) -> Result<Vec<T>, IpcError> {
        if needed > maximum {
            return Err(Error::Capacity.into());
        }
        let geometric = old.saturating_mul(2).max(needed).min(maximum);
        for (attempt, target) in [geometric, needed].into_iter().enumerate() {
            if attempt != 0 && geometric == needed {
                break;
            }
            let mut replacement = Vec::new();
            if replacement.try_reserve_exact(target).is_err() {
                continue;
            }
            let old_bytes = old
                .checked_mul(core::mem::size_of::<T>())
                .ok_or(Error::Overflow)?;
            let new_bytes = replacement
                .capacity()
                .checked_mul(core::mem::size_of::<T>())
                .ok_or(Error::Overflow)?;
            match self.account(old_bytes, new_bytes) {
                Ok(()) => return Ok(replacement),
                Err(IpcError::Protocol(Error::Capacity)) => {}
                Err(error) => return Err(error),
            }
        }
        Err(Error::Capacity.into())
    }
    fn session_slot(&mut self) -> Result<usize, IpcError> {
        if let Some(index) = self.sessions.iter().position(Option::is_none) {
            return Ok(index);
        }
        if self.sessions.len() >= self.limits.max_connections {
            return Err(Error::Capacity.into());
        }
        let needed = self.sessions.len().checked_add(1).ok_or(Error::Overflow)?;
        if needed > self.sessions.capacity() {
            let mut replacement = self.reserve_host(
                self.sessions.capacity(),
                needed,
                self.limits.max_connections,
            )?;
            replacement.append(&mut self.sessions);
            self.sessions = replacement;
        }
        self.sessions.push(None);
        Ok(needed - 1)
    }
    fn input(&mut self, index: usize) -> Result<(), IpcError> {
        let session = self.sessions[index].as_ref().ok_or(Error::Stale)?;
        if session.expected <= session.input.len() {
            return Ok(());
        }
        if session.expected <= session.input.capacity() {
            let needed = session.expected;
            self.sessions[index]
                .as_mut()
                .ok_or(Error::Stale)?
                .input
                .resize(needed, 0);
            return Ok(());
        }
        let needed = session.expected;
        let used = session.used;
        let old = session.input.capacity();
        let mut replacement = self.reserve_host(old, needed, self.limits.max_frame_bytes)?;
        replacement.resize(needed, 0);
        let session = self.sessions[index].as_mut().ok_or(Error::Stale)?;
        replacement[..used].copy_from_slice(&session.input[..used]);
        session.input = replacement;
        Ok(())
    }
    fn queue_scratch(&mut self, index: usize, size: usize) -> Result<(), IpcError> {
        let session = self.sessions[index].as_ref().ok_or(Error::Stale)?;
        let remaining = session.output.len() - session.written;
        let needed = remaining.checked_add(size).ok_or(Error::Overflow)?;
        if needed > self.limits.max_pending_bytes {
            return Err(Error::Capacity.into());
        }
        if needed > session.output.capacity() {
            let old = session.output.capacity();
            let mut replacement = self.reserve_host(old, needed, self.limits.max_pending_bytes)?;
            let session = self.sessions[index].as_mut().ok_or(Error::Stale)?;
            replacement.extend_from_slice(&session.output[session.written..]);
            replacement.extend_from_slice(&self.scratch[..size]);
            session.output = replacement;
            session.written = 0;
        } else {
            let session = self.sessions[index].as_mut().ok_or(Error::Stale)?;
            Session::queue_parts(
                &mut session.output,
                &mut session.written,
                &self.scratch[..size],
                self.limits.max_pending_bytes,
            )?;
        }
        Ok(())
    }
    fn defer(&mut self, index: usize, notification: Notification) -> Result<(), IpcError> {
        let session = self.sessions[index].as_ref().ok_or(Error::Stale)?;
        let needed = session
            .deferred
            .len()
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        let queued = needed
            .checked_mul(24)
            .and_then(|n| n.checked_add(session.output.len() - session.written))
            .ok_or(Error::Overflow)?;
        if queued > self.limits.max_pending_bytes {
            return Err(Error::Capacity.into());
        }
        if needed > session.deferred.capacity() {
            let old = session.deferred.capacity();
            let mut replacement =
                self.reserve_host(old, needed, self.limits.max_pending_bytes / 24)?;
            let session = self.sessions[index].as_mut().ok_or(Error::Stale)?;
            replacement.extend(session.deferred.iter().copied());
            replacement.push(notification);
            session.deferred = VecDeque::from(replacement);
        } else {
            self.sessions[index]
                .as_mut()
                .ok_or(Error::Stale)?
                .deferred
                .push_back(notification);
        }
        Ok(())
    }
    fn outbound(&mut self, index: usize) -> Result<bool, IpcError> {
        let session = self.sessions[index].as_ref().ok_or(Error::Stale)?;
        if session.written < session.output.len() {
            return Ok(false);
        }
        if let Some(get) = session.get {
            let size = self.core.snapshot_reply(get, &mut self.scratch)?;
            self.queue_scratch(index, size)?;
            if self.core.consume_snapshot_reply(get)? {
                self.sessions[index].as_mut().ok_or(Error::Stale)?.get = None;
            }
            return Ok(true);
        }
        if let Some(notification) = session.deferred.front().copied() {
            let size = notification.encode(&mut self.scratch)?;
            self.queue_scratch(index, size)?;
            let session = self.sessions[index].as_mut().ok_or(Error::Stale)?;
            if session.deferred.pop_front() != Some(notification) {
                return Err(Error::Stale.into());
            }
            return Ok(true);
        }
        Ok(false)
    }
    fn accept(
        &mut self,
        stream: Connection,
        peer: PeerAddress,
        access: &AccessPolicy,
        closed: &mut impl FnMut(ServiceEvent),
    ) -> Result<(), IpcError> {
        increment(&mut self.report.accepted)?;
        let allowed = match peer {
            PeerAddress::Unix => self.unix_access.allows(&stream),
            PeerAddress::Tcp(address) => Ok(access.allows(address.ip())),
        };
        let allowed = match allowed {
            Ok(allowed) => allowed,
            Err(error) => {
                increment(&mut self.report.rejected)?;
                drop(stream);
                closed(ServiceEvent::Closed(SessionClosed {
                    client: None,
                    reason: CloseReason::Failure(error.into()),
                }));
                return Ok(());
            }
        };
        if !allowed {
            increment(&mut self.report.rejected)?;
            drop(stream);
            closed(ServiceEvent::Closed(SessionClosed {
                client: None,
                reason: CloseReason::AccessDenied(peer),
            }));
            return Ok(());
        }
        let admission = (|| -> Result<(usize, Vec<u8>), IpcError> {
            let index = self.session_slot()?;
            let input = buffer(4, true)?;
            self.account(0, input.capacity())?;
            Ok((index, input))
        })();
        let (index, input) = match admission {
            Ok(value) => value,
            Err(error) => {
                increment(&mut self.report.rejected)?;
                drop(stream);
                closed(ServiceEvent::Closed(SessionClosed {
                    client: None,
                    reason: CloseReason::Failure(error),
                }));
                return Ok(());
            }
        };
        let deadline = match idle_deadline(self.limits.idle_timeout) {
            Ok(value) => value,
            Err(error) => {
                self.account(input.capacity(), 0)?;
                return Err(error);
            }
        };
        let client = match self.core.connect() {
            Ok(client) => client,
            Err(error) => {
                self.account(input.capacity(), 0)?;
                increment(&mut self.report.rejected)?;
                drop(stream);
                closed(ServiceEvent::Closed(SessionClosed {
                    client: None,
                    reason: CloseReason::Failure(error.into()),
                }));
                return Ok(());
            }
        };
        self.sessions[index] = Some(Session {
            stream,
            client,
            input,
            used: 0,
            expected: 4,
            output: Vec::new(),
            written: 0,
            deadline,
            monitor: false,
            get: None,
            deferred: VecDeque::new(),
        });
        increment(&mut self.report.admitted)
    }
    fn dispatch(&mut self, index: usize) -> Result<(), IpcError> {
        let session = self.sessions[index].as_mut().ok_or(Error::Stale)?;
        let request = match Request::decode(&session.input[..session.used]) {
            Ok(request) => request,
            Err(Error::Unsupported) if self.tolerant => {
                session.used = 0;
                session.expected = 4;
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        match request {
            Request::Set(update) => {
                let outcome = self.core.set(session.client, update)?;
                if outcome.positive_overflow {
                    increment(&mut self.report.positive_relative_overflows)?;
                }
            }
            Request::Watch(selector) => {
                self.core.watch(session.client, selector)?;
                session.monitor = true;
            }
            Request::Get(selector) => {
                session.get = Some(self.core.snapshot(session.client, selector)?);
            }
            Request::Disconnect => {
                let size = encode_disconnect_confirmation(&mut self.scratch)?;
                self.queue_scratch(index, size)?;
            }
        }
        let session = self.sessions[index].as_mut().ok_or(Error::Stale)?;
        session.used = 0;
        session.expected = 4;
        increment(&mut self.report.requests)
    }
    fn notifications(&mut self, closed: &mut impl FnMut(ServiceEvent)) -> Result<(), IpcError> {
        while let Some(notification) = self.core.notification().copied() {
            let index = self
                .sessions
                .iter()
                .position(|session| {
                    session
                        .as_ref()
                        .is_some_and(|session| session.client == notification.client)
                })
                .ok_or(Error::StaleGeneration)?;
            let pending = self.sessions[index].as_ref().ok_or(Error::Stale)?;
            let result = if pending.get.is_some() || !pending.deferred.is_empty() {
                self.defer(index, notification)
            } else {
                notification
                    .encode(&mut self.scratch)
                    .map_err(IpcError::from)
                    .and_then(|size| self.queue_scratch(index, size))
            };
            if let Err(error) = result {
                self.close(index, CloseReason::Failure(error), closed)?;
                continue;
            }
            if self.core.consume_notification() != Some(notification) {
                return Err(Error::Stale.into());
            }
            increment(&mut self.report.notifications)?;
        }
        Ok(())
    }
    fn poll(
        &mut self,
        listeners: &[Listener<'_>],
        context: &mut Context<'_>,
        accepting: bool,
    ) -> Poll<Event> {
        // Include acceptance in the same round robin as the finite client slots.
        // A continuously ready client or accept queue cannot starve other slots.
        let count = self.sessions.len() + listeners.len();
        for offset in 0..count {
            let slot = (self.cursor + offset) % count;
            let event = if slot >= self.sessions.len() {
                if accepting && self.accepting.ready() {
                    match listeners[slot - self.sessions.len()].poll_canonical_connection(context) {
                        Poll::Ready(Ok(connection)) => Some(Event::Accept(connection)),
                        Poll::Ready(Err(error)) => Some(Event::AcceptFailure(error)),
                        Poll::Pending => None,
                    }
                } else {
                    None
                }
            } else if self.sessions[slot].is_some() {
                match self.outbound(slot).and_then(|progress| {
                    self.input(slot)?;
                    Ok(progress)
                }) {
                    Err(error) => {
                        self.cursor = (slot + 1) % count;
                        return Poll::Ready(Event::Close(slot, CloseReason::Failure(error)));
                    }
                    Ok(true) => {
                        self.cursor = (slot + 1) % count;
                        return Poll::Ready(Event::Activity);
                    }
                    Ok(false) => {}
                }
                let Some(session) = &mut self.sessions[slot] else {
                    continue;
                };
                match session.poll(context, self.limits) {
                    Poll::Ready(Ok(true)) => Some(Event::Frame(slot)),
                    Poll::Ready(Ok(false)) => Some(Event::Activity),
                    Poll::Ready(Err(reason)) => Some(Event::Close(slot, reason)),
                    Poll::Pending => None,
                }
            } else {
                None
            };
            if let Some(event) = event {
                self.cursor = (slot + 1) % count;
                return Poll::Ready(event);
            }
        }
        Poll::Pending
    }
}

/// Serve official STATISTICS requests using one task and bounded host buffers.
///
/// The core must initially have no connected clients or queued effects; stored
/// rows may already have been restored. The core is exclusively borrowed until
/// shutdown/cancellation. No tasks or channels are created. Each event yields to
/// the runtime, and incomplete sockets sleep on readiness or their idle timer.
/// A failed/capacity-limited peer is closed and synchronously reported through
/// `closed`. Native acceptance diagnostics are reported synchronously too;
/// EMFILE pauses all listeners until a live client physically closes. Other
/// accept errors retain the listeners. Internal state failures are returned.
///
/// Completing `shutdown`, or dropping this future after it was polled, closes
/// all clients and releases their watches. Values remain in the caller's core.
/// DISCONNECT_CONFIRM acknowledges processing only; no persistence is performed.
pub async fn serve_statistics<
    const R: usize,
    const N: usize,
    const C: usize,
    const W: usize,
    const E: usize,
>(
    listener: &UnixListener,
    core: &mut Statistics<R, N, C, W, E>,
    limits: Limits,
    shutdown: impl Future<Output = ()>,
    closed: impl FnMut(ServiceEvent),
) -> Result<Report, IpcError> {
    serve_statistics_on(
        &[Listener::Unix(listener)],
        core,
        limits,
        &ServiceOptions::default(),
        shutdown,
        closed,
    )
    .await
}

/// Serve with the reference STATISTICS service's SOFT_SHUTDOWN policy.
///
/// Once shutdown is requested, stop accepting new connections and continue
/// processing existing non-monitor clients until they disconnect (or their
/// configured idle limits expire). A successful WATCH marks its connection as
/// a monitor. When no non-monitor clients remain, close all remaining monitors
/// and return the owned core to the caller for persistence. This follows
/// `service.c:service_shutdown/have_non_monitor_clients/client_mark_monitor`.
/// Dropping this future still cancels immediately and releases every client.
pub async fn serve_statistics_soft<
    const R: usize,
    const N: usize,
    const C: usize,
    const W: usize,
    const E: usize,
>(
    listener: &UnixListener,
    core: &mut Statistics<R, N, C, W, E>,
    limits: Limits,
    shutdown: impl Future<Output = ()>,
    closed: impl FnMut(ServiceEvent),
) -> Result<Report, IpcError> {
    serve_statistics_on(
        &[Listener::Unix(listener)],
        core,
        limits,
        &ServiceOptions {
            shutdown: ShutdownMode::Soft,
            ..ServiceOptions::default()
        },
        shutdown,
        closed,
    )
    .await
}

/// Serve a bounded set of Unix/TCP listeners with the same official request and
/// lifecycle owner. Listener acceptance and every connected session share one
/// fair round robin. Address policies run before allocating core IDs or buffers.
/// Dropping this future retires every admitted connection and WATCH generation.
pub async fn serve_statistics_on<
    const R: usize,
    const N: usize,
    const C: usize,
    const W: usize,
    const E: usize,
>(
    listeners: &[Listener<'_>],
    core: &mut Statistics<R, N, C, W, E>,
    limits: Limits,
    options: &ServiceOptions,
    shutdown: impl Future<Output = ()>,
    closed: impl FnMut(ServiceEvent),
) -> Result<Report, IpcError> {
    serve_statistics_controlled(
        listeners,
        core,
        limits,
        ServeContext {
            options,
            unix_access: UnixAccess::default(),
            clock: None,
            shutdown_grace: None,
        },
        shutdown,
        || Ok(()),
        closed,
    )
    .await
}
/// Concrete per-source policy for the existing STATISTICS loop. No implicit
/// clock, Resolver, task, credential provider or durable store is created.
pub struct ServeContext<'a> {
    /// Original address/tolerance/shutdown policy.
    pub options: &'a ServiceOptions,
    /// Actual kernel Unix admission before any core generation/buffer allocation.
    pub unix_access: UnixAccess,
    /// Original canonical process clock. None preserves legacy embedding APIs;
    /// the production SERVICE always supplies its actual shared clock.
    pub clock: Option<Arc<dyn RuntimeClock>>,
    /// Fixed native grace after the first soft stop. None preserves legacy
    /// indefinite soft-drain behavior; forced close never acknowledges requests.
    pub shutdown_grace: Option<Duration>,
}
/// Same real wire/session owner, with explicit startup callback, canonical clock,
/// Unix credentials and bounded soft-stop. The ready callback runs only after
/// all source/session metadata is allocated and the real listener owner is polled.
/// Dropping/error retires all original client generations before returning core.
pub async fn serve_statistics_controlled<
    const R: usize,
    const N: usize,
    const C: usize,
    const W: usize,
    const E: usize,
>(
    listeners: &[Listener<'_>],
    core: &mut Statistics<R, N, C, W, E>,
    limits: Limits,
    context: ServeContext<'_>,
    shutdown: impl Future<Output = ()>,
    ready: impl FnOnce() -> Result<(), IpcError>,
    mut closed: impl FnMut(ServiceEvent),
) -> Result<Report, IpcError> {
    let ServeContext {
        options,
        unix_access,
        clock,
        shutdown_grace,
    } = context;
    if shutdown_grace.is_some_and(|d| {
        d.is_zero() || d == Duration::MAX || Instant::now().checked_add(d).is_none()
    }) {
        return Err(Error::InvalidInput.into());
    }
    let mut clock_state = match &clock {
        Some(clock) => {
            let sub = clock.subscribe()?;
            let sample = clock.sample()?;
            Some((sub, sample.revision))
        }
        None => None,
    };
    if listeners.is_empty()
        || limits.max_connections == 0
        || limits.max_connections > core.limits().max_clients
        || !(4..=65535).contains(&limits.max_frame_bytes)
        || limits.max_pending_bytes < 4
        || limits.idle_timeout.is_zero()
        || core.client_count() != 0
        || core.notification_count_queued() != 0
        || idle_deadline(limits.idle_timeout).is_err()
    {
        return Err(Error::InvalidInput.into());
    }
    limits
        .max_connections
        .checked_mul(
            limits
                .max_frame_bytes
                .checked_add(limits.max_pending_bytes)
                .ok_or(Error::Overflow)?,
        )
        .ok_or(Error::Overflow)?;
    let baseline = core.external_retained_bytes();
    let scratch = buffer(limits.max_frame_bytes, true)?;
    let external = baseline
        .checked_add(scratch.capacity())
        .ok_or(Error::Overflow)?;
    core.set_external_retained_bytes(external)?;
    let mut state = State {
        core,
        sessions: Vec::new(),
        scratch,
        limits,
        cursor: 0,
        report: Report::default(),
        accepting: AcceptState::default(),
        tolerant: options.tolerant,
        unix_access,
        external,
        baseline,
    };
    tokio::pin!(shutdown);
    let timer = tokio::time::sleep(Duration::from_secs(1));
    tokio::pin!(timer);
    let mut draining = false;
    let mut stop_at = None;
    let mut first_event = poll_fn(|cx| {
        if let Some((subscription, revision)) = &mut clock_state {
            match subscription.poll_changed(cx, *revision) {
                Poll::Ready(Err(e)) => return Poll::Ready(Err(IpcError::from(e))),
                Poll::Ready(Ok(s)) => *revision = s.revision,
                Poll::Pending => {}
            }
            if let Some(clock) = &clock {
                match clock.sample() {
                    Ok(s) => *revision = s.revision,
                    Err(e) => return Poll::Ready(Err(e.into())),
                }
            }
        }
        Poll::Ready(Ok(match state.poll(listeners, cx, true) {
            Poll::Ready(event) => Some(event),
            Poll::Pending => None,
        }))
    })
    .await?;
    ready()?;
    loop {
        if draining
            && !state
                .sessions
                .iter()
                .flatten()
                .any(|session| !session.monitor)
        {
            for index in 0..state.sessions.len() {
                if state.sessions[index].is_some() {
                    state.close(index, CloseReason::Shutdown, &mut closed)?;
                }
            }
            return Ok(state.report);
        }
        let next_deadline = state
            .sessions
            .iter()
            .flatten()
            .filter_map(|session| session.deadline)
            .min()
            .into_iter()
            .chain(stop_at)
            .min();
        if let Some(deadline) = next_deadline {
            timer.as_mut().reset(deadline);
        }
        let event = poll_fn(|context| {
            // Native original stop target is checked/armed before clock waits.
            if stop_at.is_some_and(|at| Instant::now() >= at) {
                return Poll::Ready(Event::ForceShutdown);
            }
            if next_deadline.is_some() {
                let _registered = timer.as_mut().poll(context);
            }
            if let Some((subscription, revision)) = &mut clock_state {
                match subscription.poll_changed(context, *revision) {
                    Poll::Ready(Err(e)) => return Poll::Ready(Event::SourceFailure(e.into())),
                    Poll::Ready(Ok(s)) => *revision = s.revision,
                    Poll::Pending => {}
                }
                if let Some(clock) = &clock {
                    match clock.sample() {
                        Ok(s) => *revision = s.revision,
                        Err(e) => return Poll::Ready(Event::SourceFailure(e.into())),
                    }
                }
            }
            if let Some(event) = first_event.take() {
                return Poll::Ready(event);
            }
            if !draining && shutdown.as_mut().poll(context).is_ready() {
                return Poll::Ready(Event::Shutdown);
            }
            if let Poll::Ready(event) = state.poll(listeners, context, !draining) {
                return Poll::Ready(event);
            }
            if next_deadline.is_some() && timer.as_mut().poll(context).is_ready() {
                return Poll::Ready(Event::Tick);
            }
            Poll::Pending
        })
        .await;
        match event {
            Event::Accept(connection) => {
                let (stream, peer, diagnostics) = connection.into_parts();
                for diagnostic in diagnostics {
                    closed(ServiceEvent::Socket(SocketEvent::Diagnostic(diagnostic)));
                }
                state.accept(stream, peer, &options.access, &mut closed)?;
            }
            Event::AcceptFailure(failure) => {
                if matches!(&failure, AcceptError::Initialization(_)) {
                    increment(&mut state.report.accepted)?;
                    increment(&mut state.report.rejected)?;
                }
                closed(ServiceEvent::Socket(state.accepting.failed(failure)));
            }
            Event::Frame(index) => {
                if let Err(error) = state.dispatch(index) {
                    state.close(index, CloseReason::Failure(error), &mut closed)?;
                }
                state.notifications(&mut closed)?;
            }
            Event::Close(index, reason) => state.close(index, reason, &mut closed)?,
            Event::Shutdown => {
                if options.shutdown == ShutdownMode::Soft {
                    draining = true;
                    stop_at = shutdown_grace
                        .map(|d| Instant::now().checked_add(d).ok_or(Error::Overflow))
                        .transpose()?;
                    continue;
                }
                for index in 0..state.sessions.len() {
                    if state.sessions[index].is_some() {
                        state.close(index, CloseReason::Shutdown, &mut closed)?;
                    }
                }
                return Ok(state.report);
            }
            Event::ForceShutdown => {
                for index in 0..state.sessions.len() {
                    if state.sessions[index].is_some() {
                        state.close(index, CloseReason::Shutdown, &mut closed)?;
                    }
                }
                closed(ServiceEvent::ForcedShutdown);
                return Ok(state.report);
            }
            Event::SourceFailure(error) => return Err(error),
            Event::Activity | Event::Tick => {}
        }
        tokio::task::yield_now().await;
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Real socket tests assert protocol, resource and lifecycle outcomes"
    )]
    use super::*;
    use crate::{StatisticsClient, StatisticsWatchClient};
    use gnunet_client::statistics::{Response, Selector, Set};
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    use tokio::net::TcpListener;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixStream,
    };

    static NEXT: AtomicU64 = AtomicU64::new(1);
    type Core = Statistics<8, 64, 4, 8, 16>;
    type Completion<T> = Result<(Report, T, Vec<SessionClosed>), IpcError>;
    type Running<T> = (PathBuf, UnixStream, tokio::task::JoinHandle<Completion<T>>);
    fn bounded_state(core: &mut Core) -> Result<State<'_, 8, 64, 4, 8, 16>, IpcError> {
        let limits = limits();
        let sessions: Vec<Option<Session>> = std::iter::repeat_with(|| None).take(4).collect();
        let scratch = buffer(limits.max_frame_bytes, true)?;
        let baseline = core.external_retained_bytes();
        let external = baseline
            .checked_add(scratch.capacity())
            .and_then(|n| {
                sessions
                    .capacity()
                    .checked_mul(core::mem::size_of::<Option<Session>>())
                    .and_then(|m| n.checked_add(m))
            })
            .ok_or(Error::Overflow)?;
        core.set_external_retained_bytes(external)?;
        Ok(State {
            core,
            sessions,
            scratch,
            limits,
            cursor: 0,
            report: Report::default(),
            accepting: AcceptState::default(),
            tolerant: false,
            unix_access: UnixAccess::default(),
            external,
            baseline,
        })
    }
    #[test]
    fn accepted_tcp_is_canonical_before_statistics_core_admission()
    -> Result<(), Box<dyn std::error::Error>> {
        runtime()?.block_on(async {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let _peer = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
            let mut core = Core::new();
            let mut state = bounded_state(&mut core)?;
            let Event::Accept(accepted) =
                poll_fn(|cx| state.poll(&[Listener::Tcp(&listener)], cx, true)).await
            else {
                return Err("expected actual TCP acceptance".into());
            };
            assert_eq!(state.core.client_count(), 0);
            assert!(accepted.diagnostics().is_empty());
            let (stream, peer, _) = accepted.into_parts();
            let socket = socket2::SockRef::from(&stream);
            assert!(socket.nonblocking()?);
            assert!(socket.tcp_nodelay()?);
            use std::os::fd::AsFd;
            assert!(
                nix::fcntl::FdFlag::from_bits_retain(nix::fcntl::fcntl(
                    stream.as_fd(),
                    nix::fcntl::FcntlArg::F_GETFD
                )?)
                .contains(nix::fcntl::FdFlag::FD_CLOEXEC)
            );
            state.accept(stream, peer, &AccessPolicy::default(), &mut |_| {})?;
            assert_eq!(state.core.client_count(), 1);
            Ok(())
        })
    }
    #[test]
    fn finite_emfile_observation_pauses_accept_until_original_live_client_physically_closes()
    -> Result<(), Box<dyn std::error::Error>> {
        runtime()?.block_on(async {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let first = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
            let mut core = Core::new();
            let mut state = bounded_state(&mut core)?;
            let Event::Accept(accepted) =
                poll_fn(|cx| state.poll(&[Listener::Tcp(&listener)], cx, true)).await
            else {
                return Err("expected first actual accept".into());
            };
            let (stream, peer, _) = accepted.into_parts();
            state.accept(stream, peer, &AccessPolicy::default(), &mut |_| {})?;
            let original = state
                .sessions
                .iter()
                .flatten()
                .next()
                .ok_or("original session")?
                .client;
            // This error observation is a finite seam. Both native sockets and
            // the queued connection/EOF below are real; no syscall failure is claimed.
            let event = state
                .accepting
                .failed(AcceptError::Accept(io::Error::from_raw_os_error(
                    nix::errno::Errno::EMFILE as i32,
                )));
            assert!(matches!(event, SocketEvent::Failed(error) if error.is_emfile()));
            let _queued = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(20),
                    poll_fn(|cx| state.poll(&[Listener::Tcp(&listener)], cx, true))
                )
                .await
                .is_err()
            );
            assert_eq!(state.core.client_count(), 1);
            assert!(!state.accepting.ready());
            drop(first);
            let Event::Close(index, reason) =
                poll_fn(|cx| state.poll(&[Listener::Tcp(&listener)], cx, true)).await
            else {
                return Err("original EOF must remain active while accepts are paused".into());
            };
            assert!(matches!(reason, CloseReason::Eof));
            state.close(index, reason, &mut |_| {})?;
            assert_eq!(state.core.client_count(), 0);
            assert!(state.accepting.ready());
            let Event::Accept(accepted) =
                poll_fn(|cx| state.poll(&[Listener::Tcp(&listener)], cx, true)).await
            else {
                return Err(
                    "the original kernel-queued connection must be accepted after close".into(),
                );
            };
            let (stream, peer, _) = accepted.into_parts();
            state.accept(stream, peer, &AccessPolicy::default(), &mut |_| {})?;
            let replacement = state
                .sessions
                .iter()
                .flatten()
                .next()
                .ok_or("replacement session")?
                .client;
            assert_ne!(original, replacement);
            assert_eq!(state.report.accepted, 2);
            assert_eq!(state.report.admitted, 2);
            Ok(())
        })
    }
    fn path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "gnunet-server-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }
    fn limits() -> Limits {
        Limits {
            max_connections: 4,
            max_frame_bytes: 128,
            max_pending_bytes: 512,
            idle_timeout: Duration::from_secs(2),
        }
    }
    fn start<const R: usize, const N: usize, const C: usize, const W: usize, const E: usize>(
        core: Statistics<R, N, C, W, E>,
        limits: Limits,
    ) -> Result<Running<Statistics<R, N, C, W, E>>, io::Error> {
        start_with_policy(core, limits, false)
    }
    fn start_with_policy<
        const R: usize,
        const N: usize,
        const C: usize,
        const W: usize,
        const E: usize,
    >(
        mut core: Statistics<R, N, C, W, E>,
        limits: Limits,
        soft: bool,
    ) -> Result<Running<Statistics<R, N, C, W, E>>, io::Error> {
        let path = path();
        let listener = UnixListener::bind(&path)?;
        let (mut stop_reader, stop_writer) = UnixStream::pair()?;
        let task = tokio::spawn(async move {
            let stop = async {
                let mut byte = [0; 1];
                match stop_reader.read(&mut byte).await {
                    Ok(_) | Err(_) => {}
                }
            };
            let mut closed = Vec::new();
            let report = serve_statistics_on(
                &[Listener::Unix(&listener)],
                &mut core,
                limits,
                &ServiceOptions {
                    shutdown: if soft {
                        ShutdownMode::Soft
                    } else {
                        ShutdownMode::Immediate
                    },
                    ..ServiceOptions::default()
                },
                stop,
                |event| {
                    if let ServiceEvent::Closed(event) = event {
                        closed.push(event);
                    }
                },
            )
            .await?;
            Ok((report, core, closed))
        });
        Ok((path, stop_writer, task))
    }
    async fn read<const N: usize>(
        stream: &mut UnixStream,
    ) -> Result<[u8; N], Box<dyn std::error::Error>> {
        let mut bytes = [0; N];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut bytes)).await??;
        Ok(bytes)
    }
    async fn eof(stream: &mut UnixStream) -> Result<(), Box<dyn std::error::Error>> {
        let mut byte = [0; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte)).await??,
            0
        );
        Ok(())
    }
    fn runtime() -> Result<tokio::runtime::Runtime, io::Error> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
    }

    #[test]
    fn official_soft_shutdown_finishes_writer_and_does_not_wait_for_monitors()
    -> Result<(), Box<dyn std::error::Error>> {
        runtime()?.block_on(async {
            let (path, stop, mut task) = start_with_policy(Core::new(), limits(), true)?;
            let mut monitor = UnixStream::connect(&path).await?;
            monitor.write_all(b"\0\x08\0\xacs\0a\0\0\x04\0\xae").await?;
            assert_eq!(read::<4>(&mut monitor).await?, *b"\0\x04\0\xaf");
            let mut writer = UnixStream::connect(&path).await?;
            writer.write_all(b"\0\x04\0\xae").await?;
            assert_eq!(read::<4>(&mut writer).await?, *b"\0\x04\0\xaf");
            drop(stop);
            assert!(
                tokio::time::timeout(Duration::from_millis(20), &mut task)
                    .await
                    .is_err()
            );
            // Existing non-monitor requests continue after shutdown was requested.
            writer
                .write_all(b"\0\x14\0\xa8\0\0\0\x02\0\0\0\0\0\0\0\x05s\0a\0\0\x04\0\xae")
                .await?;
            assert_eq!(read::<4>(&mut writer).await?, *b"\0\x04\0\xaf");
            assert_eq!(
                read::<24>(&mut monitor).await?,
                *b"\0\x18\0\xad\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x05"
            );
            // A monitor cannot hold soft shutdown open after the last writer leaves.
            drop(writer);
            let (report, core, events) =
                tokio::time::timeout(Duration::from_secs(1), task).await???;
            eof(&mut monitor).await?;
            assert_eq!(report.requests, 5);
            assert_eq!(core.client_count(), 0);
            assert_eq!(core.watch_count(), 0);
            assert_eq!(core.persistent().count(), 1);
            assert!(
                events
                    .iter()
                    .any(|event| matches!(event.reason, CloseReason::Shutdown))
            );
            std::fs::remove_file(path)?;
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    }

    #[test]
    fn real_rust_client_and_literal_peer_get_watch_and_barrier()
    -> Result<(), Box<dyn std::error::Error>> {
        runtime()?.block_on(async {
            let (path, stop, task) = start(Core::new(), limits())?;
            let mut watcher = UnixStream::connect(&path).await?;
            // Independent literal WATCH and barrier prove the watch was processed.
            watcher
                .write_all(b"\0\x0f\0\xaccore\0peers\0\0\x04\0\xae")
                .await?;
            assert_eq!(read::<4>(&mut watcher).await?, *b"\0\x04\0\xaf");
            let selector = Selector {
                subsystem: b"core",
                name: b"peers",
            };
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut writer = StatisticsClient::connect(&path, deadline).await?;
            writer
                .set_and_disconnect(
                    Set {
                        selector,
                        flags: 2,
                        value: 9,
                    },
                    &mut [0; 128],
                    deadline,
                )
                .await?;
            assert_eq!(
                read::<24>(&mut watcher).await?,
                *b"\0\x18\0\xad\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x09"
            );
            let mut reader = StatisticsClient::connect(&path, deadline).await?;
            let mut seen = None;
            assert_eq!(
                reader
                    .get(selector, 1, &mut [0; 128], deadline, |value| {
                        seen = Some((value.uid(), value.value, value.persistent()));
                        Ok(())
                    })
                    .await?,
                1
            );
            assert_eq!(seen, Some((0, 9, true)));
            // DISCONNECT does not discard the watch or close the socket.
            watcher
                .write_all(b"\0\x04\0\xae\0\x0f\0\xa9core\0peers\0")
                .await?;
            assert_eq!(read::<4>(&mut watcher).await?, *b"\0\x04\0\xaf");
            let bytes = read::<27>(&mut watcher).await?;
            let Response::Value(value) = Response::decode(&bytes)? else {
                return Err(Error::InvalidInput.into());
            };
            assert_eq!(value.value, 9);
            assert_eq!(read::<4>(&mut watcher).await?, *b"\0\x04\0\xab");
            let mut writer = StatisticsClient::connect(&path, deadline).await?;
            writer
                .set_and_disconnect(
                    Set {
                        selector,
                        flags: 0,
                        value: 10,
                    },
                    &mut [0; 128],
                    deadline,
                )
                .await?;
            assert_eq!(
                read::<24>(&mut watcher).await?,
                *b"\0\x18\0\xad\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0a"
            );
            drop(stop);
            let (report, core, events) = task.await??;
            assert_eq!(report.requests, 9);
            assert_eq!(report.notifications, 2);
            assert_eq!(core.client_count(), 0);
            assert_eq!(core.watch_count(), 0);
            assert_eq!(core.notification_count_queued(), 0);
            assert_eq!(core.row_count(), 1);
            assert_eq!(events.len() as u64, report.closed);
            assert!(
                events
                    .iter()
                    .all(|event| !matches!(event.reason, CloseReason::Failure(_)))
            );
            std::fs::remove_file(path)?;
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    }

    #[test]
    fn malformed_oversized_and_partial_eof_close_only_their_session()
    -> Result<(), Box<dyn std::error::Error>> {
        runtime()?.block_on(async {
            let (path, stop, task) = start(Core::new(), Limits { max_connections: 1, ..limits() })?;
            for bytes in [&b"\0\x03\0\xa9"[..], &b"\0\x81\0\xa9"[..], &b"\0\x0f"[..]] {
                let mut peer = UnixStream::connect(&path).await?;
                peer.write_all(bytes).await?;
                peer.shutdown().await?;
                eof(&mut peer).await?;
            }
            let mut healthy = UnixStream::connect(&path).await?;
            healthy.write_all(b"\0\x04\0\xae").await?;
            assert_eq!(read::<4>(&mut healthy).await?, *b"\0\x04\0\xaf");
            drop(healthy);
            drop(stop);
            let (report, core, events) = task.await??;
            assert_eq!(report.admitted, 4);
            assert_eq!(report.requests, 1);
            assert_eq!(core.client_count(), 0);
            for (event, expected) in events.iter().take(3).zip([Error::InvalidInput, Error::Capacity, Error::Truncated]) {
                assert!(matches!(&event.reason, CloseReason::Failure(IpcError::Protocol(error)) if *error == expected));
            }
            std::fs::remove_file(path)?;
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    }

    #[test]
    fn output_and_core_notification_overflow_have_real_close_outcomes()
    -> Result<(), Box<dyn std::error::Error>> {
        runtime()?.block_on(async {
            let mut core = Core::new();
            let id = core.connect()?;
            core.set(
                id,
                Set {
                    selector: Selector {
                        subsystem: b"core",
                        name: b"peers",
                    },
                    flags: 0,
                    value: 9,
                },
            )?;
            core.disconnect(id)?;
            let (path, stop, task) = start(
                core,
                Limits {
                    max_connections: 1,
                    max_pending_bytes: 4,
                    ..limits()
                },
            )?;
            for request in [b"\0\x0f\0\xaccore\0peers\0", b"\0\x0f\0\xa9core\0peers\0"] {
                let mut peer = UnixStream::connect(&path).await?;
                peer.write_all(request).await?;
                eof(&mut peer).await?;
            }
            let mut healthy = UnixStream::connect(&path).await?;
            healthy.write_all(b"\0\x04\0\xae").await?;
            assert_eq!(read::<4>(&mut healthy).await?, *b"\0\x04\0\xaf");
            drop(stop);
            let (_, core, events) = task.await??;
            assert_eq!(core.client_count(), 0);
            assert_eq!(core.watch_count(), 0);
            assert_eq!(core.notification_count_queued(), 0);
            assert!(events.iter().take(2).all(|event| matches!(
                event.reason,
                CloseReason::Failure(IpcError::Protocol(Error::Capacity))
            )));
            std::fs::remove_file(path)?;

            let core = Statistics::<8, 64, 4, 8, 0>::new();
            let (path, stop, task) = start(core, limits())?;
            let mut watcher = UnixStream::connect(&path).await?;
            watcher
                .write_all(b"\0\x0f\0\xaccore\0peers\0\0\x04\0\xae")
                .await?;
            assert_eq!(read::<4>(&mut watcher).await?, *b"\0\x04\0\xaf");
            let mut writer = UnixStream::connect(&path).await?;
            writer
                .write_all(b"\0\x1b\0\xa8\0\0\0\0\0\0\0\0\0\0\0\x09core\0peers\0")
                .await?;
            eof(&mut writer).await?;
            watcher.write_all(b"\0\x0f\0\xa9core\0peers\0").await?;
            let bytes = read::<27>(&mut watcher).await?;
            let Response::Value(value) = Response::decode(&bytes)? else {
                return Err(Error::InvalidInput.into());
            };
            assert_eq!(value.value, 0); // Rejected SET did not commit a value.
            assert_eq!(read::<4>(&mut watcher).await?, *b"\0\x04\0\xab");
            drop(stop);
            let (_, core, events) = task.await??;
            assert!(events.iter().any(|event| matches!(
                event.reason,
                CloseReason::Failure(IpcError::Protocol(Error::Capacity))
            )));
            assert_eq!(core.client_count(), 0);
            assert_eq!(core.watch_count(), 0);
            std::fs::remove_file(path)?;
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    }

    #[test]
    fn connection_limit_and_idle_deadline_release_real_ids()
    -> Result<(), Box<dyn std::error::Error>> {
        runtime()?.block_on(async {
            let (path, stop, task) = start(
                Core::new(),
                Limits {
                    max_connections: 1,
                    idle_timeout: Duration::from_millis(50),
                    ..limits()
                },
            )?;
            let mut first = UnixStream::connect(&path).await?;
            first.write_all(b"\0\x04\0\xae").await?;
            assert_eq!(read::<4>(&mut first).await?, *b"\0\x04\0\xaf");
            let mut excess = UnixStream::connect(&path).await?;
            eof(&mut excess).await?;
            eof(&mut first).await?;
            let mut replacement = UnixStream::connect(&path).await?;
            replacement.write_all(b"\0\x04\0\xae").await?;
            assert_eq!(read::<4>(&mut replacement).await?, *b"\0\x04\0\xaf");
            drop(stop);
            let (report, core, events) = task.await??;
            assert_eq!(report.accepted, 3);
            assert_eq!(report.admitted, 2);
            assert_eq!(report.rejected, 1);
            assert_eq!(core.client_count(), 0);
            assert!(events.iter().any(|event| event.client.is_none()
                && matches!(
                    event.reason,
                    CloseReason::Failure(IpcError::Protocol(Error::Capacity))
                )));
            assert!(
                events
                    .iter()
                    .any(|event| matches!(event.reason, CloseReason::IdleTimeout))
            );
            std::fs::remove_file(path)?;
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    }

    #[test]
    fn cancelling_the_server_future_releases_watches_and_partial_sessions()
    -> Result<(), Box<dyn std::error::Error>> {
        runtime()?.block_on(async {
            let path = path();
            let listener = UnixListener::bind(&path)?;
            let mut core = Core::new();
            let peer_path = path.clone();
            let peer = tokio::spawn(async move {
                let mut watcher = UnixStream::connect(&peer_path).await?;
                watcher
                    .write_all(b"\0\x0f\0\xaccore\0peers\0\0\x04\0\xae")
                    .await?;
                let mut ack = [0; 4];
                watcher.read_exact(&mut ack).await?;
                assert_eq!(&ack, b"\0\x04\0\xaf");
                let mut partial = UnixStream::connect(&peer_path).await?;
                partial.write_all(b"\0\x0f").await?;
                let mut byte = [0; 1];
                assert_eq!(watcher.read(&mut byte).await?, 0);
                assert_eq!(partial.read(&mut byte).await?, 0);
                Ok::<(), io::Error>(())
            });
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(100),
                    serve_statistics(
                        &listener,
                        &mut core,
                        limits(),
                        std::future::pending(),
                        |_| {}
                    )
                )
                .await
                .is_err()
            );
            peer.await??;
            assert_eq!(core.client_count(), 0);
            assert_eq!(core.watch_count(), 0);
            assert_eq!(core.notification_count_queued(), 0);
            assert_eq!(core.row_count(), 1);
            std::fs::remove_file(path)?;
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    }

    #[test]
    fn real_watch_client_keeps_id_one_after_cancelling_zero()
    -> Result<(), Box<dyn std::error::Error>> {
        runtime()?.block_on(async {
            let old = Selector {
                subsystem: b"core",
                name: b"old",
            };
            let new = Selector {
                subsystem: b"core",
                name: b"new",
            };
            let mut core = Core::new();
            let temporary = core.connect()?;
            core.set(
                temporary,
                Set {
                    selector: old,
                    flags: 0,
                    value: 1,
                },
            )?;
            core.disconnect(temporary)?;
            let (path, stop, task) = start(core, limits())?;
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut statistics_instance_1 = gnunet_client::statistics_handle::Instance::new();
            let mut watcher = StatisticsWatchClient::<'_, 2>::connect(
                &mut statistics_instance_1,
                &path,
                deadline,
            )
            .await?;
            let mut scratch = [0; 128];
            let cancelled = watcher.watch(old, &mut scratch, deadline).await?;
            assert_eq!(cancelled.value(), 0);
            let initial = watcher.next(&mut scratch, deadline).await?;
            assert_eq!(initial.id, cancelled);
            assert_eq!(initial.notification.value, 1);
            watcher.cancel(cancelled)?;
            let active = watcher.watch(new, &mut scratch, deadline).await?;
            assert_eq!(active.value(), 1);
            // A real update of cancelled WID 0 must be consumed without
            // becoming an active subscription callback.
            for (selector, value, flags) in [(old, 9, 0), (new, 17, 2)] {
                let mut writer = StatisticsClient::connect(&path, deadline).await?;
                writer
                    .set_and_disconnect(
                        Set {
                            selector,
                            flags,
                            value,
                        },
                        &mut scratch,
                        deadline,
                    )
                    .await?;
            }
            let update = watcher.next(&mut scratch, deadline).await?;
            assert_eq!(update.id, active);
            assert_eq!(update.selector, new);
            assert_eq!(update.notification.value, 17);
            assert!(update.notification.persistent());
            watcher.close();
            assert!(watcher.is_closed());
            assert!(matches!(watcher.cancel(active), Err(IpcError::Closed)));
            // A separate GET makes the host process the watch socket's actual
            // EOF before shutdown, so resource cleanup is observed independently.
            let mut reader = StatisticsClient::connect(&path, deadline).await?;
            assert_eq!(
                reader
                    .get(
                        Selector {
                            subsystem: b"",
                            name: b""
                        },
                        2,
                        &mut scratch,
                        deadline,
                        |_| Ok(())
                    )
                    .await?,
                2
            );
            drop(stop);
            let (report, core, events) = task.await??;
            assert_eq!(report.notifications, 3);
            assert_eq!(core.client_count(), 0);
            assert_eq!(core.watch_count(), 0);
            assert_eq!(core.notification_count_queued(), 0);
            assert!(events.iter().any(|event| {
                event.client.is_some_and(|id| id.resource_id().index == 0)
                    && matches!(event.reason, CloseReason::Eof)
            }));
            std::fs::remove_file(path)?;
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    }

    #[test]
    fn overflowing_one_watch_queue_does_not_consume_another_clients_effects()
    -> Result<(), Box<dyn std::error::Error>> {
        runtime()?.block_on(async {
            let (path, stop, task) = start(
                Core::new(),
                Limits {
                    max_pending_bytes: 24,
                    ..limits()
                },
            )?;
            let mut overflowing = UnixStream::connect(&path).await?;
            overflowing
                .write_all(b"\0\x0f\0\xaccore\0peers\0\0\x0f\0\xaccore\0peers\0\0\x04\0\xae")
                .await?;
            assert_eq!(read::<4>(&mut overflowing).await?, *b"\0\x04\0\xaf");
            let mut healthy = UnixStream::connect(&path).await?;
            healthy
                .write_all(b"\0\x0f\0\xaccore\0peers\0\0\x04\0\xae")
                .await?;
            assert_eq!(read::<4>(&mut healthy).await?, *b"\0\x04\0\xaf");
            let deadline = Instant::now() + Duration::from_secs(2);
            let selector = Selector {
                subsystem: b"core",
                name: b"peers",
            };
            let mut writer = StatisticsClient::connect(&path, deadline).await?;
            writer
                .set_and_disconnect(
                    Set {
                        selector,
                        flags: 0,
                        value: 1,
                    },
                    &mut [0; 128],
                    deadline,
                )
                .await?;
            eof(&mut overflowing).await?;
            assert_eq!(
                read::<24>(&mut healthy).await?,
                *b"\0\x18\0\xad\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01"
            );
            let mut writer = StatisticsClient::connect(&path, deadline).await?;
            writer
                .set_and_disconnect(
                    Set {
                        selector,
                        flags: 0,
                        value: 2,
                    },
                    &mut [0; 128],
                    deadline,
                )
                .await?;
            assert_eq!(
                read::<24>(&mut healthy).await?,
                *b"\0\x18\0\xad\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x02"
            );
            drop(stop);
            let (_, core, events) = task.await??;
            assert_eq!(core.client_count(), 0);
            assert_eq!(core.watch_count(), 0);
            assert_eq!(core.notification_count_queued(), 0);
            assert_eq!(
                events
                    .iter()
                    .filter(|event| matches!(
                        event.reason,
                        CloseReason::Failure(IpcError::Protocol(Error::Capacity))
                    ))
                    .count(),
                1
            );
            std::fs::remove_file(path)?;
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    }
}
