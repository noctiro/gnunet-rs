//! Bounded native host for the official STATISTICS service core.
//!
//! GNUnet v0.29.1's `gnunet-service-statistics.c:415,589,732,800` dispatches
//! GET, SET, WATCH and DISCONNECT respectively. DISCONNECT is a processing
//! barrier, not EOF or a durable commit. This adapter adds no wire protocol.
//! The application binds and removes the socket and owns persistent storage.

use crate::IpcError;
use gnunet_service_runtime::acl::AccessPolicy;
use gnunet_service_runtime::connection::Connection;
use gnunet_service_runtime::local::Listener as LocalListener;
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
    listener: &LocalListener,
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
    listener: &LocalListener,
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
/// host scratch/accounting is initialized and the actual listener owner is polled.
/// Dropping/error retires all original client generations before returning core.
pub fn serve_statistics_controlled<
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
    closed: impl FnMut(ServiceEvent),
) -> impl Future<Output = Result<Report, IpcError>> {
    serve_statistics_controlled_with_async_ready(
        listeners,
        core,
        limits,
        context,
        shutdown,
        move || std::future::ready(ready()),
        closed,
    )
}
/// Serve the same original sources while awaiting native asynchronous startup.
/// Ready errors and cancellation retire admitted sessions and restore core byte
/// accounting. The callback is invoked only after actual listener polling;
/// borrowed listening sockets remain owned by the caller.
pub async fn serve_statistics_controlled_with_async_ready<
    const R: usize,
    const N: usize,
    const C: usize,
    const W: usize,
    const E: usize,
    Ready: Future<Output = Result<(), IpcError>>,
>(
    listeners: &[Listener<'_>],
    core: &mut Statistics<R, N, C, W, E>,
    limits: Limits,
    context: ServeContext<'_>,
    shutdown: impl Future<Output = ()>,
    ready: impl FnOnce() -> Ready,
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
    ready().await?;
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

#[cfg(all(test, unix))]
mod unix_tests;
