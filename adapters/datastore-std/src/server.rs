//! Independent native DATASTORE server over a dedicated serialized backend.
//!
//! One connection has one backend job and one retained reply at a time. Dropped
//! drive waits preserve both. Disconnect closes the actual socket before its
//! queued job settles and before connection-scoped reservations are released.
//! Call shutdown to join the original worker; Drop closes sockets and requests
//! termination but makes no claim that an outstanding filesystem call finished.
mod credentials;
mod worker;
pub use credentials::UnixAccess;
use gnunet_datastore::{
    Config,
    backend::{Backend, Failure},
};
use gnunet_service_runtime::{
    accepted::{AcceptState, SocketEvent},
    clock::RuntimeClock,
    framing::{Accounting, Budget, Class, Framed, Limits as FrameLimits, OwnedFrame, ReadStep},
    service::{Listener, PeerAddress, ServiceOptions, ShutdownMode},
};
use gnunet_types::Error as ProtocolError;
use gnunet_wire::official::datastore::Request;
use std::{
    fmt,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
use worker::{Action, Command, Pending, Worker};

/// Original native/service/backend failure. Backend uncertainty never becomes
/// a fabricated failure STATUS; the original physical MQ is closed instead.
#[derive(Debug)]
pub enum Error {
    /// Actual socket, thread or native random-source error.
    Io(io::Error),
    /// Official framing, owner or explicit resource refusal.
    Protocol(ProtocolError),
    /// Original backend cause with its actual commit certainty.
    Backend {
        /// Before-commit refusal versus possible committed mutation.
        certainty: Failure,
        /// Complete original backend error and its source chain.
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// Original worker command/result channel ended unexpectedly.
    WorkerGone,
    /// Original worker or its join task panicked.
    WorkerPanicked,
}
impl Error {
    fn fatal(&self) -> bool {
        matches!(
            self,
            Self::Backend {
                certainty: Failure::Unknown,
                ..
            } | Self::WorkerGone
                | Self::WorkerPanicked
                | Self::Protocol(ProtocolError::OutcomeUnknown)
        )
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "DATASTORE native IO: {error}"),
            Self::Protocol(error) => write!(f, "DATASTORE service: {error}"),
            Self::Backend { certainty, source } => {
                write!(f, "DATASTORE backend {certainty:?}: {source}")
            }
            Self::WorkerGone => f.write_str("DATASTORE worker ended"),
            Self::WorkerPanicked => f.write_str("DATASTORE worker panicked"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Backend { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}
/// Explicit native connection, queue and reclamation bounds.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum retained actual socket owners, including closing backend jobs.
    pub clients: usize,
    /// Maximum simultaneously live connection-scoped reservations.
    pub reservations: usize,
    /// Backend command queue slots. Waiting commands remain in original peers.
    pub worker_queue: usize,
    /// Largest single native read/write step, nonzero.
    pub io_slice_bytes: usize,
    /// Interval between bounded expiry/space slices; must be nonzero.
    pub maintenance_interval: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            clients: 128,
            reservations: 4096,
            worker_queue: 32,
            io_slice_bytes: 65535,
            maintenance_interval: Duration::from_secs(1),
        }
    }
}
impl Limits {
    fn validate(self) -> Result<(), ProtocolError> {
        if self.clients == 0
            || self.worker_queue == 0
            || self.worker_queue > tokio::sync::Semaphore::MAX_PERMITS
            || self.io_slice_bytes == 0
            || self.maintenance_interval.is_zero()
            || Instant::now()
                .checked_add(self.maintenance_interval)
                .is_none()
        {
            return Err(ProtocolError::InvalidInput);
        }
        Ok(())
    }
    fn framing(self) -> FrameLimits {
        FrameLimits {
            frame_bytes: 65535,
            ordinary: Budget {
                frames: 1,
                bytes: 65535,
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.io_slice_bytes,
        }
    }
}
/// Actual local service observations. Session numbers are diagnostics only;
/// none are transmitted as private request IDs or grant application authority.
pub enum Event {
    /// Canonical accept/socket initialization diagnostics in their source order.
    Socket(SocketEvent),
    /// Accepted connection failed address/credential admission.
    Rejected(PeerAddress),
    /// Original physical socket was closed; worker cleanup may still be pending.
    ClientClosed(u64),
    /// Original native/core/backend fault, including negative-reply diagnostics.
    Fault {
        /// Original client diagnostic, absent for global maintenance/shutdown.
        client: Option<u64>,
        /// Original owned cause retained without replacing it with success.
        cause: Arc<Error>,
    },
}
/// Local native progress only; no variant fabricates a service processing ACK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// One actual bounded IO, worker or cleanup step completed.
    Activity,
    /// A new canonically initialized socket owner was admitted.
    Accepted,
    /// Observation budget ended; original work is retained.
    WaitDeadline,
    /// Sockets and pure clients have closed and Stop returned. Joining the
    /// original worker remains necessary before claiming filesystem quiescence.
    Stopped,
}
/// Final native counters and the original global failure, if any.
#[derive(Clone, Debug, Default)]
pub struct Report {
    /// Actual accepted socket owners.
    pub accepted: u64,
    /// Complete valid frames submitted to the original backend worker.
    pub requests: u64,
    /// Actual complete reply frames admitted for original-socket output.
    pub replies: u64,
    /// Actual physical positive socket write bytes.
    pub written_bytes: u64,
    /// Actual original sockets closed.
    pub closed: u64,
    /// DROP was actually applied at backend shutdown.
    pub dropped_on_shutdown: bool,
    /// True only after joining this original worker, never just losing a channel.
    pub worker_quiesced: bool,
    /// First actual global failure, preserving its original source.
    pub failure: Option<Arc<Error>>,
}
#[derive(Clone, Copy)]
enum PendingKind {
    Attach,
    Request,
    Detach,
}
struct Peer {
    serial: u64,
    framed: Option<Framed<u64>>,
    pending: Option<(PendingKind, Pending)>,
    attached: bool,
    closing: bool,
}
// Peer fields are dropped before Worker. Its only command senders are either
// retained here or in Worker, so Drop cannot leave a hidden producer alive.
/// Bounded native socket owners and their original dedicated backend worker.
pub struct Server {
    peers: Vec<Option<Peer>>,
    worker: Worker,
    limits: Limits,
    options: ServiceOptions,
    unix: UnixAccess,
    accept: AcceptState,
    serial: u64,
    cursor: usize,
    listener_cursor: usize,
    class_cursor: u8,
    shutting_down: bool,
    shutdown_mode: ShutdownMode,
    stopped: bool,
    maintenance: Option<Pending>,
    stop: Option<Pending>,
    tick: Pin<Box<Sleep>>,
    wait: Option<Pin<Box<Sleep>>>,
    report: Report,
}
impl Server {
    /// Move a recovered/fenced backend into one dedicated worker. Construction
    /// creates no listener or Resolver and returns only after pure state is ready.
    pub async fn new<B>(
        backend: B,
        config: Config,
        limits: Limits,
        options: ServiceOptions,
        unix: UnixAccess,
        clock: Arc<dyn RuntimeClock>,
    ) -> Result<Self, Arc<Error>>
    where
        B: Backend + Send + 'static,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        limits
            .validate()
            .map_err(|error| Arc::new(Error::Protocol(error)))?;
        let mut peers = Vec::new();
        peers
            .try_reserve_exact(limits.clients)
            .map_err(|_| Arc::new(Error::Protocol(ProtocolError::Capacity)))?;
        peers.resize_with(limits.clients, || None);
        let worker = Worker::start(backend, config, limits, clock).await?;
        let shutdown_mode = options.shutdown;
        let next_tick = Instant::now()
            .checked_add(limits.maintenance_interval)
            .ok_or_else(|| Arc::new(Error::Protocol(ProtocolError::Overflow)))?;
        Ok(Self {
            peers,
            worker,
            limits,
            options,
            unix,
            accept: AcceptState::default(),
            serial: 0,
            cursor: 0,
            listener_cursor: 0,
            class_cursor: 0,
            shutting_down: false,
            shutdown_mode,
            stopped: false,
            maintenance: None,
            stop: None,
            tick: Box::pin(tokio::time::sleep_until(next_tick)),
            wait: None,
            report: Report::default(),
        })
    }
    /// Snapshot of actual native work; worker_quiesced remains false until join.
    #[must_use]
    pub fn report(&self) -> &Report {
        &self.report
    }
    /// Stop accepting and stop dispatching new frames. Immediate closes sockets
    /// now; Soft drains original jobs/replies before closing. Both retain the
    /// worker and its original accepted operations until actual settlement.
    pub fn request_shutdown(&mut self, mode: ShutdownMode) {
        self.shutting_down = true;
        self.shutdown_mode = mode;
    }
    fn fault(&mut self, client: Option<u64>, cause: Arc<Error>, observe: &mut impl FnMut(Event)) {
        if cause.fatal() {
            if self.report.failure.is_none() {
                self.report.failure = Some(cause.clone());
            }
            self.request_shutdown(ShutdownMode::Immediate);
        }
        observe(Event::Fault { client, cause });
    }
    fn close_wire(&mut self, index: usize, observe: &mut impl FnMut(Event)) {
        if let Some(peer) = &mut self.peers[index] {
            if let Some(mut framed) = peer.framed.take() {
                framed.retire();
                self.accept.client_closed();
                self.report.closed = self.report.closed.saturating_add(1);
                observe(Event::ClientClosed(peer.serial));
            }
            peer.closing = true;
        }
    }
    fn poll_peer(
        &mut self,
        cx: &mut Context<'_>,
        index: usize,
        observe: &mut impl FnMut(Event),
    ) -> Poll<()> {
        if self.peers[index].is_none() {
            return Poll::Pending;
        }
        if self.shutting_down && self.shutdown_mode == ShutdownMode::Immediate {
            self.close_wire(index, observe);
        }
        let ready = {
            let peer = self.peers[index].as_mut().ok_or(());
            match peer {
                Ok(peer) => peer.pending.as_mut().map(|(_, job)| job.poll(cx)),
                Err(()) => None,
            }
        };
        if let Some(Poll::Ready(answer)) = ready {
            let Some(peer) = self.peers[index].as_mut() else {
                return Poll::Ready(());
            };
            let serial = peer.serial;
            let Some((kind, _)) = peer.pending.take() else {
                self.fault(
                    Some(serial),
                    Arc::new(Error::Protocol(ProtocolError::Stale)),
                    observe,
                );
                self.close_wire(index, observe);
                return Poll::Ready(());
            };
            match answer {
                Err(error) => {
                    self.fault(Some(serial), error, observe);
                    self.close_wire(index, observe);
                    if matches!(kind, PendingKind::Attach | PendingKind::Detach) {
                        self.peers[index] = None;
                    } else if let Some(peer) = &mut self.peers[index] {
                        peer.attached = false;
                    }
                }
                Ok(answer) => {
                    if let Some(error) = answer.diagnostic {
                        self.fault(Some(serial), error, observe);
                    }
                    match answer.action {
                        Err(error) => {
                            self.fault(Some(serial), error, observe);
                            self.close_wire(index, observe);
                            if matches!(kind, PendingKind::Attach | PendingKind::Detach) {
                                if matches!(kind, PendingKind::Detach) {
                                    self.request_shutdown(ShutdownMode::Immediate);
                                }
                                self.peers[index] = None;
                            }
                        }
                        Ok(Action::Attached) => {
                            if let Some(peer) = &mut self.peers[index] {
                                peer.attached = true;
                            }
                        }
                        Ok(Action::Detached) => {
                            self.peers[index] = None;
                        }
                        Ok(Action::Reply(frame)) => {
                            if let Some(peer) = &mut self.peers[index]
                                && let Some(framed) = &mut peer.framed
                            {
                                match framed.enqueue_owned(frame, serial, Class::Ordinary) {
                                    Ok(()) => {
                                        self.report.replies = self.report.replies.saturating_add(1)
                                    }
                                    Err(rejected) => {
                                        self.fault(
                                            Some(serial),
                                            Arc::new(Error::Protocol(rejected.reason)),
                                            observe,
                                        );
                                        self.close_wire(index, observe);
                                    }
                                }
                            }
                        }
                        Ok(Action::NoReply) => {}
                        Ok(Action::Maintained | Action::Stopped { .. }) => {
                            self.fault(
                                Some(serial),
                                Arc::new(Error::Protocol(ProtocolError::Stale)),
                                observe,
                            );
                            self.close_wire(index, observe);
                        }
                    }
                }
            }
            return Poll::Ready(());
        }
        let Some(peer) = self.peers[index].as_mut() else {
            return Poll::Pending;
        };
        if peer.closing {
            if peer.pending.is_some() {
                return Poll::Pending;
            }
            if !peer.attached {
                self.peers[index] = None;
                return Poll::Ready(());
            }
            let serial = peer.serial;
            match self.worker.submit(Command::Detach(serial)) {
                Ok(job) => {
                    peer.pending = Some((PendingKind::Detach, job));
                    cx.waker().wake_by_ref();
                }
                Err(error) => {
                    self.fault(Some(serial), error, observe);
                    self.peers[index] = None;
                }
            }
            return Poll::Ready(());
        }
        let Some(framed) = &mut peer.framed else {
            return Poll::Pending;
        };
        match framed.poll_write(cx) {
            Poll::Ready(Ok(progress)) => {
                self.report.written_bytes = self
                    .report
                    .written_bytes
                    .saturating_add(progress.bytes as u64);
                return Poll::Ready(());
            }
            Poll::Ready(Err(error)) => {
                let serial = peer.serial;
                self.fault(Some(serial), Arc::new(Error::Io(error)), observe);
                self.close_wire(index, observe);
                return Poll::Ready(());
            }
            Poll::Pending => {}
        }
        if self.shutting_down && peer.pending.is_none() && framed.queued_frames() == 0 {
            self.close_wire(index, observe);
            return Poll::Ready(());
        }
        if peer.pending.is_none()
            && peer.attached
            && !self.shutting_down
            && framed.queued_frames() == 0
            && framed.frame().is_some()
        {
            let required = framed
                .frame()
                .and_then(|frame| Request::decode(frame).ok())
                .map(gnunet_datastore::required_output)
                .unwrap_or(0);
            if required > 0
                && let Err(error) = framed.reserve(required, Class::Ordinary)
            {
                let serial = peer.serial;
                self.fault(Some(serial), Arc::new(Error::Protocol(error)), observe);
                self.close_wire(index, observe);
                return Poll::Ready(());
            }
            let Some(frame) = framed.frame() else {
                return Poll::Pending;
            };
            let request = match OwnedFrame::copy_from(frame) {
                Ok(frame) => frame,
                Err(error) => {
                    let serial = peer.serial;
                    self.fault(Some(serial), Arc::new(Error::Protocol(error)), observe);
                    self.close_wire(index, observe);
                    return Poll::Ready(());
                }
            };
            match self.worker.submit(Command::Request {
                client: peer.serial,
                frame: request,
                tolerant: self.options.tolerant,
            }) {
                Ok(job) => {
                    peer.pending = Some((PendingKind::Request, job));
                    framed.release_frame();
                    self.report.requests = self.report.requests.saturating_add(1);
                    cx.waker().wake_by_ref();
                }
                Err(error) => {
                    let serial = peer.serial;
                    self.fault(Some(serial), error, observe);
                    self.close_wire(index, observe);
                }
            }
            return Poll::Ready(());
        }
        if framed.frame().is_some() {
            return Poll::Pending;
        }
        match framed.poll_read(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(ReadStep::Progress { .. })) => Poll::Ready(()),
            Poll::Ready(Ok(ReadStep::Eof)) => {
                self.close_wire(index, observe);
                Poll::Ready(())
            }
            Poll::Ready(Err(error)) => {
                let serial = peer.serial;
                self.fault(Some(serial), Arc::new(Error::Io(error)), observe);
                self.close_wire(index, observe);
                Poll::Ready(())
            }
        }
    }
    fn poll_accept(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        observe: &mut impl FnMut(Event),
    ) -> Poll<Progress> {
        if self.shutting_down || !self.accept.ready() {
            return Poll::Pending;
        }
        let Some(slot) = self.peers.iter().position(Option::is_none) else {
            return Poll::Pending;
        };
        for offset in 0..listeners.len() {
            let index = (self.listener_cursor + offset) % listeners.len();
            match listeners[index].poll_canonical_connection(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(error)) => {
                    observe(Event::Socket(self.accept.failed(error)));
                    self.listener_cursor = (index + 1) % listeners.len();
                    return Poll::Ready(Progress::Activity);
                }
                Poll::Ready(Ok(accepted)) => {
                    let address = accepted.peer();
                    let allowed = match address {
                        PeerAddress::Tcp(address) => self.options.access.allows(address.ip()),
                        PeerAddress::Unix => match self.unix.allows(accepted.connection()) {
                            Ok(allowed) => allowed,
                            Err(error) => {
                                self.fault(None, Arc::new(Error::Io(error)), observe);
                                false
                            }
                        },
                    };
                    if !allowed {
                        drop(accepted);
                        observe(Event::Rejected(address));
                        return Poll::Ready(Progress::Activity);
                    }
                    let (connection, _, diagnostics) = accepted.into_parts();
                    for diagnostic in diagnostics {
                        observe(Event::Socket(SocketEvent::Diagnostic(diagnostic)));
                    }
                    let Some(serial) = self.serial.checked_add(1) else {
                        drop(connection);
                        self.fault(
                            None,
                            Arc::new(Error::Protocol(ProtocolError::Overflow)),
                            observe,
                        );
                        self.request_shutdown(ShutdownMode::Immediate);
                        return Poll::Ready(Progress::Activity);
                    };
                    let framed = match Framed::new(connection, self.limits.framing()) {
                        Ok(framed) => framed,
                        Err(error) => {
                            self.fault(None, Arc::new(Error::Protocol(error)), observe);
                            return Poll::Ready(Progress::Activity);
                        }
                    };
                    let pending = match self.worker.submit(Command::Attach(serial)) {
                        Ok(pending) => pending,
                        Err(error) => {
                            drop(framed);
                            self.fault(None, error, observe);
                            return Poll::Ready(Progress::Activity);
                        }
                    };
                    self.serial = serial;
                    self.peers[slot] = Some(Peer {
                        serial,
                        framed: Some(framed),
                        pending: Some((PendingKind::Attach, pending)),
                        attached: false,
                        closing: false,
                    });
                    self.report.accepted = self.report.accepted.saturating_add(1);
                    self.listener_cursor = (index + 1) % listeners.len();
                    cx.waker().wake_by_ref();
                    return Poll::Ready(Progress::Accepted);
                }
            }
        }
        Poll::Pending
    }
    fn poll_management(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<()> {
        if let Some(job) = &mut self.maintenance
            && let Poll::Ready(answer) = job.poll(cx)
        {
            self.maintenance = None;
            match answer {
                Ok(answer) => {
                    if let Some(error) = answer.diagnostic {
                        self.fault(None, error, observe);
                    }
                    if let Err(error) = answer.action {
                        self.fault(None, error, observe);
                    }
                }
                Err(error) => self.fault(None, error, observe),
            }
            if let Some(next) = Instant::now().checked_add(self.limits.maintenance_interval) {
                self.tick.as_mut().reset(next);
            } else {
                self.fault(
                    None,
                    Arc::new(Error::Protocol(ProtocolError::Overflow)),
                    observe,
                );
                self.request_shutdown(ShutdownMode::Immediate);
            }
            return Poll::Ready(());
        }
        if self.shutting_down
            && self.peers.iter().all(Option::is_none)
            && self.maintenance.is_none()
        {
            if self.stop.is_none() {
                match self.worker.submit(Command::Stop) {
                    Ok(job) => self.stop = Some(job),
                    Err(error) => {
                        self.fault(None, error, observe);
                        self.stopped = true;
                        return Poll::Ready(());
                    }
                }
            }
            if let Some(job) = &mut self.stop
                && let Poll::Ready(answer) = job.poll(cx)
            {
                self.stop = None;
                match answer {
                    Ok(answer) => match answer.action {
                        Ok(Action::Stopped { dropped }) => {
                            self.report.dropped_on_shutdown = dropped
                        }
                        Ok(_) => self.fault(
                            None,
                            Arc::new(Error::Protocol(ProtocolError::Stale)),
                            observe,
                        ),
                        Err(error) => {
                            if self.report.failure.is_none() {
                                self.report.failure = Some(error.clone());
                            }
                            self.fault(None, error, observe)
                        }
                    },
                    Err(error) => self.fault(None, error, observe),
                }
                self.stopped = true;
                return Poll::Ready(());
            }
        } else if !self.shutting_down
            && self.maintenance.is_none()
            && self.tick.as_mut().poll(cx).is_ready()
        {
            match self.worker.submit(Command::Maintain) {
                Ok(job) => {
                    self.maintenance = Some(job);
                    cx.waker().wake_by_ref();
                }
                Err(error) => self.fault(None, error, observe),
            }
            return Poll::Ready(());
        }
        Poll::Pending
    }
    fn poll_drive(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        deadline: Option<Instant>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Progress> {
        if self.stopped {
            return Poll::Ready(Progress::Stopped);
        }
        for class_offset in 0..3 {
            let class = (self.class_cursor + class_offset) % 3;
            let ready = match class {
                0 => self.poll_management(cx, observe).map(|()| {
                    if self.stopped {
                        Progress::Stopped
                    } else {
                        Progress::Activity
                    }
                }),
                1 => {
                    let mut result = Poll::Pending;
                    for offset in 0..self.peers.len() {
                        let index = (self.cursor + offset) % self.peers.len();
                        if self.poll_peer(cx, index, observe).is_ready() {
                            self.cursor = (index + 1) % self.peers.len();
                            result = Poll::Ready(Progress::Activity);
                            break;
                        }
                    }
                    result
                }
                _ => self.poll_accept(cx, listeners, observe),
            };
            if let Poll::Ready(progress) = ready {
                self.class_cursor = (class + 1) % 3;
                return Poll::Ready(progress);
            }
        }
        if let Some(deadline) = deadline {
            let timer = self
                .wait
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline)));
            timer.as_mut().reset(deadline);
            if timer.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Progress::WaitDeadline);
            }
        }
        Poll::Pending
    }
    /// Drive original work and real accepted streams. Dropping this wait only
    /// stops observation; it neither cancels a backend mutation nor recreates IO.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        deadline: Option<Instant>,
        mut observe: impl FnMut(Event),
    ) -> Progress {
        poll_fn(|cx| self.poll_drive(cx, listeners, deadline, &mut observe)).await
    }
    /// Close sockets, settle original backend work, apply any requested DROP,
    /// and join the actual worker. This future may be canceled and resumed;
    /// its original worker handle remains owned and no early quiescence is reported.
    pub async fn shutdown(&mut self, mut observe: impl FnMut(Event)) -> Report {
        self.request_shutdown(self.shutdown_mode);
        while self.drive(&[], None, &mut observe).await != Progress::Stopped {}
        if !self.report.worker_quiesced {
            match self.worker.join().await {
                Ok(()) => {}
                Err(error) => {
                    if self.report.failure.is_none() {
                        self.report.failure = Some(error.clone());
                    }
                    self.fault(None, error, &mut observe)
                }
            }
            self.report.worker_quiesced = self.worker.quiesced();
        }
        self.report.clone()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        for peer in self.peers.iter_mut().flatten() {
            if let Some(mut framed) = peer.framed.take() {
                framed.retire();
            }
        }
    }
}
