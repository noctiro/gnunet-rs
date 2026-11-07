//! Bounded native FS service over explicit DATASTORE, signer, index and peer ports.
//!
//! Actual sockets and immutable jobs survive canceled drive waits. There is no
//! search END or per-query wire identifier. A terminal query is released only
//! after its authenticated reply is retained by the original socket queue.
mod admin;
pub mod cadet;
pub mod cadet_server;
/// Non-anonymous FS UBLOCK searches over original DHT GET owners.
pub mod dht;
/// Official CORE FS137/138 GAP source/routing adapter.
pub mod gap;
mod index_worker;
mod local;
/// Deferred construction and bounded direct/GAP provider composition.
pub mod peers;
pub mod ports;
mod provider_failure;
mod routing;
use crate::index::Index;
use gnunet_fs::{
    Content, Location,
    service::{ClientId, LocalResult, Lookup, PeerResult, QueryId, Route, Service, SkipReason},
};
pub use gnunet_service_runtime::credentials::UnixAccess;
use gnunet_service_runtime::{
    accepted::{AcceptState, SocketEvent},
    clock::RuntimeClock,
    framing::{Accounting, Budget, Class, Framed, Limits as FrameLimits, OwnedFrame, ReadStep},
    service::{Listener, PeerAddress, ServiceOptions},
};
use gnunet_types::Error as ProtocolError;
use gnunet_wire::official::{
    AbsoluteTime,
    datastore::{Data, Response as StoreResponse},
    fs::{ClientPut, Request, Response, Search},
    fs_cadet,
};
pub use index_worker::{IndexResolver, Resolution};
use index_worker::{Output, Pending, Task, Worker};
use ports::{LocationSigner, LookupProgress, SignProgress, StorePort};
pub use provider_failure::{FailureScope, ProviderFailure};
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

/// Original native, dependency or protocol refusal; no error creates an FS ACK.
#[derive(Debug)]
pub enum Error {
    /// Actual native socket or thread setup cause.
    Io(io::Error),
    /// Actual native filename expansion refusal before index mutation.
    Configuration(gnunet_config::Error),
    /// Exact official format, authority or bounded-resource classification.
    Protocol(ProtocolError),
    /// Original DATASTORE or PILS cause and its retained outcome.
    Port(ports::Error),
    /// Original persistent-index cause and commit certainty.
    Index(Box<crate::index::Error>),
    /// Original peer-routing provider cause.
    Route(ProviderFailure),
    /// Original index worker channel unexpectedly ended.
    WorkerGone,
    /// Original index worker panicked.
    WorkerPanicked,
}
impl Error {
    /// Whether the original worker or uncertain index storage requires stopping
    /// the containing service rather than retiring only one query/channel.
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        self.fatal()
    }
    fn fatal(&self) -> bool {
        matches!(self, Self::WorkerGone | Self::WorkerPanicked)
            || matches!(self,Self::Index(e) if e.certainty()==gnunet_datastore::backend::Failure::Unknown)
            || matches!(self,Self::Route(e) if e.is_fatal())
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "FS native IO: {e}"),
            Self::Configuration(e) => write!(f, "FS filename: {e}"),
            Self::Protocol(e) => write!(f, "FS service: {e}"),
            Self::Port(e) => write!(f, "FS dependency: {e}"),
            Self::Index(e) => write!(f, "FS index: {e}"),
            Self::Route(e) => write!(f, "FS peer port: {e}"),
            Self::WorkerGone => f.write_str("FS index worker ended"),
            Self::WorkerPanicked => f.write_str("FS index worker panicked"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Configuration(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Port(e) => Some(e),
            Self::Index(e) => Some(e.as_ref()),
            Self::Route(e) => Some(e),
            _ => None,
        }
    }
}
/// Native work/memory bounds, separate from caller-provided pure query slots.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Actual simultaneously retained client sockets.
    pub clients: usize,
    /// Actual simultaneously retained peer-route owners.
    pub route_slots: usize,
    /// Pending blocking index-worker jobs.
    pub index_queue: usize,
    /// Nonzero largest native read/write syscall slice.
    pub io_slice_bytes: usize,
    /// Cadence for explicit local rescan and unavailable-route retry.
    pub rescan_interval: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            clients: 64,
            route_slots: 128,
            index_queue: 16,
            io_slice_bytes: 65535,
            rescan_interval: Duration::from_secs(10),
        }
    }
}
impl Limits {
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
    fn validate(self) -> Result<(), ProtocolError> {
        self.framing().validate()?;
        if self.clients == 0
            || self.index_queue == 0
            || self.index_queue > tokio::sync::Semaphore::MAX_PERMITS
            || self.rescan_interval.is_zero()
            || Instant::now().checked_add(self.rescan_interval).is_none()
        {
            return Err(ProtocolError::InvalidInput);
        }
        Ok(())
    }
}
/// Real original peer-route admission, independent of protocol success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteAdmission {
    /// Provider retained the original query under its explicit bounded policy.
    /// This can include an unadmitted intent waiting for current input; it is
    /// never a native send, peer receipt or successful query result.
    Queued,
    /// No peer effect started. Park this route until an explicit retry.
    Idle,
    /// Provider refused this attempt and retains its original failure/cleanup.
    /// No consumer route is retained, but no-effect is not proven; this result
    /// never authorizes switching providers or replaying the same request.
    Refused,
}
/// Explicit local FS request-planning observations for a peer block delivery.
/// These fields do not occur in FS_CADET_REPLY or FS_PUT peer frames. The provider supplies
/// its original local observations; no default or remote metadata is inferred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalDeliveryMetadata {
    /// Actual local request-plan transmission time, or NEVER when that local
    /// planner records it as unknown/irrelevant under ClientPut semantics.
    pub last_transmission: AbsoluteTime,
    /// Transmission estimate held by the actual local request planner.
    pub num_transmissions: u32,
    /// Respect estimate held by the actual local request planner.
    pub respect_offered: u32,
}
/// One actual provider observation. Route numbers are Rust ownership labels only.
pub enum PeerProgress {
    /// One real bounded provider action, without a fabricated reply.
    Activity,
    /// Actual result bytes encoded as the official local ClientPutMessage.
    Reply {
        /// Original locally admitted route owner.
        route: u64,
        /// Complete actual metadata and block frame.
        frame: OwnedFrame,
    },
    /// Original FS_CADET_REPLY application frame from the admitted route's
    /// actual CADET channel. It carries only block type, expiry and block;
    /// local ClientPut planning fields are supplied explicitly by the provider.
    CadetReply {
        /// Original locally admitted route owner, never a GNUnet wire field.
        route: u64,
        /// Complete original type141 frame, retained unchanged until consumed.
        frame: OwnedFrame,
        /// Original local planning observations, kept apart from the peer frame.
        metadata: LocalDeliveryMetadata,
    },
    /// Exact original FS_PUT138 frame received through real CORE GAP routing.
    /// It contains no local ClientPut planning metadata; these observations are
    /// supplied separately by the original local query planner.
    GapReply {
        /// Original local FS route owner, never an official wire request ID.
        route: u64,
        /// Complete original FS_PUT frame, retained unchanged until consumed.
        frame: OwnedFrame,
        /// Explicit local planner observations, not inferred peer fields.
        metadata: LocalDeliveryMetadata,
    },
    /// This original provider operation ended; FS still emits no END frame.
    Ended(u64),
}
/// Actual local provider shutdown observation, independent of peer receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerShutdown {
    /// Provider has no explicit grace interface and needs physical close.
    /// This is never a claim that its source or output is quiescent.
    Immediate,
    /// Explicit grace was requested and original source/output still drains.
    Draining,
    /// Explicit local original source/output jobs actually settled.
    Quiesced,
    /// Original provider was physically retired; outcomes may remain uncertain.
    Retired,
}
/// Explicit independent FS P2P/CADET/DHT composition port. Implementations own
/// their actual network operations, cancellation, resource bounds and recovery.
pub trait PeerRouter {
    /// Whether original provider construction completed. Ordinary providers are
    /// constructed already; a Deferred slot blocks Server admission until filled.
    fn initialized(&self) -> bool {
        true
    }
    /// Stop fresh provider admission through its explicit grace interface.
    /// The default supports only physical close, with no grace claim.
    fn request_shutdown(&mut self) {}
    /// Read actual local grace state. Existing implementations remain Immediate
    /// until they supply their own explicit source/output lifecycle facts.
    fn shutdown_state(&self) -> PeerShutdown {
        PeerShutdown::Immediate
    }
    /// Retain these exact inputs or return Idle only when no peer effect began.
    /// Refused/Err retain original failure/cleanup and forbid automatic fallback.
    /// `route` is never a private GNUnet wire field; copy retained inputs.
    fn start(
        &mut self,
        route: u64,
        search: Search<'_>,
        seen: &[[u8; 64]],
    ) -> Result<RouteAdmission, ProviderFailure>;
    /// Poll real provider work even when no routes remain. When deliver is
    /// false, retain local, CADET and GAP results while driving IO, timers and
    /// cleanup; return only Activity/Ended/errors. Dropped waits retain jobs.
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        deliver: bool,
    ) -> Poll<Result<PeerProgress, ProviderFailure>>;
    /// One original unadmitted intent now needs current routing input. This
    /// getter performs no IO, allocation or wake; actual provider progress must
    /// establish readiness. It never requests retry of an admitted operation.
    fn input_needed(&self) -> Option<u64> {
        None
    }
    /// Supply the requested original intent with its validated current query
    /// and seen set. This completes only its first admission, without changing
    /// the canonical route identity or replaying another provider's operation.
    fn refresh(
        &mut self,
        _route: u64,
        _search: Search<'_>,
        _seen: &[[u8; 64]],
    ) -> Result<(), ProviderFailure> {
        Err(ProviderFailure::operation(ProtocolError::NotReady))
    }
    /// Retire this local route owner. Late observations cannot gain another owner.
    fn cancel(&mut self, route: u64) -> Result<(), ProviderFailure>;
    /// Close all provider-owned native operations without claiming remote ACKs.
    fn close(&mut self) -> Result<(), ProviderFailure>;
}
/// Explicit zero-connected-peer composition. Local DATASTORE/index/LOC still run;
/// this value provides no P2P implementation or synthetic network result.
#[derive(Default)]
pub struct NoPeers;
impl PeerRouter for NoPeers {
    fn start(
        &mut self,
        _route: u64,
        _search: Search<'_>,
        _seen: &[[u8; 64]],
    ) -> Result<RouteAdmission, ProviderFailure> {
        Ok(RouteAdmission::Idle)
    }
    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
        _deliver: bool,
    ) -> Poll<Result<PeerProgress, ProviderFailure>> {
        Poll::Pending
    }
    fn cancel(&mut self, _route: u64) -> Result<(), ProviderFailure> {
        Ok(())
    }
    fn close(&mut self) -> Result<(), ProviderFailure> {
        Ok(())
    }
}
/// Explicit native dependencies. No hidden Resolver, task or peer is created.
pub struct Ports<S, L, R> {
    /// One original DATASTORE query owner.
    pub datastore: S,
    /// Actual peer identity/signing owner.
    pub signer: L,
    /// Actual caller-selected peer composition, possibly zero connected peers.
    pub peers: R,
    /// Recovered private Rust file index, moved to the blocking worker.
    pub index: Index,
    /// Canonical source UTC shared with the supplied dependency ports.
    pub clock: Arc<dyn RuntimeClock>,
}
/// Original service observations, independent of official reply bytes.
pub enum Event {
    /// Native accept/initialization cause in actual source order.
    Socket(SocketEvent),
    /// Address or kernel-credential admission refused an actual stream.
    Rejected(PeerAddress),
    /// This original physical client socket was closed.
    ClientClosed(u64),
    /// Original dependency/backend/native cause, not a fabricated wire failure.
    Fault {
        /// Original physical client diagnostic, absent for global work.
        client: Option<u64>,
        /// Original owned error and its source chain.
        cause: Arc<Error>,
    },
    /// An actual candidate was invalid, expired or already known.
    Skipped {
        /// Original local query diagnostic.
        query: u64,
        /// Exact skip classification.
        reason: SkipReason,
    },
}
/// Actual native progress only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// A bounded real IO, preparation, backend or cleanup step completed.
    Activity,
    /// An actual canonical client socket was admitted.
    Accepted,
    /// Observation deadline expired, leaving original operations retained.
    WaitDeadline,
    /// Native sockets/ports have closed and original index jobs have settled.
    /// Actual worker join is still required before filesystem quiescence.
    Stopped,
}
/// Actual local counters and original global failure.
#[derive(Clone, Debug, Default)]
pub struct Report {
    /// Actual admitted original sockets.
    pub accepted: u64,
    /// Official Search frames admitted to the pure owner.
    pub searches: u64,
    /// Actual authenticated local replies queued to their original socket.
    pub local_results: u64,
    /// Exact invalid type6 removals confirmed by actual DATASTORE STATUS1.
    pub on_demand_removed: u64,
    /// Best-effort cleanup refusals, interruptions or original native failures.
    pub on_demand_cleanup_failures: u64,
    /// Actual authenticated peer replies queued to their original socket.
    pub peer_results: u64,
    /// Original queued index registration/list/unindex jobs.
    pub index_operations: u64,
    /// Actual completed bounded physical index cleanup slices.
    pub maintenance_steps: u64,
    /// Actual original sockets closed.
    pub closed: u64,
    /// Positive physical write bytes, without processing/availability claims.
    pub written_bytes: u64,
    /// True only after joining this original blocking index worker.
    pub worker_quiesced: bool,
    /// First fatal worker/uncertain-index failure with its actual cause.
    pub failure: Option<Arc<Error>>,
    /// Last actual peer-provider failure, independent of local service health.
    pub peer_failure: Option<Arc<Error>>,
    /// Last actual grace or physical-retirement observation during shutdown.
    /// Retired does not substitute for Quiesced or erase source uncertainty.
    pub peer_shutdown: Option<PeerShutdown>,
}
struct Peer<'id> {
    client: ClientId<'id>,
    framed: Framed<u64>,
    control: bool,
}
#[derive(Clone, Copy)]
enum AdminKind {
    Register,
    Remove,
    List,
}
struct Admin<'id> {
    client: ClientId<'id>,
    kind: AdminKind,
    after: Option<[u8; 64]>,
    pending: Option<Pending>,
    output: Option<Result<Output, Arc<Error>>>,
}
// Service-owned immutable cleanup carries no live FS query authority.
struct Cleanup {
    client: u64,
    frame: OwnedFrame,
    pending: bool,
}
struct LocalPending<'id> {
    lookup: Lookup<'id>,
    frame: OwnedFrame,
    resolve: Option<Pending>,
    resolved: Option<Vec<u8>>,
}
/// Original peer result retained across physical-client backpressure.
/// The variant records its real wire shape without rewriting its raw frame.
enum PeerReply {
    Local(OwnedFrame),
    Cadet {
        frame: OwnedFrame,
        metadata: LocalDeliveryMetadata,
    },
    Gap {
        frame: OwnedFrame,
        metadata: LocalDeliveryMetadata,
    },
}
/// Caller-driven FS sockets, query state and original dependency owners.
/// Index work is serialized on one bounded native thread; no payload collection
/// or list snapshot is buffered. One globally serialized list walks entries in
/// order while excluding index mutations, retaining only its current frame.
pub struct Server<'id, 'slots, 'seen, S: StorePort, L: LocationSigner, R: PeerRouter> {
    peers: Vec<Option<Peer<'id>>>,
    protocol: Service<'id, 'slots, 'seen>,
    store: S,
    signer: L,
    router: R,
    worker: Worker,
    limits: Limits,
    options: ServiceOptions,
    unix: UnixAccess,
    clock: Arc<dyn RuntimeClock>,
    accept: AcceptState,
    cursor: usize,
    listener_cursor: usize,
    class_cursor: u8,
    lookup: Option<Lookup<'id>>,
    local: Option<LocalPending<'id>>,
    cleanup: Option<Cleanup>,
    admin: Option<Admin<'id>>,
    maintenance: Option<Pending>,
    sign_client: Option<ClientId<'id>>,
    signed: Option<Location>,
    routes: Vec<(u64, Route<'id>)>,
    query_scratch: Vec<QueryId<'id>>,
    route_serial: u64,
    peer_reply: Option<(u64, PeerReply)>,
    peer_reply_ended: bool,
    peer_failed: bool,
    peer_shutdown_requested: bool,
    tick: Pin<Box<Sleep>>,
    wait: Option<Pin<Box<Sleep>>>,
    closing: bool,
    ports_closed: bool,
    stopped: bool,
    report: Report,
}
fn bytes(length: usize) -> Result<Vec<u8>, Arc<Error>> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Arc::new(Error::Protocol(ProtocolError::Capacity)))?;
    bytes.resize(length, 0);
    Ok(bytes)
}
fn encode(response: Response<'_>) -> Result<OwnedFrame, Arc<Error>> {
    let n = response
        .encoded_len()
        .map_err(|e| Arc::new(Error::Protocol(e)))?;
    let mut bytes = bytes(n)?;
    response
        .encode(&mut bytes)
        .map_err(|e| Arc::new(Error::Protocol(e)))?;
    Ok(OwnedFrame::new(bytes))
}
impl<'id, 'slots, 'seen, S: StorePort, L: LocationSigner, R: PeerRouter>
    Server<'id, 'slots, 'seen, S, L, R>
{
    /// Retain explicit owners and start only the recovered index worker. No
    /// listener, Resolver, peer identity or network route is invented here.
    pub fn new(
        protocol: Service<'id, 'slots, 'seen>,
        ports: Ports<S, L, R>,
        limits: Limits,
        options: ServiceOptions,
        unix: UnixAccess,
    ) -> Result<Self, Arc<Error>> {
        limits
            .validate()
            .map_err(|e| Arc::new(Error::Protocol(e)))?;
        let mut peers = Vec::new();
        peers
            .try_reserve_exact(limits.clients)
            .map_err(|_| Arc::new(Error::Protocol(ProtocolError::Capacity)))?;
        peers.resize_with(limits.clients, || None);
        let mut routes = Vec::new();
        routes
            .try_reserve_exact(limits.route_slots)
            .map_err(|_| Arc::new(Error::Protocol(ProtocolError::Capacity)))?;
        let next = Instant::now()
            .checked_add(limits.rescan_interval)
            .ok_or_else(|| Arc::new(Error::Protocol(ProtocolError::Overflow)))?;
        let mut query_scratch = Vec::new();
        query_scratch
            .try_reserve_exact(protocol.query_capacity())
            .map_err(|_| Arc::new(Error::Protocol(ProtocolError::Capacity)))?;
        let worker = Worker::start(ports.index, limits.index_queue)?;
        Ok(Self {
            peers,
            protocol,
            store: ports.datastore,
            signer: ports.signer,
            router: ports.peers,
            worker,
            limits,
            options,
            unix,
            clock: ports.clock,
            accept: AcceptState::default(),
            cursor: 0,
            listener_cursor: 0,
            class_cursor: 0,
            lookup: None,
            local: None,
            cleanup: None,
            admin: None,
            maintenance: None,
            sign_client: None,
            signed: None,
            routes,
            query_scratch,
            route_serial: 0,
            peer_reply: None,
            peer_reply_ended: false,
            peer_failed: false,
            peer_shutdown_requested: false,
            tick: Box::pin(tokio::time::sleep_until(next)),
            wait: None,
            closing: false,
            ports_closed: false,
            stopped: false,
            report: Report::default(),
        })
    }
    /// Share readonly type6 resolution through this server's one existing
    /// index worker. The weak port cannot open a second Index/WAL or outlive
    /// shutdown admission. Close external resolution owners before shutdown.
    pub fn on_demand_resolver(&self) -> Result<IndexResolver, Arc<Error>> {
        self.worker.resolver()
    }
    /// Observe the exact original provider. Mutable access remains restricted
    /// to the existing generation-checked recover_peer_router boundary.
    #[must_use]
    pub const fn peer_router(&self) -> &R {
        &self.router
    }
    /// Snapshot of actual work; only shutdown joins the original worker.
    #[must_use]
    pub fn report(&self) -> &Report {
        &self.report
    }
    /// Request physical client/port closure while retaining original index jobs
    /// until actual settlement. No queued registration is replayed on restart.
    pub fn request_shutdown(&mut self) {
        self.closing = true;
        if self.options.shutdown == gnunet_service_runtime::service::ShutdownMode::Soft
            && !self.peer_shutdown_requested
            && !self.peer_failed
        {
            self.router.request_shutdown();
            self.peer_shutdown_requested = true;
            self.report.peer_shutdown = Some(self.router.shutdown_state());
        }
    }
    fn fault(&mut self, client: Option<u64>, cause: Arc<Error>, observe: &mut impl FnMut(Event)) {
        if cause.fatal() {
            if self.report.failure.is_none() {
                self.report.failure = Some(cause.clone());
            }
            self.request_shutdown();
        }
        observe(Event::Fault { client, cause });
    }
    fn peer(&self, client: ClientId<'id>) -> Option<usize> {
        self.peers
            .iter()
            .position(|p| p.as_ref().is_some_and(|p| p.client == client))
    }
    fn live(&self, lookup: Lookup<'id>) -> bool {
        self.peer(lookup.client()).is_some() && self.protocol.descriptor(lookup.query_id()).is_ok()
    }
    fn ready(&self, client: ClientId<'id>) -> bool {
        self.peer(client).is_some_and(|i| {
            self.peers[i]
                .as_ref()
                .is_some_and(|p| p.framed.queued_frames() == 0)
        })
    }
    fn close_peer(&mut self, index: usize, observe: &mut impl FnMut(Event)) {
        let Some(mut peer) = self.peers[index].take() else {
            return;
        };
        peer.framed.retire();
        self.accept.client_closed();
        self.report.closed = self.report.closed.saturating_add(1);
        observe(Event::ClientClosed(peer.client.value()));
        let mut i = 0;
        while i < self.routes.len() {
            if self.routes[i].1.client() == peer.client {
                let (serial, _) = self.routes.swap_remove(i);
                if let Err(e) = self.router.cancel(serial) {
                    self.fault(
                        Some(peer.client.value()),
                        Arc::new(Error::Route(e)),
                        observe,
                    );
                }
            } else {
                i += 1;
            }
        }
        // The shared signer retains/drains the original operation. Closing
        // this FS peer cannot permanently disable signing for other clients.
        if let Err(e) = self.protocol.disconnect(peer.client) {
            self.fault(
                Some(peer.client.value()),
                Arc::new(Error::Protocol(e)),
                observe,
            );
        }
    }
    fn close_client(&mut self, client: ClientId<'id>, observe: &mut impl FnMut(Event)) {
        if let Some(index) = self.peer(client) {
            self.close_peer(index, observe);
        }
    }
    fn queue(&mut self, client: ClientId<'id>, frame: OwnedFrame) -> Result<(), Arc<Error>> {
        let index = self
            .peer(client)
            .ok_or_else(|| Arc::new(Error::Protocol(ProtocolError::Stale)))?;
        let peer = self.peers[index]
            .as_mut()
            .ok_or_else(|| Arc::new(Error::Protocol(ProtocolError::Stale)))?;
        peer.framed
            .enqueue_owned(frame, client.value(), Class::Ordinary)
            .map_err(|r| Arc::new(Error::Protocol(r.reason)))
    }
    fn release_done(
        &mut self,
        query: QueryId<'id>,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Arc<Error>> {
        if !self
            .protocol
            .completed(query)
            .map_err(|e| Arc::new(Error::Protocol(e)))?
        {
            return Ok(());
        }
        let mut i = 0;
        while i < self.routes.len() {
            if self.routes[i].1.query_id() == query {
                let (serial, route) = self.routes.swap_remove(i);
                if let Err(e) = self.router.cancel(serial) {
                    self.fault(
                        Some(route.client().value()),
                        Arc::new(Error::Route(e)),
                        observe,
                    );
                }
            } else {
                i += 1;
            }
        }
        self.protocol
            .release(query)
            .map_err(|e| Arc::new(Error::Protocol(e)))
    }
    fn now(&self) -> Result<AbsoluteTime, Arc<Error>> {
        self.clock
            .sample()
            .map(|s| s.now)
            .map_err(|e| Arc::new(Error::Protocol(e)))
    }
    fn poll_peer(
        &mut self,
        cx: &mut Context<'_>,
        index: usize,
        observe: &mut impl FnMut(Event),
    ) -> Poll<()> {
        let Some(peer) = self.peers[index].as_mut() else {
            return Poll::Pending;
        };
        let client = peer.client;
        match peer.framed.poll_write(cx) {
            Poll::Pending => {}
            Poll::Ready(Ok(progress)) => {
                self.report.written_bytes = self
                    .report
                    .written_bytes
                    .saturating_add(progress.bytes as u64);
                return Poll::Ready(());
            }
            Poll::Ready(Err(e)) => {
                self.fault(Some(client.value()), Arc::new(Error::Io(e)), observe);
                self.close_peer(index, observe);
                return Poll::Ready(());
            }
        }
        // Soft peer/source drain still drives queued client output, but no
        // new FS request can acquire an owner after shutdown starts.
        if self.closing {
            return Poll::Pending;
        }
        if peer.control {
            if peer.framed.frame().is_some() {
                return Poll::Pending;
            }
            return match peer.framed.poll_read(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(ReadStep::Progress { .. })) => Poll::Ready(()),
                Poll::Ready(Ok(ReadStep::Eof)) => {
                    self.close_peer(index, observe);
                    Poll::Ready(())
                }
                Poll::Ready(Err(error)) => {
                    self.fault(Some(client.value()), Arc::new(Error::Io(error)), observe);
                    self.close_peer(index, observe);
                    Poll::Ready(())
                }
            };
        }
        if let Some(frame) = peer.framed.frame() {
            let request = match Request::decode(frame) {
                Ok(r) => r,
                Err(ProtocolError::Unsupported) if self.options.tolerant => {
                    peer.framed.release_frame();
                    return Poll::Ready(());
                }
                Err(e) => {
                    self.fault(Some(client.value()), Arc::new(Error::Protocol(e)), observe);
                    self.close_peer(index, observe);
                    return Poll::Ready(());
                }
            };
            if !matches!(request, Request::Search(_)) && peer.framed.queued_frames() != 0 {
                return Poll::Pending;
            }
            let result = match request {
                Request::Search(search) => self
                    .protocol
                    .admit(client, search)
                    .map(|_| {
                        self.report.searches = self.report.searches.saturating_add(1);
                    })
                    .map_err(|e| Arc::new(Error::Protocol(e))),
                Request::LocSign {
                    expiration,
                    key,
                    query,
                    file_length,
                } => {
                    if self.sign_client.is_some() {
                        return Poll::Pending;
                    }
                    peer.framed
                        .reserve(112, Class::Ordinary)
                        .map_err(|e| Arc::new(Error::Protocol(e)))
                        .and_then(|()| {
                            self.signer
                                .start(
                                    Content {
                                        key,
                                        query,
                                        size: file_length,
                                    },
                                    expiration,
                                )
                                .map_err(|e| Arc::new(Error::Port(e)))
                        })
                        .map(|()| {
                            self.sign_client = Some(client);
                            peer.control = true;
                        })
                }
                Request::IndexStart {
                    device,
                    inode,
                    file_id,
                    filename,
                } => {
                    if self.admin.is_some() {
                        return Poll::Pending;
                    }
                    let mut path = Vec::new();
                    let prepared = path
                        .try_reserve_exact(filename.len())
                        .map_err(|_| Arc::new(Error::Protocol(ProtocolError::Capacity)))
                        .map(|()| path.extend_from_slice(filename))
                        .and_then(|()| {
                            peer.framed
                                .reserve(512, Class::Ordinary)
                                .map_err(|e| Arc::new(Error::Protocol(e)))
                        });
                    prepared
                        .and_then(|()| {
                            self.worker.submit(Task::Register {
                                file_id,
                                filename: path,
                                device,
                                inode,
                            })
                        })
                        .map(|job| {
                            self.admin = Some(Admin {
                                client,
                                kind: AdminKind::Register,
                                after: None,
                                pending: Some(job),
                                output: None,
                            });
                            peer.control = true;
                            self.report.index_operations =
                                self.report.index_operations.saturating_add(1);
                        })
                }
                Request::IndexList => {
                    if self.admin.is_some() {
                        return Poll::Pending;
                    }
                    self.admin = Some(Admin {
                        client,
                        kind: AdminKind::List,
                        after: None,
                        pending: None,
                        output: None,
                    });
                    peer.control = true;
                    Ok(())
                }
                Request::Unindex { file_id } => {
                    if self.admin.is_some() {
                        return Poll::Pending;
                    }
                    peer.framed
                        .reserve(4, Class::Ordinary)
                        .map_err(|e| Arc::new(Error::Protocol(e)))
                        .and_then(|()| self.worker.submit(Task::Remove(file_id)))
                        .map(|job| {
                            self.admin = Some(Admin {
                                client,
                                kind: AdminKind::Remove,
                                after: None,
                                pending: Some(job),
                                output: None,
                            });
                            peer.control = true;
                            self.report.index_operations =
                                self.report.index_operations.saturating_add(1);
                        })
                }
            };
            match result {
                Ok(()) => {
                    if let Some(p) = &mut self.peers[index] {
                        p.framed.release_frame();
                    }
                    cx.waker().wake_by_ref();
                }
                Err(error) => {
                    self.fault(Some(client.value()), error, observe);
                    self.close_peer(index, observe);
                }
            }
            return Poll::Ready(());
        }
        match peer.framed.poll_read(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(ReadStep::Progress { .. })) => Poll::Ready(()),
            Poll::Ready(Ok(ReadStep::Eof)) => {
                self.close_peer(index, observe);
                Poll::Ready(())
            }
            Poll::Ready(Err(e)) => {
                self.fault(Some(client.value()), Arc::new(Error::Io(e)), observe);
                self.close_peer(index, observe);
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
        if self.closing || !self.accept.ready() {
            return Poll::Pending;
        }
        let Some(slot) = self.peers.iter().position(Option::is_none) else {
            return Poll::Pending;
        };
        for offset in 0..listeners.len() {
            let index = (self.listener_cursor + offset) % listeners.len();
            match listeners[index].poll_canonical_connection(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(e)) => {
                    observe(Event::Socket(self.accept.failed(e)));
                    self.listener_cursor = (index + 1) % listeners.len();
                    return Poll::Ready(Progress::Activity);
                }
                Poll::Ready(Ok(accepted)) => {
                    self.listener_cursor = (index + 1) % listeners.len();
                    let address = accepted.peer();
                    let allowed = match address {
                        PeerAddress::Tcp(a) => self.options.access.allows(a.ip()),
                        PeerAddress::Unix => match self.unix.allows(accepted.connection()) {
                            Ok(v) => v,
                            Err(e) => {
                                self.fault(None, Arc::new(Error::Io(e)), observe);
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
                    for d in diagnostics {
                        observe(Event::Socket(SocketEvent::Diagnostic(d)));
                    }
                    let framed = match Framed::new(connection, self.limits.framing()) {
                        Ok(f) => f,
                        Err(e) => {
                            self.fault(None, Arc::new(Error::Protocol(e)), observe);
                            return Poll::Ready(Progress::Activity);
                        }
                    };
                    let client = match self.protocol.connect() {
                        Ok(c) => c,
                        Err(e) => {
                            drop(framed);
                            self.fault(None, Arc::new(Error::Protocol(e)), observe);
                            return Poll::Ready(Progress::Activity);
                        }
                    };
                    self.peers[slot] = Some(Peer {
                        client,
                        framed,
                        control: false,
                    });
                    self.report.accepted = self.report.accepted.saturating_add(1);
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
            && let Poll::Ready(result) = job.poll(cx)
        {
            self.maintenance = None;
            match result {
                Ok(Output::Maintained) => {
                    self.report.maintenance_steps = self.report.maintenance_steps.saturating_add(1)
                }
                Ok(_) => self.fault(
                    None,
                    Arc::new(Error::Protocol(ProtocolError::Malformed)),
                    observe,
                ),
                Err(error) => self.fault(None, error, observe),
            }
            return Poll::Ready(());
        }
        if self.closing {
            self.request_shutdown();
            if !self.ports_closed
                && !self.peer_failed
                && self.options.shutdown == gnunet_service_runtime::service::ShutdownMode::Soft
            {
                let state = self.router.shutdown_state();
                self.report.peer_shutdown = Some(state);
                if state == PeerShutdown::Draining {
                    // poll_drive continues the same original peer/source ports
                    // and worker jobs before returning here on their next wake.
                    return Poll::Pending;
                }
            }
            for i in 0..self.peers.len() {
                self.close_peer(i, observe);
            }
            // Retain an already-admitted exact REMOVE through its finite
            // original deadline. Closing its MQ must not erase uncertainty.
            if self.cleanup.is_some() {
                return Poll::Pending;
            }
            if !self.ports_closed {
                if let Err(e) = self.store.close() {
                    let error = Arc::new(Error::Port(e));
                    if self.report.failure.is_none() {
                        self.report.failure = Some(error.clone());
                    }
                    self.fault(None, error, observe);
                }
                self.signer.close();
                if let Err(e) = self.router.close() {
                    self.report.peer_shutdown = Some(PeerShutdown::Retired);
                    let error = Arc::new(Error::Route(e));
                    if self.report.failure.is_none() {
                        self.report.failure = Some(error.clone());
                    }
                    self.fault(None, error, observe);
                }
                if self.report.peer_shutdown != Some(PeerShutdown::Quiesced) {
                    self.report.peer_shutdown = Some(PeerShutdown::Retired);
                }
                self.lookup = None;
                self.peer_reply = None;
                self.sign_client = None;
                self.signed = None;
                self.routes.clear();
                self.ports_closed = true;
            }
            if self.admin.is_none() && self.local.is_none() && self.maintenance.is_none() {
                self.stopped = true;
                return Poll::Ready(());
            }
            return Poll::Pending;
        }
        if self.tick.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        // Only copy small authorities, never file lists or result payloads.
        let mut ids = std::mem::take(&mut self.query_scratch);
        ids.clear();
        ids.extend(self.protocol.query_ids());
        for query in ids.iter().copied() {
            if !self.routes.iter().any(|(_, r)| r.query_id() == query) {
                match self.protocol.retry_route(query) {
                    Ok(()) | Err(ProtocolError::InvalidInput | ProtocolError::WouldBlock) => {}
                    Err(e) => self.fault(None, Arc::new(Error::Protocol(e)), observe),
                }
            }
            match self.protocol.rescan(query) {
                Ok(()) | Err(ProtocolError::InvalidInput | ProtocolError::WouldBlock) => {}
                Err(e) => self.fault(None, Arc::new(Error::Protocol(e)), observe),
            }
        }
        self.query_scratch = ids;
        if self.maintenance.is_none() {
            match self.worker.submit(Task::CollectGarbage) {
                Ok(job) => {
                    self.maintenance = Some(job);
                    cx.waker().wake_by_ref();
                }
                Err(error) => self.fault(None, error, observe),
            }
        }

        if let Some(next) = Instant::now().checked_add(self.limits.rescan_interval) {
            self.tick.as_mut().reset(next);
        } else {
            self.fault(
                None,
                Arc::new(Error::Protocol(ProtocolError::Overflow)),
                observe,
            );
            self.closing = true;
        }
        Poll::Ready(())
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
        if !self.closing && !self.router.initialized() {
            let error = Arc::new(Error::Protocol(ProtocolError::NotReady));
            if self.report.failure.is_none() {
                self.report.failure = Some(error.clone());
            }
            self.report.peer_failure = Some(error.clone());
            self.fault(None, error, observe);
            self.request_shutdown();
            return Poll::Ready(Progress::Activity);
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Poll::Ready(Progress::WaitDeadline);
        }
        for offset in 0..7 {
            let class = (self.class_cursor + offset) % 7;
            let progress = match class {
                0 => self.poll_management(cx, observe).map(|()| {
                    if self.stopped {
                        Progress::Stopped
                    } else {
                        Progress::Activity
                    }
                }),
                1 => self.poll_store(cx, observe).map(|()| Progress::Activity),
                2 => self.poll_admin(cx, observe).map(|()| Progress::Activity),
                3 => self.poll_sign(cx, observe).map(|()| Progress::Activity),
                4 => self.poll_routes(cx, observe).map(|()| Progress::Activity),
                5 => {
                    let mut ready = Poll::Pending;
                    for offset in 0..self.peers.len() {
                        let i = (self.cursor + offset) % self.peers.len();
                        if self.poll_peer(cx, i, observe).is_ready() {
                            self.cursor = (i + 1) % self.peers.len();
                            ready = Poll::Ready(Progress::Activity);
                            break;
                        }
                    }
                    ready
                }
                _ => self.poll_accept(cx, listeners, observe),
            };
            if let Poll::Ready(p) = progress {
                self.class_cursor = (class + 1) % 7;
                return Poll::Ready(p);
            }
        }
        if let Some(deadline) = deadline {
            let wait = self
                .wait
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline)));
            wait.as_mut().reset(deadline);
            if wait.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Progress::WaitDeadline);
            }
        }
        Poll::Pending
    }
    /// Drive a bounded actual step. Dropping this wait retains original partial
    /// IO, DATASTORE query, signer operation, index job and queued reply bytes.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        deadline: Option<Instant>,
        mut observe: impl FnMut(Event),
    ) -> Progress {
        poll_fn(|cx| self.poll_drive(cx, listeners, deadline, &mut observe)).await
    }
    /// Physically close clients/dependency ports, settle original index work and
    /// join this worker. Canceling and resuming this future retains its true join.
    pub async fn shutdown(&mut self, mut observe: impl FnMut(Event)) -> Report {
        self.request_shutdown();
        while self.drive(&[], None, &mut observe).await != Progress::Stopped {}
        if !self.report.worker_quiesced {
            if let Err(e) = self.worker.join().await {
                if self.report.failure.is_none() {
                    self.report.failure = Some(e.clone());
                }
                self.fault(None, e, &mut observe);
            }
            self.report.worker_quiesced = self.worker.quiesced();
        }
        self.report.clone()
    }
}
impl<S: StorePort, L: LocationSigner, R: PeerRouter> Drop for Server<'_, '_, '_, S, L, R> {
    fn drop(&mut self) {
        for peer in self.peers.iter_mut().flatten() {
            peer.framed.retire();
        }
        let _store = self.store.close();
        self.signer.close();
        let _peers = self.router.close();
    }
}
