//! Actual caller-driven CORE FS137/138/139 and shared-source GAP composition.
//! No resolver, datastore worker/WAL, task, thread, private wire or peer ACK is created.
pub mod storage;
use super::{
    LocalDeliveryMetadata, PeerProgress, PeerRouter, ProviderFailure, RouteAdmission,
    cadet_server::source,
};
use gnunet_core_client_host::{
    self as core, Client, ConnectionEpoch, Inbound, Message, OwnedTraffic, PayloadState, Peer,
    Progress, SendId,
};
use gnunet_fs::gap::{self as pure, Destination};
use gnunet_service_runtime::{
    clock::{Deadline, RuntimeClock},
    framing::OwnedFrame,
};
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use gnunet_wire::official::{
    Frame,
    core::{ClassOrder, Direction, SEND_PREFIX},
    fs::{BlockType, SEARCH_LOOPBACK_ONLY, Search},
    fs_gap::{Get, MigrationStop, Put},
    message_type as mt,
};
use std::{
    collections::VecDeque,
    error::Error as StdError,
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};
type Failure = Box<dyn StdError + Send + Sync>;
/// Exactly the official FS CORE subscriptions, without CADET or DHT messages.
pub const MESSAGE_TYPES: [u16; 3] = [137, 138, 139];
/// Actual local composition fault; original independent causes are preserved.
#[derive(Debug)]
pub enum Error {
    /// Native original CORE/CLIENT refusal.
    Core(core::Error),
    /// Actual bounded-resource/protocol/clock refusal.
    Protocol(ProtocolError),
    /// Original source/worker cause retaining its producer-selected scope.
    Source(source::Failure),
    /// The configured provider could not be constructed. This containing
    /// lifecycle fails even when its original factory refusal was operation-local.
    SourceInitialization(source::Failure),
    /// Actual permanent dependency retirement, independent of its error category.
    SourceUnavailable(source::Failure),
    /// Permanent explicit cache/replication port or original uncertain effect.
    Storage(Failure),
    /// Actual fatal original source terminal after its channel/query retired.
    RetiredSource(Box<source::Retired>),
    /// Original rejected row carrying a producer-selected shared-source failure.
    RejectedSource(Box<source::RejectedRecord>),
    /// Original operation/driver fault plus independent explicit physical close.
    Retirement {
        /// Actual original cause, retaining its exact source uncertainty.
        cause: Box<Error>,
        /// Independent close/drain failure.
        cleanup: Box<Error>,
    },
    /// Independent explicit close failures, neither replacing the other.
    Cleanup {
        /// Original native close/drain failure.
        core: Option<Failure>,
        /// Original local source physical close failure.
        source: Option<source::Failure>,
        /// Independent original local privacy-claim retirement refusal.
        policy: Option<Failure>,
        /// Independent explicit storage/control/source retirement refusal.
        storage: Option<Failure>,
    },
}
impl Error {
    /// Preserve this concrete owner's original failure classification at the
    /// peer-port boundary, before a caller wraps its concrete diagnostic cause.
    #[must_use]
    pub fn into_provider_failure(self) -> ProviderFailure {
        let scope = if self.is_fatal() {
            super::FailureScope::Service
        } else {
            super::FailureScope::Operation
        };
        ProviderFailure::new(Box::new(self), scope)
    }
    /// An actual permanent source failure or original fatal/Unknown worker cause
    /// requires the containing FS service's controlled shutdown. Ordinary row,
    /// source-file, capacity and transient CORE failures do not enter Source.
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        match self {
            Self::Source(cause) => cause.is_fatal(),
            Self::SourceInitialization(_) | Self::SourceUnavailable(_) | Self::Storage(_) => true,
            Self::RetiredSource(retired) => retired.cause().is_some_and(source::Failure::is_fatal),
            Self::RejectedSource(record) => record.cause().is_fatal(),
            Self::Retirement { cause, cleanup } => cause.is_fatal() || cleanup.is_fatal(),
            Self::Cleanup {
                storage: Some(_), ..
            } => true,
            Self::Cleanup {
                source: Some(cause),
                ..
            } => cause.is_fatal(),
            _ => false,
        }
    }
}
impl From<core::Error> for Error {
    fn from(e: core::Error) -> Self {
        Self::Core(e)
    }
}
impl From<ProtocolError> for Error {
    fn from(e: ProtocolError) -> Self {
        Self::Protocol(e)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FS GAP {self:?}")
    }
}
impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Core(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Source(e) | Self::SourceInitialization(e) | Self::SourceUnavailable(e) => Some(e),
            Self::Storage(e) => Some(e.as_ref()),
            Self::RetiredSource(e) => e.cause().map(|e| e as &(dyn StdError + 'static)),
            Self::RejectedSource(e) => Some(e.cause()),
            Self::Retirement { cause, .. } => Some(cause.as_ref()),
            Self::Cleanup {
                core,
                source,
                policy,
                storage,
            } => core
                .as_ref()
                .map(|e| e.as_ref() as &(dyn StdError + 'static))
                .or_else(|| source.as_ref().map(|e| e as &(dyn StdError + 'static)))
                .or_else(|| {
                    policy
                        .as_ref()
                        .map(|e| e.as_ref() as &(dyn StdError + 'static))
                })
                .or_else(|| {
                    storage
                        .as_ref()
                        .map(|e| e.as_ref() as &(dyn StdError + 'static))
                }),
        }
    }
}
/// Explicit finite host scheduling/source/native bounds.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Bounded local FS consumer owners, including their pending Ended notices.
    pub local_routes: usize,
    /// Actual current/waiting/retiring CORE generations; at least P+native.sends.
    pub peer_records: usize,
    /// Complete owned incoming CORE packets awaiting one-inner-frame processing.
    pub packets: usize,
    /// Original local query wait, using the same source clock as CORE.
    pub query_timeout: Duration,
    /// Finite original send wait; a timed-out partial frame physically retires
    /// its whole original MQ and reports uncertainty instead of replaying it.
    pub send_timeout: Duration,
    /// Actual local offered GAP priority; no remote metadata is inferred.
    pub priority: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            local_routes: 128,
            peer_records: 96,
            packets: 4,
            query_timeout: Duration::from_secs(30),
            send_timeout: Duration::from_secs(10),
            priority: 32,
        }
    }
}
/// One actual immutable native completion retained for caller observation.
pub struct Completion<'c> {
    /// Original physical byte state, absent only for an
    /// immediate cancel whose native API proves no payload byte was sent.
    pub payload: Option<PayloadState<'c>>,
    /// Exact original operation.
    pub send: SendId<'c>,
    /// Actual terminal native outcome, not remote delivery.
    pub outcome: core::SendOutcome,
    /// Returned exact original source allocation.
    pub source: Message,
}
/// One original packet rejected under the explicit finite ingress policy.
pub struct IngressRefusal<'c> {
    /// Original service MQ.
    pub epoch: ConnectionEpoch<'c>,
    /// Original actual announced peer generation.
    pub peer: Peer<'c>,
    /// Original inner-frame offset at refusal.
    pub cursor: usize,
    /// Actual local refusal, not a peer negative/ACK.
    pub cause: ProtocolError,
    original: Message,
}
impl IngressRefusal<'_> {
    /// Exact original packet, retained separately from diagnostics.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.original.as_ref()
    }
}
/// Actual source-policy category for a locally retired unadmitted positive.
#[derive(Clone, Copy, Debug)]
pub enum PrivacySource {
    /// Actual local DATASTORE field, including descriptor resolution metadata.
    Local {
        /// Original publisher/source anonymity.
        anonymity: u32,
    },
    /// Original peer source carried no numeric anonymity value.
    PeerUnknown {
        /// Actual original CORE local-loopback indication.
        is_local: bool,
    },
    /// No original local source policy was provided.
    Unspecified,
}
/// One explicit local policy timeout, preserving the exact retained positive.
/// A peer source preserves its received138; a local source is the canonical138
/// composed from actual DATASTORE kind/expiration/value. It is never labeled
/// as the original local DATA frame. Diagnostic labels grant no new route/peer
/// authority or wire negative.
pub struct PrivacyRetired {
    /// Original actual type/key selection.
    pub selection: pure::Selection,
    /// Original logical route diagnostic, never a wire request ID.
    pub route: u64,
    /// Original reverse path diagnostic.
    pub path: u64,
    /// Original per-route result diagnostic.
    pub result: u64,
    /// Actual original connected destination public identity.
    pub target: [u8; 32],
    /// Actual original source metadata category.
    pub source: PrivacySource,
    /// Actual last restriction before local retirement.
    pub reason: pure::privacy::WaitReason,
    /// Original source-clock observation of this local retirement.
    pub at: AbsoluteTime,
    /// Exact retained138: original peer input, or canonical local-source PUT.
    /// Its provenance is explicit in source; no DATA UID or metadata is invented.
    pub frame: OwnedFrame,
}
impl fmt::Debug for PrivacyRetired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivacyRetired")
            .field("selection", &self.selection)
            .field("route", &self.route)
            .field("path", &self.path)
            .field("result", &self.result)
            .field("target", &self.target)
            .field("source", &self.source)
            .field("reason", &self.reason)
            .field("at", &self.at)
            .field("frame_bytes", &self.frame.len())
            .finish()
    }
}
/// Bounded actual observations. Only first diagnostics/latest native completion
/// are retained; counters include all events and never claim remote processing.
#[derive(Default)]
pub struct Report<'c> {
    /// Original intents retained with no peer, timer, source or native effect.
    pub initial_deferred: u64,
    /// Those intents actually admitted as local GAP routes after current-input
    /// refresh. This is not a CORE payload write or peer completion.
    pub initial_activations: u64,
    /// Actual ingress refusal count.
    pub ingress_refused: u64,
    /// First original owned refused packet.
    pub first_ingress_refusal: Option<IngressRefusal<'c>>,
    /// Actual source rejections.
    pub records_rejected: u64,
    /// First raw source-row refusal, including original cause.
    pub first_source_record: Option<source::RejectedRecord>,
    /// Actual ordinary source failures.
    pub source_failures: u64,
    /// Actual nonterminal signed source items observed, never a peer receipt.
    pub source_items: u64,
    /// Actual completed source items whose original local route retired.
    pub source_items_retired: u64,
    /// First exact source block completed before its local consumer retired.
    pub first_source_item_retired: Option<source::Block>,
    /// First original nonfatal source failure.
    pub first_source_failure: Option<source::Failure>,
    /// First explicit retired source terminal.
    pub first_source_retired: Option<source::Retired>,
    /// First actual source block refused after its original terminal.
    pub first_source_block_refusal: Option<source::Block>,
    /// Actual CORE losses.
    pub losses: u64,
    /// Latest actual CORE source cause.
    pub last_loss: Option<core::LossCause>,
    /// Actual source configuration unavailable events.
    pub unavailable: u64,
    /// Latest original endpoint/configuration-unavailable cause.
    pub last_unavailable: Option<core::Error>,
    /// Actual original connect-attempt failures, retaining the latest errno.
    pub connect_retries: u64,
    /// Latest original socket-attempt cause.
    pub last_connect_error: Option<std::io::Error>,
    /// Latest retained native capacity refusal's original physical epoch.
    pub last_capacity: Option<ConnectionEpoch<'c>>,
    /// Native original completions.
    pub completions: u64,
    /// Latest actual immutable completion/source.
    pub last_completion: Option<Completion<'c>>,
    /// Explicit unsupported local requests.
    pub unsupported: u64,
    /// Local query wait expirations, not absence proofs.
    pub timeouts: u64,
    /// Partial send timeouts that retired the original MQ.
    pub partial_timeouts: u64,
    /// Actual migration-stop controls observed, without migration.
    pub migration_stops: u64,
    /// Actual original outputs retired after their cover-evidence time changed.
    pub policy_time_retirements: u64,
    /// Actual unadmitted peer positives locally retired at their policy bound.
    pub privacy_expired: u64,
    /// First exact original positive and source facts from such a retirement.
    pub first_privacy_expired: Option<PrivacyRetired>,
    /// Original source selection physically closed before observed terminal.
    pub forced_source: Option<source::Selection>,
}
#[derive(Clone, Copy)]
struct PeerRecord<'c, 'g> {
    epoch: ConnectionEpoch<'c>,
    peer: Peer<'c>,
    neighbor: Option<pure::Neighbor<'g>>,
    live: bool,
    local: bool,
}
struct Packet<'c> {
    epoch: ConnectionEpoch<'c>,
    peer: Peer<'c>,
    original: Message,
    cursor: usize,
}
struct Local<'g> {
    serial: u64,
    route: pure::Route<'g>,
    path: pure::Path<'g>,
    deadline: Option<Deadline>,
    active: bool,
    end: bool,
}
#[derive(Clone, Copy)]
struct DeferredInitial {
    serial: u64,
    search: Search<'static>,
    ready: bool,
    end: bool,
}
impl DeferredInitial {
    fn matches(self, search: Search<'_>) -> bool {
        self.search.options == search.options
            && self.search.block_type == search.block_type
            && self.search.anonymity == search.anonymity
            && self.search.target == search.target
            && self.search.query == search.query
    }
}
struct Plan<'g> {
    route: pure::Route<'g>,
    metadata: LocalDeliveryMetadata,
}
impl<'g> Plan<'g> {
    fn new(route: pure::Route<'g>) -> Self {
        // Explicit original local plan: no actual GAP GET full write was observed.
        // NEVER/0/0 are local unused observations, never fields taken from PUT138.
        Self {
            route,
            metadata: LocalDeliveryMetadata {
                last_transmission: AbsoluteTime::NEVER,
                num_transmissions: 0,
                respect_offered: 0,
            },
        }
    }
}
struct Sending<'c, 'g> {
    tx: pure::Transmit<'g>,
    route: pure::Route<'g>,
    neighbor: pure::Neighbor<'g>,
    epoch: ConnectionEpoch<'c>,
    peer: Peer<'c>,
    send: Option<SendId<'c>>,
    message: Option<Message>,
    deadline: Option<Deadline>,
    query: bool,
    priority: u32,
    written: usize,
    total: usize,
    exposed: bool,
    plan_recorded: bool,
    canceling: bool,
    permit: pure::privacy::Permit<'g>,
    privacy_retiring: bool,
}
struct SourceItem {
    block: source::Block,
    terminal: bool,
}
/// Native FS GAP peer router and inbound serving owner. Supply the pure owner's
/// caller buffers/brand and one real BlockSource created against the exact clock
/// passed to source_factory. In particular reuse LocalServer.on_demand_resolver;
/// this adapter never creates another index owner, resolver or blocking worker.
pub struct Router<
    'c,
    'g,
    'slots,
    'bytes,
    S: source::BlockSource,
    E: pure::Entropy,
    const P: usize = 64,
    const N: usize = 32,
> {
    native: Client<'c, P, N>,
    gap: pure::Router<'g, 'slots, 'bytes>,
    privacy: pure::privacy::Policy<'g, 'slots>,
    privacy_timer: Option<(u64, Deadline)>,
    storage: Option<storage::Driver<'g, 'slots, 'bytes>>,
    storage_timer: Option<(u64, Deadline)>,
    storage_retirement_error: Option<Failure>,
    control: Option<storage::Control<'c, 'g>>,
    control_turn: bool,
    source: S,
    entropy: E,
    clock: Arc<dyn RuntimeClock>,
    peers: Vec<PeerRecord<'c, 'g>>,
    packets: VecDeque<Packet<'c>>,
    locals: Vec<Local<'g>>,
    initial: Vec<DeferredInitial>,
    initial_cursor: usize,
    plans: Vec<Plan<'g>>,
    job: Option<pure::Lookup<'g>>,
    source_item: Option<SourceItem>,
    source_paused: bool,
    source_sweep_failed: bool,
    source_terminal_observed: bool,
    send: Option<Sending<'c, 'g>>,
    epoch: Option<ConnectionEpoch<'c>>,
    limits: Limits,
    last_route: u64,
    round: u8,
    route_cursor: usize,
    return_cursor: usize,
    peer_cursor: usize,
    stopping: bool,
    closed: bool,
    last_now: u64,
    maintenance: Option<(u64, Deadline)>,
    report: Report<'c>,
}
impl<
    'c,
    'g,
    'slots,
    'bytes,
    S: source::BlockSource,
    E: pure::Entropy,
    const P: usize,
    const N: usize,
> Router<'c, 'g, 'slots, 'bytes, S, E, P, N>
{
    /// Construct the real CORE client with exactly137/138/139 and no traffic
    /// observation flags. Source factory receives the same native source clock.
    #[expect(
        clippy::too_many_arguments,
        reason = "Explicit CORE source, pure caller storage, shared source factory and entropy are independent ports"
    )]
    pub fn new(
        instance: &'c mut core::Instance,
        endpoint: core::EndpointSource,
        order: ClassOrder,
        native_limits: core::Limits,
        gap: pure::Router<'g, 'slots, 'bytes>,
        privacy: pure::privacy::Policy<'g, 'slots>,
        source_factory: impl FnOnce(Arc<dyn RuntimeClock>) -> Result<S, source::Failure>,
        entropy: E,
        limits: Limits,
    ) -> Result<Self, Error> {
        if gap.routes().next().is_some()
            || gap.neighbors().next().is_some()
            || gap.pending_send().is_some()
            || privacy.pending().is_some()
            || privacy.credits().next().is_some()
            || privacy.intents().next().is_some()
        {
            return Err(ProtocolError::Conflict.into());
        }
        if limits.local_routes == 0
            || limits.packets == 0
            || limits.peer_records
                < P.checked_add(native_limits.sends)
                    .ok_or(ProtocolError::Capacity)?
            || limits.query_timeout.is_zero()
            || limits.send_timeout.is_zero()
        {
            return Err(ProtocolError::InvalidInput.into());
        }
        let native = Client::new(instance, endpoint, order, 0, &MESSAGE_TYPES, native_limits)?;
        let clock = native.clock();
        // Construction cannot leave the configured provider partly available.
        // Retain the factory's original scope inside a distinct lifecycle fault;
        // ordinary source observations below do not receive this promotion.
        let source = source_factory(clock.clone()).map_err(Error::SourceInitialization)?;
        let mut peers = Vec::new();
        peers
            .try_reserve_exact(limits.peer_records)
            .map_err(|_| ProtocolError::Capacity)?;
        let mut packets = VecDeque::new();
        packets
            .try_reserve_exact(limits.packets)
            .map_err(|_| ProtocolError::Capacity)?;
        let mut locals = Vec::new();
        locals
            .try_reserve_exact(limits.local_routes)
            .map_err(|_| ProtocolError::Capacity)?;
        let mut initial = Vec::new();
        initial
            .try_reserve_exact(limits.local_routes)
            .map_err(|_| ProtocolError::Capacity)?;
        let mut plans = Vec::new();
        plans
            .try_reserve_exact(gap.route_capacity())
            .map_err(|_| ProtocolError::Capacity)?;
        Ok(Self {
            native,
            gap,
            privacy,
            privacy_timer: None,
            storage: None,
            storage_timer: None,
            storage_retirement_error: None,
            control: None,
            control_turn: true,
            source,
            entropy,
            clock,
            peers,
            packets,
            locals,
            initial,
            initial_cursor: 0,
            plans,
            job: None,
            source_item: None,
            source_paused: false,
            source_sweep_failed: false,
            source_terminal_observed: false,
            send: None,
            epoch: None,
            limits,
            last_route: 0,
            round: 0,
            route_cursor: 0,
            return_cursor: 0,
            peer_cursor: 0,
            stopping: false,
            closed: false,
            last_now: 0,
            maintenance: None,
            report: Report::default(),
        })
    }
    /// Read actual cover/intent/claim observations. These are local FS/CORE
    /// handoff facts and do not assert peer processing or statistical anonymity.
    #[must_use]
    pub const fn privacy(&self) -> &pure::privacy::Policy<'g, 'slots> {
        &self.privacy
    }
    /// Same actual source clock; no new listener or alternate clock is created.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    /// Actual current remote peers; actual CORE self-loopback is excluded.
    #[must_use]
    pub fn connected_peers(&self) -> usize {
        self.peers
            .iter()
            .filter(|p| p.live && !p.local && p.neighbor.is_some())
            .count()
    }
    /// Bounded original observations; no IO/credit is produced by reading them.
    #[must_use]
    pub const fn report(&self) -> &Report<'c> {
        &self.report
    }
    /// Original positives held for the FS local-consumer delivery gate.
    #[must_use]
    pub fn retained_results(&self) -> usize {
        self.locals
            .iter()
            .filter(|l| l.active && self.gap.local_result(l.path).is_ok_and(|v| v.is_some()))
            .count()
    }
    fn wake_initial(&mut self) {
        for original in &mut self.initial {
            if !original.end {
                original.ready = true;
            }
        }
    }
    fn initial_needed(&self) -> Option<u64> {
        if self.closed || self.stopping || self.connected_peers() == 0 {
            return None;
        }
        (0..self.initial.len()).find_map(|offset| {
            let original = self.initial[(self.initial_cursor + offset) % self.initial.len()];
            (original.ready && !original.end).then_some(original.serial)
        })
    }
    fn refresh_initial(
        &mut self,
        serial: u64,
        search: Search<'_>,
        seen: &[[u8; 64]],
    ) -> Result<(), Error> {
        if self.closed || self.stopping {
            return Err(ProtocolError::Closed.into());
        }
        let index = self
            .initial
            .iter()
            .position(|r| r.serial == serial)
            .ok_or(ProtocolError::StaleGeneration)?;
        let original = self.initial[index];
        if original.end || !original.ready || !original.matches(search) {
            return Err(ProtocolError::StaleGeneration.into());
        }
        search.validate()?;
        self.initial[index].ready = false;
        self.initial_cursor = (index + 1) % self.initial.len();
        if self.connected_peers() == 0 {
            return Ok(());
        }
        if matches!(search.block_type, BlockType::DBLOCK | BlockType::IBLOCK)
            && seen.contains(&search.query)
        {
            self.initial[index].end = true;
            return Ok(());
        }
        // Only this exact unadmitted reservation authorizes its old serial.
        // last_route remains the original global high-water mark, even if a
        // newer query was admitted before this first activation.
        match self.admit_ready(serial, search, seen)? {
            RouteAdmission::Queued => {
                self.initial.swap_remove(index);
                self.initial_cursor %= self.initial.len().max(1);
                self.report.initial_activations = self.report.initial_activations.saturating_add(1);
            }
            RouteAdmission::Idle => {
                // No effect, no new timer and no ready loop. A real peer attach
                // or pure route collection wakes the bounded waiting set again.
            }
            RouteAdmission::Refused => self.initial[index].end = true,
        }
        Ok(())
    }
    fn ensure_plan(&mut self, route: pure::Route<'g>) -> Result<(), Error> {
        if self.plans.iter().any(|p| p.route == route) {
            return Ok(());
        }
        if self.plans.len() == self.gap.route_capacity() {
            return Err(ProtocolError::Capacity.into());
        }
        self.plans.push(Plan::new(route));
        Ok(())
    }
    fn end(&mut self, index: usize) -> Result<(), Error> {
        let l = &mut self.locals[index];
        if l.active {
            self.gap.cancel(l.path)?;
            self.privacy
                .retain_intents(|r| self.gap.requirement_current(r));
            l.active = false;
            l.end = true;
            l.deadline = None;
        }
        Ok(())
    }
    fn lose_local_routes(&mut self) -> Result<(), Error> {
        for i in 0..self.locals.len() {
            if self.locals[i].active && self.gap.local_result(self.locals[i].path)?.is_none() {
                self.end(i)?;
            } else if self.locals[i].active {
                self.locals[i].deadline = None;
            }
        }
        Ok(())
    }
    fn add_peer(
        &mut self,
        epoch: ConnectionEpoch<'c>,
        peer: Peer<'c>,
        local: bool,
    ) -> Result<(), Error> {
        if self
            .peers
            .iter()
            .any(|p| p.epoch == epoch && p.peer == peer)
        {
            return Ok(());
        }
        if self.peers.len() == self.limits.peer_records {
            return Err(ProtocolError::Capacity.into());
        }
        self.peers.push(PeerRecord {
            epoch,
            peer,
            neighbor: None,
            live: true,
            local,
        });
        Ok(())
    }
    fn peer_maintenance(&mut self) -> Result<bool, Error> {
        let mut changed = false;
        let mut i = 0;
        while i < self.peers.len() {
            let p = self.peers[i];
            if !p.live
                && !self
                    .send
                    .as_ref()
                    .is_some_and(|s| s.epoch == p.epoch && s.peer == p.peer)
            {
                if let Some(n) = p.neighbor {
                    self.privacy.retire_neighbor(n);
                    if !p.local
                        && let Some(storage) = &mut self.storage
                    {
                        storage.disconnect(n)?;
                    }
                    let _actual_loss = self.gap.disconnect(n)?;
                }
                self.peers.swap_remove(i);
                changed = true;
                continue;
            }
            if p.live
                && p.neighbor.is_none()
                && self.epoch == Some(p.epoch)
                && self.native.peer(p.peer.identity()) == Some(p.peer)
                && !self
                    .peers
                    .iter()
                    .any(|old| old.peer.identity() == p.peer.identity() && old.neighbor.is_some())
            {
                match self.gap.attach(p.peer.identity().0) {
                    Ok(n) => {
                        self.peers[i].neighbor = Some(n);
                        if !p.local
                            && let Some(storage) = &mut self.storage
                        {
                            storage.attach(n, p.peer.identity().0)?;
                        }
                        if !p.local {
                            self.wake_initial();
                        }
                        changed = true;
                    }
                    Err(ProtocolError::Capacity) => {}
                    Err(e) => return Err(e.into()),
                }
            }
            i += 1;
        }
        Ok(changed)
    }
    fn refuse_packet(&mut self, p: Packet<'c>, cause: ProtocolError) {
        self.report.ingress_refused = self.report.ingress_refused.saturating_add(1);
        if self.report.first_ingress_refusal.is_none() {
            self.report.first_ingress_refusal = Some(IngressRefusal {
                epoch: p.epoch,
                peer: p.peer,
                cursor: p.cursor,
                cause,
                original: p.original,
            });
        }
    }
    fn input(&mut self, now: u64) -> Result<bool, Error> {
        let Some(mut p) = self.packets.pop_front() else {
            return Ok(false);
        };
        let current = self
            .peers
            .iter()
            .copied()
            .find(|s| s.live && s.epoch == p.epoch && s.peer == p.peer);
        let Some(current) = current else {
            self.refuse_packet(p, ProtocolError::StaleGeneration);
            return Ok(true);
        };
        let Some(neighbor) = current.neighbor else {
            // Preserve this exact announced CORE generation while its old
            // same-PID original send drains; do not bind by raw identity.
            self.packets.push_back(p);
            return Ok(false);
        };
        let outcome = (|| {
            let bytes = &p.original.as_ref()[p.cursor..];
            let (frame, _) = Frame::decode_prefix(bytes)?;
            let length = frame.encoded_len();
            let bytes = &bytes[..length];
            match frame.header().message_type() {
                t if t == mt::FS_GET => {
                    let admitted = self.gap.receive_get_from(
                        neighbor,
                        bytes,
                        now,
                        &mut self.entropy,
                        current.local,
                    )?;
                    self.ensure_plan(admitted.route).map_err(|e| match e {
                        Error::Protocol(e) => e,
                        _ => ProtocolError::Conflict,
                    })?;
                }
                t if t == mt::FS_PUT => {
                    let checked = pure::CheckedPut::decode(bytes)?;
                    let interest = self.gap.cache_interest_checked(checked)?;
                    self.gap
                        .receive_put_checked(neighbor, checked, current.local)?;
                    if !current.local
                        && let Some(storage) = &mut self.storage
                    {
                        storage.receive(neighbor, checked, interest, now)?;
                    }
                }
                t if t == mt::FS_MIGRATION_STOP => {
                    let message = MigrationStop::decode(bytes)?;
                    if !current.local
                        && let Some(storage) = &mut self.storage
                    {
                        storage.pause(neighbor, message, now)?;
                    }
                    self.report.migration_stops = self.report.migration_stops.saturating_add(1);
                }
                _ => return Err(ProtocolError::Unsupported),
            }
            Ok::<_, ProtocolError>(length)
        })();
        match outcome {
            Ok(length) => {
                p.cursor += length;
                if p.cursor < p.original.as_ref().len() {
                    self.packets.push_front(p);
                }
            }
            Err(ProtocolError::WouldBlock) => {
                self.packets.push_front(p);
                return Ok(false);
            }
            Err(cause) => self.refuse_packet(p, cause),
        }
        Ok(true)
    }
    fn source_failure(
        &mut self,
        route: pure::Route<'g>,
        cause: source::Failure,
        unavailable: bool,
    ) -> Result<(), Error> {
        self.gap.source_failed(route)?;
        self.report.source_failures = self.report.source_failures.saturating_add(1);
        if unavailable {
            self.request_shutdown();
            return Err(Error::SourceUnavailable(cause));
        }
        if cause.is_fatal() {
            self.request_shutdown();
            return Err(Error::Source(cause));
        }
        if self.report.first_source_failure.is_none() {
            self.report.first_source_failure = Some(cause);
        }
        Ok(())
    }
    fn accept_source_item(
        &mut self,
        job: pure::Lookup<'g>,
        item: SourceItem,
    ) -> Result<bool, Error> {
        let result = (|| {
            let data = item.block.data()?;
            let put = Put {
                block_type: BlockType::new(data.kind),
                expiration: data.expiration,
                block: data.value,
            };
            let size = put.encoded_len()?;
            let mut wire = Vec::new();
            wire.try_reserve_exact(size)
                .map_err(|_| ProtocolError::Capacity)?;
            wire.resize(size, 0);
            put.encode(&mut wire)?;
            if item.terminal {
                self.gap
                    .source_finished_local(job.route, Some(&wire), data.anonymity)
            } else {
                self.gap
                    .source_result_local(job.route, &wire, data.anonymity)
            }
        })();
        match result {
            Err(ProtocolError::WouldBlock) => {
                self.source_item = Some(item);
                return Ok(false);
            }
            Err(error) => {
                self.gap.source_failed(job.route)?;
                if self.report.first_source_block_refusal.is_none() {
                    self.report.first_source_block_refusal = Some(item.block);
                }
                return Err(error.into());
            }
            Ok(pure::ResultState::Retired) => {
                self.report.source_items_retired =
                    self.report.source_items_retired.saturating_add(1);
                if self.report.first_source_item_retired.is_none() {
                    self.report.first_source_item_retired = Some(item.block);
                }
            }
            Ok(_) => {}
        }
        if item.terminal {
            self.job = None;
            self.source_paused = false;
        } else {
            self.source_paused = true;
        }
        Ok(true)
    }
    fn source_poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, Error>> {
        if let Some(job) = self.job {
            if let Some(item) = self.source_item.take() {
                return match self.accept_source_item(job, item) {
                    Ok(true) => Poll::Ready(Ok(true)),
                    Ok(false) => Poll::Pending,
                    Err(error) => Poll::Ready(Err(error)),
                };
            }
            if self.source_paused {
                if self.stopping || self.gap.retiring(job.route)? {
                    self.source.request_retire();
                    self.source_paused = false;
                } else if self.gap.positive_pending(job.route)? {
                    return Poll::Pending;
                } else {
                    if let Err(cause) = self.source.resume() {
                        let unavailable = matches!(
                            self.source.availability(),
                            source::Availability::Closed | source::Availability::Unavailable
                        );
                        if unavailable || cause.is_fatal() {
                            self.source_failure(job.route, cause, unavailable)?;
                        } else {
                            // Refusing a continuation does not erase the old
                            // paused source selection. Preserve its cause and
                            // drain that exact owner before finishing its query.
                            self.report.source_failures =
                                self.report.source_failures.saturating_add(1);
                            if self.report.first_source_failure.is_none() {
                                self.report.first_source_failure = Some(cause);
                            }
                            self.source_sweep_failed = true;
                            self.source.request_retire();
                        }
                    }
                    self.source_paused = false;
                    return Poll::Ready(Ok(true));
                }
            }
            if self.stopping || self.gap.retiring(job.route)? {
                self.source.request_retire();
            }
            let result = match self.source.poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result,
            };
            match result {
                Ok(source::Progress::Activity) => return Poll::Ready(Ok(true)),
                Ok(source::Progress::Skipped(record)) => {
                    if record.selection().query != job.selection.query
                        || record.selection().block_type != job.selection.kind
                    {
                        return Poll::Ready(Err(ProtocolError::Authentication.into()));
                    }
                    self.report.records_rejected = self.report.records_rejected.saturating_add(1);
                    if record.cause().is_fatal() {
                        self.gap.source_failed(job.route)?;
                        self.request_shutdown();
                        return Poll::Ready(Err(Error::RejectedSource(Box::new(record))));
                    }
                    if self.report.first_source_record.is_none() {
                        self.report.first_source_record = Some(record);
                    }
                    return Poll::Ready(Ok(true));
                }
                Ok(source::Progress::Candidate(block)) => {
                    self.report.source_items = self.report.source_items.saturating_add(1);
                    self.source_paused = true;
                    let _accepted = self.accept_source_item(
                        job,
                        SourceItem {
                            block,
                            terminal: false,
                        },
                    )?;
                    return Poll::Ready(Ok(true));
                }
                Ok(source::Progress::Found(block)) => {
                    self.source_terminal_observed = true;
                    let _accepted = self.accept_source_item(
                        job,
                        SourceItem {
                            block,
                            terminal: true,
                        },
                    )?;
                    return Poll::Ready(Ok(true));
                }
                Ok(source::Progress::NotFound) => {
                    if self.source_sweep_failed {
                        self.gap.source_failed(job.route)?;
                    } else {
                        self.gap.source_finished(job.route, None)?;
                    }
                }
                Ok(source::Progress::Retired(retired)) => {
                    if retired.selection.query != job.selection.query
                        || retired.selection.block_type != job.selection.kind
                    {
                        return Poll::Ready(Err(ProtocolError::Authentication.into()));
                    }
                    if retired.cause().is_some_and(source::Failure::is_fatal) {
                        self.gap.source_failed(job.route)?;
                        self.request_shutdown();
                        return Poll::Ready(Err(Error::RetiredSource(Box::new(retired))));
                    }
                    if self.source_sweep_failed {
                        self.gap.source_failed(job.route)?;
                    } else {
                        self.gap.source_finished(job.route, None)?;
                    }
                    if self.report.first_source_retired.is_none() {
                        self.report.first_source_retired = Some(retired);
                    }
                }
                Ok(source::Progress::Unavailable { selection, cause }) => {
                    if selection.query != job.selection.query
                        || selection.block_type != job.selection.kind
                    {
                        return Poll::Ready(Err(ProtocolError::Authentication.into()));
                    }
                    self.source_failure(job.route, cause, true)?;
                }
                Err(cause) => {
                    let unavailable = matches!(
                        self.source.availability(),
                        source::Availability::Closed | source::Availability::Unavailable
                    );
                    self.source_failure(job.route, cause, unavailable)?;
                }
            }
            self.job = None;
            self.source_paused = false;
            self.source_sweep_failed = false;
            self.source_terminal_observed = false;
            return Poll::Ready(Ok(true));
        }
        if self.stopping {
            return Poll::Pending;
        }
        let Some(job) = self.gap.next_lookup() else {
            return Poll::Pending;
        };
        let selection = source::Selection {
            block_type: job.selection.kind,
            query: job.selection.query,
        };
        match self.source.start_stream(selection) {
            Ok(()) => {
                self.job = Some(job);
                self.source_sweep_failed = false;
                self.source_terminal_observed = false;
            }
            Err(cause) => {
                let unavailable = matches!(
                    self.source.availability(),
                    source::Availability::Closed | source::Availability::Unavailable
                );
                self.source_failure(job.route, cause, unavailable)?;
            }
        }
        Poll::Ready(Ok(true))
    }
    fn payload(&mut self, state: PayloadState<'c>, now: u64) -> Result<(), Error> {
        if self.control_payload(state)? {
            return Ok(());
        }
        let s = self.send.as_mut().ok_or(ProtocolError::StaleGeneration)?;
        if s.send != Some(state.send())
            || s.epoch != state.epoch()
            || s.peer != state.peer()
            || s.total != state.frame_bytes()
            || state.written() < s.written
        {
            return Err(ProtocolError::Authentication.into());
        }
        if state.exposed() && !s.exposed {
            self.gap.exposed(s.tx)?;
            self.privacy.exposed(s.permit)?;
            s.exposed = true;
        }
        if state.complete() && s.query && !s.plan_recorded {
            let plan = self
                .plans
                .iter_mut()
                .find(|p| p.route == s.route)
                .ok_or(ProtocolError::StaleGeneration)?;
            plan.metadata.last_transmission = AbsoluteTime::from_micros(now);
            plan.metadata.num_transmissions = plan.metadata.num_transmissions.saturating_add(1);
            plan.metadata.respect_offered =
                plan.metadata.respect_offered.saturating_add(s.priority);
            s.plan_recorded = true;
        }
        s.written = state.written();
        Ok(())
    }
    fn finish(
        &mut self,
        epoch: ConnectionEpoch<'c>,
        peer: Peer<'c>,
        send: SendId<'c>,
        payload: Option<PayloadState<'c>>,
        completion: core::SendCompletion<Message>,
        now: u64,
    ) -> Result<(), Error> {
        if self.control_matches(send) {
            return self.finish_control(epoch, peer, send, payload, completion);
        }
        let outcome = completion.outcome;
        self.report.completions = self.report.completions.saturating_add(1);
        self.report.last_completion = Some(Completion {
            payload,
            send,
            outcome,
            source: completion.source,
        });
        if let Some(state) = payload {
            self.payload(state, now)?;
        }
        let s = self.send.as_ref().ok_or(ProtocolError::StaleGeneration)?;
        if s.epoch != epoch
            || s.peer != peer
            || s.send != Some(send)
            || self.gap.send_bytes(s.tx)?.1
                != self
                    .report
                    .last_completion
                    .as_ref()
                    .ok_or(ProtocolError::StaleGeneration)?
                    .source
                    .as_ref()
        {
            return Err(ProtocolError::Authentication.into());
        }
        let complete = payload.is_some_and(|p| p.complete());
        if outcome == core::SendOutcome::Written && !complete {
            return Err(ProtocolError::Conflict.into());
        }
        let permit = s.permit;
        let fact = if complete {
            self.gap.written(s.tx)?
        } else {
            self.gap.send_failed(s.tx)?
        };
        self.settle_privacy(
            permit,
            fact,
            outcome == core::SendOutcome::Written && complete,
        )?;
        self.send = None;
        Ok(())
    }
    fn native_event(&mut self, progress: Progress<'c>, now: u64) -> Result<(), Error> {
        match progress {
            Progress::Connected(epoch) => self.epoch = Some(epoch),
            Progress::Inbound { epoch, event } => match event {
                Inbound::Ready { local, .. } => {
                    if self.epoch != Some(epoch) {
                        return Err(ProtocolError::StaleGeneration.into());
                    }
                    self.add_peer(epoch, local, true)?;
                }
                Inbound::Connected(peer) => {
                    if self.epoch != Some(epoch) {
                        return Err(ProtocolError::StaleGeneration.into());
                    }
                    self.add_peer(epoch, peer, false)?;
                }
                Inbound::Disconnected(peer) => {
                    if let Some(p) = self
                        .peers
                        .iter_mut()
                        .find(|p| p.epoch == epoch && p.peer == peer)
                    {
                        p.live = false;
                        if let Some(n) = p.neighbor {
                            self.privacy.retire_neighbor(n);
                            self.gap.retire_neighbor_paths(n)?;
                        }
                    }
                }
                Inbound::Traffic {
                    connection: Some(peer),
                    direction: Direction::Inbound,
                    traffic: OwnedTraffic::Full(original),
                    ..
                } => {
                    let packet = Packet {
                        epoch,
                        peer,
                        original,
                        cursor: 0,
                    };
                    if self.stopping {
                        self.refuse_packet(packet, ProtocolError::Closed);
                    } else if !self
                        .peers
                        .iter()
                        .any(|p| p.live && p.epoch == epoch && p.peer == peer)
                    {
                        self.refuse_packet(packet, ProtocolError::StaleGeneration);
                    } else if self.packets.len() == self.limits.packets {
                        self.refuse_packet(packet, ProtocolError::Capacity);
                    } else {
                        self.packets.push_back(packet);
                    }
                }
                Inbound::Traffic { .. }
                | Inbound::SendReady { .. }
                | Inbound::Rejected(_)
                | Inbound::IgnoredReady { .. }
                | Inbound::IgnoredSelfNotification => {}
            },
            Progress::Activity {
                payload: Some(write),
                ..
            } => self.payload(write.state(), now)?,
            Progress::Activity { .. } | Progress::WaitDeadline => {}
            Progress::Finished {
                epoch,
                peer,
                send,
                payload,
                completion,
            } => self.finish(epoch, peer, send, Some(payload), completion, now)?,
            Progress::PeerLost { epoch, peer } => {
                if let Some(p) = self
                    .peers
                    .iter_mut()
                    .find(|p| p.epoch == epoch && p.peer == peer)
                {
                    p.live = false;
                    if let Some(n) = p.neighbor {
                        self.privacy.retire_neighbor(n);
                        self.gap.retire_neighbor_paths(n)?;
                    }
                }
            }
            Progress::Lost { epoch, cause } => {
                for p in &mut self.peers {
                    if p.epoch == epoch {
                        p.live = false;
                        if let Some(n) = p.neighbor {
                            self.privacy.retire_neighbor(n);
                            self.gap.retire_neighbor_paths(n)?;
                        }
                    }
                }
                if self.epoch == Some(epoch) {
                    self.epoch = None;
                }
                self.lose_local_routes()?;
                self.report.losses = self.report.losses.saturating_add(1);
                self.report.last_loss = Some(cause);
            }
            Progress::Capacity(epoch) => {
                self.report.last_capacity = Some(epoch);
                // Native retains its original complete frame. Explicit physical
                // retirement bounds this source; no fake CORE credit is emitted.
                let loss = self.native.reconnect()?;
                self.native_event(loss, now)?;
            }
            Progress::ConnectRetry { error, .. } => {
                self.report.connect_retries = self.report.connect_retries.saturating_add(1);
                self.report.last_connect_error = Some(error);
            }
            Progress::Unavailable(error) => {
                self.report.unavailable = self.report.unavailable.saturating_add(1);
                self.report.last_unavailable = Some(error);
            }
            Progress::Closed => {
                for p in &mut self.peers {
                    p.live = false;
                }
                self.epoch = None;
            }
        }
        Ok(())
    }
    fn current_remote(&self, neighbor: pure::Neighbor<'g>) -> bool {
        self.peers.iter().any(|p| {
            p.live
                && !p.local
                && p.neighbor == Some(neighbor)
                && self.epoch == Some(p.epoch)
                && self.native.peer(p.peer.identity()) == Some(p.peer)
        })
    }
    fn settle_privacy(
        &mut self,
        permit: pure::privacy::Permit<'g>,
        fact: pure::SendRetired<'g>,
        confirmed_written: bool,
    ) -> Result<(), Error> {
        if let Some(storage) = &mut self.storage {
            storage.sent(fact, confirmed_written)?;
        }
        let target_live = self.current_remote(fact.neighbor);
        self.privacy
            .settle(permit, fact, self.last_now, confirmed_written, target_live)?;
        Ok(())
    }
    fn prepare(
        &mut self,
        tx: pure::Transmit<'g>,
        route: pure::Route<'g>,
        query: bool,
        permit: pure::privacy::Permit<'g>,
    ) -> Result<(), Error> {
        self.privacy.bind(permit, tx)?;
        let (neighbor, bytes) = self.gap.send_bytes(tx)?;
        let actual = self
            .peers
            .iter()
            .copied()
            .find(|p| p.live && p.neighbor == Some(neighbor))
            .ok_or(ProtocolError::StaleGeneration)?;
        let total = SEND_PREFIX
            .checked_add(bytes.len())
            .ok_or(ProtocolError::Overflow)?;
        let priority = if query {
            Get::decode(bytes)?.priority
        } else {
            0
        };
        let deadline = match Deadline::after(self.clock.clone(), self.limits.send_timeout) {
            Ok(d) => d,
            Err(e) => {
                let fact = self.gap.send_failed(tx)?;
                self.settle_privacy(permit, fact, false)?;
                return Err(e.into());
            }
        };
        self.send = Some(Sending {
            tx,
            route,
            neighbor,
            epoch: actual.epoch,
            peer: actual.peer,
            send: None,
            message: None,
            deadline: Some(deadline),
            query,
            priority,
            written: 0,
            total,
            exposed: false,
            plan_recorded: false,
            canceling: false,
            permit,
            privacy_retiring: false,
        });
        Ok(())
    }
    fn offer(&mut self) -> Result<bool, Error> {
        if self.stopping || self.send.is_some() || self.control.is_some() {
            return Ok(false);
        }
        self.control_turn = true;
        let returns = self.gap.ready_returns().count();
        for offset in 0..returns {
            let index = (self.return_cursor + offset) % returns;
            let path = self
                .gap
                .ready_returns()
                .nth(index)
                .ok_or(ProtocolError::StaleGeneration)?;
            let Destination::Neighbor(neighbor) = self.gap.destination(path)? else {
                continue;
            };
            if !self
                .peers
                .iter()
                .any(|p| p.live && p.neighbor == Some(neighbor))
            {
                continue;
            }
            let requirement = self.gap.reply_requirement(path)?;
            let permit = match self
                .privacy
                .admit(requirement, self.last_now, &mut self.entropy)?
            {
                pure::privacy::Admission::Wait(_) => continue,
                pure::privacy::Admission::Ready(permit) => permit,
            };
            let route = self.gap.path_route(path)?;
            let tx = match self.gap.prepare_reply_with_permit(path, permit) {
                Ok(tx) => tx,
                Err(error) => {
                    let live = self.current_remote(neighbor);
                    self.privacy
                        .cancel_unprepared(permit, self.last_now, live)?;
                    if matches!(
                        error,
                        ProtocolError::Closed
                            | ProtocolError::NotReady
                            | ProtocolError::PermissionDenied
                    ) {
                        continue;
                    }
                    return Err(error.into());
                }
            };
            self.return_cursor = (index + 1) % returns;
            self.prepare(tx, route, false, permit)?;
            return Ok(true);
        }
        let routes = self.gap.forwarding().count();
        for offset in 0..routes {
            let index = (self.route_cursor + offset) % routes;
            let route = self
                .gap
                .forwarding()
                .nth(index)
                .ok_or(ProtocolError::StaleGeneration)?;
            for step in 0..self.peers.len() {
                let p = self.peers[(self.peer_cursor + step) % self.peers.len()];
                if !p.live || p.local {
                    continue;
                }
                let Some(neighbor) = p.neighbor else {
                    continue;
                };
                let requirement = match self.gap.query_requirement(route, neighbor) {
                    Ok(requirement) => requirement,
                    Err(
                        ProtocolError::PermissionDenied
                        | ProtocolError::NotReady
                        | ProtocolError::Closed,
                    ) => continue,
                    Err(e) => return Err(e.into()),
                };
                let permit =
                    match self
                        .privacy
                        .admit(requirement, self.last_now, &mut self.entropy)?
                    {
                        pure::privacy::Admission::Wait(_) => continue,
                        pure::privacy::Admission::Ready(permit) => permit,
                    };
                let tx = match self.gap.prepare_query_with_permit(
                    route,
                    neighbor,
                    self.last_now,
                    &mut self.entropy,
                    permit,
                ) {
                    Ok(tx) => tx,
                    Err(error) => {
                        let live = self.current_remote(neighbor);
                        self.privacy
                            .cancel_unprepared(permit, self.last_now, live)?;
                        if matches!(
                            error,
                            ProtocolError::PermissionDenied
                                | ProtocolError::NotReady
                                | ProtocolError::Closed
                        ) {
                            continue;
                        }
                        return Err(error.into());
                    }
                };
                self.route_cursor = (index + 1) % routes;
                self.peer_cursor = (self.peer_cursor + step + 1) % self.peers.len();
                self.prepare(tx, route, true, permit)?;
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn submit(&mut self) -> Result<bool, Error> {
        let Some(s) = self.send.as_mut() else {
            return Ok(false);
        };
        if s.send.is_some() {
            return Ok(false);
        }
        if !self.peers.iter().any(|p| {
            p.live && p.epoch == s.epoch && p.peer == s.peer && p.neighbor == Some(s.neighbor)
        }) || self.gap.retiring(s.route)?
            || self.stopping
        {
            let permit = s.permit;
            let fact = self.gap.send_failed(s.tx)?;
            self.settle_privacy(permit, fact, false)?;
            self.send = None;
            return Ok(true);
        }
        let (_, wire) = self.gap.send_bytes(s.tx)?;
        match self
            .native
            .request_available(s.peer, wire.len(), wire.len())
        {
            Ok(false)
            | Err(core::Error::Protocol(ProtocolError::NotReady | ProtocolError::Closed)) => {
                return Ok(false);
            }
            Err(e) => return Err(e.into()),
            Ok(true) => {}
        }
        let message = match s.message.take() {
            Some(m) => m,
            None => Message::copy_from(wire)?,
        };
        let delay = u64::try_from(self.limits.send_timeout.as_micros())
            .map_err(|_| ProtocolError::Overflow)?;
        let target = self
            .last_now
            .checked_add(delay)
            .ok_or(ProtocolError::Overflow)?;
        match self.native.send(s.peer, s.priority, target, message) {
            Ok(send) => {
                s.send = Some(send);
                self.gap.admitted(s.tx)?;
                Ok(true)
            }
            Err(rejected) => {
                s.message = Some(rejected.value);
                match rejected.reason {
                    ProtocolError::Capacity
                    | ProtocolError::WouldBlock
                    | ProtocolError::NotReady => Ok(false),
                    e => Err(e.into()),
                }
            }
        }
    }
    fn retire_time_evidence(&mut self) -> Result<bool, Error> {
        let Some(s) = self.send.as_mut() else {
            return Ok(false);
        };
        if s.privacy_retiring || s.permit.cover_current() || s.permit.requirement().needed() == 0 {
            return Ok(false);
        }
        s.privacy_retiring = true;
        self.report.policy_time_retirements = self.report.policy_time_retirements.saturating_add(1);
        s.canceling = true;
        let original = (s.send, s.epoch, s.peer, s.tx, s.written, s.total, s.permit);
        if let Some(send) = original.0 {
            if original.4 != 0 && original.4 < original.5 {
                let loss = self.native.reconnect()?;
                self.native_event(loss, self.last_now)?;
            } else if let Some(completion) = self.native.cancel(send)? {
                self.finish(
                    original.1,
                    original.2,
                    send,
                    None,
                    completion,
                    self.last_now,
                )?;
            }
        } else {
            let fact = self.gap.send_failed(original.3)?;
            self.settle_privacy(original.6, fact, false)?;
            self.send = None;
        }
        Ok(true)
    }
    fn sending_poll(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        let Some(s) = self.send.as_mut() else {
            return Ok(false);
        };
        let retiring = self.gap.retiring(s.route)? || self.stopping;
        let timed = if let Some(deadline) = &mut s.deadline {
            match Pin::new(deadline).poll(cx) {
                Poll::Pending => false,
                Poll::Ready(r) => {
                    r?;
                    s.deadline = None;
                    true
                }
            }
        } else {
            false
        };
        // A local cancellation cannot remove the finite physical drain timer.
        // If an exposed suffix stalls, expiry retires the original shared MQ.
        if (!s.canceling && retiring) || timed {
            s.canceling = true;
            let original = (s.send, s.epoch, s.peer, s.tx, s.written, s.total, s.permit);
            if let Some(send) = original.0 {
                if timed && original.4 != 0 && original.4 < original.5 {
                    self.report.partial_timeouts = self.report.partial_timeouts.saturating_add(1);
                    let loss = self.native.reconnect()?;
                    self.native_event(loss, self.last_now)?;
                } else if let Some(completion) = self.native.cancel(send)? {
                    self.finish(
                        original.1,
                        original.2,
                        send,
                        None,
                        completion,
                        self.last_now,
                    )?;
                }
            } else {
                let fact = self.gap.send_failed(original.3)?;
                self.settle_privacy(original.6, fact, false)?;
                self.send = None;
            }
            return Ok(true);
        }
        Ok(false)
    }
    fn privacy_holds(&mut self) -> Result<(bool, Option<u64>), Error> {
        let mut changed = false;
        let mut next = None;
        let count = self.gap.ready_returns().count();
        for i in (0..count).rev() {
            let path = self
                .gap
                .ready_returns()
                .nth(i)
                .ok_or(ProtocolError::StaleGeneration)?;
            if !matches!(self.gap.destination(path)?, Destination::Neighbor(_)) {
                continue;
            }
            if self
                .send
                .as_ref()
                .is_some_and(|s| s.permit.requirement().path() == Some(path))
            {
                continue;
            }
            let requirement = self.gap.reply_requirement(path)?;
            if !self.privacy.holds_output(requirement) {
                continue;
            }
            let target = self.gap.residence_deadline(requirement.route())?;
            if self.last_now < target {
                next = Some(next.map_or(target, |old: u64| old.min(target)));
                continue;
            }
            let retained = if self.report.first_privacy_expired.is_none() {
                let info = self.gap.result_info(path)?;
                let source = match info.source {
                    pure::ResultSource::Unspecified => PrivacySource::Unspecified,
                    pure::ResultSource::Local { anonymity } => PrivacySource::Local { anonymity },
                    pure::ResultSource::Peer { is_local, .. } => {
                        PrivacySource::PeerUnknown { is_local }
                    }
                };
                let wire = self
                    .gap
                    .retained_result(path)?
                    .ok_or(ProtocolError::NotReady)?;
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(wire.len())
                    .map_err(|_| ProtocolError::Capacity)?;
                bytes.extend_from_slice(wire);
                Some(PrivacyRetired {
                    selection: self.gap.selection(requirement.route())?,
                    route: requirement.route().value(),
                    path: path.value(),
                    result: info.serial,
                    target: self.gap.peer(requirement.neighbor())?,
                    source,
                    reason: self.privacy.restriction(requirement, self.last_now),
                    at: AbsoluteTime::from_micros(self.last_now),
                    frame: OwnedFrame::new(bytes),
                })
            } else {
                None
            };
            // This is a local bounded policy decision before native admission.
            // The original source operation still retires through source_poll.
            self.gap.cancel(path)?;
            self.report.privacy_expired = self.report.privacy_expired.saturating_add(1);
            if let Some(retained) = retained {
                self.report.first_privacy_expired = Some(retained);
            }
            changed = true;
        }
        Ok((changed, next))
    }
    fn deadlines(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        let mut changed = self.storage_deadline(cx)?;
        let (retired, hold_target) = self.privacy_holds()?;
        changed |= retired;
        self.privacy
            .retain_intents(|r| self.gap.requirement_current(r));
        let target = self
            .privacy
            .next_deadline(self.last_now)
            .into_iter()
            .chain(hold_target)
            .min();
        if self.privacy_timer.as_ref().map(|(t, _)| *t) != target {
            self.privacy_timer = match target {
                Some(t) => Some((
                    t,
                    Deadline::at(self.clock.clone(), AbsoluteTime::from_micros(t))?,
                )),
                None => None,
            };
            changed = true;
        }
        if let Some((_, deadline)) = &mut self.privacy_timer
            && let Poll::Ready(result) = Pin::new(deadline).poll(cx)
        {
            result?;
            self.privacy_timer = None;
            changed = true;
        }
        if let Some((_, deadline)) = &mut self.maintenance
            && let Poll::Ready(result) = Pin::new(deadline).poll(cx)
        {
            result?;
            self.maintenance = None;
            changed = true;
        }

        for i in 0..self.locals.len() {
            if !self.locals[i].active {
                continue;
            }
            if self.gap.local_result(self.locals[i].path)?.is_some() {
                self.locals[i].deadline = None;
                continue;
            }
            if let Some(deadline) = &mut self.locals[i].deadline
                && let Poll::Ready(result) = Pin::new(deadline).poll(cx)
            {
                result?;
                self.end(i)?;
                self.report.timeouts = self.report.timeouts.saturating_add(1);
                changed = true;
            }
        }
        if let Some(route) = self.gap.expire(self.last_now)? {
            for i in 0..self.locals.len() {
                if self.locals[i].route == route {
                    self.end(i)?;
                }
            }
            changed = true;
        }
        let count = self.gap.routes().count();
        for index in (0..count).rev() {
            let route = { self.gap.routes().nth(index) };
            if let Some(route) = route {
                match self.gap.collect(route, self.last_now) {
                    Ok(()) => {
                        self.wake_initial();
                        changed = true;
                    }
                    Err(ProtocolError::WouldBlock) => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        self.plans.retain(|p| self.gap.selection(p.route).is_ok());
        let target = if self.stopping {
            None
        } else {
            self.gap.next_deadline(self.last_now)
        };
        if self.maintenance.as_ref().map(|(t, _)| *t) != target {
            self.maintenance = match target {
                Some(target) => Some((
                    target,
                    Deadline::at(self.clock.clone(), AbsoluteTime::from_micros(target))?,
                )),
                None => None,
            };
            changed = true;
        }
        Ok(changed)
    }
    fn delivery(&mut self, deliver: bool) -> Result<Option<PeerProgress>, Error> {
        if deliver {
            for i in 0..self.locals.len() {
                if !self.locals[i].active {
                    continue;
                }
                let l = &self.locals[i];
                let Some((tag, wire)) = self.gap.local_result(l.path)? else {
                    continue;
                };
                if tag != l.serial {
                    return Err(ProtocolError::Authentication.into());
                }
                let mut owned = Vec::new();
                owned
                    .try_reserve_exact(wire.len())
                    .map_err(|_| ProtocolError::Capacity)?;
                owned.extend_from_slice(wire);
                let metadata = self
                    .plans
                    .iter()
                    .find(|p| p.route == l.route)
                    .ok_or(ProtocolError::StaleGeneration)?
                    .metadata;
                let serial = l.serial;
                let path = l.path;
                let multiple = Put::decode(&owned)?.block_type == BlockType::UBLOCK;
                let deadline = if multiple {
                    Some(Deadline::after(
                        self.clock.clone(),
                        self.limits.query_timeout,
                    )?)
                } else {
                    None
                };
                self.gap.commit_local(path)?;
                if !multiple {
                    self.locals[i].active = false;
                    self.locals[i].end = true;
                }
                self.locals[i].deadline = deadline;
                return Ok(Some(PeerProgress::GapReply {
                    route: serial,
                    frame: OwnedFrame::new(owned),
                    metadata,
                }));
            }
        }
        if let Some(index) = self.locals.iter().position(|l| l.end) {
            let serial = self.locals.swap_remove(index).serial;
            return Ok(Some(PeerProgress::Ended(serial)));
        }
        if let Some(index) = self.initial.iter().position(|r| r.end) {
            let serial = self.initial.swap_remove(index).serial;
            self.initial_cursor %= self.initial.len().max(1);
            return Ok(Some(PeerProgress::Ended(serial)));
        }
        Ok(None)
    }
    /// Stop fresh local/inbound source work. Actual original source/CORE output
    /// still drains through poll; no network END/negative is synthesized.
    pub fn request_shutdown(&mut self) {
        self.stopping = true;
        for original in &mut self.initial {
            original.end = true;
            original.ready = false;
        }
        self.storage_stop();
        self.maintenance = None;
        self.gap.request_shutdown();
        self.privacy.request_shutdown();
        self.privacy_timer = None;
        if self.job.is_some() {
            self.source.request_retire();
        }
        for l in &mut self.locals {
            if l.active {
                l.active = false;
                l.end = true;
                l.deadline = None;
            }
        }
        while let Some(packet) = self.packets.pop_front() {
            self.refuse_packet(packet, ProtocolError::Closed);
        }
    }
    /// Only local pure/source/output jobs settled; no peer ACK/quiescence claim.
    #[must_use]
    pub fn quiesced(&self) -> bool {
        self.stopping
            && self.job.is_none()
            && self.send.is_none()
            && self.packets.is_empty()
            && self.gap.quiesced()
            && self.privacy.quiesced()
            && self.storage_quiesced()
    }
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        deliver: bool,
    ) -> Poll<Result<PeerProgress, Error>> {
        if self.closed {
            return Poll::Pending;
        }
        self.last_now = self.clock.sample()?.now.as_micros();
        self.privacy.advance(self.last_now)?;
        let mut ready = self.retire_time_evidence()?;
        for offset in 0..4 {
            match (self.round + offset) % 4 {
                0 => match self.native.poll(cx, None) {
                    Poll::Pending => {}
                    Poll::Ready(Ok(event)) => {
                        self.native_event(event, self.last_now)?;
                        ready = true;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                },
                1 => match self.source_poll(cx) {
                    Poll::Pending => {}
                    Poll::Ready(result) => ready |= result?,
                },
                2 => {
                    ready |= self.storage_poll(cx)?;
                }
                _ => {
                    ready |= self.peer_maintenance()?;
                    ready |= self.input(self.last_now)?;
                    ready |= self.deadlines(cx)?;
                    ready |= self.sending_poll(cx)?;
                    ready |= self.storage_control(cx)?;
                    ready |= self.offer()?;
                    ready |= self.submit()?;
                }
            }
        }
        self.round = (self.round + 1) % 4;
        if let Some(event) = self.delivery(deliver)? {
            return Poll::Ready(Ok(event));
        }
        if ready {
            Poll::Ready(Ok(PeerProgress::Activity))
        } else {
            Poll::Pending
        }
    }
    fn admit(
        &mut self,
        serial: u64,
        search: Search<'_>,
        seen: &[[u8; 64]],
    ) -> Result<RouteAdmission, Error> {
        if self.closed || self.stopping {
            return Ok(RouteAdmission::Idle);
        }
        if search.options & SEARCH_LOOPBACK_ONLY != 0 {
            return Ok(RouteAdmission::Idle);
        }
        if (search.anonymity == 0
            && !matches!(
                search.block_type,
                BlockType::DBLOCK | BlockType::IBLOCK | BlockType::UBLOCK
            ))
            || !matches!(
                search.block_type,
                BlockType::ANY | BlockType::DBLOCK | BlockType::IBLOCK | BlockType::UBLOCK
            )
        {
            self.report.unsupported = self.report.unsupported.saturating_add(1);
            return Ok(RouteAdmission::Idle);
        }
        search.validate()?;
        if matches!(search.block_type, BlockType::DBLOCK | BlockType::IBLOCK)
            && seen.contains(&search.query)
        {
            return Ok(RouteAdmission::Idle);
        }
        if serial <= self.last_route {
            return Err(ProtocolError::StaleGeneration.into());
        }
        if self
            .locals
            .len()
            .checked_add(self.initial.len())
            .ok_or(ProtocolError::Overflow)?
            >= self.limits.local_routes
        {
            return Ok(RouteAdmission::Idle);
        }
        if self.connected_peers() == 0 {
            self.initial.push(DeferredInitial {
                serial,
                search: Search {
                    options: search.options,
                    block_type: search.block_type,
                    anonymity: search.anonymity,
                    target: search.target,
                    query: search.query,
                    seen: &[],
                },
                ready: false,
                end: false,
            });
            self.last_route = serial;
            self.report.initial_deferred = self.report.initial_deferred.saturating_add(1);
            return Ok(RouteAdmission::Queued);
        }
        let admission = self.admit_ready(serial, search, seen)?;
        if admission == RouteAdmission::Queued {
            self.last_route = serial;
        }
        Ok(admission)
    }
    fn admit_ready(
        &mut self,
        serial: u64,
        search: Search<'_>,
        seen: &[[u8; 64]],
    ) -> Result<RouteAdmission, Error> {
        let deadline = Deadline::after(self.clock.clone(), self.limits.query_timeout)?;
        let now = self.clock.sample()?.now.as_micros();
        let admission = match self.gap.start_with_seen(
            pure::Selection {
                kind: search.block_type,
                query: search.query,
            },
            serial,
            search.anonymity,
            self.limits.priority,
            0,
            now,
            seen,
            &mut self.entropy,
        ) {
            Ok(a) => a,
            Err(ProtocolError::Closed | ProtocolError::Capacity) => {
                return Ok(RouteAdmission::Idle);
            }
            Err(e) => return Err(e.into()),
        };
        self.ensure_plan(admission.route)?;
        self.locals.push(Local {
            serial,
            route: admission.route,
            path: admission.path,
            deadline: Some(deadline),
            active: true,
            end: false,
        });
        Ok(RouteAdmission::Queued)
    }
    fn physical_close(&mut self) -> Result<(), Error> {
        if self.closed {
            return Ok(());
        }
        self.request_shutdown();
        let mut native_error = None;
        match self.native.close() {
            Ok(Some(event)) => {
                if let Err(e) = self.native_event(event, self.last_now) {
                    native_error = Some(Box::new(e) as Failure);
                }
            }
            Ok(None) => {}
            Err(e) => native_error = Some(Box::new(e) as Failure),
        }
        let mut cx = Context::from_waker(Waker::noop());
        let bound = P
            .checked_add(N)
            .and_then(|n| n.checked_add(8))
            .ok_or(ProtocolError::Capacity)?;
        let mut drained = false;
        for _ in 0..bound {
            match self.native.poll(&mut cx, None) {
                Poll::Ready(Ok(Progress::Closed)) => {
                    drained = true;
                    break;
                }
                Poll::Ready(Ok(event)) => {
                    if let Err(e) = self.native_event(event, self.last_now)
                        && native_error.is_none()
                    {
                        native_error = Some(Box::new(e) as Failure);
                    }
                }
                Poll::Ready(Err(e)) => {
                    if native_error.is_none() {
                        native_error = Some(Box::new(e) as Failure);
                    }
                    break;
                }
                Poll::Pending => break,
            }
        }
        if !drained && native_error.is_none() {
            native_error = Some(Box::new(ProtocolError::WouldBlock) as Failure);
        }
        let mut policy_error = None;
        if let Some(tx) = self.gap.pending_send() {
            match self.gap.send_failed(tx) {
                Ok(fact) => {
                    if let Some(permit) = self.privacy.pending()
                        && let Err(e) =
                            self.privacy
                                .settle(permit, fact, self.last_now, false, false)
                    {
                        policy_error = Some(Box::new(e) as Failure);
                    }
                }
                Err(error) => {
                    if native_error.is_none() {
                        native_error = Some(Box::new(error) as Failure);
                    }
                }
            }
        }
        if let Some(permit) = self.privacy.pending()
            && let Err(e) = self.privacy.cancel_unprepared(permit, self.last_now, false)
            && policy_error.is_none()
        {
            policy_error = Some(Box::new(e) as Failure);
        }
        self.send = None;
        for p in &mut self.peers {
            p.live = false;
        }
        if let Err(error) = self.peer_maintenance()
            && native_error.is_none()
        {
            native_error = Some(Box::new(error) as Failure);
        }
        self.report.forced_source = self
            .job
            .filter(|_| !self.source_terminal_observed)
            .map(|j| source::Selection {
                block_type: j.selection.kind,
                query: j.selection.query,
            });
        if let Some(item) = self.source_item.take() {
            self.report.source_items_retired = self.report.source_items_retired.saturating_add(1);
            if self.report.first_source_item_retired.is_none() {
                self.report.first_source_item_retired = Some(item.block);
            }
        }
        self.source_paused = false;
        let source_error = self.source.close().err();
        let mut storage_error = self.storage_retirement_error.take();
        if let Err(error) = self.storage_forced_control() {
            Self::retain_storage_failure(&mut storage_error, Box::new(error) as Failure);
        }
        if let Some(storage) = &mut self.storage {
            if let Err(error) = storage.sweep(&mut self.gap, self.last_now) {
                Self::retain_storage_failure(&mut storage_error, Box::new(error) as Failure);
            }
            if let Err(error) = storage.close(self.last_now) {
                Self::retain_storage_failure(&mut storage_error, error);
            }
        }
        self.initial.clear();
        self.closed = true;
        if native_error.is_some()
            || source_error.is_some()
            || policy_error.is_some()
            || storage_error.is_some()
        {
            Err(Error::Cleanup {
                core: native_error,
                source: source_error,
                policy: policy_error,
                storage: storage_error,
            })
        } else {
            Ok(())
        }
    }
    fn failed(&mut self, cause: Error) -> ProviderFailure {
        let cause = match self.physical_close() {
            Ok(()) => cause,
            Err(cleanup) => Error::Retirement {
                cause: Box::new(cause),
                cleanup: Box::new(cleanup),
            },
        };
        cause.into_provider_failure()
    }
}
impl<S: source::BlockSource, E: pure::Entropy, const P: usize, const N: usize> PeerRouter
    for Router<'_, '_, '_, '_, S, E, P, N>
{
    fn request_shutdown(&mut self) {
        Router::request_shutdown(self);
    }
    fn shutdown_state(&self) -> super::PeerShutdown {
        if self.closed {
            super::PeerShutdown::Retired
        } else if self.quiesced() {
            super::PeerShutdown::Quiesced
        } else {
            super::PeerShutdown::Draining
        }
    }
    fn start(
        &mut self,
        route: u64,
        search: Search<'_>,
        seen: &[[u8; 64]],
    ) -> Result<RouteAdmission, ProviderFailure> {
        match self.admit(route, search, seen) {
            Ok(admission) => Ok(admission),
            Err(e) => Err(self.failed(e)),
        }
    }
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        deliver: bool,
    ) -> Poll<Result<PeerProgress, ProviderFailure>> {
        match self.poll_inner(cx, deliver) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(step)) => Poll::Ready(Ok(step)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(self.failed(e))),
        }
    }
    fn input_needed(&self) -> Option<u64> {
        self.initial_needed()
    }
    fn refresh(
        &mut self,
        route: u64,
        search: Search<'_>,
        seen: &[[u8; 64]],
    ) -> Result<(), ProviderFailure> {
        self.refresh_initial(route, search, seen)
            .map_err(|e| self.failed(e))
    }
    fn cancel(&mut self, route: u64) -> Result<(), ProviderFailure> {
        if let Some(i) = self.initial.iter().position(|r| r.serial == route) {
            self.initial.swap_remove(i);
            self.initial_cursor %= self.initial.len().max(1);
        }
        if let Some(i) = self.locals.iter().position(|r| r.serial == route)
            && let Err(e) = self.end(i)
        {
            return Err(self.failed(e));
        }
        Ok(())
    }
    fn close(&mut self) -> Result<(), ProviderFailure> {
        self.physical_close().map_err(Error::into_provider_failure)
    }
}
