use crate::{
    PeerId, Times,
    communicator::{self, Queue},
    fragment::Assembly,
    outbound::{self, Book, Coverage, FragmentSend, Job, Span},
    p2p::{self, Challenge, Flow, Validation},
};
use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use gnunet_client::transport::{Request as CoreRequest, Response as CoreResponse};
use gnunet_crypto::Entropy;
use gnunet_types::{Error, MonoInstant};
use gnunet_wire::official::{AbsoluteTime, Frame, RelativeTime};
use zeroize::Zeroizing;

/// Signatures are authorized by the node's actual persistent identity owner.
pub trait Signer {
    /// Current public identity, shared by CORE and the communicators.
    fn identity(&self) -> PeerId;
    /// Sign the complete exact purpose35 region for an address challenge.
    fn sign_validation(&mut self, region: &[u8; 48]) -> Result<[u8; 64], Error>;
    /// Defer to original owned effects when the identity service is asynchronous.
    fn validation_mode(&self) -> crate::signing::ValidationMode {
        crate::signing::ValidationMode::Immediate
    }
}
/// Explicit finite service resource policy, independent of C container choices.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum physical local IPC clients.
    pub clients: usize,
    /// Maximum communicator peer queues.
    pub queues: usize,
    /// Maximum known peers, confirmed or not. Also bounds a separate pool of
    /// fixed-size application suggestion metadata across all local clients.
    pub peers: usize,
    /// Maximum capacity_users local transmissions and queued messages per class.
    pub messages: usize,
    /// Maximum buffered payload/receive-assembly bytes. Outgoing retry bitmap
    /// metadata has an additional messages*8192 bound and separate observation.
    pub bytes: usize,
    /// Additional control jobs/attempts, kept available beyond ordinary work.
    /// Also bounds separate pools of original address-create, validation-signing and local-address metadata.
    pub control_messages: usize,
    /// Additional buffered control bytes, independent of payload RAM.
    /// Also separately bounds retained original address-create bytes,48byte signing snapshots and original local native+URI bytes.
    pub control_bytes: usize,
    /// Maximum simultaneous original-message reassemblies across all peers.
    pub assemblies: usize,
    /// Maximum simultaneous reassemblies attributed to one validated peer.
    pub assemblies_per_peer: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            clients: 32,
            queues: 128,
            peers: 64,
            messages: 256,
            bytes: 4 * 1024 * 1024,
            control_messages: 8,
            control_bytes: 4096,
            assemblies: 64,
            assemblies_per_peer: 32,
        }
    }
}
/// An instance-branded local IPC owner; these bytes never enter any wire frame.
#[derive(Clone, Debug)]
pub struct ClientId {
    instance: Arc<()>,
    serial: u64,
}
impl PartialEq for ClientId {
    fn eq(&self, other: &Self) -> bool {
        self.serial == other.serial && Arc::ptr_eq(&self.instance, &other.instance)
    }
}
impl Eq for ClientId {}
/// Nonfatal rejection of one fully parsed update to an existing original queue.
/// It creates no wire ACK and leaves that queue's state unchanged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueueRejection {
    /// Original physical local communicator owner.
    pub client: ClientId,
    /// Original queue destination.
    pub peer: PeerId,
    /// Original local queue identifier.
    pub queue: u32,
    /// Exact checked resource/arithmetic refusal.
    pub reason: Error,
}
/// A retained original whose transmission preflight refused local resources.
/// Numeric operation identity is diagnostic only; it grants no ACK/cancel authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkDeferral {
    /// Original job's local diagnostic serial.
    pub operation: u64,
    /// Original destination; it does not identify a replacement queue/owner.
    pub peer: PeerId,
    /// Exact preflight failure; no frame, credit or attempt was committed.
    pub reason: Error,
}
/// Result of a scheduled work pass, independent of remote delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkStatus {
    /// No newly deferred original was encountered.
    Ready,
    /// This original is retained and skipped until explicit retry or retirement.
    Deferred(WorkDeferral),
}
/// Outcome of one complete original IPC request, separate from fatal role errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiveOutcome {
    /// Original request was handled; this asserts no remote delivery.
    Accepted,
    /// The input was consumed once; later TX preflight refused local resources.
    WorkDeferred(WorkDeferral),
    /// A known queue update was refused without retiring its physical owner.
    Rejected(QueueRejection),
    /// Original ADD refused local address quota without changing the set or MQ.
    AddressRejected(crate::addresses::AddressRejection),
}
/// Work handed to the host after protocol state has admitted it.
#[derive(Debug)]
pub enum Output {
    /// Enqueue one complete official frame on its original physical connection.
    Frame {
        /// Original local connection owner.
        client: ClientId,
        /// Complete current-profile official IPC bytes.
        bytes: Vec<u8>,
    },
    /// Persist a newly authenticated address before processing further output.
    Validated {
        /// Authenticated identity.
        peer: PeerId,
        /// Reachable queue address.
        address: Vec<u8>,
        /// Exact GNUnet logical absolute expiration in microseconds, sampled
        /// when this validation succeeded. It is not a scheduling/remote stamp.
        /// Use `validated_expiration` for the typed view; do not rebase at STORE.
        until: u64,
    },
}
impl Output {
    /// Exact absolute cache expiration on a successful validation effect. Local
    /// queue/write delay cannot remint this value or turn it into a mono target.
    #[must_use]
    pub const fn validated_expiration(&self) -> Option<AbsoluteTime> {
        match self {
            Self::Validated { until, .. } => Some(AbsoluteTime::from_micros(*until)),
            Self::Frame { .. } => None,
        }
    }
}
/// Bounded last-drop diagnostic. It never retains payload or secret key bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteDrop {
    /// Original authenticated communicator sender.
    pub peer: PeerId,
    /// Logical rejected message type, including a reassembled inner control.
    pub message_type: u16,
    /// Exact protocol/resource rejection reason.
    pub reason: Error,
}
/// Observable state for supervision and acceptance; no fabricated delivery count.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Snapshot {
    /// Original remote acknowledgement spans retained for unreliable delivery.
    pub pending_remote_acks: usize,
    /// Outgoing settled-byte metadata, separate from the payload byte budget.
    pub retry_bitmap_bytes: usize,
    /// Admitted retry1209 envelopes, not native writes or application deliveries.
    pub retransmissions: u64,
    /// Local resource-retention expiries, never successful remote delivery.
    pub expired_messages: u64,
    /// Timed-out unreliable local callback records; packet grants stay spent.
    pub expired_attempts: u64,
    /// Unknown delayed local callbacks ignored without granting any authority.
    pub ignored_local_callbacks: u64,
    /// Physical local connection owners.
    pub clients: usize,
    /// Live communicator queues.
    pub queues: usize,
    /// Peers with a currently validated route.
    pub connected: usize,
    /// Malformed or unsupported remote network frames dropped in isolation.
    pub remote_dropped: u64,
    /// Best-effort direct backchannel effects not admitted to a route/target/FIFO.
    pub backchannel_dropped: u64,
    /// Exact last backchannel resource/route refusal; not remote malformed data.
    pub last_backchannel_drop: Option<Error>,
    /// Last isolated remote rejection, retained in one fixed-size record.
    pub last_remote_drop: Option<RemoteDrop>,
    /// Authenticated challenges successfully validated.
    pub validations: u64,
    /// Bounded original address creates awaiting actual queue setup or retirement.
    pub pending_address_creates: usize,
    /// Original fixed-size purpose35 effects awaiting completion or retirement.
    pub pending_validation_signatures: usize,
    /// Live application connection demands, retired by cancellation or original MQ EOF.
    pub application_suggestions: usize,
    /// Original address bytes retained by these communicator-MQ operations.
    pub address_create_bytes: usize,
    /// Monotonic official u32 create IDs issued in this engine instance.
    pub address_creates_issued: u32,
    /// Pending local send attempts awaiting the communicator's original ACK.
    pub attempts: usize,
    /// Data messages waiting for route, window or queue capacity.
    pub pending: usize,
    /// Owned outputs that the host must still process.
    pub outputs: usize,
    /// Retained incomplete original-message reassemblies.
    pub reassemblies: usize,
    /// Body and coverage storage charged for those reassemblies.
    pub reassembly_bytes: usize,
    /// Received fragment attempts still waiting for an outgoing cumulative ACK.
    pub pending_fragment_acks: usize,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Role {
    Unregistered,
    Application,
    Core,
    Communicator,
    Monitor,
}
struct Client {
    id: ClientId,
    role: Role,
    reliable: bool,
    payload: bool,
    prefix: Option<Vec<u8>>,
    can_burst: bool,
}
// One original communicator-MQ request. A positive create response is only
// admission of its attempt; actual QueueSetup and signed validation stay separate.
struct AddressCreate {
    owner: ClientId,
    wire: [u8; 4],
    peer: PeerId,
    address: Vec<u8>,
    expires: u64,
    accepted: bool,
}
// Local bounded admission policy, not an official protocol timeout/default.
const ADDRESS_CREATE_LIFETIME: u64 = 60_000_000;
struct Route {
    owner: ClientId,
    description: Queue,
    address: Vec<u8>,
    serial: u64,
    nonce: [u8; 32],
    challenge_pending: bool,
    challenge_first: u64,
    challenge_last: u64,
    challenge_next: u64,
    // Monotonic rate floor minted only by actual local Challenge job admission.
    // This is neither a physical write nor remote validation receipt.
    challenge_not_before: u64,
    valid_until: u64,
    monitor_last_validation: u64,
    monitor_valid_until: u64,
    monitor_next_validation: u64,
    monitor_rtt: Option<u64>,
    inflight: u64,
    available: u64,
    unlimited: bool,
}
impl Route {
    fn schedule_challenge(&mut self, times: Times, desired: u64) {
        self.challenge_next = desired.max(self.challenge_not_before);
        self.monitor_next_validation = monitor::next_absolute(
            times,
            self.challenge_next.saturating_sub(times.monotonic().0),
        );
    }
}
pub mod burst;
/// Actual DV bridge ports, independent of the route/Flow implementation.
pub mod dv_bridge;
mod maintenance;
/// Physical observation subscriptions, independent of route authority.
pub mod monitor;
struct PendingAck {
    id: [u8; 16],
    received: u64,
}
struct Peer {
    id: PeerId,
    connected: bool,
    // One stale transition per original inbound-activity period, independent
    // of direct/virtual connection state and route validation expiration.
    liveness_expired: bool,
    remote_sequence: Option<u32>,
    remote_time: u64,
    remote_burst_rtt: u64,
    outbound_window: u64,
    outbound_used: u64,
    inbound_used: u64,
    inbound_released: u64,
    loss_anchor_sent: u64,
    loss_anchor_released: u64,
    ack_counter: u32,
    fragment_acks: VecDeque<PendingAck>,
    flow_sequence: u32,
    flow_time: u64,
    monitor_last_flow: u64,
    monitor_incoming_window: u64,
    flow_next: u64,
    flow_waiting_range: bool,
    flow_dirty: bool,
    last_inbound: u64,
    rtt: u64,
    core_window: i64,
    received: VecDeque<InboundAllocation>,
}
// FIFO allocation accounting only: wire366 grants aggregate capacity and names
// no message. Reclaiming these debits is not proof of application processing.
// The optional callback still owns the exact original communicator token.
struct InboundAllocation {
    size: usize,
    capacity_users: Vec<ClientId>,
    ack: Option<(ClientId, [u8; 8])>,
}
struct Held {
    dv: Option<dv_bridge::HeldSource>,
    owner: ClientId,
    peer: PeerId,
    message: Zeroizing<Vec<u8>>,
    token: Option<[u8; 8]>,
}
enum NetworkStep {
    LocalFailure(Error),
    Processed(bool),
    OwnedMessage(Zeroizing<Vec<u8>>, u64),
    Diverted,
}
enum ReceiveMode<'a> {
    Domain(Option<dv_bridge::NativeInput<'a>>),
    Maintenance(Option<dv_bridge::NativeInput<'a>>),
}
impl ReceiveMode<'_> {
    fn native(&self) -> Option<&dv_bridge::NativeInput<'_>> {
        match self {
            Self::Domain(native) | Self::Maintenance(native) => native.as_ref(),
        }
    }
}
#[derive(Clone)]
struct Attempt {
    owner: ClientId,
    peer: PeerId,
    queue: u32,
    route: u64,
    message_id: [u8; 8],
    retired: bool,
    remote_record: Option<u64>,
    expires: u64,
    bytes: usize,
}
const RETRY: u64 = 1_000_000;
const FLOW_MIN: u64 = 100_000;
const FLOW_KEEPALIVE: u64 = 150_000_000;
const UNCONFIRMED: u64 = 300_000_000;
const LIVENESS: u64 = 900_000_000;
/// One process-level protocol engine: shared service owners, independent peers.
pub struct Engine {
    dv_bridge: dv_bridge::Book,
    burst: burst::Book,
    monitor: monitor::Book,
    instance: Arc<()>,
    identity: PeerId,
    limits: Limits,
    serial: u64,
    route_serial: u64,
    message_serial: u64,
    job_serial: u64,
    ack_serial: u64,
    remote_acks: Book,
    retransmissions: u64,
    expired_messages: u64,
    expired_attempts: u64,
    ignored_local_callbacks: u64,
    fragment_seed: Option<u64>,
    fragment_serial: u64,
    clients: Vec<Client>,
    demands: crate::application::Demands,
    address_creates: Vec<AddressCreate>,
    local_addresses: crate::addresses::Book,
    signing: crate::signing::Requests,
    address_create_bytes: usize,
    address_create_serial: u32,
    routes: Vec<Route>,
    peers: Vec<Peer>,
    jobs: VecDeque<Job>,
    assemblies: Vec<Assembly>,
    held: VecDeque<Held>,
    attempts: Vec<Attempt>,
    completed: VecDeque<Attempt>,
    output: VecDeque<Output>,
    buffered: usize,
    last_monotonic: u64,
    wire_monotime: u64,
    sender_ranges: crate::monotime::Book,
    dropped: u64,
    backchannel_dropped: u64,
    last_backchannel_drop: Option<Error>,
    last_remote_drop: Option<RemoteDrop>,
    validations: u64,
}
fn copy(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(input.len())
        .map_err(|_| Error::Capacity)?;
    v.extend_from_slice(input);
    Ok(v)
}
fn message(kind: u16, size: usize) -> Result<Vec<u8>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(size).map_err(|_| Error::Capacity)?;
    v.resize(size, 0);
    p2p::header(&mut v, kind, size)?;
    Ok(v)
}
impl Engine {
    /// Reserve bounded metadata for direct reliable or acknowledged queues.
    /// No OS resources or global services are opened. Original local callbacks
    /// and remote acknowledgement records have separate finite ownership.
    pub fn new(identity: PeerId, limits: Limits) -> Result<Self, Error> {
        if limits.clients == 0
            || limits.queues == 0
            || limits.peers == 0
            || limits.messages < 8
            || limits.bytes < 65535
            || limits.control_messages == 0
            || limits.control_bytes < 120
            || limits.assemblies == 0
            || limits.assemblies_per_peer == 0
        {
            return Err(Error::InvalidInput);
        }
        let queue_limit = limits
            .messages
            .checked_add(limits.control_messages)
            .ok_or(Error::Capacity)?;
        limits
            .bytes
            .checked_add(limits.control_bytes)
            .ok_or(Error::Capacity)?;
        limits
            .messages
            .checked_mul(usize::from(u16::MAX).div_ceil(8))
            .ok_or(Error::Capacity)?;
        let instance = Arc::new(());
        let mut value = Self {
            dv_bridge: dv_bridge::Book::new(limits)?,
            burst: burst::Book::new(limits.peers),
            monitor: monitor::Book::new(limits)?,
            instance: instance.clone(),
            identity,
            limits,
            serial: 0,
            route_serial: 0,
            message_serial: 0,
            job_serial: 0,
            ack_serial: 0,
            remote_acks: Book::new(limits.messages)?,
            retransmissions: 0,
            expired_messages: 0,
            expired_attempts: 0,
            ignored_local_callbacks: 0,
            fragment_seed: None,
            fragment_serial: 0,
            clients: Vec::new(),
            demands: crate::application::Demands::new(limits.peers)?,
            address_creates: Vec::new(),
            local_addresses: crate::addresses::Book::new(
                instance.clone(),
                limits.control_messages,
                limits.control_bytes,
            )?,
            signing: crate::signing::Requests::new(
                instance.clone(),
                limits.control_messages,
                limits.control_bytes,
            )?,
            address_create_bytes: 0,
            address_create_serial: 0,
            routes: Vec::new(),
            peers: Vec::new(),
            jobs: VecDeque::new(),
            assemblies: Vec::new(),
            held: VecDeque::new(),
            attempts: Vec::new(),
            completed: VecDeque::new(),
            output: VecDeque::new(),
            buffered: 0,
            last_monotonic: 0,
            wire_monotime: 0,
            sender_ranges: crate::monotime::Book::new(instance),
            dropped: 0,
            backchannel_dropped: 0,
            last_backchannel_drop: None,
            last_remote_drop: None,
            validations: 0,
        };
        value
            .clients
            .try_reserve_exact(limits.clients)
            .map_err(|_| Error::Capacity)?;
        value
            .routes
            .try_reserve_exact(limits.queues)
            .map_err(|_| Error::Capacity)?;
        value
            .peers
            .try_reserve_exact(limits.peers)
            .map_err(|_| Error::Capacity)?;
        value
            .assemblies
            .try_reserve_exact(limits.assemblies)
            .map_err(|_| Error::Capacity)?;
        value
            .jobs
            .try_reserve_exact(queue_limit)
            .map_err(|_| Error::Capacity)?;
        value
            .held
            .try_reserve_exact(limits.messages)
            .map_err(|_| Error::Capacity)?;
        value
            .attempts
            .try_reserve_exact(queue_limit)
            .map_err(|_| Error::Capacity)?;
        value
            .completed
            .try_reserve_exact(queue_limit)
            .map_err(|_| Error::Capacity)?;
        value
            .output
            .try_reserve_exact(queue_limit)
            .map_err(|_| Error::Capacity)?;
        value
            .address_creates
            .try_reserve_exact(limits.control_messages)
            .map_err(|_| Error::Capacity)?;
        Ok(value)
    }
    /// Current dirty aggregate, borrowed until a real PILS operation copies it.
    pub fn address_publication(&self) -> Result<Option<crate::addresses::Publication<'_>>, Error> {
        self.local_addresses.publication()
    }
    /// Current physical resource set even after its aggregate FEED is settled.
    /// A cached HELLO cannot manufacture one of these original ADD leases.
    pub fn local_addresses(&self) -> impl Iterator<Item = crate::addresses::LocalAddress<'_>> {
        self.local_addresses.records()
    }
    /// Whether the exact original ADD still belongs to this engine.
    pub fn owns_local_address(&self, lease: &crate::addresses::AddressLease) -> bool {
        self.local_addresses.contains(lease)
    }
    /// Immutable aggregate view independently of whether an original FEED is
    /// pending or settled. Its id changes only when the aggregate URI set changes.
    pub fn address_snapshot(&self) -> Result<crate::addresses::Publication<'_>, Error> {
        self.local_addresses.snapshot()
    }
    /// Compare operational address claims with the current local resource set.
    /// This comparison grants no peer/address authentication or dial authority.
    pub fn addresses_match(&self, hello: gnunet_hello::Hello<'_>) -> bool {
        self.local_addresses.matches(hello)
    }
    /// Explicitly publish the current resource set (including empty) under a new
    /// enclosing identity epoch or refresh. This is a new effect, not old-body replay.
    pub fn refresh_address_publication(&mut self) -> Result<(), Error> {
        self.local_addresses.refresh()
    }
    /// Claim only after the original current-PILS operation is actually admitted.
    pub fn claim_address_publication(
        &mut self,
        id: &crate::addresses::PublicationId,
    ) -> Result<(), Error> {
        self.local_addresses.claim(id)
    }
    /// Record only the original local full write, never remote application/durability.
    /// A newer current aggregate remains pending after this older write settles.
    pub fn address_publication_written(
        &mut self,
        id: &crate::addresses::PublicationId,
    ) -> Result<(), Error> {
        self.local_addresses.written(id)
    }
    /// Admit a new physical connection with no protocol role yet.
    pub fn accept(&mut self) -> Result<ClientId, Error> {
        if self.clients.len() == self.limits.clients {
            return Err(Error::Capacity);
        }
        self.serial = self.serial.checked_add(1).ok_or(Error::Overflow)?;
        let id = ClientId {
            instance: self.instance.clone(),
            serial: self.serial,
        };
        self.clients.push(Client {
            id: id.clone(),
            role: Role::Unregistered,
            reliable: false,
            payload: false,
            prefix: None,
            can_burst: false,
        });
        Ok(id)
    }
    fn client(&self, id: &ClientId) -> Result<usize, Error> {
        self.clients
            .iter()
            .position(|v| &v.id == id)
            .ok_or(Error::Stale)
    }
    /// Preflight an explicitly shared-coordinate embedding profile. This does
    /// not infer an absolute clock from a genuinely independent monotonic one.
    pub fn validate_time(&self, now: u64) -> Result<(), Error> {
        self.validate_times(Times::shared_coordinate(now))
    }
    /// Preflight both finite clock inputs before native IO without advancing
    /// state. Only the local monotonic coordinate is required not to regress;
    /// legitimate absolute-time correction cannot retire a valid mono lease.
    pub fn validate_times(&self, times: Times) -> Result<(), Error> {
        times.validate()?;
        if times.monotonic().0 < self.last_monotonic {
            Err(Error::TimeUncertain)
        } else {
            Ok(())
        }
    }
    /// Last committed local monotonic scheduling coordinate, without a source
    /// authorization claim or conversion to an absolute record expiration.
    #[must_use]
    pub const fn monotonic_now(&self) -> MonoInstant {
        MonoInstant(self.last_monotonic)
    }
    fn time_at(&mut self, times: Times) -> Result<(), Error> {
        self.validate_times(times)?;
        self.last_monotonic = times.monotonic().0;
        self.monitor.invalidate();
        Ok(())
    }
    /// Configure the finite original storage demand budget before first use.
    /// A host without a durable provider safely defers FLOW; no RAM fallback
    /// or restart floor is manufactured by this library.
    pub fn configure_monotime(&mut self, policy: crate::monotime::Policy) -> Result<(), Error> {
        self.sender_ranges.configure(policy)
    }
    /// Current original Engine-branded demand for a genuinely persisted span.
    pub fn monotime_demand(&self) -> Option<&crate::monotime::Demand> {
        self.sender_ranges.demand()
    }
    /// Read-only representation; this is not a persistence receipt.
    pub fn monotime_state(&self) -> crate::monotime::State {
        self.sender_ranges.state()
    }
    /// Install only a matching original provider result. The caller owns the
    /// actual durable-commit assurance; numeric endpoints alone do not prove it.
    pub fn supply_monotime(
        &mut self,
        id: &crate::monotime::DemandId,
        span: crate::monotime::Span,
        times: Times,
    ) -> Result<(), Error> {
        self.validate_times(times)?;
        self.sender_ranges
            .install(id, span, times, self.wire_monotime)?;
        self.time_at(times)?;
        for peer in &mut self.peers {
            if peer.flow_waiting_range {
                peer.flow_next = peer.flow_next.min(times.monotonic().0);
                peer.flow_waiting_range = false;
            }
        }
        Ok(())
    }
    /// Retire only the exact original demand; never renew its deadlines.
    pub fn retire_monotime(&mut self, id: &crate::monotime::DemandId) -> Result<(), Error> {
        self.sender_ranges.retire(id)
    }
    /// Burn an actually committed but unusable original span, never grant it.
    pub fn burn_monotime(
        &mut self,
        id: &crate::monotime::DemandId,
        span: crate::monotime::Span,
    ) -> Result<(), Error> {
        self.sender_ranges.burn(id, span)
    }
    fn stamp(&mut self, times: Times) -> Result<Option<u64>, Error> {
        self.sender_ranges.next(&mut self.wire_monotime, times)
    }
    fn emit(&mut self, client: ClientId, bytes: Vec<u8>) -> Result<(), Error> {
        if self.output.len() >= self.limits.messages + self.limits.control_messages {
            return Err(Error::Capacity);
        }
        self.output.push_back(Output::Frame { client, bytes });
        Ok(())
    }
    fn remove_address_create(&mut self, index: usize) {
        let request = self.address_creates.remove(index);
        self.address_create_bytes -= request.address.len();
    }
    fn expire_address_creates(&mut self, now: u64) {
        let mut i = 0;
        while i < self.address_creates.len() {
            if self.address_creates[i].expires <= now {
                self.remove_address_create(i);
            } else {
                i += 1;
            }
        }
    }
    fn validate_address(
        &mut self,
        request: crate::application::ValidateAddress<'_>,
        now: u64,
    ) -> Result<crate::application::AddressAdmission, Error> {
        use crate::application::AddressAdmission;
        // Official application_validate has no result and may decline work due
        // to pressure or a recent attempt. A hint never creates a validated route.
        let Some(separator) = request.address.iter().position(|b| *b == b'-') else {
            return Ok(AddressAdmission::Unsupported);
        };
        let Some(owner) = self
            .clients
            .iter()
            .find(|c| {
                c.role == Role::Communicator
                    && c.prefix.as_deref() == Some(&request.address[..separator])
            })
            .map(|c| c.id.clone())
        else {
            return Ok(AddressAdmission::Unsupported);
        };
        if request.peer == self.identity {
            return Ok(AddressAdmission::Unsupported);
        }
        if self
            .routes
            .iter()
            .any(|r| r.description.peer == request.peer && r.address == request.address)
            || self
                .address_creates
                .iter()
                .any(|r| r.owner == owner && r.peer == request.peer && r.address == request.address)
        {
            return Ok(AddressAdmission::Existing);
        }
        if request.address.len() > self.limits.control_bytes {
            return Ok(AddressAdmission::Declined(Error::Capacity));
        }
        if self.address_creates.len() == self.limits.control_messages
            || request.address.len()
                > self
                    .limits
                    .control_bytes
                    .saturating_sub(self.address_create_bytes)
            || self.output.len() >= self.limits.messages + self.limits.control_messages
        {
            return Ok(AddressAdmission::Deferred);
        }
        let Some(serial) = self.address_create_serial.checked_add(1) else {
            return Ok(AddressAdmission::Declined(Error::Overflow));
        };
        let wire = serial.to_be_bytes();
        let address = copy(request.address)?;
        let mut output = message(1206, 41 + address.len())?;
        output[4..8].copy_from_slice(&wire);
        output[8..40].copy_from_slice(&request.peer.0);
        output[40..40 + address.len()].copy_from_slice(&address);
        self.emit(owner.clone(), output)?;
        self.address_create_serial = serial;
        self.address_create_bytes += address.len();
        self.address_creates.push(AddressCreate {
            owner,
            wire,
            peer: request.peer,
            address,
            expires: now.saturating_add(ADDRESS_CREATE_LIFETIME),
            accepted: false,
        });
        Ok(AddressAdmission::Issued)
    }
    /// Lease one fair original connection demand. The caller must drive its
    /// address source and complete the same lease; no native work occurs here.
    /// `now` explicitly selects Times::shared_coordinate; use discovery_at for independent clocks.
    pub fn discovery(&mut self, now: u64) -> Result<Option<crate::application::Discovery>, Error> {
        self.discovery_at(Times::shared_coordinate(now))
    }
    /// Lease a demand using an independent finite local scheduling coordinate.
    /// Address providers must check record expiry with `times.absolute()`.
    pub fn discovery_at(
        &mut self,
        times: Times,
    ) -> Result<Option<crate::application::Discovery>, Error> {
        let now = times.monotonic().0;
        self.time_at(times)?;
        self.demands.next(now, |peer| {
            self.peers.iter().any(|p| p.id == peer && p.connected)
        })
    }
    /// Whether the original application connection/request is still live.
    #[must_use]
    pub fn discovery_live(&self, id: &crate::application::Discovery) -> bool {
        self.demands.live(id)
    }
    /// Consider an untrusted address only for its original live peer/request.
    /// A late/foreign/canceled discovery cannot create work for a replacement.
    /// `now` asserts the shared-coordinate embedding profile; independent clocks use discovered_address_at.
    pub fn discovered_address(
        &mut self,
        id: &crate::application::Discovery,
        address: &[u8],
        now: u64,
    ) -> Result<crate::application::AddressAdmission, Error> {
        self.discovered_address_at(id, address, Times::shared_coordinate(now))
    }
    /// Admit a candidate only for its original live demand. Create/retry
    /// deadlines use local mono; the provider checks cache expiration with the
    /// independent absolute coordinate before offering these opaque bytes.
    pub fn discovered_address_at(
        &mut self,
        id: &crate::application::Discovery,
        address: &[u8],
        times: Times,
    ) -> Result<crate::application::AddressAdmission, Error> {
        let now = times.monotonic().0;
        if !self.demands.live(id) {
            return Err(Error::Stale);
        }
        self.time_at(times)?;
        if address.contains(&0) {
            return Err(Error::Malformed);
        }
        if address.len() > u16::MAX as usize - 41 {
            return Err(Error::TooLarge);
        }
        self.expire_address_creates(now);
        self.validate_address(
            crate::application::ValidateAddress {
                network: 0,
                peer: id.peer(),
                address,
            },
            now,
        )
    }
    /// Settle one source pass, retaining a bounded continuation position or
    /// scheduling another lookup for as long as this application still wants it.
    /// `now` asserts shared coordinates; use discovery_complete_at for independent clocks.
    pub fn discovery_complete(
        &mut self,
        id: &crate::application::Discovery,
        now: u64,
        cursor: usize,
        finished: bool,
    ) -> Result<(), Error> {
        self.discovery_complete_at(id, Times::shared_coordinate(now), cursor, finished)
    }
    /// Complete an original enumeration pass without mixing its local retry
    /// schedule with real cache expiration. Source ownership checks precede time.
    pub fn discovery_complete_at(
        &mut self,
        id: &crate::application::Discovery,
        times: Times,
        cursor: usize,
        finished: bool,
    ) -> Result<(), Error> {
        let now = times.monotonic().0;
        if !self.demands.live(id) {
            return Err(Error::Stale);
        }
        self.time_at(times)?;
        self.demands.complete(id, now, cursor, finished)
    }
    fn core_frame(&mut self, client: ClientId, response: CoreResponse<'_>) -> Result<(), Error> {
        let size = match response {
            CoreResponse::Received { message, .. } => 36 + message.len(),
            _ => 40,
        };
        let mut out = message(0, size)?;
        response.encode(&mut out)?;
        self.emit(client, out)
    }
    fn notify(&mut self, peer: PeerId, connected: bool) -> Result<(), Error> {
        for i in 0..self.clients.len() {
            if self.clients[i].role == Role::Core {
                let id = self.clients[i].id.clone();
                self.core_frame(
                    id,
                    if connected {
                        CoreResponse::Connected(peer)
                    } else {
                        CoreResponse::Disconnected(peer)
                    },
                )?;
            }
        }
        Ok(())
    }
    fn ensure_peer(&mut self, id: PeerId, now: u64) -> Result<usize, Error> {
        if id == self.identity {
            return Err(Error::Authentication);
        }
        if let Some(i) = self.peers.iter().position(|p| p.id == id) {
            return Ok(i);
        }
        if self.peers.len() == self.limits.peers {
            return Err(Error::Capacity);
        }
        let mut received = VecDeque::new();
        received
            .try_reserve_exact(self.limits.messages)
            .map_err(|_| Error::Capacity)?;
        let mut fragment_acks = VecDeque::new();
        fragment_acks
            .try_reserve_exact(64)
            .map_err(|_| Error::Capacity)?;
        self.peers.push(Peer {
            id,
            connected: false,
            liveness_expired: false,
            remote_sequence: None,
            remote_time: 0,
            remote_burst_rtt: u64::MAX,
            outbound_window: p2p::DEFAULT_WINDOW,
            outbound_used: 0,
            inbound_used: 0,
            inbound_released: 0,
            loss_anchor_sent: 0,
            loss_anchor_released: 0,
            ack_counter: 0,
            fragment_acks,
            flow_sequence: 0,
            flow_time: 0,
            monitor_last_flow: 0,
            monitor_incoming_window: 0,
            flow_next: now,
            flow_waiting_range: false,
            flow_dirty: true,
            last_inbound: now,
            rtt: 0,
            core_window: 4,
            received,
        });
        Ok(self.peers.len() - 1)
    }
    fn backchannel_drop(&mut self, reason: Error) {
        self.backchannel_dropped = self.backchannel_dropped.saturating_add(1);
        self.last_backchannel_drop = Some(reason);
    }
    fn control_room(&self, bytes: usize) -> bool {
        self.jobs.len() < self.limits.messages + self.limits.control_messages
            && bytes
                <= (self.limits.bytes + self.limits.control_bytes).saturating_sub(self.buffered)
    }
    fn control_route_fits(&self, peer: PeerId, bytes: usize) -> bool {
        self.routes.iter().any(|q| {
            q.description.peer == peer
                && bytes <= (q.description.mtu as usize).min(communicator::MAX_INCOMING_MESSAGE_LEN)
        }) || self
            .dv_bridge
            .virtual_path(peer, self.last_monotonic)
            .is_some_and(|(_, mtu)| bytes <= mtu)
    }
    fn enqueue(
        &mut self,
        route: Option<u64>,
        peer: PeerId,
        input: &[u8],
        core: Option<ClientId>,
        control: bool,
    ) -> Result<(), Error> {
        let extra_messages = if control {
            self.limits.control_messages
        } else {
            0
        };
        let extra_bytes = if control {
            self.limits.control_bytes
        } else {
            0
        };
        if self.jobs.len() >= self.limits.messages + extra_messages
            || self
                .buffered
                .checked_add(input.len())
                .ok_or(Error::Overflow)?
                > self.limits.bytes + extra_bytes
        {
            return Err(Error::Capacity);
        }
        let job_id = self.job_serial.checked_add(1).ok_or(Error::Overflow)?;
        let expires = if control {
            u64::MAX
        } else {
            self.last_monotonic
                .checked_add(outbound::RETENTION)
                .filter(|n| *n != u64::MAX)
                .ok_or(Error::Overflow)?
        };
        let message = copy(input)?;
        self.buffered += message.len();
        self.job_serial = job_id;
        self.jobs.push_back(Job {
            id: job_id,
            preferences: 0,
            coverage: None,
            whole_sent: false,
            expires,
            deferred: None,
            route,
            peer,
            message: Zeroizing::new(message),
            fragment: None,
            origin: core.clone(),
            core,
            control,
        });
        Ok(())
    }
    fn ack(&mut self, owner: ClientId, peer: PeerId, id: [u8; 8]) -> Result<(), Error> {
        let mut out = message(1203, 48)?;
        out[8..16].copy_from_slice(&id);
        out[16..48].copy_from_slice(&peer.0);
        self.emit(owner, out)
    }
    /// Process one complete local frame. Local role/framing errors belong to this
    /// connection; remote malformed frames are acknowledged/dropped in isolation.
    /// `now` asserts shared coordinates; independent clocks must use receive_at.
    pub fn receive(
        &mut self,
        id: &ClientId,
        input: &[u8],
        now: u64,
        signer: &mut impl Signer,
        entropy: &mut impl Entropy,
    ) -> Result<ReceiveOutcome, Error> {
        self.receive_at(id, input, Times::shared_coordinate(now), signer, entropy)
    }
    /// Process an actual original local frame with independent clock inputs.
    /// Mono owns every scheduling/RTT/retention comparison; actual absolute
    /// owns the successful validation's exact cache expiration. Original source,
    /// role, opaque-message and signature boundaries are unchanged.
    pub fn receive_at(
        &mut self,
        id: &ClientId,
        input: &[u8],
        times: Times,
        signer: &mut impl Signer,
        entropy: &mut impl Entropy,
    ) -> Result<ReceiveOutcome, Error> {
        self.receive_inner(id, input, times, signer, entropy, ReceiveMode::Domain(None))
    }
    /// Process one original raw DV communicator input without keeping the MQ
    /// head parked while Actor capacity is unavailable. The existing bounded
    /// inbox/held owners retain its original FC token and first-byte targets.
    pub fn receive_dv_at(
        &mut self,
        input: dv_bridge::NativeInput<'_>,
        times: Times,
        signer: &mut impl Signer,
        entropy: &mut impl Entropy,
    ) -> Result<ReceiveOutcome, Error> {
        self.check_native_input(&input, times)?;
        self.receive_inner(
            input.owner,
            input.bytes,
            times,
            signer,
            entropy,
            ReceiveMode::Domain(Some(input)),
        )
    }
    fn check_native_input(
        &self,
        input: &dv_bridge::NativeInput<'_>,
        times: Times,
    ) -> Result<(), Error> {
        self.validate_times(times)?;
        self.dv_check_source(input.source)?;
        if input.until.0 == u64::MAX
            || times.monotonic().0 >= input.until.0
            || input.absolute_until.as_micros() == u64::MAX
            || times.absolute() >= input.absolute_until
        {
            return Err(Error::Deadline);
        }
        let communicator::Request::Incoming {
            flow_control,
            flow_id,
            peer,
            message,
            ..
        } = communicator::Request::decode(input.bytes)?
        else {
            return Err(Error::Unsupported);
        };
        if !matches!(
            Frame::decode(message)?.header().message_type().value(),
            crate::dv::LEARN_TYPE | crate::dv::BOX_TYPE
        ) {
            return Err(Error::Unsupported);
        }
        // A duplicate token cannot acquire a second debt or acknowledge away
        // the original retained envelope. Refuse before any shared mutation.
        if flow_control && self.dv_flow_in_use(input.owner, peer, flow_id) {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn receive_inner(
        &mut self,
        id: &ClientId,
        input: &[u8],
        times: Times,
        signer: &mut impl Signer,
        entropy: &mut impl Entropy,
        mode: ReceiveMode<'_>,
    ) -> Result<ReceiveOutcome, Error> {
        let native = mode.native();
        let now = times.monotonic().0;
        // Preserve clock-error preflight without letting rejected ownership or
        // signing authority commit shared logical time for another live owner.
        self.validate_times(times)?;
        if signer.identity() != self.identity {
            return Err(Error::Authentication);
        }
        let client = self.client(id)?;
        self.time_at(times)?;
        self.burst_maintenance(times)?;
        self.expire_address_creates(now);
        let kind = Frame::decode(input)?.header().message_type().value();
        if matches!(kind, 1250 | 1255) {
            if kind == 1255 {
                return self.receive_links_at(id, input, times, signer, monitor::Links::direct());
            }
            return self.monitor_start(
                id,
                gnunet_wire::official::transport_monitor::Request::decode(input)?,
            );
        }
        if self.clients[client].role == Role::Monitor {
            return Err(Error::PermissionDenied);
        }
        if self.clients[client].role == Role::Core || kind == 360 {
            let request = CoreRequest::decode(input)?;
            match request {
                CoreRequest::Start(start) => {
                    if self.clients[client].role != Role::Unregistered {
                        return Err(Error::Malformed);
                    }
                    if start.options & 1 != 0 && start.identity != self.identity {
                        return Err(Error::Authentication);
                    }
                    self.clients[client].role = Role::Core;
                    self.clients[client].payload = start.options & 2 != 0;
                    for i in 0..self.peers.len() {
                        if self.peers[i].connected {
                            self.core_frame(id.clone(), CoreResponse::Connected(self.peers[i].id))?;
                        }
                    }
                }
                CoreRequest::Send {
                    peer,
                    message,
                    priority,
                } => {
                    if self.clients[client].role != Role::Core {
                        return Err(Error::PermissionDenied);
                    }
                    if self.peers.iter().any(|p| p.id == peer && p.connected) {
                        self.enqueue(None, peer, message, Some(id.clone()), false)?;
                        if let Some(job) = self.jobs.back_mut() {
                            job.preferences = priority;
                        }
                    } else {
                        self.core_frame(id.clone(), CoreResponse::SendCredit(peer))?;
                    }
                }
                CoreRequest::ReceiveContinue { peer, increase } => {
                    if self.clients[client].role != Role::Core {
                        return Err(Error::PermissionDenied);
                    }
                    if let Some(p) = self.peers.iter().position(|p| p.id == peer) {
                        // RECV_OK is an aggregate window delta on this physical
                        // CORE MQ, not an operation-id or a delivery proof. A late
                        // delta for a lost/unconfirmed link is explicitly ignored.
                        if self.peers[p].connected {
                            self.peers[p].core_window = self.peers[p]
                                .core_window
                                .checked_add(i64::from(increase))
                                .ok_or(Error::Overflow)?;
                            let available = self.peers[p]
                                .received
                                .iter()
                                .filter(|r| r.capacity_users.contains(id))
                                .count();
                            let release = available
                                .min(usize::try_from(increase).map_err(|_| Error::Overflow)?);
                            for _ in 0..release {
                                let r = self.peers[p]
                                    .received
                                    .iter()
                                    .position(|r| r.capacity_users.contains(id))
                                    .ok_or(Error::Stale)?;
                                self.peers[p].received[r].capacity_users.retain(|c| c != id);
                                if self.peers[p].received[r].capacity_users.is_empty() {
                                    let receipt =
                                        self.peers[p].received.remove(r).ok_or(Error::Stale)?;
                                    self.peers[p].inbound_released = self.peers[p]
                                        .inbound_released
                                        .checked_add(receipt.size as u64)
                                        .ok_or(Error::Overflow)?;
                                    self.buffered -= receipt.size;
                                    if let Some((owner, token)) = receipt.ack {
                                        self.ack(owner, peer, token)?;
                                    }
                                }
                            }
                            self.peers[p].flow_dirty = true;
                            self.release_callbacks(p)?;
                        }
                    }
                }
            }
        } else if self.clients[client].role == Role::Application || matches!(kind, 1300..=1302) {
            if kind == 1302 {
                let request = crate::application::ValidateAddress::decode(input)?;
                let _admission = self.validate_address(request, now)?;
            } else {
                if !matches!(
                    self.clients[client].role,
                    Role::Unregistered | Role::Application
                ) {
                    return Err(Error::PermissionDenied);
                }
                let (preference, cancel) = crate::application::Preference::decode(input)?;
                if cancel {
                    self.demands.cancel(id, preference.peer)?;
                } else if preference.peer != self.identity {
                    self.demands.add(id.clone(), preference, now)?;
                }
            }
            if self.clients[client].role == Role::Unregistered {
                self.clients[client].role = Role::Application;
            }
        } else {
            let request = communicator::Request::decode(input)?;
            if let communicator::Request::Register {
                characteristics,
                prefix,
                can_burst,
            } = request
            {
                if self.clients[client].role != Role::Unregistered {
                    return Err(Error::Malformed);
                }
                // A registered receive-only communicator has the empty C
                // prefix, distinct from an unregistered/missing prefix. It may
                // still receive a backchannel addressed to that exact word.
                self.clients[client].prefix = Some(copy(prefix)?);
                self.clients[client].role = Role::Communicator;
                self.clients[client].can_burst = can_burst;
                self.clients[client].reliable =
                    characteristics == communicator::Characteristics::Reliable;
            } else {
                if self.clients[client].role != Role::Communicator {
                    return Err(Error::PermissionDenied);
                }
                match request {
                    communicator::Request::QueueSetup { queue, address } => {
                        if queue.mtu <= 32 {
                            return Err(Error::Unsupported);
                        }
                        if self.routes.len() == self.limits.queues
                            || self.routes.iter().any(|q| {
                                q.owner == *id
                                    && q.description.peer == queue.peer
                                    && q.description.id == queue.id
                            })
                        {
                            return Err(Error::Capacity);
                        }
                        self.ensure_peer(queue.peer, now)?;
                        let mut nonce = [0; 32];
                        entropy.fill(&mut nonce)?;
                        self.route_serial =
                            self.route_serial.checked_add(1).ok_or(Error::Overflow)?;
                        let route = self.route_serial;
                        let route_index = self.routes.len();
                        let inherited = self
                            .routes
                            .iter()
                            .filter(|q| q.description.peer == queue.peer && q.valid_until > now)
                            .map(|q| q.valid_until)
                            .max()
                            .unwrap_or(0);
                        self.routes.push(Route {
                            owner: id.clone(),
                            description: queue,
                            address: copy(address)?,
                            serial: route,
                            nonce,
                            challenge_pending: true,
                            challenge_first: now,
                            challenge_last: now,
                            challenge_next: now.saturating_add(RETRY),
                            challenge_not_before: 0,
                            valid_until: inherited,
                            monitor_last_validation: 0,
                            monitor_valid_until: 0,
                            monitor_next_validation: monitor::next_absolute(times, RETRY),
                            monitor_rtt: None,
                            inflight: 0,
                            available: queue.length,
                            unlimited: queue.length == u64::MAX,
                        });
                        if let Some(i) = self.address_creates.iter().position(|r| {
                            r.owner == *id && r.peer == queue.peer && r.address == address
                        }) {
                            self.remove_address_create(i);
                        }
                        if queue.mtu >= 48 && queue.length > 0 {
                            self.enqueue_challenge(route_index, times)?;
                        }
                    }
                    communicator::Request::QueueUpdate(queue) => {
                        if queue.mtu <= 32 {
                            return Err(Error::Unsupported);
                        }
                        let q = self
                            .routes
                            .iter_mut()
                            .find(|q| {
                                q.owner == *id
                                    && q.description.peer == queue.peer
                                    && q.description.id == queue.id
                            })
                            .ok_or(Error::Stale)?;
                        let (available, unlimited) = if queue.length == u64::MAX {
                            (u64::MAX, true)
                        } else {
                            let Some(available) = q.available.checked_add(queue.length) else {
                                return Ok(ReceiveOutcome::Rejected(QueueRejection {
                                    client: id.clone(),
                                    peer: queue.peer,
                                    queue: queue.id,
                                    reason: Error::Overflow,
                                }));
                            };
                            (available, false)
                        };
                        let previously_usable =
                            q.description.mtu >= 48 && (q.unlimited || q.available > 0);
                        q.description = queue;
                        q.available = available;
                        q.unlimited = unlimited;
                        if !previously_usable
                            && queue.mtu >= 48
                            && queue.length > 0
                            && q.valid_until <= now
                        {
                            // Packet credit recovery does not invalidate an
                            // already checked address or advance its renewal.
                            q.schedule_challenge(times, now);
                            if q.valid_until == 0
                                && now.saturating_sub(q.challenge_first) > UNCONFIRMED
                            {
                                q.challenge_pending = false;
                                q.challenge_first = now;
                                q.challenge_last = now;
                            }
                        }
                    }
                    communicator::Request::QueueDown { peer, id: qid } => {
                        self.route_down(id, peer, qid)?
                    }
                    communicator::Request::Incoming {
                        flow_control,
                        flow_id,
                        validity,
                        peer,
                        message,
                        ..
                    } => {
                        let mut reassembled = None;
                        let mut until = now
                            .checked_add(crate::fragment::EXPIRY)
                            .ok_or(Error::Overflow)?;
                        if let Some(original) = &native {
                            until = until.min(original.until.0);
                        }
                        let mut diverted = false;
                        let result = match self.network(id, peer, message, validity, times, signer)
                        {
                            Ok(NetworkStep::LocalFailure(error)) => return Err(error),
                            Ok(NetworkStep::Processed(hold)) => Ok(hold),
                            Ok(NetworkStep::Diverted) => {
                                diverted = true;
                                Ok(false)
                            }
                            Ok(NetworkStep::OwnedMessage(body, original_until)) => {
                                until = until.min(original_until);
                                reassembled = Some(body);
                                // The assembly has left the table before an
                                // inner handler can change link state. Its
                                // exact owned body remains alive for dispatch.
                                match self.network(
                                    id,
                                    peer,
                                    reassembled.as_deref().ok_or(Error::Stale)?,
                                    validity,
                                    times,
                                    signer,
                                ) {
                                    Ok(NetworkStep::LocalFailure(error)) => return Err(error),
                                    Ok(NetworkStep::Processed(hold)) => Ok(hold),
                                    Ok(NetworkStep::OwnedMessage(_, _)) => Err(Error::Malformed),
                                    Ok(NetworkStep::Diverted) => {
                                        diverted = true;
                                        Ok(false)
                                    }
                                    Err(error) => Err(error),
                                }
                            }
                            Err(error) => Err(error),
                        };
                        let retained = reassembled.as_deref().map_or(message, |b| b.as_slice());
                        match result {
                            Ok(hold) => {
                                if diverted {
                                    let source = match &native {
                                        Some(original) => original.source.clone(),
                                        None => {
                                            self.dv_current_source().ok_or(Error::Stale)?.clone()
                                        }
                                    };
                                    // Explicit native inputs cannot migrate to
                                    // a different Actor/source during dispatch.
                                    self.dv_check_source(&source)?;
                                    let held = Held {
                                        dv: Some(dv_bridge::HeldSource {
                                            source,
                                            until,
                                            absolute_until: native
                                                .as_ref()
                                                .map(|original| original.absolute_until),
                                        }),
                                        owner: id.clone(),
                                        peer,
                                        message: match reassembled.take() {
                                            Some(body) => body,
                                            None => Zeroizing::new(copy(message)?),
                                        },
                                        token: flow_control.then_some(flow_id),
                                    };
                                    if let Err(refused) = self.dv_stage_inbox(held) {
                                        let held = refused.value;
                                        if matches!(
                                            refused.reason,
                                            Error::WouldBlock | Error::NotReady
                                        ) && self.held.len() < self.limits.messages
                                            && self.held.iter().filter(|h| h.peer == peer).count()
                                                < 16
                                            && self
                                                .buffered
                                                .checked_add(held.message.len())
                                                .is_some_and(|n| n <= self.limits.bytes)
                                        {
                                            self.buffered += held.message.len();
                                            self.held.push_back(held);
                                        } else {
                                            self.dropped = self.dropped.saturating_add(1);
                                            if let Some(token) = held.token {
                                                self.ack(held.owner, held.peer, token)?;
                                            }
                                        }
                                    }
                                } else if flow_control && hold {
                                    let p = self
                                        .peers
                                        .iter_mut()
                                        .find(|p| p.id == peer)
                                        .ok_or(Error::Stale)?;
                                    let last = p.received.back_mut().ok_or(Error::Stale)?;
                                    last.ack = Some((id.clone(), flow_id));
                                } else if flow_control {
                                    self.ack(id.clone(), peer, flow_id)?;
                                }
                            }
                            Err(Error::WouldBlock | Error::NotReady) => {
                                let unconfirmed = result == Err(Error::NotReady);
                                let per_peer = self.held.iter().filter(|h| h.peer == peer).count();
                                if per_peer >= 16
                                    || self.held.len() == self.limits.messages
                                    || self
                                        .buffered
                                        .checked_add(retained.len())
                                        .ok_or(Error::Overflow)?
                                        > self.limits.bytes
                                {
                                    self.dropped = self.dropped.saturating_add(1);
                                    if flow_control {
                                        self.ack(id.clone(), peer, flow_id)?;
                                    }
                                } else {
                                    self.held.push_back(Held {
                                        dv: None,
                                        owner: id.clone(),
                                        peer,
                                        message: match reassembled.take() {
                                            Some(body) => body,
                                            None => Zeroizing::new(copy(message)?),
                                        },
                                        token: (flow_control && !unconfirmed).then_some(flow_id),
                                    });
                                    self.buffered +=
                                        self.held.back().ok_or(Error::Stale)?.message.len();
                                    if flow_control && unconfirmed {
                                        self.ack(id.clone(), peer, flow_id)?;
                                    }
                                }
                            }
                            Err(Error::Capacity) => return Err(Error::Capacity),
                            Err(reason) => {
                                self.dropped = self.dropped.saturating_add(1);
                                self.last_remote_drop = Some(RemoteDrop {
                                    peer,
                                    message_type: Frame::decode(retained)
                                        .map(|f| f.header().message_type().value())
                                        .unwrap_or(0),
                                    reason,
                                });
                                if flow_control {
                                    self.ack(id.clone(), peer, flow_id)?;
                                }
                            }
                        }
                    }
                    communicator::Request::Sent {
                        message_id,
                        queue,
                        peer,
                        status,
                    } => {
                        self.dv_bridge.sent(id, peer, queue, message_id, status);
                        let original = |a: &Attempt| {
                            a.owner == *id
                                && a.peer == peer
                                && a.queue == queue
                                && a.message_id == message_id
                        };
                        if let Some(i) = self.attempts.iter().position(original) {
                            let attempt = self.attempts.remove(i);
                            if let Some(record) = attempt.remote_record {
                                self.remote_acks.local_done(record, attempt.message_id);
                            }
                            if !attempt.retired {
                                if let Some(q) =
                                    self.routes.iter_mut().find(|q| q.serial == attempt.route)
                                {
                                    q.inflight =
                                        q.inflight.checked_sub(1).ok_or(Error::Overflow)?;
                                }
                                if status != 1 {
                                    self.route_down(id, peer, queue)?;
                                }
                            }
                            if self.completed.len() == self.limits.messages {
                                self.completed.pop_front();
                            }
                            self.completed.push_back(attempt);
                        } else if !self.completed.iter().any(original) {
                            if self
                                .attempts
                                .iter()
                                .chain(self.completed.iter())
                                .any(|a| a.message_id == message_id)
                            {
                                // A known MID belongs to a different original
                                // owner/peer/queue; it has no authority here.
                                return Err(Error::Stale);
                            }
                            // A delayed callback may outlive its bounded
                            // tombstone or old physical owner. Unknown IDs do
                            // not mutate a replacement or close a shared MQ.
                            self.ignored_local_callbacks =
                                self.ignored_local_callbacks.saturating_add(1);
                        }
                    }
                    communicator::Request::Backchannel {
                        peer,
                        message: inner,
                        communicator: target,
                    } => {
                        let size = 4usize
                            .checked_add(inner.len())
                            .and_then(|n| n.checked_add(target.len()))
                            .and_then(|n| n.checked_add(1))
                            .ok_or(Error::Overflow)?;
                        // The official backchannel is best effort. No route or
                        // no fitting direct control route creates no pending job.
                        if !self.control_route_fits(peer, size) {
                            self.backchannel_drop(Error::NotReady);
                        } else if !self.control_room(size) {
                            self.backchannel_drop(Error::Capacity);
                        } else {
                            let mut out = message(1213, size)?;
                            p2p::Backchannel {
                                message: inner,
                                communicator: target,
                            }
                            .encode(&mut out)?;
                            self.enqueue(None, peer, &out, None, true)?;
                        }
                    }
                    communicator::Request::Created {
                        request_id,
                        success,
                    } => {
                        if let Some(i) = self
                            .address_creates
                            .iter()
                            .position(|r| r.owner == *id && r.wire == request_id && !r.accepted)
                        {
                            if success {
                                self.address_creates[i].accepted = true;
                            } else {
                                self.remove_address_create(i);
                            }
                        }
                    }
                    communicator::Request::AddAddress {
                        id,
                        validity,
                        network,
                        address,
                    } => {
                        match self.local_addresses.add(
                            &self.clients[client].id,
                            id,
                            address,
                            network,
                            validity,
                        ) {
                            Ok(()) => {}
                            Err(Error::Capacity) => {
                                return Ok(ReceiveOutcome::AddressRejected(
                                    crate::addresses::AddressRejection {
                                        client: self.clients[client].id.clone(),
                                        address_id: id,
                                        reason: Error::Capacity,
                                    },
                                ));
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    communicator::Request::DeleteAddress(id) => {
                        self.local_addresses.remove(&self.clients[client].id, id)
                    }
                    communicator::Request::BurstFinished => {
                        if !self.burst_finished(id) {
                            self.ignored_local_callbacks =
                                self.ignored_local_callbacks.saturating_add(1);
                        }
                    }
                    communicator::Request::Register { .. } => return Err(Error::Malformed),
                }
            }
        }
        let status = match mode {
            ReceiveMode::Domain(_) => self.pump(now, entropy, false)?,
            ReceiveMode::Maintenance(_) => WorkStatus::Ready,
        };
        self.refresh_monitors();
        Ok(match status {
            WorkStatus::Ready => ReceiveOutcome::Accepted,
            WorkStatus::Deferred(reason) => ReceiveOutcome::WorkDeferred(reason),
        })
    }
    fn network(
        &mut self,
        owner: &ClientId,
        peer: PeerId,
        input: &[u8],
        validity: u64,
        times: Times,
        signer: &mut impl Signer,
    ) -> Result<NetworkStep, Error> {
        if !self
            .routes
            .iter()
            .any(|q| q.owner == *owner && q.description.peer == peer)
        {
            return Err(Error::Authentication);
        }
        self.network_peer(Some(owner), peer, input, validity, times, signer)
    }
    fn network_peer(
        &mut self,
        owner: Option<&ClientId>,
        peer: PeerId,
        input: &[u8],
        validity: u64,
        times: Times,
        signer: &mut impl Signer,
    ) -> Result<NetworkStep, Error> {
        let now = times.monotonic().0;
        let p = self.ensure_peer(peer, now)?;
        self.peers[p].last_inbound = now;
        self.peers[p].liveness_expired = false;
        match Frame::decode(input)?.header().message_type().value() {
            1303 => {
                let owner = owner.ok_or(Error::Unsupported)?;
                let challenge = Challenge::decode(input)?;
                if !self.control_route_fits(peer, 120) || !self.control_room(120) {
                    return Ok(NetworkStep::Processed(false));
                }
                let lifetime = validity.min(p2p::MAX_VALIDITY);
                if signer.validation_mode() == crate::signing::ValidationMode::Deferred {
                    let route = self
                        .routes
                        .iter()
                        .find(|q| q.owner == *owner && q.description.peer == peer)
                        .ok_or(Error::Stale)?
                        .serial;
                    self.signing.stage(crate::signing::Context {
                        owner: owner.clone(),
                        peer,
                        route,
                        signer: self.identity,
                        nonce: challenge.nonce,
                        origin: challenge.origin,
                        lifetime,
                        now,
                    })?;
                    return Ok(NetworkStep::Processed(false));
                }
                let signature = signer
                    .sign_validation(&Validation::signed_region(&challenge.nonce, lifetime))?;
                self.enqueue(
                    None,
                    peer,
                    &Validation {
                        signature,
                        nonce: challenge.nonce,
                        origin: challenge.origin,
                        validity: lifetime,
                    }
                    .encode(),
                    None,
                    true,
                )?;
            }
            1304 => {
                // A response may return through an authenticated DV BOX. Its
                // signature, challenge and origin still select the original
                // pending direct queue below; the carrier grants no route.
                let response = Validation::decode(input)?;
                response.verify(peer.0)?;
                let q = self
                    .routes
                    .iter()
                    .position(|q| {
                        q.description.peer == peer
                            && q.challenge_pending
                            && q.nonce == response.nonce
                            && q.challenge_first <= response.origin
                            && response.origin <= q.challenge_last
                    })
                    .ok_or(Error::Replay)?;
                // Official cache permission and local reachability validation
                // have different duration caps, as well as different clocks.
                let cache_lifetime = response.validity.min(p2p::MAX_VALIDITY);
                let lifetime = cache_lifetime.min(p2p::VALIDATION_INTERVAL);
                if lifetime == 0 {
                    return Err(Error::Authentication);
                }
                let until = match times.monotonic_after(RelativeTime::from_micros(lifetime)) {
                    Ok(value) => value.0,
                    Err(error) => return Ok(NetworkStep::LocalFailure(error)),
                };
                let cache_until =
                    match times.absolute_after(RelativeTime::from_micros(cache_lifetime)) {
                        Ok(value) => value,
                        Err(error) => return Ok(NetworkStep::LocalFailure(error)),
                    };
                if self.output.len() >= self.limits.messages {
                    return Err(Error::Capacity);
                }
                self.output.push_back(Output::Validated {
                    peer,
                    address: copy(&self.routes[q].address)?,
                    until: cache_until.as_micros(),
                });
                self.routes[q].valid_until = until;
                self.routes[q].monitor_last_validation = times.absolute().as_micros();
                self.routes[q].monitor_valid_until =
                    cache_until.as_micros() - cache_lifetime + lifetime;
                self.routes[q].monitor_rtt = Some(now.saturating_sub(response.origin));
                self.routes[q].schedule_challenge(times, until.saturating_sub(lifetime / 8));
                self.routes[q].challenge_pending = false;
                self.peers[p].rtt = now.saturating_sub(response.origin);
                self.validations = self.validations.saturating_add(1);
                if !self.peers[p].connected {
                    self.peers[p].connected = true;
                    self.notify(peer, true)?;
                }
                self.peers[p].flow_dirty = true;
            }
            1221 => {
                let update = Flow::decode(input)?;
                if update.sender_time < self.peers[p].remote_time {
                    return Err(Error::Replay);
                }
                // C computes used + (reported - used). Store unsigned anchors
                // instead: DEFAULT + reported + newly released bytes. This also
                // handles a legal reverse counter after the other direction reset.
                let outstanding = self.peers[p]
                    .inbound_used
                    .checked_sub(self.peers[p].inbound_released)
                    .ok_or(Error::Overflow)?;
                p2p::DEFAULT_WINDOW
                    .checked_add(update.outbound_sent)
                    .and_then(|n| n.checked_add(outstanding))
                    .ok_or(Error::Overflow)?;
                let reset = self.peers[p]
                    .remote_sequence
                    .is_some_and(|s| update.sequence < s);
                let changed = self.peers[p].outbound_window != update.inbound_window;
                let released = self.peers[p].inbound_released;
                self.peers[p].remote_sequence = Some(update.sequence);
                self.peers[p].remote_time = update.sender_time;
                self.peers[p].remote_burst_rtt = update.rtt;
                self.peers[p].loss_anchor_sent = update.outbound_sent;
                self.peers[p].loss_anchor_released = released;
                if reset {
                    self.peers[p].outbound_used = 0;
                }
                self.peers[p].outbound_window = update.inbound_window;
                // Burst readiness is synchronization metadata, not a FLOW
                // acknowledgement. Stable direct peers may remain not ready.
                if changed || update.outbound_window != self.inbound_window(p)? {
                    self.peers[p].flow_dirty = true;
                }
                if let Err(error) = self.burst_flow(peer, update, times) {
                    return Ok(NetworkStep::LocalFailure(error));
                }
            }
            1213 => {
                let envelope = p2p::Backchannel::decode(input)?;
                // Delivery goes to one currently registered target prefix, not
                // the network carrier or a remembered/disconnected client token.
                if let Some(target) = self.clients.iter().find(|c| {
                    c.role == Role::Communicator
                        && c.prefix.as_deref() == Some(envelope.communicator)
                }) {
                    let target = target.id.clone();
                    if self.output.len() >= self.limits.messages + self.limits.control_messages {
                        self.backchannel_drop(Error::Capacity);
                    } else {
                        let mut out = match message(1220, 40 + envelope.message.len()) {
                            Ok(out) => out,
                            Err(error) => return Ok(NetworkStep::LocalFailure(error)),
                        };
                        out[8..40].copy_from_slice(&peer.0);
                        out[40..].copy_from_slice(envelope.message);
                        self.output.push_back(Output::Frame {
                            client: target,
                            bytes: out,
                        });
                    }
                } else {
                    self.backchannel_drop(Error::NotFound);
                }
            }
            1214 => return self.fragment(p, peer, input, now),
            1216 => {
                let boxed = p2p::Reliable::decode(input)?;
                let inner = Frame::decode(boxed.message)?
                    .header()
                    .message_type()
                    .value();
                if matches!(inner, 1214 | 1216) {
                    return Err(Error::Unsupported);
                }
                let body = Zeroizing::new(copy(boxed.message)?);
                // Countdown is an upper bound, and the protocol permits an
                // earlier ACK. Keep the bounded immediate batching policy.
                if self.peers[p].fragment_acks.len() == 64 {
                    self.peers[p].fragment_acks.pop_front();
                }
                self.peers[p].fragment_acks.push_back(PendingAck {
                    id: boxed.uuid,
                    received: now,
                });
                return Ok(NetworkStep::OwnedMessage(
                    body,
                    now.checked_add(crate::fragment::EXPIRY)
                        .ok_or(Error::Overflow)?,
                ));
            }
            1217 => {
                for (delay, uuid) in p2p::acknowledgements(input)? {
                    let Some(ack) = self.remote_acks.acknowledged(peer, uuid, delay, now) else {
                        continue;
                    };
                    if let Some(job) = self
                        .jobs
                        .iter_mut()
                        .find(|j| j.id == ack.job && j.peer == peer)
                        && let Some(coverage) = job.coverage.as_mut()
                    {
                        coverage.mark(ack.span);
                        self.remote_acks.settled(job.id, coverage, ack.span, now);
                        if let Some(rtt) = ack.rtt {
                            self.peers[p].rtt = rtt;
                        }
                    }
                }
            }
            // These active network families remain explicit required branches;
            // refusing them never converts a control envelope into CORE plaintext.
            1218 | 1219 => {
                if owner.is_some() && self.dv_accepting() {
                    return Ok(NetworkStep::Diverted);
                }
                return Err(Error::Unsupported);
            }
            _ => return self.deliver(p, peer, input).map(NetworkStep::Processed),
        }
        Ok(NetworkStep::Processed(false))
    }
    fn deliver(&mut self, p: usize, peer: PeerId, input: &[u8]) -> Result<bool, Error> {
        if input.len() > 65535 - 36 {
            return Err(Error::TooLarge);
        }
        // Apply this at the final payload boundary, including bodies completed
        // by reliability/reassembly. Authenticated control traffic may precede
        // a usable reverse route, but cannot make CORE payloads bypass it.
        if !self.peers[p].connected || !self.payload_route_live(peer, self.last_monotonic) {
            return Err(Error::NotReady);
        }
        let new_used = self.peers[p]
            .inbound_used
            .checked_add(input.len() as u64)
            .ok_or(Error::Overflow)?;
        // Admit no payload whose eventual real release could overflow a grant
        // previously anchored by an untrusted peer report.
        self.window_after_release(p, new_used)?;
        let receivers = self
            .clients
            .iter()
            .filter(|c| c.role == Role::Core && c.payload)
            .count();
        if receivers == 0 {
            let released = self.peers[p]
                .inbound_released
                .checked_add(input.len() as u64)
                .ok_or(Error::Overflow)?;
            self.window_after_release(p, released)?;
            self.peers[p].inbound_used = new_used;
            self.peers[p].inbound_released = released;
            self.peers[p].flow_dirty = true;
            return Ok(false);
        }
        if self.peers[p].core_window <= 0 {
            return Err(Error::WouldBlock);
        }
        // A later cumulative grant may be lower than one that authorized
        // already-in-flight data. Check actual retained resources, as C does,
        // rather than revoking that original wire authorization here.
        if self.peers[p].received.len() == self.limits.messages
            || self
                .buffered
                .checked_add(input.len())
                .ok_or(Error::Overflow)?
                > self.limits.bytes
        {
            return Err(Error::TooLarge);
        }
        let next_window = self.peers[p]
            .core_window
            .checked_sub(i64::try_from(receivers).map_err(|_| Error::Overflow)?)
            .ok_or(Error::Overflow)?;
        if self
            .output
            .len()
            .checked_add(receivers)
            .ok_or(Error::Overflow)?
            > self.limits.messages + self.limits.control_messages
        {
            return Err(Error::WouldBlock);
        }
        // Prepare the complete fanout and its original capacity users before
        // publishing any copy or debit. A queue/allocator refusal cannot leave
        // a partial recipient set without the corresponding release receipt.
        let mut prepared = Vec::new();
        prepared
            .try_reserve_exact(receivers)
            .map_err(|_| Error::Capacity)?;
        let mut capacity_users = Vec::new();
        capacity_users
            .try_reserve_exact(receivers)
            .map_err(|_| Error::Capacity)?;
        self.output
            .try_reserve(receivers)
            .map_err(|_| Error::Capacity)?;
        self.peers[p]
            .received
            .try_reserve(1)
            .map_err(|_| Error::Capacity)?;
        for client in self
            .clients
            .iter()
            .filter(|c| c.role == Role::Core && c.payload)
        {
            let mut bytes = message(365, 36 + input.len())?;
            CoreResponse::Received {
                peer,
                message: input,
            }
            .encode(&mut bytes)?;
            capacity_users.push(client.id.clone());
            prepared.push(Output::Frame {
                client: client.id.clone(),
                bytes,
            });
        }
        self.output.extend(prepared);
        self.peers[p].inbound_used = new_used;
        self.peers[p].core_window = next_window;
        self.peers[p].received.push_back(InboundAllocation {
            size: input.len(),
            capacity_users,
            ack: None,
        });
        self.buffered += input.len();
        Ok(self.peers[p].core_window <= 0)
    }
    fn fragment(
        &mut self,
        p: usize,
        peer: PeerId,
        input: &[u8],
        now: u64,
    ) -> Result<NetworkStep, Error> {
        if !self.peers[p].connected {
            return Err(Error::Authentication);
        }
        let fragment = p2p::Fragment::decode(input)?;
        let source = self.dv_current_source().cloned();
        // The original may be a network control. Its final destination
        // handler, rather than assembly, checks any narrower CORE envelope.
        self.expire_assemblies(now);
        let index = if let Some(i) = self
            .assemblies
            .iter()
            .position(|a| a.peer == peer && a.id == fragment.message_id && a.source == source)
        {
            i
        } else {
            let total = usize::from(fragment.total);
            let charge = total
                .checked_add(total.div_ceil(8))
                .ok_or(Error::Overflow)?;
            if self.assemblies.len() >= self.limits.assemblies
                || self.assemblies.iter().filter(|a| a.peer == peer).count()
                    >= self.limits.assemblies_per_peer
                || self.buffered.checked_add(charge).ok_or(Error::Overflow)? > self.limits.bytes
            {
                // A remote sender's chosen total/count cannot retire the shared
                // communicator or occupy its unrelated peers' owners.
                return Err(Error::TooLarge);
            }
            let assembly =
                Assembly::new(peer, fragment.message_id, fragment.total, now)?.bind_source(source);
            self.buffered += assembly.charge();
            self.assemblies.push(assembly);
            self.assemblies.len() - 1
        };
        let complete = self.assemblies[index].insert(fragment)?;
        let body = if complete {
            let assembly = self.assemblies.remove(index);
            let until = assembly.expires;
            self.buffered -= assembly.charge();
            let body = assembly.into_body();
            let kind = Frame::decode(&body)?.header().message_type().value();
            if matches!(kind, 1214 | 1216) {
                return Err(Error::Unsupported);
            }
            Some((body, until))
        } else {
            None
        };
        // ACKs name only received attempts. They are not the communicator FC
        // callbacks and never claim assembly/application delivery. A bounded
        // pending ring may lose an ACK under sustained pressure, like a network
        // control packet; reliable transmission itself does not wait on it.
        if self.peers[p].fragment_acks.len() == 64 {
            self.peers[p].fragment_acks.pop_front();
        }
        self.peers[p].fragment_acks.push_back(PendingAck {
            id: fragment.ack,
            received: now,
        });
        Ok(match body {
            Some((body, until)) => NetworkStep::OwnedMessage(body, until),
            None => NetworkStep::Processed(false),
        })
    }
    fn expire_assemblies(&mut self, now: u64) {
        let mut i = 0;
        while i < self.assemblies.len() {
            let expires = self.assemblies[i].expires;
            if expires != u64::MAX && now >= expires {
                self.buffered -= self.assemblies.remove(i).charge();
            } else {
                i += 1;
            }
        }
    }
    fn discard_assemblies(&mut self, peer: PeerId) {
        let mut i = 0;
        while i < self.assemblies.len() {
            if self.assemblies[i].peer == peer {
                self.buffered -= self.assemblies.remove(i).charge();
            } else {
                i += 1;
            }
        }
    }
    fn flush_fragment_acks(&mut self, now: u64) -> Result<(), Error> {
        for p in 0..self.peers.len() {
            let peer = self.peers[p].id;
            // ACKs are best effort; their original receipt cannot become an
            // immortal control Job while a return carrier shrinks or vanishes.
            while self.peers[p].fragment_acks.front().is_some_and(|ack| {
                ack.received
                    .saturating_add(crate::fragment::EXPIRY)
                    .min(u64::MAX - 1)
                    <= now
            }) {
                self.peers[p].fragment_acks.pop_front();
            }
            if self.peers[p].fragment_acks.is_empty() {
                continue;
            }
            let direct_mtu = self
                .routes
                .iter()
                .filter(|q| {
                    q.description.peer == peer
                        && self.clients.iter().any(|c| c.id == q.owner)
                        && (q.unlimited || q.available > 0)
                })
                .map(|q| {
                    usize::try_from(q.description.mtu)
                        .unwrap_or(usize::MAX)
                        .min(communicator::MAX_INCOMING_MESSAGE_LEN)
                })
                .max();
            // Ultimate DV peers have no physical communicator queue. Their
            // actual installed path also carries standard reliability ACKs.
            // A small direct fallback cannot hide a usable virtual carrier;
            // transmit_job still rechecks which current route fits this control.
            let virtual_mtu = self.dv_bridge.virtual_path(peer, now).map(|(_, mtu)| mtu);
            let Some(mtu) = direct_mtu.into_iter().chain(virtual_mtu).max() else {
                continue;
            };
            let count = self.peers[p]
                .fragment_acks
                .len()
                .min(64)
                .min(mtu.saturating_sub(8) / 24)
                .min(
                    (self.limits.bytes + self.limits.control_bytes)
                        .saturating_sub(self.buffered)
                        .saturating_sub(8)
                        / 24,
                );
            let size = 8 + count * 24;
            if count == 0
                || self.jobs.len() >= self.limits.messages + self.limits.control_messages
                || self.buffered.checked_add(size).ok_or(Error::Overflow)?
                    > self.limits.bytes + self.limits.control_bytes
            {
                continue;
            }
            let first = self.peers[p]
                .fragment_acks
                .iter()
                .take(count)
                .map(|ack| ack.received)
                .min()
                .ok_or(Error::NotFound)?;
            let expires = first
                .saturating_add(crate::fragment::EXPIRY)
                .min(u64::MAX - 1);
            let job = self.job_serial.checked_add(1).ok_or(Error::Overflow)?;
            let mut entries = [(0, [0; 16]); 64];
            for (slot, pending) in entries
                .iter_mut()
                .zip(self.peers[p].fragment_acks.iter())
                .take(count)
            {
                *slot = (now.saturating_sub(pending.received), pending.id);
            }
            let counter = self.peers[p].ack_counter.wrapping_add(count as u32);
            let mut out = message(1217, size)?;
            p2p::encode_acknowledgements(counter, &entries[..count], &mut out)?;
            self.jobs.push_back(Job {
                id: job,
                preferences: 0,
                coverage: None,
                whole_sent: false,
                expires,
                deferred: None,
                route: None,
                peer,
                message: Zeroizing::new(out),
                fragment: None,
                origin: None,
                core: None,
                control: true,
            });
            self.buffered += size;
            self.job_serial = job;
            for _ in 0..count {
                self.peers[p].fragment_acks.pop_front();
            }
            self.peers[p].ack_counter = counter;
        }
        Ok(())
    }
    fn release_callbacks(&mut self, p: usize) -> Result<(), Error> {
        if self.peers[p].core_window <= 0 {
            return Ok(());
        }
        let peer = self.peers[p].id;
        for i in 0..self.peers[p].received.len() {
            if let Some((owner, token)) = self.peers[p].received[i].ack.take()
                && self.client(&owner).is_ok()
            {
                self.ack(owner, peer, token)?;
            }
        }
        Ok(())
    }
    fn window_after_release(&self, p: usize, released: u64) -> Result<u64, Error> {
        p2p::DEFAULT_WINDOW
            .checked_add(self.peers[p].loss_anchor_sent)
            .and_then(|n| {
                released
                    .checked_sub(self.peers[p].loss_anchor_released)
                    .and_then(|release| n.checked_add(release))
            })
            .ok_or(Error::Overflow)
    }
    fn inbound_window(&self, p: usize) -> Result<u64, Error> {
        self.window_after_release(p, self.peers[p].inbound_released)
    }
    fn route_down(&mut self, owner: &ClientId, peer: PeerId, id: u32) -> Result<(), Error> {
        self.routes.retain(|q| {
            !(q.owner == *owner && q.description.peer == peer && q.description.id == id)
        });
        for attempt in &mut self.attempts {
            if attempt.owner == *owner && attempt.peer == peer && attempt.queue == id {
                attempt.retired = true;
                if let Some(record) = attempt.remote_record {
                    self.remote_acks.local_done(record, attempt.message_id);
                }
            }
        }
        self.retire_signing(self.last_monotonic);
        self.refresh(peer)
    }
    fn payload_route_live(&self, peer: PeerId, now: u64) -> bool {
        self.dv_bridge.has_peer(peer, now)
            || self
                .routes
                .iter()
                .any(|q| q.description.peer == peer && q.valid_until > now)
    }
    // Exact output count for the existing refresh transition. Both native
    // queue retirement and virtual-path withdrawal preflight this same policy.
    fn refresh_outputs(&self, peer: PeerId, routes: bool, live: bool) -> Result<usize, Error> {
        let Some(p) = self.peers.iter().find(|p| p.id == peer) else {
            return Ok(0);
        };
        let lost = p.connected && !live;
        if !lost && routes {
            return Ok(0);
        }
        let notifications = if lost {
            self.clients.iter().filter(|c| c.role == Role::Core).count()
        } else {
            0
        };
        let received = p
            .received
            .iter()
            .filter(|r| {
                r.ack
                    .as_ref()
                    .is_some_and(|(owner, _)| self.client(owner).is_ok())
            })
            .count();
        let held = self
            .held
            .iter()
            .filter(|h| h.peer == peer && h.token.is_some() && self.client(&h.owner).is_ok())
            .count();
        let credits = self
            .jobs
            .iter()
            .filter(|j| {
                j.peer == peer
                    && (!j.control || !routes)
                    && j.core
                        .as_ref()
                        .is_some_and(|owner| self.client(owner).is_ok())
            })
            .count();
        notifications
            .checked_add(received)
            .and_then(|n| n.checked_add(held))
            .and_then(|n| n.checked_add(credits))
            .ok_or(Error::Overflow)
    }
    fn refresh(&mut self, peer: PeerId) -> Result<(), Error> {
        if let Some(p) = self.peers.iter().position(|p| p.id == peer) {
            let virtual_live = self.dv_bridge.has_peer(peer, self.last_monotonic);
            let routes = virtual_live || self.routes.iter().any(|q| q.description.peer == peer);
            let live = self.payload_route_live(peer, self.last_monotonic);
            let lost = self.peers[p].connected && !live;
            if lost {
                self.peers[p].connected = false;
                self.notify(peer, false)?;
            }
            if lost || !routes {
                self.discard_assemblies(peer);
                self.peers[p].fragment_acks.clear();
                while let Some(receipt) = self.peers[p].received.pop_front() {
                    self.buffered -= receipt.size;
                    if let Some((owner, token)) = receipt.ack
                        && self.client(&owner).is_ok()
                    {
                        self.ack(owner, peer, token)?;
                    }
                }
                let count = self.held.len();
                for _ in 0..count {
                    if let Some(held) = self.held.pop_front() {
                        if held.peer == peer {
                            self.buffered -= held.message.len();
                            if let Some(token) = held.token
                                && self.client(&held.owner).is_ok()
                            {
                                self.ack(held.owner, peer, token)?;
                            }
                        } else {
                            self.held.push_back(held);
                        }
                    }
                }
                let count = self.jobs.len();
                for _ in 0..count {
                    if let Some(job) = self.jobs.pop_front() {
                        if job.peer == peer && (!job.control || !routes) {
                            self.buffered -= job.charge();
                            self.remote_acks.remove_job(job.id);
                            self.dv_bridge.job_retired(job.id);
                            if let Some(core) = job.core
                                && self.client(&core).is_ok()
                            {
                                self.core_frame(core, CoreResponse::SendCredit(peer))?;
                            }
                        } else {
                            self.jobs.push_back(job);
                        }
                    }
                }
                self.peers[p].core_window = 4;
                if !routes {
                    self.peers[p].remote_sequence = None;
                    self.peers[p].remote_time = 0;
                    self.peers[p].outbound_window = p2p::DEFAULT_WINDOW;
                    self.peers[p].outbound_used = 0;
                    self.peers[p].inbound_used = 0;
                    self.peers[p].inbound_released = 0;
                    self.peers[p].loss_anchor_sent = 0;
                    self.peers[p].loss_anchor_released = 0;
                    self.peers[p].flow_dirty = true;
                }
            }
        }
        Ok(())
    }
    // All fallible storage/entropy/wire preflight precedes the original commit.
    fn transmit_job(
        &mut self,
        job: &mut Job,
        now: u64,
        entropy: &mut impl Entropy,
    ) -> Result<Option<bool>, Error> {
        if job.complete() {
            return Ok(Some(true));
        }
        // FLOW/ACK carried by a DV BOX may bypass FLOW without being a
        // structural control Job: it can still need ordinary fragmentation
        // and reliability accounting under the original resource limits.
        let bypass = job.control || self.dv_bridge.external_bypass(job.id);
        let p = self
            .peers
            .iter()
            .position(|p| p.id == job.peer)
            .ok_or(Error::Stale)?;
        if !bypass
            && job.fresh_offset() == 0
            && job.preferences & (32 | 256) == 0
            && let Some(origin) = job.origin.as_ref()
            && self.jobs.iter().any(|older| {
                older.id < job.id
                    && older.peer == job.peer
                    && older.origin.as_ref() == Some(origin)
                    && !older.control
                    && !self.dv_bridge.external_bypass(older.id)
                    && older.fresh()
            })
        {
            // Resource refusal or a partial first pass must not promote this
            // submitter's later default-ordered message. Already submitted
            // spans/retries and control traffic retain independent progress;
            // remote ACK coverage is not a stream-admission barrier.
            return Ok(None);
        }
        if !bypass
            && job.fragment.is_none()
            && self.jobs.iter().any(|j| {
                j.peer == job.peer
                    && !j.control
                    && !self.dv_bridge.external_bypass(j.id)
                    && j.fragment.is_some()
                    && j.fresh()
                    && j.coverage.is_none()
            })
        {
            return Ok(None);
        }
        let attempt_limit = self.limits.messages
            + if job.control {
                self.limits.control_messages
            } else {
                0
            };
        if self.attempts.len() >= attempt_limit {
            return Ok(None);
        }
        // Keep the original first eligible physical communicator. Its queue
        // priorities are comparable within that actual owner, not a global
        // transport preference supplied by an unrelated communicator. This
        // lets an ACK-backed UDP BOX queue supersede its KX fallback without
        // crossing owners or retargeting an explicitly route-bound control.
        let q = self.routes.iter().enumerate().fold(
            None,
            |selected: Option<usize>, (index, candidate)| {
                if let Some(current) = selected
                    && (job.route.is_some()
                        || candidate.owner != self.routes[current].owner
                        || candidate.description.priority
                            <= self.routes[current].description.priority)
                {
                    return selected;
                }
                let eligible = candidate.description.peer == job.peer
                    && self.clients.iter().any(|c| c.id == candidate.owner)
                    && job.route.is_none_or(|r| r == candidate.serial)
                    && (candidate.unlimited || candidate.available > 0)
                    && (!job.control
                        || job.message.len()
                            <= (candidate.description.mtu as usize)
                                .min(communicator::MAX_INCOMING_MESSAGE_LEN))
                    && (job.control || candidate.valid_until > now);
                if eligible { Some(index) } else { selected }
            },
        );
        let virtual_path = if q.is_none() && job.route.is_none() {
            self.dv_bridge.virtual_path(job.peer, now)
        } else {
            None
        };
        if q.is_none() && virtual_path.is_none() {
            return Ok(None);
        }
        let reliable_direct = q.is_some_and(|q| {
            self.clients
                .iter()
                .any(|c| c.id == self.routes[q].owner && c.reliable)
        });
        let needs_ack = !job.control && !reliable_direct && job.preferences & 16 == 0;
        let fresh_offset = job.fresh_offset();
        let retry = if job.fresh() && (!needs_ack || self.remote_acks.room(job.id, job.peer)) {
            None
        } else {
            let Some(c) = job.coverage.as_ref() else {
                return Ok(None);
            };
            let Some(r) = self.remote_acks.next(job.id, now, c) else {
                return Ok(None);
            };
            Some(r)
        };
        let candidate = retry.map_or(
            Span {
                start: fresh_offset,
                end: job.message.len(),
            },
            |r| r.span,
        );
        let mtu = q.map_or_else(
            || virtual_path.as_ref().map_or(0, |(_, mtu)| *mtu),
            |q| {
                (self.routes[q].description.mtu as usize)
                    .min(communicator::MAX_INCOMING_MESSAGE_LEN)
            },
        );
        let fragmented =
            job.fragment.is_some() || job.message.len() + if needs_ack { 24 } else { 0 } > mtu;
        if job.control && fragmented {
            return Ok(None);
        }
        if fragmented && mtu <= 32 {
            return Err(Error::TooLarge);
        }
        let boxed = needs_ack && !fragmented;
        let chunk = if fragmented {
            candidate.len().min(mtu - 32)
        } else {
            job.message.len()
        };
        let span = if fragmented {
            Span {
                start: candidate.start,
                end: candidate.start + chunk,
            }
        } else {
            Span {
                start: 0,
                end: job.message.len(),
            }
        };
        if span.end > job.message.len() || span.len() == 0 {
            return Err(Error::InvalidInput);
        }
        let network_len = chunk
            + if fragmented {
                32
            } else if boxed {
                24
            } else {
                0
            };
        let debit = if bypass {
            self.peers[p].outbound_used
        } else {
            self.peers[p]
                .outbound_used
                .checked_add(network_len as u64)
                .ok_or(Error::Overflow)?
        };
        if !bypass && debit > self.peers[p].outbound_window {
            // The peer needs an actual FLOW exchange to correct observed loss;
            // do not wait for the long keepalive while a real window is blocked.
            self.peers[p].flow_dirty = true;
            self.peers[p].flow_next = self.peers[p].flow_next.min(now);
            return Ok(None);
        }
        let output_limit = self.limits.messages
            + if job.control {
                self.limits.control_messages
            } else {
                0
            };
        if self
            .output
            .len()
            .checked_add(usize::from(q.is_some()) + usize::from(job.core.is_some()))
            .ok_or(Error::Overflow)?
            > output_limit
        {
            return Ok(None);
        }
        if q.is_none()
            && (!self.dv_bridge.virtual_room(output_limit)
                || self.buffered.checked_add(network_len).is_none_or(|n| {
                    n > self.limits.bytes
                        + if job.control {
                            self.limits.control_bytes
                        } else {
                            0
                        }
                }))
        {
            return Ok(None);
        }
        let remote_id = if needs_ack {
            match self.remote_acks.prepare(retry, job.id, job.peer) {
                Ok(id) => Some(id),
                Err(Error::WouldBlock) => return Ok(None),
                Err(e) => return Err(e),
            }
        } else {
            None
        };
        // Retry bitmaps are finite metadata separate from already promised
        // payload bytes; a full payload reservation must still progress.
        let coverage = if needs_ack && job.coverage.is_none() {
            Some(Coverage::new(job.message.len(), fresh_offset)?)
        } else {
            None
        };
        let next_mid = self.message_serial.checked_add(1).ok_or(Error::Overflow)?;
        let message_id = next_mid.to_be_bytes();
        let mut out = message(1209, 48 + network_len)?;
        if let Some(q) = q {
            out[4..8].copy_from_slice(&self.routes[q].description.id.to_be_bytes());
        }
        out[8..16].copy_from_slice(&message_id);
        out[16..48].copy_from_slice(&job.peer.0);
        let mut seed_to_commit = None;
        let mut serial_to_commit = None;
        let mut state = job.fragment.unwrap_or(FragmentSend {
            id: [0; 8],
            offset: fresh_offset,
        });
        if fragmented && job.fragment.is_none() {
            let seed = if let Some(seed) = self.fragment_seed {
                seed
            } else {
                let mut bytes = [0; 8];
                entropy.fill(&mut bytes)?;
                u64::from_be_bytes(bytes)
            };
            let serial = self.fragment_serial.checked_add(1).ok_or(Error::Overflow)?;
            state.id = seed.wrapping_add(serial).to_be_bytes();
            seed_to_commit = Some(seed);
            serial_to_commit = Some(serial);
        }
        let mut ack_to_commit = None;
        let ack = if boxed && retry.and_then(|r| r.uuid).is_some() {
            retry.and_then(|r| r.uuid).ok_or(Error::Stale)?
        } else if fragmented || boxed {
            let serial = self.ack_serial.checked_add(1).ok_or(Error::Overflow)?;
            let mut random = [0; 16];
            let mut selected = None;
            for _ in 0..8 {
                entropy.fill(&mut random)?;
                let hash = gnunet_crypto::hash256_parts(&[&random, &serial.to_be_bytes()]);
                let mut uuid = [0; 16];
                uuid.copy_from_slice(&hash[..16]);
                if self.remote_acks.unique(uuid) {
                    selected = Some(uuid);
                    break;
                }
            }
            let uuid = selected.ok_or(Error::Entropy)?;
            ack_to_commit = Some(serial);
            uuid
        } else {
            [0; 16]
        };
        if fragmented {
            p2p::Fragment {
                offset: u16::try_from(span.start).map_err(|_| Error::Overflow)?,
                total: u16::try_from(job.message.len()).map_err(|_| Error::TooLarge)?,
                ack,
                message_id: state.id,
                body: &job.message[span.start..span.end],
            }
            .encode(&mut out[48..])?;
        } else if boxed {
            p2p::Reliable {
                countdown: 0,
                uuid: ack,
                message: &job.message,
            }
            .encode(&mut out[48..])?;
        } else {
            out[48..].copy_from_slice(&job.message);
        }
        let credit = if job.core.is_some() {
            let mut bytes = message(364, 40)?;
            CoreResponse::SendCredit(job.peer).encode(&mut bytes)?;
            Some(bytes)
        } else {
            None
        };
        let expires = if job.expires == u64::MAX {
            now.checked_add(outbound::RETENTION)
                .ok_or(Error::Overflow)?
        } else {
            job.expires
        };
        let virtual_prepared = if let Some((path, _)) = virtual_path {
            Some(self.dv_bridge.prepare_virtual(dv_bridge::VirtualPlan {
                path,
                job: job.id,
                peer: job.peer,
                mid: message_id,
                remote: remote_id,
                expires,
                control: bypass,
                origin: job.origin.clone(),
            })?)
        } else {
            None
        };
        let direct_chunk = if let Some(q) = q {
            self.dv_prepare_chunk(job.id, q, message_id, span)?
        } else {
            None
        };
        // This commit can reject only a stale prepared record, before mutation;
        // every later operation is over already reserved original storage.
        if let Some(id) = remote_id {
            self.remote_acks.commit(
                id,
                retry,
                job.id,
                job.peer,
                span,
                ack,
                message_id,
                now,
                self.peers[p].rtt,
                boxed,
            )?;
        }
        if let Some(coverage) = coverage {
            job.coverage = Some(coverage);
        }
        if let Some(q) = q {
            self.output.push_back(Output::Frame {
                client: self.routes[q].owner.clone(),
                bytes: out,
            });
        } else if let Some(prepared) = virtual_prepared {
            out.copy_within(48.., 0);
            out.truncate(network_len);
            self.buffered += network_len;
            self.dv_bridge.commit_virtual(prepared, out);
            job.expires = expires;
        }
        if let Some(bytes) = credit
            && let Some(core) = job.core.take()
        {
            self.output.push_back(Output::Frame {
                client: core,
                bytes,
            });
        }
        if let Some(q) = q {
            self.routes[q].inflight += 1;
            if !self.routes[q].unlimited {
                self.routes[q].available -= 1;
            }
            self.attempts.push(Attempt {
                owner: self.routes[q].owner.clone(),
                peer: job.peer,
                queue: self.routes[q].description.id,
                route: self.routes[q].serial,
                message_id,
                retired: false,
                remote_record: remote_id,
                bytes: network_len,
                expires: if reliable_direct {
                    u64::MAX
                } else {
                    now.saturating_add(outbound::LOCAL_HANDOFF_TIMEOUT)
                },
            });
        }
        if let Some(chunk) = direct_chunk {
            self.dv_bridge.commit_chunk(chunk);
        }
        self.peers[p].outbound_used = debit;
        self.message_serial = next_mid;
        if let Some(seed) = seed_to_commit {
            self.fragment_seed = Some(seed);
        }
        if let Some(serial) = serial_to_commit {
            self.fragment_serial = serial;
        }
        if let Some(serial) = ack_to_commit {
            self.ack_serial = serial;
        }
        if retry.is_none() {
            if fragmented {
                state.offset = span.end;
            } else {
                job.whole_sent = true;
            }
        }
        if fragmented {
            job.fragment = Some(state);
        }
        if !needs_ack && let Some(c) = job.coverage.as_mut() {
            c.mark(span);
            self.remote_acks.settled(job.id, c, span, now);
        }
        if needs_ack && job.expires == u64::MAX {
            job.expires = now.saturating_add(outbound::RETENTION);
        }
        if retry.is_some() {
            self.retransmissions = self.retransmissions.saturating_add(1);
        }
        Ok(Some(job.complete()))
    }
    fn pump_held(&mut self) -> Result<(), Error> {
        let held_count = self.held.len();
        for _ in 0..held_count {
            let Some(held) = self.held.pop_front() else {
                break;
            };
            self.buffered -= held.message.len();
            if held.dv.is_some() {
                match self.dv_stage_inbox(held) {
                    Ok(()) => {}
                    Err(refused) => {
                        let held = refused.value;
                        if matches!(refused.reason, Error::WouldBlock | Error::NotReady) {
                            self.buffered += held.message.len();
                            self.held.push_back(held);
                        } else if let Some(token) = held.token
                            && self.client(&held.owner).is_ok()
                        {
                            self.ack(held.owner, held.peer, token)?;
                        }
                    }
                }
                continue;
            }
            let result = self
                .peers
                .iter()
                .position(|p| p.id == held.peer)
                .ok_or(Error::Stale)
                .and_then(|p| self.deliver(p, held.peer, &held.message));
            match result {
                Ok(hold) => {
                    if let Some(token) = held.token {
                        if hold {
                            let p = self
                                .peers
                                .iter_mut()
                                .find(|p| p.id == held.peer)
                                .ok_or(Error::Stale)?;
                            let last = p.received.back_mut().ok_or(Error::Stale)?;
                            last.ack = Some((held.owner, token));
                        } else {
                            self.ack(held.owner, held.peer, token)?;
                        }
                    }
                }
                Err(Error::WouldBlock | Error::NotReady) => {
                    self.buffered += held.message.len();
                    self.held.push_back(held);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    fn pump(
        &mut self,
        now: u64,
        entropy: &mut impl Entropy,
        retry: bool,
    ) -> Result<WorkStatus, Error> {
        self.flush_fragment_acks(now)?;
        self.pump_held()?;
        let count = self.jobs.len();
        let mut first_deferral = None;
        for _ in 0..count {
            let Some(mut job) = self.jobs.pop_front() else {
                break;
            };
            if job.deferred.is_some() && !retry {
                self.jobs.push_back(job);
                continue;
            }
            job.deferred = None;
            match self.transmit_job(&mut job, now, entropy) {
                Ok(Some(true)) => {
                    self.buffered -= job.charge();
                    self.remote_acks.remove_job(job.id);
                    self.dv_bridge.job_finished(job.id);
                }
                Ok(None | Some(false)) => self.jobs.push_back(job),
                Err(error) => {
                    // transmit_job's fallible preflight precedes every commit.
                    // Retain the original and rotate it out of the runnable set;
                    // unrelated IPC must not retry this same resource refusal.
                    job.deferred = Some(error);
                    let refusal = WorkDeferral {
                        operation: job.id,
                        peer: job.peer,
                        reason: error,
                    };
                    self.jobs.push_back(job);
                    first_deferral.get_or_insert(refusal);
                }
            }
        }
        Ok(first_deferral.map_or(WorkStatus::Ready, WorkStatus::Deferred))
    }
    /// Inspect retained TX refusals without allocating or granting operation authority.
    pub fn deferred_work(&self) -> impl Iterator<Item = WorkDeferral> + '_ {
        self.jobs.iter().filter_map(|j| {
            j.deferred.map(|reason| WorkDeferral {
                operation: j.id,
                peer: j.peer,
                reason,
            })
        })
    }
    /// Explicitly retry retained TX preflight after the caller's resource policy permits it.
    /// This never replays an accepted IPC request. Normal receive/tick skip blocked jobs.
    /// `now` asserts shared coordinates; use retry_deferred_at for independent clocks.
    pub fn retry_deferred(
        &mut self,
        now: u64,
        entropy: &mut impl Entropy,
    ) -> Result<WorkStatus, Error> {
        self.retry_deferred_at(Times::shared_coordinate(now), entropy)
    }
    /// Retry bounded retained preflight using the original monotonic schedule;
    /// a wall correction cannot reopen or extend a local retained attempt.
    pub fn retry_deferred_at(
        &mut self,
        times: Times,
        entropy: &mut impl Entropy,
    ) -> Result<WorkStatus, Error> {
        self.time_at(times)?;
        self.pump(times.monotonic().0, entropy, true)
    }
    // Expiry retires retained local state; it never fabricates remote ACKs or
    // returns spent finite packet grant. Original callback tombstones remain.
    fn expire_outbound(&mut self, now: u64) -> Result<(), Error> {
        let count = self.jobs.len();
        for _ in 0..count {
            let Some(job) = self.jobs.pop_front() else {
                break;
            };
            if job.expires != u64::MAX && now >= job.expires {
                if let Some(core) = job.core.as_ref()
                    && self.client(core).is_ok()
                    && let Err(error) =
                        self.core_frame(core.clone(), CoreResponse::SendCredit(job.peer))
                {
                    self.jobs.push_front(job);
                    return Err(error);
                }
                self.buffered -= job.charge();
                self.remote_acks.remove_job(job.id);
                self.dv_bridge.job_retired(job.id);
                self.expired_messages = self.expired_messages.saturating_add(1);
            } else {
                self.jobs.push_back(job);
            }
        }
        let mut i = 0;
        while i < self.attempts.len() {
            let a = &self.attempts[i];
            if a.expires == u64::MAX || now < a.expires {
                i += 1;
                continue;
            }
            if !a.retired
                && let Some(q) = self.routes.iter().find(|q| q.serial == a.route)
                && q.inflight == 0
            {
                return Err(Error::Overflow);
            }
            let a = self.attempts.remove(i);
            if !a.retired
                && let Some(q) = self.routes.iter_mut().find(|q| q.serial == a.route)
            {
                q.inflight -= 1;
            }
            if let Some(record) = a.remote_record {
                self.remote_acks.local_done(record, a.message_id);
            }
            if self.completed.len() == self.limits.messages {
                self.completed.pop_front();
            }
            self.completed.push_back(a);
            self.expired_attempts = self.expired_attempts.saturating_add(1);
        }
        Ok(())
    }
    fn enqueue_challenge(&mut self, route: usize, times: Times) -> Result<(), Error> {
        let now = times.monotonic().0;
        self.enqueue(
            Some(self.routes[route].serial),
            self.routes[route].description.peer,
            &Challenge {
                nonce: self.routes[route].nonce,
                origin: now,
            }
            .encode(),
            None,
            true,
        )?;
        // Advance only after the real immutable48B job was locally admitted.
        // Native bytes/ACKs retain their existing separate original owners.
        self.routes[route].challenge_not_before = now.saturating_add(RETRY);
        self.routes[route].schedule_challenge(times, now.saturating_add(RETRY));
        Ok(())
    }
    /// Advance liveness, validation retransmission and bounded flow updates.
    /// `now` asserts shared coordinates; independent clocks must use tick_at.
    pub fn tick(&mut self, now: u64, entropy: &mut impl Entropy) -> Result<WorkStatus, Error> {
        self.tick_at(Times::shared_coordinate(now), entropy)
    }
    /// Advance local liveness, validation, flow, retransmission and retention on
    /// mono alone. An absolute clock step does not synthesize elapsed duration.
    pub fn tick_at(
        &mut self,
        times: Times,
        entropy: &mut impl Entropy,
    ) -> Result<WorkStatus, Error> {
        let now = times.monotonic().0;
        self.time_at(times)?;
        self.burst_maintenance(times)?;
        self.expire_address_creates(now);
        self.retire_signing(now);
        self.expire_outbound(now)?;
        self.expire_assemblies(now);
        self.dv_bridge.expire(now);
        // Retire reachability once before sending this turn's challenges. An
        // unanswered original challenge keeps its nonce and retry/lifetime
        // bounds; later ticks cannot turn it into a new attempt or invalidate
        // its matching response. Only a route without such an attempt starts
        // this new bounded recovery period.
        for p in 0..self.peers.len() {
            if self.peers[p].liveness_expired
                || now.saturating_sub(self.peers[p].last_inbound) <= LIVENESS
            {
                continue;
            }
            self.peers[p].liveness_expired = true;
            let peer = self.peers[p].id;
            for route in self
                .routes
                .iter_mut()
                .filter(|q| q.description.peer == peer)
            {
                route.valid_until = 0;
                if !route.challenge_pending {
                    route.challenge_first = now;
                    route.challenge_last = now;
                    route.schedule_challenge(times, now);
                }
            }
        }
        for q in 0..self.routes.len() {
            if self.routes[q].challenge_next != u64::MAX && self.routes[q].challenge_next <= now {
                // Queue-credit recovery, short positive validation TTLs and
                // liveness recovery cannot undercut an original admitted
                // challenge's rate floor. A first not-yet-admitted challenge
                // keeps floor0 and can still start immediately when usable.
                if now < self.routes[q].challenge_not_before {
                    self.routes[q].schedule_challenge(times, now);
                    continue;
                }
                self.routes[q].schedule_challenge(times, now.saturating_add(RETRY));
                let route = self.routes[q].serial;
                if self.routes[q].description.mtu < 48
                    || (!self.routes[q].unlimited && self.routes[q].available == 0)
                    || self.jobs.iter().any(|job| {
                        job.control
                            && job.route == Some(route)
                            && Frame::decode(&job.message)
                                .is_ok_and(|f| f.header().message_type().value() == 1303)
                    })
                    || !self.control_room(48)
                {
                    continue;
                }
                if self.routes[q].valid_until == 0
                    && now.saturating_sub(self.routes[q].challenge_first) > UNCONFIRMED
                {
                    continue;
                }
                if !self.routes[q].challenge_pending {
                    entropy.fill(&mut self.routes[q].nonce)?;
                    self.routes[q].challenge_first = now;
                    self.routes[q].challenge_pending = true;
                }
                self.routes[q].challenge_last = now;
                self.enqueue_challenge(q, times)?;
            }
        }
        for p in 0..self.peers.len() {
            if now.saturating_sub(self.peers[p].last_inbound) > LIVENESS {
                let peer = self.peers[p].id;
                self.refresh(peer)?;
                continue;
            }
            self.refresh(self.peers[p].id)?;
            if self.peers[p].flow_next != u64::MAX
                && self.peers[p].flow_next <= now
                && (self.peers[p].flow_dirty
                    || now.saturating_sub(self.peers[p].flow_time) >= FLOW_KEEPALIVE)
            {
                let peer = self.peers[p].id;
                if !self.control_route_fits(peer, 60)
                    || !self.control_room(60)
                    || self.jobs.iter().any(|job| {
                        job.control
                            && job.peer == peer
                            && Frame::decode(&job.message)
                                .is_ok_and(|f| f.header().message_type().value() == 1221)
                    })
                {
                    self.peers[p].flow_next = now.saturating_add(FLOW_MIN);
                    continue;
                }
                let Some(stamp) = self.stamp(times)? else {
                    self.peers[p].flow_waiting_range = true;
                    self.peers[p].flow_next = now.saturating_add(FLOW_MIN);
                    continue;
                };
                let (burst_rtt, burst_ready) = self.burst_flow_status(peer, now);
                let flow = Flow {
                    sequence: self.peers[p].flow_sequence,
                    inbound_window: self.inbound_window(p)?,
                    outbound_sent: self.peers[p].outbound_used,
                    outbound_window: self.peers[p].outbound_window,
                    sender_time: stamp,
                    rtt: burst_rtt,
                    sync_ready: burst_ready,
                };
                self.enqueue(None, self.peers[p].id, &flow.encode(), None, true)?;
                self.peers[p].flow_sequence = self.peers[p]
                    .flow_sequence
                    .checked_add(1)
                    .ok_or(Error::Overflow)?;
                self.peers[p].flow_time = now;
                self.peers[p].monitor_last_flow = times.absolute().as_micros();
                self.peers[p].monitor_incoming_window = flow.inbound_window;
                self.peers[p].flow_next = now.saturating_add(FLOW_MIN);
                self.peers[p].flow_dirty = false;
            }
        }
        let result = self.pump(now, entropy, false);
        self.refresh_monitors();
        result
    }
    /// Remove one physical owner and all routes/attempts it owned. Peer loss is
    /// announced once when its final validated route disappears.
    pub fn close(&mut self, id: &ClientId) -> Result<(), Error> {
        let client = self.client(id)?;
        if matches!(
            self.clients[client].role,
            Role::Monitor | Role::Unregistered
        ) {
            self.monitor.close(id);
            self.clients.remove(client);
            return Ok(());
        }
        self.burst_closed(id);
        self.monitor.close(id);
        self.monitor.invalidate();
        self.dv_bridge.source_lost(id);
        self.clients.retain(|c| &c.id != id);
        self.local_addresses.close(id);
        self.demands.close(id);
        let mut i = 0;
        while i < self.address_creates.len() {
            if &self.address_creates[i].owner == id {
                self.remove_address_create(i);
            } else {
                i += 1;
            }
        }
        self.routes.retain(|q| &q.owner != id);
        self.retire_signing(self.last_monotonic);
        for a in self.attempts.iter().filter(|a| &a.owner == id) {
            if let Some(record) = a.remote_record {
                self.remote_acks.local_done(record, a.message_id);
            }
        }
        self.attempts.retain(|a| &a.owner != id);
        self.completed.retain(|a| &a.owner != id);
        self.output
            .retain(|o| !matches!(o,Output::Frame{client,..}if client==id));
        for p in 0..self.peers.len() {
            let mut r = 0;
            while r < self.peers[p].received.len() {
                if self.peers[p].received[r].capacity_users.contains(id) {
                    self.peers[p].core_window = self.peers[p]
                        .core_window
                        .checked_add(1)
                        .ok_or(Error::Overflow)?;
                }
                self.peers[p].received[r].capacity_users.retain(|c| c != id);
                if self.peers[p].received[r]
                    .ack
                    .as_ref()
                    .is_some_and(|(owner, _)| owner == id)
                {
                    self.peers[p].received[r].ack = None;
                }
                if self.peers[p].received[r].capacity_users.is_empty() {
                    let receipt = self.peers[p].received.remove(r).ok_or(Error::Stale)?;
                    self.buffered -= receipt.size;
                    self.peers[p].inbound_released = self.peers[p]
                        .inbound_released
                        .checked_add(receipt.size as u64)
                        .ok_or(Error::Overflow)?;
                    if let Some((owner, token)) = receipt.ack {
                        self.ack(owner, self.peers[p].id, token)?;
                    }
                    self.peers[p].flow_dirty = true;
                } else {
                    r += 1;
                }
            }
            self.release_callbacks(p)?;
            self.refresh(self.peers[p].id)?;
        }
        let count = self.held.len();
        for _ in 0..count {
            if let Some(held) = self.held.pop_front() {
                if &held.owner == id {
                    self.buffered -= held.message.len();
                } else {
                    self.held.push_back(held);
                }
            }
        }
        let count = self.jobs.len();
        for _ in 0..count {
            if let Some(job) = self.jobs.pop_front() {
                if job.origin.as_ref() == Some(id)
                    || job
                        .route
                        .is_some_and(|r| !self.routes.iter().any(|q| q.serial == r))
                {
                    self.buffered -= job.charge();
                    self.remote_acks.remove_job(job.id);
                    self.dv_bridge.job_retired(job.id);
                } else {
                    self.jobs.push_back(job);
                }
            }
        }
        // Close never invents an entropy source. Original receive/callback
        // release effects are immediate; remaining network jobs resume on the
        // next explicit receive/tick that supplies the real entropy port.
        self.pump_held()
    }
    fn retire_signing(&mut self, now: u64) {
        let routes = &self.routes;
        self.signing.retire(
            |owner, route| {
                routes
                    .iter()
                    .any(|q| q.owner == *owner && q.serial == route)
            },
            now,
        );
    }
    /// Borrow one unclaimed original effect. Failed service admission leaves it
    /// unchanged; accepted IPC input is never replayed to recreate this request.
    pub fn validation_request(&self) -> Option<&crate::signing::ValidationRequest> {
        self.signing.next()
    }
    /// Mark only the original effect after actual signing-service admission.
    pub fn claim_validation(&mut self, id: &crate::signing::ValidationId) -> Result<(), Error> {
        self.signing.claim(id)
    }
    /// Whether the original communicator/route effect still owns this token.
    #[must_use]
    pub fn validation_live(&self, id: &crate::signing::ValidationId) -> bool {
        self.signing.get(id).is_some()
    }
    /// Retire an original effect without a response; never a remote cancellation.
    pub fn cancel_validation(&mut self, id: &crate::signing::ValidationId) -> Result<(), Error> {
        self.signing.remove(id)
    }
    /// Verify and enqueue a signature for the exact original effect and route.
    /// An error leaves the effect retained and admits no response. Success is
    /// local bounded admission, never physical write or remote delivery.
    /// `now` asserts shared coordinates; independent clocks use complete_validation_at.
    pub fn complete_validation(
        &mut self,
        id: &crate::signing::ValidationId,
        signer: PeerId,
        signature: [u8; 64],
        now: u64,
    ) -> Result<(), Error> {
        self.complete_validation_at(id, signer, signature, Times::shared_coordinate(now))
    }
    /// Complete only the original signature/route effect, using mono for its
    /// retention TTL. Remote echoed origin stays opaque and is not UTC.
    pub fn complete_validation_at(
        &mut self,
        id: &crate::signing::ValidationId,
        signer: PeerId,
        signature: [u8; 64],
        times: Times,
    ) -> Result<(), Error> {
        let now = times.monotonic().0;
        self.validate_times(times)?;
        let original = self.signing.get(id).ok_or(Error::Stale)?.clone();
        if original.expired(now) {
            return Err(Error::Stale);
        }
        if signer != self.identity || signer != original.signer() {
            return Err(Error::Authentication);
        }
        gnunet_crypto::EddsaPublicKey::from_bytes(signer.0).verify(
            35,
            original.region(),
            &gnunet_crypto::EddsaSignature::from_bytes(signature),
        )?;
        if !self
            .routes
            .iter()
            .any(|q| q.owner == *original.client() && q.serial == original.route)
        {
            return Err(Error::Stale);
        }
        self.enqueue(
            Some(original.route),
            original.peer(),
            &original.response(signature),
            None,
            true,
        )?;
        self.time_at(times)?;
        self.signing.remove(id)
    }
    /// Take the next owned output; the host preserves per-connection FIFO order.
    pub fn output(&mut self) -> Option<Output> {
        self.refresh_monitors();
        self.output.pop_front().or_else(|| self.monitor.output())
    }
    /// Read finite resource and state counts without advancing the protocol.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            pending_remote_acks: self.remote_acks.len(),
            retry_bitmap_bytes: self
                .jobs
                .iter()
                .map(|job| job.coverage.as_ref().map_or(0, Coverage::charge))
                .sum(),
            retransmissions: self.retransmissions,
            expired_messages: self.expired_messages,
            expired_attempts: self.expired_attempts,
            ignored_local_callbacks: self.ignored_local_callbacks,
            clients: self.clients.len(),
            queues: self.routes.len(),
            connected: self.peers.iter().filter(|p| p.connected).count(),
            remote_dropped: self.dropped,
            backchannel_dropped: self.backchannel_dropped,
            last_backchannel_drop: self.last_backchannel_drop,
            last_remote_drop: self.last_remote_drop,
            validations: self.validations,
            pending_address_creates: self.address_creates.len(),
            pending_validation_signatures: self.signing.len(),
            application_suggestions: self.demands.len(),
            address_create_bytes: self.address_create_bytes,
            address_creates_issued: self.address_create_serial,
            attempts: self.attempts.len(),
            pending: self.jobs.len() + self.held.len(),
            outputs: self.output.len(),
            reassemblies: self.assemblies.len(),
            reassembly_bytes: self.assemblies.iter().map(Assembly::charge).sum(),
            pending_fragment_acks: self.peers.iter().map(|p| p.fragment_acks.len()).sum(),
        }
    }
}

#[cfg(test)]
mod challenge_tests;

#[cfg(test)]
mod source_order_tests;
