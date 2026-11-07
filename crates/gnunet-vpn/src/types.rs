use crate::{Address, AfProfile, Family};
use core::{cell::Cell, ptr};
use gnunet_types::{AbsoluteTime, Error, MonoInstant};
/// Explicit stable allocation domain; checked local ids never enter official wire.
#[derive(Default, Debug)]
pub struct Instance {
    pub(crate) next: Cell<u64>,
}
impl Instance {
    /// Fresh original node domain.
    #[must_use]
    pub const fn new() -> Self {
        Self { next: Cell::new(0) }
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Handle<'id> {
    pub domain: &'id Instance,
    pub row: usize,
    pub serial: u64,
}
impl PartialEq for Handle<'_> {
    fn eq(&self, o: &Self) -> bool {
        ptr::eq(self.domain, o.domain) && self.row == o.row && self.serial == o.serial
    }
}
impl Eq for Handle<'_> {}
macro_rules! token {
    ($name:ident,$doc:literal) => {
        #[doc=$doc]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $name<'id>(pub(crate) Handle<'id>);
        impl $name<'_> {
            /// Diagnostic original allocation, never a wire capability.
            #[must_use]
            pub const fn value(self) -> u64 {
                self.0.serial
            }
        }
    };
}
token!(Client, "Original actual accepted VPN IPC MQ.");
token!(
    Request,
    "Original redirection/callback ownership; cancel has no wire command."
);
token!(Lease, "Original bounded logical address lease allocation.");
token!(Flow, "Original kernel transport tuple/channel allocation.");
token!(Buffer, "Original immutable buffered packet allocation.");
/// Original physically attached TUN device; configuration alone cannot mint it.
#[derive(Clone, Copy, Debug)]
pub struct Tun<'id> {
    pub(crate) domain: &'id Instance,
    pub(crate) serial: u64,
}
impl PartialEq for Tun<'_> {
    fn eq(&self, other: &Self) -> bool {
        ptr::eq(self.domain, other.domain) && self.serial == other.serial
    }
}
impl Eq for Tun<'_> {}
/// Original explicit OS-route provisioning/verification work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Routing<'id> {
    pub(crate) tun: Tun<'id>,
    pub(crate) serial: u64,
}
/// Original discovery job; selecting a result does not physically retire its job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Discovery<'id> {
    pub(crate) flow: Flow<'id>,
    pub(crate) serial: u64,
}
impl<'id> Discovery<'id> {
    /// Original flow allocation of this discovery job. This is metadata for
    /// checking cancellation/liveness; it grants no result or source authority.
    #[must_use]
    pub const fn flow(self) -> Flow<'id> {
        self.flow
    }
}
/// Original actual CADET open request/work, distinct from connected endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Open<'id> {
    pub(crate) flow: Flow<'id>,
    pub(crate) serial: u64,
}
/// Actual end-to-end channel source chosen by the original open work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Peer<'id> {
    pub(crate) flow: Flow<'id>,
    pub(crate) serial: u64,
    pub(crate) identity: [u8; 32],
}
impl<'id> Peer<'id> {
    /// Original flow/channel generation.
    #[must_use]
    pub const fn flow(self) -> Flow<'id> {
        self.flow
    }
    /// Original actual expected end-to-end endpoint, never inferred from raw CID.
    #[must_use]
    pub const fn identity(self) -> [u8; 32] {
        self.identity
    }
}
/// Original application-processing permission for one actual received peer frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Delivery<'id> {
    pub(crate) peer: Peer<'id>,
    pub(crate) serial: u64,
    pub(crate) buffer: Buffer<'id>,
}
impl<'id> Delivery<'id> {
    /// Original retained raw-TUN output buffer for this processing permission.
    #[must_use]
    pub const fn buffer(self) -> Buffer<'id> {
        self.buffer
    }
    /// Exact original peer source.
    #[must_use]
    pub const fn peer(self) -> Peer<'id> {
        self.peer
    }
}
/// Exact original physical output destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Destination<'id> {
    /// Actual local IPC MQ.
    Client(Client<'id>),
    /// Actual attached raw TUN source.
    Tun(Tun<'id>),
    /// Actual CADET end-to-end source.
    Peer(Peer<'id>),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Origin {
    Request(Reference),
    Packet(Reference),
}
/// Original immutable response/packet effect and source-bound physical attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Effect<'id> {
    pub(crate) origin: Origin,
    pub(crate) destination: Destination<'id>,
    pub(crate) serial: u64,
}
impl<'id> Effect<'id> {
    /// Original IPC request for this actual result frame, preserving the original
    /// instance/domain and row generation. Packet effects return None.
    #[must_use]
    pub fn request(self) -> Option<Request<'id>> {
        match (self.origin, self.destination) {
            (Origin::Request(r), Destination::Client(client)) => Some(Request(Handle {
                domain: client.0.domain,
                row: r.row,
                serial: r.serial,
            })),
            _ => None,
        }
    }
    /// Original packet buffer, preserving its original instance/row generation.
    /// IPC result effects return None; no integer-to-buffer constructor is exposed.
    #[must_use]
    pub fn buffer(self) -> Option<Buffer<'id>> {
        let Origin::Packet(r) = self.origin else {
            return None;
        };
        let domain = match self.destination {
            Destination::Peer(peer) => peer.flow.0.domain,
            Destination::Tun(tun) => tun.domain,
            Destination::Client(_) => return None,
        };
        Some(Buffer(Handle {
            domain,
            row: r.row,
            serial: r.serial,
        }))
    }
    /// Actual destination including original source generation.
    #[must_use]
    pub const fn destination(self) -> Destination<'id> {
        self.destination
    }
}
/// Borrowed original output. Copy/freeze its complete bytes before actual queue
/// admission; retain original immutable bytes through full write or source loss.
pub struct Prepared<'a, 'id> {
    /// Original effect.
    pub effect: Effect<'id>,
    /// Entire official frame or raw TUN packet.
    pub bytes: &'a [u8],
}
/// Original physical facts, never an IP-delivery or remote-application proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Buffered internal original bytes; no physical attempt yet.
    Buffered,
    /// Prepared original frame not admitted.
    Prepared,
    /// Actual original queue admission.
    Queued,
    /// Actual positive native write.
    Exposed,
    /// Complete original write; does not prove kernel delivery.
    Written,
    /// Conclusively zero-exposure native settlement.
    Unsent,
    /// Explicit local policy revoked never-admitted bytes.
    Canceled,
    /// Original physical source stopped; exposure/cause retained.
    Lost {
        /// Actual native queue admission occurred.
        queued: bool,
        /// Actual positive write occurred.
        exposed: bool,
        /// Original stop cause.
        reason: Error,
    },
}
impl Outcome {
    pub(crate) fn terminal(self) -> bool {
        matches!(
            self,
            Self::Written | Self::Unsent | Self::Canceled | Self::Lost { .. }
        )
    }
    pub(crate) fn queued(self) -> bool {
        matches!(self, Self::Queued | Self::Exposed)
    }
    pub(crate) fn exposed(self) -> bool {
        self == Self::Exposed
    }
}
/// Logical prefix whose real native device/routes must be provisioned explicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Prefix {
    /// Canonical network address.
    pub network: Address,
    /// Number of network bits.
    pub bits: u8,
    /// Actual configured TUN interface address excluded from leases.
    pub interface: Address,
}
impl Prefix {
    pub(crate) fn mask(self) -> Result<u128, Error> {
        let width = if self.network.family() == Family::V4 {
            32
        } else {
            128
        };
        if usize::from(self.bits) > width || self.interface.family() != self.network.family() {
            return Err(Error::InvalidInput);
        }
        let host = width - usize::from(self.bits);
        let low = if host == 128 {
            u128::MAX
        } else {
            (1u128 << host) - 1
        };
        let all = if width == 32 {
            u128::from(u32::MAX)
        } else {
            u128::MAX
        };
        Ok(all ^ low)
    }
    /// Whether an address is in this validated prefix.
    pub fn contains(self, a: Address) -> Result<bool, Error> {
        if a.family() != self.network.family() {
            return Ok(false);
        }
        Ok((number(a) & self.mask()?) == number(self.network))
    }
    pub(crate) fn validate(self) -> Result<(), Error> {
        let mask = self.mask()?;
        if number(self.network) & mask != number(self.network) || !self.contains(self.interface)? {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}
pub(crate) fn number(a: Address) -> u128 {
    match a {
        Address::V4(b) => u128::from(u32::from_be_bytes(b)),
        Address::V6(b) => u128::from_be_bytes(b),
    }
}
pub(crate) fn address(f: Family, n: u128) -> Address {
    match f {
        Family::V4 => Address::V4((n as u32).to_be_bytes()),
        Family::V6 => Address::V6(n.to_be_bytes()),
    }
}
/// Explicit bounded VPN policy, independent of native TUN/sysroute mechanisms.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// IPv4 address range/device plan.
    pub ipv4: Option<Prefix>,
    /// IPv6 address range/device plan.
    pub ipv6: Option<Prefix>,
    /// Actual remote/local AF assignment profile.
    pub ipc_af: AfProfile,
    /// Explicit initial peer endpoint AF profile, overridable only at actual bind.
    pub peer_af: AfProfile,
    /// Maximum raw complete TUN packet retained.
    pub packet_bytes: usize,
    /// Genuine inactive-flow lifetime; source close remains explicit.
    pub idle_micros: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            ipv4: None,
            ipv6: None,
            ipc_af: AfProfile::native(),
            peer_af: AfProfile::native(),
            packet_bytes: 65535,
            idle_micros: 300_000_000,
        }
    }
}
/// Destination copied into a flow so lease expiry does not destroy active traffic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Target {
    /// Named peer service; original request protocol is a legacy ignored C field.
    Service {
        /// Expected actual peer.
        peer: [u8; 32],
        /// Original service descriptor.
        descriptor: [u8; 64],
    },
    /// Internet destination; discovery is an explicit caller port.
    Internet(Address),
}
/// Original kernel-side tuple, without invented wire connection identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tuple {
    /// Original local kernel source.
    pub source: Address,
    /// Original allocated virtual destination.
    pub destination: Address,
    /// Actual original protocol.
    pub protocol: u8,
    /// Original source port, zero for ICMP.
    pub source_port: u16,
    /// Original destination port, zero for ICMP.
    pub destination_port: u16,
}
/// Real logical flow phase; ready refers to the actual CADET source, not TCP ACK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Actual Internet-exit discovery remains external.
    Discovering,
    /// Needs an original actual channel open.
    NeedOpen,
    /// Original open work is outstanding.
    Opening,
    /// Actual expected CADET source bound.
    Ready,
    /// Native source/job retirement still required.
    Closing,
}
/// Copied current flow facts; grants no new source/credit capability.
#[derive(Clone, Copy, Debug)]
pub struct FlowInfo {
    /// Original tuple.
    pub tuple: Tuple,
    /// Original copied destination.
    pub target: Target,
    /// Actual phase.
    pub phase: Phase,
    /// Last genuinely admitted packet in the owner's fixed native epoch.
    pub last_used: MonoInstant,
    /// Original failure if any.
    pub failure: Option<Error>,
}
/// One real Internet-exit discovery specification and original job token.
#[derive(Clone, Copy, Debug)]
pub struct DiscoveryRequest<'id> {
    /// Original work.
    pub discovery: Discovery<'id>,
    /// Actual Internet address.
    pub destination: Address,
    /// Actual transport protocol.
    pub protocol: u8,
    /// Actual desired destination port.
    pub port: u16,
}
/// One original CADET open specification. Queue/write is not endpoint acceptance.
#[derive(Clone, Copy, Debug)]
pub struct OpenRequest<'id> {
    /// Original work.
    pub open: Open<'id>,
    /// Expected actual peer.
    pub peer: [u8; 32],
    /// Exact official gateway/service port.
    pub port: [u8; 64],
}
/// Accepted actual kernel packet now retained in bounded shared storage.
#[derive(Clone, Copy, Debug)]
pub struct Ingress<'id> {
    /// Original flow.
    pub flow: Flow<'id>,
    /// Original immutable packet buffer.
    pub buffer: Buffer<'id>,
    /// New flow was actually allocated.
    pub new_flow: bool,
}
/// Original source loss summary; individual packet/request outcomes remain in
/// bounded caller storage until inspected/released, never copied into a Vec.
#[derive(Clone, Copy, Debug)]
pub struct Loss {
    /// Original outputs still retained.
    pub outputs: usize,
    /// Actual positive-write outputs among them.
    pub exposed: usize,
    /// Original physical-stop cause.
    pub reason: Error,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Reference {
    pub row: usize,
    pub serial: u64,
}
#[derive(Clone, Copy)]
pub(crate) struct Work {
    pub serial: u64,
    pub queued: bool,
    pub revoked: bool,
}
#[derive(Clone, Copy)]
pub(crate) struct ClientState {
    pub serial: u64,
    pub pending: Option<Reference>,
}
/// Caller-owned actual local MQ metadata.
#[derive(Clone, Copy)]
pub struct ClientSlot {
    pub(crate) state: Option<ClientState>,
}
impl ClientSlot {
    /// Fresh unused row.
    #[must_use]
    pub const fn new() -> Self {
        Self { state: None }
    }
}
impl Default for ClientSlot {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Clone, Copy)]
pub(crate) struct RequestState {
    pub serial: u64,
    pub client: Reference,
    pub id: [u8; 8],
    pub lease: Option<Reference>,
    pub bytes: [u8; 32],
    pub len: usize,
    pub status: Outcome,
    pub attempt: Option<u64>,
    pub canceled: bool,
    pub dead: bool,
}
/// Caller-owned fixed response/callback row; maximum32-byte IPC body is inline.
#[derive(Clone, Copy)]
pub struct RequestSlot {
    pub(crate) state: Option<RequestState>,
}
impl RequestSlot {
    /// Fresh unused row.
    #[must_use]
    pub const fn new() -> Self {
        Self { state: None }
    }
}
impl Default for RequestSlot {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Clone, Copy)]
pub(crate) struct LeaseState {
    pub serial: u64,
    pub address: Address,
    pub target: Target,
    pub expires: AbsoluteTime,
    pub used: AbsoluteTime,
}
/// Caller-owned address lease metadata.
#[derive(Clone, Copy)]
pub struct LeaseSlot {
    pub(crate) state: Option<LeaseState>,
}
impl LeaseSlot {
    /// Fresh unused row.
    #[must_use]
    pub const fn new() -> Self {
        Self { state: None }
    }
}
impl Default for LeaseSlot {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Clone, Copy)]
pub(crate) struct FlowState {
    pub af: AfProfile,
    pub serial: u64,
    pub tuple: Tuple,
    pub target: Target,
    pub phase: Phase,
    pub peer: Option<[u8; 32]>,
    pub source: Option<u64>,
    pub peer_ended: bool,
    pub discovery: Option<Work>,
    pub open: Option<Work>,
    pub start_encoded: bool,
    pub pending: Option<Reference>,
    pub receive: Option<(u64, Reference)>,
    pub used: MonoInstant,
    pub failure: Option<Error>,
}
/// Caller-owned kernel tuple/channel/job metadata.
#[derive(Clone, Copy)]
pub struct FlowSlot {
    pub(crate) state: Option<FlowState>,
}
impl FlowSlot {
    /// Fresh unused row.
    #[must_use]
    pub const fn new() -> Self {
        Self { state: None }
    }
}
impl Default for FlowSlot {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Clone, Copy)]
pub(crate) enum PacketKind {
    Peer,
    Tun {
        tun: u64,
        delivery: u64,
        credited: bool,
    },
}
#[derive(Clone, Copy)]
pub(crate) struct PacketState {
    pub serial: u64,
    pub flow: Reference,
    pub kind: PacketKind,
    pub len: usize,
    pub status: Outcome,
    pub attempt: Option<u64>,
    pub bound: Option<u64>,
}
/// Shared variable-sized packet slab; never replicated per flow/channel.
pub struct PacketSlot<'bytes> {
    pub(crate) bytes: &'bytes mut [u8],
    pub(crate) state: Option<PacketState>,
}
impl<'bytes> PacketSlot<'bytes> {
    /// Fresh shared packet buffer.
    #[must_use]
    pub fn new(bytes: &'bytes mut [u8]) -> Self {
        Self { bytes, state: None }
    }
}
/// All explicit caller storage. Rows and raw packet bodies have independent scope.
pub struct Storage<'store, 'bytes> {
    /// Actual local MQ rows.
    pub clients: &'store mut [ClientSlot],
    /// Original IPC redirection/result rows.
    pub requests: &'store mut [RequestSlot],
    /// Address lease rows.
    pub leases: &'store mut [LeaseSlot],
    /// Actual transport flow rows.
    pub flows: &'store mut [FlowSlot],
    /// Shared immutable packet payload slabs.
    pub packets: &'store mut [PacketSlot<'bytes>],
}
#[derive(Clone, Copy)]
pub(crate) struct TunState {
    pub dead: bool,
    pub serial: u64,
    pub routing: Option<Work>,
    pub ready: bool,
    pub failure: Option<Error>,
    pub routes: RouteState,
    pub routing_action: RouteAction,
}

/// Original real device and requested prefix-route work; a submitted command or
/// configuration parse alone is not a successful kernel route verification.
#[derive(Clone, Copy, Debug)]
pub struct RoutingRequest<'id> {
    /// Actual provider action; removal/ownership release needs its own receipt.
    pub action: RouteAction,
    /// Original source-bound work.
    pub routing: Routing<'id>,
    /// Exact IPv4 prefix/interface plan to apply or verify.
    pub ipv4: Option<Prefix>,
    /// Exact IPv6 prefix/interface plan to apply or verify.
    pub ipv6: Option<Prefix>,
}
/// Original actual TUN source stopped. Retained route work still requires its
/// independent provider retirement; source stop never means its job quiesced.
#[derive(Clone, Copy, Debug)]
pub struct TunLoss<'id> {
    /// Original actual TUN source.
    pub tun: Tun<'id>,
    /// Original still-retained OS-route job, if any.
    pub routing: Option<Routing<'id>>,
    /// Original packet/exposure/cause summary.
    pub loss: Loss,
    /// Original owned cleanup or logical borrowed-view release state. Physical
    /// source loss does not settle either provider-job or ownership debt.
    pub routes: RouteState,
}
/// Original actual CADET source stopped; TUN writes are a separate physical port.
#[derive(Clone, Copy, Debug)]
pub struct PeerLoss<'id> {
    /// Original end-to-end source.
    pub peer: Peer<'id>,
    /// Original physical packet/exposure/cause summary.
    pub loss: Loss,
    /// Original uncredited peer application input, if any.
    pub delivery: Option<Delivery<'id>>,
}
/// Actual allocation response facts independent of lease current validity.
#[derive(Clone, Copy, Debug)]
pub struct RequestInfo<'id> {
    /// Original wire correlation bytes.
    pub request_id: [u8; 8],
    /// Original allocation, if still a current logical lease.
    pub lease: Option<Lease<'id>>,
    /// Local callback/response observation was canceled; no wire CANCEL exists.
    pub canceled: bool,
    /// Original response native outcome.
    pub outcome: Outcome,
}
/// Current logical lease facts; grant no physical route/write/exit evidence.
#[derive(Clone, Copy, Debug)]
pub struct LeaseInfo {
    /// Allocated original virtual address.
    pub address: Address,
    /// Original logical destination.
    pub target: Target,
    /// Original absolute expiry; genuine active flows keep their copied target.
    pub expires: AbsoluteTime,
}

/// Explicit original-scope native route operation, never an automatic success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteAction {
    /// Provision the owned device/prefix plan, or verify an external plan only
    /// through the explicit routing_borrowed_queued admission port.
    Install,
    /// Remove/relinquish only that original scope's owned OS-route effects.
    Remove,
}
/// Original owned route effects or explicit borrowed-route view, independent
/// of physical TUN/job lifetime. A released borrowed view is not kernel absence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteState {
    /// No original route command was admitted, or actual cleanup was confirmed.
    Absent,
    /// Actual provider confirmed the complete original owned plan.
    Present,
    /// An admitted command/invalidated observation may have left effects; actual
    /// cleanup/reconciliation is required before source-slot reuse.
    Unknown,
    /// Actual current provider verification of an external route/interface plan.
    /// No mutation/cleanup ownership is acquired from this observation.
    BorrowedVerified,
    /// An original read-only verification is pending, failed, or invalidated.
    /// This remains external; uncertainty never authorizes deleting its routes.
    BorrowedUnverified,
    /// The logical external-route view was released after its query quiesced.
    /// External route presence is deliberately unclaimed.
    BorrowedReleased,
}
impl RouteState {
    /// Whether this is an external route view with no owned removal authority.
    #[must_use]
    pub const fn is_borrowed(self) -> bool {
        matches!(
            self,
            Self::BorrowedVerified | Self::BorrowedUnverified | Self::BorrowedReleased
        )
    }
}
