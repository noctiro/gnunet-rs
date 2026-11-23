//! Source-bound TCP candidate-address discovery and actual 1200/1201 submission.
//! Candidates and local FIFO admission prove neither reachability nor validation.
#![doc = include_str!("addresses/README.md")]
use crate::{Pool, listeners::Listeners};
use gnunet_client_host::EndpointSource;
use gnunet_crypto::EddsaPublicKey;
use gnunet_nat_client_host as nat;
use gnunet_native::interfaces::{self, InterfaceAddress};
use gnunet_service_runtime::{
    clock::{ClockSubscription, RuntimeClock},
    network_change::NetworkChanges,
};
use gnunet_tcp_communicator_host::HostError;
use gnunet_types::Error as Fault;
use std::{
    fmt::{self, Write},
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

/// Fixed owner targets and refresh policy, independent of the signed-time store.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Original canonical absolute source deadline, never extended. MAX means
    /// no overall deadline for a healthy long-lived communicator.
    pub until: u64,
    /// Each explicit new registration's local send budget, within `until`.
    pub send_timeout: Duration,
    /// Period between complete real interface scans.
    pub scan_interval: Duration,
    /// Maximum age of a successful interface snapshot before its claims expire.
    pub freshness: Duration,
    /// Finite original retirement grace; queued removals still need Pool drain.
    pub retirement: Duration,
    /// Original listener/configuration IPv6 policy.
    pub disable_v6: bool,
}
/// Explicit bounded metadata. No hidden process, Resolver or task is created.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum original kernel-bound endpoints supplied by Listeners.
    pub bindings: usize,
    /// Maximum distinct candidate addresses, including pending removals.
    pub addresses: usize,
    /// Maximum simultaneous interface/listener/NAT allocation references.
    pub claims: usize,
    /// Complete native interface snapshot bounds.
    pub interfaces: interfaces::Limits,
    /// Original registration frame/write/address bounds.
    pub nat: nat::Limits,
    /// Retry alarm for temporary original TRANSPORT FIFO pressure.
    pub capacity_retry: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            bindings: 16,
            addresses: 128,
            claims: 512,
            interfaces: interfaces::Limits {
                nodes: 2048,
                addresses: 256,
                name_bytes: 256,
            },
            nat: nat::Limits::default(),
            capacity_retry: Duration::from_millis(100),
        }
    }
}
/// Actual original failure. No error authorizes a fabricated empty scan or ADD.
#[derive(Debug)]
pub enum Failure {
    /// Original local metadata/ownership/deadline refusal.
    Protocol(Fault),
    /// Actual canonical clock sample/subscription failure.
    Clock(Fault),
    /// Actual native interface enumeration or allocation failure.
    Interfaces(io::Error),
    /// Original NAT client/configuration/connection error.
    Nat(nat::Error),
    /// Original communicator FIFO failure, kept distinct from NAT/source loss.
    Transport(HostError),
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TCP address owner: {self:?}")
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Interfaces(e) => Some(e),
            Self::Nat(e) => Some(e),
            Self::Transport(e) => Some(e),
            Self::Protocol(_) | Self::Clock(_) => None,
        }
    }
}
impl From<Fault> for Failure {
    fn from(e: Fault) -> Self {
        Self::Protocol(e)
    }
}
impl From<nat::Error> for Failure {
    fn from(e: nat::Error) -> Self {
        Self::Nat(e)
    }
}
/// One real diagnostic/submission observation, not a remote or durability ACK.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "Original bounded NAT retirement metadata is transferred without allocating after physical close"
)]
pub enum Event<'id> {
    /// Actual NAT progress, retaining original session/epoch/write identity.
    Nat(nat::Progress<'id>),
    /// The actual Pool callback-source generation changed. Old FIFO address
    /// admissions retired with that MQ; listener/NAT claims and their original
    /// freshness targets remain. This is not a DEL or replacement ADD write.
    TransportRetired {
        /// Original retired physical source generation.
        generation: u64,
        /// New callback generation already allocated by actual source loss.
        next_generation: u64,
        /// Rows whose old local FIFO admission was retired.
        admitted: usize,
    },
    /// One original held reverse callback became available. It stays owned by
    /// the same Registration until its exact token is explicitly released.
    ReverseReady(ReverseNotification<'id>),
    /// Actual complete snapshot applied; zero candidates is not NAT success.
    Scanned {
        /// Number of unique wildcard candidates in that complete snapshot.
        candidates: usize,
    },
    /// The complete scan failed. Prior claims keep only their original freshness.
    ScanFailed(Failure),
    /// A canonical original ADD was accepted into the original Pool FIFO.
    AddQueued {
        /// Original source-local communicator identifier.
        id: u32,
        /// Actual candidate endpoint, not a validated remote route.
        address: SocketAddr,
    },
    /// Original DEL was accepted into the same Pool FIFO, not physically written.
    RemoveQueued {
        /// Exact old identifier; never a replacement address's identifier.
        id: u32,
    },
    /// Actual callback was consumed without granting a candidate (e.g. disabled v6).
    Ignored,
    /// Original failure, after fresh admissions stopped; continue polling cleanup.
    Failed(Failure),
    /// Actual original NAT MQ is closed and every original ADD has a queued DEL.
    /// The same Pool must still drive those immutable frames to write or loss.
    Closed,
    /// Grace expired: the owned Pool was physically dropped, leaving dirty epoch
    /// recovery to its original owner. No clean/quiescent receipt is fabricated.
    Aborted,
}
/// Actual admission of one original official NAT reverse write, not an ACK or
/// peer authentication. Only this owner's successful `Registration::reverse`
/// call can construct it. It cannot be cloned to submit another parent intent.
#[derive(Debug)]
pub struct ReverseWrite<'nat, 'pool> {
    parent: gnunet_tcp_communicator_core::registry::Instance<'pool>,
    peer: EddsaPublicKey,
    session: nat::Session<'nat>,
    epoch: nat::Epoch<'nat>,
    write: nat::WriteId<'nat>,
    admitted_at: u64,
    until: u64,
    local: SocketAddrV4,
    remote: SocketAddrV4,
}
impl<'nat, 'pool> ReverseWrite<'nat, 'pool> {
    /// Original same-Pool parent generation, not a new registry reservation.
    pub const fn parent(&self) -> gnunet_tcp_communicator_core::registry::Instance<'pool> {
        self.parent
    }
    /// Original expected signature-verified peer, still unverified by NAT.
    pub const fn peer(&self) -> EddsaPublicKey {
        self.peer
    }
    /// Original registration allocation.
    pub const fn session(&self) -> nat::Session<'nat> {
        self.session
    }
    /// Actual original attached MQ; replacements cannot acquire this write.
    pub const fn epoch(&self) -> nat::Epoch<'nat> {
        self.epoch
    }
    /// Actual admitted original write, used to match later native progress.
    pub const fn write(&self) -> nat::WriteId<'nat> {
        self.write
    }
    /// Same-clock sample immediately before actual local admission. No fallible
    /// sample after admission may lose the already admitted original write.
    pub const fn admitted_at(&self) -> u64 {
        self.admitted_at
    }
    /// Original finite write target, unchanged by polling or capacity retry.
    pub const fn until(&self) -> u64 {
        self.until
    }
    /// Official wildcard local IPv4 address and an actual bound listener port.
    pub const fn local(&self) -> SocketAddrV4 {
        self.local
    }
    /// Original remote IPv4 target; port zero denotes its requested reversal.
    pub const fn remote(&self) -> SocketAddrV4 {
        self.remote
    }
}
/// Sealed identity of one real held callback. A copy is diagnostic metadata,
/// never a connection, authenticated sender or right to release another frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReverseNotification<'id> {
    session: nat::Session<'id>,
    epoch: nat::Epoch<'id>,
    ordinal: u64,
    remote: SocketAddrV4,
}
enum ReverseOffer<'id> {
    Absent,
    Held,
    Ready(ReverseNotification<'id>),
}
impl<'id> ReverseNotification<'id> {
    /// Original registration allocation.
    pub const fn session(self) -> nat::Session<'id> {
        self.session
    }
    /// Original attached MQ source.
    pub const fn epoch(self) -> nat::Epoch<'id> {
        self.epoch
    }
    /// Original callback ordinal, checked again on explicit release.
    pub const fn ordinal(self) -> u64 {
        self.ordinal
    }
    /// Actual service-provided endpoint; it does not authenticate any peer.
    pub const fn remote(self) -> SocketAddrV4 {
        self.remote
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Origin<'id> {
    Listener,
    Interface,
    Nat(nat::Session<'id>, nat::Epoch<'id>, nat::AddressId<'id>),
}
struct Claim<'id> {
    origin: Origin<'id>,
    address: SocketAddr,
    hard: Option<Instant>,
}
#[derive(Clone)]
struct Text {
    bytes: [u8; 96],
    len: usize,
}
impl Text {
    fn new(address: SocketAddr) -> Result<Self, Fault> {
        let mut out = Self {
            bytes: [0; 96],
            len: 0,
        };
        write!(out, "tcp-{address}").map_err(|_| Fault::TooLarge)?;
        Ok(out)
    }
    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
impl fmt::Write for Text {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.len.checked_add(value.len()).ok_or(fmt::Error)?;
        let target = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
        target.copy_from_slice(value.as_bytes());
        self.len = end;
        Ok(())
    }
}
struct Row {
    address: SocketAddr,
    text: Text,
    id: u32,
    network: u32,
    published: bool,
}

pub(crate) struct NatSource<'id> {
    pub(crate) instance: &'id nat::Instance,
    pub(crate) endpoint: EndpointSource,
}

struct ConfiguredNat<'id> {
    source: NatSource<'id>,
    registration: Option<nat::Registration<'id>>,
}

/// Exclusive wrapper of the original Pool and its address-ID namespace. The
/// caller continues real session/IPC work through `pool_mut`; no second queue,
/// Pool, connection or clock is manufactured. Adopt before any address ADD.
/// Listeners stay borrowed, so the advertised physical listening owner survives.
pub struct PublishedPool<'id, 'pool, 'listeners> {
    state: Box<State<'id, 'listeners>>,
    port: Option<Port<'pool>>,
}
enum Port<'pool> {
    Peers(Box<Pool<'pool>>),
    Retained(gnunet_tcp_communicator_host::Resources),
}
impl<'pool> Port<'pool> {
    fn transport_epoch(&self) -> u64 {
        match self {
            Self::Peers(pool) => pool.transport_epoch(),
            Self::Retained(original) => original.transport_epoch(),
        }
    }
    fn transport_online(&self) -> bool {
        match self {
            Self::Peers(pool) => pool.transport_online(),
            Self::Retained(original) => original.transport_online(),
        }
    }
    fn advertise(&mut self, id: u32, address: &[u8], network: u32) -> Result<(), HostError> {
        match self {
            Self::Peers(pool) => pool.advertise(id, address, network),
            Self::Retained(original) => original.advertise(id, address, network),
        }
    }
    fn withdraw(&mut self, id: u32) -> Result<(), HostError> {
        match self {
            Self::Peers(pool) => pool.withdraw(id),
            Self::Retained(original) => original.withdraw(id),
        }
    }
    fn owns_reversal(&self, reversal: &crate::Reversal<'pool>) -> Result<(), Fault> {
        match self {
            Self::Peers(pool) => pool.owns_reversal(reversal),
            Self::Retained(_) => Err(Fault::NotReady),
        }
    }
}
struct State<'id, 'listeners> {
    transport_epoch: u64,
    listeners: &'listeners Listeners,
    clock: Arc<dyn RuntimeClock>,
    subscription: Option<Box<dyn ClockSubscription>>,
    revision: u64,
    options: Options,
    limits: Limits,
    bindings: Vec<SocketAddr>,
    rows: Vec<Row>,
    claims: Vec<Claim<'id>>,
    desired: Vec<SocketAddr>,
    interfaces: Vec<InterfaceAddress>,
    interface_valid: bool,
    interface_hard: Instant,
    next_id: u32,
    nat: Option<ConfiguredNat<'id>>,
    pending_end: Option<nat::End<'id>>,
    pending_expired: Option<nat::WriteEnd<'id>>,
    reverse_notified: Option<ReverseNotification<'id>>,
    hard: Option<Instant>,
    next_scan: Instant,
    retry: Option<Instant>,
    cursor: usize,
    alarm: Pin<Box<Sleep>>,
    closing: bool,
    close_hard: Option<Instant>,
    close_error: Option<Failure>,
    terminal: bool,
    aborted: bool,
}
fn reserve<T>(n: usize) -> Result<Vec<T>, Fault> {
    let mut out = Vec::new();
    out.try_reserve_exact(n).map_err(|_| Fault::Capacity)?;
    Ok(out)
}
fn usable(a: SocketAddr, disable_v6: bool) -> bool {
    a.port() != 0 && usable_ip(a, disable_v6)
}
fn usable_ip(a: SocketAddr, disable_v6: bool) -> bool {
    !a.ip().is_unspecified()
        && !a.ip().is_multicast()
        && !matches!(a.ip(), IpAddr::V4(ip) if ip.is_broadcast())
        && !(disable_v6 && a.is_ipv6())
}
fn nat_usable(a: SocketAddr, disable_v6: bool) -> bool {
    // An actual NAT IPv4 port-zero observation is the official reversal hint.
    // It is published unchanged; it is never an ordinary connectable endpoint.
    (a.port() != 0 || a.is_ipv4()) && usable_ip(a, disable_v6)
}
fn candidate(mut address: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(v6) = &mut address {
        v6.set_flowinfo(0);
    }
    address
}
fn wire(a: SocketAddr) -> nat::ipc::Address<'static> {
    match a {
        SocketAddr::V4(a) => nat::ipc::Address::V4 {
            ip: a.ip().octets(),
            port: a.port(),
        },
        SocketAddr::V6(a) => nat::ipc::Address::V6 {
            ip: a.ip().octets(),
            port: a.port(),
            flow: a.flowinfo(),
            scope: a.scope_id(),
        },
    }
}
fn socket(a: nat::ipc::Address<'_>) -> Result<SocketAddr, Fault> {
    match a {
        nat::ipc::Address::V4 { ip, port } => Ok(SocketAddr::new(ip.into(), port)),
        nat::ipc::Address::V6 {
            ip,
            port,
            flow,
            scope,
        } => Ok(SocketAddrV6::new(ip.into(), port, flow, scope).into()),
        nat::ipc::Address::Unix(_) => Err(Fault::Malformed),
    }
}
impl<'id, 'listeners> PublishedPool<'id, 'static, 'listeners> {
    pub(crate) fn resume_identity<'next>(
        self,
        setup: crate::Setup<'next, ()>,
    ) -> Result<PublishedPool<'id, 'next, 'listeners>, Failure> {
        let Self { state, port } = self;
        let Some(Port::Retained(services)) = port else {
            return Err(Fault::Conflict.into());
        };
        let socket_policy = state.listeners.socket_policy().clone();
        let pool = Pool::resume(crate::Setup {
            services,
            identity: setup.identity,
            scope: setup.scope,
            slots: setup.slots,
            buffers: setup.buffers,
            policy: setup.policy,
            ipc: setup.ipc,
            capacity: setup.capacity,
            disable_v6: setup.disable_v6,
        })
        .map_err(Failure::Transport)?
        .with_socket_policy(socket_policy);
        Ok(PublishedPool {
            state,
            port: Some(Port::Peers(Box::new(pool))),
        })
    }
}
impl<'id, 'pool, 'listeners> PublishedPool<'id, 'pool, 'listeners> {
    pub(crate) fn retain_identity_resources(
        mut self,
    ) -> Result<
        (
            PublishedPool<'id, 'static, 'listeners>,
            crate::epoch::Quiescent,
        ),
        gnunet_types::Rejected<Self>,
    > {
        let Some(Port::Peers(pool)) = self.port.take() else {
            return Err(gnunet_types::Rejected {
                reason: Fault::NotReady,
                value: self,
            });
        };
        match (*pool).into_resources() {
            Ok((resources, proof)) => {
                let Self { state, .. } = self;
                Ok((
                    PublishedPool {
                        state,
                        port: Some(Port::Retained(resources)),
                    },
                    proof,
                ))
            }
            Err(rejected) => {
                self.port = Some(Port::Peers(Box::new(rejected.value)));
                Err(gnunet_types::Rejected {
                    reason: rejected.reason,
                    value: self,
                })
            }
        }
    }
    /// Perform every fallible validation/reservation before taking the original
    /// Pool. Failure leaves `pool` untouched and performs no registration IO.
    /// The source must be the caller's actual NAT selector on the same process
    /// clock/Resolver. The pool's address namespace must not have prior ADDs.
    pub fn try_adopt(
        pool: &mut Option<Pool<'pool>>,
        listeners: &'listeners Listeners,
        instance: &'id nat::Instance,
        source: EndpointSource,
        clock: Arc<dyn RuntimeClock>,
        options: Options,
        limits: Limits,
    ) -> Result<Self, Failure> {
        let endpoint = source.snapshot().map_err(nat::Error::from)?;
        Self::try_adopt_with_nat(
            pool,
            listeners,
            Some(NatSource { instance, endpoint }),
            clock,
            options,
            limits,
        )
    }

    #[expect(
        clippy::too_many_lines,
        reason = "All fallible source, metadata and registration preparation precedes the single original Pool transfer"
    )]
    pub(crate) fn try_adopt_with_nat(
        pool: &mut Option<Pool<'pool>>,
        listeners: &'listeners Listeners,
        nat: Option<NatSource<'id>>,
        clock: Arc<dyn RuntimeClock>,
        options: Options,
        limits: Limits,
    ) -> Result<Self, Failure> {
        if pool.is_none()
            || limits.bindings == 0
            || limits.addresses == 0
            || limits.claims < limits.addresses
            || limits.capacity_retry.is_zero()
            || options.send_timeout.is_zero()
            || options.scan_interval.is_zero()
            || options.freshness < options.scan_interval
            || options.retirement.is_zero()
        {
            return Err(Fault::InvalidInput.into());
        }
        let at = Instant::now();
        if nat
            .as_ref()
            .is_some_and(|source| !Arc::ptr_eq(&clock, &source.endpoint.clock()))
        {
            return Err(Fault::InvalidInput.into());
        }
        let sample = clock.sample().map_err(Failure::Clock)?;
        let hard = if options.until == u64::MAX {
            None
        } else {
            let remaining = options
                .until
                .checked_sub(sample.now.as_micros())
                .filter(|n| *n > 0)
                .ok_or(Fault::Deadline)?;
            Some(
                at.checked_add(Duration::from_micros(remaining))
                    .ok_or(Fault::Overflow)?,
            )
        };
        let latest = hard
            .unwrap_or(at)
            .checked_add(options.retirement)
            .ok_or(Fault::Overflow)?;
        latest
            .checked_add(options.scan_interval)
            .ok_or(Fault::Overflow)?;
        latest
            .checked_add(options.freshness)
            .ok_or(Fault::Overflow)?;
        latest
            .checked_add(limits.capacity_retry)
            .ok_or(Fault::Overflow)?;
        at.checked_add(options.scan_interval)
            .ok_or(Fault::Overflow)?;
        at.checked_add(options.freshness).ok_or(Fault::Overflow)?;
        at.checked_add(limits.capacity_retry)
            .ok_or(Fault::Overflow)?;
        let mut bindings = reserve(limits.bindings)?;
        for &a in listeners.addresses() {
            if options.disable_v6 && a.is_ipv6() {
                continue;
            }
            if a.port() == 0 {
                return Err(Fault::InvalidInput.into());
            }
            if !bindings.contains(&a) {
                if bindings.len() == limits.bindings {
                    return Err(Fault::Capacity.into());
                }
                bindings.push(a);
            }
        }
        if bindings.is_empty() && listeners.mode() != crate::settings::PeerMode::OutboundOnly {
            return Err(Fault::InvalidInput.into());
        }
        if listeners.mode() == crate::settings::PeerMode::OutboundOnly && nat.is_some() {
            return Err(Fault::InvalidInput.into());
        }
        let mut rows = reserve(limits.addresses)?;
        let mut claims = reserve(limits.claims)?;
        let mut next_id = 0u32;
        for &bound in &bindings {
            let address = candidate(bound);
            if usable(address, options.disable_v6)
                && !rows.iter().any(|r: &Row| r.address == address)
            {
                if rows.len() == limits.addresses || claims.len() == limits.claims {
                    return Err(Fault::Capacity.into());
                }
                let text = Text::new(address)?;
                next_id = next_id.checked_add(1).ok_or(Fault::Overflow)?;
                rows.push(Row {
                    address,
                    text,
                    id: next_id,
                    network: if address.ip().is_loopback() { 1 } else { 0 },
                    published: false,
                });
                claims.push(Claim {
                    origin: Origin::Listener,
                    address,
                    hard,
                });
            }
        }
        let desired = reserve(limits.claims)?;
        let subscription = clock.subscribe().map_err(Failure::Clock)?;
        let nat = nat
            .map(|source| {
                let registration = Self::open_nat(&source, &bindings, options, limits)?;
                Ok::<_, Failure>(ConfiguredNat {
                    source,
                    registration: Some(registration),
                })
            })
            .transpose()?;
        if hard.is_some_and(|bound| Instant::now() >= bound) {
            return Err(Fault::Deadline.into());
        }
        let alarm = Box::pin(tokio::time::sleep_until(at));
        // All fallible work is complete. The exclusive native Pool moves once.
        let transport_epoch = pool.as_ref().ok_or(Fault::Closed)?.transport_epoch();
        let original = pool.take();
        Ok(Self {
            port: original.map(|pool| Port::Peers(Box::new(pool))),
            state: Box::new(State {
                transport_epoch,
                listeners,
                clock,
                subscription: Some(subscription),
                revision: sample.revision,
                options,
                limits,
                bindings,
                rows,
                claims,
                desired,
                interfaces: Vec::new(),
                interface_valid: false,
                interface_hard: at,
                next_id,
                nat,
                pending_end: None,
                pending_expired: None,
                reverse_notified: None,
                hard,
                next_scan: at,
                retry: None,
                cursor: 0,
                alarm,
                closing: false,
                close_hard: None,
                close_error: None,
                terminal: false,
                aborted: false,
            }),
        })
    }
    fn open_nat(
        source: &NatSource<'id>,
        bindings: &[SocketAddr],
        options: Options,
        limits: Limits,
    ) -> Result<nat::Registration<'id>, Failure> {
        let profile = nat::native_profile()?;
        let mut bytes: Vec<u8> = reserve(bindings.len().checked_mul(28).ok_or(Fault::Overflow)?)?;
        bytes.resize(bindings.len() * 28, 0);
        let mut writer = nat::ipc::AddressWriter::new(&mut bytes, profile);
        for &address in bindings {
            writer.push(wire(address))?;
        }
        let now = source
            .endpoint
            .clock()
            .sample()
            .map_err(Failure::Clock)?
            .now
            .as_micros();
        let send = u64::try_from(options.send_timeout.as_micros()).map_err(|_| Fault::Overflow)?;
        let send_until = now
            .checked_add(send)
            .ok_or(Fault::Overflow)?
            .min(options.until);
        Ok(nat::Registration::new(
            source.instance,
            source.endpoint.duplicate().map_err(nat::Error::from)?,
            nat::RegistrationRequest {
                flags: nat::ipc::ADDRESSES | nat::ipc::REVERSAL,
                protocol: 6,
                addresses: writer.addresses(),
                section: b"communicator-tcp",
            },
            nat::Profiles::same(profile),
            nat::Deadlines {
                send_until,
                first_input_until: None,
                until: options.until,
            },
            limits.nat,
        )?)
    }

    fn registration(&self) -> Option<&nat::Registration<'id>> {
        self.state.nat.as_ref()?.registration.as_ref()
    }

    fn registration_mut(&mut self) -> Option<&mut nat::Registration<'id>> {
        self.state.nat.as_mut()?.registration.as_mut()
    }

    fn take_registration(&mut self) -> Option<nat::Registration<'id>> {
        self.state.nat.as_mut()?.registration.take()
    }
    /// Original Pool only; the enclosing caller fairly drives its actual queues,
    /// session callbacks and retirement using the same original ClockPort.
    pub fn pool_mut(&mut self) -> Option<&mut Pool<'pool>> {
        match self.port.as_mut()? {
            Port::Peers(pool) => Some(pool.as_mut()),
            Port::Retained(_) => None,
        }
    }
    pub(crate) fn retained_input_idle(&self) -> bool {
        matches!(&self.port, Some(Port::Retained(original)) if original.input_idle())
    }
    /// Original still-borrowed physical listener owner.
    pub fn listeners(&self) -> &Listeners {
        self.state.listeners
    }
    /// Same actual clock/Resolver domain retained by the fixed endpoint selector.
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.state.clock.clone()
    }
    fn guard_nat(&mut self, cx: &mut Context<'_>) -> Result<(), Failure> {
        // Return the retained original observation before admitting another
        // action; a getter must not overwrite or silently consume its result.
        if self.state.pending_end.is_some() || self.state.pending_expired.is_some() {
            return Err(Fault::WouldBlock.into());
        }
        let registration = self.registration_mut().ok_or(Fault::NotReady)?;
        match registration.poll_native_guard(cx, None) {
            Poll::Pending => Ok(()),
            Poll::Ready(Ok(nat::Progress::WriteExpired(write))) => {
                self.state.pending_expired = Some(write);
                cx.waker().wake_by_ref();
                Err(Fault::WouldBlock.into())
            }
            Poll::Ready(Ok(nat::Progress::Ended(end))) => {
                let clock_failed = matches!(
                    &end.source.cause,
                    nat::Cause::Clock(_) | nat::Cause::Error(nat::Error::Clock(_))
                );
                self.retire_nat_claims();
                drop(self.take_registration());
                self.state.reverse_notified = None;
                self.state.pending_end = Some(end);
                cx.waker().wake_by_ref();
                if clock_failed {
                    self.begin_close();
                }
                Err(Fault::Closed.into())
            }
            // Registration's native-only API emits only the two real original
            // retirement classes above. It never reads, decodes or emits a
            // connection/notification/wait observation from this seam.
            Poll::Ready(Ok(_)) => Err(Fault::Conflict.into()),
            Poll::Ready(Err(error)) => {
                self.begin_close();
                Err(error.into())
            }
        }
    }
    /// Submit the original same-Pool IPv4/port-zero reversal intent through this
    /// owner's existing NAT Registration. Success is immutable local admission,
    /// not whole write, NAT acceptance or authenticated reversal completion.
    /// The caller retains its original CREATE/deadline until actual resolution.
    /// An owner without a configured NAT endpoint refuses new reversals.
    pub fn request_reversal(
        &mut self,
        cx: &mut Context<'_>,
        reversal: &crate::Reversal<'pool>,
        until: u64,
    ) -> Result<ReverseWrite<'id, 'pool>, Failure> {
        if self.state.nat.is_none() {
            return Err(Fault::Unavailable.into());
        }
        self.guard_nat(cx)?;
        if self.is_retiring() {
            return Err(Fault::Closed.into());
        }
        self.check_native()?;
        self.port
            .as_ref()
            .ok_or(Fault::Closed)?
            .owns_reversal(reversal)?;
        let local = self
            .state
            .bindings
            .iter()
            .find_map(|address| match address {
                SocketAddr::V4(address) => {
                    Some(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, address.port()))
                }
                SocketAddr::V6(_) => None,
            })
            .ok_or(Fault::Unavailable)?;
        let remote = SocketAddrV4::new(reversal.remote(), 0);
        let registration = self
            .state
            .nat
            .as_mut()
            .and_then(|nat| nat.registration.as_mut())
            .ok_or(Fault::NotReady)?;
        let epoch = registration.epoch().ok_or(Fault::NotReady)?;
        if !registration.is_current(epoch)
            || !matches!(
                registration.registered_submission(),
                nat::Submission::Written { .. }
            )
        {
            return Err(Fault::NotReady.into());
        }
        // Derive the ABI from the actual retained REGISTER, not a guessed
        // replacement profile or a newly opened NAT connection.
        let profile = match registration.registration()? {
            nat::ipc::Request::Register { addresses, .. } => {
                addresses.iter().next().ok_or(Fault::NotReady)?.profile()
            }
            _ => return Err(Fault::Conflict.into()),
        };
        let now = self
            .state
            .clock
            .sample()
            .map_err(Failure::Clock)?
            .now
            .as_micros();
        if until == u64::MAX
            || until <= now
            || until > self.state.options.until
            || self.state.hard.is_some_and(|hard| Instant::now() >= hard)
        {
            return Err(Fault::Deadline.into());
        }
        let mut local_bytes = [0; 16];
        let mut remote_bytes = [0; 16];
        wire(SocketAddr::V4(local)).encode(profile, &mut local_bytes)?;
        wire(SocketAddr::V4(remote)).encode(profile, &mut remote_bytes)?;
        let local_raw = nat::ipc::RawAddress::decode(&local_bytes, profile)?;
        let remote_raw = nat::ipc::RawAddress::decode(&remote_bytes, profile)?;
        let write = registration.reverse(local_raw, remote_raw, until)?;
        // All fallible preparation preceded the actual admission. Keep this
        // exact write even if clock/backend health changes immediately after it.
        Ok(ReverseWrite {
            parent: reversal.id(),
            peer: reversal.peer(),
            session: registration.session(),
            epoch,
            write,
            admitted_at: now,
            until,
            local,
            remote,
        })
    }
    fn check_reverse_write(&self, original: &ReverseWrite<'id, 'pool>) -> Result<(), Failure> {
        let registration = self.registration().ok_or(Fault::Stale)?;
        if registration.session() != original.session || !registration.is_current(original.epoch) {
            return Err(Fault::Stale.into());
        }
        Ok(())
    }
    /// Inspect only the retained original pending write. Completed writes are
    /// reported by actual `Event::Nat(Written)` and are not retained indefinitely.
    pub fn reversal_submission(
        &self,
        original: &ReverseWrite<'id, 'pool>,
    ) -> Result<nat::Submission, Failure> {
        self.check_reverse_write(original)?;
        Ok(self
            .registration()
            .ok_or(Fault::Stale)?
            .submission(original.write)?)
    }
    /// Remove only a genuinely zero-exposure original write. None means no
    /// cancellation was performed: its actual Written/WriteExpired/End facts
    /// remain authoritative. A partial/finished write never closes the shared
    /// NAT source merely because one peer's request was canceled.
    pub fn cancel_unexposed_reverse(
        &mut self,
        cx: &mut Context<'_>,
        original: &ReverseWrite<'id, 'pool>,
    ) -> Result<Option<nat::WriteEnd<'id>>, Failure> {
        self.guard_nat(cx)?;
        self.check_reverse_write(original)?;
        let registration = self.registration_mut().ok_or(Fault::Stale)?;
        match registration.submission(original.write) {
            Ok(nat::Submission::Unsent) => {}
            Ok(_) | Err(nat::Error::Protocol(Fault::Stale)) => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        match registration.cancel_write(original.write)? {
            nat::Cancel::Unsent(write) => Ok(Some(write)),
            nat::Cancel::SessionClosed(end) => {
                // This proof can only name a Reverse command, never REGISTER.
                // Preserve any actual unexpected retirement instead of losing
                // the original End or pretending the write was unexposed.
                self.retire_nat_claims();
                drop(self.take_registration());
                self.state.reverse_notified = None;
                self.state.pending_end = Some(end);
                Err(Fault::OutcomeUnknown.into())
            }
        }
    }
    fn current_reverse(&self) -> Result<Option<ReverseNotification<'id>>, Failure> {
        let Some(registration) = self.registration() else {
            return Ok(None);
        };
        let Some(notification) = registration.notification()? else {
            return Ok(None);
        };
        if !registration.is_current(notification.epoch) {
            return Err(Fault::Stale.into());
        }
        let nat::ipc::Response::Reverse { remote } = notification.response else {
            return Ok(None);
        };
        let SocketAddr::V4(remote) = socket(remote.address())? else {
            return Err(Fault::Malformed.into());
        };
        Ok(Some(ReverseNotification {
            session: notification.session,
            epoch: notification.epoch,
            ordinal: notification.ordinal,
            remote,
        }))
    }
    /// View the original held callback after its native deadline guard. This
    /// performs no new read/clock sample and does not release the callback.
    pub fn reverse_notification(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Result<Option<ReverseNotification<'id>>, Failure> {
        if self.state.nat.is_none() {
            return Ok(None);
        }
        self.guard_nat(cx)?;
        if self.is_retiring() {
            return Err(Fault::Closed.into());
        }
        self.current_reverse()
    }
    /// Borrow the complete original held callback, including untouched producer
    /// sockaddr bytes, only for this exact sealed session/epoch/ordinal view.
    /// This inspection provides no source-liveness or authentication receipt.
    pub fn reverse_frame(
        &self,
        original: &ReverseNotification<'id>,
    ) -> Result<nat::Notification<'_, 'id>, Failure> {
        if self.current_reverse()? != Some(*original) {
            return Err(Fault::Stale.into());
        }
        self.registration()
            .ok_or(Fault::Stale)?
            .notification()?
            .ok_or_else(|| Fault::Stale.into())
    }
    /// Release only this same original held Reverse callback after its actual
    /// consumer admitted/refused the connectback intent. Source retirement keeps
    /// the unreleased full callback in its original End. An expired input guard
    /// closes the original MQ before this call may clear anything.
    pub fn release_reverse(&mut self, original: &ReverseNotification<'id>) -> Result<(), Failure> {
        if self.current_reverse()? != Some(*original) {
            return Err(Fault::Stale.into());
        }
        self.registration_mut()
            .ok_or(Fault::Stale)?
            .release_notification()?;
        self.state.reverse_notified = None;
        Ok(())
    }
    fn offer_reverse(&mut self) -> Result<ReverseOffer<'id>, Failure> {
        let Some(notification) = self.current_reverse()? else {
            return Ok(ReverseOffer::Absent);
        };
        if self.state.reverse_notified == Some(notification) {
            Ok(ReverseOffer::Held)
        } else {
            self.state.reverse_notified = Some(notification);
            Ok(ReverseOffer::Ready(notification))
        }
    }
    /// Explicit new registration intent after the previous NAT source and all its
    /// original claims retired. It cannot extend the owner hard/absolute targets,
    /// retarget live configuration or replay a prior reverse/mapping mutation.
    pub fn restart_nat(&mut self) -> Result<(), Failure> {
        if self.state.nat.is_none() {
            return Err(Fault::Unavailable.into());
        }
        let result = self.restart_nat_inner();
        if result.is_err() && !matches!(&result, Err(Failure::Protocol(Fault::Conflict))) {
            self.begin_close();
        }
        result
    }
    fn restart_nat_inner(&mut self) -> Result<(), Failure> {
        if self.state.closing
            || self.registration().is_some()
            || self.state.pending_end.is_some()
            || self.state.pending_expired.is_some()
            || self
                .state
                .claims
                .iter()
                .any(|c| matches!(c.origin, Origin::Nat(..)))
            || self
                .state
                .rows
                .iter()
                .any(|row| !self.state.claims.iter().any(|c| c.address == row.address))
        {
            return Err(Fault::Conflict.into());
        }
        self.check_native()?;
        if self.state.options.until != u64::MAX
            && self
                .state
                .clock
                .sample()
                .map_err(Failure::Clock)?
                .now
                .as_micros()
                >= self.state.options.until
        {
            return Err(Fault::Deadline.into());
        }
        let configured = self.state.nat.as_ref().ok_or(Fault::Unavailable)?;
        let registration = Self::open_nat(
            &configured.source,
            &self.state.bindings,
            self.state.options,
            self.state.limits,
        )?;
        self.check_native()?;
        self.state
            .nat
            .as_mut()
            .ok_or(Fault::Unavailable)?
            .registration = Some(registration);
        Ok(())
    }
    fn check_native(&self) -> Result<(), Failure> {
        if self.state.hard.is_some_and(|bound| Instant::now() >= bound) {
            Err(Fault::Deadline.into())
        } else {
            Ok(())
        }
    }
    fn retire_nat_claims(&mut self) {
        self.state
            .claims
            .retain(|c| !matches!(c.origin, Origin::Nat(..)));
    }
    /// Clock-free stop of fresh work and actual NAT MQ close. Original removals
    /// retain their exact FIFO intent until enqueue or this owner's forced drop.
    pub fn begin_close(&mut self) {
        if self.state.closing {
            return;
        }
        self.state.closing = true;
        self.state.reverse_notified = None;
        self.state.subscription = None;
        self.state.claims.clear();
        let now = Instant::now();
        let anchor = self.state.hard.map_or(now, |bound| now.min(bound));
        self.state.close_hard = anchor.checked_add(self.state.options.retirement);
        if self.state.close_hard.is_none() {
            self.state.close_hard = Some(now);
            self.state.close_error = Some(Fault::Overflow.into());
        }
        if let Some(mut registration) = self.take_registration() {
            self.state.pending_end = registration.close();
        }
        self.state.retry = None;
    }
    /// Physical abort of this original Pool/NAT MQ. No clean epoch receipt is
    /// produced; original queued/partial work is lost with its original owner.
    pub fn abort(&mut self) {
        self.begin_close();
        self.port = None;
        self.state.rows.clear();
        self.state.aborted = true;
    }
    /// Permanent gate for fresh accepts/CREATE/session admissions by the enclosing
    /// caller. Cleanup may still drive the same Pool without sampling a new clock.
    pub fn is_retiring(&self) -> bool {
        self.state.closing || self.state.aborted || self.port.is_none()
    }
    /// Whether all removals have been queued and NAT closed. This says nothing
    /// about the Pool's actual write/peer/drain/clean-epoch obligations.
    pub fn is_closed(&self) -> bool {
        self.state.terminal && !self.state.aborted
    }
    /// Transfer the exact same original Pool after address retirement. Any queued
    /// 1201 remains in that real FIFO and must still be driven to write or loss.
    /// This address-ID namespace must not be reused by another owner on this MQ.
    pub fn take_pool(&mut self) -> Result<Pool<'pool>, Fault> {
        if !self.is_closed()
            || self.state.pending_end.is_some()
            || self.state.pending_expired.is_some()
            || !self.state.rows.is_empty()
        {
            return Err(Fault::WouldBlock);
        }
        match self.port.take().ok_or(Fault::Closed)? {
            Port::Peers(pool) => Ok(*pool),
            Port::Retained(original) => {
                self.port = Some(Port::Retained(original));
                Err(Fault::NotReady)
            }
        }
    }
    fn network(&self, address: SocketAddr) -> u32 {
        if address.ip().is_loopback() {
            return 1;
        }
        if !self.state.interface_valid || Instant::now() >= self.state.interface_hard {
            return 0;
        }
        if self.state.interfaces.iter().any(|row| {
            match (address.ip(), row.address.ip(), row.netmask) {
                (IpAddr::V4(a), IpAddr::V4(b), Some(IpAddr::V4(m))) => a
                    .octets()
                    .into_iter()
                    .zip(b.octets())
                    .zip(m.octets())
                    .all(|((a, b), m)| a & m == b & m),
                (IpAddr::V6(a), IpAddr::V6(b), Some(IpAddr::V6(m))) => a
                    .octets()
                    .into_iter()
                    .zip(b.octets())
                    .zip(m.octets())
                    .all(|((a, b), m)| a & m == b & m),
                _ => false,
            }
        }) {
            2
        } else {
            3
        }
    }
    fn new_row(&mut self, address: SocketAddr) -> Result<(), Fault> {
        if self.state.rows.iter().any(|r| r.address == address) {
            return Ok(());
        }
        if self.state.rows.len() == self.state.limits.addresses {
            return Err(Fault::Capacity);
        }
        let id = self.state.next_id.checked_add(1).ok_or(Fault::Overflow)?;
        let text = Text::new(address)?;
        let network = self.network(address);
        self.state.rows.push(Row {
            address,
            text,
            id,
            network,
            published: false,
        });
        self.state.next_id = id;
        Ok(())
    }
    fn refresh(&mut self) -> Result<usize, Failure> {
        let started = Instant::now();
        self.state.next_scan = started
            .checked_add(self.state.options.scan_interval)
            .ok_or(Fault::Overflow)?;
        self.check_native()?;
        let rows =
            interfaces::snapshot(self.state.limits.interfaces).map_err(Failure::Interfaces)?;
        self.check_native()?;
        if self.state.options.until != u64::MAX
            && self
                .state
                .clock
                .sample()
                .map_err(Failure::Clock)?
                .now
                .as_micros()
                >= self.state.options.until
        {
            return Err(Fault::Deadline.into());
        }
        self.state.desired.clear();
        for row in &rows {
            if !row.is_up() {
                continue;
            }
            for bound in &self.state.bindings {
                if !bound.ip().is_unspecified() || bound.is_ipv4() != row.address.is_ipv4() {
                    continue;
                }
                let mut address = candidate(row.address);
                address.set_port(bound.port());
                if usable(address, self.state.options.disable_v6)
                    && !self.state.desired.contains(&address)
                {
                    if self.state.desired.len() == self.state.limits.claims {
                        return Err(Fault::Capacity.into());
                    }
                    self.state.desired.push(address);
                }
            }
        }
        let others = self
            .state
            .claims
            .iter()
            .filter(|c| c.origin != Origin::Interface)
            .count();
        let new_rows = self
            .state
            .desired
            .iter()
            .filter(|a| !self.state.rows.iter().any(|r| r.address == **a))
            .count();
        if others
            .checked_add(self.state.desired.len())
            .is_none_or(|n| n > self.state.limits.claims)
            || self
                .state
                .rows
                .len()
                .checked_add(new_rows)
                .is_none_or(|n| n > self.state.limits.addresses)
            || u32::try_from(new_rows)
                .ok()
                .and_then(|n| self.state.next_id.checked_add(n))
                .is_none()
        {
            return Err(Fault::Capacity.into());
        }
        // Preflight formatting before replacing any old snapshot claims.
        for &address in &self.state.desired {
            Text::new(address)?;
        }
        let fresh = started
            .checked_add(self.state.options.freshness)
            .ok_or(Fault::Overflow)?;
        let fresh = self.state.hard.map_or(fresh, |bound| fresh.min(bound));
        if Instant::now() >= fresh {
            return Err(Fault::Deadline.into());
        }
        self.state.interfaces = rows;
        self.state.interface_valid = true;
        self.state.interface_hard = fresh;
        self.state.claims.retain(|c| c.origin != Origin::Interface);
        for i in 0..self.state.desired.len() {
            let address = self.state.desired[i];
            self.new_row(address)?;
            self.state.claims.push(Claim {
                origin: Origin::Interface,
                address,
                hard: Some(fresh),
            });
        }
        for i in 0..self.state.rows.len() {
            if !self.state.rows[i].published {
                self.state.rows[i].network = self.network(self.state.rows[i].address);
            }
        }
        Ok(self.state.desired.len())
    }
    fn notification(&mut self) -> Result<Option<bool>, Failure> {
        let Some(registration) = self.registration() else {
            return Ok(None);
        };
        let Some(observation) = registration.notification()? else {
            return Ok(None);
        };
        if !registration.is_current(observation.epoch) {
            return Err(Fault::StaleGeneration.into());
        }
        let nat::ipc::Response::AddressChange {
            add_remove,
            address,
            ..
        } = observation.response
        else {
            return Err(Fault::Malformed.into());
        };
        if add_remove != 0 && add_remove != 1 {
            return Err(Fault::Malformed.into());
        }
        let id = observation.address_id.ok_or(Fault::Stale)?;
        let origin = Origin::Nat(observation.session, observation.epoch, id);
        let address = candidate(socket(address.address())?);
        if add_remove == 1 && nat_usable(address, self.state.options.disable_v6) {
            if !self.state.claims.iter().any(|c| c.origin == origin) {
                if self.state.claims.len() == self.state.limits.claims {
                    return Ok(Some(false));
                }
                if !self.state.rows.iter().any(|r| r.address == address)
                    && self.state.rows.len() == self.state.limits.addresses
                {
                    return Ok(Some(false));
                }
                self.new_row(address)?;
                self.state.claims.push(Claim {
                    origin,
                    address,
                    hard: self.state.hard,
                });
            }
        } else if add_remove == 0 {
            self.state.claims.retain(|c| c.origin != origin);
        }
        self.registration_mut()
            .ok_or(Fault::Closed)?
            .release_notification()?;
        Ok(Some(true))
    }
    fn alarm(&mut self, cx: &mut Context<'_>) {
        let mut at = if self.state.closing {
            self.state.close_hard.unwrap_or_else(Instant::now)
        } else if self.state.bindings.is_empty() {
            // No listener/interface/NAT claims exist in outbound-only mode.
            // Preserve a caller's finite lifetime without a periodic scan wake.
            match self.state.hard {
                Some(bound) => bound,
                None => return,
            }
        } else {
            self.state.hard.map_or(self.state.next_scan, |bound| {
                bound.min(self.state.next_scan)
            })
        };
        if let Some(retry) = self.state.retry {
            at = at.min(retry);
        }
        for claim in &self.state.claims {
            if let Some(bound) = claim.hard {
                at = at.min(bound);
            }
        }
        self.state.alarm.as_mut().reset(at);
        if self.state.alarm.as_mut().poll(cx).is_ready() {
            cx.waker().wake_by_ref();
        }
    }
    fn defer_retry(&mut self) -> Option<Event<'id>> {
        match Instant::now().checked_add(self.state.limits.capacity_retry) {
            Some(at) => {
                self.state.retry = Some(at);
                None
            }
            None => {
                self.begin_close();
                Some(Event::Failed(Fault::Overflow.into()))
            }
        }
    }
    fn publish(&mut self) -> Result<Option<Event<'id>>, Failure> {
        // Remove old unsupported claims before offering any new ADD. Aggregated
        // references keep one shared address live across interface/NAT turnover.
        if let Some(i) = self
            .state
            .rows
            .iter()
            .position(|r| !self.state.claims.iter().any(|c| c.address == r.address))
        {
            if !self.state.rows[i].published {
                self.state.rows.remove(i);
                return Ok(Some(Event::Ignored));
            }
            let id = self.state.rows[i].id;
            self.port
                .as_mut()
                .ok_or(Fault::Closed)?
                .withdraw(id)
                .map_err(Failure::Transport)?;
            self.state.rows.remove(i);
            return Ok(Some(Event::RemoveQueued { id }));
        }
        if !self.state.closing
            && self.port.as_ref().is_some_and(Port::transport_online)
            && let Some(i) = self.state.rows.iter().position(|r| !r.published)
        {
            let row = &self.state.rows[i];
            self.port
                .as_mut()
                .ok_or(Fault::Closed)?
                .advertise(row.id, row.text.bytes(), row.network)
                .map_err(Failure::Transport)?;
            self.state.rows[i].published = true;
            return Ok(Some(Event::AddQueued {
                id: self.state.rows[i].id,
                address: self.state.rows[i].address,
            }));
        }
        Ok(None)
    }
    fn nat_progress(
        &mut self,
        progress: nat::Progress<'id>,
        retry_ready: bool,
    ) -> Option<Event<'id>> {
        match progress {
            nat::Progress::Ended(end) => {
                let clock_failed = matches!(
                    &end.source.cause,
                    nat::Cause::Clock(_) | nat::Cause::Error(nat::Error::Clock(_))
                );
                self.retire_nat_claims();
                drop(self.take_registration());
                self.state.reverse_notified = None;
                if clock_failed {
                    self.begin_close();
                }
                Some(Event::Nat(nat::Progress::Ended(end)))
            }
            progress => {
                if matches!(progress, nat::Progress::Notification { .. }) {
                    match self.offer_reverse() {
                        Ok(ReverseOffer::Ready(notification)) => {
                            return Some(Event::ReverseReady(notification));
                        }
                        Ok(ReverseOffer::Held) => return None,
                        Ok(ReverseOffer::Absent) => {}
                        Err(error) => {
                            self.begin_close();
                            return Some(Event::Failed(error));
                        }
                    }
                }
                if matches!(progress, nat::Progress::Notification { .. }) && retry_ready {
                    match self.notification() {
                        Ok(Some(true)) => Some(Event::Nat(progress)),
                        Ok(Some(false)) => self.defer_retry(),
                        Ok(None) => {
                            self.begin_close();
                            Some(Event::Failed(Fault::Stale.into()))
                        }
                        Err(e) => {
                            self.begin_close();
                            Some(Event::Failed(e))
                        }
                    }
                } else {
                    Some(Event::Nat(progress))
                }
            }
        }
    }
    fn poll_nat(&mut self, cx: &mut Context<'_>, retry_ready: bool) -> Option<Event<'id>> {
        if self.state.closing {
            return None;
        }
        let registration = self.registration_mut()?;
        match registration.poll(cx, None) {
            Poll::Ready(Ok(progress)) => return self.nat_progress(progress, retry_ready),
            Poll::Ready(Err(e)) => {
                self.begin_close();
                return Some(Event::Failed(Failure::Nat(e)));
            }
            Poll::Pending => {}
        }
        if retry_ready {
            match self.offer_reverse() {
                Ok(ReverseOffer::Ready(notification)) => {
                    return Some(Event::ReverseReady(notification));
                }
                Ok(ReverseOffer::Held) => return None,
                Ok(ReverseOffer::Absent) => {}
                Err(error) => {
                    self.begin_close();
                    return Some(Event::Failed(error));
                }
            }
            match self.notification() {
                Ok(Some(true)) => return Some(Event::Ignored),
                Ok(Some(false)) => return self.defer_retry(),
                Ok(None) => {}
                Err(e) => {
                    self.begin_close();
                    return Some(Event::Failed(e));
                }
            }
        }
        None
    }
    fn poll_publication(&mut self, retry_ready: bool) -> Option<Event<'id>> {
        if !retry_ready {
            return None;
        }
        match self.publish() {
            Ok(event) => event,
            Err(Failure::Transport(HostError::Core(
                Fault::Capacity | Fault::WouldBlock | Fault::NotReady,
            ))) => self.defer_retry(),
            Err(e) => {
                self.begin_close();
                self.port = None;
                self.state.rows.clear();
                self.state.aborted = true;
                Some(Event::Failed(e))
            }
        }
    }
    fn scan_event(&mut self) -> Option<Event<'id>> {
        if self.state.closing
            || self.state.bindings.is_empty()
            || Instant::now() < self.state.next_scan
        {
            return None;
        }
        Some(match self.refresh() {
            Ok(candidates) => Event::Scanned { candidates },
            Err(e @ (Failure::Clock(_) | Failure::Protocol(Fault::Deadline | Fault::Overflow))) => {
                self.state.interface_valid = false;
                self.begin_close();
                Event::Failed(e)
            }
            Err(e) => {
                self.state.interface_valid = false;
                Event::ScanFailed(e)
            }
        })
    }
    /// Poll a bounded turn. The caller also drives the one original Pool and its
    /// Resolver. Held callbacks and unsent address intents survive future drops.
    /// No new clock is needed for retiring already admitted address declarations.
    #[expect(
        clippy::too_many_lines,
        reason = "One synchronous bounded turn preserves original callback, publication and clock-free retirement ordering without another task or queue"
    )]
    pub fn poll(&mut self, cx: &mut Context<'_>, changes: &mut NetworkChanges) -> Poll<Event<'id>> {
        if let Some(pool) = &self.port
            && pool.transport_epoch() != self.state.transport_epoch
        {
            let generation = self.state.transport_epoch;
            self.state.transport_epoch = pool.transport_epoch();
            let admitted = self.state.rows.iter().filter(|row| row.published).count();
            for row in &mut self.state.rows {
                row.published = false;
            }
            // Only an old TRANSPORT FIFO-capacity retry is retired. This does
            // not renew a listener/interface claim, NAT request, scan or clock.
            self.state.retry = None;
            cx.waker().wake_by_ref();
            return Poll::Ready(Event::TransportRetired {
                generation,
                next_generation: self.state.transport_epoch,
                admitted,
            });
        }
        if let Some(write) = self.state.pending_expired.take() {
            return Poll::Ready(Event::Nat(nat::Progress::WriteExpired(write)));
        }
        if let Some(end) = self.state.pending_end.take() {
            return Poll::Ready(Event::Nat(nat::Progress::Ended(end)));
        }
        if let Some(error) = self.state.close_error.take() {
            return Poll::Ready(Event::Failed(error));
        }
        if self.state.aborted {
            return Poll::Ready(Event::Aborted);
        }
        if self.state.terminal {
            return Poll::Ready(Event::Closed);
        }
        if !self.state.closing
            && let Some(registration) = self.registration_mut()
        {
            match registration.poll_native_guard(cx, None) {
                Poll::Ready(Ok(progress)) => {
                    if let Some(event) = self.nat_progress(progress, false) {
                        cx.waker().wake_by_ref();
                        return Poll::Ready(event);
                    }
                }
                Poll::Ready(Err(e)) => {
                    self.begin_close();
                    return Poll::Ready(Event::Failed(Failure::Nat(e)));
                }
                Poll::Pending => {}
            }
        }
        if !self.state.closing {
            if self.state.hard.is_some_and(|bound| Instant::now() >= bound) {
                self.begin_close();
            } else {
                let sampled = (|| {
                    let subscription = self
                        .state
                        .subscription
                        .as_mut()
                        .ok_or(Failure::Protocol(Fault::Closed))?;
                    match subscription.poll_changed(cx, self.state.revision) {
                        Poll::Ready(Err(e)) => return Err(Failure::Clock(e)),
                        Poll::Ready(Ok(s)) => self.state.revision = s.revision,
                        Poll::Pending => {}
                    }
                    let sample = self.state.clock.sample().map_err(Failure::Clock)?;
                    self.state.revision = sample.revision;
                    match subscription.poll_changed(cx, sample.revision) {
                        Poll::Ready(Err(e)) => return Err(Failure::Clock(e)),
                        Poll::Ready(Ok(_)) => cx.waker().wake_by_ref(),
                        Poll::Pending => {}
                    }
                    Ok(sample.now.as_micros())
                })();
                match sampled {
                    Err(e) => {
                        self.begin_close();
                        return Poll::Ready(Event::Failed(e));
                    }
                    Ok(now)
                        if self.state.options.until != u64::MAX
                            && now >= self.state.options.until
                            || self.state.hard.is_some_and(|bound| Instant::now() >= bound) =>
                    {
                        self.begin_close()
                    }
                    Ok(_) => {}
                }
            }
        }
        if let Some(end) = self.state.pending_end.take() {
            return Poll::Ready(Event::Nat(nat::Progress::Ended(end)));
        }
        if self.state.closing && self.state.close_hard.is_some_and(|at| Instant::now() >= at) {
            self.abort();
            return Poll::Ready(Event::Aborted);
        }
        let now = Instant::now();
        self.state
            .claims
            .retain(|claim| claim.hard.is_none_or(|bound| now < bound));
        let retry_ready = self.state.retry.is_none_or(|at| now >= at);
        if retry_ready {
            self.state.retry = None;
        }
        if let Some(Port::Retained(original)) = &mut self.port {
            let now = match self.state.clock.sample() {
                Ok(sample) => sample.now.as_micros(),
                Err(error) => return Poll::Ready(Event::Failed(Failure::Clock(error))),
            };
            match original.poll(cx, now) {
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Event::Failed(Failure::Transport(error.cause)));
                }
                Poll::Ready(Ok(_)) => cx.waker().wake_by_ref(),
                Poll::Pending => {}
            }
        }
        // Each ready class receives its turn, even for a legitimately tiny
        // scan interval or continuous NAT traffic. Native deadlines were already
        // checked above and cannot be hidden by a ready scan/publication event.
        for offset in 0..3 {
            let part = (self.state.cursor + offset) % 3;
            let event = match part {
                0 => self.poll_nat(cx, retry_ready),
                1 => {
                    if !self.state.closing
                        && !self.state.bindings.is_empty()
                        && changes.poll_changed(cx).is_ready()
                    {
                        self.state.next_scan = Instant::now();
                    }
                    self.scan_event()
                }
                _ => self.poll_publication(retry_ready),
            };
            if let Some(event) = event {
                self.state.cursor = (part + 1) % 3;
                cx.waker().wake_by_ref();
                return Poll::Ready(event);
            }
        }
        self.state.cursor = (self.state.cursor + 1) % 3;
        if self.state.closing && self.state.rows.is_empty() {
            self.state.terminal = true;
            return Poll::Ready(Event::Closed);
        }
        self.alarm(cx);
        Poll::Pending
    }
}
impl Drop for State<'_, '_> {
    fn drop(&mut self) {
        if let Some(registration) = self.nat.as_mut().and_then(|nat| nat.registration.as_mut()) {
            let _end = registration.close();
        }
    }
}
