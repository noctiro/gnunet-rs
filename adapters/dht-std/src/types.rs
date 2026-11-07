//! Explicit ordinary service ports, finite IO limits and payload-free reports.
use gnunet_block::{bloom::NativeEndian, plugins::Plugin};
use gnunet_client_host::EndpointSource;
use gnunet_service_runtime::{
    accepted::SocketEvent,
    clock::RuntimeClock,
    credentials::UnixAccess,
    service::{PeerAddress, ServiceOptions},
};
use gnunet_types::Error as Fault;
use std::{fmt, io, sync::Arc, time::Duration};

/// Original instance storage. No constructor reads/creates a key or starts IO.
pub struct Instances {
    /// Same volatile DHT business/cache allocation brand.
    pub dht: gnunet_dht::service::Instance,
    /// Original CORE application brand.
    pub core: gnunet_core_client_host::Instance,
    /// Original direct-IP endpoint capability brand.
    pub ip: crate::ip::Instance,
    /// Original public PILS/signing brand.
    pub pils: gnunet_pils::client::Instance,
    /// Original continuous NSE source brand.
    pub nse: gnunet_nse_client_host::Instance,
    /// Original dedicated PEERSTORE HELLO monitor brand.
    pub peerstore: gnunet_peerstore_client_host::Instance,
    /// Independent original general-MQ HELLO STORE source.
    pub peerstore_writer: gnunet_peerstore_client_host::Instance,
}
impl Default for Instances {
    fn default() -> Self {
        Self {
            dht: gnunet_dht::service::Instance::new(),
            core: gnunet_core_client_host::Instance::new(),
            ip: crate::ip::Instance::new(),
            pils: gnunet_pils::client::Instance::new(),
            nse: gnunet_nse_client_host::Instance::new(),
            peerstore: gnunet_peerstore_client_host::Instance::new(),
            peerstore_writer: gnunet_peerstore_client_host::Instance::new(),
        }
    }
}
/// Original PROGRAM/SERVICE-owned CLIENT selectors. They all use this exact
/// clock Arc and the caller's actual Resolver context; none creates a Resolver.
pub struct Ports {
    /// Actual CORE application selector.
    pub core: EndpointSource,
    /// Actual PILS selector; only public announcement/sign operations are used.
    pub pils: EndpointSource,
    /// Actual NSE statistical subscription selector.
    pub nse: EndpointSource,
    /// Actual PEERSTORE HELLO monitor selector.
    pub peerstore: EndpointSource,
    /// Actual TRANSPORT application hint/suggestion selector.
    pub transport: EndpointSource,
    /// Canonical shared source time.
    pub clock: Arc<dyn RuntimeClock>,
    /// Original canonical listener/admission/shutdown policy.
    pub options: ServiceOptions,
    /// Actual kernel Unix credential policy.
    pub unix: UnixAccess,
}
/// Real installed BLOCK registry and exact explicit HELLO/native group profile.
pub struct Blocks {
    /// Caller-selected default plugins, including actual revocation settings
    /// when that plugin is installed. No plugin is an accept-all fallback.
    pub plugins: Vec<Plugin>,
    /// Original native BLOCK nonce/serialization profile.
    pub group_profile: NativeEndian,
    /// Original HELLO compilation profile, matching PILS/other public producers.
    pub hello_profile: gnunet_hello::SignatureProfile,
}
/// Explicit official underlay selection; the algorithm and local cache stay shared.
#[derive(Clone, Copy, Debug)]
pub struct Underlays {
    /// Enable the ordinary GNUnet CORE/NSE/TRANSPORT/PEERSTORE integration.
    pub gnunet: bool,
    /// Enable the official direct IP/UDP envelope with these native bounds.
    pub ip: Option<crate::ip::Config>,
}
impl Default for Underlays {
    fn default() -> Self {
        Self {
            gnunet: true,
            ip: None,
        }
    }
}
/// Bounded native and business resources. None limits the healthy daemon's
/// total lifetime; finite source renewals are actual newly admitted sources.
#[derive(Clone, Copy)]
pub struct Limits {
    /// Actual enabled native underlays.
    pub underlays: Underlays,
    /// Existing bounded cache/local request policy.
    pub local: gnunet_dht::service::Limits,
    /// Original peer/reverse-route/output policy.
    pub network: gnunet_dht::network::Limits,
    /// Original native CORE capacity.
    pub core: gnunet_core_client_host::Limits,
    /// Original native PILS capacity; this host serializes one issued signature.
    pub pils: gnunet_pils_host::client::Limits,
    /// Original NSE source/partial-input guards.
    pub nse: gnunet_nse_client_host::Limits,
    /// Original PEERSTORE receive/operation policy.
    pub peerstore: gnunet_peerstore_client_host::Limits,
    /// Explicit HELLO parse/canonical scratch limits.
    pub hello: gnunet_hello::Limits,
    /// Selected actual PILS producer profile.
    pub pils_profile: gnunet_pils::Profile,
    /// Original native enum32 profile for CORE class fields.
    pub core_order: gnunet_core_client_host::ClassOrder,
    /// Per-local-MQ retained immutable output frame cap.
    pub client_frames: usize,
    /// Per-local-MQ retained immutable output bytes.
    pub client_bytes: usize,
    /// Aggregate original handoffs across all underlays, at most64.
    pub native_sends: usize,
    /// Actual syscall slice cap.
    pub io_slice_bytes: usize,
    /// One initial public PILS/CORE readiness bound.
    pub initial: Duration,
    /// Original finite CORE source lease before real retirement/reconnect.
    pub source_lifetime: Duration,
    /// First-byte through complete original input/credit wait.
    pub input_lifetime: Duration,
    /// Oldest original local output/underlay work bound.
    pub output_lifetime: Duration,
    /// Original cancellation suffix-drain observation budget.
    pub retirement: Duration,
    /// Whole dedicated read-only HELLO monitor lifetime before actual renewal.
    pub discovery_lifetime: Duration,
    /// Whether fresh HELLO address candidates request TRANSPORT validation.
    /// Existing connected-peer preferences still follow actual CORE events.
    pub try_connect: bool,
    /// Total candidate HELLO/address records retained for validation hints.
    pub addresses: usize,
    /// Total retained candidate/hint bytes.
    pub address_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            underlays: Underlays::default(),
            local: gnunet_dht::service::Limits::default(),
            network: gnunet_dht::network::Limits {
                put_frame_limit: gnunet_dht::network::PutFrameLimit::WIRE,
                ..gnunet_dht::network::Limits::default()
            },
            core: gnunet_core_client_host::Limits::default(),
            pils: gnunet_pils_host::client::Limits::default(),
            nse: gnunet_nse_client_host::Limits::default(),
            peerstore: gnunet_peerstore_client_host::Limits::default(),
            hello: gnunet_hello::Limits {
                maximum_input_bytes: 65535,
                maximum_address_bytes: 65535,
                maximum_addresses: 1024,
            },
            pils_profile: gnunet_pils::Profile::Reference029,
            core_order: if cfg!(target_endian = "little") {
                gnunet_core_client_host::ClassOrder::Little
            } else {
                gnunet_core_client_host::ClassOrder::Big
            },
            client_frames: 32,
            client_bytes: 1024 * 1024,
            native_sends: 64,
            io_slice_bytes: 65535,
            initial: Duration::from_secs(60),
            source_lifetime: Duration::from_secs(86400),
            input_lifetime: Duration::from_secs(30),
            output_lifetime: Duration::from_secs(30),
            retirement: Duration::from_secs(5),
            discovery_lifetime: Duration::from_secs(86400),
            try_connect: true,
            addresses: 1024,
            address_bytes: 4 * 1024 * 1024,
        }
    }
}
/// Which original independently owned native source produced an observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Provider {
    /// Original local service MQ.
    Local,
    /// Original CORE application.
    Core,
    /// Actual direct-IP datagram endpoint, without CORE authentication claims.
    Ip,
    /// Original PILS public/signing source.
    Pils,
    /// Original NSE subscription.
    Nse,
    /// Original PEERSTORE monitor.
    Peerstore,
    /// Original TRANSPORT hint/suggestion MQ.
    Transport,
}
/// Owned original cause. Reports/logging never include DHT packets or bodies.
#[derive(Debug)]
pub enum Cause {
    /// Actual bounded/protocol/clock failure.
    Protocol(Fault),
    /// Actual original native IO failure.
    Io(io::Error),
    /// Actual CLIENT/Resolver/configuration source refusal.
    Port(gnunet_client_host::ConnectError),
    /// Actual CORE physical retirement cause.
    Core(gnunet_core_client_host::LossCause),
    /// Original direct-IP protocol, socket or bounded-owner failure.
    Ip(crate::ip::Error),
    /// Same original datagram syscall error shared by its event and final report.
    IpIo(Arc<io::Error>),
    /// Recoverable receive error on this actual local socket. It identifies no
    /// remote peer or original send and does not retire the shared UDP owner.
    IpReceive {
        /// Actual receiving socket address, including its bound port.
        local: std::net::SocketAddr,
        /// Original native receive error, without guessed remote attribution.
        error: io::Error,
    },
    /// Actual PILS physical retirement cause.
    Pils(gnunet_pils_host::client::LossCause),
    /// Actual NSE physical retirement cause.
    Nse(gnunet_nse_client_host::Cause),
    /// Actual PEERSTORE physical retirement cause.
    Peerstore(gnunet_peerstore_client_host::LossCause),
    /// Original verified PILS signing refusal.
    Signature(gnunet_pils::client::Failure),
    /// All enabled underlays failed their actual construction; keep each cause.
    UnderlayInitialization {
        /// Actual original CORE constructor refusal, when enabled.
        core: Option<Box<gnunet_client_host::ConnectError>>,
        /// Actual original direct-IP constructor refusal, when enabled.
        ip: Option<Box<crate::ip::Error>>,
    },
    /// Actual configured/announced sources disagreed about the local identity.
    Identity,
}
impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DHT native source: {self:?}")
    }
}
impl std::error::Error for Cause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(e) => Some(e),
            Self::Ip(e) => Some(e),
            Self::IpIo(e) => Some(e.as_ref()),
            Self::IpReceive { error, .. } => Some(error),
            Self::UnderlayInitialization { core, ip } => core
                .as_ref()
                .map(|error| error.as_ref() as &(dyn std::error::Error + 'static))
                .or_else(|| {
                    ip.as_ref()
                        .map(|error| error.as_ref() as &(dyn std::error::Error + 'static))
                }),
            Self::Io(e) => Some(e),
            Self::Port(e) => Some(e),
            Self::Core(gnunet_core_client_host::LossCause::Io(e)) => Some(e),
            Self::Pils(gnunet_pils_host::client::LossCause::Io(e)) => Some(e),
            Self::Nse(gnunet_nse_client_host::Cause::Io(e)) => Some(e),
            Self::Peerstore(gnunet_peerstore_client_host::LossCause::Io(e)) => Some(e),
            _ => None,
        }
    }
}
/// Clone shares only the same original owned cause, not a native source/receipt.
#[derive(Clone, Debug)]
pub struct Error(pub Arc<Cause>);
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self(Arc::new(Cause::Protocol(e)))
    }
}
impl From<gnunet_client_host::ConnectError> for Error {
    fn from(e: gnunet_client_host::ConnectError) -> Self {
        Self(Arc::new(Cause::Port(e)))
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
/// Original native send completion after its carrier reports a terminal result.
#[derive(Clone, Debug)]
pub struct SendFact {
    /// Actual carrying source, independently of the logical routing peer.
    pub provider: Provider,
    /// Original business job diagnostic, not reusable authority.
    pub job: u64,
    /// Actual original destination identity.
    pub peer: [u8; 32],
    /// Actual native client's terminal outcome.
    pub outcome: SendOutcome,
    /// Actual written CORE_SEND prefix or atomic IP datagram, with its envelope.
    pub written: usize,
    /// Original whole native frame/datagram size, including the carrier envelope.
    pub frame_bytes: usize,
}
/// Native send disposition retaining the actual carrier's semantics.
#[derive(Clone, Debug)]
pub enum SendOutcome {
    /// Original CORE client completion, including any original IPC uncertainty.
    Core(gnunet_core_client_host::SendOutcome),
    /// Original datagram syscall/cancellation/endpoint-generation result.
    Ip(crate::ip::Outcome),
}
/// Last observed original payload prefix whose terminal callback was not consumed.
/// This is not a send result, replay permission or a remote acknowledgement.
#[derive(Clone, Copy, Debug)]
pub struct PendingSendFact {
    /// Original carrying source, not inferred from the peer identity.
    pub provider: Provider,
    /// Original business job diagnostic (zero for the public HELLO handoff).
    pub job: u64,
    /// Actual original peer identity, without generation authority.
    pub peer: [u8; 32],
    /// Actual observed native prefix bytes, including its carrying envelope.
    pub written: usize,
    /// Original whole native frame/datagram length.
    pub frame_bytes: usize,
}
/// One observable step; the caller may permanently gate after its Logger runs.
#[derive(Debug)]
pub enum Event {
    /// Real PILS identity, an available underlay and the volatile business owner ready.
    Ready {
        /// Actual public local identity.
        peer: [u8; 32],
    },
    /// Native initialization/accept diagnostic on its original socket.
    Socket(SocketEvent),
    /// Original typed failure, shared with the bounded final report.
    Error {
        /// Original source family.
        provider: Provider,
        /// Original owned cause.
        cause: Arc<Cause>,
    },
    /// Actual public source progress, without a wire/storage ACK.
    Activity(Provider),
    /// One real local client source admitted after access/framing setup.
    Client {
        /// Original diagnostic, not a reconstructible ClientId.
        client: u64,
        /// Original accepted address family.
        address: PeerAddress,
    },
    /// Actual original native send terminal outcome.
    Send(SendFact),
    /// Same original local owners reached their observed terminal state.
    Closed,
}
/// Original unsubmitted PUT rejected by installed BLOCK validation on retry.
/// Numeric source labels are diagnostics, never reconstructible authority.
#[derive(Clone, Copy, Debug)]
pub struct UnroutedPutFailure {
    /// Original accepted intent diagnostic.
    pub put: u64,
    /// Original submitting MQ diagnostic, even if it already disconnected.
    pub client: u64,
    /// Original canonical acceptance time.
    pub accepted: u64,
    /// Original block expiration.
    pub expiration: u64,
    /// Original bounded intent target, never a retry start time.
    pub until: u64,
    /// Actual semantic BLOCK refusal.
    pub reason: Fault,
}
/// Actual bounded final facts; a timeout/Drop cannot grant physical quiescence.
#[derive(Debug)]
pub struct Report {
    /// Actual readiness was observed at least once.
    pub ready: bool,
    /// Original local stream admissions.
    pub clients: u64,
    /// Actual complete local input frames consumed once.
    pub requests: u64,
    /// Actual local reply bytes written.
    pub local_written: u64,
    /// Actual complete CORE FIFO admissions; not transmission acknowledgements.
    pub core_admitted: u64,
    /// Original datagrams actually admitted to the bounded IP queue.
    pub ip_admitted: u64,
    /// Complete original datagrams accepted by the local send syscall.
    pub ip_written: u64,
    /// Original IP packets accepted from actual socket input.
    pub ip_received: u64,
    /// Actual completed CORE_SEND frames.
    pub core_written: u64,
    /// Actual original CORE messages whose terminal disposition was uncertain.
    pub core_uncertain: u64,
    /// Actual public HELLO observations offered only as dial candidates.
    pub hello_observations: u64,
    /// Autonomous FIND PEER rounds actually prepared by the same bounded owner.
    pub find_peer_rounds: u64,
    /// Original GET frames prepared in those rounds, not native write/ACK facts.
    pub find_peer_prepared: u64,
    /// Original unadmitted local rounds dropped at their fixed budget.
    pub find_peer_expired: u64,
    /// Actual accepted-but-not-submitted PUT queue and cumulative dispositions.
    /// Submission is original CORE FIFO admission, not a remote storage ACK.
    pub unrouted_puts: gnunet_dht::network::PutStats,
    /// First original rejected PUT metadata; later count remains in PutStats.
    pub first_unrouted_put_failure: Option<UnroutedPutFailure>,
    /// Real original PEERSTORE STORE_RESULT observations, including negative codes.
    pub peerstore_results: u64,
    /// Last actual STORE_RESULT code, never inferred from local writing.
    pub peerstore_result: Option<i32>,
    /// Actual exposed STORE retirements without authoritative result.
    pub peerstore_unknown: u64,
    /// Whole original TRANSPORT application frames written, without an ACK.
    pub transport_written: u64,
    /// Original TRANSPORT application frames with a positive prefix at retirement.
    pub transport_unknown: u64,
    /// Last physically retired original NSE START prefix (zero through four).
    pub nse_start_bytes: usize,
    /// That original NSE START was wholly written; not an estimate ACK.
    pub nse_start_written: bool,
    /// Original typed independently failed sources, bounded to first16 causes.
    pub errors: [Option<Arc<Cause>>; 16],
    /// Further actual diagnostics omitted after the fixed retention fills.
    pub omitted_errors: u64,
    /// Native owners not observed terminal before forced consuming close.
    pub unresolved: usize,
    /// Bounded original source prefixes when the caller consumes before actual
    /// CORE terminal return. Empty slots supply no proof of remote processing.
    pub unsettled: [Option<PendingSendFact>; 64],
    /// All original native/provider/local owners observed terminal locally.
    pub quiescent: bool,
}
impl Default for Report {
    fn default() -> Self {
        Self {
            ready: false,
            clients: 0,
            requests: 0,
            local_written: 0,
            core_admitted: 0,
            ip_admitted: 0,
            ip_written: 0,
            ip_received: 0,
            core_written: 0,
            core_uncertain: 0,
            hello_observations: 0,
            find_peer_rounds: 0,
            find_peer_prepared: 0,
            find_peer_expired: 0,
            unrouted_puts: gnunet_dht::network::PutStats::default(),
            first_unrouted_put_failure: None,
            peerstore_results: 0,
            peerstore_result: None,
            peerstore_unknown: 0,
            transport_written: 0,
            transport_unknown: 0,
            nse_start_bytes: 0,
            nse_start_written: false,
            errors: std::array::from_fn(|_| None),
            omitted_errors: 0,
            unresolved: 0,
            unsettled: [None; 64],
            quiescent: false,
        }
    }
}
impl Report {
    pub(crate) fn record(&mut self, cause: Cause) -> Arc<Cause> {
        let cause = Arc::new(cause);
        if let Some(slot) = self.errors.iter_mut().find(|s| s.is_none()) {
            *slot = Some(cause.clone());
        } else {
            self.omitted_errors = self.omitted_errors.saturating_add(1);
        }
        cause
    }
}
/// One caller-driven step; Ready is not remote route convergence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// One original bounded step.
    Activity,
    /// Actual initial local readiness.
    Ready,
    /// Actual same-owner terminal observation.
    Closed,
}

impl From<crate::ip::Error> for Error {
    fn from(cause: crate::ip::Error) -> Self {
        Self(Arc::new(Cause::Ip(cause)))
    }
}
