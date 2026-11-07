//! Explicit ports, finite policies and owned, payload-free terminal facts.
use crate::packet;
use gnunet_client_host::EndpointSource;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as Fault;
use std::{
    fmt, io,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
    time::Duration,
};

/// Both configured numeric listener addresses. Either actual bind may succeed.
#[derive(Clone, Copy, Debug)]
pub struct BindOptions {
    /// Original IPv4 bind request, including port zero when requested.
    pub ipv4: SocketAddrV4,
    /// Original IPv6 bind request.
    pub ipv6: SocketAddrV6,
}
/// Ordinary CLIENT ports supplied by the original PROGRAM/Broker owner.
pub struct Ports {
    /// Actual GNS service source.
    pub gns: EndpointSource,
    /// Actual IDENTITY suffix lookup source.
    pub identity: EndpointSource,
    /// Actual VPN allocation source.
    pub vpn: EndpointSource,
    /// Same selected configuration snapshot used for full-name routing.
    pub configuration: Arc<gnunet_config::Configuration>,
    /// Exact clock Arc shared by all three sources.
    pub clock: Arc<dyn RuntimeClock>,
    /// Numeric ordinary DNS upstream; no implicit Resolver is constructed.
    pub upstream: SocketAddr,
}
/// Per-request bounds and fixed maximum simultaneously retained work.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Active requests, including replies waiting for UDP writability.
    pub requests: usize,
    /// One original overall query budget; shared by every routing phase.
    pub request_lifetime: Duration,
    /// Actual requested VPN lease length, independent of query lifetime.
    pub vpn_lease: Duration,
    /// Explicit native VPN IPC address-family profile.
    pub vpn_profile: gnunet_vpn_client_host::AfProfile,
    /// Packet/parser/converted record ceilings.
    pub packet: packet::Limits,
    /// Native full-name lookup ceilings.
    pub lookup: gnunet_gns_host::tld::Limits,
    /// Native VPN allocation ceilings.
    pub vpn: gnunet_vpn_client_host::Limits,
    /// Synchronous temporary IDNA profile; no borrowed backend escapes parse.
    pub idna_profile: gnunet_idna::NativeProfile,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            requests: 64,
            request_lifetime: Duration::from_secs(60),
            vpn_lease: Duration::from_secs(30 * 60),
            vpn_profile: gnunet_vpn_client_host::AfProfile::native(),
            packet: packet::Limits::default(),
            lookup: gnunet_gns_host::tld::Limits::default(),
            vpn: gnunet_vpn_client_host::Limits::default(),
            idna_profile: gnunet_idna::NativeProfile::Libunistring1_5Unicode18_0,
        }
    }
}
/// An actual bind attempt; a healthy other family does not erase this errno.
#[derive(Debug)]
pub struct Binding {
    /// Original requested address.
    pub requested: SocketAddr,
    /// Actual local socket address after bind, including an assigned port.
    pub local: Option<SocketAddr>,
    /// Original bind/nonblocking/registration/address-query failure.
    pub error: Option<io::Error>,
}
/// Original request stage, without query bytes or user names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    /// Actual GNS answer, including empty answers.
    Gns,
    /// Only an actual full-name NotGns outcome selects ordinary DNS.
    Dns,
}
/// Why original interest ended; cancellation never revokes an existing VPN lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopReason {
    /// Original native hard elapsed.
    NativeDeadline,
    /// Permanent caller shutdown.
    Shutdown,
}
/// Explicit request failure; none of these authorizes a DNS fallback.
#[derive(Debug)]
pub enum RequestError {
    /// Original local/native deadline or caller shutdown.
    Stopped(StopReason),
    /// Original canonical query deadline elapsed.
    LogicalDeadline,
    /// Same-source clock/subscription or local bounded resource failure.
    Protocol(Fault),
    /// Actual public packet/record conversion failure, without input bytes.
    Packet(packet::Failure),
    /// Actual full-name routing/source failure.
    Lookup(gnunet_gns_host::tld::Cause),
    /// Actual ordinary DNS native owner failure.
    Dns(gnunet_dnsstub_host::HostError),
    /// Original ordinary DNS request cancellation failed independently.
    DnsCancel(gnunet_types::Error),
    /// Actual VPN CLIENT/source failure.
    Vpn(gnunet_vpn_client_host::Error),
    /// Actual original VPN MQ source loss.
    VpnLoss(gnunet_vpn_client_host::LossCause),
    /// Matching allocation returned no address or a local uncertain terminal.
    VpnOutcome(gnunet_vpn_client_host::Outcome),
    /// Unsupported original VPN protocol.
    VpnProtocol(u16),
    /// Original dedicated owner terminated without its matching result.
    Closed,
    /// Actual UDP reply syscall failure or short datagram write.
    Send(io::Error),
}
impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DNS2GNS request: {self:?}")
    }
}
impl std::error::Error for RequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(e) | Self::DnsCancel(e) => Some(e),
            Self::Packet(e) => Some(e),
            Self::Lookup(e) => Some(e),
            Self::Dns(e) => Some(e),
            Self::Vpn(e) => Some(e),
            Self::Send(e) => Some(e),
            _ => None,
        }
    }
}
/// Static original VPN operation facts after its opaque tokens are released.
#[derive(Debug, Default)]
pub struct VpnReport {
    /// Original operation diagnostic serial; never reusable authority.
    pub operation: Option<u64>,
    /// Last actual attached epoch diagnostic serial.
    pub epoch: Option<u64>,
    /// Whole original allocation request actually written locally.
    pub written: bool,
    /// Actual matching terminal callback, if received.
    pub outcome: Option<gnunet_vpn_client_host::Outcome>,
    /// Actual original loss, even if a separate failure also occurs.
    pub loss: Option<gnunet_vpn_client_host::LossCause>,
    /// First actual failed connection attempt; later success does not erase it.
    pub connect_error: Option<io::Error>,
    /// Independent original local callback cancellation result.
    pub cancel: Option<Result<gnunet_vpn_client_host::Cancel, gnunet_vpn_client_host::Error>>,
    /// Physical close was invoked on the same original client.
    pub close_invoked: bool,
    /// Independent close failure; not treated as a lease-revocation result.
    pub close_error: Option<gnunet_vpn_client_host::Error>,
    /// Actual final close observation if one was returned.
    pub close_loss: Option<gnunet_vpn_client_host::LossCause>,
}
/// Payload-free original request outcome and independent cleanup observations.
#[derive(Debug)]
pub struct RequestReport {
    /// Gateway-local serial for diagnostics only.
    pub serial: u64,
    /// Original listener index; not a reconstructed socket identity.
    pub listener: usize,
    /// Original sender address.
    pub peer: SocketAddr,
    /// Original DNS transaction bytes, if a complete header was received.
    pub id: Option<[u8; 2]>,
    /// Actual route selected; failure alone cannot select ordinary DNS.
    pub route: Option<Route>,
    /// Actual GNS source record count, including unsupported records.
    pub gns_records: Option<usize>,
    /// Actual unsupported GNS records skipped by normal DNS conversion.
    pub skipped_records: usize,
    /// Actual DNS pack counts/truncation, distinct from GNS source emptiness.
    pub packed: Option<gnunet_dns::PackReport>,
    /// Actual full-name source/cancellation/physical-close facts.
    pub lookup: Option<gnunet_gns_host::tld::Diagnostics>,
    /// First original pre-attachment GNS connection error, even after success.
    pub gns_connect_error: Option<io::Error>,
    /// Actual observed GNS connection retry failures, saturating at u64::MAX.
    pub gns_connect_failures: u64,
    /// First original pre-attachment IDENTITY connection error.
    pub identity_connect_error: Option<io::Error>,
    /// Actual observed IDENTITY connection retry failures, saturating at u64::MAX.
    pub identity_connect_failures: u64,
    /// Original DNS stub request admitted.
    pub dns_admitted: bool,
    /// Original request canceled on the same stub after completion/retirement.
    pub dns_cancelled: bool,
    /// Original stub sockets physically released by stop.
    pub dns_stopped: bool,
    /// Actual original logical stop facts, after the host released its sockets.
    pub dns_stop: Option<gnunet_dnsstub_host::Stopped>,
    /// Invalid/unrelated upstream datagrams observed, never treated as answers.
    pub dns_rejected: u64,
    /// First transient DNS syscall failure, even if a later reply succeeds.
    pub dns_io: Option<io::Error>,
    /// Independent original stub cancellation failure.
    pub dns_cancel_error: Option<Fault>,
    /// Each original allocation callback/close observation, at most record limit.
    pub vpn: Vec<VpnReport>,
    /// Reply packed/validated bytes, not a send receipt.
    pub reply_bytes: usize,
    /// Actual complete UDP datagram send result.
    pub sent_bytes: Option<usize>,
    /// Original failure, independently retained from cleanup outcomes.
    pub error: Option<RequestError>,
}
/// Bounded cumulative runtime observations. No report authorizes old tokens.
#[derive(Debug)]
pub struct Report {
    /// The two original bind attempts, in IPv4/IPv6 order.
    pub bindings: [Binding; 2],
    /// Actual received datagrams admitted into bounded request slots.
    pub received: u64,
    /// Actual complete UDP replies sent.
    pub sent: u64,
    /// Original requests ending without a complete reply send.
    pub failed: u64,
    /// Actual original tasks still retained at snapshot.
    pub active: usize,
    /// First request with a failure/independent diagnostic; later reports emit events.
    pub first_failure: Option<Arc<RequestReport>>,
    /// Independent listener receive/address errors, at most one per family.
    pub listener_errors: [Option<io::Error>; 2],
    /// Original futures/replies force-dropped without observed completion.
    pub unresolved: usize,
    /// All original request futures and replies actually consumed locally.
    pub quiescent: bool,
    /// Original listener socket owners were physically released.
    pub listeners_released: bool,
}
/// One observable progress point; callers may permanently gate after logging it.
#[derive(Debug)]
pub enum Event {
    /// Original request completed/failed, with no packet payload.
    Request(Arc<RequestReport>),
    /// One listener source failed and was closed.
    ListenerLost(usize),
    /// All original local owners retired.
    Closed,
}
/// One caller-driven step, not remote service readiness or an ACK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// One bounded original step was made.
    Activity,
    /// All original runtime owners retired locally.
    Closed,
}
/// Construction/runtime failure; both bind errors remain owned on construction failure.
#[derive(Debug)]
pub struct Failure {
    /// Original local cause.
    pub cause: RequestError,
    /// Actual attempted bindings and terminal metadata when construction failed.
    pub report: Option<Box<Report>>,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DNS2GNS runtime: {}", self.cause)
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
