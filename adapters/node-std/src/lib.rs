//! Caller-driven composition of an in-process GNUnet peer.
#![forbid(unsafe_code)]
#![cfg(any(unix, windows))]

mod lifecycle;
mod network;
mod quic;
mod runtime;
mod settings;
#[cfg(unix)]
mod unix;

pub use gnunet_nat_host::startup::HelperPrograms as NatHelperPrograms;
pub use gnunet_resolver_host::MachineInputs;
pub use gnunet_resolver_host::SystemDns;
pub use gnunet_resolver_host::startup::Upstreams;
#[cfg(any(
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd"
))]
pub use gnunet_resolver_host::{SYSTEM_DNS_WORKER_ARGUMENT, serve_system_dns_worker};
pub use gnunet_service_runtime::network::SocketPolicy;
pub use gnunet_vpn_host::coordinator::provider::Provider as VpnProvider;
pub use lifecycle::{Failure, FailureCause, Service, ServiceFailure};
pub use network::{NetworkChangeNotifier, NetworkChanges, network_changes};
pub use settings::{
    Node, Paths, PeerTransport, ResolverInputs, Settings, TcpBind, Timing, UdpBind,
};

/// Verified local readiness from the original service owners.
#[derive(Debug)]
pub struct Ready {
    /// The peer identity agreed by PILS, TRANSPORT, CORE and the communicators.
    pub peer: [u8; 32],
    /// The TCP communicator's actual endpoints after binding.
    pub tcp_addresses: Vec<std::net::SocketAddr>,
    /// The UDP communicator's actual endpoints after local registration.
    pub udp_addresses: Vec<std::net::SocketAddr>,
    /// The raw QUIC communicator's bound address when configured.
    pub quic_address: Option<std::net::SocketAddr>,
    /// The HTTP/3 communicator's bound address when configured.
    pub http3_address: Option<std::net::SocketAddr>,
    /// The UNIX testing communicator's payload MTU when configured.
    pub unix_mtu: Option<std::num::NonZeroU16>,
    /// The configured application VPN accepted its original route plan and CADET is live.
    pub vpn_ready: bool,
}

/// Clean retirement of the node and its original service owners.
#[derive(Debug)]
pub enum Exit {
    /// The host stopped before node readiness.
    BeforeReady,
    /// The node completed readiness and later retired.
    AfterReady(Ready),
}
