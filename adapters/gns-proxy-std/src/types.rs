//! Explicit process ports, source authority and bounded proxy policy.
use crate::{budget::Stop, tls};
use gnunet_client_host::EndpointSource;
use gnunet_config::Configuration;
use gnunet_service_runtime::clock::RuntimeClock;
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
/// Original native service selectors; all must share the one process clock.
pub struct Sources {
    /// Actual GNS service source; no private resolver is created.
    pub gns: EndpointSource,
    /// Actual IDENTITY suffix-lookup source.
    pub identity: EndpointSource,
    /// Actual VPN source, used only for a selected raw VPN consumer intent.
    pub vpn: EndpointSource,
}
/// Real caller-owned process capabilities. The original broker Driver remains
/// in the foreground and must still retire after this Runtime is Closed.
pub struct Ports {
    /// Coherent ordinary configuration used by full-name GNS routing.
    pub configuration: Configuration,
    /// Same actual process broker as every endpoint source.
    pub context: gnunet_resolver_broker::Context<128, 256>,
    /// Same original source clock Arc, without another time domain.
    pub clock: Arc<dyn RuntimeClock>,
    /// Explicit configured CA; no OS trust settings are changed.
    pub authority: Arc<tls::Authority>,
    /// Genuine Mozilla and optional configured public PKIX roots.
    pub roots: Arc<tls::TrustRoots>,
    /// Original startup Stop/Clock/hard guard, not renewed between bind attempts.
    pub startup_guard: tls::Guard,
}
/// Ordinary numeric SOCKS binding and outbound-family policy.
#[derive(Clone, Debug)]
pub struct Options {
    /// Numeric original bind addresses; each native failure stays observable.
    pub bind: Vec<SocketAddr>,
    /// Disable IPv6 destination selection, independently of explicit listeners.
    pub disable_ipv6: bool,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            bind: vec![
                SocketAddr::from((Ipv4Addr::LOCALHOST, 7777)),
                SocketAddr::from((Ipv6Addr::LOCALHOST, 7777)),
            ],
            disable_ipv6: false,
        }
    }
}
/// Bounded storage and native-operation policies. Body bytes stream directly
/// rather than reserving a whole response/body maximum for every session.
#[derive(Clone, Debug)]
pub struct Limits {
    /// Maximum simultaneously retained original SOCKS sessions.
    pub sessions: usize,
    /// Original whole-session native/logical lifetime, captured at admission.
    pub session_timeout: Duration,
    /// Independent once-captured cleanup span for existing resources only.
    pub cleanup_grace: Duration,
    /// Actual GNS/IDENTITY native-client resource policy.
    pub lookup: gnunet_gns_host::tld::Limits,
    /// Actual bounded result projection and VPN-intent policy.
    pub records: crate::records::Limits,
    /// Actual VPN-client resource policy; default is one original operation.
    pub vpn: gnunet_vpn_client_host::Limits,
    /// Explicit local VPN wire AF profile; native defaults target Linux/Darwin.
    pub vpn_profile: gnunet_vpn_client_host::AfProfile,
    /// Mature streaming HTTP resource policy.
    pub http: crate::http::Limits,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            sessions: 32,
            session_timeout: Duration::from_secs(300),
            cleanup_grace: Duration::from_secs(5),
            lookup: gnunet_gns_host::tld::Limits {
                name_bytes: 255,
                gns: gnunet_gns_client_host::Limits {
                    output: gnunet_service_runtime::framing::Budget {
                        frames: 1,
                        bytes: 309,
                    },
                    ..Default::default()
                },
                identity: gnunet_identity_client_host::Limits {
                    operations: 1,
                    egos: 0,
                    name_bytes: 255,
                    source_bytes: 512,
                    ..Default::default()
                },
            },
            records: Default::default(),
            vpn: gnunet_vpn_client_host::Limits {
                operations: 1,
                output: gnunet_service_runtime::framing::Budget {
                    frames: 1,
                    bytes: 128,
                },
                ..Default::default()
            },
            vpn_profile: gnunet_vpn_client_host::AfProfile::native(),
            http: Default::default(),
        }
    }
}
pub(crate) struct SessionInput {
    pub socket: Option<tokio::net::TcpStream>,
    pub sources: Sources,
    pub configuration: Arc<Configuration>,
    pub context: gnunet_resolver_broker::Context<128, 256>,
    pub authority: Arc<tls::Authority>,
    pub roots: Arc<tls::TrustRoots>,
    pub budget: crate::budget::Budget,
    pub stop: Stop,
    pub disable_ipv6: bool,
    pub limits: Limits,
    pub diagnostics: Option<gnunet_native::network::Diagnostics>,
}
