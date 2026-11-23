use gnunet_resolver_host::startup::{
    UpstreamChanges, UpstreamUpdates, Upstreams, upstream_updates,
};
use gnunet_service_runtime::network_change::{self, NetworkChange, NetworkChanges as ScanChanges};

/// A host's thread-safe network-change notifier for one original node.
#[derive(Clone)]
pub struct NetworkChangeNotifier {
    scans: [NetworkChange; 5],
    resolver: UpstreamUpdates,
}

impl NetworkChangeNotifier {
    /// Ask the running communicators and NAT to refresh their interface views.
    /// Hints can coalesce and do not carry network data or prove a refresh.
    pub fn notify(&self) {
        for target in &self.scans {
            target.notify();
        }
    }

    /// Publish the upstreams for the current network and request address scans.
    /// An empty list revokes upstreams. The receiving service may coalesce
    /// pending snapshots and applies the latest one before further DNS work.
    pub fn set_dns_upstreams(&self, upstreams: Upstreams) {
        self.resolver.replace(upstreams);
        self.notify();
    }
}

/// Inputs for interface scans and resolver updates. The default uses scan
/// timers and the Resolver's startup upstreams.
#[derive(Default)]
pub struct NetworkChanges {
    pub(crate) tcp: ScanChanges,
    pub(crate) udp: ScanChanges,
    pub(crate) nat: ScanChanges,
    pub(crate) quic: ScanChanges,
    pub(crate) http3: ScanChanges,
    pub(crate) resolver: UpstreamChanges,
}

/// Create a notifier and the receiving half for one node run.
pub fn network_changes() -> (NetworkChangeNotifier, NetworkChanges) {
    let (notify_tcp, tcp) = network_change::channel();
    let (notify_udp, udp) = network_change::channel();
    let (notify_nat, nat) = network_change::channel();
    let (notify_quic, quic) = network_change::channel();
    let (notify_http3, http3) = network_change::channel();
    let (upstreams, resolver) = upstream_updates();
    (
        NetworkChangeNotifier {
            scans: [
                notify_tcp,
                notify_udp,
                notify_nat,
                notify_quic,
                notify_http3,
            ],
            resolver: upstreams,
        },
        NetworkChanges {
            tcp,
            udp,
            nat,
            quic,
            http3,
            resolver,
        },
    )
}
