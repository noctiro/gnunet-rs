# Embedded GNUnet peer

`gnunet-node-host` runs RESOLVER, PILS, TRANSPORT, PEERSTORE, NAT, CORE, NSE,
DHT, CADET and the TCP and UDP communicators in one host. Optional
communicators include raw QUIC, HTTP/3 and UNIX datagrams. The services use
GNUnet IPC and peer wire formats.

## Configuration and lifecycle

Call `Node::new` with a configuration, private state and IPC directories,
a peer transport profile, resolver inputs and timing budgets.
The state directory contains `peer.key`, the NSE proof file and the TRANSPORT,
TCP, UDP and CADET journals. The IPC directory must fit the target's Unix socket
address. The host keeps both namespaces stable while the node runs.

An application can provide bootstrap HELLO files in its data directory's
`hellos` child through `Settings::bootstrap_data_dir`. The configuration file
can also select this source through `[paths] GNUNET_DATADIR` and
`[peerstore] USE_INCLUDED_HELLOS`. Keep the asset directory stable
through startup. PEERSTORE verifies each HELLO under the configured discovery
profile and stores accepted records before serving clients. Restarting with
the same files reuses the existing public records.

Run `Node::run` with a clock, network-change receiver and stop future on a Tokio reactor with I/O and
timers enabled. Local clients use `Node::configuration()` to obtain the
configured IPC endpoints. Readiness reports the identity observed by the
original services and the bound endpoints of every enabled communicator. It precedes remote connection
establishment. TRANSPORT starts aggregate PILS address publication after the
host accepts readiness. The communicators continue to submit address changes
to TRANSPORT during startup.

Each QUIC-family communicator is enabled by supplying its own `BINDTO` under
`[communicator-quic]` or `[communicator-http3]`. The startup path shares the
standalone communicator's configuration parser, TLS setup and resource limits.
The two profiles bind separate UDP sockets. Both register their addresses
through NAT and TRANSPORT. An absent `BINDTO` leaves that profile disabled.

`PeerTransport::OutboundTcp` retains original TCP peer dialing and multiplexed
sessions without an Internet-facing listener. It requires UDP, QUIC, HTTP/3,
UNIX datagrams and direct-IP DHTU to be disabled. Local protocol IPC and
CORE-backed DHT remain available.

On a host with AF_UNIX datagrams, set `UNIXPATH` under `[communicator-unix]`
to a separate socket directly inside the private IPC directory. Readiness
reports its payload MTU. The [UNIX testing communicator](../unix-communicator-std/README.md)
trusts sender claims in local datagrams, so use it among processes sharing
that trusted namespace.

CADET uses CORE neighbors, TRANSPORT address hints and the node's DHT for
path discovery. DHT subscribes to the node's NSE over the original local
service interface.

Hosts can create a notifier and receiver with `network_changes()` and pass the
receiver to `Node::run`. Forward native path changes to the notifier. The
communicators and NAT use the hint to advance their interface scans. When the host has a DNS snapshot
for the current network, `set_dns_upstreams` replaces the upstream list and
signals the same scan owners. An empty list removes all upstreams. Socket
binds, static hosts and local Resolver connections retain their owners.
`ResolverInputs::System` selects native system policy where supported. The
datagram snapshot channel is used only with `ResolverInputs::Datagram`.
[Resolver backends](../resolver-std/README.md#platforms-and-entry-points)

```rust,ignore
let node = Node::new(Settings {
    config,
    bootstrap_data_dir: None,
    paths: Paths { state, ipc },
    peers: PeerTransport::Listening {
        tcp: TcpBind::Address("127.0.0.1:0".parse()?),
        udp: UdpBind { ipv4: "127.0.0.1:0".parse()?, ipv6: None },
    },
    socket_policy: SocketPolicy::default(),
    vpn: None,
    resolver,
    nat_helpers: None,
    timing: Timing::new(Duration::from_secs(20), Duration::from_secs(5))?,
})?;
let exit = node.run(clock, Default::default(), stop, publish_ready).await?;
```

Stop the node by completing its stop future and awaiting the same `run`.
The application VPN retires before CADET, REGEX, DHT, NSE, CORE and the enabled
communicators.
NAT, TRANSPORT and PEERSTORE follow, then PILS and RESOLVER. A failed child
triggers the same retirement. The initiating error and independent service
failures are returned together.

Set `Settings::nat_helpers` to a deployment-owned `NatHelperPrograms` pair
to add native reversal to the embedded NAT service. The service handles
requests over private NAT IPC and supervises its own helpers.
[NAT helper contract](../nat-std/README.md#embedded-service)

## Application VPN

Supply the original `VpnProvider` in `Settings::vpn` to start a private VPN
service after its CADET and REGEX dependencies are ready. Internet redirects
use official REGEX exit discovery by default. The private REGEX service uses
the node's DHT and PILS. Set `[vpn-rust] EXIT_DISCOVERY=configured` to select
only the configured fixed gateways and omit REGEX.
Node readiness includes actual route installation. Drive the platform packet
and settings provider while the node starts and drains. On Unix,
`SocketPolicy::protected` applies the deployment's protection to each original
Internet socket before use.
Use the default policy where the deployment already enforces upstream detours.
[Provider contract](../vpn-std/COORDINATOR.md#application-providers)

The embedded [NAT service](../nat-std/README.md#embedded-service) uses the configured
interface scan, STUN and UPnP policies. Privileged reversal requires helper authority
from the deployment.
