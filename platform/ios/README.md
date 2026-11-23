# iOS GNUnet SDK

The Swift package owns one [embedded GNUnet peer](../../adapters/node-std/README.md)
in an iOS or iPadOS app. It exposes asynchronous startup, status and shutdown
over the shared [C ABI](../sdk/include/gnunet_node.h). It targets iOS 15 and later
and uses ordinary TCP and UDP sockets.

## Build and import

Use Xcode and the workspace Rust toolchain. Install both default Rust targets
and run the package builder from the repository root.

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
platform/ios/build-sdk.sh
```

The builder prints a local Swift package path under `target/ios/`. Add that
directory in Xcode with **Add Local** and link the `GNUnetNode` product. The
generated XCFramework carries separate device and simulator static libraries.
For Intel simulators, add `x86_64-apple-ios` and pass `--intel-simulator`. The
builder runs one Cargo job by default. Set `GNUNET_IOS_BUILD_JOBS` to override it.
[Apple XCFramework packaging](https://developer.apple.com/documentation/xcode/creating-a-multi-platform-binary-framework-bundle)

The [Xcode SDK consumer](../../tools/ci/ios-sdk-consumer/README.md) links the
generated package into an app, a Packet Tunnel extension and a DNS Proxy
extension. Its unsigned app bundle checks target and entitlement wiring before
device signing and provisioning.

## Configure and own the peer

Give each node its own existing private `0700` directories. Keep the state
directory across launches to preserve the peer's identity. Use an absolute IPC
directory short enough for Darwin Unix socket paths, including the `/transport`
suffix and terminator. Simulator container paths can be longer than this limit.
Use the app container's temporary directory when it fits, or supply a shorter
private directory the host can access.

```swift
import GNUnetNode

let node = GNUnetNode(options: GNUnetNodeOptions(
    stateDirectory: stateURL.path,
    ipcDirectory: ipcURL.path
))

try await node.start()
let status = try await node.snapshot()
// When phase becomes .ready, status.ready carries the peer key and bound ports.
await node.stop()
```

The default TCP and UDP binds use IPv4 loopback with ephemeral ports. Supply
numeric bind addresses for reachable listeners and optional UDP IPv6. An
optional configuration file supplies GNUnet settings, including
[QUIC and HTTP/3 listeners](../sdk/README.md#inputs-and-capabilities). `dnsServers` accepts
numeric resolver addresses or endpoints in the host's preference order. The
node starts an `NWPathMonitor` for each run and rescans addresses when the
path changes. To replace the DNS list during a run, call
`try await node.setDnsServers(servers)` with endpoints supplied by the app or
its provider. Each snapshot accepts at most 32 entries and 4096 UTF-8 bytes;
each array entry contains one numeric IP or IP:port without whitespace or NUL.
IPv6 scopes remain numeric. An empty list revokes upstreams. Startup and live
updates share the same marshalling and Rust endpoint validation. Live snapshots
apply to the current worker; restarting an ordinary node uses its original
startup options and configuration file. `NWPath.supportsDNS` reports DNS
availability as a Boolean. [Apple path capabilities](https://developer.apple.com/documentation/network/nwpath/supportsdns)

Set the app's local-network usage description when connecting to peers on the
local network. [Apple local network privacy](https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy)

`start()` returns when the worker is launched. Read `snapshot()` for `.ready`
or a terminal `.failed` phase with its diagnostic. `stop()` requests shutdown
and waits for the original worker to join on a private queue. Lifecycle operations
already submitted to the owner complete even if the waiting Swift task is
cancelled. A stopped owner can be started again.

## Optional trusted bootstrap HELLOs

Pass a directory of application-selected official HELLO URLs when building:

```sh
GNUNET_BOOTSTRAP_HELLO_DIR=/absolute/trusted-hellos platform/ios/build-sdk.sh
```

The shared producer stages `gnunet/hellos.list` and numbered files under
`gnunet/hellos` into the Swift package resource bundle. No peers are packaged by
default and no bootstrap list is downloaded. The list contains at most 1024
consecutive canonical names starting at `0000.hello`, each file is at most
65535 bytes, and all bodies total
at most 4 MiB. SwiftPM preserves this layout with its copy resource rule and
the installer uses `Bundle.module`. [Swift package resources](https://developer.apple.com/documentation/xcode/bundling-resources-with-a-swift-package)

On the application's file-I/O queue, install the packaged resources into an
existing app-private parent before constructing the node:

```swift
let bootstrap = try GNUnetBootstrap.install(in: privateAssetsURL)
let node = GNUnetNode(options: GNUnetNodeOptions(
    stateDirectory: stateURL.path,
    ipcDirectory: ipcURL.path,
    configurationFile: selectedConfigurationURL?.path,
    bootstrapDataDirectory: bootstrap.path
))
```

The installer returns a fresh generation only after its listed files have
completed. Keep that directory unchanged until every node using it has stopped;
the application may then remove it. Later installations leave earlier
generations intact. Missing or malformed packaged resources fail explicitly.
The optional startup field selects the shared official PEERSTORE import while
preserving the application's selected configuration file. Rust performs the
canonical signature, expiry and public-record checks described by the
[SDK contract](../sdk/README.md).

## App lifecycle

Retain one `GNUnetApplicationLifecycle` at app scope. Call `enterForeground()`
on initial foreground launch and when the app returns there. Call
`enterBackground(in:)` when the last foreground scene leaves. The bridge
serializes both transitions and asks UIKit for time to complete shutdown. UIKit
controls when the app is suspended. [Apple background execution](https://developer.apple.com/documentation/uikit/extending-your-app-s-background-execution-time)

## Packet tunnel resource ownership

`GNUnetPacketTunnelResources(provider:)` is the lower native boundary for one
original `NEPacketTunnelProvider` session. Its explicit
`GNUnetPacketTunnelPlan` contains addresses, included and excluded routes, DNS, MTU and the
provider's remote-address metadata. It admits one plan per OS session, with
at most 64 addresses, 128 routes and 32 DNS servers. Only the actual
`setTunnelNetworkSettings` completion reports `.applied`; a successful late
completion reports `.appliedWhileClosing` and leaves removal owed. Call the
extension's original `startTunnel` completion only after settings and the
actual shared-SDK readiness barrier succeed. [Native settings completion](https://developer.apple.com/documentation/networkextension/netunnelprovider/settunnelnetworksettings(_:completionhandler:))

`read(completion:)` admits one native read and does not rearm it automatically.
Its raw-IP packets carry a separate `GNUnetPacketVersion`; no private utun fd
or header is extracted. Native AF_INET/AF_INET6 metadata must match the packet
version. The owner validates the packet/count bounds before retaining a batch,
with at most 64 packets and 4 MiB per batch. The caller waits for its bounded
input capacity before requesting another read. [Public packet flow reads](https://developer.apple.com/documentation/networkextension/nepackettunnelflow/readpackets(completionhandler:))

`write(_:completion:)` submits exactly one immutable packet through the original
packet flow. `.accepted` records the public API's true result; `.unknown`
records false, whose zero-effect semantics are undocumented. The caller keeps
the original write identity and never automatically replays an uncertain
packet. This completion grants no remote delivery assurance.
[Public packet flow writes](https://developer.apple.com/documentation/networkextension/nepackettunnelflow/writepackets(_:withprotocols:))

`close(completion:)` fences new work and retires the logical pending read.
The OS read callback captures only a weak owner and its read serial; a late
callback owns no application completion or Rust handle. There is no wait for
an undocumented read-cancellation acknowledgment. Already executing application
callbacks and an admitted native settings/write operation retain their original
ownership until they return. The actual settings removal starts afterward and
`.cleared` requires the successful `setTunnelNetworkSettings(nil)` completion.
Call the original `stopTunnel` completion after the shared SDK and native
resource retirement have completed. The host retains this resource owner
through that completion; unresolved native operations are not reported as
removed. [Provider teardown](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider/stoptunnel(with:completionhandler:))

## Packet tunnel node

`GNUnetPacketTunnelNode(provider:options:hostPolicy:)` binds the shared SDK's
application-packet VPN controller to these original native resources. It selects
outbound TCP, passes empty listener bindings and preserves the official GNUnet
TCP protocol. The ordinary `GNUnetNode` starts application communicator listeners;
use the packet-tunnel node inside an extension. Apple's packet-tunnel guidance
excludes hosting a network listener or proxy server in this provider.
[Apple packet-tunnel usage](https://developer.apple.com/documentation/technotes/tn3120-expected-use-cases-for-network-extension-packet-tunnel-providers)

The required `GNUnetPacketTunnelHostPolicy.prepareUpstream` callback receives
the current `NWPath`. Establish or verify safe upstream routing before returning
the permitted numeric DNS endpoints for that path. The application maintains
that routing policy throughout the tunnel lifetime. Leave
`GNUnetNodeOptions.dnsServers` empty for a packet tunnel node.

The SDK clears old Resolver upstreams when a new path is observed. It cancels
superseded preparation, waits for it to settle and processes only the latest
path. Results for an unsatisfied path leave the Resolver's upstream list empty.
Node startup waits for the first qualified snapshot. The callback must honor
cancellation and return when its original work has settled.
[Apple path monitoring](https://developer.apple.com/documentation/network/nwpathmonitor)

The host policy's `dnsServers` configures NetworkExtension's tunnel DNS settings.
Exclusion routes must stay outside the GNUnet virtual prefixes. Deployment
supplies the appropriate entitlement, provider configuration and upstream route
policy for its endpoints.

`start()` services real route commands and returns after both native settings
application and the shared node readiness barrier. Complete the original
`startTunnel` callback afterward. Route and packet replies retain the original
epoch and revision; a failed packet-flow write reports an uncertain outcome and
is not replayed. One command-reader worker uses bounded waits and rearms after
each exact reply. Input backpressure retains one bounded batch until admitted.
The default packet capacity is 1500 bytes; an SDK route MTU must fit that capacity.

`stop()` requests shared node shutdown and waits up to the configured drain
budget. `retirementPending` leaves original cleanup in progress. Use
`stopAndWaitForRetirement()` for the provider's original `stopTunnel` callback.
It awaits the terminal result from the same owner, including native settings
removal, command-reader retirement and termination of the original node worker.
A terminal failure reports the actual settings error. Cancelling `start()`
requests the same original stop. Any in-flight host preparation must settle
before successful retirement. Signed installation and real routing require
deployment checks.

## DNS Proxy provider

On iOS and iPadOS 18 or later, subclass `GNUnetDNSProxyProvider` in an app
extension and select it as the principal class for
`com.apple.networkextension.dns-proxy`. Sign the extension with the `dns-proxy`
Network Extension entitlement. Use device-wide deployment on supervised
devices or a managed per-app DNS proxy profile.
[Apple DNS proxy deployment](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment#Deploying-a-DNS-proxy-provider)

Set `GNUNET_CONFIG` in `ProviderConfiguration` to a filename in the signed
extension bundle, such as `dns.conf`, or an absolute path to a file the
extension can read. The bundle filename can stay fixed across installations.
The worker loads bundle defaults from `share/gnunet/config.d` before the
selected file. Choose a private listener namespace accessible to clients of
the DNS service. For an extension with a Unix listener and no separate
STATISTICS service, substitute your listener path and numeric upstream resolver.

```ini
[dns]
UNIXPATH = /absolute/private/dns.sock
PORT = 0
DNS_EXIT = 192.0.2.53

[statistics]
DISABLE = YES
```

UDP uses the shared GNUnet DNS interception service, including DNS IPC client
phases and original endpoint-bound replies. TCP uses bounded stream relays to
the original DNS peer on the original bound interface when present. An IPv6
link-local TCP destination requires the same interface zone. NetworkExtension
exposes no TCP local endpoint for qualifying legacy site-local zones. Startup
acknowledges the service after its listeners and gateway are ready. Stop closes
admission and completes after the original native callbacks retire and the
worker joins. Port-53 multicast relay is opt-in and requires Apple's multicast
entitlement. [Native DNS backend](../../adapters/dns-service-std/NATIVE_BACKENDS.md)
