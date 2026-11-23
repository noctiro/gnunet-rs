# gnunet-service-dns

The DNS interception service composes the bounded interception engine, native
client IPC, DNSSTUB, STATISTICS and one explicitly selected packet source.
The shared foreground runs on Linux, macOS, Windows and FreeBSD. Unix uses the
bundled privileged helper. Windows selects WFP, WinDivert or a manually routed
Wintun packet source. Linux supports automatic interception
policy; macOS/FreeBSD provide a delegated
[PF backend](../../adapters/dns-service-std/PF.md). The macOS system extension
and iOS app extension use the same DNS foreground and official IPC.
Open work is tracked in [implementation status](../../IMPLEMENTATION_STATUS.md).

## Configuration and startup

Standard SERVICE options include `-c/--config`, `-d/--daemonize`, help, version
and logging. `[dns]` selects service listeners, ACLs, interface addresses and
`SKIP_ROUTING_SETUP`. On Unix, `[dns-rust] HELPER_BINARY` selects an absolute
helper executable. Otherwise `gnunet-helper-dns` resolves through
`[PATHS] SUID_BINARY_PATH` or the installation's libexec directory. Windows
provider selection is described below.

Set `[dns] DNS_EXIT` to the numeric upstream resolver on port 53. The service
and Apple providers require this setting. IPv6
link-local addresses require a nonzero native zone, for example
`DNS_EXIT = fe80::53%7`. Windows sockets and the connected Apple providers
also accept an explicit legacy site zone. The service retains the original
zone for sending and response matching.

```sh
gnunet-service-dns -c node.conf
```

Unix startup captures inherited descriptors before other resources, prepares
TCP/adopted listeners before configured identity changes, and creates local
listeners under that identity. Windows startup captures native activation,
checks configured identity and uses the qualified parent readiness channel.
Detachment precedes runtime resources and stop subscriptions.

On Unix, the helper receives the official six arguments and MQ214/TUN_PI framing.
Process creation and local pipe writes do not acknowledge interception setup
or TUN delivery. The READY line identifies the packet source and this
unacknowledged interception boundary.

## Apple DNS providers

Build `gnunet-dns-proxy` with the `macos-dns-proxy` feature for macOS 15+.
The OS launches its `GNUnetDNSProxyProvider` class; this executable is not a
replacement invocation of the ordinary service CLI. UDP flows use the shared
DNS phases, while TCP flows use a bounded byte relay with independent half-close.
Provider UDP and TCP upstreams use Network.framework.
UDP peer readiness and submitted sends have fixed monotonic bounds; a failed or
busy peer leaves other configured resolver attempts eligible for normal retry.

For macOS, set `GNUNET_CONFIG` in
`NEDNSProxyProviderProtocol.providerConfiguration` to a readable absolute
configuration filename. Installation defaults load from
`Contents/Resources/share/gnunet/config.d`. The
[iOS SDK](../../platform/ios/README.md) hosts the same service in an app
extension on iOS and iPadOS 18 or newer.

Provider startup preserves the OS process identity and environment. Omit
`[dns] USER` and configure listeners and their access policy for the provider
identity. Set `[statistics] DISABLE = YES` when no STATISTICS service is
available.

See [provider packaging and configuration](macos/README.md) for the Rust bundle
helpers, containing application's explicit management commands, native resource
settings, app-group mapping and deployment boundaries.

## Linux helper routing

The default `LINUX_BACKEND=HELPER` manages routing unless `SKIP_ROUTING_SETUP`
is enabled. If routing table `53`, priority `1053` or mark `136708149` is
reserved by the deployment, put an unused set in `/etc/gnunet/dns-routing.conf`:

```ini
TABLE = 300
PRIORITY = 1053
MARK = 0x101
```

The file and its parent directories must be root-owned, without group or other
write permission or symbolic links. Set all three keys. The helper refuses an
occupied table or priority; reserve the selected mark in the firewall policy.

## Linux transparent ingress

The Linux service can accept transparent IPv4 and IPv6 UDP DNS from named
non-loopback ingress interfaces. Configure the deployment's PREROUTING
interception and local policy route for UDP destination port 53 before starting
the service. The interception rule selects `TPROXY_PORT` while preserving the
original IP and UDP destination. Use a nonzero `TPROXY_PORT` distinct from
UDP port 53, which the service reserves as the original reply source port.
Keep `TPROXY_BYPASS_MARK` distinct from the interception routing mark and
exempt it from interception and proxy routing.
The service needs permission to open transparent sockets and set socket marks.

```ini
[dns-rust]
LINUX_BACKEND = TPROXY
TPROXY_PORT = 5300
TPROXY_FAMILIES = dual
TPROXY_INTERFACES = eth0 eth1
TPROXY_BYPASS_MARK = 0x80000000
```

`LINUX_BACKEND=HELPER` remains the default. The transparent path uses the
original ingress and source port for replies. `TPROXY_FAMILIES` selects the
required ingress listeners independently of `[dns] DNS_EXIT`. Use `ipv4` or
`ipv6` for a single-family policy. The default `dual` requires both listeners.
For a VRF, list its ingress member interfaces in `TPROXY_INTERFACES`.
Locally generated traffic redirected through loopback requires a separate
original-socket mechanism.
[Linux receiving path](../../adapters/dns-service-std/NATIVE_BACKENDS.md#linux-transparent-ingress)

## Windows automatic interception

`WINDOWS_BACKEND=WFP` opens the installed GNUnet DNS control device and starts
capture with the original bound DNSSTUB sockets. Run the service with access
to the device. The default device ACL grants this access to LocalSystem.
Neither WinDivert nor Wintun DLL configuration applies to WFP.

```ini
[dns]
SKIP_ROUTING_SETUP = NO

[dns-rust]
WINDOWS_BACKEND = WFP
```

`NATIVE_OPEN_TIMEOUT` bounds initial and replacement device open and START.
It defaults to `5 s`. Replacement starts after the old native file has closed.

The service tracks native completion separately from submission. Stopping
revokes capture before relinquishing the reserved sockets. See the
[Windows WFP adapter](../../adapters/wfp-dns-std/README.md) for the local device
and [implementation status](../../IMPLEMENTATION_STATUS.md) for qualification.
The [driver package and operator commands](../../platform/windows/wfp-driver/README.md#package-preparation)
cover persistent metadata, native retirement and the separate service lifecycle.

### WinDivert

With `SKIP_ROUTING_SETUP=NO`, WinDivert remains the default.
`[dns-rust] WINDIVERT_DLL` selects an absolute
trusted official WinDivert 2.2 DLL. Its dependencies, exact ABI and documented
thread safety are part of the operator's provider trust. The matching signed
kernel driver must already be installed, and opening capture requires native
administrator privileges. The service uses `NO_INSTALL`: it does not install or
download a driver, create a TUN, or change the machine's routing tables.

```ini
[dns]
SKIP_ROUTING_SETUP = NO

[dns-rust]
WINDIVERT_DLL = C:\GNUnet\WinDivert.dll
```

The filter captures outbound IPv4/IPv6 UDP destination-port 53 queries.
DNSSTUB exclusively binds and retains its original upstream ports before filter
creation; those ports are excluded to prevent recursive capture of `DNS_EXIT`
queries. A failed original socket stops admission rather than opening an
unexcluded replacement. Reply metadata stays bound to its captured request,
original session and observed inbound interface identity. A stale route refuses
only its query; fresh captures can use a newly observed interface. An expired
injection is canceled and retains its original completion loan within a fixed
retirement bound, without replaying the old reply. See [capture ownership](../../adapters/native-std/WINDIVERT.md)
for finite queues, asynchronous loans and uncertain teardown.

## Windows manually routed interface

`[dns-rust] WINTUN_DLL` must select an absolute trusted official Wintun DLL,
including trusted dependencies and ABI. The service loads that explicit path;
it performs no download or provider search. `WINTUN_RING_BYTES` selects a native
power-of-two ring capacity, default 128 KiB per direction.

`WINTUN_MODE=create` creates the requested `[dns] IFNAME`, configures both address
families, sets each IP family's MTU and raises administrative state.
`WINTUN_MODE=existing` opens the named adapter unchanged; addresses, MTUs and
routing remain with its administrator. Neither mode acknowledges IPv6 DAD or
remote reachability. The original provider/session and GUID/LUID identity remain
owned through packet I/O and shutdown.

```ini
[dns]
IFNAME = gnunet-dns
SKIP_ROUTING_SETUP = YES

[dns-rust]
WINTUN_DLL = C:\GNUnet\wintun.dll
WINTUN_MODE = create
WINTUN_RING_BYTES = 128 KiB
```

Administrator policy must direct intercepted DNS traffic to this interface and
exempt the daemon's `DNS_EXIT` traffic from recursion. `WINTUN_DLL` requires
manual mode; `WINDIVERT_DLL` requires automatic mode. `HELPER_BINARY` is a Unix
option and is rejected for Windows. Local Windows access uses the
[configured listener's DACL](../../adapters/service-runtime/README.md#configured-local-listeners).
`UNIX_MATCH_UID` selects owner access and takes precedence over
`UNIX_MATCH_GID`, which selects primary-group access. Standalone local listeners
default to owner access. A restricted inherited listener needs its creator's
original pre-listen protection. TCP uses the configured IP ACL.

## Resource ownership and shutdown

The [shared host](../../adapters/dns-service-std/README.md) owns client queues,
packet transports and resolver requests. Native stop control and the selected
Reporter feed the same foreground. Logger failure stops new work.

Shutdown closes local admission and drives the original packet source, DNS
upstream and STATISTICS producer within one fixed native grace interval. Provider
shutdown also drains TCP relays and native callback resource leases before
fulfilling the original OS stop obligation.
Failed waits retain the original child; exit status, wait errors, native stop errors,
forced termination and pending frame prefixes remain separate observations.
Native device-close errors are retained synchronously, including early report
conversion. Native whole-packet submissions are distinct from helper pipe writes.
Unconfirmed process retirement or control cleanup fails the service.

Ready/stopped output and diagnostics use synchronous output. Network deadlines
do not preempt an operating-system output call.
