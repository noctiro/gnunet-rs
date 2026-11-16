# gnunet-service-dns

The DNS interception service composes the bounded interception engine, native
client IPC, DNSSTUB, STATISTICS and one explicitly selected packet source.
The shared foreground runs on Linux, macOS, Windows and FreeBSD. Unix uses the
bundled privileged helper; Windows selects automatic WinDivert capture or a
manually routed Wintun packet source. Linux supports automatic interception
policy; macOS/FreeBSD provide a delegated
[PF backend](../../adapters/dns-service-std/PF.md). Remaining behavior is tracked in the
[implementation status](../../IMPLEMENTATION_STATUS.md).

## Configuration and startup

Standard SERVICE options include `-c/--config`, `-d/--daemonize`, help, version
and logging. `[dns]` selects service listeners, ACLs, interface addresses and
`SKIP_ROUTING_SETUP`. On Unix, `[dns-rust] HELPER_BINARY` selects an absolute
helper executable; the default is the sibling `gnunet-helper-dns`. Windows
provider selection is described below.

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

## Windows automatic interception

With `SKIP_ROUTING_SETUP=NO`, `[dns-rust] WINDIVERT_DLL` selects an absolute
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
option and is rejected for Windows. Local Windows endpoint access uses native ACLs; explicit Unix UID/GID matching requests are rejected.

## Resource ownership and shutdown

The [shared host](../../adapters/dns-service-std/README.md) owns client queues,
packet transports and resolver requests. Native stop control and the selected
Reporter feed the same foreground. Logger failure stops new work.

Shutdown closes local admission, retires requests and drives the original
packet source and STATISTICS producer within one fixed native grace interval.
Failed waits retain the original child; exit status, wait errors, native stop errors,
forced termination and pending frame prefixes remain separate observations.
Native device-close errors are retained synchronously, including early report
conversion. Native whole-packet submissions are distinct from helper pipe writes.
Unconfirmed process retirement or control cleanup fails the service.

Ready/stopped output and diagnostics use synchronous output. Network deadlines
do not preempt an operating-system output call.
