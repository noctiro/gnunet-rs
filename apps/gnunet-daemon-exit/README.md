# GNUnet EXIT daemon

`gnunet-daemon-exit` implements the official EXIT peer protocol through Rust
CADET, packet, DNS, REGEX and public DNS-advertisement owners. The PROGRAM entry
runs one caller-driven scheduler with the shared Resolver and canonical clock.

## Configuration and launch

The daemon accepts standard PROGRAM options, including `-c`, `-h`, `-v`, `-l`
and `-L`, without positional arguments. It reads official `[exit]` keys and
bounded `[exit-rust]` policies. See the
[configuration and native reference](CONFIGURATION.md).

```sh
gnunet-daemon-exit -c exit.conf
```

Examples cover [DNS-only operation](examples/dns-only.conf),
[Unix TUN operation](examples/tun.conf) and [Windows Wintun](examples/windows.conf).
TUN creation/configuration requires native privileges. Select a trusted official
DLL path on Windows and configure the host's forwarding/firewall/NAT policy.

## Devices and ownership

Linux supports an explicit privileged helper or direct TUN; macOS uses utun,
FreeBSD uses a checkpointed TUN, and Windows uses Wintun. DNS-only operation
requires no TUN. Windows existing mode verifies configuration without rewriting
it or acquiring route cleanup authority. Unix descriptor transfer retains its
original native ownership contract.

Windows session recovery retains the original adapter, verifies its current
configuration and attaches a fresh packet epoch under one finite outage deadline.
CADET and DNS keep their independent owners. Physical reopen reconciles the old
scope and waits for the selected logical interface to reappear, then verifies
its configuration. See [Wintun recovery](CONFIGURATION.md#windows-wintun).

Readiness requires actual interface configuration, routes, IPv6 DAD, CADET port
writes and required local REGEX submissions. It grants no remote publication or
Internet-reachability proof. Original source epochs, finite deadlines, cancellation
and independent cleanup errors remain attached to their owners.

## Architecture and constraints

[Device preparation](src/network/device.rs) is separate from
[route and DAD handling](src/network.rs), [scheduling](src/foreground.rs),
[configuration](src/settings.rs) and [cleanup ownership](src/lifecycle.rs).
The Windows [recovery controller](src/network/recovery.rs) separates retry policy,
read-only verification and source admission.
Protocol engines and native adapters remain independent of PROGRAM startup.

Native calls are synchronous and cannot be preempted by an async timer. Windows
uses native identity and termination APIs. Select `PEER_AF_PROFILE` for the
opposite peer's protocol representation when it differs from the local platform.
See the [native contracts](CONFIGURATION.md) and central
[open work](../../IMPLEMENTATION_STATUS.md).
