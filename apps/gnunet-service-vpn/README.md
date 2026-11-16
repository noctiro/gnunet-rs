# GNUnet VPN service

`gnunet-service-vpn` exposes the official VPN service IPC and routes its flows
through the independent Rust VPN engine, native packet source and CADET client.
A single caller-driven runtime also schedules Resolver and REGEX discovery.

## Configuration and launch

The service accepts standard SERVICE options, including `-c`, `-d`, `-h`, `-L`,
`-l` and `-v`. It loads official `[vpn]` keys and bounded local `[vpn-rust]`
policies. See the [configuration and device reference](CONFIGURATION.md).

```sh
gnunet-service-vpn -c vpn.conf
```

Use the [Unix fresh-device example](examples/fresh.conf) or the
[Windows Wintun example](examples/windows.conf). Select an actual trusted Wintun
DLL path on Windows. Device creation and configuration require native privileges.

## Native lifecycle

Linux can use the official framed helper; macOS uses utun, FreeBSD uses a
checkpointed TUN, and Windows uses Wintun. Fresh and caller-owned devices retain
distinct configuration responsibility. Startup captures original inherited
resources before competing handles and qualifies devices after identity setup.

Windows session recovery retains the original adapter, drains old flow debt and
verifies configuration before renewed readiness under a fixed outage deadline.
It preserves owned route cleanup responsibility and leaves borrowed routes
untouched. See [Wintun recovery](CONFIGURATION.md#windows-wintun).
Physical reopen settles the old native scope before admitting the selected
reappearing logical interface as borrowed, with fresh configuration verification.

Readiness requires the actual interface plan, routes, IPv6 DAD and CADET IPC
attachment. It grants no remote-exit reachability claim. Original stop sources,
fixed deadlines, source epochs and cleanup causes remain on their owners.

## Architecture and constraints

[Device provisioning](src/device.rs) is separate from
[foreground scheduling](src/foreground.rs),
[configuration](src/settings.rs) and [cleanup ownership](src/lifecycle.rs).
Windows [retry policy](src/recovery.rs) consumes explicit coordinator recovery
owners; packet and routing generations remain inside the shared coordinator.
Unix and Windows process startup use their native lifecycle adapters.
Protocol engines and packet bounds remain in the shared
[VPN coordinator](../../adapters/vpn-std/COORDINATOR.md).

Windows local access uses native endpoint ACLs; requested Unix UID/GID peer
checks are refused. An existing device is verified without adopting its
administrative lifetime. Native synchronous calls cannot be preempted by an
async deadline. See the [device contracts](CONFIGURATION.md#device-selection)
and central [open work](../../IMPLEMENTATION_STATUS.md).
