# GNUnet foreground node

`gnunet-node` runs the [Rust node composition](../../adapters/node-std/README.md)
as one foreground process. It uses the same local services and peer protocols as
the application SDK. A shell or a native supervisor provides the service account
and its private directories.

## Run

Build with `cargo build --locked --release -p gnunet-node`, or use the
[staged desktop prefix](../../tools/xtask/node/README.md).

Prepare two existing directories owned by the running account. Use mode `0700`
on Unix or an owner-only ACL on Windows. Keep the IPC directory path short enough
for native Unix sockets. For a private listening node on Unix:

```sh
root=$(mktemp -d /tmp/gnunet-node.XXXXXXXX)
mkdir -m 700 "$root/state" "$root/ipc"
gnunet-node --state-directory "$root/state" --ipc-directory "$root/ipc" \
  --tcp-bind 127.0.0.1:0 --udp4-bind 127.0.0.1:0
```

Set `--tcp-bind` to one numeric address or `--tcp-dual-stack` to one nonzero port.
Listening requires `--udp4-bind` and accepts `--udp6-bind`. Port zero requests an
ephemeral port for a numeric bind. `--outbound-tcp` selects dialing and excludes
all peer bind options. Local GNUnet IPC is available in either mode.

## Configuration and lifecycle

- `--config FILE` loads one explicit GNUnet configuration.
- On Linux, `--require-storage-mount PATH` requires an existing non-root mount
  and places both private directories strictly below it on the same mount.
  Supply absolute paths without symlinks or nested mounts. The startup check
  uses the original directory descriptors and requires Linux mount IDs
  (`statx`, Linux 5.8 or later). Keep the mount and its namespace stable until
  the node stops.
- `--bootstrap-data-directory PATH` selects the data directory containing
  packaged `hellos`.
- Repeat `--dns-server ADDRESS:PORT` to supply numeric upstreams in preferred
  order. IPv6 addresses use brackets and can include a numeric scope.
- Use `--system-dns` on Linux, macOS, Windows or FreeBSD to delegate address
  and reverse queries to the system resolver. This option excludes
  `--dns-server`.
- Use `--nat-helpers-directory PATH` to select the installed GNUnet NAT
  reversal observer and sender from one trusted absolute directory.
- `--startup-timeout-ms` and `--drain-timeout-ms` set the startup and TRANSPORT
  drain budgets. Their defaults are 30000 and 10000 milliseconds.

Linux, Android and OpenHarmony standard systems use rtnetlink notifications.
macOS and FreeBSD use a read-only routing socket. Both sources report
interface, address and default-route changes. Windows uses IP Helper's
interface, unicast-address and route change subscriptions. Notifications
trigger the existing interface scans. Timed scans remain available where the
system refuses the subscription. System DNS handles its own network policy.
[Resolver backends](../../adapters/resolver-std/README.md#platforms-and-entry-points)

The process writes `READY` with its agreed peer identity and actual bound
endpoints. SIGINT and SIGTERM on Unix and native console events on Windows
request retirement. The process writes `STOPPED` after its local owners retire.
Keep the process alive through that point when the supervisor requires orderly
shutdown.

## NAT reversal

The staged desktop prefix places `gnunet-helper-nat-server` and
`gnunet-helper-nat-client` under `lib/gnunet/libexec`. Windows uses the same
names with the `.exe` suffix. The deployment keeps both executables and their
directory under administrator control and supplies their native raw-socket
authority. Add the helper-directory option to the service arguments to opt in.
The node supervises the helpers through its private NAT service.
[NAT helper contract](../../adapters/nat-std/README.md#embedded-service)

## System services

Use the service recipe for your target from the
[staged prefix](../../tools/xtask/node/README.md#deploy-as-an-operating-system-service).
The recipes select a dedicated service account and separate state and IPC
directories. They run the same executable as foreground mode.

- [Linux systemd](../../platform/linux/node/README.md) uses `--systemd`
  followed by the node options. It sends native readiness and stop notifications
  to the original `NOTIFY_SOCKET`.
- [Windows Service Control Manager](../../platform/windows/node/README.md) uses
  `--windows-service` followed by the node options. The service publishes
  running and stopped states to SCM.
- [macOS launchd](../../platform/macos/node/README.md) and
  [FreeBSD rc.d](../../platform/freebsd/node/README.md) run the foreground
  command. Use the node's readiness output to confirm local service startup.
