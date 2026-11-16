# GNUnet ARM client host

The ARM host drives the borrowed ARM client and monitor cores through the shared
[CLIENT transport](../client-std/README.md). Linux, macOS and FreeBSD use the Unix
native backend; Windows uses its native socket, process and startup backends.
GNUnet messages and operation state remain in the platform-independent cores.

## Public interfaces

- `ClientHost` drives control requests, connections and original callbacks.
- `MonitorHost` owns an independent STATUS subscription.
- `LocalLauncher` prepares and starts local ARM using a caller-owned
  `ChildRegistry`; remote service requests continue through ordinary ARM IPC.
- `Clock` subscribes to the caller-selected shared runtime clock.

See [API and ownership](API.md), [live configuration](LIVE_CONFIGURATION.md) and
[native launch policy](PROCESS.md). The repository [architecture](../../ARCHITECTURE.md)
defines the shared wire and native boundaries.

## Configuration and use

`ClientHost::connect` selects the endpoint from `[arm]` using normal CLIENT
configuration. `connect_live` retains a shared configuration; `connect_unix`
selects an explicit native local endpoint. Monitor construction follows the same
selection rules. The [CLI](../../apps/gnunet-arm/README.md) is a normal consumer.

Local launch reads `BINARY`, `PREFIX`, `OPTIONS`, `CONFIG` and the existing
`TESTING` daemonization values. Unix launch takes the explicit fresh-exec helper
path. Windows launch takes native limits and needs no helper executable.
`with_environment` also takes an explicit environment/cwd snapshot and libexec
cache for isolated embeddings.

## Cancellation and resources

Dropping a drive future preserves the original stream, partial RX/TX, retry and
operation state. Canceling a callback does not retract an already queued remote
request. Disconnect closes that owner's physical IPC and suppresses its callback
authority without signaling a launched process.

The launcher borrows the caller's registry; the caller retains original-process
wait authority after dropping the host. Explicitly drain children and consume
`take_reaped()` receipts to release bounded completion credits. Drop performs no
termination, unbounded wait or background reaping.

Windows bootstrap drivers remain with the launcher when a callback is canceled
or disconnected. `settle_startups` completes remaining handshakes without
waiting for a live service to exit; `drain_children` also drives original kernel
exit waits. Dropping the launcher closes unfinished bootstrap endpoints; retain
it when admitted children still require startup progress.

## Native verification

Unix C/descriptor fixtures live under `examples/*/unix.rs` and Unix-gated suites.
The Windows `windows_client` executable exercises actual native child creation,
path arguments, qualified readiness and cancellation ownership. Its Windows
code must execute on a Windows runner; cross-compilation is not a native run.
Source references and interoperability tools are described in [UPSTREAM.md](UPSTREAM.md).
