# TCP communicator PROGRAM

`gnunet-communicator-tcp` runs the Rust GNUnet TCP communicator over native TCP
sockets and official PILS, TRANSPORT, PEERSTORE, NAT and STATISTICS IPC. The wire
source basis is GNUnet v0.29.1. Protocol and runtime interfaces are described in
the [runtime guide](../../adapters/tcp-runtime-std/README.md).

## Run and configure

```sh
gnunet-communicator-tcp -c official.conf
```

Shared PROGRAM handles `-h`, `-v`, `-L LEVEL` and `-l FILE`.
`[communicator-tcp]` supports bare-port, numeric or hostname `BINDTO`,
`DISABLE_V6`, queue/rekey settings and `USERNAME`. Hostname lookup uses the shared
Resolver and clock, with a fixed 60-second budget and at most 16 callbacks.
Each callback binds its listener before acknowledging its original lease.

Rust settings belong to `[communicator-tcp-rust]`:

| Setting | Meaning |
| --- | --- |
| `KEY_PROVIDER = existing-local` | Read the existing `[peer] PRIVATE_KEY` after PILS verification and require the same public identity; never generate a replacement key. |
| `STATE_DIRECTORY` | Paired per-peer V2 state; defaults to `$GNUNET_DATA_HOME/tcp-rust-state`. |
| `REPLAY_RECORDS` | Maximum distinct remote peer/replay-kind floors; defaults to 8192, with explicit refusal on exhaustion. |
| `PILS_PROFILE` | Optional identity profile override; must agree with an explicit global `[PILS] PROFILE`. |

PILS profiles are `reference029` (alias `reference-0.29.1`, default),
`deterministic` (alias `reference-deterministic`) and explicit `lsd0014-text`.
The last is a published textual derivation with no official interoperability
claim. Identity selection does not alter TCP handshake or rekey policy.

## Native startup and storage

Linux, macOS and FreeBSD share Unix descriptor capture and privilege handling.
Windows captures its original bootstrap/activation handles and checks configured
identity against the process token. New listeners bind before the Unix identity
switch or Windows identity check. Unix uses its reuse policy; Windows requests
exclusive address use. All platforms transfer inherited listeners exactly once
into the same Services, Resolver, clock and current-thread PROGRAM runtime.

Each complete local peer selects a V2 89-byte frontier and matching replay
catalog. Missing, foreign, older or V1 state is refused without reset or import.
The native storage layer retains original directory/file handles across
publication and reconciliation. Observed file synchronization and directory
barrier availability are recorded separately.
[Replay recovery](../../adapters/tcp-runtime-std/README.md#persistent-replay-recovery)

## Operation and shutdown

Listeners, interface snapshots and NAT notifications publish canonical ADD/DEL
claims through the original Pool. IPv4 `tcp-IP:0` CREATE uses the same NAT
registration. Clear reversal probes cannot authenticate a peer; the session
must complete signature, replay and challenge checks for its exact parent.
READY means local listener/service acquisition and successful output flush.

The shared stop subscription owns native termination and inherited parent
control. Logger, clock and source failure retain the original foreground future,
partial I/O and cleanup debt. Shutdown drains sockets and the original replay
worker. Only the consumed Pool quiescence proof and successful worker/frontier
conditions permit cleaning the epoch. The first 30-second cleanup deadline
cannot substitute for a worker join. Statistics has an independent five-second
final drain; all original and cleanup failures remain observable.

Healthy PILS identity updates retire the immutable key generation before its
replacement starts on the same listeners. Local TRANSPORT recovery preserves
healthy peer sessions while retiring old source callbacks; replacement REGISTER
and fresh queue/address announcements never replay old SEND, CREATE or NAT
operations. Physical PILS loss or uncertain replay history stops the owner.

The six official nonpersistent `communicator-tcp` statistics share the same
Resolver and clock. Publisher failure remains separate from healthy TCP work.
Native runtime and official peer qualification are tracked in the
[implementation status](../../IMPLEMENTATION_STATUS.md).
