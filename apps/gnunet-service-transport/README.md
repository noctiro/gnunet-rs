# TRANSPORT service

`gnunet-service-transport -c transport.conf` runs the Rust TRANSPORT owner with
external PILS, PEERSTORE, NAT, STATISTICS and communicator endpoints. It does not
start those dependencies or an aggregate peer node.

## Configuration

Shared SERVICE options are `-c/-d/-h/-L/-l/-v`; `-v` prints the version.
[transport.conf](transport.conf) lists official listener/ACL settings and bounded
`[transport-rust]` resource policies. `[PILS] PROFILE` selects `reference029` or the
official conditional `deterministic` profile consistently across signing,
discovery, publication and HELLO verification.

`MONOTIME_STORE` defaults to `$GNUNET_DATA_HOME/transport-rust-monotime`.
The independent marked `Namespace::Transport` stores only the public eight-byte
reservation highwater. Foreign/unmarked roots or marked roots with missing
canonical state are refused; C keys and monotime databases are not adopted.

`USE_BURST_NAT=YES` enables bounded attempts using HELLO candidates and official
START_BURST1253/BURST_FINISHED1254 messages for a registered burst communicator.
Neither command write nor burst completion proves a validated remote route.

## Native startup

Unix captures inherited listeners/control first and performs fresh-process
detachment before runtime or private resources. TCP/activation preparation
precedes the configured account transition; new local paths finish afterwards.
Windows captures native activation/bootstrap and verifies the selected process
SID. Both entries register original parent/native stop subscriptions before
opening reservation workers and use the same foreground, session and DV drivers.

Unix UID matching takes priority over GID matching. Windows protects local paths
with native ACLs; Unix UID/GID requests remain explicit unsupported errors.
Configured TCP endpoints use the shared address ACLs.

## Readiness and cleanup

The once-only READY observer runs after actual PILS authority and required
persistence receipts make the Owner admissible. It flushes the real public peer
identity to stdout. Windows then drives the original asynchronous parent status
with one fixed native deadline; failure cannot restart or resubmit it.
A listener, queued publication or control EOF cannot substitute for readiness.

Source recovery preserves original queued/partial work and worker ownership.
Soft shutdown stops new admission, drains eligible non-monitor work under its
original finite grace, then closes remaining sources. Reservation/DV workers
must actually drain and join. An admitted synchronous filesystem operation cannot
be force-canceled by socket grace. Service, output, diagnostics and independent
cleanup failures remain observable.

## Resource and time contracts

The example configuration lists source, input, operation, initialization and
retirement bounds. Idle application MQs have no first-frame/INIT timeout;
partial-input time starts at the first byte and cannot renew with progress.
Payload, protocol credit and immutable output retain their original owners.

RTT, retries and scheduling use monotonic elapsed time; signed records use the
canonical GNUnet absolute clock. Absolute adjustment does not create a new
monotonic source, reservation interval or native deadline. File synchronization
and directory-barrier observations remain distinct on native storage backends.
See the [service API](../../adapters/transport-service-std/) and central
[compatibility contract](../../spec/gnunet/compatibility.md) for further contracts.
