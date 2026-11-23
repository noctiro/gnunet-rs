# Native NSE host

This adapter drives the pure NSE owner through native CORE/PILS clients, local
subscribers and an exact raw8 proof store. It uses the verified PILS key and
matching CORE INIT_REPLY before activating an identity.

## Public interfaces

`Host` owns original client streams, operation leases, proof work and subscribers.
Callers supply `Instances`, `Ports`, `Limits`, the canonical `RuntimeClock` and
service access policy. `drive` performs bounded fair turns; dropping a waiting
future retains partial cursors, original attempts and cooperative yield state.
Permanent closure cannot be reversed by clock or backend recovery.

`startup::{foreground,foreground_with_clock}` binds configured or inherited
listeners. `foreground_listening_with_clock` consumes completed listeners and
accepts a separate original readiness future. Unix callers may use the
`foreground_prepared*` APIs around an explicit identity transition. Embeddings
must already have the configured account; these APIs never change identity.

`startup::serve_embedded` selects the node's original private IPC sources and
absolute raw8 proof path. Its callback follows matching CORE/PILS activation
and a usable proof store. Proof search can continue after readiness. Complete
the stop future and keep driving the service until native sources retire and
pending proof progress is flushed.

The [standard executable](../../apps/gnunet-service-nse/) selects native startup,
logging, stop subscriptions and a concrete STATISTICS publisher.

## Configuration and work

Official defaults are `WORKBITS=15`, `INTERVAL=1h` and `WORKDELAY=5ms`.
`PROOFFILE` selects raw8 persistence. Node-wide `[PILS] PROFILE` selects
`reference029`/`reference-0.29.1` or the official conditional `deterministic`
profile before private resources or native-client admission. Verification never
falls back to another profile.

Native work slices try one through four candidates, default one. Checkpoints
coalesce for an explicit one-second default; discovery and clean shutdown flush
immediately. These local scheduling policies do not change proof difficulty,
round timing or the configured PoW delay. Loaded proofs are candidates, including
missing-as-zero; the pure owner verifies them for the exact activated identity.

## Native proof storage

`proof::Store` holds the original directory and a persistent native
`File::try_lock` guard. Paths are anchored relative to that directory, file
identities retain the full native representation, and symlink/special objects
cannot become proofs. The caller excludes hostile namespace administration.

A commit writes a private stage, synchronizes the file, publishes that original
object and checks exact raw8 readback through its held handle. Interrupted writes
are not retried. Before publication, cleanup targets only that owned stage and
retains its failure separately. `loaded` distinguishes absence from eight zero
bytes. Synchronous bounded filesystem operations remain outside detached tasks.

Publication errors or failed readback retain the original file and expected
bytes, fence further writes and require `recover_backend`. Recovery never writes
a newer value or accepts a different object with equal bytes. The host retires
its identity and physical outputs before recovery and then requires fresh
CORE/PILS agreement.

`Report::commits` and `Progress::Committed` report file-sync/publication/readback
completion. `Report::directory_sync` and `Store::directory_sync` separately report
the [native naming barrier](../native-std/API.md#anchored-filesystem-operations).

## Streams and cancellation

Each START321 belongs to its original subscriber. Estimates323 retain immutable
notification origins and partial cursors; only a full native write invokes
`notified`. Later revisions coalesce behind that original output, including
duplicate START refreshes.

Rotation or PILS loss invalidates old logical effects, closes CORE output and
subscribers, cancels original PILS operations and retires alarms before a new
identity commits. CORE loss retires its original peer scopes without replaying
old sends. Each caller turn also drives the shared Resolver even when host work
is ready; Resolver progress cannot skip the host.

## Readiness, diagnostics and statistics

The driver notifies readiness only after actual activation and the ready observer.
It polls the original notification once with a fixed ten-second native deadline,
the same shutdown future and permanent diagnostic-failure latch. Failure reaches
normal host, statistics and Resolver cleanup; binding alone cannot signal ready.

`statistics::{Statistics,StatisticsFactory}` supplies concrete error, report and
driver types without coupling the NSE host to a statistics protocol package.
The executable injects the shared ten-key `Producer` on the same Resolver and
clock. Native guards precede canonical waits; publisher failure fences only that
publisher, preserving unknown deltas without replay on a replacement source.
Successful shutdown has one bounded final publisher drain before Resolver
retirement. Failed service/diagnostics abort it and retain independent cleanup
errors. A statistics deadline cannot force-cancel a synchronous proof operation.

See the [compatibility contract](../../spec/gnunet/compatibility.md) for external
interoperability and qualification requirements.
