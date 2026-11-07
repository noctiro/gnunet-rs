# Native NSE host

`Host<P,S>` composes the pure `gnunet-nse::owner::Service`, original native CORE
and PILS clients, and common bounded `Framed` subscriber connections. `Instances`
remain external to these movable owners. `Ports` must share the same explicit
canonical absolute UTC clock; construction reserves listeners and a fallible
heap allocation of exactly 1024 Argon2 blocks, never a 1MiB stack array. No
Resolver, background task, C daemon or libgnunet implementation is created.

An verified PILS announcement must match CORE's actual `Ready.local`
before identity activation. Every original CORE peer/epoch has its own NSE
peer token, including self-loopback, which contributes to the peer floor and
`SelfUpdate`. Original signing leases map to PILS operations with an exact
verified target and verified signer. Original transmissions map to CORE
send IDs; only full local writes return submission capacity. Forwarded
remote origin signatures remain unchanged. Submission is not remote delivery.

Configured foregrounds select node-wide `[PILS] PROFILE` once before listener
completion, proof storage and native-client admission. The official default
`reference029`/`reference-0.29.1` and explicit conditional `deterministic` profile
reach the original PILS client through `Limits.pils_profile`; a direct Host
constructor uses that explicit typed field. Unknown configuration is refused,
and HELLO verification never tries a different profile after failure.

The normal settings remain WORKBITS15, INTERVAL1h and WORKDELAY5ms. Native work
slices allow one through four candidates, default one, and rotate with CORE,
PILS, subscriber and accept progress. Native progress checkpoints coalesce for
an explicit one-second default; discovery and clean shutdown flush immediately. This does not change proof difficulty, round timing or the PoW delay. Each raw8
persistence request retains its original lease until durability.

`proof::Store` owns a real `File::try_lock` guard for its entire writer lifetime. It never treats a PID file as a lock or unlinks the persistent guard. The writer
checks its original guard inode, writes exact raw8 to an owned temporary,
synchronizes the file, atomically renames, synchronizes the directory, and checks
exact readback. Temporary cleanup checks inode ownership and disarms after rename. `loaded()` distinguishes a missing file from a zero raw8 file. The host
explicitly uses missing as unauthenticated candidate zero, then pure NSE verifies
any loaded candidate against the exact activated identity and configured work.

A post-rename failure retains the original expected raw8 and quiesces writes. `recover_backend` synchronizes and reads back that same original commit; it does
not write a replacement or acknowledge a newer effect. Fence loss is an explicit
error, including when no rename began. The host retires its active identity and
physical outputs before recovery, then requires CORE/PILS agreement. On
restart, the new OS writer lease settles directory state and validates raw8 before
activation. The native backend uses synchronous bounded metadata operations; it
owns no detached writer whose completion could outlive its fence.

Every NSE START321 belongs to its original physical subscriber. Each estimate
323 uses an immutable `Notification` origin and retained partial cursor. A full
native write alone invokes `notified`; later revisions coalesce behind it. Duplicate START refresh waits behind any original partial output. Rotation and
PILS loss invalidate old logical effects, close CORE output and subscriber MQs,
cancel original PILS operations and retire alarms before committing a new identity. CORE loss retires original peer scopes; no original send is replayed. Canceled
`drive` futures retain all native attempts, partial cursors and original leases. The Host retains its pre-effect yield state across canceled, singly-polled
drives, so overdue proof alarms
cannot starve the native reactor on slower hosts. Foreground composition gives
the explicit shared Resolver one bounded poll per turn, even with a ready host;
Resolver progress cannot skip the host. Permanent closure prevents clock/backend recovery from reviving the owner.

`gnunet-service-nse` is a foreground official-configuration/activation executable
with SIGINT/SIGTERM shutdown and parent-control-byte dispatch. The shared
startup layer captures the original transferred listener/control FDs before
configuration or runtime initialization; control EOF closes only that input and
invents no shutdown signal. The executable resolves NSE `USERNAME` through the
shared startup layer. While its single current-thread runtime is only entered,
it first calls the shared `BoundListeners::prepare_before_identity`: nonempty
activation retains exactly those original listeners; otherwise configured TCP
ports are bound while the old process identity can open privileged ports. No
async task is polled at this stage. New Unix paths are deferred. After leaving
the entered scope, the binary applies the original native primary/fallback
identity sequence; a partial failure exits without retrying or claiming rollback. Only then does it register original parent-control/signals and call
`startup::foreground_prepared`. That entry still verifies real/effective
UID/GID, finishes the new Unix bind under the target identity, then enters the
unchanged proof/CORE/PILS/Host driver. It never reopens or renumbers the original
inherited/prebound TCP sockets or chowns an existing path or parent. Alternate
listener failures remain with the shared owner, and at least one real
successful listener is required before the service can run.

An embedding caller may still use `startup::foreground_with_clock` after applying
its configured account, or use `foreground_prepared_with_clock` with the same
explicit shared listener preparation. Both verify real/effective UID/GID
before proof/native initialization and refuse a mismatch; neither switches a
process identity inside async work. The check makes no saved-ID, capability or
supplementary-group guarantee beyond the shared sequence's report. The
administrator still provisions key/proof/runtime directories and any inherited
Unix listener permissions for the target account. This source change does not
claim a cross-account or privileged-port runtime acceptance experiment.

The foreground reads `UNIX_MATCH_UID` and `UNIX_MATCH_GID` and passes the selected
shared `UnixAccess` into `Host::new_with_access`. UID matching takes priority;
otherwise GID admits the effective primary group or the shared native
membership check. Each original Unix connection is checked against kernel peer
credentials before framing allocation or pure START admission; TCP connections
use the configured address ACL. `Host::admit` also exposes this boundary to
callers owning canonical accepted streams. A denied or failed stream is
physically closed, preserving its peer/error and counters without
resuming an EMFILE-suspended listener or affecting existing subscribers. `Host::new` uses the shared default with no extra Unix credential restriction;
configuration-driven services use `new_with_access`. Configured identity and
credential policy do not grant access to a filesystem path the account cannot
traverse or open. The two admission models cover option/primary-ID decisions
and same-account Unix/TCP denial/capacity/EOF; they do not claim a
cross-account privilege-switch acceptance run. The SDK exposes it through optional `official-nse`, independently of CORE service
hosting. The default SDK remains free of native runtime dependencies.

tests cover raw8 fencing/unknown recovery, native CORE/PILS loopback and
subscriber I/O, default15 discovery from saved progress and default15 signed
frames across explicit absolute-clock round changes, verified identity rotation
with an late new-signer response to an old snapshot, original subscriber
EOF/new connection, and active backend fence loss with explicit recovery. The standalone bounded
miner additionally searched 32509 candidates from zero for the normal
PILS-derived fixture key. Those are separate scopes. Normal C subscription
counterparts run against NSE/CORE/PILS assemblies, with a test-only
TRANSPORT START sink. Remote CAKE, complete mixed peer rounds, multihop and the
complete34-subsystem/8-foundation node still require their own acceptance.

The standard SERVICE entry uses the shared byte-preserving SERVICE option table
`-c/--config`, `-d/--daemonize`, `-h/--help`, `-L/--log`,
`-l/--logfile` and `-v/--version`. Selected logging rules and the owned file
destination actually filter/route entry identity, socket and fatal diagnostics;
NSE additionally forwards its original unadmitted-subscriber cause through a
typed caller diagnostic. Real Rust caller locations are retained without global
fd2 replacement. A diagnostic I/O failure wakes ordinary service shutdown and
remains distinct from the triggering service error. Existing SERVICE default
configuration fallback is retained. The shared clock also drives the actual
service/Resolver.

The standard executable's `-d/--daemonize` uses shared explicit single-fork/setsid
after flushed SERVICE option/logfile selection, before account lookup, runtime
and listener paths. Only the child continues original USERNAME/TCP preparation/
target-identity Unix finish and proof/CORE/PILS work. Original parent-control
ownership and signal dispatch are retained. Parent startup success requires the
NSE Activated/ready callback, never pipe EOF or local listener bind. A
clean stop without activation reports 'S'; startup errors report 'I'; later
ready/identity callbacks cannot signal twice. Generic async entry points never
fork or switch identity.

## Injected original-source STATISTICS publisher

`Host::metrics()` is a read-only copy of its unique pure Service observations. The host has no dependency on gnunet-ipc-unix or gnunet-statistics, directly or
through a statistics type in its API. Its existing shared-I/O boundary remains. `statistics::{Statistics,StatisticsFactory}` are small domain-independent ports
with associated concrete error, owned report and driver types. Startup supplies
its LiveConfiguration, Resolver context, exact RuntimeClock Arc and
initial metrics to that caller-owned factory once. It owns no separate setter,
queue, epoch or statistics protocol model.

The standard executable declares the ten static nonpersistent metrics in
its own `statistics.rs` and injects a shared `Producer<10>` through a thin
factory/driver implementation. It externally owns the IPC Instance for
the entire future. Embeddings which previously had no publisher explicitly use
NoStatistics, whose uninhabited driver cannot fake activity/success. The real
executable never uses that absence path. `[statistics] DISABLE` remains a real
Producer-owned report, not a fabricated None or service-ready receipt.

The original native guard precedes canonical/provider waits. The injected
publisher, CORE/PILS/PoW host and shared Resolver get bounded fair turns. The main passes its existing permanent diagnostic-failure latch without a new
logger/parser. That gate prevents later normal-input/Stats/Resolver polling in
the same turn and enters Host close. Statistics-only failure is retained
without changing NSE history or stopping otherwise healthy peers. Unknown
relative deltas are never replayed to a replacement source.

Normal Host close freezes final metrics for a fixed five-second original
drain. A main/close/diagnostic failure instead clock-free aborts the same
publisher. CORE/PILS retirement and original proof flush retain their existing
mechanisms. `startup::Report<R>` carries original `host` observations and the
injected driver's actual `statistics` report. Typed aggregation keeps main,
Host close, publisher/cleanup, Resolver drain/close/IO/connect errors separate. The same Resolver disconnect occurs after the concrete publisher retires. Nonpersistent unconfirmed writes are not a durability failure. A synchronous
proof OS operation keeps its existing blocking boundary; a statistics deadline
does not pretend to force-cancel it.

Existing shared-I/O guard roots/rules are unchanged.
