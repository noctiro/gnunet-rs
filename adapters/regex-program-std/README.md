# REGEX standard SERVICE frontend

`gnunet-regex-program-host` joins the REGEX IPC server/distributed Core,
PILS purpose-18 signer, one shared Resolver, the caller's DHT provider and
an independent bounded official STATISTICS publisher. It is a production library
entry for a native caller implementing `Factory`. `NativeFactory` supplies the
bounded DHT client/reader, and `gnunet-service-regex` is the standard
installed entry. No successful dummy backend is supplied.

Node-wide `[PILS] PROFILE` is selected once by normal `Settings` and passed to
the purpose-18 PILS signer. It defaults to `reference029` (alias
`reference-0.29.1`); `deterministic`/`reference-deterministic` selects the official
conditional address-derived profile. Explicit `lsd0014-text` remains the separate
published textual interpretation and grants no official C compatibility claim. Unknown selections fail before factory/native admission; verification never
tries another mode after failure. Existing identity-generation and original
signing-job retirement contracts continue to apply.

The process entry is `unsafe fn run<F: Factory>()`; the ordinary binary selects
`NativeFactory`. Its documented contract
requires the first initialization in a fresh single-threaded exec. It first
adopts the original activation/parent-control descriptors, then selects official
SERVICE `-c/-d/-h/-L/-l/-v` options and the Logger. Optional daemon detach
uses the admitted shared explicit fork/setsid/status-pipe implementation, before
runtime/tasks, account lookup, new listeners or a constructed Factory provider. The original parent releases activation/control ownership and waits on the real
child status pipe. EOF/failure is not readiness. The child refreshes the Logger's
PID without reopening the selected log file.

New TCP listeners are prepared before applying configured `[regex] USERNAME`. New Unix endpoints are finished under that target account. The same
`UNIX_MATCH_UID` / `UNIX_MATCH_GID` booleans control new filesystem paths and the
server's original kernel credential checks; absent values are false. Existing
parents/inherited endpoints are not changed. The official REGEX service's
`OPTION_NONE` maps to immediate physical IPC shutdown. Shared service parsing
continues to provide TCP ACL and TOLERANT configuration.

Only after runtime/account/listeners and the shared Resolver exist does
`Factory::storage` allocate caller-owned storage and `Factory::create` construct
the provider. `Context` supplies the original live configuration,
configured DHT endpoint, shared resolution context, exact clock Arc and first
startup native deadline. GAT provider lifetimes permit borrowing stable external
storage without a self-reference, leaked box or hidden task. The provider must
keep original uncertain operations and its native/worker cleanup debts until
retirement. Constructor error must not leave detached work.

Ready is sent once only after the Driver has progressed and current
PILS identity, its same canonical clock sample and `Factory::ready` for the
original owned provider all succeed. This is initial local service readiness;
it is not a DHT PUT acknowledgement or remote availability guarantee. No source
or retained-job token is replaced during a wait. Missing PILS/DHT readiness keeps
startup pending until an signal/control stop or its original fixed hard.

The main current-thread loop polls native guards, Driver, statistics and
Resolver fairly, retaining their owners across pending/canceled wait
futures. It yields at least every64 local ready turns. Original native job bounds
are owned by the admitted Driver/provider; the reactor quantum only
observes them. Original parent-control bytes and SIGINT/SIGTERM stop the service. A selected-Logger error causes the same normal stop path; severity-specific
cache site IDs prevent DEBUG admission from suppressing later WARNING records.

Normal stop calls the original Driver.stop and polls the same Driver until
`Progress::Closed`, then freezes the final Core metrics and drains the
same statistics publisher, then disconnects the shared Resolver. Driver
construction failure returns its parts through `ConstructionFailure` and
performs independent cleanup without losing Provider ownership. Cleanup and
source failures remain independent in `Errors` / `LifecycleFailure`; no
cancellation request, Drop, write progress or timeout is called quiescence.

A STATISTICS failure fences/physically retires only that diagnostic publisher;
healthy REGEX work continues, the first error/report is retained, and an
unknown relative mutation is not replayed. A fatal Driver/Resolver failure uses
its explicit clock-free statistics abort. Local whole writes, DestroyReport and
remote processing are separate facts. An unconfirmed/Discarded destroy result
alone is not a reason to replay counters or fail successful business operations.

The configuration below adds finite Rust resource policies to the standard
`[regex]` listener section. All times are standard GNUnet relative-time values,
positive and at most24h. `REACTOR_QUANTUM` is at most1s. The retained/compiler
limits are enforced by the Core; native output/input caps by the server.

| Key | Default |
|---|---|
| MAX_CLIENTS / MAX_JOBS / MAX_BRANCHES | 32 / 1024 / 128 |
| MAX_RESULTS / MAX_SEEN_RESULTS | 128 / 4096 |
| MAX_INPUT_BYTES / IO_SLICE_BYTES | 4096 / 65535 |
| RETAINED_BYTES / ANNOUNCEMENT_BYTES | 32MiB / 4MiB |
| FIRST_INPUT_TIMEOUT / PARTIAL_INPUT_TIMEOUT | 15s / 15s |
| OUTPUT_TIMEOUT / SIGNATURE_TIMEOUT | 30s / 300s |
| STARTUP_TIMEOUT | 300s |
| STATISTICS_TIMEOUT / STATISTICS_SHUTDOWN_GRACE | 5s / 5s |
| REACTOR_QUANTUM | 50ms |
| RETIREMENT_NOTICE_DELAY | 5s |

`RETIREMENT_NOTICE_DELAY` is a fixed one-shot diagnostic threshold. It never
releases unresolved Provider/worker debt and never promises to interrupt a
blocking OS call. This stage deliberately has no fake forced-completion path. Synchronous account/configuration/stdio/Factory construction and underlying
blocking OS/worker boundaries retain their duration and errors.

The ordinary native Factory derives metadata/byte/path capacities from the
Core/Driver configuration and finite native phase bounds from existing
OUTPUT_TIMEOUT/PARTIAL_INPUT_TIMEOUT. Initial startup keeps its original fixed
STARTUP_TIMEOUT; an attached local DHT MQ supplies local readiness only, never
remote replication, lookup completion or publication acknowledgement.

Core retirement and provider bookkeeping release are distinct steps. `release`
returns false while unconsumed observations remain, and errors preserve the
metadata. The Driver records successful release before delivering the exact Core
retirement, preventing another provider release after a later pure failure. Actual terminal PUT/source observations are consumed once and remain typed. A
bounded Driver acknowledgment slot retains a successful Core mutation and its
original operation until exact Provider consumption succeeds; it retries no Core
mutation and does not wait for another canonical sample.

Historical interface-only compiler receipts keep their original scopes. Actual
native SERVICE/key/crypto/network/worker and official interoperability acceptance
remain unverified for the new production binding and ordinary binary.
