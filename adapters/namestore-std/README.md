# Actual NAMESTORE SERVICE adapter

`gnunet-namestore-host` is a Unix caller-driven SERVICE owner for the active
v0.29.1 protocol. It composes the pure NAMESTORE Core/streams with shared
SERVICE accepted connections, ACL/credentials, canonical clock and retained
Framed I/O. It borrows one separately and explicitly started
`gnunet_snapshot_host::worker::Worker`. It creates no Resolver, thread/task,
identity runtime, key generator, cryptographic operation or GNS host.

`Server::recover(&mut Store, Loaded, coreLimits, criticalFn)` checks the actual
`Namespace::Namestore` and matching original physical generation before reading
its qualified body. A newly created generation0 namespace is initialized under
that same held lease with a real 12-byte `GNMCORE1`/zero-count canonical image. The synchronous initialization transaction completes before recover returns,
worker startup, socket business or READY; normal cancellation cannot split it
at an await. Its committed generation is1, without a client transaction,
monitor event or business-commit count. Existing marked generation0/missing
canonical state is refused. A committed zero-length body is also refused;
a normal committed empty authority has the valid 12-byte format. Actual commit
errors retain the original Storage failure Arc, exposure and error source chain. No silent reset or legacy state import is attempted. `Server::new(core, &mut Worker, generation, Limits, Ports)` also checks the
worker namespace. Accepted sources get checked original Client identities,
finite deadlines and their own retained cursors. Constructor/admission allocation
is fallible; canonical ACL/Unix credential checks precede private frame allocation.

## commands and original persistence

The service handles STORE batches and single_tx, filtered Lookup,
ZoneToName, credited iterator START/NEXT/STOP, monitor START/NEXT/SYNC and1750–1752
editor-hint operations. Empty records remove labels through Core policy; empty
STORE is a no-op decision. With single_tx false, a failing later set can
leave a prepared successful prefix: that prefix is durably committed through the
same worker before the returned error code is sent. No standalone
TX_CONTROL message or fabricated rollback is introduced.

A mutation's immutable after-image is encoded into one zeroizing raw body and
admitted to the one bounded worker. Only that admission calls Core.queued. Core Transaction, Zone, Snapshot, Query and Change remain on the caller's thread;
none of their Rc brands cross the worker channel. Only an owned erased body,
expected physical generation and the private native job are sent. The original
private Completion must match that exact job/namespace and expected committed
generation before Core.commit and the prepared result are released. Actual
prepublication failure uses abort; Unknown fences Core reads/mutations,
stops MQs, and requires external marked-store recovery. A client close never
cancels, replays or pretends to settle its already admitted disk mutation.

Socket polling performs only bounded CPU preparation and nonblocking worker
admission. Business filesystem writes/rename/fsync run on that explicit single
worker. The one fresh empty-canonical initialization is synchronous startup
storage under the original Store lease, before any worker/socket polling. There is no per-client thread, blocking fsync in a socket poll, C backend wrapper
or automatic import of a C database. The backend/worker are re-exported from the
shared snapshot package, not copied or imported from IDENTITY runtime.

Lookup and reverse replies use owned Query results and represent real
misses. A completed reverse lookup with no matching delegation returns the public
API's NO_RESULTS code and echoes the request's supplied opaque zone key. The
official C client reads that field before routing NO_RESULTS to its normal empty
result callback. Actual errors remain errors, including raw peer ZONE_NOT_FOUND
responses. Rust still accepts the reference service's keyless error frames
without copying its C reader assertion defect. Editor begin returns the
optional previous hint. Conditional editor replacement is a distinct
state-changing command; MQ close does not promise advisory unlock. Private keys,
records and hints are encoded into erased frames without automatic Debug/JSON. The built-in `critical_type` predicate matches the pinned GNS plugin's four
critical types; DNS returns false and other active built-ins provide no callback. No C plugin is loaded. Embedders inject their extended registry predicate.

## Real stream queues and slow monitors

Each source has a bounded iterator table (default one, matching the public C
exclusive iterator handle) plus an independent monitor slot. The pure
stream captures its Core snapshot and source domain. It produces immutable
Record/End/Sync descriptions; native code preflights, encodes one erased frame,
actually enqueues it, and only then calls queued on the same original Write. Only positive original native writes call exposed; only that frame's complete
native write calls written. Raw RID, private stream generation, source Client,
native frame serial and pure Write remain distinct. A reused iterator slot cannot
receive an old output callback. A stopped stream retains its already admitted
suffix until write or source retirement; STOP invents no End/ack.

Monitor NEXT credit is granted from an complete admitted input, not from
an invented ACK. Record results consume credit; SYNC and invisible revisions do
not. Every committed revision, including hint-only empty changes, is
offered exactly once. A monitor opened after a commit has that state in its
initial snapshot and is not rebound to an older Change.

One original notification debt is retained globally. Further mutations wait in
their original bounded RX frames until that debt releases. For record-producing
Store commits, its result waits until every original live target monitor's
queued_revision covers the complete selected batch, or that exact physical source
retires. Actual local queue admission is not consumer processing. No committed
change is silently dropped. Hint-only revisions are offered but need not wait
for record processing. Per-monitor pure backlogs and Core retained memory remain
bounded. A slow monitor is physically retired at the first notification/output
deadline; this releases the source obligation instead of faking its credit. Capacity-refused offers are retried after peer state advances; watermark
waits sleep on IO/timers rather than busy rescanning.

Sources keep bounded FIFO business replies. Queue overflow, permanent oversize,
malformed data, stale references and expired first-input/output lifetimes close
the original MQ. Temporary capacity retains the input/cursor under its
first finite lifetime while other sources, flow-control input, worker results
and stream writes keep progressing. There is no unbounded diagnostic/job queue.

## Resource and close boundaries

Defaults:32 MQ sources,8 pending reply items per source, one physical output frame
with65535-byte budget, one iterator plus one monitor slot,8 committed pure monitor
changes,16 scanned rows per pure turn,65535-byte RX frames,8MiB maximum private
snapshot body,30s first-input/input/output/storage lifetimes. Large payloads are
allocated only for requests/outputs/snapshots, not per empty iterator or
peer. Core defaults additionally bound labels/zones, record sets and aggregate
current/staged/history/query memory. The foreground exposes explicit overrides.

`close`, `close_all`, Drop and shutdown independently retire native MQs without
reading the clock before each pure stream's source_lost receipt. Original debt
flags are reported after physical retirement. A fatal clock/storage cause closes
all MQs before returning. Shutdown stops admission, consumes every original disk
result, then joins the worker. A socket grace does not bound or cancel an
OS fsync/rename; the worker is joined rather than detached. Namespace/job checks
are not promoted to durability by themselves; only the original physical worker
receipt permits commit. No late result is sent to a replacement Client allocation.

## Checks

One controlled IPC/worker/
restart model source uses only published structural mock bytes and public A
record values, with no key generation, signing, encryption or decryption. This model is intentionally ignored and compile-only under the current execution
boundary: although helpers do not peek files, the production path would send
mock zone bytes through snapshot encoding, integrity hashing, file publication
and recovery. It must not be run as an indirect key/storage test or counted as a
passed runtime model. This is not private-key or C interoperability evidence and does not
restore any stopped GNS host/recovery, DHT or UDP communicator implementation.

No storage, recovery, official C interoperability
or whole-service qualification is claimed by those compile checks.
