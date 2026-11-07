# Official REGEX IPC server host

`Server::new(core, Limits, Ports { clock, options, unix })` owns the supplied
actual `gnunet-regex-service` Core and kernel Unix/TCP MQs. It starts no DHT,
PILS, resolver, worker, thread or detached task. The coordinator supplies real
PILS signing and the caller-owned native DHT provider described below.

The pinned production service allows one ANNOUNCE and one SEARCH simultaneously
on a connection, with duplicate same-kind requests closing that original source. The Core owns this rule. Host uses official wire codecs, preserving SEARCH C
prefix semantics and refusing malformed known frames. There is no wire RID,
CANCEL, publication ACK or search END/DONE. TOLERANT consumes only unknown message
types without granting an input admission or renewing the first-input deadline.

accept applies the TCP ACL or original kernel Unix UID/GID policy. Unix
socket/parent filesystem permissions belong to the caller's listener startup
and must use the same matching flags. Unadmitted failures close their own original
stream and retain errors. Physical Core-client rows remain reserved while
backend/output retirement debt exists, preventing source/token reuse.

Each accepted MQ allocates one bounded RX arena. One shared encode arena serves
all clients. Each MQ retains at most one original result frame/output coordinate;
slow writes backpressure Core results until their original native deadline closes
that source. Limits default to32 clients,65535-byte frames, one frame/output per
client,15s first/partial input and30s original output lifetime. Live subscribed
searches/announcements do not acquire an invented idle lifetime or fake DONE.

`sample_times()` is the sole native epoch plus original canonical clock source
for Core/coordinator actions. `clock()` clones that same original Arc. The actual
clock subscription and native timers are caller-polled. First/partial/output
hard bounds are stored once, checked before native polls/admission and
never renewed by a canceled drive, queue attempt or retry. `poll_native_guard`
can close expired original sources without sampling canonical time; no pending
clock waiter masks those original physical deadlines.

`core()`/`core_mut()` expose the same distributed Core for original work. The backend must retain leased work data or its owned copy, not drop a borrowed
lease and pretend submission. Only matching original backend results retire jobs. `poll`/`drive` perform bounded fair kernel accept/read/write and Core input/output
transitions. Dropping a drive future retains all fields/cursors/deadlines.

Only positive write progress marks the original Core output exposed; only
whole original frame progress calls written. Public write/close observations keep
those byte facts even if later Core cleanup fails. Internal Copy write
serials map to the original non-Copy branded Core output and have no wire or
success authority. No callback may reenter the borrowed server.

`close_client`, `close_all`, and `reap` require no clock. Actual Framed retirement
precedes Core.disconnect, then original queued/exposed output abortion; unqueued
Ready results are cleared by Core.disconnect. Original sign/DHT retire jobs stay
in Core until the external provider confirms retirement. `PhysicalStopped`
means only all Host MQs closed. `Stopped`/`is_drained` additionally require every
Host client released and Core.quiescent, under that provider receipt contract. The caller must keep driving its original backend before dropping the allocation. Drop force-closes MQ owners; it cannot certify remote cancellation or quiescence.

The actual `driver::Driver` joins this same Server, an owned
`pils::Signer` and an explicitly supplied DHT `Provider`. The signer uses
one existing native PILS client, an exact original identity target and the
original eighty-byte purpose18 material. It retains the result until
its original copied frame is quiescent. Signature cancellation drains or closes
that same original MQ. The default300s signing bound has its own single native
Sleep anchored at original submission; silent peers cannot hide it behind an
indefinite outer wait. Native guard scans allocate no per-poll workspace.

The coordinator reserves a finite original-operation table (default1024), keeps
Core JobIds through DHT submission/results/retirement, compares all three
clock Arcs, and rotates host/PILS/DHT progress fairly. Single-slot signing
backpressure does not lease another signature or block retirement work. Each64
turns yield before new effects, including refresh0. Fatal errors latch before
returning, so uncertain event-consumption failure cannot replay a committed core
mutation. A single acknowledgment slot keeps the already committed pure result
and original operation until Provider.consume succeeds; an error retains the exact
provider event, and shutdown retries only its acknowledgment. No new canonical
sample is needed to acknowledge that existing fact. Stop/drain retains the same
original owners and independent errors; physical host close, signer close and
provider retirement remain distinct.

`dht::Native` implements the explicit Provider contract with one existing
DHT client/reader and stable caller-owned Instance. The standard SERVICE frontend
and official STATISTICS publisher live in `adapters/regex-program-std`;
its production `NativeFactory` is installed by `gnunet-service-regex`.

Persistent GETs keep their original JobId/GetId across readonly MQ replacement. GET registration/STOP, queued PUT, source connection and partial-input phases
have fixed native bounds; those bounds never invent a full-search TTL. A new
physical GET registration gets a new phase bound only after the preceding
registration genuinely completed. An unfinished original phase is not renewed. PUT bodies waiting for an epoch retain their original data, expiry and
native target; admitted or uncertain PUTs are never reconstructed/replayed.

local whole PUT writing is reported independently, including when its
Core target was already retiring. Source/connect/guard failures remain separate
observations; safe readonly queries retain their logical identity. A complete
received frame is retained until consume, with exact ordered predecessor
arrays and separately bounded path storage; the Core still validates the block. Quiescence/metadata release cannot erase a held reply, failure or terminal fact. Idle shutdown also physically retires a connection attempt with no epoch. The
source is closed only after its events/cursors/debts have settled.

`Driver::try_new` returns `ConstructionFailure` with the same original
Server/Signer/Provider on validation or allocation failure. It does not discard
an already-created provider or hide its native/worker debts in Drop. Readonly
peer/provider/metrics views support foreground readiness and diagnostics;
they create no work or success receipt. Diagnostic PUT counters advance only
after original provider admission and never control business progress.

The native source/standalone composition requires its own affected compiler and
runtime qualification. Historical interface-only compiler receipts keep their
original source scope; no new native, crypto, service or official interoperability
execution is implied by these source paths.
