# Native PEERSTORE client

`Client::new` reserves one caller-driven shared CLIENT MQ for official STORE and
request-ID iterators. `Client::new_monitor` explicitly reserves a separate MQ
for one monitor, because MONITOR_NEXT has no request ID. Each owner exclusively
borrows a non-ZST `Instance`. `Operation`, `Epoch` and `WriteId` carry its actual
brand and checked serials; callers cannot reconstruct them from diagnostic
integers. The only encoded request identifier is the official u32 RID. It is
never reused in this owner's lifetime, including cancellation and reconnection;
exhaustion is explicit. No service, persistence backend, global counter, hidden
Resolver, worker or task is created. The older TRANSPORT-specific PEERSTORE
server remains a separate subset and is not used as this general client.

The API accepts borrowed official `Record` and `Filter` values. Subsystem is
required; STORE also requires a key. An empty C string remains distinct from an
absent optional selector. Options1 means replace; other raw STORE option values
retain reference multiple semantics. Opaque value bytes, claimed record peers
and expiry are not authenticated by PEERSTORE. Returned `Observation` owns the
exact original RECORD frame and records its original MQ, operation and actual
iteration/initial-monitor/live phase; structural decoding adds no peer proof.

Every operation requires a finite original absolute UTC deadline, independently
of a stored record's cache expiry. Original request bytes remain bounded
by `source_bytes`; the shared physical FIFO has independent retained frame/byte
bounds. Slots contain small metadata and actual-length frame allocations,
rather than one maximum-size array per operation. STORE source bytes are erased
and released after the original full request write. Filter/source bytes for an
iterator or monitor remain immutable until retirement. One earliest source
`Deadline` registers one independent change listener alongside the shared
CLIENT's listener. There is no per-operation timer task or implicit thread. Clock rollback rechecks the original absolute target; source/timer refusal
physically closes the MQ before local settlement and exposes the error. `recover_ports` is explicit and reconstructs no prior STORE or iterator.

Only a matching STORE_RESULT from the original MQ produces
`Outcome::StoreResult(i32)`; GNUNET_OK is1, SYSERR is-1, and all signed values are
preserved. A local full write is a `Written` observation. It grants no save,
backend commit or application ACK. MQ loss terminates every original STORE as
local `Unsent` or `Unknown`, closes physical IO first, and never replays it. Iterators are likewise interrupted rather than silently restarting a snapshot. Caller-owned cached observations remain readable after retirement but confer no
old operation/epoch authority over a replacement MQ.

An iterator starts with credit1 only after its START fully writes. Each
RECORD consumes one unit; another round requires exhausted current
credit and at most one pending NEXT. A grant is clamped to256 as in the service
and becomes local credit only when its original whole frame writes. An actual
ITERATE_END preserves its signed result. An END racing a queued NEXT removes
only wholly unwritten originals; a partial suffix retains its original
debt slot until full drain or finite physical retirement.

A monitor also starts with credit1. Initial records precede MONITOR_SYNC;
SYNC consumes no credit. When initial enumeration consumes exactly its credit,
NEXT is required before the service can discover its empty end and send SYNC. Live updates consume monitor credit; events skipped by the service at
zero credit are not replayed or invented by this client. MONITOR_NEXT adds a
clamped increment; a zero monitor increment remains a wire no-op. A physical
monitor loss exposes `Lost`, closes the original MQ, and may restore its retained
read-only intent on a new epoch, with fresh credit1 and a new SYNC phase. The original deadline never resets. This explicitly permits re-enumeration or
live gaps; it makes no uninterrupted or exactly-once stream claim.

`cancel` removes exact wholly unwritten originals. STORE requests with any
exposure terminate locally as Unknown. An iterator's partial original request
or NEXT remains immutable, then the exact ITERATE_STOP drains on that same MQ. `StopSubmitted` means the original STOP fully wrote; there is no STOP ACK. A
monitor has no stop message, so cancellation physically closes its dedicated
MQ. A finite original drain-grace bound closes a stalled original MQ before
terminating debt; unrelated pending requests on that MQ receive their own
local outcomes. New peer/MQ slots cannot silently assume old debt. Closing the client releases connections and clock/deadline listeners;
retained terminal observations remain drainable through `next_event`/`drive`.

`drive(Some(native_target))` registers that caller's original observation alarm
even while shared CLIENT clock stabilization returns Pending. It reuses the
same Channel's one native wait alarm; no second timer or task is created. `WaitDeadline` only ends this borrow's wait, without canceling, closing,
re-admitting or renewing the underlying operation. Already retained completions,
Closed and port/clock failures keep their existing earlier priority. The record's expiry and operation's absolute UTC deadline remain separate.

The one native model uses Unix streams with a clearly controlled IPC
actor. It emits a STORE failure-1 and a second request's unanswered MQ
loss; it does not fabricate saved/durable success. It checks no STORE replay,
iterator credit/clamping/STOP and two monitor epochs with initial/SYNC/
live credit and physical cancellation. The model is not a backend or C
counterpart profile and does not certify the new service/WAL or whole node. Production code relies only on the fixed official codec; it never constructs a
service response. See the package handoff for its exact codec dependency.
