# Official caller-driven NAMESTORE client

This crate implements the active v0.29.1 local NAMESTORE client boundary using
shared CLIENT endpoint selection, the caller's canonical RuntimeClock/Resolver,
and retained Framed read/write cursors. It creates no Resolver, background
task, thread, daemon, zone key, signing/encryption context or GNS host. All I/O is
explicitly driven by `poll` / `drive`. Construction reserves bounded metadata and
the original source clock listener without opening a socket.

## General operations

`Client` provides RID-tagged requests and preserves official replies:

- `store` submits a preencoded checked `ipc::RecordSets` batch in one frame.
  Empty records remove a label. `single_tx=true` requests atomicity of only that
  frame. False preserves the provider's sequential-store semantics and possible
  partial updates. An empty batch is sent to the service for its result.
- `store_batch` takes borrowed `ipc::StoreSet` values and admits the largest
  complete-set prefix fitting the one frame and current byte budget. Its `Stored`
  returns the original operation and exact `sets_sent`. The caller explicitly
  handles a remainder; the client neither silently splits a transaction nor
  invents cross-frame atomicity. One bounded zeroizing scratch holds the selected
  batch before encoding its final immutable frame. Call `store` with caller
  prepared storage to avoid that convenience scratch/copy.
- `lookup` sends the original private zone, label and raw16-bit record filter.
  The actual `found`1/0/-1 and records stay in the returned checked response.
  A miss is separate from source loss, timeout or backend failure.
- `zone_to_name` sends an typed public target zone. It accepts the real
  header-only no-results response (code5010) with no echoed zone key, and never
  fabricates a key or successful result to work around the C consumer assertion.
- `edit_begin` invokes the actual1750 editor-hint operation and returns the1751
  reply, previous optional hint,16-bit code and records. `edit_cancel` sends the
  actual1752 conditional hint-replacement RPC and receives Generic code32. It is
  distinct from `cancel`, which only suppresses a local callback.

No active message number, handler or public function supplies standalone
TX_CONTROL BEGIN/COMMIT/ROLLBACK. Dormant C structs and enum comments do not create
such an RPC. This crate implements the STORE `single_tx` field instead.

Every response matches the original RID, kind, physical epoch and complete
request write. Returned zone keys are compared to the original opaque zone key
where one was specified. All-zone streams accept checked typed returned keys. Record counts, labels and hints have explicit bounds. Raw response/error
codes are retained; code0 does not independently prove disk fsync, monitor
consumption, publication or a GNS naming/authentication result. The service owns
name normalization, record filtering/nick/tombstone policy and database effects.

## Independent credited iterator and monitor

`ZoneIterator::new` owns a dedicated MQ, matching the official public
iterator's exclusive-handle contract. It sends START and initially grants one
record only after that exact frame's whole local write. `next(limit, until)` is
accepted after START wrote, under explicit credit/control bounds. It creates one
immutable original NEXT; added credit becomes effective only after that control's
whole write. Queue admission/partial writes grant no credit. Each Records
response consumes one; End consumes none.

Natural completion is the RID-tagged END response. `stop` sends the actual
STOP command when the original was exposed. A wholly unwritten START can instead
be removed and the source stopped. A pending NEXT returns WouldBlock: drive the
original suffix first, or independently close the source. Once STOP is wholly
written, the source physically closes and a local canceled outcome is reported. STOP has no server acknowledgement and is never promoted to a natural END. The pending control's original exposure remains available in close/loss reports.

`Monitor::new` owns a dedicated original MQ because MONITOR_NEXT has no RID. `iterate_first` and the filter are sent in the START. The initial credit
is one. Actual MONITOR_SYNC marks that original snapshot synchronized, consumes
no record credit, and is distinct from initial/live Records. `next` uses the
no-RID MONITOR_NEXT frame and the same whole-write credit rule. `stop`
physically stops that MQ without sampling a clock; there is no monitor STOP or
RPC-CANCEL frame. A lost/closed monitor immediately ceases to be synchronized.

Streams do not resume/replay a lost cursor. Construct a fresh explicit owner for
a fresh enumeration/snapshot; old progress/keys never authenticate that new MQ. A monitor can receive empty records for deletions. The native client does
not require a synthetic negative record or END for live monitoring.

## Sensitive ownership and resource policy

Zone inputs are borrowed `gnunet_identity::SecretKey` owners: zeroizing, no
ordinary Clone/Hash/Serialize and redacted Debug. An explicit fixed-size secret
copy is retained only while the original request/stream needs to check its zone. All queued sources, partial read/write frames, batch scratch and returned replies
use zeroizing storage. `Reply` owns the one exact response copy; `view`
explicitly borrows the checked wire response with opaque SecretKeyView and Records
wrappers. Reply Debug exposes only byte length and `[REDACTED]`, not keys, labels,
record values or editor hints. Returned replies are caller-owned and wipe when
dropped. No private material is put in JSON, logs, a RID or a key hash by default.

Default limits are32 general operation/completion rows,256KiB total outbound
pending/physical bytes,65535-byte complete frames, one physical output frame,
512 sets per STORE frame,4096 records per individual set,255-byte labels,
4096-byte hints,256 outstanding stream records and5s partial-drain grace. Dedicated streams allocate one operation row plus one optional small NEXT/STOP
control. Large payload buffers are allocated on admission, not per peer or
per operation slot. Returned response copies are fallible and bounded by one RX
frame. All capacity refusals are explicit; permanent bad input stops its source
rather than parking a head frame or fabricating an empty result.

A stable caller-owned Instance supplies checked unique local allocation IDs for
owners, epochs, requests and controls. None enter wire. Official general RIDs are
BE32 and never reused within a Client, even after replacing its MQ. Exhaustion
refuses new work instead of wrapping. Actual queued, positive Activity, whole
Written, ControlWritten and service Completed events are separate observations.

Each request/stream has an original finite absolute deadline in the canonical
clock and an original native-time bound. Canceling a drive future preserves
original cursors and accounting. The optional Tokio wait is observation-only. Wholly unwritten originals may be removed; partial originals keep their exact
suffix under `min(native-now, original-hard)+grace`. A late poll or repeated
cancel never renews that bound. Fully written locally canceled/timed-out requests
retire locally and their never-reused late RID replies are ignored. Source loss
never replays unknown writes, advisory lock operations, lookups or iterators. General reconnect can create a new empty source after old completions drain.

A source clock refusal during public admission immediately stops the old physical
owner before returning the error, preserving one bounded original loss record
for polling. Clock/Resolver port recovery is explicit. Close/Drop stop the native
owner without reading a clock. Existing partial control exposure and the known
original failure are retained; no independent kernel-close errno/remote rollback
receipt is invented where shared CLIENT exposes none. Closing/canceling an edit
callback does not prove its advisory hint was undone. Use the EditCancel RPC
for the desired conditional replacement and observe its result.

## Pinned C interoperability facts

The C service's no-results ZoneToName frame omits the key, and an EditBegin reply
can omit its previous hint. These are accepted without copying the C consumer's
assertion/validation defects. The pinned C EditCancel checker mistakenly reads
the replacement length from the old hint field, so it may reject a correct frame
when the two lengths differ. Its nonzero Generic error code is also assigned
using htons into32 bits. The client sends correct declared fields without secret
padding/truncation workarounds and retains the raw response value; these
upstream defects do not become invented Rust protocol success or compatibility
messages. Current/replacement hints are explicit valid C strings, including an
empty replacement. No null pointer/unterminated replacement UB is copied.

## Checks

The one controlled Unix model
source uses an explicitly published synthetic mock encoding and empty records;
it performs no generation, derivation, signing, hashing, encryption or decryption. It covers all active general commands, keyless misses, optional previous
hint, partial cancellation/late RID, unknown mutating-write loss/no replay,
whole-write NEXT credit, STOP distinct from natural END, and monitor SYNC/live
credit/source close. It is not C-process/key/crypto or full-GNUnet evidence. The original stopped GNS host/recovery, DHT and UDP communicator branches are not
used, inspected or restored by this client boundary.

`Client::poll_native_guard` checks/arms original native operation/control/drain
bounds before an enclosing canonical-clock wait. It performs no socket IO,
logical sampling, decoding or cryptographic work. It can return prior admission
loss, an already settled completion or a native expiry result; local Unsent and
Unknown outcomes remain distinct from service results. Ordinary poll shares the
same logic, and its pinned native timer is reused when only the wake target
changes. Dedicated ZoneIterator/Monitor expose the same guard as a Result<Option<Progress>> and use the normal terminal settlement: physical source close and close-report retention precede terminal delivery. No cursor is reconnected or replayed.
