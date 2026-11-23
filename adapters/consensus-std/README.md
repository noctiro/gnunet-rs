# Native CONSENSUS bridge

This adapter connects a caller-driven CONSENSUS session to the generic SET SDK
and normal service IPC. It owns the original Session, SET Factory, Listener,
source populations, preparations and operation tokens. The foreground service
owns configuration, Resolver, process control and PILS. No background task is
spawned. The [core](../../crates/gnunet-consensus/README.md) defines wire,
grading and application-value contracts.

## Identity and configuration

The configured PILS client must retain the original verified identity's epoch
and peer before every normal bridge turn. A same-source, same-peer metadata
refresh is allowed within the original bounds; source replacement or identity
change cancels that session. Metadata-only HELLO coverage grants no address or
dial authority. Official C CONSENSUS instead derives identity from its configured
`PEER/PRIVATE_KEY`; Rust's identity provider is an internal implementation choice.

`Sources::new` takes one coherent configuration snapshot and selects explicit
fixed endpoints. Later copies share selected `Arc` payloads. The shared clock,
Resolver and temporary native paths retain separate owners. An endpoint snapshot
does not identify a remote daemon restart generation.

## SET operations and task results

`PrepareSet` creates an empty UNION source and streams its immutable population,
waiting for each ADD whole-write. Core `Written` follows CREATE and all original
ADD writes. No second complete encoded population is retained.

`Reconcile` binds the original TaskId, SetId, OfferId and deadline to the SDK
prepare/accept/commit owners. `OperationBound` reports the actual native operation
and epoch; `OperationWritten` activates the core task. ADD_LOCAL, ADD_REMOTE and
matching DONE/FAILURE drive results. HALF_DONE does not terminate a task. Union,
inventory and leader membership changes remain task-bound until DONE. Incoming
and outgoing reconciliation use the same
[SET options](../../crates/gnunet-consensus/README.md#effects-and-retirement).
Every native event and loss receipt remains observable.

Future incoming contexts retain an offline original preparation. Options may be
set before its first successful commit. Invalid or unclaimed offers are rejected
through their exact factory domain, listener epoch and accept id. Queue admission
retains the rejection token until that listener's whole REJECT write or physical
closure. A committed preparation belongs to its original SET operation and
cannot become a new rejection. Dropping a preparation is not a peer receipt.

The [listener owner](src/bridge/listener.rs) keeps native write observations
separate from core cleanup. Only a whole rejection write matching both the
original epoch and accept id retires that offer; a partial write retains it.
The resulting core terminal is `Retired`, while the native `Written` event
remains independently observable. Other offers and the listener remain usable.

## Failures, bounds and retirement

Each source uses its original effect deadline clamped to unchanged outer bounds.
IO gates are checked again after pure deadline or cancellation progress. A phase
expiry stops new IO and requires actual retirement of published populations.
Never-published core snapshots have no native close obligation.

The bridge reserves its population ledger before fallible native admission.
A proven never-created source settles Unsent and retains its logical CloseSet
obligation. Refusal after creation physically retires that owner and preserves
its native loss separately from the business cause. `SourceRefused` reports the
bounded original diagnostic without turning a source refusal into a global fault.

Transport loss, source protocol failure and invalid mode/terminal results retire
the identified source and all its unfinished tasks. Pending effects retain their
actual Written, Unsent or Lost disposition. Completed tasks keep their matching
DONE results; failed sources cannot be recreated under the same core capability.
Other leader sources may advance within their original bounds. Shared clock,
selector, listener, PILS and ownership failures fence the whole session.

The core source-retirement metadata pass is bounded by task limits; subsequent
native loss work visits at most one task row per turn. Source polling rotates
fairly, visits at most32 sources per turn and parks after a complete blocked
pass. Ready events and local queue admissions renew polling debt, including
CREATE queued by Attached and writes queued on already-visited sources.

Cancellation intent is captured from the SDK receipt. Deadlines, EOF and local
queue admission do not manufacture remote DONE, successful writes or retirement
receipts. Original first causes and partial-write exposure remain in the report.

## Service IPC and completion

The SERVICE layer uses accepted credentials, framed IPC and locally pinned
futures. Each client owns its PILS and core domains, SET Factory and Bridge.
It consumes JOIN520 before INSERT521/CONCLUDE524 and emits standard523/525 frames.
PILS is polled first; identity and output gates are checked before new syscalls.

`ClientFrame` retains its EffectId until the IPC owner supplies the actual whole
Written, Unsent or Lost disposition. `CloseClient` waits for physical retirement.
A known whole525 write is settled before classifying later client EOF. The
original listener, offers and SET sources retire before public completion. The
shared global-id lease remains held through dependency retirement. Overlapping
joins fail that client; sequential reuse introduces no private nonce or ACK.

Shutdown first marks every owner and closes original IPC, SET, listener and PILS
objects without requiring a clock sample. A separate bounded pass drains pure
bookkeeping within the original retirement grace. `physical_closed` and
quiescence are independent. Incomplete cleanup remains undrained; diagnostics
retain bounded first-cause/count summaries and exposed operation receipts.

## Resource limits and qualification

`ServerLimits` separates client counts, bridge limits, aggregate session
reservations, frame/slice limits, first/partial/whole lifetimes, retirement grace
and identity profile bounds. Server, registry and endpoint capacity is deducted
before session permits. Native and canonical admission origins precede fallible
ACL work. READY means IPC admission, not remote service or participant readiness.
Allocation limits do not claim measured resident memory or throughput.

The normal service accepts opaque application labels explicitly; it does not
reinterpret them as BLOCK plugin types. Applications can supply an independent
`Validator`. DHT BLOCK registration remains a separate boundary.

Current-source mixed-C grading, full-transfer, identity and same-global reuse
qualification remains in [implementation status](../../IMPLEMENTATION_STATUS.md).
