# Native generic SET caller

`gnunet-set-client-host` drives the active GNUnet v0.29.1 `set` endpoint. It uses
its generic SET codec and the existing shared CLIENT/Framed transport. It does not route through SETI/SETU, spawn a service, create a Resolver worker,
or invent acknowledgements. Drive owners from an entered Tokio runtime with
IO/time enabled; the caller also drives its explicitly selected Resolver.

## Source ownership

Create `Factory` from a configured `EndpointSource`. It fallibly freezes that
selector's configuration once and retains the same clock and Resolver. Related
Set, Listener and copy MQs share a local factory-domain token. Accept/copy also
retain their original source epoch. This prevents explicit cross-factory or
already-retired-source ID reuse. It does not authenticate a remote daemon or
prove that DNS changes, path replacement or a service restart preserve the same
remote generation; this protocol has no such handshake.

`factory.set(operation, limits, bounds)` creates an empty source owner. Poll its
initializer whole write before Add, Remove, commit, iteration or copy. `initialized()` means that local whole write, not a service processing ACK. Add/Remove may then queue within explicit limits and expose continuations only
on whole writes. Attached Set loss invalidates original operations and
contents; no mutation/result/partial write is replayed on another MQ.

`Prepared::evaluate` is offline. `Set::commit` binds it to a Set source and
a nonreused request ID. Admission failure returns the unchanged preparation. A Listener has a separate original MQ; its callback borrows the incoming request
and returns Accept or Reject synchronously. Accept yields a Prepared operation;
only commit sends its original accept ID on the chosen same-domain Set MQ. `Listener::reject_prepared` instead consumes that still-uncommitted owner on its
exact original factory domain/listener epoch. Foreign, retired or Evaluate
preparations cannot reject another request. Admission failure returns the same
Prepared; successful admission returns an opaque original RejectId. Match that
token against the original listener's whole REJECT write, or retain it
until that listener physically closes. Queueing, a partial write and dropping a
Prepared are separate facts and do not prove a remote rejection was processed. The original listener epoch must remain known-live until Accept writes. Listener
EOF/native socket loss can restore the read-only registration after its old
physical source retires, within the same original Bounds. Port/config/clock or
malformed-input refusal is terminal; it cannot become an immediate retry loop.

## Results and cancellation

Results retain size and a `ResultValue`: an ordinary element, local addition,
remote addition, HALF_DONE, DONE or FAILURE. Element variants preserve the exact
type and bytes, including type zero and zero-length data. Status-only variants
carry no element; as in the C API, their wire element fields are ignored.
Each operation retains its original result mode. FULL, REMOVED and ADDED deliver
ordinary elements; SYMMETRIC delivers local/remote additions. A contradictory
element status retires the source with `Error::UnexpectedResult` and all original
unfinished receipts. HALF_DONE is nonterminal; only DONE or FAILURE terminate.
A canceled/unknown RID is consumed without a
replacement callback. CANCEL completion is local whole write, not remote ACK. Zero-written operations are actually removed; cancelling a partial request
retires the original MQ and reports every unfinished original owner.

## Iteration and copies

One iteration is active per Set. Each element requires an explicit IterAck. Cancel while an element awaits ACK queues0; its whole write advances the local
wire generation and reports local cancellation. There is no cancellation END
or ACK. When an ACK1/initial reply is already outstanding, cancellation intent
waits for the original next element (then ACK0) or IterDone. A partial
control write forces physical source retirement. This prevents an untagged old
IterDone from being mistaken for a newly started iteration. Native generation
65535 is usable once; further iteration returns Overflow rather than recycling
old local authority. Normal IterDone is never inferred from EOF.

CopyLazyPrepare admits one outstanding cookie query. Its exact raw four bytes
produce a single-use CopyTicket, which a same-factory new MQ echoes in
CopyLazyConnect. Failed local copy admission returns the unchanged ticket. The service performs the lazy membership fork on connect; the SDK does
not pretend that the earlier cookie receipt was an eager content snapshot. The original source must remain known-live until the copy initializer writes.

## Resource policy

Limits select an explicit C ABI (native order and uint64 alignment4/8), frame,
queued wire-byte/frame, live operation and syscall budgets. Initializer, partial
input and each queued write have independent finite native/canonical targets,
clamped to the immutable original source lifetime. Operation/iteration/copy
expiration conservatively closes the original Set MQ, returning its original
unfinished receipts; caller output waits may invoke the same clock-free native
fence. Immutable `Bounds` are plain copied targets. One reusable native alarm
belongs to the active transport Session, selecting the earliest overall,
initializer, partial-input or queued-write target. A separate reusable alarm
belongs to the active Set, selecting the earliest uncanceled operation, effective
iteration cleanup/original target or copy target. Session polling cannot overwrite
an earlier Set target. Replacing the earliest owner can reset its waiter earlier
or later, and an empty owner clears it; none of these actions renew an original
bound. Physical retirement clears both waiters before returning receipts. Operation/copy receipts have no duplicate expiry owner or runtime future, while
iteration cleanup retains its plain Bounds. Canceled operations still owe
their original queued CANCEL write bound; iteration cleanup replaces its original
business bound exactly as before. Canonical checks still examine all active
original targets. Queue bytes are retained **wire** accounting, not an exact RSS
promise. Metadata grows on demand within frame/operation count caps. No background
task or hidden timeout worker is created.

Local-only operation0 is represented as the public enum declares;
fixed C's create-handler restriction to1/2 remains a separate counterpart
profile limitation, not a reason to alter wire fields or claim acceptance.

## Failure provenance

Before shared Set/Listener physical retirement, TransportLoss captures the exact
current Framed input prefix, including malformed headers whose native read
failed before ReadStep::Progress. It takes the maximum of the observed head
counter and the retained head extent, rather than adding two views of
the same bytes. Loss capture samples no clock and performs no I/O.

The client checks each write against its original target before clearing that
target. If the check fails, the client closes the connection before returning
the actual write progress. The next progress poll, native guard or explicit
close returns the original loss. Whole writes report local transport exposure.

Loss provenance is supplied by the boundary. `Cause::origin()` and
`Error::origin()` expose `LossOrigin::{Bounds, Source, Clock, Selector}` without
classifying by a numeric error value. Actual original native/canonical bound
expiry is `Error::Deadline(context)` or `Cause::Deadline`; a shared Clock returning that
same low-level value remains `Error::Clock` with the complete original
`ConnectError`/port marker. CLIENT configuration, Resolver and endpoint-selection
refusals remain `Error::Client`. Native read/write/framing errors retain their
original `Error::Io`, and received status/frame refusals remain source-local. These origins describe where a failure arose; they are not cryptographic,
remote-completion or general source-authority receipts.

Synchronous admission methods preserve the same provenance. A caller retiring
the original Set after its own Add/commit/cancel failure can move that exact
error into `Set::retire_after(error)`. The SDK physically closes that MQ before
returning all original mutation/operation/iteration/copy and transport facts;
it does not replace the failure with Requested, clone an I/O error, extend a
deadline, replay writes or claim a remote result. A composed owner can isolate
Source/Bounds loss while independently fencing a refused shared Clock/Selector.

Exact deadline facts remain a fixed `Copy` value carried in one cold box by
`Error::Deadline(context)` and `SetLoss::deadline`/`ListenerLoss::deadline`. The deadline check allocates that box once. Error-to-loss conversion
moves the same box, so retirement receipt assembly adds no allocation. Ordinary
progress values and non-deadline errors do not carry its inline storage. The context names the overall/initial/partial-input/write or original
operation/iteration/copy predicate and unchanged target, plus native time at
that check and a canonical sample only when the check already obtained one. Native guards add no Clock sample. `BudgetCreation` has no canonical target yet;
its `expires` is `None`. Serial/request labels are diagnostics, not authority. Clock-provider errors retain `Error::Clock` and no deadline context even when
the provider's own error value is Deadline. Original Cause/IO receipts remain
separate from these facts; no context proves a peer result or processing ACK.

A response that becomes physically complete within its original partial-input
bound ends that partial phase before delivery on the next caller poll. Its
existing bound is checked after the last read before being cleared; the first
read of a whole frame creates no new partial interval. Scheduling delay after
completion cannot resurrect that finished partial phase. The original overall,
operation and queued-write bounds still gate delivery.
