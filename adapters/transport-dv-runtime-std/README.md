# Actual DV runtime actor

`Runtime` is a caller-driven Unix runtime library. It uses the admitted PILS client, DV crypto/cache, independent durable DV Provider, and BoxAdmission gate. It creates no hidden Tokio task, implicit Resolver, thread, socket, entropy provider or disk worker. The caller explicitly constructs/drives a fresh PILS client to its public identity, opens the independent marked `TransportDv` Provider (one explicit worker), supplies one crypto Source for that original local PILS epoch, and supplies all fixed route/cache/replay/loan storage. `new` verifies ready identity/epoch, no tracked logical operation/copied native output, and pointer equality of the original shared RuntimeClock Arc. The separate pure Source constructor is not itself an MQ authentication receipt.

This actor is composed with the shared Engine through [transport-dv-bridge-std](../transport-dv-bridge-std/README.md). The standard [TRANSPORT service](../transport-service-std/README.md) constructs and drives that composition through `foreground` → `session` → `dv_program`, including the original physical input/FC leases, direct-neighbour generations, output receipts, authenticated final delivery, scheduling and durable sender stamps.

## Implemented paths

- `attach(ClientId, peer, queue, reverse_link)` registers an original caller-port lease for an actually current eligible direct queue. The Engine-minted ClientId and the actor's checked private allocation identity distinguish same-number queue reuse. The native coordinator must detach the exact lease on physical/queue loss; registration is not end-to-end peer authentication. `reverse_link` is only the caller's bidirectionality fact, not an inferred property of a signed path.
- `receive` validates one complete official1218/1219 frame and its recipient/source structure, reserves bounded metadata/bytes, and makes a fallible immutable copy before accepting the caller's original `J` attribution. No FC ACK or CORE delivery occurs here.
- `receive_with_budget` keeps the original input's canonical/native targets. `InputBudgetExpired` means that exact incoming budget expired before admission and returns the same caller debt; it does not assert source liveness. Actual source, PILS, clock and actor-bound failures retain their own causes.
- LEARN processing performs initiator/purpose37 and all purpose36 hop verification. Actual Routes source gates use Provider load, exact store admission and exact private commit receipt before passive route installation. A busy Provider retains the original requested load/store phase; it cannot strand the Routes pending bit. Failed/canceled original source work is retired before a later fresh load. Confirmed paths require the original challenge/stamp probe and an whole-write timestamp. Probe RTT/residence/scheduling use independent nondecreasing native elapsed time, not UTC or remote monotime.
- `probe` actually obtains caller entropy, registers the original challenge, admits purpose37 signing to the existing PILS MQ, verifies its exact result and exposes official immutable bytes. `forward_learn` actually admits/validates purpose36 for the original predecessor/challenge/selected successor and appends the original hop with native residence time. Forwarding/fork selection is an explicit bounded caller policy: inspect `learn`, choose only registered neighbours, call `forward_learn`, then `finish_learning`. All selected outputs and the original input attribution remain retained through outcomes. This does not duplicate C's internal fork scheduler.
- Incoming BOX with remaining hops selects the farthest actually registered direct shortcut, strips only the selected prefix in its original owned buffer, and transfers that same allocation to its forwarding output. Ciphertext/MAC/encapsulation/nonce/orig-size remain unchanged. A full output directory retains the same input and its original targets without a new wake chain; capacity release permits another bounded scan. No second ciphertext allocation or double byte reservation is needed. The original physical input and FC attribution remain retained until the outgoing output terminates. No reachable hop is a refusal/drop, not fake forwarding.
- Final BOX uses fixed receive material, or admits the exact PILS DHKEM operation and validates its original identity/epoch/result. Every packet gets AEAD and exact sender purpose30 authentication; signature caching only follows the existing exact-statement rules. Each new material epoch captures its own fixed canonical/native lease, capped by the original Source guard, adopted identity, source native deadline and explicit material lifetime (default300s). Hits preserve that epoch; neither the first packet nor its route shortens later packets. Each packet retains its own original canonical/native budget. A receive hit that expires or is replaced before use returns the same input to a lookup/KEM miss within that unchanged budget; authenticated/opened grants and immutable output no longer depend on the cache lease.
- Actual `box_admission` then performs original durable sender-floor load/store, exact Namespace/Operation/Job/generation completion, current same-provider load immediately before grant, and one shared live Replay owner for all ingress. `delivery` returns only its private-constructor `Granted`, with original source/clock/native deadline/durable/current-floor/nonce checks. External Engine acceptance must consume exactly those immutable inner bytes before `delivered` is called. No boxed1218/1219 is offered to CORE.
- Outbound `send` selects a currently confirmed route with an actually registered first hop; preserves its exact path; uses bounded certified send material or purpose30 PILS signing, independent verification and AEAD. Each original packet seals once with its unique nonce. Native partial retries reuse immutable bytes; they never reseal. Actual source-monotime values come from the caller's reservation port and are not called durable merely because they are u64.
- `queued`, `exposed`, `written`, and `output_lost` report separate original physical facts. `queued` is a synchronous completion immediately after immutable-frame enqueue following `output` preflight, without an await or owner teardown between those calls; it samples no fresh clock that could misclassify an already admitted native frame as unsent. Only whole probe write starts RTT. Explicit output loss preserves known positive exposure and never invents unknown=false. `output_lost` ends that original external output owner: it can describe shared-source loss or a retired incomplete logical output whose chunks all ended. It does not by itself assert shared-MQ closure or whole-message transmission. The external Engine/Server distinguishes settled local output from its still-live logical Job and unknown native chunks; task expiry cancels only the original logical owner before that completion check and does not fabricate remote acknowledgement.
- Callback cancellation keeps exact original PILS operation retirement metadata; native hard guard runs before canonical sampling and actually closes the original MQ after finite suffix grace. First partial input, original source lifetime and each original task have finite immutable native bounds. Source/clock failure physically closes PILS before pure Source/cache/replay retirement; no request is replayed to a fresh source. Every canonical/source sample failure in admission/poll closes the actor's own physical source.
- Original plaintext loans are caller-owned, shared across all peers, erased and returned on every success/refusal/bad-MAC/stale-slot/cancel path through the admitted full-loan API. No self-reference, unsafe, leaked buffer, arbitrary plaintext-to-authenticated constructor or per-channel maximum-payload Vec exists.
- `close` is clock-free and closes the owned PILS source, recycles each live proof loan, independently requests worker stop and retains first cleanup error. It does **not** pretend to close the external TRANSPORT owner: queued outputs remain `AwaitPhysical`, `RetireOutput` and `retirement` identify the exact originals, and `native_outputs_pending` remains nonzero until actual `written`/`output_lost` callbacks arrive. `take_finished` returns original `J`, disposition and original optional disk debt for the FC owner. Returning a buffer/origin is not a remote application ACK. `shutdown` actually drains/joins the original Provider worker; fsync/rename may block in the OS. `take_buffers` returns erased caller loans after source retirement.

`try_take_output_finished` synchronously hands off only the external non-clone
origin. The same completed row, neighbour, original bounds, immutable packet and
outcome stay in Runtime until success. A refusal restores the returned
same origin in that slot and creates no scan debt, wake, source or native fact. The closure cannot change the recorded outcome or borrow the Runtime again. `take_output_finished` uses this boundary too. The private finished state carries
its actual `WriteOutcome`; there is no separate optional result which could
strand an otherwise terminal row.

Cancellation collects the first failure and first independent cleanup error
while visiting every original child. A refused PILS cancellation still joins
that same operation's quiescence with its bounded retirement ledger; an
unknown result, full ledger or unrepresentable target physically fences the
original PILS source and completes the actor's remaining local cleanup. Provider
operations retain their existing worker ownership through completion/join. Queued external TRANSPORT outputs keep their physical retirement debt. Actual
Written and Lost callbacks are saved even when independent probe/RTT cleanup
refuses; the caller never needs to repeat a physical fact.

Incoming `receive`/`receive_with_budget` return `InputRefused<J>` with an
explicit `InputRefusalDisposition`. Each capacity/copy, packet-shape,
original-budget or shared-authority step selects Deferred, Rejected, Expired or
Source, respectively, and returns the same non-Clone origin before input
admission. A rejected stale neighbour or truncated frame is input-scoped, not a
claim of peer malice or Actor source loss. Shared Clock errors retain Source
scope even when their numeric cause equals a packet or capacity error. Incoming
admission rechecks the PILS identity/epoch; the disposition itself does
not prove a physical close. Outbound `Refused<J>` remains a separate contract.

## Bounds and costs

The explicit policy bounds retained input/output/neighbour metadata and the shared packet-buffer/clear-before-seal allocation capacity. Each retained Vec is charged once by capacity, including unused tail capacity after route compaction; this excludes allocator overhead and is not a process RSS bound. Admissions preflight the requested sizes and then check allocated capacities before accepting ownership or admitting crypto work. Caller storage independently bounds route/probe/source directories, send/receive material, replay peers/exact nonces, scratch and total plaintext loan bytes. Metadata Vec capacities are reserved fallibly once; packet copies reserve before admission. One shared scratch is reused. Two private concrete material owners each hold the pure cache, exact typed-ID/lease slots and replacement cursor. They alone perform lookup, last-use checks, checked installation, revocation and close, so Runtime cannot install material separately from its lease or update a cursor independently. The same fixed-ID/material-lease arrays retain each epoch's original canonical/native provenance without per-packet key cloning or additional allocations. Pending sign/KEM owners also retain their independent material lease and original packet operation bounds; their completions must pass both before cache installation. Cancellation removes the original matching job, so a later native completion cannot install material for that canceled packet. These are bounded metadata costs, including the existing boxed signing owner, rather than a new queue or per-packet key cache. The fixed300s material policy is an internal lease, not a claim to reproduce C inactivity or rotation scheduling. Per-poll state transitions are limited by `quantum`; all hop scans and signature statements are bounded by the official16-hop limit. Exact replay probing uses the supplied fixed bounds and exact bytes, not hash-only equality. Route and retained frame lookups are bounded linear scans; no unlimited persistent nonce ledger is claimed. Full live replay tables refuse new admission rather than evicting still-relevant nonce facts.

`Step::Failed` carries an inline `FailureContext` captured before the original
transition consumes state or cancellation changes its phase. It retains typed
input/output phase, original row/source targets and adopted identity expiry,
the original neighbour lease, and bounded parent/planning/physical-callback
facts. Native guard failures have no canonical observation; other paths reuse
their existing sample without reading the clock again. Input age is native
elapsed time at the snapshot. Context contains no frame, key, proof loan or
application `J`, and creates no queue or refreshed deadline. An actor's false
queued/exposed flag is not independent evidence about the external native
owner; that owner's original transfer/cursor observations remain necessary.

A failed `Forwarding` input also snapshots its unique retained child output by
matching the original parent token before cancellation. `forwarding_child`
contains that existing output's token, exact phase, queued/exposed observations,
retained outcome and unchanged budget. It contains no bytes or new owner. No
match or multiple matches produce `None` without changing failure/cleanup; the
snapshot cannot authorize Written, FC release or reconstruction of an output. The existing token enumeration and native bridge's original transfer facts are
still required to distinguish staging, physical admission and packet callbacks.

## Runtime composition

The bridge consumes original accepted physical frames and reassembled outer bodies with their queue generation, FC lease and first expiry. It tracks direct neighbours and maps immutable output admission, positive exposure, whole writes and loss through the existing Flow/reliability queues. Verified `Granted` bytes enter the shared fragment/control/CORE path with their authenticated ultimate sender. The service supplies bounded probe/forwarding scheduling and durable local sender-monotime reservations. Epoch retirement retains old physical output and input debt until settlement, closes the original PILS source and drains its provider before a replacement allocation.

These source paths do not establish successful multi-hop deployment or unchanged-C/mixed-peer interoperability. Required runtime, failure/recovery, platform and measured resource/performance qualification remains outstanding; selected historical receipts retain their original source and execution scope.

Independent original source IDs never enter wire. This actor owns its PILS and durable DV provider; external TRANSPORT, communicator and application owners retain their separate lifecycle and completion contracts.

`TaskBudgetExpired` identifies expiration at an existing input/output token or
explicit original budget. Callers retire that same task and keep independent
work alive. Source clock/identity/native-source failures retain their original
error variants. A positive packet write remains Written when only its RTT
probe observation has expired; no successful probe is inferred.
