# Native CONSENSUS bridge

Bridge owns one original core Session and generic SET Factory, Listener,
Set, Prepared, MutationId and OperationId owners. It does not spawn a service,
background task, Resolver or private CONSENSUS peer transport. The normal process
owns its configured PILS Client and its original IPC connection. Current
PILS epoch+peer must match the original verified Identity before each normal
bridge turn. A lost/changed source cancels that original session instead of
silently replacing its local identity. Same-source, same-peer verified metadata
refresh is allowed within the unchanged original session/native bounds.

Fixed C consensus calls GNUNET_CRYPTO_get_peer_identity, whose util implementation
loads PEER/PRIVATE_KEY and derives its public identity. It does not itself use
PILS. Rust's PILS observation is an explicit internal identity provider
choice, never guessed from participant order or a configured public string. The caller reports PILS events first; metadata-only HELLO coverage makes
no authenticated address/dial capability claim. Configuration snapshots across
MQs do not prove a remote SET daemon restart generation.

PrepareSet creates an empty UNION source and serially admits each frozen
population element, waiting for its exact mutation whole-write before advancing. The aggregate core Written occurs only after CREATE and every original
ADD whole-write. Reconcile binds prepare/accept/commit to the same core
TaskId/SetId/OfferId and original hard bound. OperationBound exposes the real
native OperationId/epoch association after admission, without a write/ACK claim. OperationWritten whole activates the original core task. Actual ADD_LOCAL,
ADD_REMOTE and only DONE/FAILURE drive semantic results; HALF_DONE never
terminates a task. Every native progress/loss/receipt remains exposed.

A valid future incoming context is accepted only into an offline original
Prepared. Its domain, epoch and accept id stay unchanged. Before first successful
commit, Prepared::with_options supplies that task's standard options; it
cannot reconfigure an already consumed committed preparation. Invalid incoming
contexts produce native rejection writes and independent Rejected events. Dropping an offline preparation alone is not a peer rejection/retirement proof. An uncommitted offer on a retired SET is rejected through that original
Prepared's exact factory domain, listener epoch and accept id. Admission retains
the same preparation on failure; successful queueing retains a rejection token
until the exact original listener's whole REJECT write, or that listener's real
physical closure. A committed preparation cannot be recovered as a rejection:
its operation belongs to its original SET loss/cancellation. This permits
other leaders to keep their listener and immutable sources. The original
listener still physically closes before public523/525 completion. No private nonce/ACK is invented for
sequential reuse of a standard global session hash.

Normal native sources use original per-effect bounds clamped to the outer
unchanged canonical/native limits. Actual source/clock failure is retained in
its original native event or Fault; core classifications never erase that cause. Closing uses native close and bounded original loss work. Historical
last_now is used only for matching failure metadata, never a fake clock read,
new deadline or new IO permission. Already admitted writes retain their actual
known whole/prefix disposition. One source's loss is applied to all its
original tasks, including plans without native OperationIds. Pending commit
exposure remains Written, Unsent or Lost according to its original
receipt. The failed core set is no longer ready/live and cannot admit another
PrepareSet/Reconcile. Its host row and logical CloseSet debt remain until their
exact retirement settles; other sources and leader frontiers can continue with
the original bounds. No partial result is relabeled as a new epoch, peer DONE
or replay. A pending source-effect window expiry stops new IO and physically
retires that source before settlement; it does not renew the target or alone
manufacture a native loss receipt. Identifiable native EOF, native hard expiry
and original socket IO losses are source-scoped. Shared clock/selector failures,
ambiguous Protocol failures, listener/PILS loss and the original whole-session
deadline remain global fences. PrepareSet reserves and records its never-created population row before any
fallible deadline/Factory admission. A refusal at that boundary retires only the
exact original source with Unsent, retaining its empty row through CloseSet;
it creates no synthetic SET loss. An already-created source's local admission
refusal physically closes that same owner and retains its Requested loss
separately from the business refusal supplied to source_retired. An uncommitted
incoming preparation remains owned for rejection on the original listener. SourceRefused carries a single bounded original diagnostic; SessionReport keeps
its count and first cause without passing it through the global Fault channel. Ledger allocation failures, shared Clock/selector failures and ownership
invariant failures remain whole-session fences. Before a global Unsent closes
its logical population, the proven never-created host row is removed as well;
no nonexistent physical owner or unreachable CloseSet debt remains. Deadline and cancellation
classification is taken once from the SDK cancellation intent, independent
of whether another pure effect happens to be pending. The current SDK produces
Requested cancellations; the Deadline-intent unit case verifies only the typed
mapping and is not evidence of a native deadline-cancellation event. The final
bounded-cleanup fallback also moves any unconsumed SourceRefused diagnostic into
the report, without upgrading unresolved retirement to success.

All normal-source IO gates are checked again after pure deadline/cancel progress.

ClientFrame gives the standard523/525 bytes and original EffectId to the
normal IPC owner. That caller retains its physical cursor and reports only its
Written/Unsent/Lost via complete_client. CloseClient similarly waits for
physical retirement. EOF/deadline/cancel cannot manufacture525. Ordinary
C destroys its MQ after525: a known original whole write must be settled before
classifying that later EOF. All original listener/offers and SET sources retire
before completion; the wire has no global run epoch or remote port-close ACK,
so delayed same-id/context and full-SYMMETRIC profiles still require evidence.

Limits separately bound the pure session, native SET queues/sources and actual
bridge token-slot metadata. Population is streamed; no complete second encoded
set is retained. A single bounded scan turn polls at most32 sources, rotates
fairly, and parks after a complete blocked pass since the last Ready
source event. Ready renews that finite scan debt while preserving the fair
cursor: for example, Attached queues CREATE and does not prove that source's
new local write is drained. Successful local ADD/commit/cancellation queue
admissions also renew that debt, including for a source already visited in a
pass spanning more than32 sources. The next turn must revisit it even if the
remainder of the previous pass contains only idle sources. Physical source loss
work visits at most one original native task row per turn after the bounded
core source-retirement metadata pass. These source bounds are not measured
RSS/time claims. The core's public-vs-C grading choices and mixed-C full-transfer behavior remain
required profiles. Current Rust SET supplies reciprocal full-transfer information;
C notification/Byzantine/snapshot limits remain explicit, with no BFT or whole
interoperability proof.

The SERVICE Server layer uses accepted/credentials/service/Framed
facilities and locally pinned futures. No future is spawned. Each original IPC
owner has stack-local PILS/core domains, current PILS Client, SET Factory
and Bridge. It consumes actual520 first, then521/524 complete frames, and writes
original523/525 with one retained physical cursor. PILS is polled first on every
normal turn. Before every new syscall the same original native/partial bounds,
original identity epoch+peer and core output gate are checked again. Admitted whole output facts are settled before later EOF/deadline classification.

Sources::new first takes one coherent snapshot_all, then chooses explicit
fixed endpoints. Their getter must return Some selected storage; both
role selections are charged once outside the per-session aggregate reservation. All later copies share selected Arc payloads, not complete Configurations. Shared clock/Resolver and temporary native shortened paths remain separately
owned. No fixed profile is silently treated as a live resampling configuration,
and these reservations make no allocator-overhead or measured RSS guarantee.

ServerLimits keeps bridge limits separate from clients, conservative session and
aggregate reservations, frame/slice limits, fixed first/partial/whole lifetimes,
independent retirement grace and identity-only PILS/HELLO/profile bounds. READY means IPC admission; it does not pretend PILS/SET is online or peers
have accepted a session. The original shared global-id lease remains held until
its dependencies retire. Duplicate overlapping joins fail that client;
no private run nonce or ACK is used to make a stale same-id callback fresh.

Shutdown first marks every original owner. Each local future closes IPC,
all original SET/Listener sources and PILS without a clock sample, preserving
loss receipts in already owned slots. A separate pass drains bounded pure
bookkeeping within the original retirement grace. Before any incomplete receipt
list is extracted, lack of quiescence is recorded as undrained; physical_closed
is independent. Exact original native failures, unknown/exposed operation
receipts and cleanup causes remain in SessionReport, with bounded first/count
summaries explicitly distinguished from exhaustive logs. Normal empty requested
closes are counted rather than retaining full successful phase histories.

The normal application policy explicitly chooses public opaque payload labels,
without an authentication claim; wrapper/marker/USER_MAX checks remain in core. It does not reinterpret an application label as an implicit BLOCK plugin type. The optional bridge Validator API permits an independently selected
application policy. DHT BLOCK24/25 registration and nested checks remain separate.

The ordinary process entry/configuration/Resolver/signals/parent control is a
separate foreground service package. Core public-vs-C grading, mixed-C full-transfer
behavior, legacy private-derived vs PILS identity and same-global
reuse profiles remain explicit unverified requirements. No whole CONSENSUS,
secretsharing or GNUnet completion/Byzantine/performance acceptance credit.

server/owner/registry capacities and fixed endpoint storage are
deducted before session permits. Native and canonical admission origins precede
fallible ACL/diagnostic work; the unchanged hard target covers all provider time. Original author non-execution and required semantic qualification remain unchanged.

A two-node C public-API component profile after the SET corrections reached
four normal DONEs and zero failed SET operations at each endpoint, then stalled
while preparing the next gradecast population. The source scan could consume
its last old debt on an idle source after another source's Attached event had
just queued CREATE, parking before that original CREATE was ever polled. This
source correction preserves all original ownership, memory and time bounds; it
does not relabel that failed run or claim the complete agreement succeeded. No full Bridge fixture using an invented PILS Identity was introduced. The
source author only inspected the finite causal trace and formatted the patch;
unchanged normal-service API qualification remains separate.
