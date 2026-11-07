# CONSENSUS core

The fixed v0.29.1 active contrib service uses old generic SET UNION with
SYMMETRIC results and547 round contexts. It does not use the inactive541–545
transport or SETI/SETU message aliases. This crate is no_std; its explicit alloc
profile implements an original client session, immutable SET populations,
per-peer task owners, bounded element/ballot storage and result scheduling. It performs no native IO, implicit clock, entropy, FFI or worker launch.

The participant list is sorted by peer bytes, includes the local identity
if omitted and rejects duplicate identities. The global SET application hash is
HKDF-GNUnet with the exact salt `gnunet-service-consensus/session_id`, sorted peer
bytes as key material and the original local session hash as context. Public
absolute start/deadline and the canonical cyclic peer1/peer2 roles are preserved.

The plan implements two all-to-all union phases, then floor(n/3)+1 repetitions
of parallel leader dissemination, echo, confirmation, grading and majority
application. Every leader has its own dissemination, echo, confirmation and
grading frontier. A ready leader can advance while another leader's original
operation is still waiting; there is no all-leader barrier between those phases. Only all-leader grading completion permits round application. This composes with
the fixed C scheduler, which can wait for one leader's ECHO before starting a
different leader's dissemination, without copying that scheduler's serialization.

Each leader retains at most n task rows and one original immutable SET source,
including its close debt: concurrent tasks remain at most n² and sources at most
n. The original source must actually retire after all its tasks become terminal
before that leader gets a fresh next-phase source. Old TaskId/SetId capabilities
are never reused; removing only that retired source's rows preserves other
leaders' original callbacks and serial ordering. A unique wrapper pool owns
payloads once; memberships and ballots keep stable indices. The two bounded CPU
scan classes rotate fairly and park after a full blocked pass. They restart for
effects, offers, results, state transitions or actionable expiry, without a
new timer or worker. Actual array capacity and transient metadata growth are bounded;
these are core allocation limits, not measured whole-process peak RSS.

Each Reconcile is the exact original native prepare/accept/commit, using UNION2,
SYMMETRIC1 and the explicit standard SET options. `Written` proves only the
original composite local writes. Only a matching SET DONE/FAILURE supplies
semantic terminal state. Partial/admitted actions retain their original effect,
source and immutable population across cancellation. Normal IO permission is
projected by task/set/offer/listener/effect gates; a native caller still validates
its SDK epoch/channel/factory capability and original native hard bound. Every normal effect stores its original absolute deadline. SET sources freeze
their phase target when created, and Reconcile/result expiry uses the exact
original TaskKey's shared round window. A later leader cannot renew an admitted
target or move an earlier source into a later phase. The next wake target is the
earliest still-live original frontier/task target. Incoming offers are compared
with their own repetition and leader frontier, so an earlier leader's ECHO cannot
invalidate another leader's still-valid dissemination. New blacklist decisions
are applied only after every leader has graded, preserving the original current
repetition's electorate. A new IO attempt may not start after its bound, and its
partial original source must actually retire before Lost/Unsent cleanup is reported. `retire_step` is closing-only and needs no
synthetic clock sample; an outstanding admitted effect still needs its receipt.

The original input set determines the meaning of ADD_LOCAL/ADD_REMOTE. Opaque
payloads retain their application type and are wrapped as outer SET type25. Application labels are not an implicit BLOCK namespace: the caller selects an
explicit Validator policy yielding Opaque or Checked. Unknown application data
can be opaque without any signature/authentication claim. Wrapper, marker and
USER_MAX bounds are mandatory; selected validation failures are preserved. The separately installed BLOCK24/25 callbacks have their own registry contract;
DHT registration alone does not connect them to a consensus service caller.

Contested state uses the official547 field and the original marker. Each task
freezes its own marker state, records remote marker/missing-own-marker
differences and commits only on the matching SET DONE. A common marker inference
assumes the public SYMMETRIC difference contract is complete. The current Rust
[generic SET implementation](../gnunet-set/README.md) retains reciprocal full
requests, original snapshots and output debts before reconstructing local
ADD_REMOTE results. Unmodified C full-transfer notification, Byzantine and
concurrent-mutation profiles remain explicit limits; no peer queries, nonce
fields or fabricated votes replace missing observations. There is no Byzantine theorem or all-profile acceptance claim.

Grading uses committed, noncontested confirmation votes and n-faults /
faults+1 thresholds with faults=floor((n-1)/3). A contested confirmation represents
bottom: its payload supplies neither presence nor absence votes. Echo counting
still uses its original committed electorate. Final-round membership includes an
element supported by at least ceil(nonzero-grade leaders/2), so a membership tie
includes the element from either original local base. Zero eligible votes cannot
create support; the original strong round quorum remains mandatory. Final output
is the resulting Current set, excluding locally inserted values and internal
markers. These two corrections follow the [construction's exact-agreement rules](https://grothoff.org/christian/consensus2016.pdf). A failed direct LEAD does not veto genuine matching CONFIRM results: more
than `faults` noncontested matching confirmations can produce grade1 even when
that receiver's original LEAD operation failed. A four-peer public Session
source case checks one Byzantine leader's failed LEAD to A, subsequent actual
SET population differences and DONEs, A's bottom confirmation, and the resulting
grades1/2 at correct receivers A/B without injecting grade fields. It establishes
this source boundary, not native or full Byzantine qualification. The failed
normal runs bound to `5094dbcc` and `78802c65` still returned no elements or525;
their missing per-phase transcripts do not establish that this defect caused
those runs' Unavailable outcomes.

Other grading choices retain their existing profile; this is not an arbitrary
transcript equivalence or Byzantine correctness proof. It deliberately does not copy
C's Echo-vs-Confirm selection, LastGradecast alias, weak threshold or unfinished
timeout implementation. Those differences are explicit semantic/interoperability
profiles requiring review and evidence, rather than quiet whole-feature
credit. Early stopping retains the two adequate-repetition shape, with
adequacy requiring the same n-faults support used by the construction. The weaker
2*floor(n/3) condition can abort or finish early with two allowed faulty peers
in an eight-peer session; it is not used as an early majority threshold. The C referendum helper also retains a local value on a tie; that source behavior
does not implement the construction's absolute final membership rule. Correcting
it here makes no mixed-peer Byzantine acceptance claim for an unmodified C peer.

A local commit or deadline cannot substitute for remote DONE. Unqualified quorum
ends with a failure/close, not525. Output elements and525 are each retained
until their whole write. The original listener/offers retire before public
output completion: installed secretsharing immediately destroys one consensus and
starts another with the same peers/session hash. Normal C client EOF after a
known525 write is cleanup, not a retroactive business failure. The old wire has
no run epoch and global_id excludes times; sequential reuse still depends on real
old native/channel retirement and must not relabel an old callback as a new task.

The native [host](../../adapters/consensus-std/README.md), client SDK and
[normal service](../../apps/gnunet-service-consensus/) are present with selected
static compilation evidence. They enforce original source identity and deadlines,
pass genuine SET results, and retain native errors and terminal receipts. Actual mixed-peer behavior still requires runtime qualification. `task_failures`
is explicitly a bounded first-cause/count summary, not a complete audit trail. `Session::failure_context()` returns an inline immutable copy captured at the
first business fail/cancel, before cleanup changes phase or removes metadata. It records the stage, applicable kind/repetition, original participant
and strong thresholds, positive leader count, completed retained leader
grades with ungraded rows separate, and remote task states by network kind. Task counts describe rows retained at that boundary, not historical totals. The first failed task's original local task/SET serials, official context,
canonical peer index, pre-failure state and existing canonical observation are
captured when it first fails, so an Apply failure can retain that association
after its earlier phase rows disappear. Later errors and cleanup never overwrite
the snapshot; teardown following a known525 write creates no business failure. These are diagnostic labels, not capabilities, source facts or renewed budgets. No payload, key, native owner, allocation or event queue is added. Public source
cases cover an unqualified round after matching task failures and an
original public deadline, preserving snapshots through scripted retirement
and a separate cleanup loss. They do not attribute previous normal-run failures
or qualify a new native run.

Physical loss of an original SET source is separate from whole-session failure. The trusted `source_retired` boundary settles that source's pending effect with
its original Written/Unsent/Lost disposition, fails every unfinished task on it
(including plans that never acquired a native operation), and prevents future
population or reconciliation on that SetId. A population lost before planning
does not become a ready set: later plans fail without IO. Its logical CloseSet
still waits for the matching retirement effect, while unrelated leaders and
their pending effects remain intact. The same original threshold and deadline
gates decide whether the remaining genuine votes suffice; no loss grants DONE,
membership support or525. No replacement or replay of that original source is
introduced. Uncommitted incoming offers retain their original owner and request
an rejection on their original listener before further phase work. Listener/PILS/shared-clock/whole-session failures still cancel the session.

Ten public Session source cases cover canonical namespace, single-participant
phase flow and own-value filtering, absence of remote DONE despite local writes,
admitted cancellation with independent cleanup failure, original offer ownership
and cancellation, absolute final membership ties, contested confirmation payloads,
and two successive weak faulty gradecasts in an eight-peer session that must
reach the original third repetition. Two of these cases retain both original
leader proposals concurrently, let one leader finish ECHO and CONFIRM while the
other remains live, and admit a valid later-leader proposal offer while an
earlier leader's ECHO is already active. They check original source retirement,
unchanged shared-window targets, fresh capabilities and the original n²-task /
n-source limits through the public effects and matching SET results.

The complete differences, task DONEs and write/retirement receipts in these
cases are scripted inputs. They do not supply native daemon, SET peer or
Byzantine agreement evidence. Session construction uses the deterministic
namespace HKDF; these source cases require neither entropy nor a native service.