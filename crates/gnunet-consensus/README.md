# CONSENSUS core

This `no_std` crate implements caller-driven GNUnet CONSENSUS sessions. Its
`alloc` feature supplies bounded element pools, SET populations, task ownership,
gradecast and client-result scheduling. Native IPC and SET ownership belong to
the [host adapter](../../adapters/consensus-std/README.md).

## Wire and participants

The selected reference uses generic SET UNION with SYMMETRIC results and type547
round contexts. It does not use the inactive541–545 transport or SETI/SETU aliases.
Participants are sorted by identity, include the actual local identity and must
be distinct. The global SET application hash uses HKDF-GNUnet with salt
`gnunet-service-consensus/session_id`, sorted peer bytes as key material and the
original client session hash as context. Cyclic peer1/peer2 roles and the public
absolute start/deadline retain their wire meaning.

Application values retain their type and opaque payload inside outer SET type25.
`Validator` explicitly selects opaque acceptance or checked application data;
an application type is not implicitly a BLOCK namespace. Wrapper/marker and
USER_MAX bounds are mandatory.

## Rounds and immutable bounds

Five typed internal rounds map to the official context kinds:

| Round | Kind | Population |
| --- | --- | --- |
| Initial union | 0 | Current values |
| Inventory | 1 | Current values and original size marker |
| Leader dissemination | 2 | Current values |
| Echo | 3 | That leader's proposal |
| Confirmation | 5 | That leader's echo, including a contested marker when required |

An immutable schedule retains the original public interval and the observable
`floor(n/3)+1` repetition count. Unknown wire kinds are rejected at offer
admission. Each immutable SET freezes its round window when created. Tasks must
match that source's round, repetition and leader and copy its exact deadline;
result handling and recovery use those original source facts. Later leaders,
context decoding and new attempts cannot renew an admitted bound.
`next_deadline()` also exposes the original union/inventory window during
population setup, before a native source has been created or prepared.
An early inbound offer retains its phase deadline while the client collects
inputs. After expiry its slot remains owned until the original rejection
retires.

Leader chains advance independently through dissemination, echo and confirmation.
A lagging leader does not impose an all-leader barrier between those phases.
Every leader must finish grading before round application. A phase source must
retire after all its original tasks become terminal before its next source is
created. Original TaskId/SetId capabilities are never reused.

An expired phase rejects new offers and contributes no remote vote. A population
whose preparation was never published is released locally; published preparations
retain their original host retirement obligation. Expired prefaces and leader
phases can advance without creating new native populations. Existing active tasks
still require actual cancellation and source retirement before advancing. The
public session deadline and grading quorums remain mandatory.
Unclaimed offers are rejected through their original listener when their phase
completes or expires, including before the client concludes. The offer holds
its capacity until the original rejection or listener retirement settles.

[Session ownership](src/session.rs), [initial reconciliation](src/session/preface.rs),
[gradecast decisions](src/session/gradecast.rs),
[task result intake](src/session/results.rs), the [round schedule](src/session/round.rs),
[source retirement](src/session/source.rs), [effect settlement](src/session/effects.rs)
and [session cleanup](src/session/retirement.rs) are separate internal modules.

## Grade and result decisions

The fault bound is `floor((n-1)/3)`. Grading uses genuine committed,
noncontested confirmation votes, with thresholds `n-faults` and `faults+1`.
A contested confirmation is bottom and supplies neither presence nor absence
votes. A failed direct LEAD does not invalidate sufficient matching CONFIRMs.
Final membership includes a value supported by at least
`ceil(nonzero-grade leaders/2)`; a tie includes the value independently of the
local base. Zero eligible votes provide no support.

Original strong quorum remains mandatory. Early stopping requires two adequate
repetitions under the same `n-faults` threshold. Final client output is Current
without locally inserted values or internal markers. These decisions follow the
[construction's agreement rules](https://grothoff.org/christian/consensus2016.pdf).
The selected C service grades using the ECHO referendum and starts final
iteration from the last evaluated ECHO output. Its thresholds and unfinished
timeout handling also differ.

## Effects and retirement

`Reconcile` preserves original prepare/accept/commit ownership and SET options.
`Written` acknowledges a composite local write. Matching SET DONE/FAILURE supplies
semantic terminal state; cancellation and deadline expiry cannot create a vote.
Input populations remain immutable while their operations are active. A remote
contested marker is exactly the three-byte wrapper, with an unused payload type
and no trailing data. Marker inference requires the complete SYMMETRIC
difference contract described by the [SET core](../gnunet-set/README.md).

Union and leader differences remain staged on their original task until matching
DONE. The scheduler applies one completed membership change per turn before
creating the next population. Failure or cancellation discards partial changes;
later physical source loss does not revoke a previously completed task. Echo and
confirmation ballots similarly count only committed tasks.
A removal must refer to the original local population. It never allocates a
new payload. A leader retains its own proposal population independently of
peer-only differences returned by its dissemination tasks.

Inventory size markers describe individual SET populations. Their sender is
checked against the matching inventory task. The official sender field is one
byte, so participants above index 255 omit the marker. CONSENSUS enables generic
SET Byzantine checks with a zero shared-membership minimum because gradecast
can compare disjoint populations. Confirmation and grading use their own
quorums.

Trusted `source_retired` settles that source's pending effect with its actual
Written/Unsent/Lost disposition and fails all unfinished tasks on it. Future
plans on the retired source fail without IO. Unrelated leaders and pending effects
remain intact. Its logical CloseSet debt still requires retirement. Listener,
PILS, shared-clock and whole-session failures retain their separate fences.

Effect settlement checks the disposition before consuming the pending effect.
`Written` cannot settle a cleanup action; a refused receipt retains its original
admitted EffectId and retirement obligation. `Retired` cannot settle a normal
write. Error dispositions `Unsent` and `Lost` require actual physical retirement
of any original resources, independently of their exposure certainty.

Client elements and type525 completion remain owned until whole writes. The
original listener/offers retire before public completion so a subsequent session
can reuse the same public hash. EOF after a known525 write is cleanup. The wire
contains no global run epoch; old native sources/channels must actually retire.

## Storage and diagnostics

One payload pool owns wrapper bytes; memberships and ballots retain stable
indices. Staged task differences retain only those indices. Their allocation
capacity remains charged until the owning task rows retire. Live sources, tasks,
offers, retained allocation capacity and CPU work
have independent limits. Bounded scans rotate fairly, park after blocked passes
and resume for actionable effects, results and expiry.

`failure_context` returns an inline copy captured before failure cleanup changes
phase metadata. It preserves the first original task association, completed and
pending grade counts, retained task states and the observed canonical time.
These diagnostics grant no capability or vote. First-cause/count summaries are
bounded. Current-source C↔Rust and native recovery qualification remains tracked
in [implementation status](../../IMPLEMENTATION_STATUS.md).
