# Generic SET core

This is the active contrib generic SET protocol, distinct from SETI and SETU. The default no-system profile exports public values and the official wire types. The explicit `alloc` profile adds bounded membership and original-operation
service owners. It performs no IO and takes entropy/compression through ports.

Each local set has one typed element namespace. Its fingerprint is the official
SHA-512 of native-order u16 size, native-order u16 element type and opaque bytes. Immutable payloads are shared by frozen operation/iteration views and lazy copies. A copy cookie selects the source membership at the connect, not prepare. Add admission prepares geometric metadata growth and checks the body and
service quota before changing membership; duplicate content adds no payload.

The union engine implements the old native-column 13-byte IBF, key derivation,
rotated salts, collision inquiries/offers/demands, 32 independent strata and the
full/missing-only return exchange. This is not SETU's IBF layout or negotiation. Normal raw strata are supported; compressed strata go through bounded exact
member decompression. The intersection engine implements the old count/xor,
fragmented Bloom and DONE exchange with the original snapshot retained for FULL
and REMOVED output, including both empty/nonempty roles. Actual ABI word order
and u64 alignment are explicit; no profile is guessed from a received packet.

Service handles are branded per original instance and independent of raw IPC
request IDs. Pending offers use the CADET listener port and peer, not the
payload app_id (the ordinary C sender leaves that field unset). Accept transfers
the same channel through a retained AdoptPeer effect. Closing a listener
retires unaccepted offers while accepted operations remain with their set. Every
admitted effect survives cancel and physical peer loss until its own completion. Peer loss can precede the separate ClosePeer receipt without relabeling that debt. A later redundant Unsent(Closed) cannot overturn an already proven protocol close;
EOF, source loss, deadline and invalid phase cannot manufacture success.

Final client DONE/FAILURE follows the algorithm outcome and original peer
retirement/output debts. `Written` only records the original native whole write
or applied local ownership action; it does not claim remote processing. Cancel
suppresses original future output and retires its original owners, with no replay,
private acknowledgement or renewed deadline. Clock-free shutdown retains actual
retirement debts. A native caller must continue to report their terminals.

Resource limits bound local membership, accumulated union bodies, filters,
rounds, records (including repeated input), original owners and output. UNION
charges its retained buffers and shared immutable views against the
service budget. Each sequential constructor/input/progress turn preclaims new
allocations from the remaining shared capacity, including full replacement
buffers and transient encodings while the entry owners are still alive. Claims
are not refunded inside a turn: moving an input or builder into a local variable
cannot hide its original charge. Actual final capacities are checked before a
new allocation is attached. Exhaustion follows the original terminal Capacity
path; it does not replay input, shrink the peer limits or serialize independent
operations. Output transfers preserve the same payload charge in its immutable
effect until that original effect settles. Intersection retains its conservative
future per-operation reservation. Actual membership/effect/owner metadata remains
charged, and failure keeps all still-owned buffers and original IO leases. These
are admission bounds; they are not a claim that every configured maximum can be
used simultaneously, a heap allocator guarantee or a measured RSS. Large IBFs are initialized in 4096-cell steps, built in 32-key steps, and searched
in 64-cell steps. Existing algorithm output is transferred before more CPU work.

Fair native effect selection uses `EffectScan` and `scan_effect`: at most 64
candidate/dependency checks per call, bounded binary searches over stable serials
and constant-time frozen dependency metadata. Ready advances even when that sink
is blocked. Pending preserves the scan. End requires reset; a frozen upper serial
makes each round finite despite new producers. Same-client frames, original
channel Open/Adopt/Send/Close, port ownership and listener/adoption barriers stay
ordered. The O(1) `effect()` convenience only exposes the global front and is not
a replacement for this fair native driver.

## Full transfer and symmetric results

The current source keeps two independent obligations when each endpoint has
legally requested the other's full set. A SYMMETRIC evaluator can request the
acceptor's full snapshot, as before. If a SYMMETRIC acceptor receives that request
while EXPECT_IBF, it issues exactly one reciprocal REQUEST_FULL and first waits
for the evaluator's complete original snapshot. The evaluator is also still
EXPECT_IBF after its original request; it fulfils this reciprocal request
without losing its own still-outstanding request for the acceptor's full set. After receiving that first FULL_DONE, the acceptor fulfils the original request
with its complete original snapshot. Both requested sets are actually supplied;
there is no repeated counter-request, role bit, private query or guessed remote
absence. This sequence also works for two Rust SYMMETRIC endpoints selecting full.

All full sends enumerate immutable original Snapshot members, including the
reciprocal response. Imported remote elements can grow/reorder the working union
but cannot enter the original owed snapshot or alter its cursor. The ordinary
single-request full receiver still returns only its original elements missing
remotely. The reciprocal receiver instead sends all its original members because
that exact full set remains owed. Full peer data establishes ADD_LOCAL;
a complete peer full-set boundary permits local-only original elements to become
ADD_REMOTE. ADDED mode reports only its own new elements. FULL/REMOVED remain
intersection-only public result modes and are refused for union.

Each original full request is sent/fulfilled once. Duplicate RequestFull/FullDone
or data after the peer's full boundary is refused. An early peer FULL_DONE can
record complete peer data while an independent local full response is still
unsent/partial; it never settles that native output or makes it timely success. No extra OVER is required from the C FULL_SENDING path, which actually destroys
its channel after receiving the return FULL_DONE. The reciprocal receiver waits
for all evaluator data before sending its own final response, so it does not
cause C to close while that original first-leg data is merely queued.

The final symmetric scan is bounded to one original member per CPU step. Only
when both full boundaries are known, first_error is absent, every original send
is settled, and no input/IBF/strata/offer/demand/builder debt remains can a normal
physical peer close leave this scan active. It then performs local/client work
only. Gone remains a source fact and never permits new peer IO. The
Service retains the same original expires in tick/next_deadline until local work
finishes; it creates no fresh timeout. Lost/Unsent still fails through the original
terminal path even though it also settles peer_pending. Drained alone is not
proof. Early close/unknown original sends cannot upgrade after later settlement. Final client DONE still uses the original peer retirement, pending output
and same-client FIFO; no native Written is called a remote processing ACK.

Normal default SYMMETRIC still prefers delta. Explicit FORCE_DELTA refuses an
actually received full strategy, and FORCE_FULL refuses actually received IBF;
contradictory local force flags are invalid. The peer operation request carries
neither side's local result mode/strategy, so a local acceptor cannot compel an
unmodified C evaluator to honour a policy it was never told. Such a strategy
conflict fails, without pretending the opposite strategy met the caller's option. No additional restriction is applied to ordinary non-forced negotiation.

Byzantine full transfer rejects an exact element already received from that
remote operation with Replay before changing its record count, membership or
result queue. The first receipt of a common original element remains legal;
honest overlap is not classified through a fresh/total heuristic. A blocked
first receipt is not marked remote. Ordinary full transfer keeps its existing
repeated-element behavior under the configured record bound. This check does
not prove the remote set's completeness or repair the C implementation's
heuristic and result-reporting limitations.

### Unmodified C profiles and source qualification

The legal counter path is limited to C's EXPECT_IBF handler. No request is
sent after C has entered FULL_SENDING or the IBF inventory path. Its public
FORCE_FULL/FORCE_DELTA options explicitly warn of Byzantine detection. A concrete
C source example is A386/B385 subset with Byzantine mode: after reciprocal full
transfer, its 385th common returned element triggers the duplicate/fresh check. That C profile can fail; this implementation does not mute its errors or claim
all mode/option/Byzantine combinations succeeded. The C full algorithm itself
also omits its client's ADD_REMOTE in SYMMETRIC; this forward does not add Demand
to repair the C process's own notifications or treat those missing results as
Rust evidence. A correct Rust local result is not proof of C API completion.

C send_full_set iterates its current content table without the generation filter
used for its initial operation view. Therefore the declared original-snapshot
mixed profile additionally requires no concurrent mutation of that C Set during
the operation. Rust always sends its frozen Snapshot; it does not reproduce
this C defect or assert a FULL_DONE alone proves C respected its generation. No extra generation/identity ACK or private verification wire is invented.

The previous baseline has selected static integration receipts. They do not
qualify this new reciprocal-full source. Its three new/replacement pure source
cases cover mode/role/empty-set transcripts and a legitimate local-only close,
early/duplicate FullDone/request versus unsettled original writes, and explicit
strategy conflicts. They were only formatted during authoring. These source cases remain
unexecuted. Actual full
interoperability, resources/performance and whole GNUnet acceptance remain open.

## Delta completion authority

The current IBF role determines who may close a completed delta channel. After
the passive endpoint has received the decoder's DONE and satisfied its own
demands, it sends its own DONE and enters PassiveDone. This records its receive
result while preserving the channel: an earlier inquiry can still produce a
legitimate later demand for its original data. It continues answering such
demands in order. The active decoder closes only after its own demands are
satisfied and its original output is settled. The passive endpoint then observes
that peer retirement. An actually received official OVER can also permit
its existing terminal close; no new OVER sender or mandatory extra message is
introduced. Current algorithm roles, including IBF role reversals, determine this
authority independently of the original evaluator/acceptor role. Full-transfer
completion, first failures, original deadlines and output leases are unchanged.

The two-node API profile after the capacity correction exposed this earlier
closure: passive Alice emitted DONE and immediately closed while active Bob's
legitimate demand was still in flight. Alice reported DONE but Bob reported
FAILURE. The source correction does not relabel that failed run. A new pure
source transcript uses those observed ordinary type25 bodies, preserves each
wire direction's FIFO, delays consumption of a written offer/DONE, then verifies
the passive endpoint remains available for the late demand before the active
endpoint closes.

## Shared UNION capacity

A normal two-node C public CONSENSUS API component profile reached the Rust
CONSENSUS and generic SET services but failed at the second simultaneous UNION
admission. The former default reservation charged about 53.5 MB of hypothetical
maximum resources per tiny operation against a 64 MiB service budget. CONSENSUS
legitimately needs concurrent operations on the same immutable set. This source
change keeps that budget and every per-operation algorithm limit, while charging
UNION owners and preclaiming each new allocation. It does not qualify the
failed profile as successful or change agreement, deadlines or wire behavior.

Two added pure source cases describe the observed default-budget concurrent
admissions and an advertised order20 IBF refused by a smaller explicit shared
budget before its cell allocation, retaining the original failure, expiry,
client and admitted retirement effects. They were formatted during authoring;
no test, native product, protocol actor, crypto, benchmark or network run was
performed by the source authors. Runtime interoperability and performance for
this correction require their own results.
