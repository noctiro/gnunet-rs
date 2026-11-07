# Native scalarproduct service host

This is the caller-polled SERVICE/SETI/CADET composition for the normal
scalarproduct-alice and scalarproduct-bob IPC endpoints. `Server::new` retains
default ECC. `Server::new_with_profile` explicitly selects ECC or the installed
Paillier peer profile. One private Backend action view drives the same socket
reactor, fair bounded original sessions, guards and independent cleanup. There
is no spawned task/worker, extra Resolver, self RPC, replacement epoch, private
wire or algorithm fallback.

The complete original IPC vector owns one Vec<Value>, then its selected core
adopts it once. Role/total/partial input, duplicate keys and zero coefficients
are checked before per-query crypto/dependency admission. Session-key leases
remain held until cleanup. Original ECC tokens stay original; original
Paillier Binding/Frame owners move without hash-based reconstruction. Each
computation's brands and SDK borrows remain on its pinned local future stack.

For Paillier Alice, the next original Bob multipart packet may already be held
while the previous copied chunk is still in cooperative decryption. A normal
Bob can finish its local reply handoff and close before that work completes. The private `can_drain_peer_input(source)` gate exposes only this original
source's reply-continuation phase after SETI DONE, with no Alice output
still owed. Together with the shared native held-packet path, it permits only
that already captured packet/cursor to retry ordinary profile-aware receive
after old math releases capacity. It does not authorize new native IO, a new
ACK, a complete transcript, a computed product or a successful client result. Original cancellation and canonical/native hard limits still apply. Complete
tail validation and the existing final-owned-input/math/IPC-write gates remain
required; an incomplete or malformed reply cannot succeed because it closed.

Enabling the original CADET dependency is local driver progress. If the
fair peer class has already run before a CONNECT or OPEN_PORT action first
activates it, the containing future wakes for another poll. Later polls that
only await the same connection report no progress; activation does not renew
the original native write/setup deadline or complete any protocol effect.

ECC's SETI application is SHA512(session), while Paillier's is raw session, as
the two active C producers require. Both scalarproduct CADET ports are raw
session. Actual listened Port and authenticated ChannelInfo.peer select the
owner; a matching header alone authenticates nothing. Native SETI CREATE/ADD/
LISTEN/EVALUATE/ACCEPT whole writes populate/activate the original set. O(1)
indexed population avoids a second key copy and quadratic walks. Real original
DEL_LOCAL events derive the remaining count; DONE seals that snapshot. C's unset DONE current_size field is not authoritative. SETI layout and native
hash-word byte order are explicit profiles. The original SETI listener remains driven after the set MQ's ACCEPT whole
write, until DONE/FAIL or cancellation, expiry, or source retirement. That local write does not prove the service has moved the incoming request
from its listener to the set; closing the listener then could reject the
request before ACCEPT is processed on the other MQ.

Paillier Alice polls one bounded shared Keygen before `ready`; Bob creates
no unused private key. The fixed startup target covers generation. Active
sessions retain their original Rc<KeyPair> mathematics even if the server drops
its shared reference on shutdown. Each later client has its separate unchanged
first-admission target. Normal callers poll until ready with signal/logger/
Resolver guards and yield between immediate CPU Activity turns. Ready proves
local admission and required shared-key readiness, not remote service health.

ECC uses its point/scalar/DLOG core. Paillier uses original-key
EncryptJob/DecryptJob/homomorphic arithmetic, standard signed32 masks and two
independent permutations, checked signed sums, exact-even division and full
standard signed MPI output. Paillier results never pass through ECC's bounded
i32 type. Whole local writes are not remote processing, Alice-result proof or
durability. Bob records only his last local reply handoff. Native client
status/MPI output remains a distinct original socket write.

An original multi-inner CADET packet retains its Delivery and byte offset. Processed means only a non-final inner was handled; receive_done is
written only after the final inner. If a peer closes after the complete required
reply was copied, local math can continue only through the explicit capability
and retirement API. The shared reactor first verifies every original outer-tail
byte, physically closes old dependency IO, and settles exact original ACK
Written/Lost/Unsent metadata. Unknown tails, missing data, wrong sources,
unsettled debts, cancellation or failed bounds keep the failure path. No close
is treated as DONE, a product or a peer ACK. ECC DLOG and Paillier decryption,
range and divisibility checks still run under the original deadline. No old
source is polled, reopened or acknowledged afterwards. The raw cause remains
independently in SessionReport.dependency_loss, alongside typed computation and
client-write facts.

Native guards precede canonical sampling, follow it, and run before each reactor
class. Whole/partial/unknown writes keep original identities. Clock-free physical
retirement precedes effect/local-end draining. A computation failure closes old
dependency IO before final failure output and does not inherit retired-source
partial timers. The original cause, dependency loss and cleanup cause stay
separate. Every owner is attempted during shutdown; an undrained original debt
immediately fences new admission. Drop uses the same physical close/drain path.

`Profile::default_host_limits` derives coherent selected defaults before explicit
configuration overrides. Default ECC retains its existing16-owner/65536-row,
8MiB core,16MiB session and256MiB plus256KiB aggregate headroom. Paillier derives operation,
work/count and core/session/global reservations from its policy. These
are quotas, not allocations of all maximum-size tables. Each input allocates
its declared count; every core capacity, frame, shared key and bounded
native-copy allowance is charged. Sources use one CADET MQ, one SETI set MQ and
Alice's SETI listener MQ per computation. Independent maxima need not fit
simultaneously. Selected CADET/SETI endpoints are fixed once and shared through
Arc; each session avoids copying the configuration table. Actual selected endpoint
capacities, server/owner/registry metadata and shared key reservation are deducted
before session permits. These checked reservations are not measured RSS,
allocator/OS memory or performance.

Known fixed-reference Paillier source defects in multipart-column copying and
local-versus-peer count are not reproduced; source-present Rust does not prove
unrestricted reference interoperability. The prior default-ECC static receipts
bind their recorded b07b baseline. This fresh shared-profile/local-retirement
increment passed selected offline macOS/GNU Linux/no-system compiler and
changed-graph architecture checks.
