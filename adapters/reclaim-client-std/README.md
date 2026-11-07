# RECLAIM native CLIENT

caller-driven local IPC adapter for the v0.29.1 active RECLAIM protocol,
using `gnunet-reclaim`
`9059e4313c5134a08a37ab341c9a0a180cd80094cc2f58abbe2135b2f35588ec`. It uses existing shared CLIENT `EndpointSource/Channel`, RuntimeClock and
Framed/OwnedFrame; it creates no Resolver, runtime, background task or service. Both Unix and TCP endpoint sources use the same connection driver.

`Client::new(&Instance, EndpointSource, Limits)` reserves bounded metadata and
subscribes to that source's clock. It opens no socket until driven. Public
operations: `store_attribute`, `store_credential`, `delete_attribute`,
`delete_credential`, `issue_ticket`, `revoke_ticket`, `consume_ticket`. Private keys enter as borrowed redacted `SecretKeyView`; there is no extra owned
key cache or key derivation. Objects remain opaque and serialization-level names
are not silently converted. Store relative expiration is a wire interval and is
separate from the caller's original local operation deadline.

Each admission returns original typed Operation; `request_id` reports its actual
RID. RIDs, including initial0, are never reused by a Client, even across source
replacement. Stable caller-owned Instance allocates checked unique private
owner/operation/epoch/control serials, so bounded dynamic owners may reuse one
Instance without leaking allocations or accepting an old token. Original Epoch
exists only after an attachment. `Queued` is queue admission;
`Written` means only a whole local write. Completion is either an ACTUAL checked
family/RID/source reply or an explicitly local outcome. No ACK is invented. Replies retain ONE zeroizing immutable frame copy, immediately releasing RX,
and expose borrowed typed `view()`. No secret/name/credential/capability Debug,
ordinary Clone/Hash, unzeroized extraction, or second parsed payload cache exists. Raw service statuses, including GNUNET_OK1 and the pinned C consumed-result
htons→uint32 defect, remain unnormalized. Missing ticket is not promoted to success.

`Iterator::new(..., ipc::Iteration::{Attributes,Credentials,Tickets}, ...)`
reserves one independent original MQ and START. All three support real
original NEXT and STOP frames. No operation CANCEL exists. At most one immutable
control is retained; NEXT requires START whole write and no unused item grant. Attribute/credential item grants become active only on whole original START/NEXT
write and are consumed by items. Ticket handling follows the actual
pinned `collect_tickets_cb`, which unconditionally advances its NAMESTORE cursor:
additional genuine tickets can therefore arrive without NEXT. They are delivered
one bounded frame per poll, without manufacturing credit or rejecting this C
behavior. No automatic NEXT is emitted. Callers may explicitly issue ticket
NEXT, with the public provider's own advancement/race semantics.

Iterator items arrive as `Progress::Item`; empty-key attribute/credential or
missing-ticket ticket responses are terminal replies. C can use those
same records on backend iteration errors, so they are not called an independent
success acknowledgement. Before exposing any iterator terminal Completion,
this adapter physically closes its original MQ. STOP is retired only on its
whole local write followed by physical source close; `ControlWritten`
is not a STOP ACK. Unsent START can be removed and physically closed with no STOP. A pending NEXT returns WouldBlock from stop: drive it or explicitly close. A lost iterator never reconnects/replays; create a new owner for a new snapshot.

`until: u64` on submissions/control methods is the ORIGINAL absolute monotonic
microsecond deadline in the supplied RuntimeClock domain. Every operation also
captures a native Tokio Instant hard deadline at admission. NEXT/STOP is capped
by both original iterator deadlines. `drive/poll` optional Tokio Instant is
observation-only and changes no operation deadline or cursor. Canceling a drive
future retains RX/TX positions. Ordinary `cancel(op)` removes zero-exposure
frames, ignores late nonreused RIDs after whole writes, and drains a positive
partial suffix only on its original socket. Its grace is fixed at
`min(first_cancel_observation, original_hard)+retirement_grace`; neither repeated
cancel, late polling nor clock changes can extend it. Late first expiry performs
same-poll native close if that original capped grace already elapsed.

Incomplete RX has an independent nonrenewable deadline fixed at its first
positive byte. Native operation/control/input/retirement expiration and native
Sleep registration run BEFORE awaiting the canonical clock, so subscription
revision-race Pending cannot suspend original hard closure. Canonical clock
sample/subscription/Resolver failure independently closes original IO,
then publishes the original cause/loss. An admission sample failure also closes
immediately and retains one bounded pending loss before allowing new admission. All physical close paths work without a healthy clock. Shared Channel physically
drops its socket but exposes no close errno; Loss is not a fabricated close-error
or remote-processing receipt.

General MQ loss retires all live old requests locally, preserving exposure;
old frames/requests are never replayed. Default reconnect=false requires explicit
`reconnect()`; optional replacement also creates a fresh Epoch and keeps
old completions tagged with their original Epoch. `recover_ports` explicitly
recovers failed shared ports; no implicit healthy-source claim is made. `close()`/Drop stops native ownership without sampling a clock.

Limits bound live rows including undelivered replies, total logical held/admitted
outbound bytes, complete frame size, syscall quantum, list objects, partial-input
lifetime and original suffix grace. Only one physical outbound frame and one RX
frame are retained per MQ. Queue-owned bytes are moved, not copied. Whole local
writes release their original outbound charge; stored undelivered reply memory
is bounded by operations*frame_bytes plus fixed row metadata. Caller-owned replies
returned by value are subsequently the caller's resource responsibility. The
shared Rust allocator has its existing allocation-capacity/OOM contracts; no
allocator overhead or kernel buffering is misrepresented as logical wire quota. Every syscall poll is bounded; the adapter also yields between nonterminal native
observations to avoid monopolizing a caller executor.

It contains all seven ordinary operations, a
positive-prefix cancel/drain with late old RID, source EOF/no replay,
attribute NEXT/natural terminal close, credential STOP, and two ticket pushes
without NEXT. It has finite outer waits and actor abort/join cleanup. It performs
no key arithmetic, private-file read/hash, credential/ticket backend, crypto or
storage operation.

Still missing outside this client: JWT/PABC parsing/verification and presentation
creation, ticket business implementation, persistence/resolution and a production
RECLAIM SERVICE/foreground. This adapter cannot make those functions available by
itself and does not enter any stopped subsystem.
