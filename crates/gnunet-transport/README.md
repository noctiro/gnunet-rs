# TRANSPORT

The base `no_std` API decodes and encodes current official communicator IPC and
TNG network frames. `alloc` enables an owned bounded engine. Signing, entropy,
UTC-microsecond time, durable address effects and exact local IPC owners are
explicit ports; the engine has no socket, timer, identity-file or C backend.

`own_wire` provides the official purpose29 address certificate region and public
PEERSTORE value codec without an allocator. The signed region is80 bytes: an
8-byte size/purpose header, an8-byte generation time and SHA512 of the original
native address without its terminating NUL. The public value uses padded standard
base64, unsigned decimal fields and a final NUL. Network classification and the
PEERSTORE record expiration remain unsigned metadata; signature verification
cannot promote them into authenticated claims or prove address reachability.

With `alloc`, each admitted communicator ADD receives a private `AddressLease`,
including identical ADDs with the same wire address id. `Certificate` retains one
immutable purpose29 offer and its original signature/commit phases. Its host
supplies a durably reserved generation timestamp and port outcomes. Unknown commit outcomes retain the original candidate and block fresh effects
until explicit recovery. Cache expiry preserves the original forecast, including
zero and FOREVER. Independent finite renewal uses a 30-second floor and a
12-hour cap; a clock overflow returns an error before installing a MAX timer.

`publication_record` distinguishes a newly verified staged value from an earlier
known committed current. Reuse of a current requires its original live resource,
authority and strictly future cache expiry. Pending signing/write/unknown phases
block fallback to an old current. A caller must also check the original lease is
still in its desired resource snapshot. This permits an unchanged member to join
a new member's projection, and aggregate HELLO renewal without re-signing every
purpose29 value. The separate `current` view remains history for withdrawal and
does not grant publication authority on its own.

`own_hello::HelloCandidate` reuses the common binary HELLO encoder and explicit
normal v0.29.1 signature profile. That profile authenticates metadata only. Preparing or verifying a candidate performs no I/O or storage. A known committed
nonempty candidate exposes a finite12-hour renewal deadline anchored to its
original preparation; Writing/Unknown do not authorize a replacement. This also
covers FOREVER communicator forecasts. An empty managed
projection removes this publisher's record; it does not store an empty HELLO
with a future expiration. `PublicationBounds` checks the complete public
PEERSTORE envelopes as well as PILS output before the new publisher can admit
work. The existing runtime's FEED owner and external observation limits retain
their separate behavior.

These pure certificate/candidate owners have Rust lifecycle tests. The host's separate
fenced managed Journal adapter and native foreground publisher coordinate these
owners with PILS and public PEERSTORE. Fresh official C interoperability and
complete Node acceptance remain required work.

The implemented engine covers direct queues with advertised MTU >32, including
reliable communicators and official1216 acknowledgement/retry over unreliable
ones. Registration preserves Unknown0/Reliable1/Unreliable2 values; the
unknown guarantee takes the same conservative acknowledged path as unreliable2. Official1214 fragmentation and1217 cumulative attempt ACKs retain distinct IDs. Queue setup alone does not announce CONNECT. A fresh challenge/signature/nonce/timestamp must
verify, or a new same-peer queue may inherit a sibling's still-future proof. Inheritance does not persist a newly authenticated address or create another
peer CONNECT. Expiry, last-route loss and physical owner loss retire old state. A tiny queue may remain available beside a larger validation/control route;
generated without-FC controls use an actually fitting route and are not privately
fragmented. An unusable first route cannot starve a later fitting one. UDP
production communicator, DV routing and complete-node acceptance remain separate capabilities; accepting a characteristic is not proof of a UDP node.

Each outgoing original owns immutable zeroizing payload. Fragmented originals
keep their8-byte message UUID and offset across MTU changes; each1214 attempt
gets a fresh16-byte ACK UUID. Cached1216 retries may reuse their ACK UUID. Local
opaque MIDs identify separate communicator handoffs. Storage/entropy/metadata/counters and the first local
CORE credit are preflighted before committing a fragment. Exactly one SEND_OK is
returned per admitted original, never as proof of remote delivery. Closing its
CORE owner cancels its not-yet-admitted attempts even after credit was returned. Already admitted attempts may still reach the peer. Original communicator,
peer/qid/route generation/MID remain authoritative for1210; retired/duplicate old
callbacks cannot give a replacement credit or tear it down.

A direct Actor transfer records Job retirement separately from normal
first-pass completion. If that Job retires after only a prefix was sent, every
chunk must end before the local outcome becomes `Incomplete`. The successful
prefix retains its original1210 coverage; the unsent suffix is not an unknown
native packet or a source-loss fact. Late chunk callbacks keep their original
owner, and failure/source loss takes precedence. Normal Job completion
with missing callbacks remains pending; it cannot become `Incomplete` merely
because a caller later requests cancellation. The business query
`dv_transfer_completion` uses the same gate as metadata take: the original Job
must have ended, the local outcome must exist, and no original parent SendRow
may remain. A local Written result with an active remote-ACK/retry Job is not yet
a completed transfer; deadline cancellation stops only that original Job and
never fabricates its remote ACK.

Queue packet grant and in-flight attempts are independent. SETUP starts a finite
budget; each1209 consumes one. SEND_ACK1210 retires only that attempt. UPDATE1222
adds finite grant, while MAX explicitly selects unlimited mode with sentinel
balance MAX. A finite0 update leaves that mode with finite MAX; subsequent finite
adds use checked arithmetic. Overflow of a fully decoded known-queue update
returns `ReceiveOutcome::Rejected` carrying its original client/peer/qid/cause,
without committing any queue metadata or creating a wire ACK. That original MQ
can continue, including other peers; a valid update or DOWN/recreation recovers. These overflow/mode boundaries deliberately avoid the reference C implementation's
native modulo `q_capacity += q_len`; they do not claim stepwise wrap equivalence.

Receive reassembly is bounded globally, per peer and by declared body+bitmap
bytes. Identical overlap/out-of-order input is supported; conflicting overlap
fails before mutating retained coverage. The original first-fragment expiry is
four minutes and duplicates cannot extend it. Completed storage leaves the table
before inner dispatch. Legal reassembled controls use their network handler;
nested fragment/reliability/DV boxes and unsupported families never become CORE
payload. Complete payloads retained for CORE capacity own only their final
original communicator FC token. Partial-fragment1203 callbacks and1217 attempt
ACKs remain distinct and assert neither complete assembly nor delivery. Original, reassembly and Held bodies wipe on release, expiry, link loss or
owner teardown.

ACK parsing accepts the entire legal nonempty u16 extent (up to2730 entries of
24bytes), independent from the engine's bounded64-entry pending/batching policy. Each entry preserves its opaque UUID and BE64 delay; the BE32 prefix is a counter,
not a reserved field. Bounded ACK pressure may lose an old unsent ACK, like loss
of a network control packet. Reliable direct transmission does not await it. Unreliable acknowledged
transmissions retain original payload and remote records until settlement,
explicit cancellation/loss or bounded resource expiry.

Flow uses official1221 fields and the default128KiB cumulative grant. On accepted
FC it anchors `(reported outbound_sent, actual locally released bytes)` and offers
`DEFAULT + reported + newly released bytes`. This equals C's
`DEFAULT + used + (reported-used) + later_release` without signed/wrapping
arithmetic. Sender-time filters stale paths first; decreasing sender sequence
resets our outbound debit. Reverse/duplicate reported byte counts may be legal
when the opposite sequence reset and are not given a new monotonic restriction. Reports correct wire grant only: they never release RAM, deliver payload,
or complete an operation. Checked overflow leaves flow fields intact, drops that
remote message in isolation and permits later normal recovery. A later lower
grant cannot revoke already-in-flight data; receive admission checks actual
retained capacity instead. Control traffic has separate bounded resource reserve
and may progress with ordinary byte/CORE windows closed.

FLOW's `sync_ready` is NAT-burst synchronization metadata, not an acknowledgement
request. Direct peers may keep it false while their windows are current; that
alone does not schedule another FLOW. Initial announcements, changed grants,
stale window echoes and blocked-window recovery still request updates. The existing100ms minimum interval,150s keepalive and burst metadata processing
remain unchanged; this does not change padding or introduce cover traffic.

CORE RECV_OK is aggregate capacity, without an operation ID or wire generation. Four is the initial window and a fanout can take it below zero. Unknown/lost-link
grants are harmless; a current positive grant is never attributed to delivery of
a particular new operation. Communicator acknowledgements preserve their exact
original owner/token. Snapshots expose bounded resource counts and a last remote
drop reason without retaining payload or keys.

Official CORE SEND permits65495 inner bytes. The48-byte outgoing communicator
prefix and88-byte incoming prefix have distinct limits65487/65447. Fragment sizing
fits both IPC envelopes; complete CORE sends65488..65495 are supported. The normal C public incoming allocator narrows its total size to u16 without an
overflow guard, so an inner65448 call is unsafe in that implementation. That C
boundary is source evidence, not a claimed successful oversized C API operation.

Unreliable originals live in the private outbound owner rather than a C fragment
tree. One immutable zeroizing body plus a bounded settled-byte bitmap supports
flat retransmission and MTU changes. A retransmitted1214 uses fresh attempt UUID
with stable original message UUID. Cached1216 may retain its UUID; a delayed ACK
for the whole box can still confirm the same original after it changes to
fragments. Once fragmented, it stays fragmented if MTU grows. ACKs match the
original peer/job/byte range and can arrive on another queue or communicator;
wrong-peer/unknown/duplicate ACKs do not complete another original. Confirmed
coverage is never resent merely because another range's ACK is missing.

Local1210 and remote1217 are independent. Remote ACK can settle the body before
its original MID callback; that local debt still drains exactly once. A local
callback alone cannot settle the body. Retries consume packet grant and wire
bytes again. The first local CORE SEND_OK is returned once, independently from
remote delivery. Preference bit16 permits best-effort raw/fragment admission
without retaining remote-ACK state. Waiting for an unreliable message's ACK does
not serialize later heartbeat/handshake traffic behind it. Reliable fragmentation
keeps its existing admission order.

Remote metadata has a global `Limits.messages` bound, at most four delayed UUID
aliases per span, per-peer quota min(32,ceil(messages/2)) and per-original quota
min(8,ceil(messages/4)). A full original quota still permits due retries; it must
not turn a missing ACK into an unrecoverable fresh-fragment stall. Other originals
and peers retain remote-record space within these quotas. This does not isolate
shared payload/job budgets: callers may still exhaust those shared bounds. Pending original bodies obey the payload budget. Outgoing
settled-byte bitmaps are a separate metadata class bounded by messages*8192 bytes;
`retry_bitmap_bytes` reports current bytes. This avoids a circular wait
when payload reservations fill their budget before first admission. Incoming
assembly bitmaps retain their original shared receive budget. Other metadata is
reserved separately, and none of these logical budgets is an exact RSS bound.

The supplied canonical microsecond clock drives a minimum40ms RTO, default4s,
exponential delay capped60s, and a four-minute original retention policy. This
expiry is a Rust resource boundary, not a wire deadline or successful delivery. Unreliable local callback records expire after5s without restoring finite grant;
late original callbacks remain harmless even after their bounded tombstone was
evicted. Actual Unix tests wait5.1s on clock samples, retire/replace CORE
owners, and evict callback history through260 sends before checking another
peer still progresses on the same MQ. They are Rust IO evidence, not C or UDP
interoperability. No absolute exactly-once promise is made: the reference may
redeliver1216 after ACK loss, and1216→1214 has no shared receiver-side logical ID.

A transmission preflight resource refusal retains the immutable original and is
observable as `ReceiveOutcome::WorkDeferred` or `WorkStatus::Deferred`. The input
has already been consumed and may have committed FLOW/grant/local-callback state;
it must not be replayed. Its diagnostic operation serial and peer confer no ACK,
queue or cancellation authority. `deferred_work()` exposes bounded retained causes
without allocation. Normal receive/tick skip blocked jobs; only an explicit
`retry_deferred` reattempts them. Unrelated originals, peer IO and scheduled control
work remain runnable. Retirement/expiry/owner loss still erase the original. This resumable boundary covers TX preflight, not arbitrary handler, persistence,
framing allocation or system failure. Those errors remain explicit supervision
causes and may follow input commit; callers must choose a policy without replay.

The pure TRANSPORT owner accepts the official application1302 address-validation hint. It selects an already registered communicator by its original prefix and emits an official1206 CREATE with an immutable address, expected peer and unique opaque request ID. The native caller retains the connect future; successful local admission and CREATE_OK do not authenticate a route or prove delivery. Actual QueueSetup and the existing signed1303/1304 reachability exchange remain required before CORE sees a connected peer.

Application validation is fire-and-forget. Unknown prefixes, duplicate pending/existing addresses and admission pressure may be declined without a response, as the public API permits. Original pending creates occupy a separate finite pool bounded by `control_messages` and `control_bytes`; these limits also continue to bound ordinary control work separately. Pending creates retain their original communicator-MQ authority through positive CREATE_OK, until matching QueueSetup, explicit CREATE_FAIL, physical communicator retirement or a local60second admission expiry. Request IDs never reset across communicator reconnects in one engine; exhaustion declines further hints rather than aliasing an old ID. The application stream may close after its hint is accepted without retracting that service-owned work.

This codec/owner adds no socket, resolver, task or NSE dependency. Application suggest/cancel messages1300/1301, broader discovery policies, production foreground integration and the remaining complete-node obligations have separate scope. The additional bidirectional test carrier only supports explicit numeric loopback TCP addresses and preserves the original CREATE result across IPC backpressure.

Official application1300/1301 connection demand has separate bounded metadata
and private original discovery leases. Background/zero-bandwidth requests still
seek a connection; cancellation and application MQ loss retire only their own
request. They do not retract already admitted communicator attempts or established
routes. Duplicate starts on one MQ and unknown cancels are protocol errors. A
new physical MQ needs a fresh request, and old discovery capabilities cannot
address it. Preference bits are preserved without promising bandwidth allocation.

The host explicitly drives `Server::discover` alongside IO/ticks, with separate
engine time and expiry-checking UTC. Address enumeration is caller-driven and
bounded. Current journal discovery reads only the requested peer's unexpired
communicator URLs and verified029 HELLO metadata, converts URI schemes to official
communicator prefixes, and still requires full communicator/signed validation. Its HELLO parser policy is65535 input bytes,8192 address bytes and128 addresses;
records outside this local policy are skipped. A continuation moves beyond
unsupported candidates and permanently oversized addresses; temporary output
pressure retains its original position. Retry delays are local Rust policy, not
C scheduler compatibility requirements. Complete foreground/Node discovery and
normal C application acceptance remain separate until actually verified.

The fixed suggestion table has its own bound from `Limits::peers`. Refusing a
request at this bound retires only the submitting MQ; allocator or storage
failures keep their distinct supervision causes. Old/foreign discovery callbacks
are rejected before advancing logical time for another current request.

The optional allocation-backed engine also supports asynchronous address-validation
signing. `Signer::validation_mode` selects an immediate capability or a retained
original effect. Deferred effects keep an engine-branded token, original physical
communicator and route generation, peer, local signer,48byte purpose35 region
and unchanged echoed origin. A separate fixed-metadata pool is bounded by
`control_messages` and `control_bytes /48`; full admission may decline one
challenge without replaying its consumed IPC frame. An unclaimed request survives
a signing-port refusal. Claim it only after service admission, and return
the signer/signature through `complete_validation`. The engine verifies
the original snapshot and current original route before enqueueing. A local
capacity error retains the effect; successful enqueue is not physical write or
remote delivery. Queue/MQ retirement and an explicit local60second retention
limit retire original effects, including claimed ones. The outer runtime must
cancel their original service operations; copied partial bytes must drain or the
whole physical MQ must close. No private wire fields or C ABI are introduced.

The new noalloc `dv` module implements current1218 learn and1219 box framing:
152-byte learn prefix,96-byte hop records,86-byte box prefix with a24-byte
XChaCha nonce,104-byte plaintext prefix, and exact purposes37/36/30. Structural
views grant no authenticity. `Learn::verify` verifies the initiator and every
hop against predecessor/successor/challenge binding; `Plaintext::verify_signature`
still requires a separate successful AEAD operation before attribution. Forwarding preserves encapsulation/nonce/MAC/ciphertext/orig_size and bounds all
skipped hops, slicing ciphertext from the received frame length.

`dv::routes` uses caller-owned fixed directories and opaque instance/serial IDs. Signed remote monotime, monotonic local scheduling and UTC are separate concepts. Own returned routes require a matching actually-written live discovery nonce;
passive signed paths remain unconfirmed and have no fabricated RTT. Replay-source
loads and STORE results are explicit matching generation-bound barriers before
passive path admission. A newer pending or committed source watermark only gates
new packet admission: an already admitted signed inverse route retains its exact
RouteId, original expiration, Passive freshness and unknown RTT until actual
source loss, expiration or accepted path replacement. Older incoming LEARN stamps
remain rejected after the durable floor advances. The book supports at most3
paths/target and17 path peers (one direct receiver plus16 box entries), rejects
loops, and checks direct reachability on selection. The standard DV actor
owns the KEM/AEAD, replay and durable provider; the TRANSPORT Bridge publishes
only its admitted route leases to the Engine. Pure route declarations are not
native write/store receipts or evidence of complete runtime interoperability.

Peer liveness expiry is a one-time transition for each inbound-activity
period, independent of direct/virtual link state. It invalidates reachability
before validation sends while preserving any pending original challenge nonce,
first/last timestamps and retry target. A route with no pending challenge starts
one bounded recovery attempt. Later ticks retain the existing one-second retry
and five-minute unconfirmed bound; only inbound resets the expiry latch. This source fix adds no wire field or peer-authentication proof.

`monitor` implements the active ordinary TRANSPORT observation boundary over the
same Engine. It owns physical monitor/listing requests and bounded original
response FIFOs, with exact standard wire codecs in
`gnunet_wire::official::transport_monitor`. Actual queue snapshots/changes and
read-only host-supplied current Actor paths grant no routing, authentication,
CORE membership or delivery authority. A failed/slow original observation source
is retired with its cause rather than losing an update and emitting a fictitious
completion. One-shot completion follows full original selected enumeration. The ordinary host uses its existing native IO deadlines and Reporter. Public
observations and the current-source DV bridge are source/rustfmt preparation;
this entry is not runtime, performance or official interoperability evidence.

Normal direct transmission preserves the first eligible physical communicator
owner, then honors the highest advertised queue priority within that same
owner and peer. Equal priorities keep their original order. This makes the
ordinary UDP BOX queue (priority1) usable once its ACK grants provide
credit, while retaining the KX queue (priority0) as fallback when BOX is empty
or otherwise ineligible. Credits remain packet counts and are spent only by
the existing selected-queue commit; priority creates no window or delivery ACK.

Every existing current-owner, peer, finite credit, route-binding, validation,
clock and control-MTU filter remains in force. Explicit route-bound validation
controls retain their original route. Unbound controls use priority only among
queues which already fit that exact control; they gain no fragmentation or
validation bypass. Priorities from unrelated physical owners do not override
the existing communicator choice. This is a Rust scheduling policy within the
official public priority contract, not a claim to reproduce C scheduling or to
explain a particular previous UDP timeout. The fixed C UDP implementation
advertises KX priority0 and BOX priority1; its current TRANSPORT priority helper
also has implementation-specific communicator-prefix conditions. New public
Engine regression source covers outgoing queue IDs, finite grant
exhaustion/addition, same-owner preference, foreign-owner isolation, bound
validation and control-MTU fallback. Source presence alone supplies no execution,
normal UDP BOX interoperability or performance qualification.

Virtual path reachability follows the same installation lifetime as its
transmit path. Withdrawing the final path removes only that source/peer's virtual
visibility and refreshes the original CORE/payload gate immediately. The Engine
preflights the existing notification/FC/CORE-credit output slots before this
withdrawal; a slot refusal leaves the original path intact. Later allocation
failure during refresh encoding still returns the original error with
reachability revoked, for source retirement; this is not an all-allocation
transaction guarantee. An eligible same-peer replacement installs the new path
atomically, marks old staged/admitted attempts canceled and preserves the live
CORE connection, existing Jobs and their original deadlines. Original Actor
claims and callbacks remain tied to the old path and retire on their own owners. Signed inverse paths remain passive; installation does not invent a local probe.

Standard1217 reliability acknowledgements also use current virtual carriers for
ultimate peers with no physical communicator queue. Batching considers currently
usable physical queues and the virtual MTU, and the ordinary control send
path rechecks the selected carrier. ACKs retain only received UUIDs and
receive times, with the existing64-entry limit and byte budgets. Each batch uses
an ordinary unique Job serial and a finite expiry derived from its earliest
original receipt plus the existing fragment retention interval. A later smaller
path cannot renew an unsendable ACK Job indefinitely; expired best-effort ACKs
may be dropped, and genuine retransmissions create their own new observations. This source behavior and pure trusted-host wire fixtures do not constitute
native/C-peer or four-party CONSENSUS interoperability evidence.
