# Native CADET application IPC

`Client::new` borrows a pure Instance and fixed port/channel metadata, plus an
explicit EndpointSource and native Limits. Poll `Client::poll` or `drive` from
the caller's runtime. No background task, hidden Resolver, private handshake or
unbounded payload queue is created. `clock()` returns the original shared source
clock for containing owners.

`listen`, `open`, `send`, `destroy` and `receive_done` retain one original
immutable outgoing frame. `Step::Written` confirms the local full write;
`Step::Credit` grants a local send slot. `Step::Data` owns original received IPC
bytes and its processing token. Waiting-future cancellation preserves cursors. On physical loss, `Step::Lost` retains the original cause and pending exposure;
only logical listening ports reannounce after reconnect. Channels and payloads
require new explicit application work.

`inspect::Inspector` gives each peer/tunnel/path query its own MQ. It emits
original frames incrementally and completes only on the matching official END. EOF is interrupted; partial results remain in Report. The current official C
service has no GetChannel handler, so no working operation is fabricated for it. `gnunet-cli cadet --help` documents the streaming command entry points.

`cadet_block_loopback` is a test/example driver for two Rust clients through an
unchanged official v0.29.1 CADET daemon's own-peer path. It exchanges official FS
140/141 frames, authenticates a DBLOCK and checks management END records. This is local service IPC evidence; cross-peer tunnel/session interoperability
and the full independent Rust CADET service remain incomplete.

`server::Server` drives the independent application SERVICE core over actual
accepted streams. The caller supplies configured listeners, admission policy,
bounded tables/shared payload buffers and the canonical clock. Each MQ retains
its original input, immutable output and partial cursors across canceled waits. Positive output and complete writes update the pure owner before observation;
physical retirement precedes detach. Local loopback uses port ownership,
send credit and application receive_done.

The caller owns that Server and its application pools. `node::Parts` borrows it
for one peer coordinator lifetime, so peer construction failure cannot consume
the long-lived application owner. Explicit normal cleanup remains in the caller;
Node's Drop still closes application MQs when its peer debt was not explicitly
retired. Explicit `retire_peers` pauses application IO while independent peer
sources and original effects drain; `release_applications` requires the actual
Node barrier, and the caller also retires its independent signer. A released Node
cannot poll again and its Drop preserves the application's original MQs. The pure identity-cut barrier preserves logical port handles and established
loopback pairs, rejects remaining dispatched opens/bindings before mutation and
recomputes current port challenges without changing frozen native output.

Peer operations remain explicit `next_open`/`next_send`/receive/close effects,
bound to peer owners and their completions. Without a peer backend
there is no remote Ready or credit. Management serving still requires real
coordinator state; known unsupported requests return a protocol failure rather
than a fabricated END. Capacity-blocked input stays retained in wire order;
the caller must apply a bounded retirement policy when later requests on that
same MQ would be required to free its resources. `Stopped` describes local MQs,
not external peer-effect quiescence.

`connection::Bridge` separately owns a CORE client and fixed peer/send maps. Actual CORE generations authorize neighbors, and each immutable connection frame
binds one SendId. Only its per-send physical receipt exposes/completes that
frame. An old partial send drains before a replacement peer generation receives
a new neighbor. Committed input effects use mandatory synchronous callbacks;
transactional capacity refusal returns the original input as explicit packet
loss. Discovery, signing, KX/channel orchestration and connection timers remain
the containing coordinator's work.

A false-to-true local CORE request-availability transition schedules the same
original Bridge/Node owner once, even if the Book has no frame yet. The Node's
channel class may have just refused to prepare an ACK or DATA while that neighbor
was busy; it must reconsider the newly available source without waiting for
unrelated network input or a route timer. The bridge compares the exact original
live Book neighbor state with current native admission availability. Repeated ready observations do not wake again. This grants no wire SendReady,
remote acknowledgement, extra queue slot or changed retry deadline.

`identity_dh::Connecting` observes and verifies its PILS identity before
binding one shared `identity_dh::Port`. Fixed job and context tables bound
concurrent DH operations and reject copied old requests after slot reuse. Private
results remain tied to their original operation, identity, epoch and deadline;
canceling a wait does not retire copied request bytes. The standard C PILS
component example checks both initial KX roles and Rust AEAD without reading a
private key. Its Book/CORE link is explicitly modeled, so it does not prove C
encrypted peer interoperability. Dynamic controllers own non-Copy context
leases from caller-supplied fixed registries. Scopes borrow stable domains and
registry rows, so controllers can move and retired rows can serve new peers
while old tokens remain stale. The shared native DH source similarly owns an
explicit binding lease. Logical revocation prevents new admissions; original
native jobs retain their separate drain obligation. Registry availability
does not assert physical quiescence. The node coordinator supports
directly connected CORE peers and explicitly admitted verified DHT routing
candidates. The ordinary foreground supplies the DHT discovery owner;
explicit `[cadet-rust] PEER_CORE=NO` selects its local-only profile.

`management` supplies bounded PEERS/TUNNELS/PATH snapshots. Node captures actual
Book/controller/channel state and binds the completed snapshot to the original
MQ/query. Private management and application output origins remain separate. Partial writes retain the original frame and report; only matching full END
writes complete a stream. Another management MQ or ordinary application can
continue while one inspector is slow. Server without an explicit provider keeps
management Unsupported. GetChannel remains Unsupported, matching the pinned C
service's absence of a registered handler. These metadata snapshots are not
authentication or peer-processing receipts.

`node::Node` owns the application/connection/DH drivers and borrows explicit
fixed registries and reusable key/payload pools. `poll_signing` drives one separate
node-wide `signing::Signer`, preserving original purpose38 jobs and native
retirement. `monotime::Store::reserve` commits a range before Node consumes values
with `take_next`; no disk sync runs inside socket polling. Original CORE sends
have independent finite lifetimes and hard retirement bounds. Logical revocation
does not settle physical IO, and full CORE writes do not acknowledge peer data.

A new sign admission selects the current verified PILS
announcement only after matching the original MQ epoch and original peer-key
anchor. This accepts a refreshed same-key HELLO revision without changing that
anchor, a previously admitted job, its purpose, expiry or fixed hard-stop target. Exact PILS admission and existing signature verification remain mandatory;
changed-key or changed-epoch sources keep their original refusal/close behavior. The corresponding source regression consumes newer same-key announcements before
and during an original signing job.

An two-foreground file flow uses unchanged C PILS and a controlled CORE
IPC relay. It exercises signed CREATE, KX/authentication, encrypted reliable
channels, application receive completion and complete CHK validation. It does
not establish original C CORE/underlay, C CADET peer or whole-node interoperability.

The Node exposes original pending-discovery tickets in bounded slot order, an original native opening target, exact-current checks and a narrow public-path admission method. Projection first checks the same exact live application Open phase as target lookup and admission: an application EOF/close cannot briefly reappear as discovery work while its peer owner awaits a later fair retirement turn or an old GET finishes its stop. Admission validates the original generational app open and its original logical/native bounds, local/remote endpoints, no cycles, Book path capacity and a current first-hop neighbor. It uses the same Book CREATE, monotime/signing and tunnel KX rather than returning an authenticated-connection receipt. The ordinary service verifies DHT HELLO/path signatures before invoking it. Open native bounds are minted when the original application open is taken, not when a lookup is retried or a result arrives. These source/API changes have no new private wire or storage representation and are not runtime/interoperability acceptance.

The standard `CADET_DROP_CADET_MESSAGE` diagnostic request is accepted on the
ordinary application MQ for its original channel. The pure/native client API
retains its original immutable transmit token and has no service ACK or replay
across source loss. One bounded opaque two-byte selector replaces the previous
selector; zero clears it, unknown channels are ignored, and the next matching
peer plaintext is discarded before encryption or CORE queueing. The fixed
C daemon compares these bytes directly against the encoded peer header; they are
preserved without a host/network-order reinterpretation. Local loopback traffic
and unrelated channels/packet types do not consume it.

An explicit `Emission::Dropped` is separate from `Sent` and physical failure;
exposed attempts cannot be relabeled dropped. Reliable DATA/OPEN retain their
original MID/payload and bounded retry; dropped ACK/OPEN_ACK/DESTROY consume only
the selected original control attempt. Node reports diagnostic drops
separately from physical writes and peer acceptance. This source path has no
runtime, fault-injection or official interoperability acceptance yet.

The Node retains fixed first/last authenticated DATA and DATA_ACK observations for
the last original channel occupying each preallocated slot. Records identify
its peer, tunnel allocation, wire channel and application port hash. DATA
records include MID, original expected base and the stripped owner result;
ACK records include its base/bitmap, acceptance count and free send slots
before/after application. Counts have an explicit overflow flag. No payload,
private key or authority token is stored, and observing a record changes no
protocol decision, timer, retry, queue, nonce or acknowledgement.

Records remain after the original owner returns its slab; an later channel
allocation replaces that slot's previous diagnostic occupant. This is bounded
last-occupant evidence, not a complete lifecycle or packet history. The normal
service emits those retained records once at final INFO reporting, without
logging every input or allocating a traffic-sized history. Source presence alone
does not explain a particular retransmission or establish peer interoperability.

Incoming CTN reservations follow original channel lifetimes. A closing owner
still reserves its number while any original native attempt, send result,
receive handoff or application binding remains. Only its closed owner
returning the complete buffer package can release that reservation, after a
final check for pending channel/negative-response effects. New incoming admission
also checks those original pending effects independently of the reservation table,
including an unknown-channel DATA's already queued negative response. A later authenticated
OPEN on an absent CTN can therefore create a new generational channel, including
a peer service restarting while the original encrypted tunnel survives. This
matches the official active-channel map rather than banning a CTN until tunnel
keys retire. Existing tunnel authentication, ciphertext replay checks, CTN side
selection, port proof and original ChannelOwner/Application generations remain.

An authenticated OPEN to a currently closed port retains the official
LOOSE lifecycle in a separate fixed metadata slab sharing the same CTN claim
budget. It keeps the original tunnel Scope, CTN and h_port, with one
first30-second canonical/native bound. Duplicate OPEN neither replaces those
bytes nor renews that target. No payload/channel slab or application endpoint
is allocated while the port is closed; DATA/ACK without a listener is ignored
without a delivery or flow ACK. An authenticated remote DESTROY removes only
that original pending entry.

Normal polling rechecks local port registrations. A matching current
listener permits the ordinary challenge-verified ChannelOwner allocation and
application accept, then the existing output path emits standard OPEN_ACK. Temporary capacity keeps the same original pending entry and deadline. The
private service port record caches its fixed-local-peer challenge at actual
registration, avoiding repeated SHA512 work while scanning waiting entries.

The first closed-port timeout removes local state and its now-idle CTN claim;
it sends no DESTROY, matching the official timeout callback. A retry
after that removal can start a fresh request; it cannot prolong an existing
pending wait. Both the canonical deadline and original native Instant wake the
same Node; expiry is checked again immediately before application accept. Pending entries keep their tunnel out of idle retirement and appear in actual
management channel counts. Stop/tunnel close or stale Scope retires them without
minting a new source, key, retry or deadline.

Unknown-channel negative responses still retain a bounded reservation only after
their frame is queued, releasing it after all original negative frames
have terminal local outcomes. A failed seal/queue creates no permanent
reservation. The final ordinary INFO summary exposes retained, later-bound, expired
and remotely destroyed waits as separate local counters. It does not turn them
into application-delivery or remote-ACK receipts. This connected source addition
has not by itself established the late-listener normal runtime or C-peer
interoperability result.

The Node selects pending application sends through the pure service's
`next_send_where` boundary. Its readonly predicate checks the matching actual
binding, channel retirement, a free retained-admission slot and the original
peer owner's available send window. A blocked channel leaves other queued
channel heads eligible, while copy/admission still validates the original
capabilities and bytes. If all candidates are blocked, that application class
returns no activity or self-wake; peer ACK/owner progress resumes admission. The original serial order, budgets, immutable bytes and message numbers are
unchanged. This source repair is not a causal attribution for previous failed
normal runs.
