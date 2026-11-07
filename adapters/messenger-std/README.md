# Caller-driven MESSENGER SERVICE

`gnunet-messenger-service-host` implements the application daemon over the
existing official IPC codec and `Core::Mode::Service`. It is distinct from the
higher-level `gnunet-messenger-host` application client.

`Server::new` takes caller-owned CADET/PILS Instance brands and fixed CADET
port/channel metadata, explicit Core/native limits, SERVICE ACL/Unix access,
exact shared-clock CADET/PILS EndpointSources, and an explicit Entropy owner. It creates no resolver, socket, worker or task until the caller polls IO. `admit`, `poll`/`drive`, `request_shutdown`, `close_client`, `close_all` and
`take_cleanup_error` expose ownership. Callback return precedes the next
external operation. The PROGRAM supplies one shared Resolver and clock.

`Limits.pils_profile` selects the official PILS/HELLO semantics and defaults
to normal `Reference029`; it is separate from the local and remote Messenger
producer-layout profiles. The PILS client verifies nonempty announcements
under only that selected mode. Conditional `ReferenceDeterministic` is explicit,
with no fallback after failed verification. Current signing authority, physical
source epochs and historical provenance remain separate observations.

Implemented production paths:

* Actual CREATE/DESTROY, OPEN/ENTRY, CLOSE/SYNC, signed SEND and GET IPC. CREATE
  is idempotent and grants no authority or invented ACK. After SERVICE
  admission, a first OPEN/ENTRY is accepted without an additional CREATE
  handshake, as required by the unchanged C client's reconnect path. The first
  structurally decoded request ends only initial-idle classification; per-frame
  and room deadlines, identity validation and original client ownership remain.
  DESTROY physically retires the original MQ. Whole-handle
  public identity, per-room collision assignment and signed KEY/ID
  transitions remain separate. Collision notices propose an ID; the ID
  changes only after its original signed message passes Core.
* Real CADET port announcement, outbound channel creation, incoming channels,
  service credit, CADET_CLI1059 framing, authenticated INFO8 handshake and bounded
  room/peer routing. Remote ENTRY waits for service credit and verified remote
  INFO; a queued CREATE is not a connected-room proof. Ordinary member messages,
  opaque PRIVATE/SECRET/group data and peer controls retain their signed bytes.
* Additional remote ENTRY on an Active room admits the supplied door through the same
  native channel path, or reuses a live matching room/door route. The original
  generated Source identity, room and door must still match and be compatible
  before a notification for that requested door enters the control FIFO.
  Existing Active membership and other tunnels survive a failed additional
  request. One pending entry per lease and one retained complete input per app
  provide bounded backpressure; neither deadline is renewed between polls.
  Complete additional ENTRY input is classified before native expiry, including
  during history freezes, so expiry releases that request instead of closing its
  Active MQ. Partial/invalid input and independent output, sync or initial-entry
  deadlines keep their existing rules. Local `Event::EntryFailed` retains the
  original client/room/door/cause; it is not a new wire failure or a successful
  Entry. The standard observer reports client and cause without room/door bytes.
* Personal rooms with private feeds accept normal local ENTRY (zero or explicit
  self door) and retain the original member assignment, JOIN and notification
  paths without opening a listening port. The private-feed restriction applies
  to OPEN: both an initial OPEN and OPEN after ENTRY are refused, and the actual
  port factory independently enforces that restriction. This does not supply
  missing official AUTHORIZATION MAC data or assert encrypted-group interop.
* A zero ENTRY door resolves to the verified local peer; zero and explicit self
  join through the original service-client assignment without a self channel or
  listening port. This assigns the local client and does not manufacture a JOIN,
  member authentication or remote INFO. The later signed JOIN remains on the
  original client-message path. ENTRY alone leaves the room non-hosting.
* Shared room ownership retains the original logical CADET port across healthy
  PILS/CADET identity changes. Its hash-only PortOpen is a listening intent on
  the same MQ; no PID attestation or service acknowledgement exists on wire.
  Fresh OPEN replies use the applied current identity after the original
  announcement is wholewritten, without re-registering an existing port.
  Whole IPC writing still proves no remote reachability or message delivery.
* Explicit OPEN owns the listening-port request. An already entered room
  retains its membership and peer routes while one bounded pending OPEN waits for
  its original Port to be announced. OPEN during initial entry retains its exact
  input; complete-input expiry is classified before native expiry, including
  history freezes. Original deadlines are not renewed. `Event::OpenFailed`
  preserves local refusal separately from a successful wire response. OPEN,
  CLOSE and SYNC identify the local peer in their room response; ENTRY
  identifies its resolved selected door. The public client permits OPEN after
  ENTRY and repeated OPEN on the same Source, and still waits for the actual
  corresponding written-operation response before completing.
* One shared PILS client signs the exact original72-byte purpose12 region.
  Exact operation, source epoch and returned signer are checked. Core
  independently verifies the retained original signature/header/body before
  explicit local commit. Admitted, request-written, applied and refusal events
  are distinct; none is a remote publication/delivery receipt. No seed is read.
* Actual peer PEER/CONNECTION/MISS controls, frontier MERGE and local SYNC,
  signature-attributed app notifications, TALK subscription gates, member
  and epoch bootstrap, known REQUEST history responses and unanswerable request
  forwarding. GET uses bounded original tombstone edges plus daemon history/auth
  checks; it does not require client-only recipient crypto to have completed.
* A per-room first-write epoch-alias Core dependency preserves known mappings
  for missing predecessor hashes. Missing placeholders remain normal lookup
  targets and do not gate raw notification/forwarding. They grant no membership.
* One original application TX per MQ, fixed small control queues, global bounded
  delivery/message/retrieval metadata, actual-length retained CADET input per
  channel, and one shared CADET TX. Slow owners have original finite
  deadlines. Metadata pressure never manufactures credit or success.
* Core's original outer `MessageRef::padding()` is used to strip/repack signed
  frames. Binary IPC tails are never guessed with Detect. The public
  CADET message bound64348 is enforced; no private fragmentation/truncation is
  invented when C's preferred padding rounding would exceed that carrier.

Physical loss never replays an old application packet on a new MQ/channel. Accepting the normal C client's reconnect requests does not by itself restore
logical room intents in the separate Rust high-level client. The intent
recovery implementation is documented in that API and normal command package. Open logical listening ports can be reannounced by the CADET client. Healthy same-MQ PILS identity changes retain original app/CADET owners. The
identity owner fences fresh signing, settles original admitted signatures and
retires only unadmitted drafts before atomically changing Core's signer leases. Admitted signatures retain their exact original Identity, operation, frame and
deadlines. Same-PID refreshes do not repeat identity changes. Physical PILS epoch
replacement or source loss still stops the original signing owner.

Open rooms track local PEER/MISS commits under fixed parent bounds. PEER(new) precedes MISS for previously announced own identities; public
remote PEER messages cannot extend local signer provenance. Already encoded
application replies and CADET output retain their bytes. Local ENTRY remains a
local-room selection; remote doors retain their selected identity and channel. An old CADET port does not prove that a new PID is reachable; normal CADET
identity recovery requires separate implementation and qualification. No-clock shutdown retires every app, CADET and PILS physical owner before Core
source cleanup, preserves independent errors and does not claim remote drain.

## owned history and explicit producer layouts

The fresh history extension implements `history::History::open`, exact
`Server::install_history`, a single explicit shared snapshot worker, bounded
microbatch cuts, and durable receipt gating. See the core
[archive contract](../../crates/gnunet-messenger-core/ARCHIVE.md). `close_all` first stops app/CADET/PILS physical owners without sampling the
logical clock. `finish_history` then submits the final accepted cut, preserves
its original outcome, drains and joins the worker. Socket grace is finite;
filesystem fsync and emergency worker join have no fabricated finite cancel.

New app/peer payload notifications and CADET receive_done wait for the exact
current accepted cut to commit. Existing queued partial writes continue on their
original owners. At most one prepared/worker image exists; mutations of retained
business state pause while that original immutable image is pending. Socket IO,
original cursors, PILS completions and physical retirement still progress. The bounded batching policy uses actual-length raw frames, not per-peer maximum
buffers. Snapshot serialization is a full bounded image per batch; append-only
WAL/compaction are not implemented.

`layout::Policy` separates the declared original signed body layout from the
relay's incoming/outgoing padding encoder/decoder layout and room-port
word order. Non-FILE SERVICE bodies have a profile-independent network-order or
opaque grammar; `Portable` records this fact without claiming an original host
endian. FILE width comes from an explicit signer/hash rule or explicitly declared
common NAME_MAX constraint; it is never guessed from message length. Exact
room/message/signer overrides and current relay/room declarations are bounded. Actual cryptographic admission independently checks any expected original signer. The retained body/signature/hash bytes are preserved. Only unsigned outer padding
is repacked for the explicitly configured recipient decoder. Raw C endpoints
have no profile-negotiation message, so deployment policy must supply the facts.

Prior runtime receipts retain
their original exact scope. Application recipient/group decryption and the
separate M5 high-level client's mixed-layout decryption remain CLIENT
responsibilities. Its independent `ClientLayout` and bounded `Profiles` API is
implemented in that package. This SERVICE also selects app SEND body layout
from its bound OPEN principal/exact signed-message policy before real
Core signature admission; it never substitutes the current daemon's native body
layout for every app producer. No daemon imports member private keys or fabricates the
missing official AUTHORIZATION MAC. This remains an external-CADET/PILS daemon,
not a complete independent GNUnet node or a full-function acceptance claim.

remote CADET channel destruction revokes new tunnel sends, INFO,
bootstrap and entry-readiness work while retaining already delivered DATA in
its original room/Source. That DATA keeps its original byte cursor and
Receive.until across history preparation/worker commit. It is processed through
the existing verification/semantic path only after the frozen cut permits it,
and local release waits for history_ready. A gone channel receives no
new receive_done/ACK. Only then is its original Source retired; other shared
MQ channels and credit events continue to progress. Original admitted native
suffixes, Written/exposure observations and history receipts are not
relabelled as remote acknowledgement or replayed.

Local room closure, refusal and original expiry still revoke held input; later
Destroyed cannot revive it. Expiry checks remain outside the history-freeze
gate and keep their original targets. History failure still fails closed and
permanent shutdown physically closes sources before its independent worker
drain/join. Archive format, transient projection, epoch/room recovery and
original storage transactions are unchanged.

`history_committed` reports the durable event cut independently of live
PILS identity readiness; explicit volatile mode returns no durable receipt. `history_ready` remains the live-output/identity gate. Revoking physical-source
authority does not undo an earlier worker commit. The normal shutdown report
requires successful final history completion before reporting a committed cut.
