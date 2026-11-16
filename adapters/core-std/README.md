# Rust CORE service host

This host runs official CORE application/monitor IPC 64,65,67,68,70,71,74,75,76,78,79,
and uses the official TRANSPORT 360..366 connection for CAKE peer traffic. It composes `gnunet-core::session::Session`; it neither launches a C service nor
implements a substitute handshake. Layouts come from `gnunet-wire`. The reference
profile is v0.29.1 `346358e26d4dcc2dc4f51bef5d52dca29c7d8165`.

## Construction

`Host::with_clock` borrows an initialized `Identity` and local service-info bytes,
and joins the embedding process's `Arc<RuntimeClock>`. It owns dynamic maps of
physical application streams and peer sessions, bounded FIFO bytes, original
reservations and partial I/O. Canceling `drive` preserves that owner. Shutdown
immediately closes owned sockets, erases peer keys and releases its clock waiter. The enclosing owner drops its borrowed identity afterwards. Shared listener
access/tolerant policy is applied; shutdown is an explicit immediate operation.

Unix application and monitor streams also pass the configured `UnixAccess`
policy before acquiring client state. `UNIX_MATCH_UID=YES` requires the original
socket's kernel-reported UID to equal the service's effective UID and takes
precedence over GID matching. Otherwise `UNIX_MATCH_GID=YES` accepts the service's
effective GID or peer account membership in that group. A mismatch closes
only that unadmitted connection; a native credentials/group lookup error closes
it and returns the original error to the enclosing foreground cleanup. TCP keeps
its existing address ACL. Embedders may call `Host::set_unix_access` before their
first client; direct `attach_client` also enforces that policy on Unix sockets. It cannot be changed after any client admission. Constructors default both flags
to false. Foreground parses `[core]` flags before bootstrap and applies them to
every new Host before READY, including identity rotation and PILS reconnection. Absent flags are false; the official shipped `core.conf.in` supplies UID=NO and
GID=YES. The pinned generic C service parses both flags but its current AF_UNIX
accept branch permits filesystem-controlled sockets without checking them; this
Rust host explicitly implements their declared credential policy. Configured `USERNAME` must match the actual process account before service work.

`attach_client` and `attach_transport` accept original initialized stream
capabilities for embedding. An attached TRANSPORT receives the ordinary START
with self-check and payload options. The host consumes each peer's send
credits and grants a RECV_OK exactly once after processing/admitting or explicitly
discarding that original received message. SEND_OK is flow control; no remote
application delivery receipt is invented. Retiring a failed TRANSPORT MQ drops
its peer generations, request reservations and unadmitted work before reconnect. Late SEND_OK for a disconnected peer is legal and does not retire other peers.

The record receiver classifies the two public epoch-policy refusals at the
record-open boundary. Too-far future and expired-ring epochs discard only
their original RECV, increment the existing rejected-record count, wipe scratch
and enqueue the existing one RECV_OK. They do not retire the TRANSPORT MQ, other
peers, the association, pending SENDs or original flow credits; rejected input
does not refresh liveness or alter replay state. The plaintext epoch is not
AEAD-covered by the reference wire. `Session::receive_classified` and
`Receiver::open_classified` retain this provenance while the existing `receive`
and `open` APIs project to their original error values. Arbitrary `Stale` or
`TooLarge` from a different step remain local failures, not silent discards. Capacity, ownership, crypto/provider and physical-MQ failure policy is unchanged. The normal stop Report retains the total `rejected_records` and separate
saturating counts for the original receive classifications `RejectedEpoch`,
`Authentication`, `Replay`, `Truncated`, `Malformed`, `InvalidInput` and
`Unsupported`. Epoch refusals combine the existing TooNew/TooOld policy cases;
other counts retain their receive error without claiming a particular
AEAD, handshake or peer-fault cause. Foreground identity rotations accumulate
each category alongside the total. These fixed counters add no per-record log,
peer/value dump or new discard, credit or recovery behavior. This source repair follows the fixed C record rejection/receive-continue path;
it adds no wire field, crypto work, fake ACK or extra queue. Disconnect cancels only wholly unwritten old SEND frames. Any old committed or
partial SEND still owes a refund: bounded retired-credit debt consumes those
returns before a later same-identity generation receives additional credit. Already started frames retain their original FIFO tail. Credits carry no invented
wire generation or message ID. Losing the physical MQ retires its whole debt map.

The stop Report separately counts TRANSPORT disconnects of known
confirmed peers and Session association expirations. `first_peer_loss`
retains one fixed pre-transition snapshot with typed origin, original peer and
phase/confirmation/deadline, existing host canonical logical sample, and the
original send credits and queued ciphertext counts/bytes. Unknown or
unconfirmed TRANSPORT peers do not fill that slot. A tick snapshot is published
only when that same tick returns Lost. The logical sample/deadline is not a
native IO target, and this observation is not a packet or application callback
receipt. Foreground accumulation keeps the first observed loss across Host
rotations even if a later logical sample is smaller. Counters saturate; no
queue, extra clock sample, timeout change or per-packet log is introduced. Whole TRANSPORT MQ loss remains the independent `transport_losses` counter.

## Application queues

Applications receive INIT_REPLY and the existing authenticated peer snapshot. The local identity supports self loopback without a fabricated peer
CONNECT. Registered inbound types, full inbound/outbound, header previews and
the current empty-subscription wildcard behavior follow the official service. A slow client exceeding its explicit output capacity is closed; other clients
continue. Application payloads are not guaranteed remote delivery by this IPC.

SEND_REQUEST reserves bounded body capacity and queues its original READY ID. A replacement request cancels the old reservation. SEND consumes only its
original peer reservation; a legal old partially written SEND arriving after
that peer's disconnect is discarded. Before DISCONNECT, unissued reservations
are removed; already queued READY stays ahead of it in the same FIFO. A later
same-identity CONNECT starts fresh request ownership. A blocked peer does not
stall another peer, while each peer's submission order stays intact. The current source's SEND_REQUEST deadline is scheduling metadata and does not
expire the reservation; the host does not invent a hard cancellation timeout.

Plaintext stays queued until TRANSPORT credit and immutable FIFO capacity
are available. Storage/metadata preflight precedes consuming a sender nonce;
the encoded frame is retained unchanged through partial writes. There is no
large backlog pre-encrypted under an association that might be replaced. Unadmitted old control flights and plaintext reservations are discarded on
association loss. Already admitted partial frames drain unchanged or their
whole original MQ closes. Cancellation never claims definite remote non-delivery.

## Monitoring

Monitor connections start independently of INIT, include handshakes in progress,
finish the initial snapshot with state11/zeropeer/FOREVER, and then continue with
state/deadline updates. Deadlines stay in the shared absolute source
domain. Rollback preserves original targets; adjustment subscriptions re-arm
native wakes. Clock errors remain errors and never become a fake FOREVER. An FOREVER target is never immediately due, including when a trusted
clock reaches u64::MAX. Only the initial ready phase runs immediately; saturated
retransmit, probe and idle targets remain unscheduled.

## Native startup and cleanup

The standard service has separate Unix descriptor/account and Windows
SID/activation/bootstrap entries around one foreground. Unix `prepare_process`
and synchronous `apply_identity` retain the original TCP/inherited listeners
across the account transition. `PreparedProcess::finish` completes local binding
and returns a `PreparedService` with its validated policy. Windows constructs the
same type from completed native listeners after configured-SID verification.

`foreground[_with_clock]` and `PreparedService::from_listening` verify the actual
configured account without changing it. The caller owns account provisioning;
no saved-ID, capability or impersonation guarantee is inferred from that check.
A read-only embedding may use an already applied account without manufacturing a
privilege report.

The shared driver polls the original operation and Resolver fairly on each
turn. Its one parent notification begins only after verified PILS identity and
real host construction, with a fixed native deadline and the same shutdown
future. Readiness failure still closes the current host and retains its counters.
All foreground exits explicitly disconnect the original Resolver and retain
independent I/O, connection and cleanup errors. Whole-future cancellation also
runs `Host::Drop` shutdown and scratch erasure.

The read-only master loader is `gnunet-pils-host::identity::load_existing`:
existing raw32 files must be private regular files. The host verifies actual
PILS1831 framing, HELLO signature/expiration, announced context hash and the
derived public identity before publishing it. `MasterKey::with_active_seed`
constructs the CORE key owner without exporting or logging the master.

Node-wide `[PILS] PROFILE` selects one explicit profile, defaulting to Reference029. Its current HELLO
profile signs metadata using the source's empty address hash: this does **not**
authenticate address contents. Direct feeds can use `PilsFeed::with_profile`; failure never triggers a different profile. An identity change closes/drops the old host and its key associations before
constructing the new one. PILS loss retires that epoch and retries with backoff.

Limits are host capabilities, not invented configuration/wire fields. Each app
has a 65535-byte RX buffer and separate bounded router/physical TX queues. The
TRANSPORT FIFO reserves `4*max_peers+2` additional fixed40-byte credit frames;
these are resource reserves, not a claimed per-peer RECV protocol maximum. Peer control queues reserve four extra entries/4096 bytes beyond their base
limits. Exhausting even those reserves explicitly retires the MQ rather than
deadlocking a RECV before its own later SEND_OK. Default local info is empty;
the selected Session1024 profile allows up to830 local info bytes. Incoming
handshake parsing uses shared65535 scratch. Larger local-info storage and full
independent-node acceptance remain explicit work, not inferred from this profile.

The shared startup/listener/ACL/activation runtime owns Connection and accepted
stream effects. Shared CLIENT endpoint selection comes from `gnunet-client-host`;
the process Resolver broker implements its typed effects. The host and protocol
engine have no production dependency on the STATISTICS adapter or public facade. `io::Link` is a thin domain budget adapter over runtime `framing::Framed<()>`. It retains whole-frame accounting and the original control reserve, frame/byte
limits and IO quantum. The generic layer owns the exact physical cursor and
immutable bytes; the domain keeps credit, cancellation and nonce authority.

The standard SERVICE entry uses the shared byte-preserving SERVICE option table
`-c/--config`, `-d/--daemonize`, `-h/--help`, `-L/--log`,
`-l/--logfile` and `-v/--version`. Selected logging rules and the owned file
destination actually filter/route entry identity, socket and fatal diagnostics;
NSE additionally forwards its original unadmitted-subscriber cause through a
typed caller diagnostic. Real Rust caller locations are retained without global
fd2 replacement. A diagnostic I/O failure wakes ordinary service shutdown and
remains distinct from the triggering service error. Existing SERVICE default
configuration fallback is retained. The shared clock also drives the actual
service/Resolver.

The standard executable's `-d/--daemonize` uses the explicit shared
service-startup single-fork/setsid boundary before account/runtime/listener-path
initialization. It retains original activation/control/logfile owners, creates
new Unix endpoints only after USERNAME, and reports parent success only from the
Host-ready callback. The parent treats failure/EOF as failure and never
waits for a live daemon to stop. Later PILS identity rotations do not send a
second ready byte. Generic library foreground functions still never fork.
