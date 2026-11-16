# UDP communicator host API

The base library exposes private replay journals and numeric datagram sockets.
`transport` enables official TRANSPORT IPC drivers, multi-peer ownership and
LAN discovery; `pils-client` adds provenance-bound identity selection. The normal
[UDP PROGRAM](../../apps/gnunet-communicator-udp/) owns configuration and startup.

## Replay state

`replay::Journal` is a UDP-specific persistence adapter for the pure receiver's
`ReplayStore` trait. It has no dependency on TRANSPORT service ownership or its
current shared journal. Production code is Rust only and forbids unsafe code.

One existing private directory has one retained OS `File::try_lock` owner on a
stable native file identity. The database binds the exact local peer identity and sorted remote
peer/timestamp records. Timestamps are strictly increasing per remote peer;
equality is a replay. The bounded, checksummed snapshot is an internal disk format,
not a GNUnet network message. Peer capacity is explicit and bounded to 4096. Local outgoing monotime intervals are reserved under the same writer fence. Unused issued timestamps remain skipped after restart.

A successful commit requires the complete temporary write, file synchronization,
original-file publication, the native directory barrier and exact original-file
snapshot/hash readback. `Journal::directory_sync()` reports that barrier's actual
capability; Windows reports `DirectorySync::Unavailable`, which is not a crash
persistence guarantee. Recovery retains the original opened replacement and
refuses another file even when its bytes are equal. Uncertainty blocks further
commits and ready history reads. A pre-existing fence with no canonical state
is refused rather than resetting replay history.

The pure-core trait preserves Storage/OutcomeUnknown/Replay. `take_failure`
returns the original stage, outcome, native cause and independent cleanup error;
it never resolves a transaction. No detached writer outlives the owner.

`replay::Namespace` holds one process writer fence above full-local-identity
child Journals. A live child retains that root fence even if the Namespace
facade drops. Returning peers reopen original replay floors and outgoing
high-water; unsuffixed snapshots/temporary footprints are refused without reset
or migration. Root and child fences check the held parent descriptor and lock
identity. Packet admission does not enumerate identity directories.

Communicator's explicit `retire_identity`/`resume_identity` boundary retires the
old TRANSPORT MQ, records partial effects and canceled native packet metadata,
and erases peer keys before selecting a matched next key and ready Journal. Default sockets and bounded backing stay owned; utility endpoints retire. Replacement still needs original-loss observation and an reconnect. Queue/token serials do not reset, and cached discovery signatures cannot cross
the cut. The normal program owns PILS provenance and bounded recovery policy. These are local cancellation facts, not successful draining, remote quiescence
or callback replay.

Native filesystem and pure receiver composition witnesses cover captured KX
rejection after a journal restart, durable interval reservations, actual
cross-process writer exclusion and process-kill release, post-rename parent
path loss and exact recovery, corruption, aliases, replaced fence and canonical-entry replacement. The subprocess probe is harness support, not a separate
service conformance case.

## Datagram and driver ownership

Isolated UDP receive failures yield `Activity::ReceiveError` with the actual
native cause. They consume one bounded receive attempt and erase any touched
scratch, while preserving the original shared socket. No peer, packet byte
count, authenticated admission or delivery receipt is inferred from ICMP errors.

The [transmit owner](src/communicator/transmit.rs) isolates destination-level
send errors as `Activity::SendError`, retaining the intended target and actual
native cause without attributing an asynchronous error to that peer. Its original
negative SEND result precedes retirement of both endpoint queues. Other endpoints
retain their socket, keys, replay state and MQ. Failed packets are never retried
and consumed BOX sequences are not refunded. Socket-owner, resource and positive
short-write failures remain terminal.

`socket::DatagramSocket` owns one nonblocking socket, one retained
immutable outgoing `Datagram`, and one preallocated65536-byte receive slot. Wait cancellation leaves these owners intact. An explicit socket-identity and generation receipt
must be consumed before the next receive. Sends use one whole datagram
syscall; errors retain the same packet and original OS cause. There is no suffix
send, nonce regeneration, implicit remote receipt or cryptographic credit refund. IPv6 sets IPV6_V6ONLY. The source profiles are IPv4 base1452/KX1300/BOX1404
and IPv6 base1232/KX1080/BOX1184; source-compatible rekey adds36 to the BOX extent.

Before publishing a bound or adopted socket, the adapter requests a 128 KiB
kernel receive buffer if the reported budget is smaller, allowing a maximum
datagram plus kernel accounting. The operating system may adjust the request.

The UDP packet component profile compares initial exchanges, BOX packets and
rekeys across C and Rust packet observers. It requires received bytes to match
the original transmitted packet images. These finite packet observers do not
stand in for normal communicator daemons, TRANSPORT IPC, PILS or NAT owners.

The optional `pils-client` feature adds `identity::IdentityEpoch`. It obtains an
active UDP key only from matched current verified pure/native PILS client access,
using PILS's existing profile/derivation. Every key borrow checks that actual
client's original epoch/revision and key status plus explicit current UTC. The
returned borrow also holds the client borrow, preventing source rotation/loss
while that key is in use. MQ replacement, distinct branded client, key disable,
announcement revision change, expired HELLO or explicit close refuses access. Cached peer/observation methods provide public teardown data only. This feature
creates no key file and exports no master, signing seed or exchange scalar. Pure client/service composition and a borrow compile-fail witness test the guard;
these are not additional native PILS IPC or normal C daemon conformance claims.

Receipts retain a checked, never-reused process-local socket identity as well as
the receive generation. A same-source/same-size packet at another socket cannot
read or consume this slot. Moves preserve the original identity; closed or later
socket owners cannot reuse its receipt. This identity never enters a wire frame.

The optional `transport` feature adds the exact public communicator IPC
codec and `driver::Driver`, one explicit peer/address session on one original
TRANSPORT MQ and UDP socket. Its normal dependencies include pure TRANSPORT and
the shared native framing/connection runtime; the TRANSPORT host appears only in
dev fixtures. The driver registers unreliable UDP, advertises source MTUs, uses
actual1212/1213/1220 for ACK credit, and completes the original local1210 only
after the same prepared packet's whole native send. Losing/evicting a BOX master
cannot turn an unsent message into success. A payload that also fits KX may use
a fresh durable initial exchange; otherwise the original send fails.

The caller supplies clocks, entropy, local history and current keys. `poll_bound`
also checks the native PILS client epoch/revision/key/UTC before every
step, retiring original UDP/MQ owners on identity loss. Waiting cancellation
retains partial original frames and the same pending datagram. `finish` freezes all queue-teardown buffers before canceling a pending native
attempt or publishing teardown, then drains the original MQ; immediate `close` is loss. An unknown/replaced history fence blocks every IO until the original outcome or
fence is actually settled. Foreign local keys/history namespaces close both IO
owners before cached registration/output is written.

The fixed driver has explicit Active, Retiring, Draining and Closed stages. A failed SEND for its queue records the original negative result, stops
new session work and drains the existing completion and DOWN before closing. Unknown peer/QID refusals do not retire that live session. The enclosing owner
can create a new driver/MQ after terminal retirement; no old packet is replayed.

The multi-peer communicator retires the complete KX/BOX sender generation after
a negative result for one of its queues. A later CREATE gets fresh queue IDs;
old ACKs cannot return credit or resurrect that sender. Endpoint admission
explicitly distinguishes Live, Retiring and New. Native input encountering a
retiring endpoint is consumed before replay commit, while other key-id candidates
can still authenticate. A burst selection waits for retirement under its original
deadline before transferring its socket or issuing a completion. Failed results
and queue teardowns drain in bounded steps, including the four-frame profile.

The [receive coordinator](src/communicator/incoming.rs) authenticates a BOX before
calling the address classifier. The pure receiver's exclusive `PreparedBox` holds
all cryptographic changes until endpoint preparation succeeds. Forged selectors
cannot invoke classification; refusal leaves the original KID usable. Initial
KX endpoint preparation likewise precedes the durable replay commit.
`Activity::ClassificationFailed` retains the exact provider error, address, peer
value and input kind. CREATE queues the standard negative CREATED reply; KX, BOX,
signed discovery and passive probes consume only that datagram. No fallback
network category, ACK or new queue is admitted, and healthy endpoints retain the
original shared socket and MQ. A live endpoint uses its retained classification.

Retained effect frame count and charged wire bytes are explicit. Both frozen
52-byte success/failure alternatives of a pending native attempt count toward
those limits, although only one can be emitted. One MQ output frame, one MQ RX
buffer, the65536-byte socket RX slot and65536-byte plaintext scratch are separate
fixed owners. Incoming staging reserves at most two116-byte ACK envelopes, one
65535-byte incoming envelope before authentication, then one address/queue
envelope before replay/KID consumption. A frame allocation may retain unused capacity; its
physical upper bound is65535 bytes per retained frame, separately from charged
wire bytes. No successful authentication/replay commit is followed by a fallible
effect-buffer allocation.

An incoming datagram whose worst-case effects cannot fit even an empty configured
frame/byte budget is explicitly consumed as `Discarded(Capacity)` before crypto
or replay admission. Only transient pressure retains the original RX receipt. The regression uses an actual65495-byte loopback datagram with frames4/bytes65535,
then admits the next signed initial packet. A separate signed-receipt test
keeps that same small budget under temporary registration/queue output pressure
and verifies that the original packet survives until those effects drain.

two-Rust-session IPv4/IPv6 tests use production TRANSPORT routing through
original loopback stream MQs and private journals; they observe BOX in both directions and
original queue/MQ teardown. Separate lifecycle tests cover foreign identity and
history, a replaced writer-lock inode, and native PILS MQ EOF. The PILS
lifecycle fixture uses the existing pure Service to produce its announcement;
it is not normal C daemon evidence.

The `normal_udp_peer` example observes one configured peer and its local services.

Normal `finish` drains admitted callbacks and queue teardown frames, then polls
write-side shutdown on that same IPC connection before retiring it. Canceled
waits retain the shutdown phase; native failures preserve their cause. Abrupt
`close` remains source loss with no successful-drain or peer-delivery claim.

## Native platforms

The same socket, replay, driver and communicator owners are available on Linux,
macOS, FreeBSD and Windows. Unix discovery sends use `sendmsg`; Windows uses
provider-qualified `WSASendMsg` with `IP_PKTINFO` or `IPV6_PKTINFO` on the original
socket. Windows interface facts include actual native access type and address
DAD state. Discovery snapshots remain bounded; an invalid snapshot never implies
that existing interface claims should be removed. LAN observations pass through
APPLICATION validation and do not grant authenticated queues or remote credit.
The discovery owner uses the platform's explicit sockaddr profile for signing;
verification includes all four producer profiles while preserving the observed
IP, flow and scope. Unsupported platforms refuse discovery during construction.

## Discovery retirement

`prepare_interfaces` returns an exclusive `InterfaceUpdate` guard after validating
and reserving the complete replacement. Dropping it preserves the original rows,
retry targets, memberships and pending announcements. `commit` installs it without
allocation or I/O, allowing an enclosing program to prepare address publication
before changing either consumer. `update_interfaces` prepares and commits directly.

The [discovery I/O owner](src/communicator/discovery_io.rs) separates optional
LAN work from encrypted endpoint lifetime. `Activity::DiscoveryFailed` retains
the original send/join/leave action, interface and native cause. Failed sends
are not replayed. A native deadline retires its original announcement before
canonical-clock work; its observation occupies at most one slot per default
socket. A complete replacement interface snapshot revokes pending announcements
whose exact source row disappeared. Invalid snapshots leave existing work intact.

Interface/network failures during send or membership changes preserve the shared
socket, TRANSPORT MQ, peer keys and encrypted queues. Joins and unresolved leaves
retry no sooner than the configured discovery interval. Successful membership
admission remains charged until actual leave or socket close. Linux additionally
settles a leave when the [kernel reports no matching socket membership](https://github.com/torvalds/linux/blob/master/net/ipv6/mcast.c);
other platforms retain that failed leave for retry or close. A full bounded
membership table defers a new optional join. Descriptor, allocation, malformed
completion and positive short-write faults remain terminal.

## Normal communicator public burst path

The normal PROGRAM supplies one explicit `burst::Instance` and its existing
RuntimeClock to `Communicator::enable_burst` before the registration enters native IO. Only this complete composition replaces the original unexposed registration with
`can_burst=true`. The low-level single-peer Driver keeps its explicit false
capability. Ordinary UDP cryptography, KID/replay/ACK state and backchannel bytes
are unchanged. This implements the public NAT burst product path, separate from
the official unimplemented UDP reversal callback.

An actual 1253 reserves its finite native deadline before clock sampling,
utility construction or output pressure. The default is at most the official
60 seconds. TRANSPORT has already performed synchronization and delay;
`Burst::start_ready` receives that original native deadline and canonical bound.
A new MQ command supersedes the preceding running probe, as in the official
communicator. Repeated polling of one held MQ frame retains its original bound.

The [state owner](src/communicator/burst/state.rs) separates four phases:
waiting retains the original MQ input; running owns the utility; selected owns
its exact chosen socket; retired retains a typed outcome and any unreleased
input. Retired work owns no probe or selected socket and cannot resume. The
[retirement owner](src/communicator/burst/retirement.rs) handles native bounds
before canonical-clock work. Report backpressure can retain expired metadata,
but cannot extend its deadline or pin the shared UDP receive slot.

The default DatagramSocket remains the only reader of its original socket. It
passes complete 36-byte probes only to the running utility. DATA, ACK and KX use
normal dispatch. Scan sockets follow the utility's bounded 512-descriptor,
100 ms lifetime and 10 us pacing policy. Non-probe scan data observed before
selection is counted as ignored, without authenticated delivery credit.

The [handoff owner](src/communicator/burst/handoff.rs) stages a selected scan
socket and endpoint plan locally. Address classification and the original
deadline must pass before the socket, queue and 1254 publication are committed.
A refused or late candidate drops its staged socket without adding a socket
slot, consuming a queue ID or publishing a frame. A default selection keeps the
original socket. Dedicated selected sockets close after their final endpoint
retires; each adopted receive buffer is bounded to 65536 bytes.

Timeout, exhaustion and failures confined to scan-owned resources retire that
attempt and preserve the shared socket, TRANSPORT MQ and encrypted endpoints.
Shared clock/default-socket failures and invalid positive short writes retain
their fatal scope. No failure-shaped 1254 is added: only installed candidates
queue the official completion. Its publication ticket distinguishes queued,
whole-written and retired facts; a write fence preserves callback order.

`take_burst_report` returns mutually exclusive not-started, preparation-refused,
utility-stopped, candidate-rejected, candidate-installed or unobserved-receipt
outcomes. Native counts and independent interruption causes remain associated
with their original operation. A completed report and a canceled pending report
have fixed FIFO slots. Callers drain them before admitting more work; capacity refusal
never overwrites a retained report. Source loss or shutdown cancels original
probe resources before default sockets close. Selection and 1254 establish only
an unauthenticated candidate and local publication, without peer-delivery credit.

The public probe's native Endian profile is preserved: local fields use the local
producer ABI, while `burst::Policy::remote_order` explicitly describes received
raw native fields (default local ABI). Address selection uses recvfrom
endpoints rather than trusting advertised native ports. Passive default-port0
probes produce only bounded unauthenticated dial candidates; they do not generate
a completion without an original active command. Adopted IPv6 utility sockets
retain their bound endpoint and IPv6 mode; mapped-v4 endpoints are refused.

A live socket is distinct from a quiescent
socket: endpoint creation checks handle ownership, and an extra slot is
reused only after closure, all endpoint references and pending send completions
are gone. The receive loop skips only closed owners; it polls healthy idle
sockets to register their read waker and receive original packets. Quiescence
remains a separate teardown/debt diagnostic. Ready deadline alarms retire
the original probe resources before further clock/provider work.

The multi-peer `Communicator` separates the physical TRANSPORT MQ from its
original UDP socket, identity, receiver, sender and replay-journal owners. Actual
MQ EOF/I/O loss retires its input and output FIFO. A preallocated bounded loss
ledger records original partial frame extents, unsubmitted SEND metadata and
pending native datagrams, without retaining payload or key bytes. Pending native
packets are canceled and their prepared nonces remain spent. Completed native
sends whose callbacks have not wholly written retain their status only as
old-source diagnostics; no old callback, MID or payload is replayed.

The caller observes `transport_loss` and supplies a newly connected standard MQ
through `reconnect`. The retained owner sends the official REGISTER, then fresh
queue SETUPs for surviving endpoints. KX capacity retains its unlimited message
count; BOX capacity comes from the same sender's remaining `available()`
message count, including already applied grants and spent preparations. It never
restores a previous delta or resets credit. Expiry keeps the original ACK and
native-clock targets. Endpoints track the exact MQ generation of their queues. Fresh-source commands and native work interleave with bounded restoration, so a
TRANSPORT service emitting reachability SENDs cannot block SETUP replay in a
full-duplex buffer cycle. ACK work on an unannounced endpoint updates only its
retained sender; its later SETUP captures that total. Announced endpoints use the
normal delta UPDATE path. New CREATE/RX endpoints are marked current and skipped
by restoration. Partly applied ACK work keeps its cursor and generation watermark,
but cannot release a replacement-source input frame. A source-bound FIFO write
fence completes restoration even when unrelated new traffic remains queued. `Activity::Registered` and `Activity::Restored`
report distinct local write milestones and imply no peer acknowledgement.

Publication tickets retain the immutable communicator brand and exact original
MQ generation. A historical whole write remains `Written` after retirement; an
unfinished old ticket remains `Retired` even after newer sources write. Fatal
identity, journal, native guard, Stop and cleanup failures still physically close
the owner.

A verified PILS HELLO refresh on the same physical MQ can change its local
revision and validity while retaining exactly the same active key context. In
the normal Reference029 profile, an ordinary address FEED produces such updates. `IdentityEpoch::refresh_client` and `refresh_native` explicitly adopt the latest
public observation only when its original epoch, public peer, derivation hash
and signature coverage remain identical and local key status remains Matched. The latest announcement must still be valid and its revision cannot move back. This updates no private key, UDP nonce, replay namespace, ACK credit or original
operation deadline. Rejection leaves the previous binding unchanged; a closed
owner cannot be revived. Key borrowing still requires exact equality with the
client's current observation after this explicit refresh.
