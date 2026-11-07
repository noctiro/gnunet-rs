# Native UDP resources

`replay::Journal` is a UDP-specific durable adapter for the pure receiver's
`ReplayStore` trait. It has no dependency on TRANSPORT service ownership or its
current shared journal. Production code is Rust only and forbids unsafe code.

One existing private directory has one retained OS `File::try_lock` owner on a
stable inode. The database binds the exact local peer identity and sorted remote
peer/timestamp records. Timestamps are strictly increasing per remote peer;
equality is a replay. The bounded, checksummed snapshot is an internal disk format,
not a GNUnet network message. Peer capacity is explicit and bounded to 4096. Local outgoing monotime intervals are reserved under the same durable writer fence. Unused issued timestamps remain skipped after restart.

A successful commit requires complete temporary write, file synchronization,
atomic rename, parent directory synchronization, and exact snapshot/hash readback. Post-rename uncertainty retains the original snapshot/hash and blocks all further
commits and ready history reads. `recover` synchronizes and checks precisely that
original snapshot; a different valid older snapshot does not resolve it. The
pure-core trait preserves Storage/OutcomeUnknown/Replay, while `take_failure`
retains the original native stage, outcome and IO cause. Taking that diagnostic
never resolves the pending transaction. No detached writer outlives this owner.

`replay::Namespace` holds one process writer fence above full-local-identity
child Journals. A live child retains that root fence even if the Namespace
facade drops. Returning peers reopen original replay floors and outgoing
high-water; unsuffixed snapshots/temporary footprints are refused without reset
or migration. Root and child fences check the held parent descriptor and lock
inode. Packet admission does not enumerate identity directories.

Communicator's explicit `retire_identity`/`resume_identity` boundary retires the
old TRANSPORT MQ, records partial effects and canceled native packet metadata,
and erases peer keys before selecting a matched next key and ready Journal. Default sockets and bounded backing stay owned; utility endpoints retire. Replacement still needs original-loss observation and an reconnect. Queue/token serials do not reset, and cached discovery signatures cannot cross
the cut. The normal program owns PILS provenance and bounded recovery policy. These are local cancellation facts, not successful draining, remote quiescence
or callback replay.

Native filesystem and pure receiver composition witnesses cover captured KX
rejection after a journal restart, durable interval reservations, actual
cross-process writer exclusion and process-kill release, post-rename parent
path loss and exact recovery, corruption, aliases, replaced fence and a genuine
pre-rename OS error. The subprocess probe is harness support, not a separate
service conformance case.

The journal/socket observations below predate the later multi-peer communicator
and normal PROGRAM present in this adapter. Current source composes PILS,
NAT/address publication, official TRANSPORT IPC, ACK handling and bounded teardown. Current complete C daemon interoperability and full UDP/Node acceptance remain
unverified; the historical component receipts retain their original scope.

`socket::DatagramSocket` owns one nonblocking socket, one retained
immutable outgoing `Datagram`, and one preallocated65536-byte receive slot. Wait cancellation leaves these owners intact. An explicit socket-identity and generation receipt
must be consumed before the next receive. Sends use one whole datagram
syscall; errors retain the same packet and original OS cause. There is no suffix
send, nonce regeneration, implicit remote receipt or cryptographic credit refund. IPv6 sets IPV6_V6ONLY. The source profiles are IPv4 base1452/KX1300/BOX1404
and IPv6 base1232/KX1080/BOX1184; source-compatible rekey adds36 to the BOX extent.

Real Rust socket composition passed IPv4 and IPv6 initial/BOX/rekey/newmaster
traffic and captured KX rejection after a durable journal restart. The unchanged
native test binary first failed all three tests with sandbox EPERM at bind; those
logs remain under `socket-trials/sandbox-v1`, with authorized loopback results
under `socket-trials/loopback-v1`. These tests apply ACKs through public component
APIs and do not establish official transport backchannel behavior.

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

Retained effect frame count and charged wire bytes are explicit. Both frozen
52-byte success/failure alternatives of a pending native attempt count toward
those limits, although only one can be emitted. One MQ output frame, one MQ RX
buffer, the65536-byte socket RX slot and65536-byte plaintext scratch are separate
fixed owners. Incoming staging reserves at most two116-byte ACK envelopes, one
65535-byte incoming envelope and one address/queue envelope before authentication
or replay/KID consumption. A frame allocation may retain unused capacity; its
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
original Unix MQs and durable journals; they observe BOX in both directions and
original queue/MQ teardown. Separate lifecycle tests cover foreign identity and
history, a replaced writer-lock inode, and native PILS MQ EOF. The PILS
lifecycle fixture uses the existing pure Service to produce its announcement;
it is not normal C daemon evidence.

The finite `normal_udp_peer` example additionally binds a native PILS source
and replaces one normal C UDP communicator against five unchanged normal C local
services. The normal C public TRANSPORT application exchanged512 bytes each way
with one notification per side, no bad payload or timeout, and clean Rust
history/IO teardown. The first mixed profile observed Rust receiving BOX but
sending only Initial; its captured IPC does not claim reverse ACK/BOX coverage. The all-C calibration and mixed profile retain byte-transparent multi-MQ taps;
an earlier no-tap all-C connection timeout remains an unresolved failure. The
normal source main macro returns raw `GNUNET_OK=1` after controlled CUDP shutdown;
this is narrowly bound to the source and is not blanket exit1 acceptance.

That finite example covers one peer. Later normal PROGRAM source adds the
shared multi-peer MQ/socket owner, NAT/address lifecycle and LAN discovery. Those
additions and the burst composition below have selected static checks; current
normal C IPv6, traversal and full UDP/Node acceptance remain unverified.

## Normal communicator public burst path

The normal PROGRAM supplies one explicit `burst::Instance` and its existing
RuntimeClock to `Communicator::enable_burst` before the registration enters native IO. Only this complete composition replaces the original unexposed registration with
`can_burst=true`. The low-level single-peer Driver keeps its explicit false
capability. Ordinary UDP cryptography, KID/replay/ACK state and backchannel bytes
are unchanged. This implements the public NAT burst product path, separate from
the official unimplemented UDP reversal callback.

An actual1253 reserves a finite native hard before clock sampling, utility
allocation or output pressure. The default is at most the official60seconds. TRANSPORT already performed synchronization/delay; the shared utility's explicit
`start_ready` takes this original hard and canonical bound directly. Each MQ owns
one original command. A different or repeated command after admission is an
explicit conflict, not a renewed intent or replacement callback. An unstarted
command held behind a prior report/write fence retains its first bound.

The same default Tokio socket is shared only with the public burst sender. Its
DatagramSocket remains the sole reader and passes exact36-byte probes to
that same utility owner. Default DATA/ACK/KX continues through ordinary dispatch. Scan sockets use the existing bounded512-descriptor,100ms,10us utility policy. Non-probe scan data consumed before a socket becomes an endpoint is explicitly
counted as ignored input, matching the public utility's responsibility boundary;
it is never claimed as authenticated business delivery. No new receive worker or
noise cache is created.

A Default selection reuses the original default socket index. A Scan
selection transfers that exact descriptor into a new original
DatagramSocket, without rebind or a second reader. Metadata is reserved before
registration; at most one extra selected descriptor per configured endpoint is
retained, and each adopted RX buffer is bounded65536bytes. Subsequent
KX/DATA/ACK follows normal authentication and replay handling. Newly observed
endpoints retain their receiving socket for replies; peer identity comes
from the original command and later authenticated packets, never the asserted
probe identity. Dedicated sockets close after their last original endpoint
retires. Default discovery/NAT publication continues to use only default sockets.

Only candidate installation queues1254 on the original MQ. Its original
publication ticket distinguishes queued, whole-written and retired facts. A
write fence prevents a later command overtaking the previous callback. Selection
and1254 establish neither authenticated reachability nor remote delivery. Failed,
exhausted or late scans preserve their cause and retire descriptors; no1254
is invented. Original source close/finish cancels the same utility owner before
closing default sockets. Reports retain a completed original and, if necessary,
one cancelled pending original without overwriting them.

The public probe's native Endian profile is preserved: local fields use the local
producer ABI, while `burst::Policy::remote_order` explicitly describes received
raw native fields (default local ABI). Address selection uses recvfrom
endpoints rather than trusting advertised native ports. Passive default-port0
probes produce only bounded unauthenticated dial candidates; they do not generate
a completion without an original active command. Adopted IPv6 utility sockets
keep their native configuration; mapped-v4 endpoints are refused.

Affected macOS/Linux strict library/binary checks and three architecture guards
passed during central integration. A live socket is distinct from a quiescent
socket: endpoint creation checks handle ownership, and an extra slot is
reused only after closure, all endpoint references and pending send completions
are gone. The receive loop skips only closed owners; it polls healthy idle
sockets to register their read waker and receive original packets. Quiescence
remains a separate teardown/debt diagnostic. Ready deadline alarms terminate
their original request immediately. Historical runtime receipts retain their
original inputs and do not qualify this successor.

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
the owner. This recovery implementation and its normal PROGRAM integration are
source changes; complete UDP peer interoperability and recovery qualification
require their own normal-runtime evidence.

A verified PILS HELLO refresh on the same physical MQ can change its local
revision and validity while retaining exactly the same active key context. In
the normal Reference029 profile, an ordinary address FEED produces such updates. `IdentityEpoch::refresh_client` and `refresh_native` explicitly adopt the latest
public observation only when its original epoch, public peer, derivation hash
and signature coverage remain identical and local key status remains Matched. The latest announcement must still be valid and its revision cannot move back. This updates no private key, UDP nonce, replay namespace, ACK credit or original
operation deadline. Rejection leaves the previous binding unchanged; a closed
owner cannot be revived. Key borrowing still requires exact equality with the
client's current observation after this explicit refresh.
