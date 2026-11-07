# Actual QUIC and HTTP3 communicator host

This host owns one Quinn endpoint, the standard communicator MQ, one
public PILS client, an optional NAT registration, and fixed caller-supplied
application loans. It contains no TCP/UDP communicator business implementation,
libgnunet FFI, hidden Resolver, detached Tokio task, or peer-authentication claim.

`Runtime::new` requires a current Tokio runtime, explicit fixed TLS material,
selectors sharing one RuntimeClock, finite Limits, and a matching Buffers pool. It snapshots all live selectors together before admission. Remote queue addresses
are the admitted numeric `quic-`/`http3-` address codec. Local configuration is
handled by the separate PROGRAM module. A `None` NAT source explicitly selects
local-only operation, advertising only a concrete bound numeric address;
a wildcard is never presented as a learned public address.

The raw profile retains stream0 without FIN/reset/STOP and continues accepting
stream4. The original 32-byte identity proposal and GNUnet frame cursors survive
canceled drive futures and partial provider writes. H3 uses its own concrete
HTTP3 link and pure slot loans. It is not HTTP/1 or a private stream framing. The selected upstream h3 implementation identifies itself as experimental; these
sources do not claim runtime or mixed-C qualification.

## Ownership and local facts

A queue id is checked, never reused within this allocation, and belongs only to
its original MQ. The source allocation is pointer plus checked caller Instance
allocation. An incoming frame has its exact private profile FrameId and one
original flow id. A matching Received callback is accepted only after the actual
Incoming frame completed its local MQ write. Closing the MQ classifies remaining
callback debts as lost; it cannot generate processing or FC acknowledgments.

A SEND is admitted to one concrete original Link before the held RX is released. It retains one immutable copy, original message id, original queue, hard bound,
known provider prefix and any unknown-exposure report. The local Sent
result and additional queue credit use the same physical FIFO. Sent whole-write
is separate from provider plaintext acceptance; neither proves UDP transmission
or remote HTTP/peer processing. Credit is restored only after the original Sent
result and credit frame really completed local writing, and the link has a free
bounded send reservation. An H3 POST can still own its native/profile row after
its DATA was accepted and its local Sent result was written; that row is reused
only after its original response, body retirement and output completion. Initial
and recovered queues advertise zero credit while that reservation is unavailable. A command already held by the MQ keeps its original deadline until capacity
returns. Whole provider acceptance is never automatically replayed as a new POST
or stream message.

Every original native hard alarm is registered before clock or provider polling. Source lifetime, partial input, callback and send bounds remain finite. Logical
clock rollback never extends the native bound. The first close fixes its grace;
canceling shutdown cannot restart it. Unexpected clock/source errors physically
retire all original MQs and backend/application owners before returning the
original error, preserving independent backend cleanup facts for shutdown. Each retired connection also fixes a finite original close bound; an overdue
unsettled backend/FC/output debt retires the whole source instead of silently
freeing its driver ticket for another peer. Already observed completions
can be reaped without granting a new operation after expiry. Normal close first closes connections, drops the sole endpoint handle,
and then polls original driver futures until completion or fixed grace. Any
forced drop is explicitly reported, not called successful completion. Kernel
close errno is not separately available through Quinn/std; no such receipt is
invented. Loans return only after the old drivers are complete/dropped
and original stream/FC/output ownership has been retired.

## Resource and runtime boundaries

The backend pool reserves one endpoint driver plus one slot per retained real
connection. The pinned Quinn constructors have two synchronous spawn sites. A ticket is reserved before entering either constructor; runtime.spawn has no
capacity-overflow discard path. Every driver future is polled and dropped
outside the shared mutex. A Polling slot still occupies its original capacity. Endpoint/Runtime clones never escape this owner. No Quinn spawn is delegated to
Tokio spawn. Application futures remain caller-driven current-thread state.

Caller pools cap retained connections and bodies. Raw default receive slabs are
1232 bytes while the advertised outbound queue MTU remains1000. H3 default body
slabs are1452 bytes, outbound MTU1080, and each connection requires at least
polls+2 slots. Backend QUIC windows, pending initial bytes, stream credit, output
frames/bytes, receive slices and total source lifetime are separately bounded. The socket wrapper limits each receive batch to8. The raw incremental
read scratch is1024 bytes per retained connection. A full FIFO/held callback does
not renew a deadline, create another operation, or count as IO progress.

TLS uses explicit caller-provided Rustls/AWS-LC configurations and Quinn
rustls adapters. TLS1.3 only, exact ALPN, no early data/resumption/tickets, and no
global default provider. GNUnet transport certificates follow the explicitly
untrusted C policy, while TLS CertificateVerify signatures are checked by
the provider; a certificate or raw PID proposal never authenticates a GNUnet
peer. HOSTLIST PKI policy is unchanged. This is not a pure-Rust cryptographic primitive/FIPS claim.

## Native NAT

The bound UDP port is registered with the explicit native sockaddr ABI. Actual add/remove address callbacks retain their original NAT AddressId and map
to distinct standard TRANSPORT address ids. No REGISTER ACK or NAT reachability
success is invented. A NAT end retires this source; no old registration or
one-shot mutation is replayed into another epoch. The pinned raw C communicator
has no reversal implementation and no STUN handler; reversal notifications are
explicit diagnostics rather than fake completed operations. Actual bounded interface snapshots implement the public nt.c loopback/local
prefix/WAN categories. A120-second default refresh is caller-configurable. Refresh failure preserves its error and classifies new observations as
Unknown0; neither a NIC category nor a snapshot proves remote reachability. Existing queues keep their original attributes. Native address
scope/flow restrictions follow the shared admitted address codec.

## Runtime composition

The `program` feature connects the shared standard PROGRAM to this runtime,
configuration, selected logging, signals, Resolver and caller-owned receive
pools. The `gnunet-communicator-quic` and `gnunet-communicator-http3` binaries use
that entry point. Configured TLS pairs are loaded with finite byte/chain limits;
new pairs use exclusive creation, private modes and retained cleanup errors.

The earlier unavailable-compiler observation remains
historical and does not describe the current toolchain.

Those results
remain unproved; successful compilation does not qualify the full GNUnet peer.

## TRANSPORT source recovery

The normal raw QUIC and HTTP/3 programs retain the original QUIC endpoint, TLS
state, application streams, PILS identity, NAT registration, clock and lifetime
when only the local TRANSPORT MQ fails. The same CLIENT channel physically
detaches the failed MQ and retries. Exact old output prefixes and input/flow
debts retire with that generation; old payloads, SENT results and flow ACKs are
not replayed on the replacement. Protocol, clock, provider and permanent resource
errors retain their terminal failure boundary.

The replacement writes a fresh standard REGISTER and announces current addresses
and live queues with fresh local IDs. Finite address validity uses the remaining
original logical and native lifetime. Each current address and queue needs its
whole-write fact before the recovery milestone is emitted; ongoing data
does not require a globally empty FIFO. Initial startup expiry applies only until
the first Ready, while every original operation and overall lifetime keeps
its original target.

An accepted reliable stream send keeps its exact native SendId and original
deadline while draining. Its replacement queue has no credit until that native
send really settles. Only then can a new capacity update be sent, without an old
SENT result. Failed old receive callbacks release their original application
frame as local retirement, not successful delivery. Native source loss and
explicit shutdown still close their original endpoint and drivers.

The three local IPC source cases cover partial-prefix EOF/reconnection without
FIFO replay, malformed framing remaining fatal, and announcement/removal
prefix completion without waiting for later unrelated data. They are controlled private
Unix MQ witnesses, not normal C interoperability, QUIC/TLS traffic, whole-process
resource measurements or full feature qualification.

SEND result and queue credit/withdrawal admission use the encoded extent of the
standard request. A 52-byte SENT result waits when only 48–51 bytes remain,
without releasing its original input, queuing a duplicate result or treating
temporary output pressure as a failure of the shared communicator. The local MQ
capacity regression fills the retained output budget to 51 spare bytes,
keeps the original SEND and deadline, then drains a whole frame and checks that
exactly one unchanged result follows the earlier outputs. It does not require
QUIC/TLS or simulate peer delivery.

Both normal QUIC and HTTP/3 programs select the PILS identity/HELLO profile from
`[PILS] PROFILE`: `reference029` (also `reference-0.29.1`) is the unchanged
default; `deterministic` (also `reference-deterministic`) selects the official
conditional address-derived profile. Explicit `lsd0014-text` selects the
published textual derivation and grants no official interoperability claim. Optional `[communicator-quic-rust] PILS_PROFILE` or
`[communicator-http3-rust] PILS_PROFILE` must agree with an explicit global
choice. The selected `Limits.identity_profile` reaches the PILS client;
it is independent of the raw QUIC versus HTTP/3 TLS/ALPN application profile. Healthy changed PIDs on the original branded observer enter explicit
Retiring and Restoring phases. The process endpoint/socket, TLS configuration,
NAT observations, external frame pool, original clock and publisher survive. Each connection freezes its local PID before its handshake; it cannot
adopt a later process PID. Original MQ output/FC/send authority retires without
replay, and old connections close before their drivers and loans retire. An overdue connection driver is force-canceled explicitly; the endpoint driver
is a distinct protected ticket and remains alive. Each original retirement target is checked at that exact
future's poll boundary. One endpoint turn visits every slot once; vacant slots
cannot repeatedly rescan and poll the same live future. Forced cancellation is
not a successful remote drain. New IPC attachment/admission follows that barrier.

Repeated announcements, including changes during local restoration, share one
original native/canonical 30-second recovery window. Actual REGISTER/address
announcement completion clears it. Original connection operation bounds and
queue/flow/send serials do not reset. Current identity comes from the typed PILS
observation rather than duplicated peer/expiry fields. Physical observer loss
retains its original producer cause and remains fatal. Raw and HTTP3 retain
their own application/TLS/ALPN semantics; no GNUnet authentication is added to
the official public peer proposal.
