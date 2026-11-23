# Actual QUIC and HTTP3 communicator host

This host owns one Quinn endpoint, the standard communicator MQ, one
public PILS client, an optional NAT registration, and fixed caller-supplied
application loans. It contains no TCP/UDP communicator business implementation,
libgnunet FFI, hidden Resolver, detached Tokio task, or peer-authentication claim.

`Runtime::new` requires a current Tokio runtime, explicit fixed TLS material,
selectors sharing one RuntimeClock, finite Limits, and a matching Buffers pool. It snapshots all live selectors together before admission. Remote queue addresses
are the admitted numeric `quic-`/`http3-` address codec. A `None` NAT source explicitly selects
local-only operation, advertising only a concrete bound numeric address;
a wildcard is never presented as a learned public address.

The raw profile retains stream0 without FIN/reset/STOP and continues accepting
stream4. The original 32-byte identity proposal and GNUnet frame cursors survive
canceled drive futures and partial provider writes. H3 uses its own concrete
HTTP3 link and pure slot loans, preserving the official application framing.
The shared [compatibility contract](../../spec/gnunet/compatibility.md) defines
peer interoperability qualification.

## Embedded foreground

`embedded::serve` owns the receive pool and runs the communicator on the
caller's Tokio reactor. With `embedded-config`, `Configured::read` and
`serve_configured` use the standard bind, TLS files and resource settings.
Use `read_with_environment` to provide an explicit filename context.
Both entry points take the original TRANSPORT, PILS and optional NAT selectors.
The caller supplies one shared clock through these selectors.
`Settings.socket_policy`, or the explicit policy argument after `network_changes`
in `serve_configured`, prepares the original UDP endpoint before bind. Both raw
QUIC and HTTP/3 use that same endpoint through identity replacement. Standalone
and low-level `Runtime::new` startup use the ordinary process policy.

Readiness gives the verified local peer and numeric bound UDP endpoint after
the original TRANSPORT registration is written. The `NetworkChanges` receiver
advances the original interface scanner. NAT retains address publication.
Complete the stop future and await retirement of the same runtime. The
`h3-profile` feature enables HTTP/3.

## Ownership and local facts

A queue id is checked, never reused within this allocation, and belongs only to
its original MQ. The source allocation is pointer plus checked caller Instance
allocation. An incoming frame has its exact private profile FrameId and one
original flow id. A matching Received callback is accepted only after the actual
Incoming frame completed its local MQ write. Closing the MQ classifies remaining
callback debts as lost; it cannot generate processing or FC acknowledgments.

A queue admits one SEND into its exclusive bounded state before releasing the
physical MQ frame. It retains one immutable allocation, original message id,
queue and hard bound. Native stream pressure leaves that SEND queued while
later MQ commands, including flow-control acknowledgments, can progress. When
native capacity becomes available, the allocation moves once into the original
Link without renewing its deadline. Queued bytes have no native acceptance;
submitted bytes retain their known provider prefix and unknown-exposure facts.

The local Sent result and additional queue credit use the same physical FIFO.
Credit is restored only after both frames complete local writing and the
exclusive SEND state is released. Credit describes this admission state, not
temporary HTTP stream availability. An H3 POST can still own its native/profile
row after its DATA was accepted and its local Sent result was written; that row
is reused only after its original response, body retirement and output
completion. Sent whole-write and provider plaintext acceptance do not prove UDP
transmission or remote HTTP/peer processing. Whole provider acceptance is never
automatically replayed as a new POST or stream message.

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
frames/bytes, receive slices and total source lifetime are separately bounded.
The UDP socket uses Quinn's ancillary-data backend through bounded Tokio
readiness. Each receive poll attempts one batch of up to eight buffers.
An isolated error, including Windows ICMP TTL expiry, schedules another
poll through the original endpoint owner. Other receive failures retain their
native cause. Recoverable send failures count as datagram loss and only bytes
accepted by the UDP socket contribute to the send total.
Raw incremental reads use 1024 bytes of scratch space per retained connection.
A full FIFO or held callback does not renew a deadline, create another
operation, or count as IO progress.

Quinn runs TLS 1.3 through explicit Rustls configurations, with profile-specific
ALPN and early data, resumption and tickets disabled. The
[shared Rust provider](../tls-crypto-std/README.md) handles handshake and packet
protection and checks CertificateVerify signatures. The adapter supplies Rust
Retry integrity, stateless reset and address-validation token keys. Configured
credentials use the shared provider's private-key validation and signing.
GNUnet peer authentication remains the responsibility of the transport protocol.

## Native NAT

The single bound UDP address and actual port are registered with NAT through
its native sockaddr ABI. IPv6 listeners use `IPV6_V6ONLY` on all hosts.
A numeric `BINDTO` port selects a wildcard, with `DISABLE_V6` selecting
the IPv4 wildcard. A literal address selects its own family.
Peer dials and advertisements use the bound address family and a concrete
unicast address with a nonzero port. IPv4-mapped IPv6 addresses and IPv6
link-local routes or addresses with zone or flow metadata are refused. A bad
peer address refuses the original queue request and preserves the endpoint.
NAT add/remove callbacks retain their original AddressId. Publishable addresses
receive a standard TRANSPORT address id. Other callbacks retire through NAT
without blocking valid announcements. A NAT end retires this source. The pinned
raw C communicator
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
new pairs use exclusive creation and native private file permissions. Original
parent-directory and file handles authorize cleanup; a replaced credential link
is refused. Partial pairs remain an explicit error. File flushes and directory
barrier observations stay separate.
[Native directory barrier](../native-std/API.md#anchored-filesystem-operations)

Linux, macOS, FreeBSD and Windows share the same runtime. Native client startup
captures original inheritance once and refuses service listeners. Unix applies
configured process privileges; Windows verifies the configured primary-token
SID. Shared native stop subscriptions retain the original parent control.
Identity selection and the first stop check precede TLS credential and UDP
endpoint creation. On Windows, the endpoint sets `SO_EXCLUSIVEADDRUSE` before
binding and gives the same socket to Quinn.
Standard-stream and credential-file calls retain native OS blocking semantics.

`program.rs` selects PROGRAM options and identity. `program/scheduling.rs`
composes the shared foreground scheduler, Resolver and stop latch;
`program/drive.rs` owns runtime progress and retirement. Credential namespace
ownership and independent terminal errors live in their respective modules.
Within the runtime, `send.rs` owns SEND admission, `recovery.rs` handles physical
TRANSPORT replacement, and `retirement.rs` settles original connection debts and
driver ownership. Raw and HTTP/3 links own their respective native framing.

## Building

```sh
cargo build --release -p gnunet-communicator-quic -p gnunet-communicator-http3
```

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

Never-submitted queued bytes are erased when their physical MQ fails. A native
reliable stream send keeps its exact SendId, original deadline and exposure facts
while draining, including when no accepted prefix has yet been observed. Its
replacement queue can be announced with zero credit while that original SEND
occupies the admission state. Only after it settles can a capacity update be
sent, without an old SENT result. Failed old receive callbacks release their
original application frame as local retirement, not successful delivery. Native
source loss and explicit shutdown still close their original endpoint and drivers.

Local IPC cases cover partial-prefix EOF/reconnection without FIFO replay,
malformed framing remaining fatal, source identity pauses and announcement
ordering. Their fixtures select the shared native AF_UNIX owner.

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
observation rather than duplicated peer/expiry fields.

PILS EOF and connection I/O loss enter that same retirement path with no
verified target. The old TRANSPORT source, connection drivers and frame loans
retire before the retained PILS client can reconnect. A new socket alone grants
no identity or IPC admission. A signed, unexpired observation must have a
strictly newer epoch of the same client and a newer identity revision before
IPC and endpoint admission resume. The endpoint, TLS configuration, NAT claims,
frame pool and serial counters remain owned by the process. Repeated losses
retain the first source cause and original recovery window. Protocol, resource
and clock errors remain terminal; a failed recovery returns both its first
connection loss and independent terminal error.

The identity state machine is separate from connection/loan retirement. A
shared native connect gate and framed IPC checks enforce the same recovery
bound after clock providers, before socket creation and before read/write.
Queued frames retain their admitted hard bounds. Recovery completion requires
actual REGISTER/address writes and a fresh deadline check. Retired partial
prefixes remain unknown exposure; they are never replayed as fresh output.
Raw and HTTP3 retain their own application/TLS/ALPN semantics; the official
public peer proposal gains no GNUnet authentication.

## Statistics publication

See [statistics ownership and shutdown](STATISTICS.md) for metric semantics,
independent publisher failure and bounded final drain.
