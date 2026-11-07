# Official SETI native service

`gnunet-seti-host::Server` composes the allocation-free SETI core, actual
ServiceRuntime accepted IPC sockets, and one explicit CADET native CLIENT. It creates no resolver, task or thread. Caller-owned core and CADET backing have
independent lifetimes; the movable owner contains no self references or leaked
allocation. The executable is `gnunet-service-seti -c official.conf`.

The complete active IPC commands are CREATE, ADD, EVALUATE, LISTEN, ACCEPT,
REJECT and CANCEL. There is no invented REMOVE/ITERATE command. Local input and
result/suggestion output use the official codec and native RESULT ABI. All wire Bloom reconciliation runs in `gnunet-seti`; this adapter does not replace
it with a private element-list or successful mock peer port.

## Driver

Construct `Server::new(core_service, actual_cadet_client, Limits, ServiceOptions,
UnixAccess)`. Core and native limits should agree with the supplied fixed storage. A mismatch produces an explicit original-source/resource refusal; it cannot grow
an unbounded queue. The CADET client's canonical clock is the only clock
used for logical operation deadlines. Its native connection is caller driven.

`poll(cx, &[service::Listener], entropy, wait_deadline, observer)` advances one
fair bounded transition, rotating local MQs, CADET IO, peer work, Bloom
construction/retirement and acceptance. `drive` is only its poll_fn wrapper. Canceled observation futures preserve every accepted RX/TX cursor, held immutable
frame, channel operation, processing delivery and original physical source. Callbacks are synchronous after committed facts and cannot reenter the owner.

A logical LISTEN is bound to a pure `Port` only after the CADET PortOpen
writes. An original CADET MQ loss revokes that binding; a reannouncement
creates a new pure binding. An outbound operation requests the exact expected
peer/app port and waits for service-granted send credit before binding
its pure `PeerSource`. This local service fact grants no proof of remote
application acceptance/delivery. Incoming identities and ports come from the
CADET source and typed channel metadata, never SETI plaintext claims.

Each MQ retains one output; only positive native writes call exposed,
and only the complete original frame calls written. PeerQueued correlates the
original SETI effect with its CADET transmit; PeerWritten proves local
writing only. If a remote channel is destroyed while its immutable native DATA
suffix is still pending, RetiredData retains the original attempt until actual
writing/MQ loss. RetiredWrite reports those later physical facts without reviving
the old operation or applying them to a reused row. Such original pending attempts
also prevent early operation-slot retirement.

A received outer CADET msgstring is retained without another payload copy. Every
complete inner message is processed in order. The outer receive_done is
queued only after every original pure Delivery is eligible and consumed. The
initial operation request remains uncredited through suggestion writing and local
ACCEPT. Invalid/oversized input closes the channel without fake credit;
no tail is truncated and no private fragmentation header is introduced. Outgoing
context plus its 72-byte request must fit the real 64348-byte CADET application
limit; BF chunks use the official 60 KiB frame ceiling.

A later channel Destroyed preserves earlier complete held DATA for its
original running operation. Its original pure processing Delivery must become
ready and be consumed before that packet cursor advances. A fully consumed outer
packet on the gone channel is released locally, without native receive_done or
an invented ACK. Local cancel/failure abandons held input; a gone initial request
cannot create or wait for a new local acceptance. Other channels' credit
and MQ events keep progressing. No new DATA is sent on the gone channel, and
original admitted suffixes settle as RetiredData with exposure/whole-write
facts before the pure peer_lost callback. Such late writes do not advance protocol
DONE. Existing validated peer DONE or an already-written original local DONE,
original result/output obligations, cancellation and failure determine completion;
physical destruction never supplies missing protocol evidence or renews a target.

Fixed mapping limits bound local clients, listeners and live/rejected channels. Payloads remain in the shared pure element pool; each operation borrows its chosen
bitmaps/Bloom/context. Native RX storage is created only for accepted MQs,
with at most one held outer DATA per channel. One global peer preparation and
one immutable output per application MQ bound extra frame storage. Two
read-only pure output-readiness hooks avoid allocating a maximum frame on every
idle MQ/channel poll. All frame allocations use fallible reservation before core
output acceptance; final native copies reserve before consuming CADET credit. A permanently refused ordered IPC input/output closes only that original MQ and
preserves its loss. If incoming mapping capacity is exhausted, the shared
CADET MQ is stopped, retiring all of its channels with exact original loss facts;
no unsupported failure wire or ACK is invented.

`Limits.operation_lifetime` optionally imposes an explicit original logical
policy. Default None preserves C's unlimited established-operation lifetime. Initial incoming request expiry still follows the pure finite timeout. Every
admitted native CADET frame has a separate finite send_timeout. A stalled
frame's deadline actually detaches/reconnects the original shared CADET MQ,
including a partial suffix. TTL/cancellation alone is never physical settlement. Ports may reannounce after attachment; old channels, exposed application
frames and canceled operation results are never replayed onto a replacement.

`request_shutdown(Soft)` stops admission/announcements while clients drain. The caller owns the finite grace. `close(observer)` requires no clock: it actually
stops all local MQs, closes the original CADET owner, preserves independent losses
and attempts all remaining metadata retirement. Its Close report preserves the
first cleanup error and retained count. It does not claim remote processing or
remote effects quiescence. Drop is not a replacement for explicit close/reporting.

## Foreground

The foreground uses official [seti] endpoint/ACL/TOLERANT/USER/UNIX_MATCH_UID/
UNIX_MATCH_GID, inherited listener activation, UID/GID initialization, signals and
parent-control bytes. Its one explicit Resolver/context and clock are
shared with [cadet] endpoint selection; no hidden Resolver is started. It builds
all bounded backing before physical connection. READY is printed only after an
CADET MQ attaches; the field says `backend=cadet-client-attached`, not that
remote peers or application operations have succeeded.

[seti-rust] settings: MAX_CLIENTS(16), MAX_SETS(8), MAX_LISTENERS(8),
MAX_OPERATIONS(32), ELEMENT_SLOTS(1024), ELEMENT_BYTES(1024),
LARGE_ELEMENT_SLOTS(16), LARGE_ELEMENT_BYTES(native RESULT maximum),
BLOOM_BYTES(64KiB/operation), CONTEXT_BYTES(1024), HASH_ROUNDS(256),
MAX_EXCHANGES(1024), IO_SLICE_BYTES(65535), optional OPERATION_TIMEOUT,
SEND_TIMEOUT(30s), CADET_STARTUP_TIMEOUT(15s), SHUTDOWN_GRACE(10s). Shared element bodies are not replicated per channel; the optional large slab
surplus admits large elements without assigning each ordinary element a 64KiB
buffer. Foreground validates an aggregate backing ceiling of 128MiB.

The sole added model drives this SETI service and the existing production
CADET service in own-peer mode over IPC sockets, with three-byte syscall
slices. It exercises two separate set MQs plus a listen MQ, genuine Bloom/full
and removal-delta results, and independent close. It is not a C peer or
remote encrypted-network interoperability claim. No prior C component evidence is relabeled.
