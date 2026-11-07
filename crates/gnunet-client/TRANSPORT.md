# Current TRANSPORT client boundary

`transport` implements the GNUnet v0.29.1 `GNUNET_TRANSPORT_CORE_VERSION`
client/service IPC family 360..366. It provides exact checked codecs plus a
bounded sans-I/O client owner. It does not implement the TRANSPORT service,
communicator manager, CORE CAKE or a complete node.

The source authority is the unchanged official commit
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`, particularly
`src/service/transport/{transport.h,transport_api_core.c,gnunet-service-transport.c}`.
The current profile has 40-byte START/CONNECT/DISCONNECT/SEND_OK/RECV_OK;
SEND has a 40-byte prefix and RECV has a 36-byte prefix. SEND has no old timeout
field. Integers are network byte order, nested messages are exact complete
GNUnet frames, and reserved current-profile fields encode zero.

## Embedding the owner

The host owns the service socket, partial read/write buffers, immutable
outbound frames and reconnect scheduling. A `TransportClient` owns peer state,
four initial send credits per peer, original local send cursors/results and
explicit receive-processing tokens. Caller-owned `Instance` storage brands tokens;
foreign instances, old epochs and retired generations cannot affect live work.
Moving the client preserves these capabilities.

1. Establish a configured official IPC connection, then `begin` and retain
   its START frame. Requested self checking is an option sent to the service,
   not a locally fabricated authentication result. The pinned service currently
   comments out its self-id check; the client does not pretend otherwise.
2. Feed complete received frames to `receive`. CONNECT announces a peer; SEND_OK
   returns a send-window credit. Neither event authenticates CORE or establishes
   application delivery. A late SEND_OK for a retired generation consumes only
   that generation's recorded refund, even when the identity has reconnected. An
   absent peer's SEND_OK is ignored, as in the pinned current public client.
3. `prepare_send` consumes one peer credit only after successful bounded encoding.
   Retain that exact frame and report native byte counts with
   `send_bytes_written` before processing further service frames. A zero cursor
   must mean the host knows no byte has entered the stream. A completed write is
   a local `Written` outcome; it does
   not return send-window credit or prove remote processing. Only a SEND_OK
   returns that credit.
4. A received application message has a unique `ReceiveId`. Finish application
   processing, preflight the outbound host queue, then `complete_receive` and
   retain the resulting RECV_OK(delta=1). Dropping a message or waiting future
   never implicitly acknowledges it. Short output and duplicate/stale tokens do
   not return credit.
5. If the host removes an entirely unwritten SEND, `cancel_unwritten` restores
   its one local credit while its original peer generation remains connected.
   After DISCONNECT it releases only that original deferred promise. This never
   grants credit to a reconnected generation. Once bytes entered the stream,
   `cancel_started` suppresses
   local completion while the host drains that same original frame or retires the
   whole connection. No wire cancellation message exists, and partially written
   data cannot be retracted or reported as definitely undelivered.
6. On socket failure call `connection_lost`. Retained pending sends have a
   `ConnectionLost` result; `next_lost_peer` drains each disconnect notice once.
   Reconnect creates a new epoch and START. Old receive tokens and service-frame
   epochs remain invalid; no old pending send is silently replayed.

P, S and R bound peers, local SEND operations and unprocessed receives. The
optional fourth const parameter D (default P) bounds identities retaining refund
ownership on this physical MQ. `prepare_send` reserves that account before
encoding or consuming credit; full accounts reject outgoing admission without
blocking later DISCONNECT or SEND_OK processing. D=0 supports receive-only use.

At DISCONNECT, started or completed outgoing SENDs keep their original refund
debt, independently of whether their local `Written` result has been taken.
Wholly unwritten SENDs retain deferred promises instead: a host may remove and
cancel one without waiting for a refund that will never arrive. If it retains
the frame, its first positive native write converts that promise into old debt.
Preserve the original physical FIFO, including every old partial tail. Retired
debt absorbs refunds before a new generation can gain credit. The wire has no
generation field; local typed generations alone cannot correlate these refunds.
physical connection loss clears all accounts and invalidates old tokens.

R must
admit the initial four-message service receive window for every admitted peer.
The host needs its own byte/frame/backpressure budgets. Resource rejection is
explicit; the client does not alter wire sizes or truncate messages to fit.

## Deliberate internal choices and current limits

Rust uses typed permits and explicit native progress, rather than copying the C
callback/MQ internals. Internal backoff strategy is a host choice. The C cancel
implementation contains source-level assumptions about its own envelope and
window state; the Rust API instead requires honest unwritten/started cancellation
facts and preserves a partial frame. This is a local API contract, not a claim
that every C internal cancellation branch was executed or reproduced.

The supported strict decoder rejects unknown message types, unknown START option
bits, nonzero reserved fields, malformed nested frames and zero RECV_OK deltas.
The owner rejects duplicate CONNECT, payload for unannounced peers and unearned
SEND_OK credit above its initial window. These checks accept the observed normal
current-profile traffic; they do not certify all unusual upstream race paths or
future extensions. Complete profile/recovery acceptance remains separate work.

`examples/transport-ipc-oracle.rs` is a std test observer using the production
codecs and owner. `vectors`/`decode` support independent C comparison; `serve`
hosts a bounded test conversation for a C public client; `probe` drives the
Rust owner against an service socket. This observer is not a production
async host or a replacement TRANSPORT implementation. C services used in these
tests remain independent reference counterparts, not Rust production backends.
