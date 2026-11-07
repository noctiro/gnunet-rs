# CORE application and monitor IPC

Pure current-profile layouts live in `gnunet_wire::official::core`. The
`gnunet_client::core` module owns application peer/request state and a standalone
continuous monitor. Neither layer implements the CORE service, CAKE or a complete
node. The production dependency direction remains client -> wire, without crypto,
runtime, facade or libgnunet implementation dependencies.

The baseline is official v0.29.1 commit
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`, especially `core.h`, `core_api.c`,
`core_api_monitor_peers.c`, `gnunet-service-core.c`, the session queue and constants.

## Complete current application/monitor message scope

| Message | Type | Current layout/meaning |
| --- | ---: | --- |
| INIT | 64 | Eight-byte prefix, option bits and BE16 subscriptions |
| INIT_REPLY | 65 | 44 bytes; local identity and native enum32 class |
| NOTIFY_CONNECT | 67 | 44 bytes; remote identity and native enum32 class |
| NOTIFY_DISCONNECT | 68 | 40 bytes; reserved zero and peer |
| NOTIFY_INBOUND | 70 | 36-byte prefix plus full message or header-only preview |
| NOTIFY_OUTBOUND | 71 | Same layout with opposite traffic direction |
| SEND_REQUEST | 74 | 56 bytes; priority, deadline, peer, reserved, size and echoed ID |
| SEND_READY | 75 | 40 bytes; permitted size, original ID and peer; zero rejects |
| SEND | 76 | 48-byte prefix plus complete inner-message sequence |
| MONITOR_PEERS | 78 | Header only, independent of INIT |
| MONITOR_NOTIFY | 79 | 48 bytes; state BE32, peer and timeout BE64 |

The profile explicitly handles both inbound/outbound full and header previews,
zero-size READY rejection, and the state11/zeropeer/FOREVER snapshot marker.
The marker completes the initial snapshot and monitoring continues afterwards.
Unknown informational class/state values remain representable. Current reserved
fields, option bits, framing, nested lengths and unknown message identifiers are
validated. A complete four-byte message is indistinguishable from its complete
header preview on the wire; decoding returns `Traffic::Full` in that case.

`CORE_NOTIFY_STATUS_CHANGE` 69 and `CORE_PEER_ID` 1811 exist in the pinned registry
but have no active layout/handler/reference outside that registry in the pinned
source. No imaginary layout is assigned to them. This observation does not remove
future external variants from the interoperability scope when upstream changes.

The C public connect API copies a required service-info argument, but currently
does not serialize it into INIT. Do not invent an extra field. INIT_REPLY creates
the local loopback peer in the Rust client without fabricating a CONNECT
wire message. Local identity observations across reconnect are explicit events.
ClassOrder selects the source-native enum32 profile only for 65/67; remaining
numeric fields use network byte order. Big-endian compilation/unit checks do not
establish big-endian reference execution.

## Send ownership and immutable admission

`SendOperation<T>` owns a payload **source**, which can be a Vec/Box on a host or
a borrowed slice in no_std. Request admission locks its peer, size, priority,
deadline and original operation identity. An arbitrary safe `AsRef` implementation
may change views, so request admission makes no promise that body bytes are fixed
yet. Same-length deferred generation after READY is supported deliberately.

Only a matching `(peer, request_id)` nonzero READY authorizes `prepare_payload`.
It reads AsRef once, rechecks the body, and encodes once into caller storage.
The returned PreparedFrame borrows that storage immutably. Later partial
write reports never reread T or regenerate bytes; a second preparation is refused.
The host must retain the same frame through its IO future. A std host can retain
one admitted owned-frame copy instead of keeping a borrowed scratch buffer.
The Cell-based regression demonstrates that safe AsRef view changes cannot
replace an admitted partially written frame.

One original operation is active per peer. The owner combines an instance brand,
connection epoch, peer/slot generation and a local serial with the finite echoed
16-bit wire ID. Matching READY retires the older reply frontier on the reliable
ordered service MQ. Normal progress permits wire-counter wrap; more than 65535
unanswered/canceled IDs causes explicit backpressure before reuse. No private
generation field is added to the wire. Foreign/old local capabilities cannot
authorize another instance or physical connection.

A same-MQ peer DISCONNECT is a server-to-client ordering barrier. The pinned
service removes/frees active client requests before queuing DISCONNECT, and
READY uses that same append-tail FIFO. Thus an already queued READY cannot cross
the barrier. This does not order the opposite byte stream: an original client
SEND_REQUEST may still be queued or partial when DISCONNECT and a new same-PID
CONNECT arrive. Its remaining bytes may then reach the new server connectmap
entry, legally producing an old echoed ID after the new CONNECT. The service
also explicitly replaces an existing same-PID CAR when a newer request arrives.

The Rust owner retains a bounded per-PID issued/READY frontier for unsettled IDs
across peer generations on the same physical MQ. Those tombstones consume P
slots alongside live peers and cannot be evicted or reset while IDs remain
unsettled. A new generation continues that frontier, preventing an old original
request from granting a newer operation. Settled frontiers may be released at the
server disconnect barrier. Physical-MQ retirement clears obsolete tombstones.
Metadata capacity or exhausted unanswered ID range is explicit backpressure;
the host may retire/rebuild the MQ when progress requires it. Disconnecting A
does not itself close the shared MQ or disconnect a healthy B. No generation
field is added to official messages. The Unix regression preserves both
stream orders and the original partial request; it is a controlled fixture,
not a normal C remote-peer execution.

READY is permission, not transmission or delivery. A zero permit yields Rejected.
Only full local CORE_SEND writes yield Written, which does not promise
remote application delivery. Cancellation before payload emission removes that
payload; its already admitted SEND_REQUEST must still drain. A partial payload
must drain unchanged or its whole MQ must close. Cancellation after a partial
write reports uncertainty, never definite remote non-delivery. Peer/connection
loss preserve original outcomes and return the original owned source once.

## Payload boundaries and source inconsistency

The raw IPC envelope can carry 65487 inner bytes. The current normal C remote
session queue additionally rejects aggregate requests above 64512 bytes, while
self-loopback bypasses that queue. The C transmission loop asserts that **each**
inner message is strictly below 64512 even though its request check permits an
aggregate equal to 64512. The client therefore preflights remote aggregate <=64512
and each inner <64512, both at request admission and deferred body freeze. A
compound aggregate of exactly 64512 with smaller members remains supported.
Loopback and raw codecs retain the full IPC envelope range.

The inconsistent single-message boundary is recorded from source; the known C
assert path was not executed or credited as successful interoperability. The
Rust service implementation can avoid that failure, while tests against the
version-pinned C service must preserve the explicit safe profile and exception.

## Monitor and verification boundary

Monitor cancellation/loss closes its original physical MQ; no UNWATCH/END message
is invented. A fresh connection starts a new snapshot and epoch. State12 is the
current C API's **local** reconnect callback value, not a server END. The initial
C monitor start installs its callback only after reconnect setup, so it does not
emit that local callback on its first connection. A monitor snapshot marker can
carry an all-zero peer pointer in the C callback rather than a literal NULL;
the Rust owner identifies the marker fields.

The std `core-ipc-oracle` example uses production codecs/owners for independent C
vectors, a C public application/monitor client against a Rust socket fixture,
and a Rust application self-loopback/monitor against an C CORE service.
The header-only observer uses a nonmatching subscription: current C treats an
empty subscription list plus observation flags as an inbound wildcard and sends
full inbound data. The owner accepts the valid full/header wire forms.
These are component IPC observations, separate from CAKE peer execution and
independent-node acceptance. The optional `gnunet-core-client-host` adapter supplies caller-driven native
application and monitor owners. SDK feature `official-core-client` selects it
independently of the CORE service host. It owns bounded exact message sources,
immutable wire frames, native attempts and timers, and one canonical-clock
listener. Its drive future may be canceled without dropping these owners. Actual
positive payload writes reach the pure original operation before further RX.
Owned traffic allocation precedes pure frame consumption. Capacity refusal
retains the exact complete frame for retry or explicit MQ retirement. Loss
stops the original physical owner first, then returns original completions and
all peer notices before starting another physical epoch. No application source
is replayed automatically. Full service/NSE/native node acceptance remains
separate work.
