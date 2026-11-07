# Official MESSENGER native IPC client

`Client` owns one caller-driven official Unix/TCP MQ using the common CLIENT,
canonical clock and retained framing layers. It creates no task, hidden Resolver,
service, room, key or storage. The higher Messenger domain owns room/member
state, message authentication, history and notification interpretation.

The port exposes the CREATE, DESTROY, OPEN, ENTRY, CLOSE, SYNC, SEND and
GET containers and every active asynchronous notification. There is no wire RID,
generic response, SEND ACK or invented cancellation. Local `Operation` and
`Epoch` tokens are checked source metadata and never enter official bytes.

`submit_bounded(request, expires, hard)` accepts a higher owner's original
absolute source-clock and native targets. Both are checked after immutable
encoding/allocation and clock sampling, before admission or I/O, and retained
unchanged with the operation. Expired input leaves the live source untouched;
clock failure physically retires it and preserves its original loss. The duration convenience method shares the same preflight/admission path.

1. Create one `Instance` and a `Client` with an explicit `EndpointSource` and
   finite `Limits`. The initial connection+CREATE deadline starts at construction.
2. Drive `progress()` until the actual `Attached(epoch)` event. Submit CREATE,
   then observe its whole `Written` event before admitting other requests. Neither event proves that the remote service processed CREATE.
3. Submit borrowed official requests with a finite original write timeout. The
   client serializes once into zeroizing immutable storage. A single actual
   framed queue preserves original FIFO ordering. Positive prefixes and complete
   writes are reported before another service read. `Written(Send)` is local
   exposure only; the sender domain handles any later RECV notification.
4. `Notification` retains one zeroizing original outer frame and exposes checked
   borrowed IPC fields. Incoming flags, member reset values, room identifiers and
   message bytes are preserved. No operation is selected by notification arrival
   order. Encoded SEND/RECV message tails remain opaque to this port and confer no
   hash/signature validity or room/member authority.
5. Dropping a `progress()` future cancels only that wait; all original native
   cursors remain in the client. Explicit `cancel(operation)` physically stops
   the entire MQ and reports each pending original frame's exact positive prefix. It sends no invented CANCEL and claims no rollback of exposed service work.
6. Loss, malformed input, clock/port refusal or any original timeout physically
   retires the MQ before publishing `Lost`. A partial input has one deadline
   anchored to its first positive byte. Native bounds and wake registration run
   before canonical revision-race waits. Timeouts never refresh on observation.
7. Explicit `reconnect()` reserves a fresh source after loss, recovers an actual
   refused clock/Resolver port if needed, and starts a fresh initial deadline. It retains no old CREATE, room or message request. The caller must invalidate
   original room ownership, await the new epoch, and perform a new CREATE.
8. DESTROY drains behind prior admitted requests; its whole write closes
   this client permanently. Explicit `close()` is immediate physical retirement.

The queue is bounded by original frame count and allocated payload
capacity, with separately fixed RX storage and fallibly reserved metadata. It
holds at most one original framed TX and one RX; it does not keep a second parsed
message cache. Returned notifications/loss reports are caller-owned and no longer
part of this client's retained budget. No physical RSS/performance claim follows
from these logical bounds.

The reference is GNUnet v0.29.1 commit
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`, particularly `messenger_api.c`,
`messenger_api.h`, `gnunet-service-messenger.c` and the public service header. The one controlled Unix model uses fixed public mock room/hash/member arrays and
an explicitly opaque message tail. It exercises this native IPC port only;
it does not execute cryptography, keys, persistence, C actors or an actual
Messenger room service. Full Messenger domain/native service/API composition and
official interoperability remain unfinished.

The pinned MEMBER_ID reset producer/reader uses native u32 without
htonl/ntohl. Response encoding/decoding therefore requires the explicit original
producer Profile; the native client retains Limits.profile in each Notification. Other network u32 fields, including RECV flags, remain BE. This is one documented
reference wire property, with no private extension or old compatibility fallback.
