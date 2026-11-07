# Official resolver client core

This code independently implements the v0.29.1 resolver public client's pure
state and IPC contract. It is `no_std`, uses no allocator or native FFI, and
forbids unsafe code. It does not provide a DNS daemon, native gethostname /
getaddrinfo helper, cache or a system DNS fallback.

`resolver.rs` provides borrowed codecs for the official 4/5 messages. The host
supplies an explicit native `FamilyProfile`: IPv6 is 30 on Darwin and 10 on
Linux; IDs are four opaque echoed bytes. A maximum-length forward frame is
65535 bytes (65518 hostname bytes plus fixed fields and terminating NUL), while
65536 cannot be encoded. Capacity/validation failure leaves output unchanged.
Decoded names retain their raw bytes; reverse callback strings use the first
NUL after validating the required final NUL, matching C.

`ResolverHandle<R,N>` owns R slots, each with N bytes of forward-name storage.
Slots cover pending local tasks, queued requests, sent/canceled drains and
pending terminal events. No separate completion queue can overflow after
admission. Failed admission reserves no slot and consumes no ID. Generation
exhaustion retires slots. Request IDs are capabilities **only in their original
owner**; equal slot/generation values in different owners are not detected as
foreign. No global atomics or global singleton is required.

The host retains immutable configuration/endpoint data, supplying the actual
`check_config` result to `new`/`connect`. Numeric forward requests and the two
case-insensitive loopback names bypass this check; numeric reverse requires it.
Native hostname resolution calls the host gethostname helper then admits
that name through `ip_get`. The separate synchronous FQDN helper must use the
normal build's getaddrinfo behavior; returning a raw hostname would not
complete that API.

Drive the owner as follows:

1. Admit `ip_get` / `hostname_get` with the original caller timeout and current
   monotonic microseconds. Every request retains its original deadline. The
   official u64::MAX FOREVER duration and finite addition overflow saturate to
   a FOREVER deadline; neither produces a finite timer or expires at MAX.
2. Drain **one** `next_event(now)` at a time. After every value callback, permit
   `request_cancel` or other mutations before taking the next event. Fast paths
   are deferred tasks, including timeout-zero numeric requests. `Complete`
   invalidates its token before it is returned. The host must not cache a batch
   of future callback events and deliver them after cancellation.
3. When `connection_needed(now)`, `begin_connection` allocates a virtual MQ epoch
   after the source's 1 ms initial backoff. Socket retries within an immutable
   virtual MQ can retain that epoch. `next_request` encodes and commits only the
   current FIFO head into host-owned immutable transmit storage. A submitted
   envelope is marked sent at MQ admission, matching `GNUNET_MQ_send`, rather
   than waiting for the physical frame to finish writing. If output/host queue
   capacity is unavailable, do not call this admission method yet.
4. Deliver complete incoming `Frame`s through `receive`. A returned value
   borrows only input bytes, so the owner can be canceled/mutated during the
   callback. END queues deferred fallback/terminal events to drain next.
   Unknown IDs and malformed frames retire the connection epoch; identified
   malformed payloads also finish the offending request. Do not report another
   transport loss for an epoch already retired by `receive`.
5. `connection_lost` retries the head with its same wire ID and original deadline.
   Already received reverse-name state is retained, so a later timeout does not
   produce a numeric fallback after a name. Drain ready events before
   creating/sending new transport work; `next_request` enforces this boundary.
6. Call `poll_idle_close` at the scheduled 1 ms idle wakeup, including when it
   returns None: it reclaims canceled tombstones and resets retry backoff even
   when no MQ exists. Close only the returned epoch. `next_wakeup` accounts for
   tasks, deadlines, reconnect and idle close; backoff caps at 15 minutes.

Cancellation never creates a wire cancel message or a completion callback.
Unsent/local requests are reclaimed immediately. A sent cancel suppresses
callbacks and stays at the FIFO head until END, connection failure, or the
1 ms all-canceled close. If another live request is behind it, it remains
blocked until that drain completes. A timeout removes the original request;
a late reply can become an unknown ID and cause reconnection of the next head.
`disconnect` requires queued remote requests to be canceled/completed and
returns the MQ epoch to destroy. Deferred local numeric tasks are independent,
as in the normal C implementation.

This safe event interface deliberately avoids source UAF behavior: canceling a
numeric/loopback callback cannot free a still-used C pointer or emit the second
loopback/terminal event after cancellation. Unsupported native sockaddr families
and malformed forward AF values are errors, not the C daemon's assertion.
Local `Completion` reasons explain lifecycle state; they are not added wire
fields or remote error acknowledgments. Host numeric fallback formatting still
needs the native inet_ntop-compatible behavior, including mapped IPv6 forms.

The pinned source is revision `346358e26d4dcc2dc4f51bef5d52dca29c7d8165`:
`gnunet_resolver_service.h`, `resolver.h`, `resolver_api.c`,
`gnunet_util_lib.h` and registry constants. Rust fixtures cover direct-wire and
state boundaries. Use the [native Resolver profile](../../adapters/ipc-unix/examples/RESOLVER.md)
for service execution; a stored byte fixture does not certify a daemon roundtrip.

A further ordinary normal libgnunetutil caller independently executed the
65535/65536 admission boundary, FOREVER relative duration, and finite overflow
saturation. Its five observations and C-source/binary/compiler command hashes
are retained at `normal-limits-result.json` in the temporary development crate.
No resolver connection was established: admitted work was canceled before the
initial connection timer, and no public DNS was queried.
