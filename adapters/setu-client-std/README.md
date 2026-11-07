# Native SETU CLIENT adapter

`gnunet-setu-client-host` is the caller-driven local IPC adapter for the active
GNUnet v0.29.1 SETU interface at upstream commit
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`. The protocol definitions come from
`src/service/setu/setu.h`, `setu_api.c`, `gnunet-service-setu.c` and
`src/include/gnunet_setu_service.h`. Native framing, endpoint selection and clock
ports are the existing shared CLIENT/runtime components. There is no thread,
service, storage backend, Resolver construction or implicit computation here.

The Rust ownership/I/O structure was adapted from the repository's newly written
`adapters/seti-client-std` implementation. Every SETU command, status, option and
native layout was checked against the active SETU definitions; there is no REMOVE
command or intersection-return selector in this interface.

## Callable surface

- Exclusively borrow an `Instance` into `Client::new_set` or `new_listener`.
  Each client owns a distinct physical MQ; listeners do not create sets.
- Drive with `Client::drive` until actual `Written(_, _, Command::Create)` or
  `Written(_, _, Command::Listen)`. `initialized()` means only that this command
  was fully written locally. It does not mean the service acknowledged it.
- `add(kind, bytes, until)` queues an ADD. `evaluate(peer, app, options,
  context, until)` starts an operation. `accept(&mut incoming, options, until)`
  moves one original listener suggestion into an existing set operation.
- `Step::Result` owns immutable exact RESULT bytes and their original epoch and
  operation. `response()` decodes with the configured ABI; `element()` returns
  the element for `Status::AddLocal` or `Status::AddRemote`. Only actual
  `Status::Failure` and `Status::Done` terminate a protocol operation. A result
  from a retired RID is consumed without rebinding it to a new operation.
- `reject` writes on the original listener MQ. Dropping an `Incoming` requests
  its original REJECT on a subsequent drive. Held suggestions expire too;
  source retirement invalidates them before a new listener epoch can attach.
- `cancel` removes wholly unwritten operation frames. If any bytes were exposed,
  the partial original suffix and exact original CANCEL drain on that same MQ.
  `LocalEnd(..., Submission::CancelSubmitted)` means local CANCEL writing only.
  `Unsent`, `Unknown`, deadline, cancellation and source loss remain local
  observations and never manufacture a FAILURE/DONE frame.
- `close` closes the physical owner before yielding local operation retirement.
  A lost set cannot reconnect or replay CREATE/ADD/operations. A caller may
  explicitly `reconnect_listener` within its original finite intent deadline;
  old incoming ids remain bound to the retired source lease even when a new
  listener receives the same raw id.

All `until` values are finite absolute microseconds in that client's original
`EndpointSource::clock()` domain. The optional Tokio `Instant` passed to `drive`
limits that one wait. It does not replace operation or listener deadlines. There
is one earliest-deadline alarm per client. Retirement uses a fixed grace, capped
at the original operation/suggestion expiry plus that grace; late polling does
not extend the cap. If a rejection or partial suffix cannot finish by its bound,
the physical MQ is retired. Callers drive both set and listener clients and select
the same SETU provider for an ACCEPT; local endpoint metadata is not peer
or service authentication.

## source ABI and option semantics

`Limits::abi` is `ipc::Abi { order, align64 }`. Supported alignment is 4 or 8;
byte order is explicitly Little or Big. The default is `Abi::native()` for a
co-located native service with that ABI. No frame sniffing, retry negotiation or
layout fallback is performed. The active C RESULT has a 24-byte prefix for
alignment 8 and 20 for alignment 4; ACCEPT is respectively 56 or 52 bytes. RESULT size/RID/status/element type and ADD element type use network order. The
four operation flags are raw bytes, the lower bound is network u32, and the four
u64 option fields are native order because the active service reads them directly.

`ipc::Options` supplies those service-read native numeric values. Defaults
match the active C defaults. The C API's custom-option setter applies `htonl` to a
u64 option and then assigns the truncated u32 result to a u64 field, while the
service does no inverse conversion. This adapter encodes the explicit native
values the caller requests; it does not silently reproduce that C setter bug. To reproduce C API custom bytes deliberately, choose the source ABI and the exact
resulting native value explicitly. Original RESULT bytes are always preserved. Symmetric mode asks for ADD_REMOTE; active C full-mode sender behavior may omit
those reports. That is a service behavior, not a reason to invent callbacks.

## Bounds

`Limits` bounds concurrent operations, pending suggestions, retained suggestion
bytes, original output frames/bytes, frame size and bytes per syscall. Tokens are
opaque and tied to the original nonzero-size `Instance`; RIDs never recycle within
that client. Returned records and consumed suggestions may retain their owned
bytes in the caller; the caller controls that lifetime. Retained input capacity
backpressure still allows queued original REJECT/CANCEL output to drain.

`tests/native.rs` is one local Unix socket ownership model with three-byte
native reads/writes. Its actor emits only FAILURE messages and suggestions;
it does not compute a union or fabricate successful peer interoperability. It
checks exact CREATE/ADD/EVALUATE option bytes, original RIDs, full and wholly
unwritten cancellation, a late cancelled reply, ACCEPT on the set MQ, REJECT on
the listener MQ, dropped/expired input retirement, a fresh listener epoch with a
reused raw id, and set loss without replay.
