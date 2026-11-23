# gnunet-vpn-host

This is the callable production local SERVICE/IPC port for the independent pure
VPN Engine. It owns canonically accepted Unix/TCP MQs and official client
frames202/203 and response204, using the existing shared service runtime. It
creates no listener itself. The separate [coordinator](COORDINATOR.md) composes
TUN, route and CADET owners on the caller's runtime. The `unavailable`
example uses native local IPC and stop sources on Unix and Windows, with no
TUN. It restricts the endpoint to its owner; Windows uses native ACLs, while
Unix additionally checks the peer UID. No private protocol, private-key access
or GNUnet C FFI is used.

The foreground/coordinator constructs `gnunet_vpn::Engine` with its external
Instance, ClientSlot/RequestSlot/LeaseSlot/FlowSlot/PacketSlot pools, then moves
that engine into `server::Server::new(core, clock, limits, options, unix)` on its
existing Tokio runtime. `clock` must be the same canonical RuntimeClock used by
all other coordinator ports. The server accepts only an untouched pure engine,
reserves exactly one independent clock subscription, and fixes one native activity
anchor. Prior sampling or drained historical work cannot acquire a replacement
epoch. The coordinator samples activity through this same server, preserving
the original anchor across its transfer. Engine IPC AF assignments are read through `Engine::ipc_af()`;
there is no second independently guessed native AF profile.

`poll(cx, listeners, optional_wait_until, observe)` and `drive(...)` accept shared
`service_runtime::service::Listener` references. Existing activation/listener
setup, AcceptState EMFILE gating, canonical socket initialization diagnostics,
TCP address ACL and UnixAccess kernel credential checks are reused. `admit(AcceptedConnection, observe)` exposes the same source admission for
a larger coordinator. Unadmitted/rejected streams are physically dropped before
any pure attach_client. No raw RID or caller-created socket can manufacture an
old Client token. Unix/TCP owners are never replaced beneath Framed.

## Application entry

`startup::ApplicationSettings::read(config)` validates an immutable application
policy before the enclosing node selects its local services. `uses_regex()`
reports the required discovery dependency. Automatic REGEX discovery is the
default, shared with the standalone service; `[vpn-rust] EXIT_DISCOVERY=configured`
explicitly selects the configured exit policies.
Nonempty `CONFIGURED_EXITS` requires that explicit configured mode; automatic
discovery neither ignores the fixed list nor falls back to it.

Pass the prepared settings to `serve_embedded` with `LocalEndpoints`, the original
application provider and the shared clock. The endpoint bundle contains distinct
literal VPN and CADET paths in one private directory, plus
`DiscoveryEndpoint::Regex(path)` for automatic discovery or
`DiscoveryEndpoint::Configured` for the explicit opt-out. A mismatched endpoint
choice fails before native admission. The settings are consumed without reparsing
configuration. The local REGEX service owns its DHT dependency.

The shared `discovery::Provider` is also the standalone service's discovery owner.
It retains each original VPN discovery capability and native REGEX search through
whole local request writes, gateway selection and physical search retirement.
Search exhaustion is inconclusive rather than proof that no gateway exists.
`REGEX_SEARCHES`, `REGEX_SEND_TIMEOUT`, `REGEX_FIRST_RESULT_TIMEOUT`,
`REGEX_SEARCH_TIMEOUT` and `REGEX_IO_SLICE_BYTES` set finite bounds in `[vpn-rust]`.
After a stop, new offers are refused and every original search is canceled before
the coordinator closes its resources. Cleanup errors and remaining route or
discovery debt remain explicit in the embedded result. When startup exits before
the coordinator adopts the provider, an unconfirmed route close and any native
close error are reported separately. Readiness requires the actual native
settings receipt and a live CADET source.

## Original input, response and source ownership

Each admitted MQ owns one `Framed<Effect>`, a bounded request count, at most one
immutable held response and at most one admitted original response. The pure
engine allows only one Prepared/Queued/Exposed response per original client, so
native held and queued states do not coexist during normal operation. Frames are
copied fallibly once from `prepare_client`; copying and queue admission never
regenerate a response from a mutable lease. Official opaque RID bytes remain
unchanged. `Effect::request()` preserves original instance/row/generation and
`Engine::request_client()` proves original MQ ownership even after physical loss. Original request metadata remains in the bounded caller pool, not a duplicated
per-client growing Vec.

A complete RX frame is released only after successful `redirect` admission
(or an explicitly tolerant unknown type). The pure API guarantees Capacity,
validation and overflow refusals precede business mutation. Capacity/WouldBlock
therefore retains the complete original RX frame and its original first-byte
input deadline while the same MQ's previous TX continues to drain. The native
per-client request bound behaves the same way. Backpressured is emitted once per
blocked input episode. Malformed known requests, invalid AF values and duplicate
live RIDs close only their original MQ. Tolerant mode ignores unknown message
types; it does not suppress malformed known request errors. There is no VPN
CANCEL IPC; the server does not invent one.

Immediately before admission, `can_queue` validates the original prepared effect. Actual enqueue is followed by `queued`. Every positive socket write calls
`exposed`, including a one-call complete response. Only a complete original frame
calls `written`, followed by `retire_request` for that original request. Native
Written says only that the original response entered the local socket, without
proof of application processing. Allocation leases remain independent of request
callback/socket lifetime. `Retired` includes the genuine last RequestInfo/outcome;
`Queued` and `Write` report local IPC facts without claiming TUN, route,
connected exit, IP delivery or full VPN success.

Local engine `cancel_request` is supported: canceled Buffered rows retire;
never-admitted canceled Prepared output is rejected/retired; already queued or
exposed output retains its immutable original suffix and drains on that same MQ. Dropping a waiting future retains every original RX/TX cursor, prepared effect,
request and deadline. No frame suffix is moved to another MQ or replayed after
loss. A fresh accept always receives a new original Client generation.

`stop` physically retires the original Framed connection before `client_lost` and
before retiring that MQ's remaining original request debts. Whole writes already
settled remain whole writes; still outstanding originals become truthful Lost
with their queued/exposed facts. Native/protocol cause remains in Closed,
and core cleanup failures are reported independently. No fake service ACK or
unsent settlement is substituted for an exposed response.

## Finite deadlines, clock failures and shutdown

The first RX byte starts input_timeout. The deadline covers the entire
frame and any complete-frame capacity wait and is not reset by partial reads. The oldest current request admission starts send_timeout for that MQ's current
outstanding response batch. Preparation, partial writes, extra pipelined requests
and shorter drive waits do not extend it. The send deadline is released only
when all current original request debts are actually retired; each immutable
prepared/queued output retains that same bound. This conservative bounded batch
policy prevents a peer from keeping old debt alive with repeated new requests. Native timeout physically closes the source rather than fabricating completion. Wire `expires` is independent logical lease expiry and is passed unchanged to the
engine, including FOREVER. It never disables native input/send bounds.

Each scheduling pass registers the original clock subscription before sampling
and checks again for an adjustment. Actual `AbsoluteTime` remains authoritative
for wire address leases. Flow activity and idle duration use only elapsed native
`MonoInstant` from the server's fixed anchor; forward jumps and rollback never
move the original idle target. A fixed maintenance wake (default100ms, configurable1ms..1s)
keeps idle expiry bounded without creating a new subscription per response. Caller
wait deadlines end only that observation. Original hard input/send/shutdown
bounds are serviced before a shorter caller wait timeout.

A fatal original clock/core scheduling error first independently closes **all**
MQs, then invokes pure source-loss/debt cleanup, then returns the original
error. Cleanup requires no successful clock sample. Each physical source closes
even if another source's callback fails; the first cleanup refusal is retained and
reported separately. No-clock `shutdown(observe)` exposes the same synchronous
closure path and report. Drop also physically closes all original MQs before
best-effort logical cleanup, without callback or remote completion claims.

`request_shutdown(Soft)` stops accepting and reading new requests. Already
admitted response debts drain within their original bounds and one original
shutdown_grace. Repeated shutdown calls do not reset that grace. Drained MQs
physically close; expiry or Immediate forces all physical closes. `Stopped` and
`ipc_quiescent()` refer only to this IPC owner's MQs. Other engine ports,
TUN/routing jobs, CADET channels and discovery work remain coordinator-owned.

## Composition and limits

Use `Device::from_provider` when an application owns the system packet source
and route settings. The [application provider contract](COORDINATOR.md#application-providers)
defines the original install, removal and packet write receipts.

On Windows, `Device::from_wintun` consumes an actual explicitly provisioned
session. The first session of a Created adapter permits configuration; restarted
and Opened sessions use unchanged-plan verification. The
[shared Wintun reactor](../tun-std/WINDOWS.md)
provides whole packets, actual native administrative returns, route queries and
DAD samples. Unix helper variants remain specific to their process/pipe backend.
The [coordinator recovery contract](COORDINATOR.md#session-recovery) preserves
the original route scope when replacing a packet session on the same adapter.

`engine()` exposes pure facts; `engine_mut()` is the explicit coordinator port for
TUN attachment, original routing receipts, discovery/CADET work and
packet processing. The coordinator must not independently consume this server's
Client/output effects or retire its request rows. Local request cancellation is
valid. This adapter never defaults to `route_applied`, select_exit, connected or
successful native configuration. With no ready TUN/route, the pure engine
returns the official AF_UNSPEC allocation-failure response.

Defaults:32 MQs,32 retained original requests per MQ (also constrained by the pure
shared request pool),128-byte RX frame capacity, one32-byte maximum queued
response, at most one32-byte held response,65535-byte native syscall slice,5s
input/send/shutdown bounds and100ms maintenance wake. Frame capacity is explicit
128..65535 and native syscall size is nonzero. All native slot storage is reserved
fallibly during construction. Original framing allocation and queue reservation
use the existing shared checked/fallible runtime. Per-MQ request rows are never
copied into an unbounded host collection. Scanning original debts is bounded by
the supplied pure request pool. Each scheduling step performs at most one accept,
read or write syscall, plus bounded pure/metadata cleanup. A complete shutdown may
close all bounded independent sources in one synchronous call.

## Checks

`tests/native.rs` contains one Unix IPC model for central execution. It uses
two MQs, one pure request row, one-byte native I/O slices and a controlled
clock. It checks capacity-retained RX while earlier TX drains, same raw RID on
distinct sources and later legal reuse, genuine no-TUN AF_UNSPEC responses, and
clock failure after exactly one positive response byte. The expected result is
physical close before the original clock error, exposed Lost debt, real
EOF, no suffix replay and all original request rows retired. This is a controlled
local IPC model, not C interoperability, TUN qualification, VPN data-path or
full-node evidence.

Primary protocol source: unmodified pinned GNUnet commit
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`,
`src/service/vpn/{vpn.h,gnunet-service-vpn.c,vpn_api.c}` and
`src/include/gnunet_vpn_service.h`. Native ownership/framing conventions reuse
shared `gnunet-service-runtime` and local SETI/SETU adapters.
