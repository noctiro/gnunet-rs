# Public utility NAT burst owner

`gnunet-nat-burst-host` implements the active public utility API from pinned GNUnet v0.29.1 `gnunet_nat_lib.h` and `src/lib/util/nat.c`, commit `346358e26d4dcc2dc4f51bef5d52dca29c7d8165`. It has no relationship to a transport's encryption, peer admission, or authenticated connectivity. Its output is an **unauthenticated socket observation**.

The default noalloc `gnunet_nat::burst` module supplies the protocol computations: exact 12-byte `BurstSync` (u64 BE RTT, native enum32) and 36-byte `BurstMessage` (public peer32, native unsigned32 local port), explicit producer `Endian`, and the official finite RTT/difference rule. There is no GNUnet message header, RID, ACK, authentication, or wire cancellation. Both RTTs must be finite and differ by strictly less than 150ms; remote ready exactly 1 selects twice the local RTT, other raw values select four times it. Multiplication saturates in the pure rule, while the native owner rejects a delay that does not fit the original finite lifetime.

## callable interface

Create a stable caller `Instance`, retain a separately owned `Arc<tokio::net::UdpSocket>` for the already-bound, unconnected default socket, then call `Burst::new(instance, default_clone, Parameters, Limits, clock)`. Parameters freeze the remote IP/default port, initialized public peer bytes, both producer byte orders, original RTT/sync message, and absolute logical `until`. The pinned C default peer bytes are zero; callers can explicitly pass `[0; 32]`. Every Rust packet initializes all 36 bytes. No identity lookup, key, entropy, resolver, or provider is implicit.

Drive `poll_step(cx, observe)` or its cancellation-safe `drive(observe)` future in the caller's Tokio runtime with I/O and time enabled. A new owner performs no packet sends until driven. `Step::Progress` means local work/expiry; `Event::Written` and `Report::datagrams_written` mean only a whole datagram accepted by the local kernel. They do not claim peer processing. A positive short UDP write terminates the original attempt with the exposed byte count; the suffix is never sent as another datagram.

The same foreground dispatcher remains the only reader of the default socket. After receiving a complete application datagram there, it calls `on_datagram(original_default_id, actual_sender, exact_bytes)`. The input remains caller-owned regardless of the returned `Disposition`; unrelated input stays in the application's original path. The owner never polls receive on this default socket. Serialize the initial default send in that dispatcher as well, or use its same task/waker: Tokio's poll send API retains only its last send-direction waker. The independent original send/hard timers still bound a pending initial send.

After the synchronization delay, the owner first sends from the default local port to the supplied remote default port. It then tries each port 1024 through 65535 once, skips the default local port, binds the same local port it targets remotely, and uses no address/port reuse. Defaults are a minimum 10us between port attempts, 100ms per original scan descriptor, and at most 512 simultaneously owned scan sockets. An occupied port is reported with its actual `AddrInUse`; other bind/reactor/read/send errors terminate with the original error after retiring other owned descriptors. Opening a descriptor and pending sends cannot renew its original expiry. The overall logical and native hard bounds never renew.

`Event::Datagram` forwards non-burst data read on scan sockets synchronously, unchanged, with original socket token and sender. The callback can copy it under the caller's own budget. `scan_socket(original_id)` permits later borrowed application handling while that original socket is live; it does not extend its lease. A zero-length packet is forwarded as application data. The owner reserves one reusable 65536-byte zeroizing buffer: all ordinary UDP datagrams fit, so a datagram longer than 36 bytes cannot become a truncated apparent probe. The `at_capacity` bit explicitly preserves uncertainty for a nonstandard jumbo datagram that fills that buffer; it is never classified as a probe. Payload bytes are redacted from Debug and wiped after callback and at retirement.

Matching requires the fixed remote IP, the explicitly configured IPv6 scope when nonzero, and an exact 36-byte datagram. The raw remote identity and advertised native u32 port remain assertions, including zero/out-of-range raw values. The recvfrom endpoint is retained by value. A match stores `Selection` and emits `Step::Selected`; `take_selection()` transfers the descriptor to the caller. All other scan handles are retired and the default clone detached first. `cancel()` preserves an already selected descriptor; dropping an owner also drops any selection it still owns, so transfer it before dropping the owner when it must survive. A selected default socket is an Arc clone, and the original caller keeps its own ownership.

## Lifetime and capacity

Every explicit new intent consumes a checked caller-domain allocation. Original `Attempt`/`SocketId` values compare domain pointer, allocation, and serial; no old callback can attach to a new attempt in the same caller slot. Reusing the default Arc for a new attempt requires a new explicit owner and token. No implicit reconnect or restart exists. `on_datagram` rejects a stale default token before affecting the current owner.

The owner stores at most 512 scan rows, one initialized 36-byte send packet on the stack, one 65536-byte receive allocation, one selected descriptor, one native alarm and one independent clock subscription. The caller controls concurrency of separate owners. Allocations for scan rows and the receive buffer are fallible and occur before admission. No per-port buffer, queue growth, global linked list, hidden task/thread, or per-result copy is used. One foreground poll completes at most the configured I/O budget and registers readiness on at most 512 live rows; send and port-admission progress precede unrelated receive work, and scan input rotates across descriptors.

The immutable native hard bound is computed once from the original logical deadline at admission. Native expiry/alarms are handled before waiting on a logical revision race. Logical clock failure independently retires descriptors; cancellation does not sample the clock. Clock rollback can delay the logical start/deadline but cannot renew the native hard bound or a scan descriptor. All pending operations have reactor, clock-subscription, or finite native timer wake sources. A dropped drive future leaves the owner, pending whole packets, selected result, and original tokens intact.

`end()` retains the original cause, distinguishing logical deadline, immutable hard bound, and initial send bound; I/O errors and unexpected positive byte counts are retained independently of cleanup. Rust socket destruction does not expose a close errno. End therefore reports retirement of owned handles without fabricating a kernel close ACK. A caller's separately owned default socket is never closed by this adapter.

## Deliberate fixes and qualification

The pinned utility uses a global socket list, a freed scan continuation, an escaped stack sockaddr, uninitialized peer bytes in scan packets, and an ineffective maximum-socket check. These internal defects are not part of the public wire contract. This implementation owns descriptors and addresses, initializes every byte, enforces the live cap, and checks the requested remote IP. The public datagram formats and synchronization arithmetic are preserved.

One public framing/readiness/allocation model passed; it performs no socket,
packet, native provider or crypto work and grants no traversal credit. Native admission
anchors its hard bound before clock subscription/sampling; post-sample/default
input and post-recv scan checks cannot revive an expired original socket. Actual interoperability, NAT traversal effectiveness and
full-node integration remain unqualified. This utility is independent of the
NAT registration/NATauto client and service. Selection is unauthenticated.

## Already-synchronized communicator entry

`ReadyParameters` and `Burst::start_ready` compose the same public scan after an
TRANSPORT 1253 command. TRANSPORT has already performed the FLOW readiness
check and synchronization delay. This entry carries no fake `BurstSync` or RTT;
it starts the scan stage immediately and clips every derived native target to
the caller's original `hard`, captured before canonical clock/preparation work. `until` is the independently supplied original canonical bound. The existing
`Burst::new` still performs its original public synchronization rule.

`poll_native_guard` only retires expired native descriptors and registers their
original alarms; it performs no socket read/send or canonical clock request. `into_end` consumes the owner and transfers its terminal cause and counters. An untransferred selection is dropped with its descriptor; callers use
`take_selection` first when that exact socket must continue in the communicator. Default-socket reads remain exclusively in the original external dispatcher. These additions pass affected macOS/Linux strict library/binary checks and three
architecture guards with the normal UDP composition.
