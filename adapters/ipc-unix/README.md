# STATISTICS native IPC host

This host adapter uses the official GNUnet v0.29.1 service messages. It currently
provides STATISTICS clients and hosting for `gnunet-statistics` over native
AF_UNIX and TCP on Linux, macOS, Windows and FreeBSD.

`StatisticsClient` performs bounded GET and SET+DISCONNECT operations. `StatisticsWatchClient<'a, N>` submits at most N WATCH requests and returns
notifications bound to their original borrowed selectors. Watch IDs are scoped
to the same instance/connection; cancellation leaves a local tombstone because
the official protocol has no unwatch message. Closing the socket releases the
server's watches. A submitted WATCH has no protocol acknowledgement, and a zero
initial value need not produce a notification.

Each client call receives a caller-owned scratch buffer and an absolute Tokio
deadline. Every read/write poll checks the original deadline. Input or
capacity rejection before admission performs no I/O. A failed or cancelled
admitted operation closes its connection. In particular, a cancelled partial
read cannot leave a suffix that a replacement operation mistakes for a header.

## Hosting the service core

`server::serve_statistics` accepts a caller-owned native local listener.
`serve_statistics_on` serves a mixed local/TCP set. Both borrow the exclusive
core, explicit `Limits`, a shutdown future and a synchronous session observer.
The caller owns configuration, endpoint permissions, cleanup and durable storage.
Use `BoundListeners::bind_configured` to prepare real local/TCP endpoints:

```rust,ignore
use gnunet_ipc_unix::server::{self, ServiceOptions};
use gnunet_service_runtime::{BoundListeners, LocalListenerAccess};

let bound = BoundListeners::bind_configured(
    &config, b"statistics", LocalListenerAccess::Owner,
).await?;
let listeners = bound.listeners();
let report = server::serve_statistics_on(
    &listeners, &mut core, limits, &ServiceOptions::default(),
    shutdown, |event| { /* observe actual native/session outcomes */ },
).await?;
```

`serve_statistics_controlled` adds the canonical clock, peer admission, grace
policy and a synchronous startup callback. `serve_statistics_controlled_with_async_ready`
awaits an asynchronous startup effect after real listener polling. Failure or
cancellation releases accepted streams and core generations and restores the
original retained-byte accounting. Borrowed listeners remain caller-owned.
Windows applies local restrictions through the
[original configured listener's DACL](../service-runtime/README.md#configured-local-listeners).

The adapter runs one task, with a bounded connection table, input and output
buffers. It creates no detached connection task or unbounded channel. It polls
acceptance and sessions in round-robin order, yields after each event and sleeps
on readiness/idle timers. Core and host capacity failures close the responsible
session and are reported; other clients continue. The idle timeout measures time
without successful I/O progress, not a fixed total connection lifetime. `Duration::MAX` disables the idle policy for indefinite monitors.

SET, GET, WATCH and DISCONNECT use the core. Notifications cross connection
boundaries and remain ordered. GET ends only with the official END message. DISCONNECT is a processing barrier: its confirmation does not close the socket
and does not claim a disk sync. EOF, shutdown and external future cancellation
close sockets and release client generations, watches and their queued effects. `serve_statistics_soft` instead applies the reference soft-shutdown policy: stop
accepting after a shutdown request, let existing non-monitor clients finish, then
close remaining WATCH monitors. External future cancellation still releases all
resources immediately. Global statistic values remain available in the caller's core afterward.

To persist values, encode every `core.persistent()` entry and store the resulting
concatenated official SET frames. Before hosting, import complete frames with
`core.restore()`. The application supplies transaction/fsync/recovery policy. The application retains configuration, supervision and storage ownership.

The server obtains canonical accepted streams from
[`gnunet-service-runtime::accepted`](../service-runtime/src/accepted.rs).
Native initialization failure closes the original connection and retains prior
diagnostics. Address/peer policies run before allocating core client IDs or
session buffers; a failed peer does not become a replacement source.

Long-lived STATISTICS owners and dedicated WATCH connections require caller-owned
`statistics_handle::Instance` storage (re-exported as `handle::Instance`). Pass an
exclusive borrow to the constructor and retain the storage until the owner and
all issued tokens are gone. The pure core remains allocation-free; no global id,
leaked allocation or self-reference supplies identity. Local slot/serial values
remain diagnostics and never authorize operations on another owner or enter the
wire. Callback events keep the long owner lifetime separate from short frame
views, so ids can be retained while commands are admitted through the context.

Generic connections/acceptance live in `gnunet-service-runtime`. Shared CLIENT
endpoint/live configuration/Resolver ports and weak presence observations live
in `gnunet-client-host`. This package retains STATISTICS operation ownership,
barriers, watches and hosting only; other services must not depend on it for I/O. The existing domain frame cursors and one-shot cancellation contracts are intact.

`StatisticsHandle::destroy_with_timeout` selects a finite microsecond-resolution
confirmation budget independently of connection retry backoff. The pure owner
uses `begin_destroy_with_timeout`; queue admission and real DISCONNECT/CONFIRM
requirements match `destroy`. Submicrosecond and overflowing drain budgets are
refused before queue mutation. Ordinary CLI SET selects five seconds and requires
an actual processing confirmation with no discarded or unconfirmed mutations;
a completed local write cannot satisfy that condition.

`StatisticsHandle::confirm_and_destroy` explicitly requests the same official
barrier on the current connection even after all setters have been written.
It uses one finite budget, starts no replacement connection and cannot confirm
mutations from an older lost epoch. With no current connection, it closes with
the actual discarded/unconfirmed counts. This Rust shutdown policy leaves the
C-compatible queue condition of `destroy` and `destroy_with_timeout` intact.

`producer::Producer<N>` shares the native lifetime and bounded setter machinery
for service statistics. Domain wrappers supply immutable official metric names,
persistence flags and snapshots. Counters emit positive signed UPDATE chunks
after an explicit baseline; gauges emit absolute SET values, including their
initial zero and subsequent decreases. One setter is pending at a time, so newer
observations never rewrite an admitted frame. Same-epoch whole writes advance
local accounting only. Source loss permanently fences the producer and retains
uncertain work and the original destroy/error facts; it creates no replacement
owner or replay. Final drain uses one fixed deadline. RECLAIM and REGEX share
this implementation through small domain wrappers.

## Source layout

`lib.rs` exposes the public interfaces. `client.rs` owns one-shot operations,
`error.rs` preserves failure causes, and `framing.rs` owns partial I/O cursors,
interruption retry and original deadlines. WATCH, long-lived handles, producers
and the server retain separate lifecycle owners. Native stream and accept
mechanisms stay in `gnunet-service-runtime`; this package has no per-OS protocol
or service state-machine copy.

## Verification

`cargo test -p gnunet-ipc-unix --all-targets --all-features --locked` runs portable
framing cases and the host's native fixtures. `tests/native.rs` uses the same
local/TCP cases on all supported hosts: shared values/WATCH, processing barriers,
malformed-peer isolation, partial-reply cancellation, asynchronous ready failure,
lazy handles and destroy confirmation. Unix descriptor/pair fixtures supplement
that shared coverage. These cases are part of `cargo xtask verify runtime`.
Execution coverage and official-peer comparisons follow the [test guide](../../tests/README.md).
