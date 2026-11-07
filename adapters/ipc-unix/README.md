# STATISTICS Unix/TCP host

This host adapter uses the official GNUnet v0.29.1 service messages. It currently
provides STATISTICS clients and hosting for `gnunet-statistics`. Its dependencies
are Rust libraries; production does not load libgnunet through FFI.

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

`server::serve_statistics` accepts a caller-bound `UnixListener`, an exclusive
borrow of the core, explicit `Limits`, a shutdown future and a synchronous
session-close observer. The caller controls socket path permissions, cleanup,
configuration and durable storage. A minimal finite host uses:

```rust,ignore
use gnunet::{ipc::server::{Limits, serve_statistics}, statistics::Statistics};
use std::time::Duration;
use tokio::net::UnixListener;

let listener = UnixListener::bind("/private/path/statistics.sock")?;
let mut core = Statistics::<16, 128, 4, 16, 32>::new();
let report = serve_statistics(
    &listener,
    &mut core,
    Limits {
        max_connections: 4,
        max_frame_bytes: 65535,
        max_pending_bytes: 128 * 1024,
        idle_timeout: Duration::from_secs(60),
    },
    tokio::time::sleep(Duration::from_secs(30)),
    |closed| { /* observe this session's real close reason */ },
).await?;
```

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
`core.restore()`. The application supplies transaction/fsync/recovery policy. There is no private dump envelope or old-state migration. This adapter is not
the complete GNUnet service supervisor, configuration loader or peer daemon.

`Listener::poll_canonical_connection` owns accepted-stream initialization through
`gnunet-native::network` and returns the original peer plus bounded diagnostics. Fatal initialization closes that socket and retains prior diagnostics. The ARM
daemon reactor uses this composition. The pure `Connection` constructors
retain the caller's supplied socket settings. STATISTICS/Resolver accept callsite
and full shared logging integration, earlier std/mio failure policies and other
Unix execution remain required. The maintained finite proof is
`tools/reference/accepted-stream/verify.py`, including normal-C loopback
observations; it stages exact current production bodies and full lint/contracts.

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
