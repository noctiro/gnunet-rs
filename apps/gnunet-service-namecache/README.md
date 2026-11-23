# gnunet-service-namecache

Native GNUnet NAMECACHE service for bounded encrypted-block caching, lookup and
deletion. Linux, macOS, FreeBSD and Windows share the same cache, IPC handler,
Resolver, statistics producer and foreground loop.

## Usage and configuration

```sh
gnunet-service-namecache -c gnunet.conf
gnunet-service-namecache -d -c gnunet.conf
```

Standard SERVICE configuration, help, version and `-L/-l` options apply.
`[namecache]` selects `HOSTNAME`, `PORT`, `UNIXPATH`, ACLs, tolerance and local
peer policy. `USERNAME` selects the Unix process account; Windows verifies the
account under which the supervisor launched the process. Configured and
inherited listeners use the shared native runtime.

`[namecache-rust] BACKEND` defaults to `files`, which saves ciphertext under
`DIRECTORY` (default `${GNUNET_DATA_HOME}/namecache-rust`). Use a dedicated
private directory per service instance. The service restores unexpired entries
before startup acknowledgement. `BACKEND = memory` selects a cache cleared at
restart. Both modes serve the same NAMECACHE requests and responses.
Set `DIRECTORY` only in file mode.

## Resource limits

`[namecache-rust]` supplies these defaults:

| Keys | Defaults |
| --- | --- |
| `MAX_ENTRIES`, `CACHE_BYTES`, `MAX_BLOCK_BYTES` | 1024, 8 MiB, 63 KiB |
| `MAX_CLIENTS`, `FRAME_BYTES` | 32, 65,535 |
| `OUTPUT_FRAMES`, `OUTPUT_BYTES`, `IO_SLICE_BYTES` | 4, 262,140, 65,535 |
| `FIRST_INPUT_TIMEOUT`, `INPUT_LIFETIME`, `OUTPUT_LIFETIME` | 30 s each |
| `MAINTENANCE_INTERVAL`, `SHUTDOWN_GRACE` | 1 h, 10 s |
| `STATISTICS_OPERATION_TIMEOUT`, `STATISTICS_SHUTDOWN_GRACE` | 5 s each |

Frame capacity must fit the selected block maximum plus the official 16-byte
prefix. Original source/input/output deadlines do not renew on partial progress.
The [shared server contract](../../adapters/namecache-std/README.md) defines
preallocation before effects, reply ownership and source isolation.

## Startup, shutdown and diagnostics

Early startup captures inheritance before opening unrelated native resources.
Unix performs the daemon split and configured identity transition before new
local endpoints are created. Windows uses original-process detachment, socket
activation and a qualified private parent connection.

Cache recovery, clock subscription, listeners and flushed READY output
precede the parent acknowledgement. That acknowledgement has one independent
finite deadline and observes stop/logging failures. Parent EOF does not request
shutdown or prove readiness. Native termination and parent interrupt/terminate
bytes drive the same foreground stop policy.

Immediate shutdown is the default. Soft shutdown retains one finite grace for
complete requests and queued output. Physical client closure precedes completion
of any submitted storage operation and retirement of the Resolver, statistics and
listeners. Operation, cleanup, readiness, output and logger errors remain independent.

Four handler counters describe lookups, hits, cache calls and delete calls.
They use the same Resolver and clock with bounded final publication. A failed
statistics owner is fenced while cache handling continues; `[statistics]
DISABLE = YES` opens no statistics source. Publication is not a persistence or
remote-processing acknowledgement.

## Source layout

`main.rs` composes completion and diagnostics; `unix.rs` and `windows.rs` own
native startup. `early.rs` handles Unix descriptor capture. `foreground.rs`
drives the shared host and uses PROGRAM's shared bounded acknowledgement.
`control.rs`, `settings.rs` and `lifecycle.rs` own stop subscriptions, configuration
and independent cleanup errors. `tests/normal_process.rs` exercises native IPC
and real child shutdown through platform process adapters.
