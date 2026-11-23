# STATISTICS service

Serves official SET, GET and WATCH IPC over configured AF_UNIX/TCP listeners.
Clients share one bounded statistics core; persistent rows use the official
concatenated-SET database format.

## Run

Create an owned runtime/data directory and a configuration file. Replace the
absolute paths below with that directory:

```ini
[statistics]
UNIXPATH = /absolute/path/to/statistics/statistics.sock
PORT = 0
UNIX_MATCH_UID = YES
DATABASE = /absolute/path/to/statistics/statistics.db
```

Start the foreground service:

```sh
cargo run -p gnunet-service-statistics --locked -- -c /path/to/gnunet.conf
```

In another terminal:

```sh
cargo run -p gnunet-cli --locked -- statistics set /absolute/path/to/statistics/statistics.sock demo requests 1 --persistent
cargo run -p gnunet-cli --locked -- statistics get /absolute/path/to/statistics/statistics.sock demo requests
```

Stop with Ctrl-C. SET confirmation establishes service processing; persistent
rows are saved during service shutdown, not by that confirmation alone.

## Startup and storage

The normal entry uses shared GNUnet SERVICE options `-c/--config`, `-d/--daemonize`, `-L/--loglevel`, `-l/--logfile`, help and version. `main.rs` owns shared diagnostics; `unix.rs` and `windows.rs` compose native startup around `host.rs`, `settings.rs` and `control.rs`. Both use the selected Logger, original listener/control owners and one SharedClock. Unix binds listeners around the configured `[statistics] USERNAME` transition. Windows verifies the current account; it never treats a requested different account as a successful transition.

The `gnunet-ipc-unix` server and `gnunet-statistics-store` remain the protocol and persistence owners. The ordinary host uses `AllocatedStatistics` with the same protocol/business algorithm as the allocation-free fixed-capacity core. Rows, names, connections, subscriptions, notifications and GET snapshots grow on demand within explicit bounds; startup does not allocate the maximum row count times the maximum name size. Global rows survive client disconnection and are never silently evicted to make room. Capacity or allocation failure is a refusal.

All listeners share one core. TCP uses the configured IP ACLs and Unix checks
kernel UID/GID. For Windows, use native absolute paths.
`UNIX_MATCH_UID` and `UNIX_MATCH_GID` select owner or group access on the
[configured AF_UNIX listener](../../adapters/service-runtime/README.md#configured-local-listeners).
Activation retains original listeners and leaves their filesystem nodes with the
creator. Standalone `-d` uses shared native re-exec. Supervised `-d` detaches
before provider import, runtime and signal registration.

Startup loads the official concatenated SET database into a fresh unpublished core with the selected resource limits. Invalid, truncated or capacity-exceeding files fail without replacing them with empty state. With no DATABASE, state is explicitly memory-only. Actual host metadata, bound listeners, database load and the saving buffer's retained-byte admission precede Ready, stdout flush and the original daemon-parent ready byte. A dropped parent control pipe is detached; only interrupt/terminate requests initiate shutdown. The daemon parent never continues service initialization.

## Shutdown

Soft shutdown stops admission and lets existing non-monitor clients finish before retiring WATCH sources. `[statistics-rust] SHUTDOWN_GRACE` defaults to 5 seconds and fixes one native deadline on the first request; at that boundary remaining original sources physically close without acknowledging unprocessed requests. Default idle lifetime remains unlimited as in C. Optional `IDLE_TIMEOUT` is a native resource bound. Clock failure closes original MQ owners independently of obtaining another clock sample.

After all original client generations retire, shutdown saves persistent rows
through the [snapshot store](../../adapters/statistics-store/README.md#saving-and-publication).
The report separates file synchronization, publication and the barrier on the
original directory. Empty persistent state removes the ordinary database file.
Save errors retain their stage
and uncertain-commit classification and are not retried. A prior driver/control
error remains primary, with save/output/logging failures retained separately.
DISCONNECT_CONFIRM is a processing barrier, never a durable save receipt.

## Resource limits

Deployment bounds under `[statistics-rust]`:

| Setting | Accepted range | Default |
| --- | --- | --- |
| `MAX_ROWS` |1..1048576 |65536 |
| `MAX_NAME_BYTES` |2..`MAX_FRAME_BYTES-16` |65519 at the default frame size; otherwise capped to frame minus 16 |
| `MAX_CLIENTS` |1..65536 |32 |
| `MAX_WATCHES` |1..1048576 |65536 |
| `MAX_EVENTS` |1..1048576 |262144 |
| `MAX_RETAINED_BYTES` |1..4GiB, representable by native `usize` |64MiB |
| `MAX_FRAME_BYTES` |18..65535 |65535 |
| `MAX_PENDING_BYTES` |`MAX_FRAME_BYTES`..16MiB per client |1MiB |
| `MAX_DATABASE_BYTES` |1..256MiB |16MiB |
| `MAX_DATABASE_RECORDS` |1..1048576 |65536 |

`MAX_NAME_BYTES` counts the two logical NUL terminators. An empty subsystem/name pair is valid within the minimum 2 bytes. Every admitted row must fit a complete SET/VALUE frame including its 16-byte fixed prefix; the selected limits also apply during database loading. Database record limits count input frames, including duplicate names, independently of the distinct-row limit. Saved snapshots use the official SET format and the bounded saving scratch.

The retained-byte budget covers core tables/names, retained snapshot data and reported host buffers, including the saving scratch. Container spare capacity remains charged until physically released. The separate count/byte limits are ceilings, not a promise that all maxima can be reached simultaneously: an exhausted total budget causes an error before admission. A budget too small for startup resources fails before Ready. The fixed `no_std` backend retains its zero-capacity and allocation-free behavior.

Existing official DATABASE/listener/ACL/tolerance settings remain under `[statistics]`; `IDLE_TIMEOUT` and `SHUTDOWN_GRACE` remain under `[statistics-rust]`. Private database parents are created only under the target process identity.
