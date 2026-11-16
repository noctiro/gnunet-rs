# Native PEERSTORE service and durable WAL

`backend::Wal::open(directory, limits)` opens this independent Rust backend under a process writer lock. It uses the private `GPSW1` file format only on disk; public IPC remains the official GNUnet protocol. No C/SQLite implementation is loaded and no existing transport-specific journal or C sqlite file is migrated or overwritten.

## Journal and native storage

Live rows retain only their record frames and stable positive UIDs. MULTIPLE appends a new UID; REPLACE removes the exact subsystem/peer/key tuple and gives the replacement a new UID. Explicit expiration removes only expiry < now. Appends are checksummed, fsynced and checked against the original file/directory/fence before success. Bounded checkpoints retain active rows and the durable UID high-water, so restart never reuses a committed UID. Reopen replays complete transactions and retires only an incomplete trailing entry; complete corrupt/unknown artifacts are preserved and refused. Any uncertain write/publication latches the owner and retains its original native failure; last-known rows/sequence are not presented as resolution of that uncertainty.

The namespace backend retains original native directory, lock and WAL handles,
using complete platform file identities. Unix operations are descriptor-relative;
Windows uses native relative handles and private DACLs. Checkpoint publication
installs the original staged file without reopening its path. Interrupted writes
are not retried; a staging-cleanup failure remains independent of the original
failure. File sync and `Wal::directory_sync()` are separate observations;
Windows reports the unavailable directory barrier explicitly. The terminal
worker receipt retains that observation.

## Worker and framing

The foreground explicitly calls `Worker::start(wal, capacity)` once for the whole service. Its command and result channels are both bounded (1..=4096). Only owned official bytes and a private worker Job enter the thread; pure MQ/operation tokens never cross threads. The original private completion returns the storage result. A poisoned WAL prevents new admission and already queued but unstarted commands receive known cancellation, never saved-success.

`server::Server::new(core, &mut worker, limits, options, access, clock)` borrows this independently owned worker. Construction performs no thread creation, so a constructor error leaves the original worker available for explicit drain/join. Every STORE, record scan, expiration and checkpoint syscall runs in that worker, outside socket poll. The socket owner retains one Framed RX/TX cursor and immutable output origin per source; waiting-future cancellation does not clear them. Input acceptance, worker admission, disk commit, local frame write and application consumption are separate facts.

Fair classes independently poll source directions, original worker results, scans, accept and maintenance. An accepted monitor that requests no initial scan prepares its original SYNC before the next rotating business class, so a completed STORE cannot label a new live record as initial. SYNC uses the existing single response slot and consumes no record credit. If that source cannot pass its pending SYNC barrier, an entitled live update triggers the same explicit slow-monitor capacity failure and physical source retirement; no record crosses the barrier and no global worker completion is held indefinitely. Slow/over-budget monitors are explicitly closed instead of silently dropping an entitled update or blocking the global completion cursor. There is one original storage job per source plus maintenance capacity; the foreground reserves at least clients+1 jobs. Physical source loss does not cancel an admitted disk write. Shutdown independently closes local MQs, drains all admitted original jobs, then actually joins the original thread. Drop alone is not a join receipt. Original uncertainty survives in the terminal worker report.

## Resource bounds

Defaults: 4096 live records, 8 MiB live record frames, 16 MiB WAL, 12 MiB checkpoint threshold; 16 MQs, 64 operation/filter rows, 1024 filter bytes each, 65535-byte response slabs, 17 worker jobs. Payload frames allocate only for rows/jobs/physical queues; no per-iterator database clone is kept. File/record/queue bounds are explicit and fallible. Header/transaction metadata is included in the WAL capacity validation. The existing transport-std managed replay/HELLO journal is deliberately unchanged and remains a separate owner.
