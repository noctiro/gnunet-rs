# gnunet-service-namecache

Run `gnunet-service-namecache -c official.conf`, or use the standard SERVICE
`-d/--daemonize` mode. Options are the shared official c,d,h,L,l,v set. The
installed v0.29.1 source is GNUNET_SERVICE_MAIN with SERVICE_OPTION_NONE; this
entry uses that lifecycle rather than a PROGRAM wrapper. It serves the existing
lookup/cache/delete IPC through the existing bounded Server and Cache.

The backend remains bounded volatile ciphertext memory. Startup reports
`backend=volatile-memory restart-persistence=no workers=0`. Cache/delete success
follows an memory operation; the external IPC does not promise disk
fsync. Restart clears the cache. The C DATABASE/SQL plugin configuration does not
load a pretend SQL backend here: internal BACKEND defaults to memory and another
explicit value is rejected. No GNS resolver host or private key source is added.

Original inherited listeners and the separate parent-control read descriptor are
captured once before logger/configuration/runtime opens. After selected logging
and an optional daemon split, only the service branch continues. TCP and
inherited listener preparation precede configured USERNAME/group transition;
new Unix endpoints finish under the target account. UNIX_MATCH_UID/GID determine
new endpoint creation permissions and, separately, kernel peer admission. Existing parents/inherited paths are not chmod/chown'ed. The original listener
owners and inode guards close/unlink in their existing shared order.

cache allocation, logical clock subscription and configured/activated
listeners precede the flushed READY observation. Only then does ChildReady try
the original daemon status byte. Parent EOF or an initialization/failure byte is
never success. The foreground branch uses the same readiness path without a
fake parent receipt. Readiness is historical, not a claim of future health or
remote processing. No PILS dependency is required by this cache service.

The same SharedClock is passed to the cache service, its original Resolver broker
and the shared selected Logger. The broker's configuration selection is
performed explicitly; the original driver is polled fairly with Server, the
shared statistics producer and parent/signals in one caller-driven loop. There is no PROGRAM task, hidden
runtime, worker, second listener or second cache. Standard -L/-l policy applies to
admission/source/Resolver/failure/cleanup events. A first logging failure
latches and wakes this same loop; sources close before its owned error is returned. Taking the logging error never clears the failure latch.

SERVICE_OPTION_NONE defaults to immediate SIGINT/SIGTERM/parent-stop shutdown. The existing Server's bounded soft-drain branch remains available internally;
its original finite grace is not renewed by another signal. All exits close the
MQs without requiring another clock sample, disconnect the same Resolver,
and release listener ownership. Original task, Resolver cleanup, daemon status,
stdout and selected-logging errors are retained independently. An emergency-drop
cleanup slots preserve original Resolver and statistics-abort errors independently
rather than merely printing them. No queue admission is called a whole write, remote ACK or disk commit.

Official [namecache] HOSTNAME, PORT, UNIXPATH, UNIX_MATCH_UID, UNIX_MATCH_GID,
USERNAME, ACL and tolerance options are consumed by the existing shared owners. With no explicit -c, SERVICE uses the XDG/user candidate and installed
defaults. The official DISABLE key remains a consumer-side cache-use choice;
the C NAMECACHE service itself also continues to expose its API.

Bounded [namecache-rust] resource keys are unchanged:

- BACKEND=memory, MAX_ENTRIES=1024, CACHE_BYTES=8 MiB, MAX_BLOCK_BYTES=63 KiB.
- MAX_CLIENTS=32, FRAME_BYTES=65535, OUTPUT_FRAMES=4, OUTPUT_BYTES=262140,
  IO_SLICE_BYTES=65535.
- FIRST_INPUT_TIMEOUT=30 s, INPUT_LIFETIME=30 s, OUTPUT_LIFETIME=30 s,
  MAINTENANCE_INTERVAL=1 h, SHUTDOWN_GRACE=10 s.

FRAME_BYTES must fit MAX_BLOCK_BYTES+16 and at least72 bytes. Original per-source
FIFO/backpressure, fixed input/output deadlines, malformed-source isolation and
logical expiry behavior are unchanged. Sources do not migrate/replay results on
another MQ. STOPPED reports local/cache counters and the original statistics
producer report; failures retain Resolver drain and later disconnect separately.

## Official statistics

The same shared `gnunet_ipc_unix::producer` used by other services emits four
nonpersistent official counters under subsystem `namecache`:

- `blocks looked up`: each lookup handler invocation, including miss.
- `blocks found in cache`: each returned nonempty lookup block.
- `blocks cached`: each cache handler invocation, including backend
  rejection/failure; this is not the number of successful insertions.
- `blocks removed`: each delete handler invocation, including missing
  blocks/backend failure; this is not a successful-removal count.

These are separate from `cache_stats()` entries/block_bytes/metadata_bytes and
native source/write counters. Observations happen inside the original production
dispatch after frame/output preflight and before the backend call, with found
observed only from its response. Held-RX capacity retries, response-size
lookups and queued/written responses do not count. The existing pure dispatch
model shares the same implementation through its test-only no-observer wrapper.

The host stores four checked u64 counters and a diagnostic overflow flag. A
representation overflow fences the producer snapshot; it never rejects or
changes the original cache operation, its RID or reply. There is no new cache,
wire message, storage worker, crypto provider or private key source.

The producer uses the same original Resolver context and RuntimeClock Arc. Its own native operation hard guard runs before shared-clock waits, and the
service checks the permanent Reporter latch before every provider class,
including after a native-guard error's warning. A statistics failure fences only
that original diagnostic owner; healthy cache business continues. No failed
owner is recreated to replay a relative delta. Local write/Destroy/Unknown facts
are retained as the producer report; none is a disk or remote-application
acknowledgement.

On ordinary stop, all application MQs physically stop first. One final actual
counter snapshot is frozen for a finite diagnostic drain while the same original
Resolver remains alive. `[namecache-rust] STATISTICS_SHUTDOWN_GRACE=5 s` bounds
that original intent and cannot be renewed by progress/retry. `STATISTICS_OPERATION_TIMEOUT=5 s` bounds each original setter; its frame cap
is256 bytes and native write quantum is min(IO_SLICE_BYTES,256). Business/clock/log
failure uses immediate clock-free diagnostic abort instead. `[statistics]
DISABLE` remains the common client-side switch. Statistics startup does
not add an external Connected requirement to local NAMECACHE readiness.
