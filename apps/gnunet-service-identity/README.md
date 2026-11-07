# Rust IDENTITY SERVICE

`gnunet-service-identity` uses the shared standard SERVICE options (`-c`, `-d`,
`-h`, `-L`, `-l`, `-v`), default configuration selection and selected Logger. The pinned public v0.29.1 entry is `GNUNET_SERVICE_MAIN("identity",
GNUNET_SERVICE_OPTION_NONE, ...)`. This app continues to use the existing real
Ego CRUD, exact/suffix lookup, subscription, IPC, canonical inventory and marked
snapshot Server; no protocol or key/storage algorithm is replaced.

Early startup captures the original inherited listener and parent-control FDs
once. Explicit daemonization occurs before NSS, runtime, listener paths, store
or worker. New TCP listeners are prebound before configured `USERNAME`, then
new Unix listeners are created under the selected UID/GID filesystem policy;
inherited listeners keep their original ownership. Kernel peer credentials
remain a separate admission check in the unchanged Server.

One caller-owned future runs on one explicit current-thread runtime with the
same shared clock, Logger and Resolver broker. It is not moved into a PROGRAM
scheduler task. Actual listeners, marked-store recovery, original worker and
Server precede `READY identity ...`; successful stdout flush precedes the
original daemon `ChildReady` byte. Failed recovery or initialization never
claims readiness. Parent-control EOF is distinct from a stop signal and cannot
manufacture a ready byte.

SIGINT/SIGTERM or the matching parent-control byte starts one finite soft MQ
grace; a second signal ends it. Selected-Logger failure permanently gates new
provider polls and wakes the same future. Its native grace is checked before
canonical/provider progress and is never renewed. Actual MQ retirement and
Resolver physical closure precede waiting for the original disk result/join. After `Worker::start`, constructor errors run that same worker's shutdown;
a successfully constructed Server uses its existing shutdown/drain/join. An elapsed native grace is only an observation: an OS filesystem operation is
not force-canceled, a timeout is not join, and no replacement worker is started.

Owned terminal results retain Server/worker reports, original operation,
Resolver closure, stdout, selected-Logger and independent cleanup errors,
including a Logger-only failure. Logs contain public metadata, not request
frames, ego names, keys or snapshots. `STOPPED` reports original results.

Example (choose a final store directory that does **not** already exist):

```ini
[identity]
HOSTNAME = localhost
PORT = 0
UNIXPATH = /private/tmp/my-private-runtime/id.sock
UNIX_MATCH_UID = YES
UNIX_MATCH_GID = NO

[identity-rust]
DIRECTORY = /private/tmp/my-private-data/new-identity-store
MAX_CLIENTS = 32
MAX_EGOS = 256
MAX_NAME_BYTES = 1024
SNAPSHOT_BYTES = 4 MiB
STORE_BODY_BYTES = 4 MiB
OUTPUT_ITEMS = 8
OUTPUT_FRAMES = 2
OUTPUT_BYTES = 131070
FRAME_BYTES = 65535
IO_SLICE_BYTES = 65535
RETAINED_VERSIONS = 8
FIRST_INPUT_TIMEOUT = 30 s
INPUT_LIFETIME = 30 s
OUTPUT_LIFETIME = 30 s
STORAGE_LIFETIME = 30 s
SHUTDOWN_GRACE = 10 s
```

`DIRECTORY` defaults to `${GNUNET_DATA_HOME}/identity-rust-v1`, independent of C's
`EGODIR`. It must be absolute. Existing unmarked final directories and C stores
are never imported or migrated. Private material stays in the service storage owner.
