# IDENTITY service

`gnunet-service-identity` serves the official IDENTITY IPC protocol through the
[shared host](../../adapters/identity-std/README.md): ego CRUD, exact/suffix
lookup, subscription and a private Rust inventory store. Standard SERVICE
options are `-c`, `-d`, `-h`, `-L`, `-l`, `-v`.

## Startup and platform ownership

`main.rs` owns diagnostics; `settings.rs` owns configuration. `foreground.rs`
and `lifecycle.rs` share the same Server, disk worker, Resolver and stop policy.
`unix.rs` and `windows.rs` contain only native bootstrap differences.

Unix captures inherited descriptors once and detaches before runtime, account
lookup or workers. TCP listeners prepare before configured `USERNAME`; new
local listeners finish under the selected UID/GID. Windows captures native
activation and parent bootstrap, verifies the configured account against its
primary-token SID before listeners/storage, and uses native managed detachment
or standalone re-exec. Inherited listeners retain their original ownership.

Readiness follows listener setup, marked-store recovery, worker/Server creation
and successful output flush. The platform callback then acknowledges the
original parent. Initialization failure never sends success; parent EOF does
not fabricate a stop. Local credentials and configured IP ACLs remain separate
admission checks.

## Shutdown and errors

Native stop or parent interrupt/terminate starts one finite MQ grace; a second
stop ends it. Logger failure stops new work and wakes the same service future.
Physical MQ/Resolver retirement precedes waiting for the original disk result
and worker join. Constructor failure after worker startup runs the same cleanup.
An elapsed grace cannot cancel a kernel filesystem syscall or stand in for join.

Terminal results retain the operation, Server/worker, Resolver, output, Logger
and independent cleanup failures. Logs contain public metadata, never ego names,
keys, frames or snapshot bodies.

## Configuration

Choose a final store directory that does not already exist, or an already
qualified Rust store. This Unix example uses private local IPC; on Windows,
select absolute native paths for `UNIXPATH` and `DIRECTORY`.

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
