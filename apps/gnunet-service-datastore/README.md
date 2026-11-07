# Rust DATASTORE service

`gnunet-service-datastore -c official.conf` runs the independent standard
SERVICE. Shared `-d`, `-h`, `-L`, `-l` and `-v` options select daemonization,
help, logging and version behavior. Configured activation/TCP setup precedes
USERNAME switching; new Unix listeners and the durable store belong to the
selected account. The same selected clock drives logging and the server.

`READY` and the separate daemon-parent byte follow backend recovery, actual
listeners and worker construction. SIGINT/SIGTERM, parent control or the first
logging error take the ordinary immediate shutdown path. Original operations,
requested DROP and the storage-thread join settle before return. Operation,
worker, stdout and selected-log errors remain independent failure facts.

The storage directory is an internal Rust backend choice; no old layout or CLI
migration is required. Configure it explicitly or use the normal data home:

```ini
[datastore]
UNIXPATH = /private/tmp/example-datastore/socket
PORT = 0
QUOTA = 32 MB
UNIX_MATCH_UID = YES

[datastore-rust]
DIRECTORY = /private/tmp/example-datastore/rust
```

Without DIRECTORY, `${GNUNET_DATA_HOME}/datastore/rust` is selected; an unresolved
home is an error. QUOTA defaults to the official 5,000,000,000 bytes. Existing
MAX_RECORDS, MAX_WAL_BYTES, CHECKPOINT_BYTES, MAX_TRANSACTION_OPS, GARBAGE_ENTRIES,
MAX_VALUE_BYTES, eviction/client/reservation/worker/IO budgets and finite
MAINTENANCE_INTERVAL retain their backend/service meanings.

New Unix socket/parent permissions follow the configured credential policy:
owner 0700/0700, group 0770/0750, or local 0777/0755. Existing parents and inherited
socket permissions remain unchanged. Filesystem creation permissions and actual
kernel UID/GID checks are independent; the server applies both. Database parent
directories remain private.

The changed service/runtime/backend sources pass macOS/Linux strict compilation. Official-C and whole-node qualification remain
separate, unproved work.
