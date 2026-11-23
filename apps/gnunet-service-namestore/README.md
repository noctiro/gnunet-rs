# NAMESTORE service

`gnunet-service-namestore` hosts the official NAMESTORE IPC protocol through the
[shared host](../../adapters/namestore-std/README.md) and an independent marked
Rust snapshot store. Standard SERVICE options are `-c`, `-d`, `-h`, `-L`, `-l`,
`-v`.

## Source and platform ownership

`main.rs` owns diagnostics, `settings.rs` configuration, and `foreground.rs` the
caller-driven Server/worker/Resolver loop. `lifecycle.rs` retains cleanup facts.
The same business and protocol code runs on Unix and Windows.

`unix.rs` captures original descriptors and detaches before runtime or account
lookup. TCP/activation preparation precedes privilege selection; new local
listeners finish under the selected UID/GID. `windows.rs` captures native
activation and parent bootstrap, checks configured `USERNAME` against the
primary-token SID, and selects managed detachment or standalone re-exec before
registering stop handlers. Inherited socket ownership is retained.

## Configuration and storage

Use standard `[namestore]` listener/ACL settings. `[namestore-rust] DIRECTORY`
selects an absolute private Rust namespace, defaulting to
`${GNUNET_DATA_HOME}/namestore-rust-v1`. Parents may exist; the final directory
must be fresh or already contain the exact Rust marker and canonical state.
For a local-only service:

```ini
[namestore]
UNIXPATH = ${GNUNET_RUNTIME_DIR}/namestore.sock
UNIX_MATCH_UID = YES

[namestore-rust]
DIRECTORY = ${GNUNET_DATA_HOME}/namestore
```

On Windows, use absolute native paths. A new store commits the valid empty
canonical format under its original lease before worker startup or readiness.
An existing marked store with missing or malformed canonical state is refused.
Snapshot capacity must fit the 12-byte empty authority before opening storage.
The [shared snapshot contract](../../adapters/snapshot-std/README.md) defines
private creation, original-object fences, native file synchronization and
explicit directory-barrier availability. C databases are not imported.

## Offline maintenance

`gnunet-namestore-dbtool` uses the service's storage path and exclusive writer
lease. Run it under the configured service account. Stop the service before
opening its store with this command.

```sh
gnunet-namestore-dbtool -c gnunet.conf --plugin rust --init
gnunet-namestore-dbtool -c gnunet.conf --plugin rust --reset
```

`--init` initializes fresh storage or completes a marked store whose first
snapshot is absent. An intact existing inventory is validated and kept.
`--reset` discards all stored NAMESTORE rows by publishing an empty snapshot
under the same lease. It keeps the store marker and advances the snapshot
generation. Previously published GNS data retains its original lifetime.
Physical media erasure is outside the snapshot publication contract.

## Readiness, stop and errors

READY follows listeners, recovery, original worker and Server, an installed stop
check and output flush. Only then does the native callback acknowledge the
original parent. Shared stop subscriptions retain parent EOF separately from
interrupt/terminate; Windows also observes native console termination.

One finite native grace bounds new socket work. Shutdown closes actual sources,
retires the Resolver, drains the original disk completion and joins its worker.
Canceling a wait retains its original owner; a timeout cannot cancel a kernel
filesystem syscall or claim a join. Startup/runtime failures retain original
operation and independent cleanup/diagnostic causes. Logs omit private requests,
labels, keys and snapshots.
