# Independent PEERSTORE standard SERVICE

Run `gnunet-service-peerstore -c official.conf`. The standard shared SERVICE options are `-c/--config`, `-d/--daemonize`, `-h/--help`, `-L/--log`, `-l/--logfile`, `-v/--version`; SERVICE does not register `-V/--verbose`. Selected Logger policy and its owned file actually handle entry, socket, HELLO-import, storage-failure and cleanup diagnostics without changing global fd2. The former private `--storage` option is removed. Storage is selected only by `[peerstore-rust] DIRECTORY`, otherwise `${GNUNET_DATA_HOME}/peerstore/rust`; existing C plugin/database directories are not migrated or adopted.

## Native startup

Startup captures original activation/parent-control descriptors first, selects options/logging, then uses the explicit fresh single-thread daemon boundary if requested. Configured account resolution and TCP/inherited-listener preparation precede identity application; new Unix endpoints finish under the target account. Every listener is complete before opening the Rust WAL or starting its one bounded worker. READY is sent only after the original server is fully constructed and stdout is flushed; the daemon's original status writer reports ready once. Earlier errors and clean pre-ready stops report failed startup. No runtime task performs a process identity change.

Windows captures native activation/bootstrap, verifies the selected process SID,
and registers its qualified parent and native stop subscriptions before opening
the same private WAL or worker. Both platforms share one foreground and Reporter.
Readiness acknowledgement has a fixed deadline and observes stop/logging failures.

## Configuration

`[peerstore]` listener/ACL/Unix-credential/USERNAME and USE_INCLUDED_HELLOS policy retain their original behavior. Included public HELLO files are bounded and parsed into the existing binary HELLO cache records, without inventing signature/address authentication. The original UID iterator, monitor credit, source loss, immutable send exposure, committed STORE_RESULT and WAL/worker implementations are unchanged.

`[peerstore-rust]` resource keys remain MAX_RECORDS, MAX_LIVE_BYTES, MAX_WAL_BYTES, CHECKPOINT_BYTES, MAX_CLIENTS, MAX_OPERATIONS, FILTER_BYTES, MAX_RECORD_BYTES, WORKER_QUEUE, IO_SLICE_BYTES, MAINTENANCE_INTERVAL, MAX_INCLUDED_HELLOS, HELLO_DIRECTORY and SHUTDOWN_GRACE. WORKER_QUEUE must be at least MAX_CLIENTS+1. MAX_RECORD_BYTES defaults to 65535 for unchanged C monitor producers with harmless trailing padding. These are bounded local storage/runtime policies, not a new wire protocol.

## Shutdown

Native termination and diagnostic IO failure request the configured soft lifetime: monitors do not keep the service alive and ordinary MQs receive one fixed finite grace (default 10 seconds). A second signal or that original deadline forces local source cleanup. Original admitted disk work still drains and the original worker is actually joined. Service errors, server cleanup, joined worker failure/missing receipt, outer fallback join and diagnostic/output failures are preserved independently; no earlier `result?` hides later failures. A local source stop is not a disk completion, and a status byte is not a remote delivery receipt.

Socket grace cannot force-cancel synchronous OS file operations, admitted fsync/rename or thread join.
