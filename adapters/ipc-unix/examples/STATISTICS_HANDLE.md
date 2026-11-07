# Official STATISTICS handle Unix/TCP daemon probe

`statistics_handle.rs` exercises `gnunet_ipc_unix::handle::StatisticsHandle`
through official configuration and the unmodified GNUnet v0.29.1 C
STATISTICS daemon. It uses the high-level queued owner, rather than the one-shot
GET/SET clients or independently encoded private messages.

```sh
cargo build -p gnunet-ipc-unix --example statistics_handle --locked --offline
python3 adapters/ipc-unix/examples/statistics_handle_oracle.py \
  --reference /absolute/path/to/build-result.json \
  --rust target/debug/examples/statistics_handle \
  --output /absolute/path/to/new-owned-proof-directory
```

The reference receipt is produced by `tools/reference/build_reference.py`. The
runner requires its pinned clean official source, unchanged normal executables,
libraries and default configurations. It copies participant executables into
its proof directory, runs the existing C binaries unchanged, and binds runtime
source/executable/reference hashes in `result.json`. Every socket, PID and data
file belongs to a private 0700 temporary directory; all child processes are
reaped and runtime files removed. No public network, ARM or peer process starts.

The roundtrip case checks lazy create, zero-update no-op, queued setter
coalescing, persistent GET and WATCH values, ignored WATCH return flow,
reentrant current-GET cancellation, draining that GET's END before a replacement,
iterator abort with its successful END continuation, and an actual
DISCONNECT_CONFIRM during `destroy(true)`. A normal C CLI independently reads
counter43/barrier99 and checks that zero-update created no row. The C daemon
then exits normally and saves the fixture database.

The reconnect case cancels the first of two logical watches, reuses its slot
for a third selector, and writes an explicit PID ready file. Only after that
signal does the runner inject **SIGKILL into its owned daemon**. It records the
expected signal exit separately and starts another normal C daemon. The Rust
handle must deliver the surviving `b` watch on fresh wire WID0 and replacement
`c` on WID1, with the original logical identities/selectors. No callback may
revive the cancelled watch. The restored values were saved by the earlier
normal daemon shutdown; the injected crash does not prove new writes durable.
Both normal daemon instances exit0; the intentionally crashed instance is
explicitly recorded as signal9. A processing confirmation establishes server
processing only, never a disk commit or exactly-once delivery.

The C source's callback-array hole/re-registration problem remains a
source-derived potential C-client bug; this probe establishes correct Rust
logical/WID mapping against the C **server**, and does not claim to have
reproduced that C-client callback bug.

The caller-owned wrapper deliberately stores no task or per-operation callback closure
map. Each `drive` dispatch is synchronous. Dropping a drive future preserves its
partial cursors and original operation; explicit `get_cancel` cancels that
operation. A caller that keeps ID→closure maps can use `owns_get`,
`get_callbacks_enabled` and `owns_watch` (also available in `CallbackContext`)
to release local state when the C lifecycle suppresses a continuation, including
explicit cancellation or an aborted iterator followed by connection loss.

Independent review followed `src/service/statistics/statistics_api.c` and
`src/lib/util/client.c` at commit
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`. No existing wire/lifecycle bug was
found in the new Unix driver. The review added lifecycle-introspection forwards
and two actual-socket tests: iterator abort preserves completion on END while
suppressing it on disconnect; exact processing confirmation closes the socket
and revokes all subsequent callback admission. The runtime test suite has eight
cases, including fragmentation, future cancellation, virtual MQ initial retries,
watch remapping and an already-expired destruction deadline.

An additional normal C daemon binds an explicit IPv4 loopback TCP port. The
Rust client receives a separate configuration containing only HOSTNAME/PORT,
with no UNIXPATH, and runs the same complete roundtrip through TCP. A normal C
CLI independently reads the resulting counter/barrier values. The runner binds
the shared transport, network helpers, configuration and other Rust
inputs in addition to the owner and example sources. This proves the normal C
service's TCP data path; it does not exercise a normal C client's complete
callback lifecycle or the full resolver service.

Configured clients implement the active `util/client.c` endpoint order: even
attempts try Unix before TCP in the same round, odd attempts select TCP, and
Unix-only endpoints always try Unix. Long paths use the official byte-path
shortening helper. Numeric addresses and official loopback names have exact
fast paths; general hostnames query the configured GNUnet resolver using its
request4/response5 frames. Each TCP probe and DNS request has the source's
five-second budget; up to32 address probes are admitted, with explicit capacity
failure instead of silently truncating DNS results. TCP disables Nagle as the C
network initialization does. One current connection's initial retry retains its
immutable virtual MQ; an established failure creates a new epoch.

`from_config` owns a configuration snapshot and checks only DISABLE at creation.
Invalid endpoint configuration is reported lazily as ConnectionUnavailable with
the detailed `take_connect_error`, using the STATISTICS backoff without creating
a fictitious MQ. Pending setters remain coalescible and unsubmitted. Only YES
disables; missing/invalid DISABLE values remain enabled. Raw empty UNIXPATH is
expanded as a relative filename by official configuration, so it must not be
confused with failed filename expansion.
