# Normal STATISTICS public-owner reference probe

This runner compiles an ordinary caller of the official public STATISTICS APIs
against a normal unmodified `libgnunetstatistics`/`libgnunetutil` build. It then
runs the Rust `StatisticsHandle` and restricted `CallbackContext` against
the same literal local fixtures and a fresh normal C statistics daemon. It does
not extract upstream function bodies, replace libraries, patch upstream source,
call public DNS, or introduce production C FFI.

## Invocation

```sh
cargo build -p gnunet-ipc-unix --example statistics_public_owner --locked --offline
python3 tools/reference/statistics_public_owner.py \
  --reference /path/to/normal-statistics-build/build-result.json \
  --rust target/debug/examples/statistics_public_owner \
  --output target/statistics-public-owner/new-run
```

## Runtime scope

The reference must be the normal v0.29.1 build recorded by `build_reference.py`.
Its full tracked source identity, generated headers, libraries and binaries are
checked before execution and again afterward. The compiler uses the normal build's
recorded include/link flags. The output directory must not already exist.
All accepted Unix sockets and IPv4/IPv6 listeners are owned local resources;
child processes are reaped and private IPC directories removed. The intentionally
crashing C negative case has core dumps disabled. No unrelated daemon is stopped.

The scenario catalog includes five DISABLE values, lazy create/update0,
missing transport, numeric IPv4/IPv6, pending setter coalescing across GET,
unsigned wrap/clamp, signed relative SET, wildcard/opaque GET, WATCH interleave,
queued/current/buffered cancellation, iterator abort END/loss, malformed VALUE/END,
unhandled type, null continuation, unexpected CONFIRM, watch identity/reconnect,
partial old RX, immediate/deferred destroy, deadline/loss, and pending
setter retention beyond2seconds. The C daemon separately tests persistent
GET, watch initial nonzero/unset zero/first zero/equal suppression, literal empty
watch selectors, duplicate cancellation and watcher return values.

The C and Rust observers receive control commands from outside their owner.
Each COMMIT batch runs synchronously before scheduler/driver progress, preserving
MQ admission and pending-action coalescing. The Rust observer drives the real
caller-owned handle; stdin polling may drop a single drive future while retaining
the owner and its partial cursors. Get cancellation happens through the formal
CallbackContext before the next co-buffered VALUE. Per-operation consumer
contexts are keyed by typed GetId/WatchId; duplicate C callback identities map to
ordered logical tokens. Names and values are copied only during each callback.
The observer does not synchronously destroy an owner from a GET continuation.
Both owners ignore well-framed unregistered message types and retain the original GET/epoch. Registered malformed VALUE/END/CONFIRM messages still follow their handler failure paths.

`result.json` retains nonzero assertion counts, every scenario and trace
hash, both callbacks and wire frames, compiler argv, binaries, source inputs,
and official source invariance. Each executed C/Rust pair compares wire
output bytes and ordered callback values. Literal input bytes must be identical.
There is no normalization that changes callback values to make a C defect match.
Known differences are recorded with both raw observations. This is selected
observable equivalence, not exact wall-clock or internal-MQ introspection.

## Reference differences

- C watch persistence checks the VALUE UID high bit; official daemon WATCH_VALUE
  uses flag2. Rust preserves and interprets flag2 correctly. Both literal and real
  C daemon observations are retained.
- C reserved7 produces a source assertion diagnostic and still calls the watcher.
  Rust retains raw reserved/flags in the typed notification instead of pretending
  its diagnostic is byte-identical to a C source-line log.
- C canceled slots survive MQ recreation: fresh WID0/B is suppressed, fresh
  WID1/C reaches old B's callback. Rust uses fresh wire-to-logical mappings.
- Present valid UNIXPATH plus PORT0 but absent HOSTNAME reaches `strlen(NULL)`
  in C CLIENT. Rust can use the valid Unix endpoint safely. This C process's
  SIGSEGV is an expected diagnostic, not correct production behavior to copy.
- C immediate destroy calls an eligible current GET continuation synchronously;
  Rust queues it for the next drive. Final values agree, while API event ordering
  is explicitly checked and retained as a scheduling difference.

The comparison covers observable wire bytes and callback order. Exact scheduler
intervals, private MQ states, capacity limits, activation and platform behavior
require their corresponding profiles. A stale C pointer must never be invoked to
imitate a Rust stale-token test.

## Case inventory

Exact operation and case IDs are maintained in the
[STATISTICS catalog](../../spec/gnunet/api/statistics.json). The runner records
its executed scenarios and both raw traces in `result.json`. A catalog entry is
not an executed result; inspect the report for paired, C-only and untested cases.
