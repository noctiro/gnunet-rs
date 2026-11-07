# Normal STATISTICS public-owner reference probe

This runner compiles an ordinary caller of all8official public STATISTICS APIs
against a normal unmodified `libgnunetstatistics`/`libgnunetutil` build. It then
runs the Rust `StatisticsHandle` and restricted `CallbackContext` against
the same literal local fixtures and a fresh normal C statistics daemon. It does
not extract upstream function bodies, replace libraries, patch upstream source,
call public DNS, or introduce production C FFI.

```sh
cargo build -p gnunet-ipc-unix --example statistics_public_owner --locked --offline
python3 tools/reference/statistics_public_owner.py \
  --reference /path/to/normal-statistics-build/build-result.json \
  --rust target/debug/examples/statistics_public_owner \
  --output /new/public-owner-evidence
```

The reference must be the normal v0.29.1 build recorded by `build_reference.py`.
Its full tracked source identity, generated headers, libraries and binaries are
checked before execution and again afterward. The compiler uses the normal build's
recorded include/link flags. The output directory must not already exist.
All accepted Unix sockets and IPv4/IPv6 listeners are owned local resources;
child processes are reaped and private IPC directories removed. The intentionally
crashing C negative case has core dumps disabled. No unrelated daemon is stopped.

The33scenario catalog includes five DISABLE values, lazy create/update0,
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
and official source invariance. Each of the33C/Rust pairs compares wire
output bytes and ordered callback values. Literal input bytes must be identical.
There is no normalization that changes callback values to make a C defect match.
Known differences are recorded with both raw observations. This is selected
observable equivalence, not exact wall-clock or internal-MQ introspection.

## Deliberate reference differences

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

`full_client_api_verified` remains false. Four scenario pairs have explicit
reference differences; the destroy scheduling difference also exists within a
pair whose wire output and callback values agree. All required lifecycle cases,
public API surfaces and host/runtime dependency closure still need their own
source-bound review. Exact1ms/backoff cap/reset/deadline equality, private MQ
inflight/send0/EAGAIN/fatalfirst states, Rust capacity/generation boundaries,
resolver/DNS, activation/ARM and the whole configuration/platform matrix are not
inferred from normal process success. A normal C raw pointer after terminal
completion must never be passed back merely to mimic a Rust stale-ID test.

## Case inventory

The runner binds all exact required case IDs from `spec/gnunet/api/statistics.json`
and reports the following C-only observations. No row automatically promotes its
Rust criterion or sets verification. `c_observed` means selected normal C behavior
was observed; `c_partial` retains untested parts; `c_discrepancy` retains an actual
reference variance; contract and Rust-only cases need separate validation.

| # | Exact case | C observation | Remaining scope |
| --- | --- | --- | --- |
| 1 | `statistics.client.create.disabled` | `c_observed` | Rust paired trace still required. |
| 2 | `statistics.client.create.lazy` | `c_partial` | The private initial 1ms backoff value is not inspected. |
| 3 | `statistics.client.create.subsystem` | `c_observed` | Rust event/API pairing remains pending. |
| 4 | `statistics.client.create.config` | `c_partial` | No ARM activation, public/general DNS, Unix/TCP round alternation, longpath, or every config profile. Rust must safely reject/ignore invalid TCP, not copy the crash. |
| 5 | `statistics.client.destroy.immediate` | `c_observed` | No Rust callback-owner or stale future proof. |
| 6 | `statistics.client.destroy.current-get` | `c_observed` | Rust completion scheduling differs and must be documented/tested. |
| 7 | `statistics.client.destroy.defer-condition` | `c_partial` | Private MQ in-flight-only and first-try fatal/EAGAIN/full-write boundaries are not introspected. |
| 8 | `statistics.client.destroy.drain` | `c_observed` | Processing confirmation is not a filesystem durability proof. |
| 9 | `statistics.client.destroy.confirm` | `c_partial` | Trailing/malformed CONFIRM and early barrier-write races are not tested; no false durable result is invented for C void API. |
| 10 | `statistics.client.destroy.deadline` | `c_partial` | Exact admission+5*backoff equality, cap/reset internals, overflow and immutable deadline require clock/MQ oracle or Rust virtual time. |
| 11 | `statistics.client.destroy.failure` | `c_partial` | C has no DestroyReport; Rust discarded/unknown mutation counts must be independently checked. |
| 12 | `statistics.client.destroy.callback-authority` | `c_partial` | Old connect/read/write/timer completion generation checks exist only in Rust and need paired host tests. |
| 13 | `statistics.client.get.wildcards` | `c_observed` | No new Rust conformance credit. |
| 14 | `statistics.client.get.queue` | `c_observed` | No C generation IDs exist. |
| 15 | `statistics.client.get.values` | `c_observed` | Borrowed callback contract follows the public header; no invalid retained pointer is exercised. |
| 16 | `statistics.client.get.watch-interleave` | `c_observed` | Rust paired buffered trace remains pending. |
| 17 | `statistics.client.get.end` | `c_partial` | Private backoff reset to precisely 1ms is source reviewed, not normally introspected. |
| 18 | `statistics.client.get.abort-iterator` | `c_observed` | No Rust callback-interface promotion. |
| 19 | `statistics.client.get.failure` | `c_observed` | Both owners ignore well-framed unregistered types and continue VALUE/END; malformed registered messages fail. Callback registry/platform scope remains separate. |
| 20 | `statistics.client.get.callback-lifetime` | `contract_only` | Not an executable proof of Rust type/lifetime exclusion; add compile-fail/API contract review. Never invoke forbidden C use to obtain a passing test. |
| 21 | `statistics.client.get.bounds` | `rust_only_pending` | Rust queue/name/terminal atomic admission, IDs and callback authority require Rust snapshots; C process success cannot certify them. |
| 22 | `statistics.client.get_cancel.queued` | `c_observed` | Rust pair still pending. |
| 23 | `statistics.client.get_cancel.current` | `c_observed` | No C pointer can be reused after terminal completion. |
| 24 | `statistics.client.get_cancel.late` | `rust_only_pending` | Passing a stale C pointer is invalid use, not a normal reference test. Rust logical generation reuse protection needs Rust-only negative tests. |
| 25 | `statistics.client.get_cancel.buffered` | `c_observed` | Rust event/CallbackContext pairing still pending. |
| 26 | `statistics.client.set.absolute` | `c_partial` | Standalone absolute zero/UINT64_MAX full-domain boundary samples are not both sent without coalescing in this batch. |
| 27 | `statistics.client.set.replace` | `c_partial` | Same-name in-flight vs pending mutation and EAGAIN should be added to paired trace. |
| 28 | `statistics.client.set.coalesce-order` | `c_observed` | No queue shim used. |
| 29 | `statistics.client.set.update-to-set` | `c_observed` | No Rust paired trace yet. |
| 30 | `statistics.client.set.queue-atomic` | `rust_only_pending` | Rust capacity rejection must prove old value/persistence/FIFO/completion ownership unchanged; not observable through normal C allocation success. |
| 31 | `statistics.client.set.submission` | `c_partial` | Kernel partial/fatal-first/EAGAIN and in-flight length boundary need explicit socket or component proof; unknown Rust outcomes are independent. |
| 32 | `statistics.client.update.signed` | `c_observed` | INT64_MIN C undefined negation is deliberately excluded from portable behavior claims. |
| 33 | `statistics.client.update.zero` | `c_partial` | Existing-row persistence not changed by a new update(0) is not independently sampled in the normal daemon. |
| 34 | `statistics.client.update.absolute-pending` | `c_partial` | INT64_MIN negative magnitude is undefined in the C subtract expression; do not certify that C UB as a standard. Rust defined safe boundary needs its own test. |
| 35 | `statistics.client.update.relative-pending` | `c_observed` | Other unsigned-wrap boundary samples remain available in extracted C queue oracle, not recredited here. |
| 36 | `statistics.client.update.persistence` | `c_observed` | Zero-call persistence is separately partial. |
| 37 | `statistics.client.update.timeout` | `c_observed` | This is non-expiry past2s, not a claim on precise retry intervals. |
| 38 | `statistics.client.watch.literal` | `c_observed` | No wildcard watch semantics invented. |
| 39 | `statistics.client.watch.no-ack` | `c_partial` | No claimed positive WATCH acknowledgment or remote cancellation acknowledgment. |
| 40 | `statistics.client.watch.initial` | `c_observed` | Service and client are both unmodified C binaries. |
| 41 | `statistics.client.watch.ordering` | `c_observed` | Reconnection hole separately records C discrepancy. |
| 42 | `statistics.client.watch.callback` | `c_observed` | No callback return translated into private unwatch. |
| 43 | `statistics.client.watch.flags` | `c_discrepancy` | Rust correct flag2/raw flags representation must remain a documented safe protocol discrepancy, not edited C expectations. |
| 44 | `statistics.client.watch.reconnect` | `c_observed` | C stale array callback mapping is separately defective. |
| 45 | `statistics.client.watch.epochs` | `c_partial` | C has no explicit epoch/generation token; canceled-hole watch mapping actually differs. Rust stale connect/read/write and reused logical slot tests remain required. |
| 46 | `statistics.client.watch_cancel.local` | `c_observed` | Service resource release follows connection ownership; no invented remote unwatch ACK. |
| 47 | `statistics.client.watch_cancel.identity` | `c_observed` | Rust logical tokens need equivalent selection documented. |
| 48 | `statistics.client.watch_cancel.queued-copy` | `c_partial` | Rust reused-slot generational authority is not a C public feature and needs Rust trace. |
| 49 | `statistics.client.watch_cancel.reconnect-hole` | `c_discrepancy` | The safe logical-vs-wire remapping requirement intentionally fixes this C defect. Do not silently mark C behavior equivalent. |
| 50 | `statistics.client.reconnect.backoff` | `c_partial` | Exact 1ms/doubling/900s cap/END reset and initial CLIENT2ms distinction require clock/component proof, not wall-clock guess. |
| 51 | `statistics.client.transport.partial-write` | `c_partial` | No guaranteed kernel EAGAIN, send0, fatal first send, or exact non-inflight-length proof. Existing extracted MQ/core tests remain separate evidence. |
