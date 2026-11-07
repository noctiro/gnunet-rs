# Maintained STATISTICS CLOCK-MQ / IO-SEAM witness

This package adds deterministic component evidence to the normal-C/Rust socket and daemon checks. It does not implement a replacement C state machine or certify all STATISTICS/GNUnet features.

Run the C/Rust component check from any directory, with a fresh output path:

```sh
python3 tools/reference/statistics-clock/run.py \
  --repository /absolute/path/to/gnunet-rs \
  --source /absolute/path/to/clean-pinned-gnunet \
  --reference /absolute/path/to/normal-build/build-result.json \
  --output /absolute/path/to/results/statistics-clock
```

The same flags work before integration by pointing to this temporary package's `run.py`. An output inside the repository must be under `target/`; an output inside this tool package is rejected. No generated file is written into this package or production source. The runner creates the independent crate, seeded/generated lockfile, complete unchanged `handle.rs` prefix, copied literal `include_str!` documents, and all Rust seam/test sources under `--output/rust`. All compilation products go under `--output/target`. Cargo runs with explicit `+1.99.1`, offline, from the generated crate working directory. Registry package identities in the generated lock must be a subset of the workspace lock; subsequent checks are locked.

The templates have `.in` filenames and no actual `Cargo.toml` exists in this package. Path dependencies are generated as quoted absolute paths from `--repository`. This permits installing the directory as `tools/reference/statistics-clock/` without accidentally adding a Cargo workspace or changing source hashes during execution.

For Rust-only generator maintenance, omit the C inputs and pass `--rust-only`. This runs the generated owners, port checks, Clippy and rustdoc; its receipt explicitly records that no fresh C comparison ran. It does not promote any C interoperability claim.

A full C/Rust acceptance run requires all of the following:

- Entire unchanged pinned v0.29.1 `statistics_api.c`, plus 26 complete original client/MQ/time declarations or function bodies, compiled against unchanged normal reference libutil/configuration helpers.
- Clean exact pinned upstream source state, matching the normal build receipt, before and after. Actual generated configuration, libraries and compiler dependencies are checked before/after use; compiler/tool versions and full commands are recorded.
- Exactly 73 C observation rows, byte-identical under `-O2` and `-O0 -fwrapv` with the current C compiler. Darwin-specific flags are conditional on the platform; Linux execution requires its own normal reference receipt and has not been claimed by a macOS result.
- Exactly 17 named Rust component tests: eight core clock/queue tests, seven finite I/O tests and two port-binding tests appended to the complete original driver prefix. All source bytes, including `include_str!("handle_lifetimes.md")`, remain unchanged. The referenced Markdown is copied to the generated crate and hashed. The copied public lifetime docs add their doc tests; they are not counted toward the seventeen component tests.
- Fifty-eight common observable C/Rust rows: 32 exact backoff deadlines plus END reset, 21 positive/retry IO states, two immutable-envelope states, the public-owner fatal-first MQ/pending state, and the saturated absolute deadline target.
- All-target Clippy and rustdoc with warnings denied.
- Unchanged repository, tool-package, generated source and copied-document hashes before/after execution.

The C seams provide an exact virtual clock, a finite scheduler invoking the original callbacks, finite NULL/normal-MQ connector outcomes, and finite send-return classes. Original MQ observation wrappers call the complete original bodies. C client sockets are valid owned unbound AF_UNIX objects; no remote send, invalid pointer or public network is used. The generated crate aliases `gnunet_client_host` and `gnunet_service_runtime` only to thin tool capability bindings, while its separately named `client_host_real` and `runtime_real` dependencies execute the public `CLIENT` source/endpoint/attempt, `SharedResolution`, `LiveConfiguration`, and `RuntimeClock`/`Deadline` ports. Only the seven finite I/O tests substitute a scripted physical `Connection`; native connection attempts execute the CLIENT implementation. The two port tests check canonical source identity with distinct waiter ownership, preservation of a caller timer refusal, and Unix connection selection after a live UNIXPATH change. The port fixture supplies no DNS callback stream or protocol responses. Real unmodified core/config/wire/types and driver poll/admission/loss/destruction/cancellation code execute.

The comparator's five negative controls run against the **fresh** C/Rust outputs on every acceptance run. They can also be checked without a C build:

```sh
python3 tools/reference/statistics-clock/selftest.py
```

The standalone control uses stored lexical comparator fixtures. Those fixtures are checker tests and never count as a new C oracle, a fresh implementation receipt, or subsystem-completion evidence. Each mutation must be rejected: partial cursor changed, backoff row removed, sent callback duplicated, fatal first write falsely marked in-flight, and a changed saturated deadline target. `--c-trace` and `--rust-output` can supply another pair; `--output` optionally writes the control result to the caller-selected location.

The covered obligation IDs are `statistics.client.create.lazy`, `destroy.defer-condition`, `destroy.deadline`, `get.end`, `set.submission`, `reconnect.backoff`, and `transport.partial-write`. They distinguish lazy create; 1ms doubling with a 15-minute cap; END-only reset; MQ non-in-flight length; a single destroy deadline of admission time plus five times current backoff; expected confirmation/loss/timeout; full-first/partial/zero/EAGAIN/EINTR/fatal-first writes; cancellation preserving cursors; and two immutable envelopes before another pending setter can be admitted.

Known boundaries remain explicit:

- Repeated C zero/EAGAIN/EINTR calls at offset zero invoke `MQ_impl_send_in_flight` repeatedly, but its sent callback runs once. Rust's one started flag is compared through observable admission/state, not fabricated identical internal function counts.
- Full first write goes directly to continuation. Fatal first EPIPE reaches the error handler without marking in-flight. Original C owner and Rust driver both discard the admitted first setter, preserve the second pending setter and avoid replay. Rust's extra destruction accounting honestly reports pending discarded=1, unconfirmed=1, persistent unconfirmed=1.
- Both admitted absolute destroy deadlines saturate to FOREVER. The C component also emits its nonfatal diagnostic; Rust does not duplicate that internal logging. The comparator checks the resulting target. The Rust test verifies that FOREVER does not expire even at MAX and that the original GET drains before the confirmation barrier. Confirmation enters a separate ready cleanup task; it does not immediately close the owner, and a later clock rollback cannot delay that already-ready finalizer.
- Processing confirmation is not disk durability. These components do not claim kernel EAGAIN/EINTR, daemon confirmation, normal Resolver MQ/DNS callbacks through the Unix-only port test, optional heap-statistics injection, or full service/runtime/CLI coverage.

No receipt is copied into the package as fresh evidence.

Maintenance boundaries: the generated `handle.rs` prefix and copied lifetime document remain byte-identical to current production inputs. The `ports.rs` facade delegates `EndpointSource`, endpoint snapshots and the retained attempt to `gnunet-client-host`; `connection.rs` delegates native I/O to service-runtime and supplies a scripted variant only under test. These aliases are tool bindings and supply no extra protocol credit. The adapter contains only bindings to public native ports; it does not copy CLIENT endpoint selection, retry, DNS, STATISTICS, or scheduler transitions. The recorded before-failures of obsolete mock interfaces and old immediate-close/Overflow/zero-retired-storage expectations are historical tool failures, not regressions repaired by changing production clock behavior. A successful Rust-only receipt replaces neither the C component receipt nor normal-C daemon/public-client clock coverage.
