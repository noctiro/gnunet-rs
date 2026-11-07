# Official STATISTICS service core

Baseline: GNUnet v0.29.1, commit
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`. The authoritative implementation
is `src/service/statistics/gnunet-service-statistics.c`; IPC structures are in
`statistics.h`. This crate implements their business state with explicit finite
capacities, without allocation, unsafe code, sockets or filesystem I/O.

`Statistics<ROWS, NAME_BYTES, CLIENTS, WATCHES, EVENTS>` admits private generational
connection handles. Names are opaque bytes separated by NUL on the wire;
`NAME_BYTES` includes both terminators. A row stores global value, UID,
persistence and whether an explicit value was established. Rows survive client
disconnection. Resource refusal occurs before changing any row, UID, watch ID,
ordering, watch notification state or queued effect.

SET uses unsigned absolute values and signed two's-complement relative deltas.
Negative deltas saturate at zero. Positive overflow triggers a C diagnostic but
still wraps; `SetOutcome::positive_overflow` exposes that diagnostic. A newly
created row with a nonpositive relative delta remains unset. A subsequent SET,
including zero, marks it set. Every SET replaces persistence, ignoring unknown
flag bits, and moves its row to the front of its subsystem's list.

GET's empty subsystem/name are independent wildcards. It returns unset rows too,
in the C implementation's newest-subsystem-first and current row-list order,
then exactly one END. The iterator borrows the state; a host transport must
finish or abandon enumeration before the next mutation. WATCH uses exact names,
including empty names, and connection-local IDs starting at zero. Duplicate
watches are separate subscriptions. Nonzero values notify immediately; zero
values do not. The first SET of an unset watched row notifies even for zero.
Subsequent equal values are suppressed independently for each subscription.
Changing only persistence produces no notification.

Queued notifications retain every admitted intermediate value and persistence
flag. The transport peeks, encodes and admits an effect before consuming it.
A full effect queue rejects the originating SET/WATCH atomically. Disconnect
removes only that generation's subscriptions and queued effects; generation
exhaustion retires a connection slot. UID admission stops before its reserved
persistence bit; WID and ordering exhaustion are also explicit rejections.
These are resource policies rather than new protocol fields.

The protocol DISCONNECT request is a processing barrier. The pinned handler only
sends DISCONNECT_CONFIRM; it does not itself close the socket or save to disk.
Real EOF/cancellation invokes the separate owner cleanup operation. Durability
must not be inferred from the confirmation.

Persistence enumeration yields the official absolute SET records with flags 2,
concatenated without any private header. `restore` imports one canonical record
at a time when no clients are connected. It rejects noncanonical flags and foreign
message types, a deliberate narrower input contract than the C file injector.
The caller supplies file size limits, stream framing, storage and crash policy.
No successful disk write, fsync or crash recovery is fabricated by this core.

Two upstream details require care:

- `notify_change` sends WATCH_VALUE persistence in flags bit 2, while
  `statistics_api.c:handle_statistics_watch_value` tests the VALUE UID's high bit.
  This crate reproduces the server's flags 2; it does not copy the client
  interpretation error into the wire format.
- The C negative-delta comparison evaluates `-delta`, which has ISO C undefined
  behavior for `INT64_MIN`. Rust uses the defined unsigned magnitude. The oracle
  checks the pinned C under ordinary optimization and defined signed wrapping;
  both agree for this boundary on the tested compiler. This does not prove that
  the undefined C expression is portable to every compiler.

Tests include independent wire literals, exact framing, zero-watch behavior,
signed extrema, GET order/wildcards, owner cleanup and slot reuse, all declared
resource limits, notification backpressure, and canonical persistence records.
The separate C oracle extracts original, unmodified handler and container/string
bodies from the pinned checkout into a temporary program. Its shims replace
allocation, scheduling and message delivery; it is not a full C service daemon.
The original copyright/license notices accompany the temporary C source.

```sh
python3 crates/gnunet-statistics/tests/upstream_oracle.py --source /path/to/gnunet
cargo test --locked -p gnunet-statistics
cargo clippy --locked -p gnunet-statistics --all-targets
cargo check --locked -p gnunet-statistics --target thumbv6m-none-eabi
```

The oracle verifies the pinned revision and exact source hashes. Default mode
compares both executed C profiles with the checked-in 68-line trace; `--write`
explicitly regenerates it. The Rust integration test executes the same action
sequence and compares its response/state trace with that fixture. The
reference runner independently captures and compares all three traces and records
their commands, rows and hashes. None of these tests claims complete
GNUnet daemon, persistent storage or peer-network interoperability.
