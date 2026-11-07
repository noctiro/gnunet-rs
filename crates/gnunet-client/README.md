# Official STATISTICS clients

The low-level `statistics` module provides checked official message codecs,
GET sessions and connection-local WATCH ownership. The `statistics_handle`
module adds the long-lived queued service handle corresponding to the eight
public operations in GNUnet v0.29.1 `gnunet_statistics_service.h`.

The core is `no_std`, forbids unsafe code and performs no allocation or I/O. `StatisticsHandle<A, N, W, WW, T>` bounds action slots, owned name bytes, live
logical watches, lifetime wire WIDs in one connection, and original GET lifetime
reservations. The creating subsystem is owned; GET/WATCH selectors are copied. Only the host adapter resolves configuration, supplies time and drives sockets.

`new(subsystem, enabled)` is lazy and returns None for disabled statistics. `set` and `update` report Queued/Coalesced/Noop, never remote execution. Pending
setters with identical case-sensitive names coalesce across intervening GETs. Absolute sets replace; signed updates add with unsigned wrapping or clamp an
absolute value at zero. Latest persistence wins. Calling update(0) is a no-op;
nonzero updates that merge to zero still produce a relative SET. The pinned C
source stores a two-second setter timeout but never enforces it, so this owner
has no invented automatic setter expiry.

`get` returns a generational local ID. Cancelling a queued request removes it;
cancelling a current request suppresses callbacks while retaining its original
stream tombstone until END. Iterator Abort suppresses later rows but still
allows the successful END continuation. A disconnect after iterator Abort
suppresses that continuation, as in C. `GetCompletion` capacity is reserved at
admission, so END or failure cannot silently lose ownership. The host must
consume completions; cancellation and interrupted aborted iterations do not
manufacture one. `owns_get` and `get_callbacks_enabled` distinguish retained
stream state from callback authority.

`watch` returns a stable logical subscription ID. Canceled queued registration
copies can still consume a connection WID, but those WIDs map to tombstones. A new virtual connection discards stale queued registration copies and appends
live subscriptions in original registration order after pending non-watch
work. Fresh wire WIDs map to logical IDs independently of cancelled holes or
reused slots. Names for watch callbacks come from original registration via
`watch_selector`, not from untrusted notification bytes. WATCH_VALUE's raw flags
and reserved field remain available; persistence follows the service's bit 2.

The host boundary owns at most two immutable envelopes. `next_request` encodes
and admits only after the host preflights its buffer/queue. A first partial or
EAGAIN send attempt marks the front envelope irreversible; a complete first
write can call `on_frame_written` directly. These events are distinct from
remote execution. Initial socket connection retries retain the same virtual MQ,
current GET and encoded envelopes. A failed established connection retires its
epoch, fails a non-aborted current GET, retains pending actions and backs off
from 1 ms to 15 minutes. Only a current exact END resets the owner backoff. Stale epoch/transmit completions cannot affect a replacement connection.

No admitted setter is automatically replayed. Confirmation on a later epoch
cannot acknowledge mutations from an earlier lost epoch. `DestroyReport`
retains those historical unconfirmed counts even when the current connection's
barrier was processed successfully.

`begin_destroy(sync_first, now)` follows the C API's MQ-queue condition. If it cannot defer, it reports Discarded and accounts for pending/unconfirmed
work. Deferred destruction drops queued GET/WATCH requests, drains setters and
any current GET, sends DISCONNECT and waits for the exact confirmation. Its
original deadline is five times the current owner backoff. Late or premature
confirmation, connection loss and timeout cannot produce success. A processing
confirmation does not establish disk durability. `tick` and every host
I/O poll must use that same original deadline.

The source C API has known discrepancies: WATCH persistence tests the wrong bit;
watch cancellation holes can misroute freshly compacted reconnect WIDs; signed
negation of INT64_MIN is undefined. The Rust owner preserves official
frames and intended logical ownership without copying memory/identity bugs. The per-connection WID correction and premature/late confirmation rejection are
explicitly documented behavioral safety differences, not a private protocol.

Tests cover callbacks/cancellation, stream tombstones, coalescing, wrapping,
logical/wire watch IDs, reconnect capacity reservation, terminal capacity,
zero/partial/full MQ writes, generation/epoch exhaustion, backoff, destruction
and historical mutation ambiguity. The deterministic C oracle executes original
create/set/update/get/get_cancel/queue code with a controlled busy MQ seam under
two compiler profiles. Its 17 rows are compared with a Rust owner trace. That evidence covers pending-action behavior; it does not certify all callback,
watch, reconnect or complete daemon cases. Normal C library/service tests belong
to the host interoperability harness and the complete API capability ledger.

```sh
cargo test -p gnunet-client --locked
cargo clippy -p gnunet-client --all-targets --locked -- -D warnings
cargo check -p gnunet-client --target thumbv6m-none-eabi --locked
python3 crates/gnunet-client/tests/handle_c_oracle.py --source /path/to/pinned/gnunet --output /new/evidence/directory
```
