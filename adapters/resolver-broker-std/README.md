# Shared Resolver broker

This package owns one process Resolver domain using official Resolver IPC.
`Context` clones share bounded requests, IDs, configuration, backoff and MQ state;
one caller-driven `Driver` owns physical I/O. PROGRAM can supply the selected
configuration and clock to all CLIENT, ARM and STATISTICS consumers.

## Public interfaces

`broker` returns the shared `Context` and its unique `Driver`. Construction creates
no socket, task or runtime. The caller drives that owner alongside client hosts.
A callback `Delivery` borrows its original query until return. `Query` and native
CLIENT resolution subscriptions preserve original cancellation authority.

```rust
use gnunet_resolver_broker::{broker, native_profile, Limits, LiveConfiguration, SystemClock};
use std::sync::Arc;

// `configuration` belongs to the embedding program.
let (context, driver) = broker::<32, 4096>(
    LiveConfiguration::new(configuration),
    Limits::default(),
    native_profile()?,
    Arc::new(SystemClock),
)?;
```

Pass `context.resolution_context()` to configured client constructors and retain
the returned driver. See [design and contracts](DESIGN.md) for FIFO, timeout,
configuration sampling and callback ownership.

## Configuration and lifetime

`[resolver]` selects native local IPC through `UNIXPATH` or a directly addressable
TCP `HOSTNAME`/`PORT`. Resolver endpoint selection cannot recursively depend on
that same Resolver. Direct local-only CLIENT constructors need no DNS domain.
The broker does not substitute system DNS when a required Resolver fails.

Successful CLIENT TCP establishment retains its DNS drain lease until original
END/timeout or connection destruction. Cancellation does not replay requests or
retarget an already admitted connection. Live configuration, queued requests and
original retry targets retain their distinct sampling points. Limits charge all
owned names, frames and slots, including reserved internal lookup capacity.

## Native verification

Resolver stream, retry, clock and multi-host suites use real native local/TCP
peers. [Local fixture ownership](tests/support/local.rs) pairs each native listener
with its original path guard; [private roots](tests/support/directory.rs) are shared
across suites. The same stream contracts compile on Windows and Unix systems.
Error-retention cases compare against a real failed native connection, preserving
both its error class and OS code across retry/clock failures.

```sh
cargo test --locked -p gnunet-resolver-broker --all-features
```

## Reference verifier

`tools/verify.py` copies the complete workspace and validates package roles,
settings, locks and declared witnesses before executing comparisons against the
supplied normal C builds. Use `--help` for required build inputs. Output must be
new and disjoint from the repository and reference trees.

`--preflight` checks preparation and tool controls without compiling or running
Rust/C participants. Full mode records literal-peer, extracted-component and
normal-daemon observations separately. `--profile` selects its explicit witness
inventory; a missing or changed witness fails validation. The integrated workspace
needs no overlay. Generated receipts and transcripts belong under `target/`.
