# Shared Resolver broker

This package implements one caller-owned process Resolver domain. It
uses official type4/type5 messages and contains no production GNUnet FFI or
system-DNS fallback. `Context` clones share one queue, IDs, backoff, selected
configuration and MQ; one `Driver` owns I/O. PROGRAM supplies an explicit
clock and selects configuration before main. A callback `Delivery` borrows its
query until return. Successful CLIENT TCP connections retain a DNS drain lease
until END/timeout or connection destruction.

The current source-based design is in `DESIGN.md`, the complete seven-function
Resolver public inventory and remaining acceptance scope in `inventory.json`,
and the concrete constructor migration in `INTEGRATION.json`. The workspace replaces configured CLIENT, ARM, monitor and STATISTICS
constructors with a required shared context. Direct Unix-only constructors need
no Resolver. The caller must drive the returned unique owner alongside its host
reactors; production spawns no hidden task. Full PROGRAM composition is a
separate developing component.

The independent verifier accepts existing immutable normal C build receipts and
rebuilds only its small public callers/component in the output directory. It
runs exact nonempty named Rust tests, strict package lints, no_std embedded
compilation, both lifetime UI cases (negative must emit E0505), owned literal
peer pairs, a generic CLIENT TCP/DNS lifetime pair, a selected-config readpoint
pair, a normal C Resolver daemon local-hosts pair, and a public ARM/STATISTICS
two-service pair using one explicitly verified normal util image. The daemon and
non-TCP actors have IP output denied; the TCP lifecycle peer binds only its own
127.0.0.1 socket. No /etc file is modified; local hosts evidence is refused when
the explicit broadcasthost fixture is absent. The original daemon PID is reaped. The exact reconnect-body component has observer-only scheduler shims. The
numeric CLIENT component executes original numeric and address callback bodies
with normal util sockets and a owned loopback accept; it records the
5s write registration without executing a fabricated completion callback. Neither component claims full scheduler/daemon integration. Internal CLIENT
returns its address callback only after the native connect starts, then
continues only that original local callback stack to NULL/free. Public callback
leases retain their explicit Driver return boundary.

Declared R/N, immutable MQ credits and address-probe limits are resource bounds,
not official config keys. Capacity/OS errors remain visible rather than becoming
synthetic DNS success or timeout. A successful TCP probe keeps its original DNS
subscription until END/timeout or connection destruction.

Run from this package with fixed parameters and an output directory disjoint
from the package, repository, upstream and old build receipts:

```sh
python3 -B tools/verify.py --repo /absolute/repository \
  --upstream /absolute/pinned/gnunet \
  --normal-receipt /absolute/arm-normal/build-result.json \
  --normal-statistics-receipt /absolute/statistics-normal/build-result.json \
  --normal-resolver-base /absolute/resolver-normal/build-result.json \
  --normal-resolver-receipt /absolute/resolver-normal/resolver-build-result.json \
  --reference-helper /absolute/repository/tools/reference/build_reference.py \
  --output /absolute/new-proof
```

The verifier uses pinned Cargo1.99.1, offline locked metadata/builds, jobs2 and an
output-local target. It snapshots every reachable local package's sources,
fixtures, tests/tools/docs/manifests plus repository settings and lock before
and after. Normal C source, receipt libraries/configs and actor binaries
are checked before and after execution. Historical trial receipts certify only
their original recorded source/tool/binary snapshots. A new source edit requires
a fresh receipt; an old passed count is never promoted to the current owner.
