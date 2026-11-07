# Embedded compilation checks

The standalone `noalloc` library depends on the default official SDK. It uses
official STATISTICS framing, GNS record cryptography, hashing, peer purpose
signatures and signed HELLO formats without requesting `alloc`, `std`, IPC or a
runtime. It also instantiates the resolver FIFO, encodes its official request,
and cancels/releases that owner with caller storage. Native hostname and FQDN
helpers remain outside this dependency graph.

The default SDK also includes the pure CORE peer engine. The fixture constructs
its handshake owner with caller-provided entropy and encodes a first flight;
it performs no native I/O or synthetic peer establishment. This adds compile/feature
coverage, not a physical device or interoperability claim.

```sh
cargo xtask check-noalloc
cargo check --manifest-path tests/embedded/noalloc/Cargo.toml --target thumbv6m-none-eabi --locked
cargo check --manifest-path tests/embedded/noalloc/Cargo.toml --target thumbv7em-none-eabi --locked
```

The guard inspects the target dependency closure. These library checks
establish compilation and selected feature closure; they do not measure a
linked firmware's memory, timing or device behavior.
