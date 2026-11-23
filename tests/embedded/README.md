# Embedded compilation checks

The standalone `noalloc` library exercises GNUnet protocols with caller-owned
storage, including STATISTICS framing, GNS record cryptography, signed HELLOs,
resolver requests, the CORE handshake's first flight, and MESSENGER room
hosting with signed JOIN admission and checkpoint preparation and recovery.

## Build checks

The embedded verification task compiles the `gnunet` facade and the standalone
fixture on Cortex-M0, Cortex-M4 and RV32IMAC. The dependency guard checks the
fixture's target dependency graph for allocator and host-runtime features.

```sh
rustup target add thumbv6m-none-eabi thumbv7em-none-eabi riscv32imac-unknown-none-elf
cargo xtask check-noalloc
cargo xtask verify embedded
```
