# GNUnet CORE CLI

`gnunet-core` displays connected-peer and key-exchange state from the configured
CORE service. Linux, macOS, Windows and FreeBSD share the same monitor client,
command phases, logging and output. Native startup capture and stop subscriptions
remain outside the protocol state machine.

## Build and use

```sh
cargo build --locked -p gnunet-core-cli
target/debug/gnunet-core -c /path/to/owned.conf -s
target/debug/gnunet-core -c /path/to/owned.conf -m
```

Use `gnunet-core.exe` on Windows. `-s` prints the initial snapshot and exits only
after its official end marker. `-m`, including `-s -m`, continues monitoring.
`--help` lists PROGRAM options. Ordinary PROGRAM configuration, `-L/-l` logging,
Resolver selection and the shared clock apply.

## Configuration and output

`[core]` selects the normal CLIENT local/TCP endpoint. `[resolver]` supplies the
shared Resolver when TCP hostname lookup is required. Rows contain UTC logical
time, peer abbreviation, numeric state and remaining timeout. Unknown numeric
states remain visible. A successful local request write is not snapshot completion;
EOF without the end marker fails snapshot mode.

`[core-cli-rust]` bounds local work and resources:

| Key | Default |
| --- | --- |
| `LIFETIME` | 30 seconds for snapshot; 8 hours for monitor |
| `SNAPSHOT_TIMEOUT` | 30 seconds |
| `FRAME_TIMEOUT` | 10 seconds |
| `MAX_ROWS` | 1,000,000 |
| `MAX_RECONNECTS` | 1,024 |
| `FRAME_BYTES` | 256 |
| `IO_SLICE_BYTES` | 65,535 |

Durations must be finite and nonzero. Frame storage is at least 56 bytes and no
more than the official u16 frame width. Native hard targets are captured once;
clock rollback, partial reads and retry do not renew an original bound.

## Module and resource ownership

`main.rs` selects PROGRAM configuration and diagnostics. `foreground.rs` drives
CORE and Resolver; `bounds.rs`, `settings.rs`, `reporting.rs` and `output.rs` own
their respective command policies. `early.rs` calls shared
[`ClientStartup`](../../adapters/service-startup/README.md#client-program-startup)
before competing native resources. `control.rs` uses the same client stop adapter,
including Windows console notifications and original parent control.

The command runs as its invoking process identity. The daemon's `USERNAME`
configuration does not change the client token. A client owns no listening-service
readiness endpoint and refuses inherited listeners. Every shutdown path closes
its CORE monitor and independently disconnects Resolver. Cleanup and final output
errors remain observable; EOF on parent control does not fabricate a stop signal.
Synchronous OS stdout/calendar calls are not forcibly interrupted by network
bounds.

## Native tests

[Normal-process tests](tests/normal_process.rs) execute the built command against
private TCP peers with literal official monitor frames. They cover fragmented
rows, future state values, genuine end markers, EOF failure and original socket
retirement. The same cases run on native CI platforms. These fixtures are Rust
process/transport regressions; C interoperability receipts remain separate.
