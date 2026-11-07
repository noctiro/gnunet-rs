# Testing

## Local checks

Run from the repository root using the pinned Rust toolchain.

| Command | Scope |
| --- | --- |
| `cargo test -p PACKAGE --locked` | Affected package |
| `cargo xtask verify format` | Workspace and embedded-fixture formatting |
| `cargo xtask verify lint` | Dependency/feature boundaries, Clippy and rustdoc |
| `cargo xtask verify tools` | Python syntax and tool controls |
| `cargo xtask verify portable` | Core feature profiles and facade allocation tiers |
| `cargo xtask verify test` | Unix workspace with all features |
| `cargo xtask verify embedded` | Cortex-M0/M4 compilation and no-allocation closure |

`cargo xtask verify` runs all local groups above except the package-specific
command. External C groups require explicit invocation.

Native tests use private files and Unix/loopback sockets. Keep socket paths short,
for example `TMPDIR=/tmp cargo xtask verify test` on macOS.

The portable group selects core packages from the architecture inventory. It
runs without default features, then with all core features, and tests the facade
with no features, `alloc` and `std`. Native adapters stay outside these profiles.
Windows supports this group; native workspace and reference groups require Unix.

## Tool controls

```sh
python3 -B tools/check_tools.py --list
cargo xtask verify tools
```

The runner checks Python syntax and discovers `test_*.py`, `*_tests.py`,
`tests.py`, `selftest.py` and explicit self-test entry points. Suites run in
separate processes with a 120-second timeout. Failures are collected; logs go to
`target/tool-controls/`. These controls need no C checkout or running services.

## Continuous integration

[GitHub Actions](../.github/workflows/quality.yml) runs on pull requests, pushes
to `main`, version tags and manual dispatch.

| Platform | Tests |
| --- | --- |
| Linux x86_64 / ARM64 | Native workspace |
| macOS Intel / ARM64 | Native workspace |
| FreeBSD 14.5 / 15.1 x86_64 | Native workspace, portable core and tool controls in an unprivileged VM |
| Windows x86_64 / ARM64 | Portable core and facade allocation tiers |
| Cortex-M0 / M4 | Compilation and no-allocation closure |

Linux also runs architecture, lint/docs, isolated core feature profiles and C
comparisons. Python controls run on Linux and macOS. CI scans Git history for
credentials and checks all tracked Cargo lockfiles against RustSec.

The [Rust setup](../.github/actions/setup-rust/action.yml) reads
`rust-toolchain.toml` and verifies the native host. It caches downloaded Cargo
inputs; compiled output is not cached. Unix runtime jobs use `/tmp`.

## Official C comparisons

The component and STATISTICS groups pin GNUnet v0.29.1 and require a clean
reference checkout.

```sh
GNUNET_REFERENCE_SOURCE=/path/to/pinned/gnunet cargo xtask verify reference
```

This runs framing/registry, crypto/data-format, configuration and STATISTICS
component comparisons. For normal STATISTICS client/service execution, prepare
the C build using the [reference guide](../tools/reference/README.md), then run:

```sh
GNUNET_REFERENCE_SOURCE=/path/to/pinned/gnunet \
GNUNET_REFERENCE_BUILD=/path/to/build-result.json \
cargo xtask verify daemon-reference
```

The daemon group runs C client→Rust service and Rust client→C service, including
WATCH, persistence and selected failure/restart cases. Results go under `target/`.

## Specialized profiles

| Area | Guide or harness |
| --- | --- |
| STATISTICS listeners/activation | [Activation](../apps/gnunet-service-statistics/ACTIVATION.md), [listener runner](../tools/reference/statistics_runtime.py) |
| Configuration | [Reference contract](../adapters/config-std/UPSTREAM.md) |
| HELLO | [Reference profiles](../crates/gnunet-hello/UPSTREAM.md) |
| GNS cryptography | [Reference profile](../crates/gnunet-gnscrypto/UPSTREAM.md) |
| Session crypto | [Sources](../crates/gnunet-session-crypto/UPSTREAM.md), [HPKE](../crates/gnunet-session-crypto/HPKE.md), [GCM](../crates/gnunet-session-crypto/GCM.md) |
| Resolver | [Host tools](../adapters/resolver-std/tools/verify.py) |
| ARM | [Client tools](../adapters/arm-std/tools/verify.py), [service core](../crates/gnunet-arm-service-core/README.md) |
| Conversation | [Controller](../tools/reference/conversation-controller.README.md) |

Public-network, privileged/device, audio and benchmark profiles require their
own setup. For cross-compilation, select the target standard library and
`CARGO_TARGET_<TRIPLE>_LINKER`; C dependencies may also need target-specific
`CC_<triple>` and `AR_<triple>`. Execute tests on the target platform.

## Full conformance

```sh
cargo xtask check-conformance --strict
```

This enforces the [external release criteria](../spec/gnunet/external/RELEASE.md),
including reviewed contracts and current-source C interoperability evidence.
Missing or unknown behavior fails the gate. Open work is tracked in
[implementation status](../IMPLEMENTATION_STATUS.md).
