# Testing

## Verification commands

Run from the repository root using the pinned Rust toolchain.

| Command | Scope |
| --- | --- |
| `cargo test -p PACKAGE --locked` | Affected package |
| `cargo xtask verify source` | Formatting, dependency and feature boundaries, lint policy and recorded external status |
| `cargo xtask verify native` | Portable feature tiers, isolated production builds, native Clippy, rustdoc and workspace tests |
| `cargo xtask verify format` | Workspace and embedded-fixture formatting |
| `cargo xtask verify lint` | Native Clippy and rustdoc |
| `cargo xtask verify tools` | Python syntax and tool controls |
| `cargo xtask verify profiles` | Independent production adapter, service, SDK and CLI feature selections |
| `cargo xtask verify portable` | Core feature profiles and facade allocation tiers |
| `cargo xtask verify runtime` | Focused IPC, service, storage, startup and recovery scenarios |
| `cargo xtask verify test` | Native workspace with all features |
| `cargo xtask verify embedded` | Cortex-M0, Cortex-M4 and RV32IMAC compilation and no-allocation checks |

`cargo xtask verify` runs the source, tool, native and embedded checks.
Workspace tests include the focused runtime tests. External C comparisons
require explicit invocation. Prefer the affected package or group during local
development.

Portable checks run core packages without default features and with all core
features, then check the facade with no features, `alloc` and `std`. Native
adapters stay outside those selections. Production profiles use separate Cargo
invocations, so development dependencies and other workspace packages cannot
supply a missing feature.

Native tests use private files and local or loopback sockets. Keep local socket
paths short; on macOS, use `TMPDIR=/private/tmp`. Platform-specific filesystem,
process, credential and device tests supplement the shared scenarios.

## Logs and failure results

Add `--log-dir PATH` to any verification group:

```sh
cargo xtask verify native --log-dir target/ci/native
```

Each run creates a separate directory containing an incremental `result.json`
and per-command stdout/stderr logs. Output also streams to the console with
fixed-size buffers. A command or policy failure stops that group and records its
original cause; an independent reporting failure cannot turn it into success.
An interrupted run can leave a `running` result, which is not a passing result.

Generated logs, C build receipts and performance results belong under `target/`.
Do not commit them.

## Continuous integration

[Quality checks](../.github/workflows/quality.yml) run on pull requests, merge
groups, pushes to `main`, version tags and manual dispatch.

| Target | Contract |
| --- | --- |
| Linux x86_64 / ARM64 | `verify native` |
| macOS Intel / ARM64 | `verify native` |
| Windows x86_64 / ARM64 | `verify native` |
| FreeBSD 14.5 / 15.1 x86_64 | The same native contract, plus Python controls, as an unprivileged VM user |
| Cortex-M0 / Cortex-M4 / RV32IMAC | Embedded compilation and no-allocation checks |
| Android, iOS and OpenHarmony standard | Isolated Rust SDK cross-compilation checks for the documented application ABIs |

Source policies run once before native and reference jobs. The native matrix
keeps `fail-fast: false`, so one platform failure does not cancel the others.
Failures upload diagnostic files. FreeBSD builds in a VM-private checkout and
returns logs and its actual exit status separately from the VM transfer result.

The fixed `ci-complete` job runs after every required job, including the C
references and security checks. It succeeds only when all required jobs succeed;
failed, canceled or skipped jobs cannot satisfy it. Select this check in the
repository's branch protection or ruleset when requiring CI before merge.

The [shared Rust setup](../tools/ci/setup-rust.sh) lets `rustup` read
`rust-toolchain.toml`, then verifies the expected compiler host and required
tools. It runs on disposable CI hosts and requires no Python. CI caches
downloaded Cargo inputs rather than compiled output.

[Security checks](../.github/workflows/security.yml) run from quality CI and on
a separate daily schedule. They scan Git history and audit every tracked Cargo
lockfile against the recorded RustSec database revision.
[Dependabot](../.github/dependabot.yml) proposes grouped weekly Action updates
while retaining full commit pins.

## Python controls and reference tooling

Rust build and verification contracts belong to `xtask`. Python tools own
independent C builds, reference-program orchestration, corpus and evidence
processing, and their own controls. Production package checks use the actual
Rust workspace; separate component probes retain their explicitly narrower scope.

```sh
python3 -B tools/check_tools.py --list
cargo xtask verify tools
```

Use Python 3.11 or newer with assertions enabled. The runner checks source syntax
and discovers conventional test scripts and explicit self-test entry points.
Suites run in separate processes with a 120-second timeout; failures are
collected under `target/tool-controls/`. These controls need no official C
checkout or running services.

## Official C comparisons

The component group uses two clean, independently pinned GNUnet checkouts.
`GNUNET_REFERENCE_SOURCE` supplies v0.29.1, commit
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`, for protocol and STATISTICS
comparisons. `GNUNET_CONFIG_REFERENCE_SOURCE` supplies commit
`7e0f9c3640310fd406fcf32c271ab583ef83d6c9` for the configuration component.
Each oracle checks its own revision; neither source substitutes for the other.

```sh
GNUNET_REFERENCE_SOURCE=/path/to/gnunet-0.29.1 \
GNUNET_CONFIG_REFERENCE_SOURCE=/path/to/pinned/configuration-source \
cargo xtask verify reference
```

This compares selected framing, crypto/data-format, configuration and STATISTICS
boundaries. Normal C client/service execution continues to use only the
v0.29.1 source and its matching build receipt. Prepare the C build using the
[reference guide](../tools/reference/README.md), then run:

```sh
GNUNET_REFERENCE_SOURCE=/path/to/pinned/gnunet \
GNUNET_REFERENCE_BUILD=/path/to/build-result.json \
cargo xtask verify daemon-reference
```

The daemon group runs C client→Rust service and Rust client→C service, including
absolute SET and selector GET through the standalone Rust `gnunet-statistics`,
WATCH, persistence and selected restart/failure cases. Results identify their
actual source, binary and reference inputs.

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
| Conversation | [Controller](../tools/reference/CONVERSATION.md) |

Public-network, privileged/device, audio and benchmark profiles require their
own setup. Cross-compilation needs target standard libraries and a suitable
linker; native C dependencies can also need target-specific compiler settings.
Run tests on the target platform.

Release acceptance follows the [external release criteria](../spec/gnunet/external/RELEASE.md)
and `cargo xtask check-conformance --strict`. Known product gaps are tracked in
[implementation status](../IMPLEMENTATION_STATUS.md).
