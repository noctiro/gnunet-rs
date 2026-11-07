# Actual official C reference programs

This directory builds and runs the **unmodified GNUnet v0.29.1 STATISTICS
daemon and CLI**, using their normal util/statistics shared libraries. The exact
release commit is `346358e26d4dcc2dc4f51bef5d52dca29c7d8165`; the official
handbook gitlink is `cede13d10fb1ca0c1b33d8ed8a21507eda41d03b`.

These are external reference test artifacts. Production Rust never loads them
through FFI. The source/build tree, dependency prefix and runtime directories
are isolated. The harness starts no ARM supervisor, communicators, bootstrap or
public GNUnet network. It tests the STATISTICS boundary, not a complete peer.
Child processes discard inherited GNUNET activation/configuration overrides and
use private XDG directories. The user's HOME and environment are unchanged.

## Build prerequisites

Linux needs a C compiler, Make, Git, Python with venv, curl, pkg-config, gettext,
and development packages for ltdl, unistring, sqlite3, curl, gcrypt, GMP, GnuTLS
and IDN2. The CI job in `.github/workflows/quality.yml` lists its apt packages
and retains the package versions. The hosted reference jobs use Linux.

On macOS the matching libraries already available through Homebrew can be used
without modifying their installation. The reference builder prepares the following fixed libraries in a private prefix:

| Source | Version | Archive SHA256 |
| --- | --- | --- |
| [libsodium](https://download.libsodium.org/libsodium/releases/libsodium-1.0.22.tar.gz) | 1.0.22 | `adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349` |
| [Jansson](https://github.com/akheron/jansson/releases/download/v2.15.1/jansson-2.15.1.tar.gz) | 2.15.1 | `0c7114dc0b2d22a670724a1f95922029d7077c19dbf79a584cb8084d2f267f2f` |
| [libmicrohttpd](https://ftp.gnu.org/gnu/libmicrohttpd/libmicrohttpd-1.0.10.tar.gz) | 1.0.10 | `04bfe8ef75db7d629a33de767599765cecadc56274a39822d5d081030d577685` |

`bootstrap_dependencies.py` downloads those exact archives, checks their hashes,
and configures/compiles/installs them only under its new output directory. It
also creates a local venv with Meson 1.9.1 and Ninja 1.13.0. It never invokes
`brew install`, sudo or a global Python install. Its receipt retains actual
commands, exits and hashed logs. macOS configure probes require normal read
access to `sysctl`; a restrictive sandbox can otherwise yield a broken libtool
command-length detection. Use the host's authorized compiler environment.

## Reproduce the build

Choose a new directory for every invocation. A build never resets an existing
checkout or replaces an earlier evidence tree.

```sh
gnunet_ref=$(mktemp -d "${TMPDIR:-/tmp}/gnunet-reference.XXXXXX")
python3 -B tools/reference/bootstrap_dependencies.py --output "$gnunet_ref/deps" --jobs 4
git clone --depth 1 --branch v0.29.1 https://git.gnunet.org/gnunet.git "$gnunet_ref/source"
git -C "$gnunet_ref/source" -c url.https://git.gnunet.org/.insteadOf=git://git.gnunet.org/ submodule update --init --recursive
python3 -B tools/reference/build_reference.py --source "$gnunet_ref/source" --output "$gnunet_ref/build-evidence" --prefix "$gnunet_ref/prefix" --deps-prefix "$gnunet_ref/deps/prefix" --meson "$gnunet_ref/deps/venv/bin/meson" --ninja "$gnunet_ref/deps/venv/bin/ninja" --jobs 4
```

With Homebrew's default arm64 layout, the final build command additionally uses
the existing headers and libraries through:

```sh
CPPFLAGS='-I/opt/homebrew/include -I/opt/homebrew/opt/libunistring/include -I/opt/homebrew/opt/libtool/include' \
LDFLAGS='-L/opt/homebrew/lib -L/opt/homebrew/opt/libunistring/lib -L/opt/homebrew/opt/libtool/lib' \
python3 -B tools/reference/build_reference.py --source "$gnunet_ref/source" --output "$gnunet_ref/build-evidence-macos" --prefix "$gnunet_ref/prefix-macos" --deps-prefix "$gnunet_ref/deps/prefix" --meson "$gnunet_ref/deps/venv/bin/meson" --ninja "$gnunet_ref/deps/venv/bin/ninja" --jobs 4
```

The build selects `gnunet-statistics` and `gnunet-service-statistics` in the
unchanged Meson graph. Their normal upstream library dependencies are built;
no shim, patched handler, stub scheduler or substitute configuration engine is
used. Staging copies executables/libraries and generated defaults without
rewriting their bytes. The receipt binds the release/tag, all 2,193 tracked
inputs (including the official gitlink identity), clean source state, builder,
tool-version logs, compile commands, generated config and output binary hashes.

## Run programs in both directions

```sh
GNUNET_REFERENCE_SOURCE="$gnunet_ref/source" \
GNUNET_REFERENCE_BUILD="$gnunet_ref/build-evidence/build-result.json" \
cargo xtask verify daemon-reference
```

The explicit group builds both Rust executables and runs
`statistics_daemons.py`. It is separate from the smaller component oracle group
`cargo xtask verify reference`. To invoke the process harness directly:

```sh
python3 -B tools/reference/statistics_daemons.py \
  --reference "$gnunet_ref/build-evidence/build-result.json" \
  --rust-client target/debug/gnunet-cli \
  --rust-service target/debug/gnunet-service-statistics \
  --output target/reference-daemons/new-run
```

For the first normal Unix GET/SET, C WATCH and graceful persistence-restart
profile, add `--normal-only` to the direct harness command. It explicitly skips
malformed/partial-EOF and unknown-type diagnostics, and records that selection.
Omitting the option retains the broader existing diagnostic profile.

The harness rechecks the receipt-bound official executables, shared libraries
and default configurations after the run as well as before it. A change makes
the input-stability observation fail.

The harness snapshots and hashes all four participant executables. It uses the
build receipt's loader/default-configuration environment and verifies reference
libraries/defaults before running. Complete official tracked-source/clean-state
binding remains in the C build receipt and is rechecked before and after the run.
Exact Rust source/spec fingerprints use a hash-only helper with the original
input set and algorithm; no component oracle runner/catalog is imported or run.
These file reads do not execute tests. Binaries are compared again afterward;
concurrent source changes fail the run. The harness records Rust executable
hashes and source stability, but a separate fresh normal Rust build receipt is
needed to establish which source produced those executables.

Observed cases include Rust SET/GET against the C daemon, the C
CLI SET/GET/WATCH against Rust, relative updates received by C WATCH, independent
official SET dump validation, and both services' graceful persistent restart.
Transient values must disappear after restart and persistent values must retain
their value/flag. Each persistent dump is then loaded by the other
implementation and queried through both clients. Invalid framing and partial EOF must close the bad session
while an independent healthy client still succeeds. Rust readiness requires the
normal SERVICE's flushed initialized `READY statistics` line from the exact
owned foreground child and a successful probe of its private Unix socket.
Services start with ordinary `-c ... -L ERROR` arguments. SIGTERM must produce
an zero exit, persisted data, and socket cleanup; no private ready or
shutdown files are used. Rust GET requires the numeric value, textual
and raw-byte selectors, requested persistence flag and exact END/count.

Each process has its own session/process group and retained stdout/stderr.
Timeouts and nonzero exits do not become success. The C watch runs with an actual
PTY so its normal stdio buffering does not require changing the C program.
Acceptance counts come from executed observations, not fixed success text. The
known unknown-type observations and their intentionally killed C diagnostic
process have separate `diagnostics` command/check/probe arrays; they cannot
inflate the passing acceptance counts. Cleanup signals
and reaps only owned children, including an interrupted one-shot CLI, and removes
only the private runtime directory. Timeout kills cannot become successful
normal-service exits; intentional C diagnostic kills remain separate.

The harness main installs a SIGTERM handler that raises `InterruptedError`;
normal SIGINT raises `KeyboardInterrupt`. Only during launch through ownership
registration (or local launch-failure cleanup), these already-handled signals
are deferred and then propagated after restoring their original handlers.
No blocked signal mask is inherited by the exec child. An embedded caller's
default/ignored signal dispositions are unchanged; default SIGTERM, SIGKILL and
host failure cannot promise Python cleanup. This is distinct from ordinary
SIGTERM sent to an owned service for its graceful shutdown.

Cleanup attempts every owned child and each PTY/log/hash independently. Its
errors remain separate from the original operation/interruption failure, and
any cleanup error makes the report fail. Runtime-directory removal and report
writing are still attempted; a report-write failure is emitted in the terminal
summary. Actual reaping/removal fields are observations, not guarantees.

## Explicit reference differences

The pinned C source has two relevant inconsistencies; the report retains them:

- In `mq.c`, `GNUNET_MQ_inject_message` handles a malformed-message `SYSERR` but
  does not handle the unmatched-handler `NO` result. An unknown type can leave
  `service_client_mst_cb`'s `needs_continue` set, pause that client and prevent
  soft shutdown. A separate diagnostic C instance observes both timeouts and is
  explicitly killed/reaped. The normal persistence instances still must exit
  zero. Rust promptly closes unsupported requests. This difference cannot earn
  full-conformance credit by treating the C timeout as a fictitious close event.
- The C server emits WATCH persistence in flags bit 2, while the C client tests
  VALUE UID's high bit. The Rust server emits the official server format.
  Numeric C watch values are checked; that test does not erase the client's
  persistence interpretation discrepancy.

On the tested macOS version, the C programs also emit a retained
`socket_set_nosigpipe` diagnostic from `network.c` for a platform socket probe.
The selected Unix operations and normal service shutdown still execute and exit
zero. Nonempty reference stderr is retained and catalogued in
`reference_diagnostics`; it is not silently dropped or called a clean log.

A passing report establishes only the listed IPC/restart observations.
It does not prove crash consistency, every STATISTICS API/failure mode, service
activation, TCP/remote ACL behavior, an entire GNUnet daemon or P2P interoperability.
The repository's strict capability gate remains authoritative and incomplete.

## Service listener profile

`statistics_runtime.py` compares the normal official C client against each
normal C and Rust service over private Unix and loopback TCP listeners. The private profile explicitly selects `UNIX_MATCH_UID = YES` and
`UNIX_MATCH_GID = NO`, retaining the exact `0700` socket assertion and recording
the mode. It also covers numeric inherited listeners, TCP ACL denial with Unix admission retained,
XDG configuration discovery, official long Unix-path shortening and an actual
restart without a DATABASE. This is a separate runtime scope from the first
normal Unix/persistence run; preparing the helper does not execute that scope.

The helper uses ordinary `-c ... -L ERROR` arguments (or no `-c` for discovery)
and the flushed Rust READY line, selecting `memory-only` only when the
DATABASE is absent. Full shared source/spec fingerprints and the fixed C build
receipt, libraries/defaults and participants are checked before and after.
A separate current normal Rust build receipt must bind the selected service.
Each acquired parent socket and duplicated numeric FD is owned before its next
fallible operation; their closes, child reaping, runtime removal and report
writing are attempted independently and retain original failures. An unavailable
IPv6 capability is recorded as a skipped profile with its errno/reason;
other acquisition failures fail the run.

With that separate runtime scope authorized and a current normal build bound:

```sh
python3 -B tools/reference/statistics_runtime.py \
  --reference /private/tmp/C-build/build-result.json \
  --rust-service /private/tmp/Rust-build/gnunet-service-statistics \
  --output /private/tmp/new-statistics-listener-evidence
```

The result applies only to its executed C-client/service listener observations.
It does not establish default/shared-UID-GID socket permissions, Rust WATCH, C public relative updates, ARM process
activation/reconnect, malformed-message recovery, full STATISTICS, peer
interoperability or measured resource/performance behavior. Reference stderr is
retained; unavailable IPv6 profiles cannot be reported as passing observations.

## Harness-boundary tests

```sh
python3 -B tools/reference/test_reference_tools.py
```

These isolated tests cover invalid/empty dumps, nonzero/timeout reporting,
owned-child cleanup and exact observed watch output. They are unit tests of the
harness and do not count as official C interoperability evidence.

The [DNS packet proof](DNS_PACKET.md) rebuilds the normal C observer and checks
its wire/field projections against current Rust. Full native IDNA remains
explicitly pending. The [STATISTICS clock/MQ/write proof](statistics-clock/README.md)
runs complete original C functions and the unchanged Rust driver through finite
host capabilities; its five comparator rejection controls are in the default
local verification matrix. A fresh component receipt complements normal
C/Rust socket and daemon tests and grants no whole-service status by itself.
