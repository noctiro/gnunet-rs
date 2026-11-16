# Official C reference programs

These tools build and run isolated official GNUnet software for component and
interoperability comparisons. The baseline STATISTICS build uses unmodified
GNUnet v0.29.1 at `346358e26d4dcc2dc4f51bef5d52dca29c7d8165`.
Each specialized runner declares its reference revision and execution scope.

## Build prerequisites

Linux requires a C compiler, Make, Git, Python with venv, curl, pkg-config,
gettext and development libraries for ltdl, unistring, SQLite, curl, gcrypt, GMP,
GnuTLS and IDN2. The [reference CI jobs](../../.github/workflows/quality.yml)
define the package setup.

`bootstrap_dependencies.py` pins and verifies its dependency archives, builds
private libraries and creates a local Meson/Ninja environment from the
[hash-pinned wheel requirements](requirements-build.txt). Missing platform wheels
fail explicitly; source-build tooling is not downloaded implicitly. It installs
nothing into the system. On macOS, existing Homebrew libraries may supply the
remaining headers and libraries. Compiler probes require the host's normal
read-only system access.

## Build STATISTICS

Use new directories for each build:

```sh
gnunet_ref=$(mktemp -d "$PWD/target/reference.XXXXXX")
python3 -B tools/reference/bootstrap_dependencies.py --output "$gnunet_ref/deps" --jobs 4
git clone --depth 1 --branch v0.29.1 https://git.gnunet.org/gnunet.git "$gnunet_ref/source"
git -C "$gnunet_ref/source" -c url.https://git.gnunet.org/.insteadOf=git://git.gnunet.org/ submodule update --init --recursive
python3 -B tools/reference/build_reference.py --source "$gnunet_ref/source" --output "$gnunet_ref/build" --prefix "$gnunet_ref/prefix" --deps-prefix "$gnunet_ref/deps/prefix" --meson "$gnunet_ref/deps/venv/bin/meson" --ninja "$gnunet_ref/deps/venv/bin/ninja" --jobs 4
```

Set `CPPFLAGS` and `LDFLAGS` when using a non-default native dependency prefix.
The builder selects normal Meson targets and retains source, configuration,
compiler, library and executable identities in `build-result.json`.

## Compare STATISTICS clients and services

```sh
GNUNET_REFERENCE_SOURCE="$gnunet_ref/source" \
GNUNET_REFERENCE_BUILD="$gnunet_ref/build/build-result.json" \
cargo xtask verify daemon-reference
```

This builds the Rust participants and runs `statistics_daemons.py`. The smaller
`cargo xtask verify reference` group performs component comparisons.

The daemon runner checks C client→Rust service and Rust client→C service,
GET/SET/WATCH, relative updates, persistent restart and cross-loading official
SET dumps. `--normal-only` excludes the malformed-message and unknown-type
diagnostic profiles. Persistent and transient values have separate restart
expectations. A diagnostic timeout or intentional kill cannot satisfy a normal
service-exit requirement.

For Unix/TCP listeners, inherited descriptors, ACL denial, configuration discovery,
long-path handling and restart without a database, run:

```sh
python3 -B tools/reference/statistics_runtime.py \
  --reference "$gnunet_ref/build/build-result.json" \
  --rust-service /absolute/path/to/gnunet-service-statistics \
  --output target/statistics-listeners/new-run
```

Unavailable IPv6 is recorded as a skipped profile with its cause. See
[public-owner comparisons](STATISTICS_PUBLIC_OWNER.md) for callback/API scenarios
and [clock/MQ comparisons](statistics-clock/README.md) for controlled timing and
partial-write cases.

## HELLO contracts

`hello_owner.py` runs normal and deterministic C/Rust HELLO comparisons and
checks the reviewed acceptance map:

```sh
python3 -B tools/reference/hello_owner.py \
  --source /absolute/path/to/pinned/gnunet \
  --api-build /absolute/path/to/compiler-inventory-build \
  --build /absolute/path/to/normal-hello-build \
  --deterministic-build /absolute/path/to/deterministic-hello-build \
  --deps-prefix /absolute/path/to/reference-dependencies \
  --output target/hello-owner/new-run
```

The output must be new. `--update-ledger` explicitly records the generated
foundation report; without it, the ledger is unchanged. Normative changes require
reviewing the acceptance map's requirement digest. A previous report does not
certify changed inputs.

## Other profiles

| Profile | Guide |
| --- | --- |
| Conversation reference build | [Build preparation](CONVERSATION_BUILD.md) |
| Conversation process control | [Controller](CONVERSATION.md) |
| STATISTICS component benchmark | [Workload and metrics](STATISTICS_BENCHMARK.md) |
| Consensus public API | [CONSENSUS](CONSENSUS.md) |
| DV peer observations | [DV](DV.md) |
| DNS packet projections | [DNS packet observer](DNS_PACKET.md) |
| SecretSharing singleton | [Public API caller](SS_SINGLETON.md) |
| Accepted streams | [Stream fixtures](accepted-stream/README.md) |
| Service descriptor exhaustion | [EMFILE fixtures](service_emfile/README.md) |

## Reference differences

STATISTICS has two relevant baseline inconsistencies. Unknown message handling
can leave the C client's `needs_continue` set and prevent soft shutdown; the
runner records that diagnostic separately. The C server emits WATCH persistence
in flags bit 2 while its client tests the VALUE UID high bit. Rust preserves the
server wire format and reports the client discrepancy.

## Results and cleanup

Runners use owned processes, private directories and declared endpoints. They
retain participant output and recheck input identities. Cleanup attempts every
owned child and resource; cleanup failures remain separate from the initiating
error and fail the report. Reports record actual reaping and removal outcomes.
No report can guarantee cleanup after SIGKILL or host failure.

A selected executable's hash identifies its bytes; a corresponding build record
must establish which source produced it. Results apply only to the executed
profiles under the [compatibility policy](../../spec/gnunet/compatibility.md).
Generated logs, transcripts and receipts belong under `target/`.

Harness unit controls are listed by `python3 -B tools/check_tools.py --list`.
They validate the runners and are separate from their C/Rust observations.
