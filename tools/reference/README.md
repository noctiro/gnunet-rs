# Official C reference programs

These tools build and run isolated official GNUnet software for component and
interoperability comparisons. The [compatibility policy](../../spec/gnunet/compatibility-policy.json)
selects the active release and commit. Specialized runners with version-specific
fixtures declare their own reference identity and scope.

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
gnunet_release=$(python3 -B tools/reference/build_reference.py --print-target release)
gnunet_revision=$(python3 -B tools/reference/build_reference.py --print-target revision)
git clone --depth 1 --branch "$gnunet_release" https://git.gnunet.org/gnunet.git "$gnunet_ref/source"
test "$(git -C "$gnunet_ref/source" rev-parse HEAD)" = "$gnunet_revision"
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

This builds `gnunet-statistics`, `gnunet-cli` and `gnunet-service-statistics`
with the STATISTICS command feature and runs `statistics_daemons.py`. The
smaller `cargo xtask verify reference` group performs component comparisons.

The daemon runner checks C client→Rust service and Rust client→C service,
GET/SET/WATCH, relative updates, persistent restart and cross-loading official
SET dumps. It compares the standalone Rust `gnunet-statistics` absolute SET
and quiet selector GET with the C service and client. The grouped
`gnunet-cli statistics` supplies the JSON and relative-update comparisons.
Direct harness invocations supply `--rust-statistics`, `--rust-client` and
`--rust-service` for the three Rust binaries.
`--normal-only` excludes the malformed-message and unknown-type
diagnostic profiles. Persistent and transient values have separate restart
expectations. A diagnostic timeout or intentional kill cannot satisfy a normal
service-exit requirement.

On Linux, add `--capture-linux-images` to a direct `statistics_daemons.py` run to
retain the executable and file-backed code mappings of each owned daemon at
readiness and before graceful shutdown, and of the C WATCH client after its
first observed value and before graceful shutdown. The report records the
mapped device and inode, content hashes and capture failures. The
`linux_image_capture` result reports which long-lived actors had matching
observations and normal exits. It identifies one-shot clients without live
image observations and excluded diagnostic actors separately. Anonymous and
kernel-provided mappings are outside this scope.
The behavioral suite and image capture have separate statuses.

The run retains all four normal daemon configurations, the reference build
receipt, process transcripts and the exact persistence dumps used for
cross-loading. These artifacts support the separate
[external release review](../../spec/gnunet/external/RELEASE.md).

For the initial WATCH notification alone, Linux can capture both participating
processes:

```sh
python3 -B tools/reference/statistics_daemons.py \
  --reference "$gnunet_ref/build/build-result.json" \
  --rust-service /absolute/path/to/gnunet-service-statistics \
  --watch-initial-only --capture-linux-images \
  --output target/statistics-watch-initial/new-run
```

The Rust service loads a single public SET database frame. The official C
WATCH client reads its initial numeric value over the private Unix socket.
Use the full suite for updates, persistence restarts and cross-loading.
[Candidate evidence verifier](../external-contracts/README.md#statistics-watch).

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

### Multi-node process budgets

Run the DV and four-participant CONSENSUS topologies in a disposable Linux guest
with cgroup v2, systemd 250 or later and a user service manager. Stage the
binaries and configuration inside the guest before starting the topology. Start
the controller directly as the main process of one transient service:

```sh
systemd-run --user --unit="gnunet-reference-$(date +%s)" --same-dir --service-type=exec \
  --wait --pipe --collect \
  -p CPUQuota=200% -p MemoryMax=2G -p MemorySwapMax=0 -p TasksMax=128 \
  -p RuntimeMaxSec=260s -p TimeoutStopSec=8s -p ExitType=main -p KillMode=control-group \
  -p Restart=no -p SendSIGKILL=yes -p OOMPolicy=kill \
  python3 -B tools/reference/dv_private.py \
  --manifest /ABS/manifest.json --output /ABS/new-evidence --middle c --execute
```

The runner checks the kernel's CPU, memory, swap and task limits, and the user
manager's lifetime and stop policy, before starting children. The manager stops
the entire cgroup if the controller exits. Keep the original protocol deadlines
and the consuming child waits in the controller so a stop or incomplete cleanup
counts as a failed run. If the guest itself hangs, discard it before another run.

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
