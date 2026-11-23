# External inventory tools

`verify.py` checks the reviewed external inventory in
[`spec/gnunet/external`](../../spec/gnunet/external/README.md). It has no dependency
on C helper classifications or Rust API names. It never grants conformance
credit. `--strict` reports that whole-project interoperability remains pending.

`tests.py` exercises omission, false-credit, whole-owner downgrades, topology
substitution, numeric aliases, zero-token sources, C line splicing, source
drift and safe input paths. These controls also run in the xtask Rust test suite.

`scan.py` collects conservative source candidates and hashes, retaining original
physical lines. It does not evaluate the preprocessor, build activation or
complete semantic protocols. C/header/generated/non-C and third-party protocol
review remains necessary.

`capture.py --source SOURCE --output NEW.json` captures a discovery proposal into
a new file. It refuses to replace an existing output and never updates a
reviewed requirement lock. Compare and review the old/new protocol requirement
delta before accepting any proposal. Regeneration is not a release check.

The new canonical release stage is `release.py`, invoked by
`cargo xtask check-conformance [--strict]` or `check-external-release`.
It preserves and checks this original draft before evaluating separately pinned
external requirements and current evidence bindings. The complete semantic
inventory remains pending; strict mode must reject it. See
[the migration contract](../../spec/gnunet/external/RELEASE.md).
`release_tests.py` tests the immutable floor, reviewed catalog admission and
source-bound evidence with local synthetic files.

## STATISTICS WATCH

`statistics_watch_initial.py` evaluates the frozen
[initial WATCH profile](../reference/README.md#compare-statistics-clients-and-services).
The candidate case is `statistics.watch-initial:case:1` in
`statistics-private-unix-watch-initial`, direction `C-to-Rust`. Its two
process roles are `rust-service-watch-initial` and `c-watch-initial`. The
evidence verifier compares both live image observations, process arguments
and exits, the shared private configuration, the input SET frame, and the
numeric WATCH transcript.

The receipt retains the C reference build JSON and generated configuration
along with the Rust Cargo JSON build log and both native executables. The
Cargo log records a fresh compilation of `gnunet-service-statistics`. A
reviewed catalog must pin the adapter and case before the release checker
accepts receipts for this profile.

On the producing Linux host, keep the active
[official C build and staged prefix](../reference/README.md#build-statistics)
under one evidence root. Keep the reference checkout and native toolchain
available. The Rust build uses the installed toolchain and cached dependencies:

```sh
watch_rust=$(python3 -B tools/external-contracts/statistics_watch_receipt.py build-rust \
  --output "$gnunet_ref/watch-rust")
python3 -B tools/reference/statistics_daemons.py \
  --reference "$gnunet_ref/build/build-result.json" --rust-service "$watch_rust" \
  --watch-initial-only --capture-linux-images --output "$gnunet_ref/watch-run"
```

Provide the case review input as a regular file under the same evidence root.
Assembly reuses the canonical artifact checks and runs the offline WATCH
adapter before writing a new pending candidate:

```sh
python3 -B tools/external-contracts/statistics_watch_receipt.py assemble \
  --evidence-root "$gnunet_ref" --reference-source "$gnunet_ref/source" \
  --run "$gnunet_ref/watch-run/result.json" \
  --rust-build "$gnunet_ref/watch-rust/build-result.json" \
  --review "$gnunet_ref/review-input.txt" \
  --output "$gnunet_ref/watch-candidate.json"
```
