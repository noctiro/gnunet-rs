# BLOCK reference tools

`verify.py` compares the Rust BLOCK implementation with normal and deterministic
HELLO profiles of an unmodified official C build. It copies the complete supplied
workspace, including member manifests, settings and both lockfiles. Shared
workspace input checks come from the TCP verifier's `session_inputs.py`.

## Prepare a workspace copy

```sh
python3 -B crates/gnunet-block/tools/verify.py \
  --repository "$PWD" \
  --output "$PWD/target/block-reference/new-run" \
  --prepare-only
```

Preparation writes `preparation.json`; it runs no Rust build or comparison.
`--development-snapshot` labels a run against an independent source copy.

## Build reference profiles

`build_normal.py` creates a new Meson build and private prefix. Run from this
directory, replacing the uppercase arguments with absolute paths:

```sh
python3 -B build_normal.py --source UPSTREAM --baseline NORMAL_RECIPE_RECEIPT --reference-helper REFERENCE_HELPER --hello-profile normal --output NEW_NORMAL_BUILD
python3 -B build_normal.py --source UPSTREAM --baseline NORMAL_RECIPE_RECEIPT --reference-helper REFERENCE_HELPER --hello-profile deterministic --output NEW_DETERMINISTIC_BUILD
```

Both profiles use the same clean reference revision. Deterministic mode adds the
official compiler macro while retaining the native include flags.

## Run comparisons

A full verifier run additionally requires `--normal-receipt`,
`--deterministic-receipt`, `--reference-helper`, `--audit-tool`, `--audit-db` and
`--audit-revision`. `--workspace-helper` overrides the shared input checker.
Output directories must be new and disjoint from source and reference inputs.

The verifier selects Rust executables from Cargo JSON, runs the declared package
and tool checks, builds the embedded fixtures and audits both lockfiles against
the selected RustSec revision. C probes retain normal compiler flags and bind
source, headers, libraries and provider dependencies before and after execution.
Build receipts identify the executed builder, common helper and reference helper;
missing or mismatched source roles fail validation.

Comparison corpora and exact case IDs are maintained by the runner and its
inventories. Reports apply to their recorded inputs and selected profiles under
the [compatibility policy](../../../spec/gnunet/compatibility.md).
