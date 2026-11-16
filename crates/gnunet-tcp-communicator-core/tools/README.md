# TCP reference tools

`verify_session.py` checks the integrated TCP core, native host and shared
session cryptography against unmodified official C components and peers.

## Inputs and invocation

Supply absolute `--repository`, `--source`, `--reference`,
`--component-reference` and `--output` paths. The output must be new and disjoint
from source and reference inputs. Generated output belongs under `target/`.

Both reference receipts bind GNUnet v0.29.1 at
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`. Their required kinds are:

- `unmodified-official-c-tcp-peer-services-reference-build`
- `unmodified-official-c-tcp-communicator-reference-build`

`--prepare-only` writes the workspace-copy preparation without acceptance.
`--development-snapshot` labels a run against an independent source copy.

## Workspace and artifact checks

The verifier copies the complete workspace with its settings, architecture roles,
features and both lockfiles. It compares dependency declarations and resolved
profiles, selects artifacts from Cargo JSON and runs the configured tests,
Clippy, Rustdoc and embedded checks. It does not generate a subset workspace.

Reference checks bind clean tracked C source, Meson configuration, compiler
inputs, libraries and dynamic providers. Source and artifact sets are rechecked
after execution. Critical checks use explicit errors and remain enabled under
optimized Python. Immutable builder snapshots, when required by an older input
receipt, are inert provenance data and are never imported or executed.

## Runtime scope

The normal peer profile uses owned processes, private Unix sockets and numeric
loopback endpoints. It checks bidirectional TRANSPORT traffic, rekeying, replay
timestamp records, quiescent Rust retirement and owned-process exits. Component,
raw TRANSPORT and CORE observations are recorded separately.

The reference runner uses macOS `sandbox-exec`, `otool` and `lsof`. Embedded
compilation does not execute that native profile. Known reference differences
are documented in [UPSTREAM.md](../UPSTREAM.md); reports retain their actual
source and execution scope under the
[compatibility policy](../../../spec/gnunet/compatibility.md).
