# Maintained BLOCK workspace validation

`verify.py` validates the integrated `gnunet-block` package by copying the
complete supplied repository, including `.cargo`, all member manifests and both
lockfiles. It does not generate a smaller Cargo workspace. The reviewed TCP
`session_inputs.py` supplies the shared complete-workspace/dependency/role/feature
contract. The helper path is explicit and its bytes are bound; no second copy of
that implementation is maintained here.

Preparation, with no acceptance result or Rust build:

```sh
python3 -B crates/gnunet-block/tools/verify.py \
  --repository "$PWD" \
  --output /private/tmp/block-preparation-new \
  --prepare-only
```

A full run additionally requires `--normal-receipt`, `--deterministic-receipt`,
`--reference-helper`, `--audit-tool`, `--audit-db`, and `--audit-revision`.
`--workspace-helper` selects an independent reviewed helper when developing tools
outside the repository. Its default is the repository TCP helper.
`--development-snapshot` labels an independent development source copy; it must
not be described as current-workspace evidence.

The full run requires all 18 named Rust tests, two docs (one compile-fail),
seven Cargo JSON test/example artifacts, the original 14 tool controls plus three
workspace controls and two builder-source controls, plus six real
reference-receipt rejection controls. It builds
both M0/M4 targets through the actual `tests/embedded/noalloc` fixture and traverses
that fixture's resolved graph, rather than virtual-workspace feature unions.
Workspace architecture checks and three metadata profiles are retained.
Both lockfiles are audited against an explicit fixed clean RustSec commit.
The three new Argon2 dependency archives and extracted sources are checked.

Release probe/vector paths come from member Cargo JSON artifacts. Normal
C probes use the original normal Meson compiler flags, with complete preprocessor
input discovery before compile and dependency-file comparison afterward.
Compiler executable/version, generated headers, normal libraries, installed
plugins, transitive non-system providers and process binaries are bound. The
normal reference guard checks all 2,193 pinned C inputs, exact successful setup
source/build/prefix, profile, current builder source, baseline receipt and library
hashes. Whole source/tool file sets and every binary/provider/header are checked
again after processes. No Python `assert` controls a verification decision.

The finite comparison corpus is unchanged: 867 core cases and 1,296 signed/group
cases for each normal/deterministic HELLO profile; each signed profile builds 22
vectors through C APIs and 22 through Rust. These observations do not
complete the BLOCK owner, the general plugin mechanism or any full subsystem.
Defined C assertion/pointer preconditions remain excluded.

Historical stock3/det2 receipts are immutable. Their original builder source
blobs were not preserved, so current tools reject them as fresh build-recipe
proof. Fresh normal/deterministic outputs are created with the current
repository builder, in separate directories/prefixes. Historical functional
observations are retained separately and are not relabeled.

The normal build receipt records all three executed local source roles:
`builder`, imported `common`, and imported `reference-helper`. Each actual
canonical absolute path/hash is captured before native build work and rechecked
at completion. The consumer requires the exact nonempty three-role set without
duplicate roles/paths, validates each original file, and compares its bytes
to the current reviewed source for that role. A future reviewed repository path
may differ from an executed frozen temporary path only when both exact source
bytes match; the original executed path is retained, never rewritten. Older
receipts without the imported-source closure remain historical and are rejected
by the fresh reference guard.
