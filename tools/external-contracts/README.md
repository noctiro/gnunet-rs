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
`release_tests.py` tests omission, unknown-capability and source/evidence controls
using local synthetic files. No reference C or network profile runs in those tests.
