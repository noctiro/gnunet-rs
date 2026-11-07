# HELLO owner evidence

The HELLO foundation has 36 obligations: its API and behavior interfaces, 30
public functions and four public surfaces. `hello_acceptance.json` records the
reviewed operation/ownership reasoning and C comparison/Rust test witnesses.
It accepts the documented Rust borrow, authority and explicit-clock decomposition;
it does not claim C ABI, PILS, communicator or whole-GNUnet equivalence.

`hello_owner.py` always executes a fresh normal/conditional C and Rust oracle.
It checks both library/configuration profiles, generated artifact hashes,
successful C assertions, exact executed Rust test names, the complete criterion
set and source/specification fingerprints before writing a conformance report.
The Rust test binary is preserved by a byte-identical copy. The C driver
and both profiles remain in the generated component receipt.

```sh
python3 -B tools/reference/hello_owner.py \
  --source /path/to/pinned/gnunet \
  --api-build /path/to/compiler-inventory-build \
  --build /path/to/normal-hello-build \
  --deterministic-build /path/to/conditional-hello-build \
  --deps-prefix /path/to/reference-dependencies \
  --output target/hello-owner/new-run \
  --update-ledger
```

Run while implementation and normative files are frozen. The output directory
must be new and inside the workspace. No C library is edited or rebuilt. Without
`--update-ledger`, the generated report is available for inspection and the ledger
is unchanged. The option records the source-bound report for this foundation only.

Any normative change invalidates the acceptance map's reviewed requirement digest.
Re-review the changed requirements and witness reasoning before deliberately
updating that digest; the tool will not silently stamp a new one onto old claims.
Any implementation change requires fresh execution and source binding. Reports
from another snapshot remain historical and do not certify changed source.

The strict global gate continues to reject incomplete owners even when this
foundation's report is accepted. Missing, stale or tampered proof artifacts also
remain errors; a passing count or source correspondence alone never earns credit.
