# Official API inventory tools

Run `python3 tools/api_inventory/check.py --self-test` for deterministic boundary
regressions. The checker validates relationships and coverage claims; the parent
GNUnet evidence validator still validates operation results and artifacts.

See [the catalog contract](../../spec/gnunet/api/README.md) for normal/strict
checks, generation commands, supported capture scope and pending limitations.
The tools execute only their own fixed compiler/Git/nm commands. Command arrays
inside catalog data are descriptions; the checker never executes them.

`extract.py` creates a new raw capture directory using the configured
Meson build and Clang's typed AST. `operations.py` adds all configured installed
production translation-unit preprocessing and optional exported symbols.
`import_capture.py` checks complete header membership and explicitly writes the
versioned compact catalog. `statistics_inventory.py` writes the reviewed case
inventory without claiming those cases have passed.
