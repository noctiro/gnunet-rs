# Accepted stream source component

Run `python3 -B tools/reference/accepted-stream/verify.py --repository /absolute/repo
--source /absolute/pinned-gnunet --reference /absolute/normal-arm-build/build-result.json
--output /absolute/fresh-external-output`.

## Usage

Generation copies the complete repository workspace, all local sources,
settings and both lock files to an isolated tree. Cargo adds only the
observation probe as a workspace member and extends the copied lock offline. No
Native/IPC manifest or dependency graph is reconstructed from templates.
All original local package manifest roles must remain unique, and every full
production/dev/build dependency contract and feature declaration is compared
with paths normalized to the same workspace role. Existing package entries in
the lock must stay unchanged. Workspace lint declarations must match the
reviewed `lint-policy.toml`.
Only the copied tree is compiled; no original repository path dependency is
left to create a second IPC/CLIENT/types identity.

The reviewed `test-inventory.json` identifies runtime and compile-fail scopes.
Tool controls reject foreign or duplicate local package identities, changed
dependencies, and lock changes beyond adding the probe.

The finite Darwin profile retains24 normal-C and18 Rust observations.
All6 canonical profiles must match, while raw/pure wrappers retain8 known
native-option differences. C binaries are fresh-compiled against unchanged
normal util libraries; compile source path, reference/source/library commitment,
pre-wrapping std/mio/socket2 audited sources and the pinned Rust sysroot are
checked. Every actor binary is checked before/after every process. The input
file sets and complete copied workspace must be unchanged after validation.

This is component evidence. Raw pre-wrapping CLOEXEC policy, Tokio registration
errors, unexecuted C syscall failures, other Unix platforms, complete SERVICE
lifetimes and full PROGRAM logging remain separate obligations. No complete
network/STATISTICS/Resolver owner is promoted by this proof.

Product Connection and canonical accept come from service-runtime, whose
reactor policy accepts valid descriptors beyond FD_SETSIZE. The C select ceiling
is not a protocol conformance obligation. The inventory must be reviewed against
the current source before rerunning the full catalog.
