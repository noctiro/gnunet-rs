# Accepted stream source component

Run `python3 -B tools/reference/accepted-stream/verify.py --repository /absolute/repo
--source /absolute/pinned-gnunet --reference /absolute/normal-arm-build/build-result.json
--output /absolute/fresh-external-output`.

Generation copies the complete repository workspace, all local sources,
settings and both lock files to an isolated tree. It adds only the observation
probe as a workspace member and regenerates that tree's lock offline. No
Native/IPC manifest or dependency graph is reconstructed from templates.
All original local package manifest roles must remain unique, and every full
production/dev/build dependency contract and feature declaration is compared
with paths normalized to the same workspace role. Registry identities cannot
change. Workspace lint declarations must match the reviewed lint-policy.toml.
Only the copied tree is compiled; no original repository path dependency is
left to create a second IPC/CLIENT/types identity.

The reviewed test-inventory.json fixes source names and executed groups:
Native12, IPC56 and Broker19, total87. IPC includes the12 Resolver tests ported
directly to Context/Query/Driver and the2 new M12 STATISTICS unit boundaries. The old72 count changes by six removed private transport units, nineteen real
shared broker checks and two M12 checks:72-6+19+2=87. The private filename
assertion is still in IPC; endpoint rounds, actual5s lookup deadline, numeric
callback order, MAX-frame and retained DNS assertions are in Broker. No test is
filtered to preserve a stale count.

Lifetime controls are separate: IPC4 docs/3 compile-fail controls and Broker2
docs/1 compile-fail control. The12 original named tool controls remain exact;
the same controls also reject foreign/duplicate local package identities and
wrong dependency fields. Actual named source and runtime sets must match each
reviewed group exactly; new/deleted/renamed tests require review.

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

The frozen historical receipts above retain their original source-shaped scope.
Product Connection and canonical accept come from service-runtime, whose
reactor policy accepts valid descriptors beyond FD_SETSIZE. The C select ceiling
is not a protocol conformance obligation. The old exact named test inventory is
historical and needs a separate reviewed revision before rerunning this whole
catalog; no previous receipt is relabelled as evidence for a new binary.
