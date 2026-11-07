# External contract proposals

These source-bound proposals prepare required acceptance work. They are not
registered semantic inventories, canonical requirements, evidence or passing
results. All behaviors remain unverified. The current release requirements,
locks, original unknowns and FS inventory keep their existing authority.

- [STATISTICS contracts](statistics-contracts.json) group the public messages,
  callbacks, storage artifacts and failure/recovery semantics with explicit
  source and deployment conditions.
- [First STATISTICS run](statistics-first-run.json) maps only the real calls and
  assertions prepared in the current normal-daemon harness. It is a subset of
  the contracts; unselected directions and cases remain open.

Official C CLI relative updates are not available: its `-r` means remote. The
reverse relative direction needs an actual official public-API caller. Runtime
execution remains subject to the existing pause and pending resumption request.

The contract proposal records its original source baseline, including the
normal service's fixed128-row/256-name-byte capacity. Configurable bounded host
storage and streamed GET output are separate active source work; wire-format
coverage does not establish that deployed capacity or measured memory use.
