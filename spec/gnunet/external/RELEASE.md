# External release criteria

The release checker validates external requirements, semantic inventories and
source-bound evidence. Open implementation and qualification work is tracked in
[Implementation status](../../../IMPLEMENTATION_STATUS.md).

## Checker modes

`cargo xtask check-conformance` and `check-external-release` use the canonical
stage2 requirement format. Ordinary mode exits 0 for an internally valid pending
report. `--strict` exits 1 while any required review, case, profile, direction or
evidence remains unresolved. Checker success in ordinary mode is an integrity
result, not a protocol or release pass.

Stage2 preserves the stage1 subsystem, foundation, registry, operation, profile
and case identities, including aliases and zero-use registry entries. Unresolved
review obligations retain their identities, reasons and scope. C helper names,
signatures, queues, scheduler, plugin ABI and process organization do not become
Rust requirements merely by appearing in reference source.

## Production operation entry mapping

[operation-entrypoints.json](operation-entrypoints.json) locates Rust production
entries and official reference sources for a finite set of operation groups.
`present` identifies an entry; it does not certify every message, profile, edge
condition or runtime behavior. Active contrib implementations have a separate
[capability map](proposals/active-contrib-capabilities.json).

Both maps are navigation data. They neither complete the semantic inventory nor
supply runtime, release or semantic-review credit.

## Semantic inventories

[semantic/fs.json](semantic/fs.json) defines draft FS capability contracts, cases,
profiles and registry identities. It covers public artifacts, content trees,
metadata, directories, UBLOCKs, normalization, publication, search, download,
indexing, service IPC, anonymous CORE routing, directed CADET transfers,
migration, persistence, resources and user operations. The fixed content encoding
is AEAD. FS_PUT client and peer layouts remain separate operations despite their
shared message ID.

Operations cite reference source hashes and line anchors; cases and profiles
reference each other. Draft review states and empty evidence slots are pending
obligations, not observed failures or a count of missing functions. The optional
publish-helper profile does not mandate C helper processes; Rust-native metadata
scanning and extraction remain required. A reviewed boundary choice may exclude
that helper profile only while preserving these capabilities.

[semantic-inventory.schema.json](semantic-inventory.schema.json) defines the
closed draft format. `semantic.py` checks references, unique identities,
source-index membership and hashes, case ownership, profile directions and the
registry floor. With `GNUNET_REFERENCE_SOURCE`, it also checks original file
bytes, line anchors and ranges against the tracked-source survey before and
after verification. These integrity checks run no C build or network profile.

[release-lock.json](release-lock.json) binds the requirements, schemas,
inventories and stage1 predecessor. Its independently pinned checksum prevents
removing an extension, reducing the lock or editing source anchors unnoticed.
The checker rejects self-awarded draft-to-reviewed changes. Satisfying an
obligation requires an explicit review model and permitted case/profile/direction
slots; a status string or passing parser cannot establish completeness.

## Historical input

The original stage1 data files remain under `history/stage1/` because the checker
supports reading that format explicitly:

```sh
python3 -B tools/external-contracts/release.py --historical-stage1
python3 -B tools/external-contracts/release.py --historical-stage1 --strict
```

The first command reports recorded unknowns and pending cases; the strict form
refuses release. Canonical mode rejects a stage1 lock as a downgrade.

## Evidence requirements

[release-evidence.schema.json](release-evidence.schema.json) defines source-bound
receipts. Verification checks actor binaries, compiler/build provenance,
configuration, generated and dependency inputs, implementation/reference maps,
loaded file hashes, exits, raw artifacts and semantic-adapter verdicts. Legacy
C-helper catalogs are excluded from the implementation map; required owner flags
and the external floor remain independently checked. A shared-cache UUID is not
a file-content hash.

The adapter registry and evidence index contain no accepted entries. Draft FS
IDs cannot be receipt targets. Existing component results are not automatically
release receipts. A reviewed adapter reads frozen artifacts and validates the
unchanged receipt; it cannot execute a new profile while evaluating old evidence.
Reference C software, generated responses and substitute services cannot stand
in for production Rust behavior.

Readiness derives from unresolved reviews, cases, evidence slots, semantic
inventory and actual reference-source checking. The current pending inputs keep
`complete_semantic_inventory`, `release_ready` and
`full_GNUnet_conformance_verified` false. Full release also requires the platform,
living-standard, non-C, submodule and cross-owner surveys, architecture/resource
correctness, interoperability and performance criteria in the
[implementation contract](../architecture.md).

## Integrity controls

```sh
python3 -B tools/external-contracts/release_tests.py
```

These synthetic controls validate the checker, not GNUnet protocol behavior.
They preserve owner, alias and case floors, historical readability and actor
provenance. They reject omitted semantics, source/hash/anchor changes, mismatched
profiles and directions, self-awarded review, draft receipts and canonical
downgrade.
