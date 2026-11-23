# External release criteria

The release checker validates external requirements, semantic inventories and
source-bound evidence. Known product gaps are tracked in
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

## Reviewed additions

The canonical checker can load `release-review-catalog.json` from this directory
once its digest is pinned in the verifier. The catalog binds the stage2 lock and
reference revision. New operations cite the original source, and their cases
bind specific profiles, directions and adapters. Every topology and adapter
must be used by a case. The checker evaluates the new cases alongside the
original floor and pending semantic reviews.
[Release verifier](../../../tools/external-contracts/release.py)

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
a file-content hash. Each observed process image must match the bytes of a
binary in the build provenance.

The adapter registry and evidence index contain no accepted entries. Draft FS
IDs cannot be receipt targets. Existing component results are not automatically
release receipts. A reviewed adapter reads frozen artifacts and validates the
unchanged receipt; it cannot execute a new profile while evaluating old evidence.
Each receipt must match a reviewed case, profile, direction and adapter slot.
The verifier runs the checked adapter bytes in an isolated Python process.
Reference C software, generated responses and substitute services cannot stand
in for production Rust behavior.

Readiness derives from unresolved reviews, cases, evidence slots, semantic
inventory and actual reference-source checking. The current pending inputs keep
`complete_semantic_inventory`, `release_ready` and
`full_GNUnet_conformance_verified` false. Full release also requires the platform,
living-standard, non-C, submodule and cross-owner surveys, architecture/resource
correctness, interoperability and performance criteria in the
[implementation contract](../architecture.md).

For each shipped [desktop service recipe](../../../tools/xtask/node/README.md#deploy-as-an-operating-system-service),
verify installation, startup readiness, a manager-issued stop through
retirement and restart with the original peer key. Observe readiness through
the systemd or SCM status on those targets and through the node's ready event
under launchd or rc.d.

For shipped [system DNS providers](../../../adapters/resolver-std/README.md#platforms-and-entry-points),
verify A, AAAA and PTR results through RESOLVER IPC, system search and
split DNS, and cancellation on timeout or disconnect.

For deployments that grant [native NAT reversal](../../../apps/gnunet-node/README.md#nat-reversal),
verify the approved helper identity, a peer reversal through the NAT service,
and child retirement when its interface is removed or the node stops.

For application SDKs, build a consumer from the distributed package. Record
the application and extension identities, signing profile and installed SDK
version on the target. Verify official peer interoperability, network changes
and bounded shutdown. Exercise permission revocation for each shipped VPN or
DNS provider.

- Install the [Android library](../../../platform/android/README.md#android-library-build)
  from its Maven publication on each supported device profile. For image
  deployments, verify init integration under the product's SELinux policy.
- Build and provision the [iOS app and network extensions](../../../tools/ci/ios-sdk-consumer/README.md)
  with their own bundle identities. Verify Packet Tunnel outbound detours and
  DNS behavior across network changes. For DNS Proxy, qualify managed-profile
  activation, UDP GNUnet DNS client phases, TCP DNS forwarding, upstream
  recursion exclusion and original native flow retirement.
- Build the [OpenHarmony source HAR](../../../platform/openharmony/README.md)
  with Hvigor and exercise it in a signed HAP. Verify VPN protection and native
  descriptor retirement on each supported API profile. For image deployments,
  verify init integration on the product image. Evaluate Huawei HarmonyOS
  separately with its SDK, signing and devices.

For [HiSpark Taurus Linux](../../../platform/openharmony/system/small-linux/README.md),
build the staged GN target into the product image. Verify the installed init
fragment, ARM executable and non-root service identity. Boot with `/storage`
unavailable to check startup refusal, then qualify ordinary startup, official
peer interoperability, original process retirement and peer identity across reboot.

For a product with DoT tickets enabled, verify full and resumed queries
against a ticket-issuing server for both certificates and raw public keys.
Verify a fresh authentication after ticket rejection and after a change to
the qualified route or its TLSA proof.

## Integrity controls

```sh
python3 -B tools/external-contracts/release_tests.py
```

These synthetic controls validate the checker, not GNUnet protocol behavior.
They preserve owner, alias and case floors, historical readability and actor
provenance. They reject omitted semantics, source/hash/anchor changes, mismatched
profiles and directions, self-awarded review, draft receipts and canonical
downgrade.
