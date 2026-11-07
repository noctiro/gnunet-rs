# External capability inventory

The inventory describes externally observable GNUnet behavior rather than C
function parity. [Release criteria](RELEASE.md) define the conformance gate;
[implementation status](../../../IMPLEMENTATION_STATUS.md) lists open work.

| Data | Role |
| --- | --- |
| [discovery.json](discovery.json) | Discovered external contracts and source anchors |
| [coverage.json](coverage.json) | Mapping and coverage status |
| [node-path.json](node-path.json) | Node-level behavior and composition cases |
| [operation-entrypoints.json](operation-entrypoints.json) | Finite production entry-point map |
| [release-requirements.json](release-requirements.json) | Required release obligations |
| [release-source-index.json](release-source-index.json) | Source bindings |
| [release-evidence.json](release-evidence.json) | Evidence assignments |
| [proposals/](proposals/) | Unadopted or partial capability proposals |

Lock and schema files bind the inventories. A mapped entry point or registry ID
does not establish full semantics. Required error, cancellation, reconnect,
restart and recovery behavior needs its own cases and profile-specific evidence.
Do not promote a partial proposal, source review or native-only fixture into
complete external coverage.
