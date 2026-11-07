# Protocol contracts

This directory defines GNUnet compatibility requirements and acceptance data.
The selected reference revision is recorded in
[implementation status](../../IMPLEMENTATION_STATUS.md).

| Start here | Purpose |
| --- | --- |
| [Compatibility policy](compatibility.md) | External requirements and permitted Rust implementation differences |
| [Implementation contract](architecture.md) | Required behavior, deployment and acceptance matrix |
| [External release criteria](external/RELEASE.md) | Executable completion gate and evidence requirements |
| [External inventory](external/README.md) | Operations, profiles, production entry points and coverage |

## Authority and inventories

Use versioned official source, registries and service handlers together with the
published Living Standards and applicable RFCs. Record source/specification
differences instead of silently mixing versions or weakening validation.

[conformance.json](conformance.json) records subsystem/foundation requirements
and source anchors. The [C API inventory](api/README.md) supports discovery and
historical helper analysis; C function parity is not the Rust feature matrix.
[evidence.schema.json](evidence.schema.json) describes the original component
report format, separately from the current external-release schema.

## Checks

```sh
cargo xtask check-external-contracts
cargo xtask check-conformance --strict
```

The first checks inventory integrity. The second requires complete external
contracts and current-source qualification. Passing a build, component test or
source-fingerprint check does not establish complete protocol semantics.
See the [test guide](../../tests/README.md) for targeted and official-C jobs.
