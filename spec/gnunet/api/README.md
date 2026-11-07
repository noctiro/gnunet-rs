# C API source inventory

Versioned declarations, operation candidates and historical Rust-equivalence
mappings for the reference C implementation. This is discovery/audit data;
[external release criteria](../external/RELEASE.md) define product acceptance.
Rust need not reproduce every C function, callback, type or macro.

| File | Contents |
| --- | --- |
| [catalog.json](catalog.json) | Version, source/profile metadata and inventory references |
| [declarations.json](declarations.json) | Compiler-derived declarations |
| [operations.json](operations.json) | Reviewed operation candidates and behavior cases |
| [statistics.json](statistics.json) | STATISTICS-specific inventory |
| [catalog.schema.json](catalog.schema.json) | Inventory schema |

```sh
cargo xtask check-api-inventory
```

Regeneration and compiler/build inputs are documented in
[the inventory tool guide](../../../tools/api_inventory/README.md).
The [compatibility policy](../compatibility.md) distinguishes external capabilities
from C internal parity.
