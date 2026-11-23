# External contract proposals

These drafts describe candidate scope for future review under the
[external release criteria](../RELEASE.md).

- [STATISTICS contracts](statistics-contracts.json) group the public messages,
  callbacks, storage artifacts and failure/recovery semantics with explicit
  source and deployment conditions.
- [STATISTICS daemon tests](../../../../tools/reference/README.md) document the
  current C↔Rust harness and its runtime inputs. A C-authored relative update
  requires an official public API caller because the C command uses `-r` for
  remote access.
