# BLOCK

Allocation-free `no_std` block validation, key extraction, reply classification
and group handling for the GNUnet BLOCK library and its installed plugins.
The crate contains no unsafe code. The public facade exposes it as
`gnunet::block`.

## Public interfaces

`plugins::Context` selects builtin plugins.
`callbacks::CallbackContext<P, N>` accepts typed custom plugins. Callers supply
storage, HELLO limits, operation-time UTC, native byte order and an explicit
HELLO signature profile. `GroupSizing` represents group-creation options.

Key extraction, block validation and reply validation are separate operations.
A successfully extracted key does not establish signature validity. The normal
HELLO profile authenticates metadata only; addresses remain unauthenticated
claims.

## Memory and dependencies

REV verification requires `pow::MEMORY_BLOCKS` caller-owned aligned Argon2 blocks,
using 1 MiB of main work memory. `pow` re-exports `gnunet_crypto::pow`; the
implementation is shared. Production dependencies are the workspace types,
cryptography and HELLO crates. Dependency versions and features are maintained
in the Cargo manifests and lockfiles.

## Reference and tests

[Design](DESIGN.md) documents wire behavior, resource contracts and reference
quirks. [inventory.json](inventory.json) maps the selected reference interfaces.
The [tool guide](tools/README.md) covers isolated C builds and comparisons.

Run package checks from the repository root:

```sh
cargo test -p gnunet-block --locked
cargo clippy -p gnunet-block --all-targets --all-features --locked -- -D warnings
```
