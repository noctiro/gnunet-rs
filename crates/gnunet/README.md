# gnunet Rust API

The public facade re-exports protocol engines and optional native adapters.
Default features are empty; the default library is `no_std`. Allocation and
native capabilities are selected explicitly in [Cargo.toml](Cargo.toml).

## Add a source dependency

For an application beside this checkout:

```toml
[dependencies]
gnunet = { path = "../gnunet-rs/crates/gnunet", default-features = false }
```

Add the required features to that dependency, for example
`features = ["official-ipc"]` for the native STATISTICS IPC adapter on Unix.
Enabling a feature exposes its API; it does not start services or supply their
configuration, sockets or runtime drivers.

## API paths

| Area | Examples |
| --- | --- |
| Shared formats/types | `gnunet::wire`, `gnunet::types`, `gnunet::resources` |
| Crypto/artifacts | `gnunet::crypto`, `gnunet::session_crypto`, `gnunet::hello`, `gnunet::gnscrypto` |
| Pure engines | `gnunet::core`, `gnunet::transport`, `gnunet::tcp`, `gnunet::udp`, `gnunet::statistics` |
| Service clients | `gnunet::clients`; individual native clients use their feature gates |
| Native STATISTICS IPC | `gnunet::ipc` with `official-ipc` on Unix |

The [library source](src/lib.rs) and [client exports](src/clients.rs) show the full
module/feature mapping. Individual crates and adapters document operation-level
contracts.

## Feature selection

- Use the default API for caller-storage codecs and pure engines.
- `alloc` and domain-specific allocation features enable owned state where offered.
- Native features such as `official-ipc`, `official-pils-client` and
  `official-dht-client` add their selected host adapters. Check platform gates;
  native features do not imply universal OS support.
- Use the service executables in [apps/](../../apps/) when a process entry point
  is required. The facade itself does not launch a node stack.

## Driving operations

Pure engines emit effects for caller-supplied ports. Native owners document their
required clock, endpoint, polling and cleanup contracts. Preserve operation/source
identity through partial IO and canceled waits. Keep local write, remote result
and durable commit outcomes distinct; unknown mutations are not retry permission.

From the workspace root:

```sh
cargo check -p gnunet --no-default-features --locked
cargo check -p gnunet --features official-ipc --locked
cargo doc -p gnunet --no-deps --locked
```

See [architecture](../../ARCHITECTURE.md) for ownership rules and
[implementation status](../../IMPLEMENTATION_STATUS.md) for open capabilities.
