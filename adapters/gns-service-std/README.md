# GNS service host

Drives the GNS resolver core, explicit dependency providers and official type500/501 service IPC. DNS validation, provider failures and client output remain separate contracts.

## Interfaces

| Boundary | Reference |
| --- | --- |
| Native providers | [Contract](API.md#native-ipc-providers) |
| Auxiliary dependencies | [Contract](API.md#ordinary-auxiliary-dependencies) |
| Service frontend | [Contract](API.md#official-ipc-frontend-and-service-owner) |

## Configuration and integration

The [service or application guide](../../apps/gnunet-service-gns/README.md) owns executable configuration
and startup. The [API reference](API.md) documents constructor inputs, limits,
cancellation and cleanup requirements.

## API documentation

```sh
cargo doc -p gnunet-gns-service-host --no-deps --open
```
