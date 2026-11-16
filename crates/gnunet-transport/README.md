# TRANSPORT

GNUnet communicator IPC and TNG network protocols. The default `no_std` API provides codecs; `alloc` enables the bounded transport engine. Signing, entropy, clocks and durable effects are explicit caller ports.

## Interfaces

| Boundary | Reference |
| --- | --- |
| Engine and queues | [Contract](API.md#direct-queues-and-transmission) |
| Address publication | [Contract](API.md#address-publication) |
| Flow and receiving | [Contract](API.md#receiving-and-flow-control) |
| Discovery and routing | [Contract](API.md#address-discovery) |

## Configuration and integration

The [service or application guide](../../adapters/transport-service-std/README.md) owns executable configuration
and startup. The [API reference](API.md) documents constructor inputs, limits,
cancellation and cleanup requirements.

## API documentation

```sh
cargo doc -p gnunet-transport --no-deps --open
```
