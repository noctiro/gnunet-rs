# TRANSPORT

GNUnet communicator IPC and TNG network protocols. The default `no_std` API
provides codecs and bounded owners for direct links, HELLO discovery and DV
routes. `alloc` enables the transport service engine. Signing, entropy, clocks
and durable effects are explicit caller ports.

## Interfaces

| Boundary | Reference |
| --- | --- |
| Engine and queues | [Contract](API.md#direct-queues-and-transmission) |
| Address publication | [Contract](API.md#address-publication) |
| Flow and receiving | [Contract](API.md#receiving-and-flow-control) |
| Discovery and routing | [Contract](API.md#address-discovery) |
| Direct address validation | `direct_validation::DirectValidation` uses the original carrier and caller-owned signing and time |
| Direct byte credit | `direct_flow::DirectFlow` tracks official FLOW updates, actual BOX admission and original receive receipts |
| Direct link | `direct::Link` combines validation, FLOW and concurrent bounded reassembly for CORE and DV on a reliable carrier |
| Bounded HELLO discovery | `direct_discovery::Book` retains and selects one provisioned peer's live addresses |
| Bounded DV routes | `dv::routes::Routes` uses caller-owned route, probe and source slots, with explicit durable replay effects and first-hop reachability |
| Direct DV forwarding | `direct_routes::Router` binds routes and original forwarding work to live carrier generations |

## Configuration and integration

The [service or application guide](../../adapters/transport-service-std/README.md) owns executable configuration
and startup. The [API reference](API.md) documents constructor inputs, limits,
cancellation and cleanup requirements.

The HELLO book accepts standalone imports with the official address-binding
signature profile. The [direct CORE peer](../gnunet-direct-peer/README.md#discover-peer-addresses)
can also attribute a normal-profile HELLO to its own authenticated sender.

## API documentation

```sh
cargo doc -p gnunet-transport --no-deps --open
```
