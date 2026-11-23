# DHT service host

Composes the DHT protocol owner with CORE, PILS, HELLO, local IPC and optional
direct-IP transport.

## Interfaces

| Boundary | Reference |
| --- | --- |
| Forwarded PUT policy | [Contract](API.md#put-path-size-truncation) |
| Unknown block types | [Contract](API.md#opaque-unknown-type-put-transit) |
| Reverse paths | [Contract](API.md#recent-reverse-routes-and-terminal-replies) |
| Direct IP and own HELLO | [Contract](API.md#direct-ip-composition-and-own-hello) |

## Configuration and integration

The [service or application guide](../../apps/gnunet-service-dht/README.md) owns executable configuration
and startup. The [API reference](API.md) documents constructor inputs, limits,
cancellation and cleanup requirements.

The `startup` feature exposes `startup::serve_embedded`. It serves the same DHT
protocol on the node's private IPC path and uses the supplied local CORE, PILS,
PEERSTORE and TRANSPORT endpoints. Supply the node's NSE endpoint to consume
its live estimates. An absent NSE endpoint leaves the initial estimate in use
unless the configured direct-IP underlay supplies one. Complete the stop future
and keep the service running through retirement before stopping dependencies.

## API documentation

```sh
cargo doc -p gnunet-dht-service-host --no-deps --open
```
