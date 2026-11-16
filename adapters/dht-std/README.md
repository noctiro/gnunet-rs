# DHT service host

Composes the DHT protocol owner with CORE, PILS, HELLO, local IPC and optional direct-IP transport. The caller owns listeners, clock, Resolver, instances and entropy.

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

## API documentation

```sh
cargo doc -p gnunet-dht-service-host --no-deps --open
```
