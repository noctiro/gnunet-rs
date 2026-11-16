# TRANSPORT host

Native IPC serving around the bounded TRANSPORT engine. Server retains accepted sockets, frame storage, partial-write cursors and fair I/O scheduling across canceled waits.

## Interfaces

| Boundary | Reference |
| --- | --- |
| Framing and storage | [Contract](API.md#native-framing-and-storage) |
| Native retirement | [Contract](API.md#original-native-retirement-observations) |

## Configuration and integration

The [service or application guide](../../apps/gnunet-service-transport/README.md) owns executable configuration
and startup. The [API reference](API.md) documents constructor inputs, limits,
cancellation and cleanup requirements.

## API documentation

```sh
cargo doc -p gnunet-transport-host --no-deps --open
```
