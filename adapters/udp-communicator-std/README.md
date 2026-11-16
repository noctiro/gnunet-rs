# UDP communicator host

Native replay journals and datagram sockets for the GNUnet UDP communicator. The `transport` feature adds TRANSPORT IPC, multi-peer driving and discovery; `pils-client` adds provenance-bound identity selection.

## Interfaces

| Boundary | Reference |
| --- | --- |
| Replay journals | [Contract](API.md#replay-state) |
| Sockets and operation owners | [Contract](API.md#datagram-and-driver-ownership) |
| Platform mechanisms | [Contract](API.md#native-platforms) |
| Discovery retirement | [Contract](API.md#discovery-retirement) |

## Configuration and integration

The [service or application guide](../../apps/gnunet-communicator-udp/README.md) owns executable configuration
and startup. The [API reference](API.md) documents constructor inputs, limits,
cancellation and cleanup requirements.

## API documentation

```sh
cargo doc -p gnunet-udp-communicator-host --no-deps --open
```
