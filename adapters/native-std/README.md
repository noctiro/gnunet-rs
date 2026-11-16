# Native platform adapter

Native socket, process, filesystem, identity, locale and device primitives used by the host adapters. Platform calls and unsafe ABI handling stay behind these ownership boundaries.

## Interfaces

| Boundary | Reference |
| --- | --- |
| Filesystem and processes | [Contract](API.md#anchored-filesystem-operations) |
| Network observations | [Contract](API.md#interface-snapshots-and-datagrams) |
| Locale and calendars | [Contract](API.md#locale-readers) |
| Native provider loading | [Contract](API.md#native-library-references) |

## Integration

The [API reference](API.md) documents native capabilities, errors and resource
ownership. Shared composition rules are in [Architecture](../../ARCHITECTURE.md).

## API documentation

```sh
cargo doc -p gnunet-native --no-deps --open
```
