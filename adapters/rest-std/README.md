# REST host

Executes owned REST requests through explicit GNUnet service clients. Caller-owned instances and endpoint selectors share one clock; each execution owns its clients and preserves original cancellation and error outcomes.

## Interfaces

| Boundary | Reference |
| --- | --- |
| Request execution | [Contract](API.md#request-execution) |
| Configuration and GNS sources | [Contract](API.md#config-and-explicit-gns-query-source) |
| Optional OpenID provider | [Contract](API.md#conditional-oidc) |

## Configuration and integration

The [service or application guide](../../apps/gnunet-rest-server/README.md) owns executable configuration
and startup. The [API reference](API.md) documents constructor inputs, limits,
cancellation and cleanup requirements.

## API documentation

```sh
cargo doc -p gnunet-rest-host --no-deps --open
```
