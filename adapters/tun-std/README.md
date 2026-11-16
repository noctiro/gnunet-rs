# TUN host

Caller-driven Linux TUN, macOS utun, FreeBSD TUN and Windows Wintun packet sources. Device identity, packet loans, route effects and cleanup retain separate ownership.

## Interfaces

| Boundary | Reference |
| --- | --- |
| Device qualification | [Contract](API.md#device-ownership-and-provisioning) |
| Whole-packet I/O | [Contract](API.md#packet-io) |
| Route and address effects | [Contract](API.md#native-address-and-route-execution) |
| IPv6 readiness | [Contract](API.md#read-only-ipv6-readiness-observation) |

## Configuration and integration

The [service or application guide](../../apps/gnunet-service-vpn/README.md) owns executable configuration
and startup. The [API reference](API.md) documents constructor inputs, limits,
cancellation and cleanup requirements.

## API documentation

```sh
cargo doc -p gnunet-tun-host --no-deps --open
```
