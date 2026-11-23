# Applications

This directory composes core engines and native adapters into GNUnet commands,
services, communicators and helpers. Each executable's README owns its options,
configuration, dependencies and examples.

## Commands and supervision

| Task | Guide |
| --- | --- |
| General commands | [CLI](gnunet-cli/README.md), [command reference](gnunet-cli/commands.md) |
| Start and supervise services | [ARM command](gnunet-arm/README.md), [ARM service](gnunet-service-arm/README.md) |
| Run one embedded peer as a process | [Foreground node](gnunet-node/README.md) |
| Query local services | [Resolver](gnunet-resolver/README.md), [CORE](gnunet-core/README.md), [DHT](gnunet-dht/README.md), [DATASTORE](gnunet-datastore/README.md) |
| Identities and contacts | [PILS](gnunet-pils/README.md), [HELLO](gnunet-hello/README.md), [ECC](gnunet-ecc/README.md), [revocation proof](gnunet-scrypt/README.md) |
| Naming | [GNS](gnunet-gns/README.md), [NAMECACHE](gnunet-namecache/README.md), [zone import](gnunet-zoneimport/README.md), [proxy](gnunet-gns-proxy/README.md) |
| Calls and messaging | [CADET](gnunet-cadet/README.md), [Conversation](gnunet-conversation/README.md), [Messenger](gnunet-messenger/README.md) |
| Files | [Directory inspection](gnunet-directory/README.md), [automatic sharing](gnunet-auto-share/README.md), [FS service](gnunet-service-fs/README.md) |
| Local test environments | [TESTBED](gnunet-testbed/README.md), [TRANSPORT node](gnunet-transport-node/README.md) |

Run commands from the repository root with the pinned toolchain:

```sh
cargo run -p gnunet-cli --locked -- --help
cargo run -p gnunet-service-statistics --locked -- -c /path/to/gnunet.conf
```

## Services and communicators

`gnunet-service-*` packages provide service processes. Communicators have separate
[TCP](gnunet-communicator-tcp/README.md),
[UDP](gnunet-communicator-udp/README.md),
[QUIC](gnunet-communicator-quic/README.md),
[HTTP/3](gnunet-communicator-http3/README.md) and
[Unix](gnunet-communicator-unix/README.md) guides.

Shared startup and readiness rules are documented by
[PROGRAM](../adapters/program-std/README.md) and
[service startup](../adapters/service-startup/README.md). A service's guide lists
the dependencies that must be running before it can become ready.

## Network helpers and providers

[DNS](gnunet-service-dns/README.md), [VPN](gnunet-service-vpn/README.md),
[EXIT](gnunet-daemon-exit/README.md), [NAT](gnunet-service-nat/README.md) and
[audio](gnunet-helper-audio/README.md) select native providers. Their guides
describe permissions, device access and platform-specific configuration.

Current platform and interoperability limits are tracked in
[Implementation status](../IMPLEMENTATION_STATUS.md).
