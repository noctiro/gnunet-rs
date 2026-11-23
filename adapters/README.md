# Native adapters

Adapters execute protocol effects using sockets, files, processes and platform
providers. They retain native resource ownership and translate observations back
to the [core engines](../crates/README.md). The shared layering and cancellation
rules are defined in [Architecture](../ARCHITECTURE.md).

## Shared infrastructure

| Boundary | Guide |
| --- | --- |
| Native files, processes, locale and network primitives | [Native adapter](native-std/README.md) |
| Listeners, credentials, framing, clocks and process supervision | [Service runtime](service-runtime/README.md) |
| Process preparation, activation and readiness | [Service startup](service-startup/README.md) |
| Commands, logging and bounded file/stdio work | [PROGRAM](program-std/README.md) |
| Configuration and anchored publication | [CONFIG](config-std/README.md) |
| Client connections and name resolution | [CLIENT](client-std/README.md), [Resolver](resolver-std/README.md), [broker](resolver-broker-std/README.md) |
| In-process peer composition | [Embedded peer](node-std/README.md) |
| Durable service images | [Snapshots](snapshot-std/README.md) |

## Domain hosts

| Area | Guides |
| --- | --- |
| Transport | [TRANSPORT service](transport-service-std/README.md), [runtime](transport-runtime-std/README.md), [CORE](core-std/README.md), [CADET](cadet-std/README.md) |
| Communicators | [TCP](tcp-runtime-std/README.md), [UDP](udp-communicator-std/README.md), [QUIC/HTTP3](quic-communicator-std/README.md), [Unix](unix-communicator-std/README.md) |
| Storage | [DATASTORE](datastore-std/README.md), [FS](fs-std/README.md), [PEERSTORE](peerstore-std/README.md), [STATISTICS](ipc-unix/README.md) |
| Naming | [GNS](gns-service-std/README.md), [NAMESTORE](namestore-std/README.md), [NAMECACHE](namecache-std/README.md), [ZONEMASTER](zonemaster-std/README.md), [zone import](zoneimport-std/README.md) |
| DNS and routing | [DNS service](dns-service-std/README.md), [Windows WFP](wfp-dns-std/README.md), [DNS2GNS](dns2gns-std/README.md), [TUN](tun-std/README.md), [VPN](vpn-std/README.md), [EXIT](exit-std/README.md), [PT](pt-std/README.md) |
| Discovery | [DHT](dht-std/README.md), [NAT](nat-std/README.md), [RPS](rps-std/README.md), [NSE](nse-std/README.md), [HOSTLIST](hostlist-std/README.md) |
| Multi-party operations | [SET](set-std/README.md), [SETI](seti-std/README.md), [SETU](setu-std/README.md), [CONSENSUS](consensus-std/README.md), [SCALARPRODUCT](scalarproduct-std/README.md), [SECRETSHARING](secretsharing-std/README.md) |
| Calls and messaging | [Conversation](conversation-std/README.md), [audio](conversation-audio-std/README.md), [Messenger service](messenger-std/README.md), [Messenger API](messenger-api-std/README.md) |
| Identity and credentials | [PILS](pils-std/README.md), [IDENTITY](identity-std/README.md), [RECLAIM](reclaim-std/README.md), [DID](did-std/README.md), [REVOCATION](revocation-std/README.md) |
| Supervision and test environments | [ARM client](arm-std/README.md), [ARM service](arm-service-std/README.md), [TESTBED](testbed-std/README.md) |

## Integration

Client adapters are named `*-client-std`; service and provider adapters document
their construction and shutdown requirements. Applications select concrete
providers and drive the retained owners. Configuration examples belong to the
[executable guides](../apps/README.md).

See [testing](../tests/README.md) for native checks and
[Implementation status](../IMPLEMENTATION_STATUS.md) for platform constraints.
