# Core libraries

Protocol engines and reusable foundations live here. Native I/O belongs in
[adapters](../adapters/README.md); executable composition belongs in
[apps](../apps/README.md). Shared dependency and ownership rules are in
[Architecture](../ARCHITECTURE.md).

## Public Rust API

Start with the [gnunet facade](gnunet/README.md) for feature selection and API
paths. Package READMEs describe their contracts; Rustdoc documents individual
types and methods. Build a package's API reference with:

```sh
cargo doc -p gnunet --no-deps --open
```

## Protocols and foundations

| Area | Guides |
| --- | --- |
| Wire, types and resources | [Wire codecs](gnunet-wire/src/lib.rs), [types](gnunet-types/src/lib.rs), [resources](gnunet-resources/src/lib.rs) |
| Cryptography and identity | [Cryptography](gnunet-crypto/README.md), [session crypto](gnunet-session-crypto/README.md), [PILS](gnunet-pils/README.md), [IDENTITY](gnunet-identity/README.md), [REVOCATION](gnunet-revocation/README.md) |
| Connections and routing | [CLIENT](gnunet-client/README.md), [TRANSPORT](gnunet-transport/README.md), [CORE](gnunet-core/README.md), [CADET](gnunet-cadet/README.md), [DHT](gnunet-dht/README.md) |
| Communicators | [TCP](gnunet-tcp-communicator-core/README.md), [UDP](gnunet-udp-communicator-core/README.md), [QUIC/HTTP3](gnunet-transport-quic/README.md), [Unix](gnunet-unix-communicator/README.md) |
| Naming and DNS | [GNS](gnunet-gns/README.md), [records](gnunet-gnsrecord-text/README.md), [NAMESTORE](gnunet-namestore/README.md), [NAMECACHE](gnunet-namecache/README.md), [DNS](gnunet-dns/README.md), [DNSSTUB](gnunet-dnsstub/README.md) |
| Storage and files | [FS](gnunet-fs/README.md), [FS codecs](gnunet-fs-codec/README.md), [BLOCK](gnunet-block/README.md), [DATACACHE](gnunet-datacache/README.md), [PEERSTORE](gnunet-peerstore/README.md) |
| Set and multi-party operations | [SET](gnunet-set/README.md), [SETI](gnunet-seti/README.md), [SETU](gnunet-setu/README.md), [CONSENSUS](gnunet-consensus/README.md), [SCALARPRODUCT](gnunet-scalarproduct/README.md), [SECRETSHARING](gnunet-secretsharing/README.md) |
| Calls and messaging | [Conversation](gnunet-conversation/README.md), [Messenger API](gnunet-messenger/README.md), [Messenger core](gnunet-messenger-core/README.md) |
| Credentials and applications | [RECLAIM](gnunet-reclaim/README.md), [DID](gnunet-did/README.md), [ABD](gnunet-abd/README.md), [REST](gnunet-rest/README.md) |
| Network services | [NAT](gnunet-nat/README.md), [VPN](gnunet-vpn/README.md), [EXIT](gnunet-exit/README.md), [PT](gnunet-pt/README.md), [RPS](gnunet-rps/README.md), [NSE](gnunet-nse/README.md) |
| Supervision and testing | [ARM client](gnunet-arm-core/README.md), [ARM service](gnunet-arm-service-core/README.md), [TESTBED](gnunet-testbed/README.md) |

## Compatibility and checks

The [protocol contracts](../spec/gnunet/README.md) define compatibility;
[Implementation status](../IMPLEMENTATION_STATUS.md) tracks unresolved work.
Use the [test guide](../tests/README.md) for package checks and reference profiles.
