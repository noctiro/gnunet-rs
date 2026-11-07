# FS host

Native files, storage clients, task recovery and peer providers for the GNUnet FS
engine. Public contracts are documented in the [API reference](API.md).

| Area | Main interfaces |
| --- | --- |
| Local content | `Repository`, reusable `Buffers`, descriptor-anchored `OutputDir` |
| Service requests | `ipc::Client`, block lookup, LOC signing, indexing and unindexing |
| Transfers | Authenticated file/range/tree download and full/indexed publication |
| Search | Keyword/namespace sessions, probes and retained observations |
| Durable tasks | Download, publication, search, probe and unindex tasks; bounded catalog worker |
| Providers | DATASTORE, CADET, GAP/CORE and DHT serving/routing |
| Metadata | Shared extraction, keyword preparation and offline inspection |

The `service` feature enables native FS requests; `network` adds publication.
The facade exposes local hosts through `official-fs`, clients through
`official-fs-client` and publication through `official-fs-network`.

Operations retain their source, deadline, partial effects and cleanup outcome.
Unknown storage mutations are not automatically replayed. Output uses held
parent descriptors and no-clobber commits. A verified range does not certify
unselected content; a local write does not certify remote delivery.

See the [CLI guide](../../apps/gnunet-cli/README.md) and
[FS service configuration](../../apps/gnunet-service-fs/README.md).
