# Native DATASTORE client and service

`gnunet-datastore-host` provides the native GNUnet DATASTORE client, service and
independent storage backend on Unix and Windows.

## Client interface

The client connects the allocation-free caller-buffer DATASTORE owner to the
shared native CLIENT channel. Construct `ProtocolClient` over
reusable `Slot` and `ReservationSlot` storage, then move it into `Client` with
one explicit `EndpointSource` and bounded frame/reply limits. No service or
background task is started.

Submit requests and call `drive` until the operation can be `take`n. `Taken` retains the STATUS/DATA/DATA_END bytes; DATA is already terminal. One physical stream has one request in flight. Partial input/output and original
deadlines survive dropped drive futures and observation timeouts. Reply storage
is reserved before the pure owner accepts a response.

Cancellation removes a leased frame only when framing proves zero written bytes. Written requests retain ownership while draining their reply or until
bounded physical retirement. PUT/REMOVE/replication can have uncertain effects
after loss and are never replayed. Reservation numbers belong to their original
connection; invalidated numbers cannot authorize a replacement MQ. Duplicate or
failed written PUTs still consume their reserved budget. DROP has no service ACK;
full write is unconfirmed and physically closes the dedicated connection.

`cancel_and_retire` supports cleanup without a new clock sample. It cancels the
original operation and physically retires its MQ/connection attempt; the last
validated canonical time is used only for retirement. Actual terminal replies,
other operations' loss/uncertainty and invalidated reservations remain available
to their original owners. An absent protocol epoch does not claim that no native
connection attempt existed. A later independent read may reuse the client with
a fresh request and original new bounds.

The SDK opt-in is `official-datastore`. It preserves caller-selected Resolver and
clock ports.

## Service interface

With `server` (SDK `official-datastore-server`), `server::Server` accepts shared
Unix/TCP listeners over the allocation-free `gnunet-datastore::Service` and any
explicit `Backend`. It starts one bounded, serialized storage worker. Each
socket retains its immutable original job and at most one reply; dropped waits
neither replay mutations nor replace streams. An uncertain commit closes the
physical MQ and fences all service clients. `shutdown` settles original work,
applies a requested DROP and joins the worker. Dropping the owner requests
termination without claiming filesystem quiescence.

A service reservation holds one quota balance: content bytes plus 256 bytes for
each estimated entry. PUT consumes its actual value size and entry overhead from
that balance. An underestimated or exhausted reservation can use ordinary free
quota; every other client's reserved balance still lowers the backend ceiling.
This accepts normal C FS publications whose estimate omits encrypted-block tags,
without unsigned underflow or treating entry estimates as write permissions.
Duplicate and failed PUTs consume the covered balance. Release and disconnect
return only the remaining quota; RIDs remain bound to their original connection.

## Storage and recovery

`backend::Store` is an independent native implementation: metadata
indexes, immutable UID value files, checksummed append WAL and streamed periodic
checkpoints. Values are arbitrary bytes under arbitrary keys. Duplicate identity
is key plus exact value; merges preserve UID/type/anonymity, saturate counters,
and take the latest expiration. Replication durably decrements before returning
the original score. PUT and required quota eviction share one atomic commit;
a bounded refusal does not partially evict. This internal policy and score
reporting profile do not copy every C backend's choice. Payloads stay on disk,
with one reusable selected-value buffer; configured record/log/transaction bounds
are separate from the official logical quota.

An uncertain WAL append retains its original cause and candidate sequence. `recover` or reopening explicitly settles complete transactions; a torn final
tail can be truncated, while complete corruption is refused. Snapshot replacement
retains original image handles and admits only the exact selected or pending
candidate during explicit recovery. Cleanup problems
after a durable logical commit remain available through `cleanup_failure`. The backend never opens or migrates C SQLite files or invokes a C service/FFI.

Storage roots must be private to the process user; existing public directories
are refused rather than silently changing their permissions. File-data
synchronization and logical WAL commit are distinct from naming
barriers. `Store::directory_sync` reports the last successful observation covering
the values directory, store root and its parent. Windows reports
`Some(DirectorySync::Unavailable)`; a pending naming operation or fenced store
returns `None`. Neither result claims a Windows directory flush.

## Configuration and examples

See the [service process](../../apps/gnunet-service-datastore/README.md) for
configuration and CLI use. External interoperability requirements are defined by
the [central protocol contract](../../spec/gnunet/README.md).
