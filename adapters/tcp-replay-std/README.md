# TCP replay storage

This adapter owns the public replay catalog for GNUnet TCP handshake,
acknowledgement and rekey timestamps. It uses the shared snapshot `TransportTcp`
namespace and one bounded worker. The catalog contains a local peer, public
LedgerId, bootstrap phase and sorted `(remote peer, ReplayKind, maximum stamp)`
records. It stores no keys, ciphertext or nonce history.

## Public interface

`Ledger::open(directory, local, limits, frontier)` requires an existing paired
frontier intent. `bind_frontier` completes bootstrap. `catalog` exposes a borrowed
catalog; its lease retains the original authority for epoch pairing. `submit`
accepts a timestamp only after the caller has verified the original session's
signature. The caller polls the original token to completion and matches its
peer, kind and stamp before authorizing a session effect.

A strictly smaller received timestamp is refused; equality follows official
GNUnet behavior. Capacity exhaustion refuses new records without eviction.
Restore validates namespace, generation, exact length, count, identity, phase,
reserved bytes and unique ordering. In-memory capacity grows with actual records
up to the configured limit. Each new row reserves its slot before worker
admission, so installing a committed result requires no allocation. Serialized
buffers are erased on release.

`cancel` revokes business permission while preserving admitted filesystem work.
A committed canceled job advances the catalog and yields `Retired`, never a new
floor. Unknown outcomes fence the source without resubmission. `begin_close` is
clock-free; `shutdown` drains original outcomes and joins the worker, retaining
both the first failure and independent join/store errors. Worker Drop performs
emergency physical join and does not prove backend quiescence.

## Frontier pairing and recovery

The companion runtime first publishes a min0 frontier intent before creating a
ledger directory. It then commits empty Unbound generation 1, publishes frontier
min1 and commits Bound generation 2. Only the exact clean min0 intent permits
recovery of an interrupted first initialization. Bound catalogs require the
matching local peer, LedgerId and minimum generation. Missing, foreign or older
components never reset a floor. The private V2 frontier remains exactly 89 bytes;
V1 is refused without migration.

Frontier inspection uses a held native directory and the original private,
single-link file. It synchronizes the original file and directory, pins a
separate same-identity read-only handle and closes the synchronization handle
before capturing the full immutable read fence. Exact original bytes, EOF,
metadata and file/directory name bindings remain checked; failures never remove
canonical state. First catalog
creation uses the shared no-replace directory publication backend on Linux,
macOS, FreeBSD and Windows.

`Ledger::synchronization` and `CatalogLease::synchronization` expose the last
actual frontier and snapshot directory barriers. Windows reports `Unavailable`
and flushes the original file; this is not a directory crash-persistence
guarantee. These observations grant no replay, epoch or remote-effect authority.

## Runtime integration

The [TCP runtime](../tcp-runtime-std/README.md#persistent-replay-recovery) pairs
this catalog with its signed-time frontier and original clock owner. Every
PEERSTORE STORE waits for its exact worker receipt and frontier authorization.
A later remote REPLACE cannot lower the local maximum. A floor neither verifies
a signature nor proves session acceptance or remote storage.

The [normal executable](../../apps/gnunet-communicator-tcp/README.md) configures
`REPLAY_RECORDS` and `STATE_DIRECTORY`; embedding callers supply explicit limits
and absolute frontier paths. The paired files protect this deployment against
missing, foreign and older individual components. They do not protect against
hostile rollback of the entire trusted storage root. Protocol qualification and
release requirements follow the [central compatibility contract](../../spec/gnunet/compatibility.md).
