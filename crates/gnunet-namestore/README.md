# NAMESTORE protocol core

Independent Rust NAMESTORE policy and state machines for the pinned official
GNUnet reference. The default build has no allocator, filesystem, tasks or clock. Labels use case-preserving Unicode18 NFC, reject dot/NUL and permit at most255
UTF-8 bytes. Caller-owned buffers hold normalized records and sorting indices.

## Public interface

Record policy handles private/maintenance filtering, critical record types,
exclusive delegations, relative/shadow expiry, apex nickname metadata and deletion
tombstones protecting the previous public expiry. Non-apex nicknames are
removed before validating a replacement set. Lookup normalization still validates
all retained records. The caller supplies the source time and record semantics.

Authoritative set constraints share the allocation-free GNS record policy:
supplemental records do not conflict with a primary delegation or redirection,
same-type SHADOW delegation/REDIRECT values may accompany one active value,
and GNS2DNS admits supported DNS connection-security records. These legal sets
survive NAMESTORE's appended supplemental NICK and ordinary ZONEMASTER's second
normalization. Multiple active delegation/REDIRECT values remain refused. Record-derived block expiry follows LSD0001/RFC9498 section6.3 (greatest lifetime
per type, then minimum across types), retaining the explicit tombstone floor. Strictly increasing expirations across previously sealed blocks require a
separate durable publication authority; a record-derived value is not one.

The default `fixed` API uses a caller-owned `Inventory`, `StoreScratch`
and `ReadScratch`. Choose the per-row byte capacity and the sort offset
capacity independently. Store and read operations serialize selected records
directly into their destination, without fixed descriptor tables on the stack.
A STORE stages only the changed label rows. Its publisher
borrows the complete after-image and confirms durable state before the
owner changes its inventory. An editor-only change borrows unchanged
record bodies and preserves the original serials. The host selects a
rendering buffer large enough for stored records plus a supplemental
nickname.

The `alloc` feature adds a bounded immutable authority inventory, staged provider
transactions, lookup/reverse lookup, advisory edit hints, snapshot iteration and
credited monitors. The edit response retains the live apex nickname and its
original flags and expiration. Opaque zone owners and record/hint bytes are
zeroized and have redacted formatting. Snapshots and committed changes share retained references
under one aggregate budget; no secret-derived key hash is used as an identifier.

A prepared transaction is not a successful write. Only the original provider's
commit can publish its after-image and response. Known abort and unknown
outcome remain distinct; unknown outcome permanently stops that core source. `single_tx` applies to one complete Store frame. Non-atomic validation errors can
commit a valid prefix; atomic validation failures publish nothing.

Iterators and monitors retain original source/cursor/write identities. NEXT
supplies credit, SYNC consumes none, and queued/written/remote processing are
separate facts. A stopped stream retains already queued debt until whole
write completion or physical source loss.

The wire codecs live in `gnunet-wire::official::namestore`; native clients live in
`gnunet-namestore-client-host`. This core does not itself persist records or start
a service. Native durable service source is supplied by `gnunet-namestore-host`; current
official C interoperability qualification remains open. Pure models use published mock bytes only.

Allocated after-images share immutable unchanged payloads and copy only row
metadata; a changed record/hint gets independent storage. Raw reverse queries can
retain the same payload allocation. Budgets still charge each retained logical
image conservatively, including shared allocation headers and capacities. Host record owners keep Send/Sync via Arc, with an Rc fallback on atomics-free
allocated targets. Row-directory scans/copy/sort and whole-snapshot persistence
remain; no new physical benchmark or hard process-RSS ceiling is claimed.
