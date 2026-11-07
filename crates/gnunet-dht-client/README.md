# Official DHT logical client

The explicit `alloc` feature provides a caller-driven owner for the public GNUnet
v0.29.1 DHT client protocol: GET, known-result hashes, STOP, PUT, monitors and
HELLO observations/offers. The empty default is `no_std` without allocation and
exports the official borrowed codec and branded identity types. Native IO lives
in the independent `gnunet-dht-client-host` adapter.

`Instance` storage brands each client. Logical requests, physical MQ epochs and
immutable output attempts have separate private identities. Eight-byte GET IDs
are opaque protocol data; all zero is valid. An output must finish writing to
its original MQ or that MQ must be retired before calling `lost`. Cancellation
never swaps or truncates a frame that has already been issued.

After physical loss, GETs, known hashes, monitors and idempotent HELLO observation
intent can be reconstructed as fresh attempts. PUT and HELLO offers are never
replayed. A PUT completion means only that the complete original frame was
written locally; GNUnet has no public DHT PUT acknowledgement. Message 152 is an
upstream TODO and is not treated as an acknowledgement.

All retained metadata, source charges, known history and physical attempts are
bounded explicitly. Explicit known filters are admitted atomically. If optional
automatic history fills, results still arrive with `remembered=false`. Duplicates remain observable. Results, paths, monitors and returned HELLO URLs
are unverified observations. HELLO offers require a valid unexpired official
signature at caller-supplied UTC; v0.29.1 coverage is `MetadataOnly`, which does not
authenticate its addresses.

This is a client component. Its local IPC tests and single-node normal official
C-service interoperation do not establish cross-node R5N routing, block plugin
completeness or an entire GNUnet node implementation.
