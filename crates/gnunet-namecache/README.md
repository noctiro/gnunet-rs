# Official NAMECACHE wire and ciphertext cache

This is an independent NAMECACHE component for GNUnet v0.29.1 pinned revision
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`. It implements the six active
messages and a bounded volatile encrypted-block cache. It has no GNS resolver,
zone-secret manager, record decryption, host recovery, DHT or native process.

The original repository supplied NAMECACHE message constants and complete public
`gnunet_gnscrypto::Block` decoding/query/expiration and zone-bound verification,
but no independent NAMECACHE IPC codec or storage core. Native transport/client dispatch and persistent service hosting
are separate work; this source candidate does not claim they exist or have passed
an interoperability run.

| Active message | Number | Exact fields after normal BE16 size/type header |
| --- | --- | --- |
| LOOKUP_BLOCK |431| BE32 original request id,64 query bytes |
| LOOKUP_BLOCK_RESPONSE |432| BE32 id, BE64 expiration, whole encrypted block |
| BLOCK_CACHE |433| BE32 id, BE64 outer expiration, whole encrypted block |
| BLOCK_CACHE_RESPONSE |434| BE32 id, signed BE32 operation result |
| BLOCK_DELETE |1850| BE32 id,64 query bytes |
| BLOCK_DELETE_RESPONSE |1851| BE32 id, signed BE32 operation result |

LOOKUP/DELETE requests are72 bytes, block prefixes16, result frames12. A lookup
miss is expiration0 with canonical empty body. The reference client ignores any
tail accompanying expiration0; the codec preserves that original body, and
`verify_lookup` follows the zero sentinel. A hit is one response, with no DONE. The official CACHE producer leaves outer expiration0, and the service ignores
that field: storage derives query and expiry from the enclosed block. There is
no wire cancel, initialization, success ACK beyond the two result frames,
or request replay instruction. Result values are signed and unknown values are
preserved. GNUNET_SYSERR=-1, GNUNET_NO=0, GNUNET_OK=GNUNET_YES=1.

Wire framing accepts the BE16 frame boundary (maximum enclosed block
65519 bytes). The public C API declares a63KiB maximum value; `Limits::default`
uses that value for cache admission. The live C MQ producer does not separately
enforce that declaration, so a caller can explicitly configure the core up to
the wire limit without introducing a different encoding. All length and
capacity checks precede writes in the wire encoder; decoding never dereferences
an unvalidated C block structure.

The default feature set is allocation-free. `verify_lookup` checks only public
material: exact block structure, original query equality, equal inner/outer
expiration and the official carried-key signature. Expiration0 remains a miss. `Block::verify_signature` factors the existing signature verifier into a public
entry point corresponding to `GNUNET_GNSRECORD_block_verify`; it does not assert
that a carried key is authorized for a zone/name. The old `verify_for` continues
to check its original zone/name binding before calling the same signature code. No plaintext is decrypted by the cache or native-client validation entry point.

The explicit `alloc` feature provides real `Cache::{insert,lookup,delete,
expire_before,handle}`. Queries are sorted for allocation-free binary-search
lookups. One metadata vector is reserved at construction; moving metadata never
copies payload bytes. Accounted metadata capacity plus ciphertext-buffer
capacities cannot exceed `Limits.bytes`. Distinct queries and individual blocks
also have explicit ceilings. Failed allocation/size admission leaves the cache
unchanged; no implicit unexpired eviction is hidden behind a successful result.

The official SQL backends delete versions with expiration less than or equal to
the incoming block, then insert it, and select the greatest expiration on lookup. The Rust core retains only that greatest version. A newer version cannot be
replaced by an older expiry; equal expiry uses the new bytes, and exact duplicates
need no new allocation. Lower-expiry rows cannot become valid after the greatest
version has expired, so retaining them would only waste bounded cache space. Deletion actually removes the query and reports its presence/absence.

Expiration is explicit, using the exact SQL predicate `expiration < now`; equality
stays valid. The native SQLite implementation schedules cleanup hourly during
cache calls; PostgreSQL cleans on each cache call. Their raw lookup has no
expiration predicate and can return a block awaiting cleanup. The pure core also
has no hidden clock: raw lookup does not invent a miss. A service owner must call
`expire_before` on its chosen maintenance schedule; the record consumer remains
responsible for trusted-time validity checks. UINT64_MAX remains the official
never value.

As in the service/database boundary, insertion parses structure and derives
the query/expiry, but treats ciphertext as opaque and does not prove signatures. Native clients check public signatures before accepting results. `handle` replies
only after the in-memory mutation finishes; resource rejection maps to
SYSERR, deletion absence to NO, and a hit contains stored
bytes. Malformed block input is an error for the original native owner to reject,
not a fabricated success or lookup miss. Memory success is never described as a
durable disk commit, remote publication, or a future backend receipt.

The single focused model uses the preexisting public encrypted-block/query
fixtures for both key constructions and covers public-only response verification,
exact frame layout, signed results, replacement, bounded refusal, expiry and
delete outcomes. Mutated expiry bytes appear only as opaque cache mocks,
not valid-signature vectors. It includes no private-input fixtures or key files. This pure model and one controlled Unix client model passed using only
the declared public ciphertext/query vectors. Native service/persistence qualification remains separate.

A replacement fitting the existing ciphertext capacity reuses that allocation
after full structural validation, keeping the same accounted capacity. Larger
replacements allocate fallibly before changing the old entry; allocation failure
preserves the original block. This bounds retained cache memory; transient growth
and allocator overhead are separate from that retained-memory budget.
