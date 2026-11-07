# Official GNUnet IDENTITY core

This independently written Rust component implements the active IDENTITY
IPC semantics of GNUnet v0.29.1, revision
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`. The wire module lives in
`gnunet-wire::official::identity`. Private disk layout and internal state are
separate from that official local protocol.

The active operations are START624, RESULT_CODE625, UPDATE626, CREATE629,
RENAME630, DELETE631, LOOKUP632, and LOOKUP_BY_SUFFIX633. This revision's public
header and active message handlers have no default-ego get/set operation. Old
comments and residual default-map housekeeping do not define another message.

CREATE sends BE16 name length including NUL, BE16 key length, serialized key,
then the name. UPDATE sends name length, end flag, key length and reserved fields,
then optional name and serialized key. An ordinary key is BE32 type65536 (ECDSA)
or65556 (EdDSA), followed by32 opaque bytes. Deleted updates still carry the key
and have name length0. Present empty names have length1. START ends its initial
inventory with exactly12 bytes, name/key length0 and end flag1. A failed lookup
returns RESULT_CODE200; a successful lookup returns one UPDATE, with no DONE.

The wire codec checks exact framing, every offset and supported key tag without
allocation or scalar operations. Outgoing names are canonical C strings. Malformed
zero lengths, interior NUL ambiguities and C out-of-bounds cases are rejected. C-ignored reserved fields are accepted on decoding and zero on encoding. Local
whole-write, preparation, and worker admission are never persistence receipts.

`SecretKey` owns zeroizing fixed storage, has redacted Debug, and provides no
ordinary Clone, Hash, equality, or implicit raw export. Sensitive copies for a
new snapshot are explicit; equality uses the existing constant-time primitive. Production generation consumes the caller's entropy port and applies the official
ECDSA clamping or unclamped EdDSA seed rule. Public derivation uses existing pure
cryptographic primitives. The anonymous EdDSA seed is the official published
constant (little-endian1); it does not import a private file. A borrowed wire view
cannot erase its owner's frame: native owners must use zeroizing receive/transmit
storage and omit raw frames and keys from diagnostics.

With the explicit `alloc` feature, `Core` owns one immutable committed snapshot
and at most one staged mutation. `Snapshot::clone` only retains an Rc reference;
it never duplicates key storage. Preparing a complete after-image copies secrets
only into separately zeroizing owners. All live historical snapshots share one
aggregate byte budget, including vector capacities, names and fixed key owners. The limit covers accounted snapshot allocations, not allocator metadata or public
normalization scratch. Native owners separately bound peer/output cursor counts. Name normalization scratch is bounded by configured maximum name bytes. Vec
admission is fallible; as with the rest of this workspace, small Rc control-block
allocation follows the process allocator's out-of-memory policy.

CRUD uses locale-neutral Unicode18 lowercase plus canonical NFD, corresponding
to `GNUNET_STRINGS_utf8_tolower` and the pinned libunistring1.5 dependency. The
public UCD18 archive hash is checked by `generate.py`; provenance and both Unicode
license notices are retained. Full default lowercase includes the contextual
Final_Sigma rule and the expanding dotted-I mapping. NFD reuses the existing fixed
normalization tables in `gnunet-idna`; a generic caller-scratch entry point adds
stable counting-sort ordering for long combining-mark runs, without changing
existing NFC or IDNA operations. Exact lookup follows C-locale ASCII-insensitive
`strcasecmp` and does not normalize the request. Suffix lookup is case sensitive,
uses a whole-name or dot boundary, and returns the longest stored suffix.

`begin` returns an official business rejection or an unforgeable original
transaction token plus a staged before/after view. The native backend serializes
the after-image into one bounded zeroizing body. Actual worker admission calls
`queued`; an durable private receipt calls `commit`. Commit swaps already
allocated state and allocates nothing. A known pre-publication failure calls
`abort`; an indeterminate admitted outcome calls `unknown`, which latches the
instance. The native owner must then physically close clients and recover actual
durable state into a new Core. A timeout cannot establish rollback. Losing the
requesting client after backend admission does not cancel its storage mutation.

The native owner supplies original-MQ FIFO, subscription cursors and bounded
notifications. Initialization retains one consistent snapshot and follows it
with changes. CREATE's success result precedes its broadcast UPDATE;
RENAME/DELETE broadcast before success, as in the official API. The C service's
premature CREATE success and ignored write/rename/delete persistence errors are
not copied: Rust success requires an durable completion. Distinct names
may contain the same opaque key, as the official service permits; no key hash
or secret-derived public identifier is introduced.

The default feature set has no allocation or operating-system dependency. The
core has no filesystem, socket, executor, private-key loading, or storage format. Native client/service, authorized root-key production and durable recovery
are separate adapters. The one focused pure model source uses only a published,
noncryptographic all-zero mock body, not generated secrets or key derivation. The focused
pure model passed for official framing, Unicode names, snapshot budgets and
transaction settlement. It uses only the public mock body described above.
