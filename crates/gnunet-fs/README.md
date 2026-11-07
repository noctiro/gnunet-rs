# FS URI, content, metadata and directory artifacts

This pure `no_std`, allocation-free crate represents official v0.29.1 CHK, SKS,
KSK and LOC URI artifacts. `Uri::parse` borrows input; `encode` preflights the
caller's output. KSK terms decode lazily and explicit term lists borrow caller
storage. No OS, native runtime, service client, C FFI or implicit allocator is
part of the production dependency closure.

`Content` retains both64-byte hashes and a u64 file size. `Namespace` retains the
32-byte namespace key and the literal remainder, including empty identifiers,
slashes and literal percent characters. `Keywords` preserves order, duplicates
and mandatory flags. Literal constructors reject data that cannot round-trip
through the keyword URI grammar: NUL, quotes, an optional leading plus or empty
optional text. A mandatory term may have an empty payload: it counts as one term
and encodes as `%2B`, matching a stable artifact emitted by official constructors. `Keywords::from_user_text` adds a borrowed user-input view with balanced double
quotes and ASCII whitespace grouping. `from_user_args` instead preserves each
argument boundary and removes quotes without requiring balance, as the official
argument constructor does. Both retain literal percent/non-ASCII bytes, duplicate
terms and the initial-plus mandatory flag, with explicit aggregate/term/count
limits and no allocation. Neither performs locale or Unicode normalization. Optional empty terms and quoted optional leading-plus terms retain their actual
search meaning. The official KSK URI grammar cannot faithfully represent those
two states, so URI encoding explicitly refuses them; native searches can consume
the view directly without rewriting the query. Raw NUL input is explicitly refused. URI parsing is a separate choice and does not reinterpret keyword input.

Parsing safely preserves the reference's percent-decoded NUL truncation and
encoded quote syntax. Optional empty decoded terms (including `%00`) and raw
double quotes are rejected. C accepts some such values but canonical round-trip
can lose a term or change its payload. The three measured stricter inputs `%00`,
`a+%00+b` and `a"b` format into an empty URI/term or an unparseable quote sequence;
these boundaries are recorded separately from the common C comparison.

`Location` verifies ordinary Ed25519 purpose5 over exactly184bytes: the size and
purpose header, expiration microseconds, file size, key, query and peer key. Its
constructors take an explicit signing capability or verified external signature. Signing rounds expiration down to seconds. No clock is sampled: signature
validity does not prove current expiry, availability, possession or a connection. The text expiration is in seconds. The typed external-signature constructor
requires whole seconds so serialization retains the signed timestamp.

Crockford case aliases O/0, I/L/1 and U/V and unused trailing padding bits match
the reference. Its unsigned numeric-prefix parsing is also reproduced safely:
leading ASCII whitespace/sign, ignored suffix, negative wrapping and overflow
saturation. LOC's permissive input conversion wraps seconds to microseconds as
in that pinned source; such noncanonical inputs need not survive its own
canonical text normalization. These parsing quirks are implementation
compatibility, not a claim that the URI specification requires malformed input. Rust retains the authenticated claim when a permissive LOC timestamp wraps to
non-whole microseconds, but `encoded_len` and `encode` return `InvalidInput` for
that state before writing. Encoding never silently changes a signed timestamp. All `%` escapes require two hexadecimal digits. Truncated scanf-like reads and
unsafe quote-count behavior are not emulated. Fully explicit byte lengths reject
raw embedded NUL, rather than silently accepting a hidden suffix.

The SDK exposes `gnunet::fs`. The `metadata` module provides bounded v2 record
parsing, explicit reference-prefix recovery, value import and full/partial
serialization planning. Real zlib codecs live in the separate pure Rust
`gnunet-fs-codec` package. See [metadata ownership](METADATA.md) for compression,
allocation, null and malformed-input boundaries. Full publication/search/download,
metadata extraction and normalization, service IPC,
and network/Node ownership remain separate required work. URI artifacts alone confer no complete FS, network interoperability, platform
or performance-completion credit.

The pure `gap` owner also handles official FS peer GET137/PUT138 traffic. Incoming
GET Bloom hints contain a four-byte native nonce followed by the complete
power-of-two filter, from8 through32768 bytes. Small groups are inline. Optional
`alloc` enables fallible larger filters with an aggregate actual-capacity budget;
the default remains allocation-free and returns Capacity for oversized groups. Existing route merges do not allocate, and retained/retiring groups remain
charged until release. Ordinary local search IPC uses 64-byte seen hashes
instead. Normal outgoing peer hints are empty to accommodate the pinned C
checker's contradictory whole-tail length test.

The `content` module adds local DBLOCK and IBLOCK encode/open operations. The
plaintext hash derives the XChaCha20-Poly1305 key and nonce using the pinned
GNUnet HKDF labels. The ciphertext ends with the16-byte tag; hashing that whole
artifact yields its query. Opening checks the query, tag and plaintext hash. There is no type AAD, private domain or hidden format. Input/framing/capacity
refusal preserves output; authentication failure erases the plaintext-sized
output prefix. Plaintext, encrypted output and index scratch belong to callers.

`Layout` describes every u64 file length with at most8 levels, including the
data level. Span and endpoint arithmetic uses u128 before clipping to the file
length; global node ordinals remain u64 on32-bit targets. A zero-byte file still
has one encrypted empty data block. An index contains1..=256 ordered child
references, and partial tails retain every required single-child index level.

`FileEncoder` borrows `Layout::required_keys()` key slots and emits one actual
encrypted data or index block per operation. At most1538 key slots are reserved
across its per-level buckets, plus explicit caller plaintext/output buffers. Each data push accepts exactly the next leaf; a pending index must be emitted
before more data is supplied. Capacity refusal never advances progress or
changes the refused output. The separate `ReferenceFrontier` can assemble
unverified precomputed subtree references; it performs geometry only and grants
no hashing, availability or processed-file-byte credit.

`NodeRef::root` binds a CHK URI's key pair to its size-derived position. Opening
checks the exact payload length and every CHK layer before yielding an
`OpenedNode`. Authenticated parents yield unopened child references; every
child target still needs its own successful open. `RangeTraversal` requests
only nodes intersecting a caller-selected half-open range and advances only
after its exact pending node is authenticated. An empty range requests nothing
and authenticates nothing; an empty file's root can be opened separately.

`FileReader` drives the complete authenticated tree, including an empty file's
root, and returns sealed `VerifiedChunk` views bound to that original CHK. It reuses one plaintext block and caller frontier storage. `SourceParser`
consumes those chunks directly with the streaming directory parser and returns
`VerifiedEntry` capabilities for parent records. Public plaintext slices
cannot manufacture that source binding. Neither reader buffers or re-encodes
the complete file; the host supplies block retrieval and retains output as needed.

Rust tests distinguish file encoding and byte recovery through8MiB+1
from synthetic full-u64 geometry and selected authenticated paths with fake,
unvisited sibling references. Synthetic cases do not prove complete enormous
files or full file-sharing interoperability. Official C artifact comparisons
cover their recorded sizes and protocol paths.

These APIs provide no content repository, distributed lookup,
publication, persistence or streaming transfer service. Existing pure AEAD
primitives are reused from `gnunet-session-crypto` without selecting a session
owner or host runtime. The `directory` module adds checked full/segmented local
artifact parsing and construction, explicit partial recovery and inline
CHK verification. Its recursive walker owns bounded jobs, shared content,
namespace resolution requests, retries and cancellation over verified source
entries. See [directory ownership](DIRECTORY.md).

The `ublock` module constructs and verifies official keyword/namespace results,
including raw-byte labels, derived EdDSA signatures, query derivation, AEAD and
optional typed metadata. Contexts cache derivation work and keep their secrets in
zeroizing owners. Search/update scheduling, datastore operations and namespace
freshness belong to their service owners. Native local storage, streaming file
I/O and no-clobber authenticated output are in `gnunet-fs-host`; complete network
publication/search/download remains required work.

The normative format sources are the unmodified official `gnunet_fs_service.h`,
`src/service/fs/fs_uri.c`, `fs_tree.c`, `fs_tree.h` and `fs_api.h` at revision
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`. Observed C-internal hash-map/equality
helper behavior does not prescribe Rust data layout or APIs. The offline
`artifact_oracle` example is test tooling only; it does not download or publish.
