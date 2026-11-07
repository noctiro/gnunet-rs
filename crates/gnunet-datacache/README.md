# Local DATACACHE library

This independently written Rust component implements the active local DATACACHE
contract of GNUnet v0.29.1, revision346358e26d4dcc2dc4f51bef5d52dca29c7d8165. DATACACHE is a transient bounded local key/value library. It has no independent
wire, message registry, socket protocol or SERVICE. This crate invents none. Destroying its memory owner discards all content. It contains no DHT network
owner, resolver/host recovery, native runtime, crypto or key-loading operation.

The default noalloc API defines borrowed Block/PathElement metadata, a compile-time
replaceable Storage trait and Cache<S> facade. It uses existing absolute-microsecond
and Error types. A caller can supply fixed-storage or other Rust backends;
there is no dynamic C ABI or SQL layout requirement. Storage operations return
results, and read/storage failure cannot be silently converted to zero
matches, a duplicate, or success. The explicit alloc feature supplies Memory.

Active functionality includes put, exact get with typed/ANY matching,
count-only and early-abort visitation, bounded get_closest, explicit expiration,
quota eviction, clear and ownership-based destruction. Payload, type, route flags,
truncation peer and every public path signature/predecessor field are retained
exactly; this cache neither authenticates nor interprets them. Block Debug omits
payload, paths and key bytes. There is no hidden crypto hash or random entropy.

Same key/type/payload is a duplicate as in the heap implementation. Duplicate
returns equivalent GNUNET_NO0 and retains the maximum expiration together with
one complete caller-supplied path/truncation/options context. A valid duplicate
with an earlier expiration preserves the entire existing context without a new
path allocation or eviction. Equal or later expiration adopts the incoming
context and reuses its payload and an already sufficient path buffer. Purpose-6
DHT path signatures bind expiration, so an old expiration cannot be combined with
a path supplied for another expiration. The C heap makes that mixed update; Rust
does not copy it. This library still treats all metadata as opaque and performs
no signature operation. The normal Rust DHT has its own cache and already keeps
its contexts intact; this is a local-library correction, not evidence of a
current DHT-network failure. The original proximity hint stays attached to
the same key/value. A new value returns equivalent GNUNET_OK1. Too-large,
expired input and resource failures remain errors. Equality with is
still valid; only expiration<is expired, matching the SQL predicates.

Exact lookup returns unexpired values with freshest expiration first. Numeric
unknown block types and route bits are preserved; block type0 is ANY for queries. Results borrow one immutable storage owner, so safe Rust cannot mutate that owner
while a result or its iterator remains borrowed. Counts preserve backend errors;
a visitation count includes the item on which the callback requests a stop.

The public closest-query documentation describes numerically close circular
successors and asks for num_results. Memory uses portable lexicographic64-byte
key order (as the SQL BLOB keys), starts at key>=target, wraps once and returns at
most the requested number of unexpired typed results. Equal-key values
are freshest first, and no entry repeats on wrapping. A limit0 query is empty. This is a local ring scan, not an XOR-routing or network-replication operation.

The pinned C sources disagree internally: the plugin header describes up to2N
predecessor/successor results, SQLite uses a two-sided UNION, while the public
library header describes circular successors/N. Heap get_closest uses an
uninitialized N-sized array as2N entries and can write/read out of bounds. Its
hash comparison is also host-word/endian-dependent, unlike SQL BLOB ordering. Those implementation defects and inconsistent internal limits are not copied. The Rust contract above is explicit; this is not a claim of byte-for-byte C
plugin/ABI behavior or a new protocol compatibility mode.

Memory preallocates stable value slots, a sorted key index, free-slot stack and
quota-selection workspace. Query startup is logarithmic; reading matches and
clockwise scans allocate no heap memory. Metadata insertion moves slot indexes,
never payload/path buffers. Normal one-victim pressure uses a linear minimum
scan; multi-victim pressure sorts a single bounded batch, avoiding repeated
scan/remove passes. Explicit expiration scans fixed metadata and drops expired
buffers. Priority is expired first, then the supplied proximity hint, expiration
and original insertion serial, corresponding to the SQLite eviction
intent. There is no optional bloom file or hidden filesystem side effect.

Quota includes capacities of every fixed metadata vector, payload buffer
and typed path buffer. This fixes the C plugins' omitted path-memory charge. Value size, path length and live value count have independent explicit limits;
no u16 IPC restriction is imposed on this local API. All fallible admission work
and victim selection precede effects. An oversized single item is rejected
before eviction, fixing the C insertion/quota assertion failure. A successful
admission may actually evict other values and returns their count.

The quota covers retained cache allocations, excluding allocator headers and
bounded sorting stack. Atomic admission can temporarily hold one candidate's
new payload/path before old victims are removed; that candidate is separately
bounded by the same payload allowance. Common duplicate payload and sufficient
path storage need no second copy/allocation. No unbounded stale heap entries,
per-query vectors, shadow cache or generated identifiers are retained.

The pure model cases use fabricated public tags, opaque data and path metadata. They cover newest-first/ANY lookup, complete duplicate expiry/path-context
selection, strict expiry, circular bounded scan, quota eviction, refusal, clear
and storage-error propagation. These cases cover the local library contract;
cryptographic and DHT/network acceptance requires evidence from those owners.
