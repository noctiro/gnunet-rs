# Metadata artifacts and ownership

`metadata` implements the official v2 twelve-byte header, twenty-byte descriptors
and reversed variable payload. It borrows all inputs/workspaces, owns no codec,
and performs no allocation, file access or service operation. The source basis
is official `meta_data.c`, `gnunet_fs_service.h` and `compress.c` at commit
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`.

`decode` handles uncompressed bodies and complete zlib bodies through an explicit
`Inflater`. `decode_uncompressed` selects no codec. The Rust provider is
`gnunet-fs-codec::Inflate`, optionally exposed as `gnunet::fs_codec` by `fs-codec`.
Inflation checks the zlib stream, checksum, consumed input and exact declared
output length before returning a metadata view. Codec failure wipes the declared
plaintext scratch prefix. Framing, limits and scratch capacity are checked
before invoking a codec. Buffers remain caller-owned throughout.

`Mode::Strict` requires every declared entry and exact variable-payload
consumption. `ReferencePrefix` explicitly reports the first invalid entry or
unused payload, matching the reference's useful recovery boundary without
calling it complete. The original C deserializer breaks at an invalid entry
and returns its earlier container, including a non-null empty recovery if the
first entry is invalid. Envelope or zlib failure is a whole failure. A recovered
view retains its original descriptor-table offset and exposes only its accepted
wire prefix; its count is not a deduplicated logical-container count.

UTF8 and C_STRING values retain their complete terminated byte spans. The C
decoder checks the last NUL but does not establish Unicode validity or exclude
interior NULs; Rust exposes raw bytes, bounded C-prefix text and fallible UTF8
conversion separately. Binary can be empty. Names distinguish absent from
present empty. Serialization canonicalizes plugin/MIME names to their bounded
first C-string prefix and reports that normalization. Unknown type IDs remain
open u32 values; unknown formats are invalid entries.

`Set` is a caller-slot semantic import helper. Duplicate identity is type plus
exact raw data before filename normalization, as in the pinned C source. It can
enrich absent MIME or upgrade C_STRING to UTF8, while retaining the first plugin.
New records use stable descending data-size order. Filename types2/180 replace
backslashes only before the first NUL, using explicit caller storage and bounded
iteration. Repeated raw backslash filenames can therefore become two identical
normalized entries; the API does not silently change that ordering of operations.
No C linked list, mutable serialization cache or memory-management API is copied.

`plan` validates source records, prepares the reversed body and chooses a
complete full or partial selection before `Plan::write` touches final output.
Its caller supplies ordering, plain and coded workspaces plus a `Deflater`.
`plan_uncompressed` makes the Never policy explicit without selecting a provider.
Adaptive uses zlib only when smaller; Always requests a legal zlib member even
when larger, which is useful for complete branch verification. An unavailable
codec is a typed error, not successful compressed support. The reusable
`Compressor` requires the codec package's `alloc` capability, exposed through SDK
`fs-compression`. It actually allocates internal state; compression is not a
zero-heap claim. The protocol core and default inflater remain independent of it.

Full output includes every source record or refuses. Partial output tries stable
descending-data-size suffixes under an explicit trial budget, reports selected
source indices and omitted counts, and can emit a legal empty v2 container.
Every size check includes the twelve-byte header. Capacity, invalid input,
codec or work refusal yields no final output; scratch may have been written.
The original C compressed-fit branch and decompression helper have static
length-check concerns that are not emulated. Rust validates complete lengths.
Compression level/bitstream identity and the C cache's NO_COMPRESS timing are
not wire requirements; explicit Never is honored on every Rust operation.

An absent optional value is distinct from raw v1's recognized null marker and
present-empty v2. `write_absent`, `Plan::write_length_prefixed` and
`decode_length_prefixed` expose the official BIO-style big-endian u32 frame.
Other embeddings choose their true frame/null policy. Directory root metadata
rejects null in the reference; no global null-equals-empty conversion is applied.
The default coded/plain/item limits are caller policies, not universal wire
limits. The C BIO1MiB budget and compressed40MiB allocation guard are distinct
from directory and UBLOCK embedding budgets.

Rust tests exercise both wire forms with the provider, wrong lengths,
checksums, truncation, trailing bytes, partial/recovery reports, output limits
and reset/retry. Fresh original-C metadata acceptance remains required. These
local artifact APIs do not complete metadata extraction, directory/UBLOCK
composition, search, publication, download, storage, IPC or full FS/Node ownership.
