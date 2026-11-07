# Directory artifacts and ownership

The wire follows pinned official `fs_directory.c` at commit346358e: magic8,
BE32 root-metadata length and raw metadata, then URI+NUL+BE32 metadata length and
metadata per entry. There is no entry count or terminator. Directory metadata is
mandatory present metadata; empty v2 is valid, absence/v1null are rejected in this
context. Full compressed and raw v2 artifacts use the existing metadata module
and an explicit caller-selected Inflater. KSK entries refuse; CHK, LOC and SKS
remain representable. `MIME_ITEM` is a canonical root MIME item; the parser does
not mistake a MIME claim for content authentication or require that claim.

`Parser` retains only one record in a caller-owned carry arena and lends each
event from that arena and caller decompression scratch. Whole-buffer and arbitrary
contiguous split input use the same state machine. Even whole-buffer input is
copied to the reusable record arena; this implementation does not promise a
zero-copy fast path. `Segment.base` must equal the explicit absolute cursor.
Only `Progress.consumed` bytes were accepted. Supply the remainder after every
event, even if the event consumed zero bytes. Known final extent is retained
across calls; without it, input end is NeedMore rather than Complete. A field
ending at known final EOF is Truncated. Zero-marker skips to the next absolute
32768-byte boundary; known terminal padding is explicit. Ordinary reading accepts
opaque skipped bytes like C, while `canonical_padding` requires zeroes.

NeedRecord and NeedPlain are retryable. `replace_buffer` copies retained bytes
before swapping caller carry; it never resets a partial URI or re-emits committed
events. A caller may need another growth request after learning a longer token's
length. Plain capacity refusal does not invoke the codec. Fatal errors include
the call's consumed byte count, absolute stop position and field stage; start a
new parser afterwards. Prior emitted entries stay accounted. Work limits charge
input copies/skips, URI validation, and declared metadata body bytes. These are
explicit logical work units, not a CPU/stack/RSS benchmark. Codec or later syntax
failures retain the metadata module's documented scratch-wipe boundary.

Entries and root events retain original raw coded metadata and exact URI bytes.
Decoded metadata retains every raw record. `Entry::uri` explicitly re-parses the
validated representation when a full URI value is needed, keeping large LOC
values out of every noalloc event. That accessor's additional signature work is
the caller's choice. For C logical collection semantics,
explicitly import through `metadata::Set`, then use its item order with `filename`,
`claims_directory` and `hints`. Import may normalize filename backslashes or
enrich duplicates; raw parse does not silently modify original values. Text
conversion remains fallible. Names remain untrusted bytes, including path-like
values. There is no filesystem write or path extraction in this core.

`from_boundary` starts at a caller-asserted entry boundary and retains missing
root coverage. `from_block` requires absolute block alignment and labels emitted
entry boundaries untracked. URI-looking bytes inside an unknown long record may
be false candidates. `recover_uri` skips an invalid URI to the next block boundary;
metadata ReferencePrefix preserves its exact recovery report. Such streams finish
Partial, never Complete. These statuses describe syntax coverage, not authenticated
source membership. Public `DataSlice` construction cannot mint source proof.

For authenticated reading, `content::FileReader` follows index references
from the chosen root and emits sealed `VerifiedChunk` views. `SourceParser`
accepts only matching chunks at its exact cursor and runs strict syntax parsing
from offset zero. Its sealed `VerifiedEntry` binds a record to the original
parent CHK. This is prefix membership: later malformed records, unresolved
children and filesystem output still need their owning operation to settle.
The two readers share reusable block/record buffers and bounded frontier slots;
they need neither a whole-file copy nor full source re-encoding.

`walk::Walk` schedules recursive file/directory jobs over caller-owned task slots
and namespace identifier storage. The host obtains work with `begin`, reads it
through FileReader/SourceParser, admits VerifiedEntry children and returns
the corresponding completion receipt. Namespace jobs remain explicit until a
namespace owner supplies their resolved content. Classification, shared-content
reuse and ancestor-cycle policy are caller choices. Depth, entry count, queued
work and total content bytes have independent limits; refused admission preserves
the original entry for retry. Growing storage preserves task identity. Retried
parent reads reuse retained entry ranges, and late attempts cannot finish a new
generation. Cancellation drains admitted originals before quiescence and never
becomes successful traversal. Empty-ready polling is constant time; task history
and shared-content lookup remain bounded by the caller's entry capacity.

Construction first materializes a metadata Plan into caller storage, or
strictly validates supplied bytes with the inflater, producing sealed
PreparedMetadata. Materialize each entry into a distinct caller arena through
PreparedEntry; reusing a borrowed metadata plan's mutable scratch for retained
records is not allowed by these lifetimes. `plan` borrows prepared records and
caller placement slots, checks u64 arithmetic, output extent, source/selected
entry caps and layout attempts, then reports selected source indices and omissions.
Full directory selection refuses instead of silently dropping records. Known
local metadata PART selections require `allow_partial_metadata` and are counted.
Externally supplied metadata has unknown selection origin, rather than a fabricated
claim that every original source item was preserved. Root and entry metadata
compression/selection are explicit metadata-planner choices. A caller adding the
root MIME must decide how to handle an existing conflicting MIME claim.

The deterministic builder preserves selected input order. Short records crossing
a block move to its next boundary; records longer than a block start at a boundary
and can span many blocks. Root metadata can also cross blocks. Zero-fill gaps are
canonical. C greedy packing, linked lists, cache choices and compression bitstream
identity are not copied. Final write preflights all local output capacity before
changing any output; trailing bytes remain intact. Layout workspace may change
on plan refusal. Output extent bounds final bytes; max_trials bounds entry layout
attempts, not the earlier metadata compression work selected by its own planner.

Type174 FULL_DATA items are raw InlineHints, without a global65536 parser cap.
All raw candidates and present-empty data remain visible; the caller can explicitly
apply C's first logical item projection. `verify_inline` requires resolved contextual
CHK/LOC Content and exact plaintext size, then actually encodes all data/index nodes
and compares both root hashes. `max_encoded_work` bounds theoretical output
bytes across the complete tree. Caller frontier/index/ciphertext buffers may change
on refusal; retry the operation with sufficient buffers. The private VerifiedInline
contains only successfully matched bytes and Content, with no path, availability,
expiry or durability credit. Namespace content must resolve separately.

VerifiedInline::item provides canonical binary type174 for an metadata
plan. `automatic_inline_fits` implements the optional positive-length <=65536 and
no-extra-entry-block producer heuristic using baseline/augmented metadata
lengths. It is separate from the parser, explicit hint insertion and publication
owner's `<65536` read policy. Compression is provided by the alloc-gated pure Rust
compressor; core and default inflation do not allocate.

Rust tests cover records up to two blocks plus one byte, real80KiB hints,
compressed/raw root-entry products, arbitrary contiguous splits, refusal/retry,
prefix recovery and complete inline trees through65537bytes. These are not
an original C directory comparison. Nested local artifacts can be inspected and
their inline CHKs verified. Source-bound reading and recursive scheduling are
implemented in the pure core; native transfer, namespace authentication, filesystem
anchoring/path/collision/link policy and owned-output handling remain necessary.
Directory draft cases and all FS/Node completion remain pending separate acceptance.
