# FS public artifact contract

Target: official GNUnet v0.29.1, revision
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`.
Reference inputs are the unmodified public FS header, `src/service/fs/fs_uri.c`,
`fs_api.h` and util string/signature primitives. They are protocol discovery and
behavioral interpretation sources, not production dependencies or Rust API shapes.

| Artifact | External data |
| --- | --- |
| CHK | Exact `gnunet://fs/chk/` prefix; two103-character Crockford SHA-512 values, dots, decimal u64 file length |
| SKS | Exact `gnunet://fs/sks/` prefix;52-character namespace key; first slash separates a literal remainder that may be empty |
| KSK | Exact `gnunet://fs/ksk/` prefix; plus-separated encoded terms, percent bytes, leading mandatory marker, optional encoded quote syntax; marker-only `%2B` is one mandatory term |
| LOC | CHK data followed by dot,52-character peer key, dot,103-character signature, dot, expiration seconds; signature authenticates the184-byte purpose5 region |

Crockford normalization accepts case and O/0, I/L/1, U/V aliases. The final unused
padding bits are ignored by the reference. The formatter always emits uppercase
canonical alphabet. SKS identifiers are not percent-decoded or interpreted as
paths, URLs or DNS names. KSK payload remains byte-oriented and exact; metadata
Unicode normalization is a different FS capability.

The LOC signed region is BE32(184), BE32(5), BE64(expiration microseconds),
BE64(file length), key64, query64, peer32. Ordinary Ed25519 signs the entire
region without a private extra hash/domain. Creation rounds expiration to whole
seconds. Parsing authenticates the region but performs no current-time check.
A service consuming the claim must separately decide expiry and availability.

## Reference permissiveness and strict differences

The pinned `%llu` parsing accepts an ASCII whitespace/sign prefix, ignores a
suffix, wraps a negative in-range value and saturates a scan overflow in the
observed C profile. LOC input multiplies seconds with unsigned wrap. Rust
implements these bounded numeric behaviors without a host scanner. An oversized
LOC timestamp may be authentic under the wrapped microseconds but may not remain
authentic after the C formatter truncates to seconds. This is explicitly a
reference-permissive input property, not a normative requirement or canonical
round-trip guarantee.

Rust can authenticate and expose that reference-permissive wrapped timestamp,
but canonical `encoded_len`/`encode` reject non-whole signed microseconds with
`InvalidInput` before touching output. They do not copy the C formatter's lossy
seconds conversion. An own-key public API regression signs a 448384-microsecond
claim encoded with input seconds 18446744073710, verifies successful parse, and
requires both canonical output operations to reject it atomically.

A decoded NUL truncates the reference keyword payload. Nonempty prefixes such as
`a%00discarded` are preserved and format as `a`. Optional empty decoded terms
(`%00`, `a+%00+b`) and raw double quotes are explicitly rejected by Rust even
when C accepts them: canonical round-trip can lose a term or change its payload.
The separate strict-input comparison retains three differences `%00`,
`a+%00+b` and `a"b`, which format into an empty URI/term or an unparseable quote
sequence. No claim that every string accepted by C is accepted is made.
`%22%22` was a first-pass C/Rust mismatch; the optional-empty correction
is retained with its original failing comparison.

Marker-only `%2B` is a stable mandatory term with zero payload bytes. Official
`GNUNET_FS_uri_ksk_create_from_args` emits it for the nonempty arguments `+` and
`"+"`; C parse/format retains the mandatory flag and term count. Rust parses and
encodes this artifact and permits `Keyword::new(b"", true)` to express it without
copying the C command-line constructor API. The original candidate incorrectly
rejected this term; its failing generator comparison remains separate historical
evidence. `Keyword::is_empty` describes payload bytes, not the URI's term count.

Malformed or truncated percent escapes must have two hexadecimal digits. The C
scanner's under-specified reads and unsafe quoted-separator counting are not
emulated, nor executed as foreign stress inputs. Rust safely handles balanced
encoded quotes and enforces a bounded keyword count and decoded length. Raw NUL
inside a length-delimited URI is rejected rather than hiding an unchecked suffix.

## Content block and bounded tree format

The same pinned revision's `fs.h:41`, `fs_api.h:44`, `fs_tree.c:320–424` and
public `GNUNET_FS_hash_to_symmetric_key` in `fs_api.c:3342` define the local
content-artifact format. DBLOCK plaintext is at most32768bytes. IBLOCK plaintext
contains1..256 ordered128-byte entries, each key64 followed by query64, with no
header or count. SHA512 of plaintext is the key. The historical GNUnet HKDF
derives32key bytes with salt `Hash key derivation` and24nonce bytes with salt
`Initialization vector derivation`; neither label includes a NUL or extra info.
The current `crypto_symmetric.c:245–296` implements XChaCha20-Poly1305 IETF
detached, with empty AAD in FS. The tag16 is appended; SHA512 of ciphertext plus
tag is the query. Older AES/Twofish content descriptions do not specify this
pinned format.

The initial file-tree API explicitly supports at most256 data leaves (8MiB).
Zero bytes require one empty DBLOCK,1..32768bytes use one data root, and larger
supported files use one index root with exactly ceil(filebytes/32768) children.
An exact8MiB file has256 full leaves, not an additional empty leaf. Standalone
one-child IBLOCKs remain representable as blocks. There is no type header/AAD:
the same128 plaintext bytes are also a valid128-byte data-root file. Small-file
layouts interpret the root as data; a mismatched claimed length is rejected,
and the file encoder adds no index wrapper for a single leaf. Geometry, query, tag and
plaintext-hash checks are distinct; the test design includes a forged valid
query/tag under material derived from a different plaintext hash.

Public FS tree encoder/decoder buffer oracles have not been identified:
`fs_tree.h` explicitly describes its exported tree API as internal. Public hash,
FS key derivation and generic AEAD calls can establish primitive observations;
an independently orchestrated composition must be labeled as such. No C FS tree
or download acceptance is implied. Static inspection also found inconsistent
size/tag offsets and index ciphertext alignment checks in the pinned
`fs_download.c`; that downloader is not an oracle for this pure buffer stage.
No service/download execution is used to investigate it.

## URI validation scope

Pure tests cover exact hash/length fields, literal namespace identifiers,
keyword flags/order/duplicates and limits, capacity-atomic serialization, signed
region order/time units, changed signed fields/signatures and expired artifact
verification without a clock. SDK and noalloc fixtures instantiate this actual
code on the declared embedded compile targets. These are library compilation
checks, not physical-device RAM/stack/performance or complete node results.

The offline counterpart compiles two original unmodified FS translation units
(`fs_uri.c`, `meta_data.c`) and links the existing normal util/Unicode libraries.
It calls only public pure URI parse/format/construction functions, not a URI CLI
which might download. It is not a full C FS library or service build. Both
implementations construct LOCs, parse each other's artifacts and reject
changed signed fields. Runtime file-backed images are hashed; shared-cache image
UUID observations are not claimed to be file-content verification. The Rust
test observer loads no GNUnet C library; production Rust never calls C.

Full FS publication/search/download, metadata extraction/query tokenization,
deeper content trees, service IPC and network ownership remain required.
Internal C equality/hash-map keys, allocation layout and helper function counts
are not external interoperability requirements. No external-release status,
unknown-inventory count, full FS or Node completion is promoted by this component.
