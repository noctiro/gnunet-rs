# GNUnet GNS cryptographic profile

The implementation and test oracle are bound to official GNUnet **v0.29.1**, commit
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`. Production is Rust only, `no_std`,
without heap allocation or unsafe code. Both official supported zone types are
implemented: PKEY (65536) and EDKEY (65556). The registered FAESTKEY codepoint is
not a supported key construction in this reference release.

Authoritative source functions:

| Source | Contract |
| --- | --- |
| `src/lib/util/crypto_hkdf.c` | HMAC-SHA512 extract followed by HMAC-SHA256 expand; ordered info slices have no added length/NUL framing. |
| `src/lib/util/crypto_ecc_gnsrecord.c` | `key-derivation` salt, original public key IKM, NFC label plus `gns` context; raw 64-byte hash interpreted big endian and reduced modulo L; PKEY and EDKEY private/public blinding. |
| `src/lib/util/crypto_ecc.c` | PKEY is ECDSA on Edwards25519, SHA512 and RFC6979, r/s big endian; EDKEY uses an expanded scalar and SHA256-derived nonce prefix with ordinary Ed25519 verification. |
| `src/lib/util/crypto_symmetric.c` | AES256 CTR with a big-endian 128-bit counter; tag-first NaCl XSalsa20-Poly1305. |
| `src/lib/gnsrecord/gnsrecord_crypto.c`, `gnsrecord_crypto.h` | 112-byte block header; signature purpose 15 over purpose/size, expiry and ciphertext; AES/XSalsa key and IV contexts; per-record filtering. |
| `src/lib/gnsrecord/gnsrecord_misc.c` | NFC normalization, publication set exclusivity, private/maintenance/expired filtering and shadow-extended block expiry. |

`gnunet-crypto::gns` is a low-level primitive layer; it requires an already
normalized label. `gnunet-gnscrypto::Label` performs complete NFC with explicit
caller scalar/UTF-8 buffers. There is no case folding, IDNA conversion, invented
cryptographic domain, or type prefix in the final query hash. The query is
SHA512 of the derived public key's 32 bytes.

`ZoneSecret::seal` accepts framed absolute public records. The owner must first
apply publication policy, for example with `prepare_publication_at`, and then
serialize via `gnunet-gnsrecord`. The helper supplies explicit UTC and a
critical-type callback corresponding to the official plugin registry; relative
expirations become saturating absolute times before encryption. It omits NICK
at the apex (`@`) because that is the pinned C conditional, despite the
opposite wording in its adjacent comment. Extension types/flags are retained.

A structurally decoded `Block` is untrusted. `verify_for` checks the carried
key against the **requested original zone and NFC label**, then validates the
signature and returns a `VerifiedBlock`. Only this type exposes decryption.
`open_at` checks block expiry, authenticates before releasing plaintext, checks
all record framing/padding, and returns an iterator that applies record expiry
and shadow fallback. Trusted UTC and publication authorization belong to the
host. Caller storage bounds normalization, plaintext and wire output; the
reference limits of 63 KiB plaintext and 2048 records are enforced.

## Deliberate boundary checks relative to the C API

The C `block_verify` checks the carried key's signature without zone/name
binding. Its separate `open` API does not call signature verification. Rust
requires both before decryption. C's resolver mutates its record array while
selecting shadows, and a sole expired shadow bypasses an expiry check inside
an empty inner loop. Rust filters from the immutable original set, always
rejects expired shadows, and ignores relative records as active competitors.
These affect malformed or expired inputs; they do not change any valid wire
encoding. Block-expiry equality and per-record-expiry equality are valid.

Secret owners do not implement Clone/Debug or export key bytes. Seeds, derived
scalars/prefixes, expanded key material, RFC6979 K/V, HMAC PRK, symmetric keys
and Poly1305 one-time keys use compiler-resistant zeroization. HMAC orchestration
uses RustCrypto SHA-2 with explicitly erased padded keys and intermediate digests;
this avoids the un-erased derived-key temporary in hmac 0.13. Both SHA-256 and
SHA-512 HMAC paths match RFC 4231 short-key and hashed-long-key vectors. Caller-held
copies and persisted secrets remain the host's responsibility. This does not
claim immunity against compiler spills or a compromised host.

## Unicode data and licensing

The reference `libunistring` **1.5** reports Unicode **18.0.0** through
`_libunistring_unicode_version == 0x1200`. This is an explicit normalization
profile, since GNUnet's normalization implementation inherits its runtime
libunistring version. Generated canonical data uses these official sources:

| Input under `https://www.unicode.org/Public/18.0.0/ucd/` | SHA256 |
| --- | --- |
| `UnicodeData.txt` | `0736451de439ae7baf1425136617da495e09ee5afbe6e394374db7009ea08950` |
| `DerivedNormalizationProps.txt` | `98ac7f67d985fe781e317f6182e885e94cabb0c314769e6dd73e48b226931ccd` |
| `NormalizationTest.txt` | `25a50d816764b04abfb4a646d3eb2b2a803284c3873d9a06757b94fe4513dde3` |

Unicode License V3 is retained at `third-party/UNICODE-LICENSE.txt` (downloaded
from `https://www.unicode.org/license.txt`, SHA256
`e7a93b009565cfce55919a381437ac4db883e9da2126fa28b91d12732bc53d96`).
`tools/generate_nfc.py /path/to/ucd` checks these hashes and reproduces
`src/nfc_data.rs` and `tests/fixtures/normalization-18.bin`: 1002 nonzero CCC
entries, 2081 canonical decompositions, 961 compositions, and **20171 official
conformance rows / 100855 NFC transformations**. Hangul composition and
decomposition are algorithmic. No Unicode normalization dependency or allocator
is linked into production.

## Independent normal C oracle

`tests/reference/gns_vectors.c` uses normal unmodified reference shared
libraries; it does not extract/replace cryptographic functions. It generates
ASCII and decomposed Unicode cases for **both** PKEY and EDKEY with fixed
public synthetic keys. Fixtures cover the raw blinding hash, reduced scalar,
derived private/public bytes, symmetric key/nonce, complete signed/encrypted
block, query and decrypted records. The normal upstream
`test_gnsrecord_testvectors` also passed its four independent published cases.

Run `tools/reference_oracle.py --source SOURCE --build MESON_BUILD
--prefix RUNTIME_PREFIX --output NEW_OUTPUT_DIR --cflags 'DEPENDENCY_CFLAGS'
--ldflags 'DEPENDENCY_LDFLAGS' --unicode-data UCD_DIRECTORY`.

The normal Meson build must provide `libgnunetutil`, `libgnunetgnsrecord` and
the normal GNS/DNS record plugins; its runtime prefix must contain matching
libraries and `share/gnunet/config.d`. The runner checks clean official HEAD,
normal build/staged library hashes, compiles test-only C drivers, compares
fresh C output with the fixtures, invokes Rust complete-block conformance
while exporting its sealed blocks to the owned output directory, then
uses `accept_block.c` to verify/query-bind/decrypt those Rust outputs through
normal GNUnet APIs. C verifies and opens **four** Rust blocks with exact record
plaintext; Rust verifies and opens all four C blocks. When given the pinned
Unicode data, the C normalizer must match all 100855 transformations. Command
exit codes, output hashes, source/header hashes and reference library hashes
are retained in `result.json`; the runner makes no public network connection.

Rust tests additionally reject each single-byte block mutation, wrong type,
zone, label and purpose, truncation, expired lifetime, bad secretbox tag even
with a valid zone signature, malformed authenticated plaintext/padding, excess
record count, and inadequate caller storage. They check publication rules and
buffer preservation/erasure. These are component-level cryptographic and GNS
block interoperability tests, not an end-to-end resolver/DHT/network claim.
