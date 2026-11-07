# Official GNUnet HELLO

Allocation-free, pure Rust HELLO address sets, signing, verification, blocks,
HELLO_URI/DHT messages and `gnunet://hello/` URLs for GNUnet v0.29.1. The library
has no default features, no allocator, OS clock, sockets, C FFI or unsafe code. Its only dependencies are the internal types, wire and crypto crates.

Callers provide byte storage, finite input/address/count limits, explicit UTC and
an explicit `SignatureProfile`. Addresses are public opaque byte URIs. Builders
sort in the C implementation's **descending** `strcmp` order and treat
addresses as a set; parser duplicates fail. Parsing does not authenticate data.

`HelloBuilder::sign` signs the exact purpose7 region using an owner-held Ed25519
key. `Hello::verify_at` checks signature, then expiration, and returns the precise
`SignatureCoverage` plus the observation time. The normal official build hashes
**SHA512(empty)** and does not bind addresses. Its result is `MetadataOnly`. `DeterministicPidDerivation` is the official conditional compilation alternative;
it hashes descending NUL-delimited addresses and yields `MetadataAndAddresses`. The verifier never tries an alternate profile after authentication failure. Neither result is a network capability or a durable future validity guarantee.

`parse_block`, `parse_message` and `parse_url` canonicalize into caller scratch
storage. Scratch may change on failure; no partially parsed value is returned. Binary message parsing follows the normal C parser by ignoring reserved/count
fields and computing the address count. Encoding emits zero reserved bits
and the true count, checks all lengths first, and leaves output unchanged on
refusal. Raw blocks support caller-bounded sizes beyond a message's 16-bit width.

All timestamps are absolute microseconds. Expiration equal to `now` is valid. `default_expiration(now)` adds the official two-day lifetime with saturation. Representation constructors preserve zero rather than consulting a hidden clock;
to reproduce C's zero-expiration builder convenience, pass
`default_expiration(now)` explicitly when the supplied expiry is zero.

URL formatting/parsing reproduces C Crockford aliases/tail bits and percent
encoding, including its unusual treatment of opaque byte sequences. C formats a
space as `+` but parses `+` literally, so textual roundtrips can change an address. Percent-decoded NUL truncates the effective C-string address body. Rust rejects
truncated percent triplets, embedded literal NUL and decimal overflow safely;
the C implementations may access freed storage or have undefined conversion
behavior on such malformed inputs. See [UPSTREAM.md](UPSTREAM.md) for all 30 API
mappings and intentionally safe differences.

Run `cargo test -p gnunet-hello` and `cargo clippy -p gnunet-hello --all-targets`. For live bidirectional testing, build the **unmodified** official Meson target
`test_hello_uri` into a separate directory, then run:

```sh
python3 crates/gnunet-hello/tests/normal_c_oracle.py \
  --source /path/to/clean/pinned/gnunet \
  --build /path/to/normal/meson-build \
  --deterministic-build /path/to/separate/conditional/meson-build \
  --deps-prefix /path/to/dependencies \
  --output /path/to/new/proof-directory
```

The conditional build uses `-DHELLO_DETERMINISTIC_PID_DERIVATION=1` in its real
Meson `c_args`, preserving any dependency include flags. The oracle verifies the
source revision, compiler macro profile, generated configurations, normal
library symbols/hashes and Rust inputs. It compiles a C driver against the real
shared libraries, regenerates deterministic C outputs, runs Rust tests
against those outputs and a nonempty live C behavior corpus, and sends Rust
outputs back through both C profiles. It never edits or rebuilds the supplied
reference builds. Reports describe this HELLO boundary, not whole GNUnet readiness.

The live corpus separates C's `noverify` argument from the Rust verifier step:
raw blocks and HELLO_URI can retain bad signatures or expired timestamps when C
is unchecked; DHT still verifies inside its C conversion even with `noverify=YES`. The equivalent Rust DHT pipeline includes `verify_at` in those cases. Both profiles
exercise wrong external peers, correctly self-declared short message sizes,
reserved/count normalization, and exact callback peer/URI sequences. The script
compares the C subset/prefix relation traces against Rust results, including
empty and self subsets, deletion, required-size queries and unchanged short outputs. Default expiry is captured from each C serializer, checked against a real
before/after clock window and the numeric lifetime, and reproduced byte-for-byte by
Rust with the corresponding explicit caller time. This also demonstrates that a
serializer does not re-sign metadata when defaulting expiration.

Rustdoc includes three rejected examples with valid positive counterparts:
mutating a builder while an address is live, overwriting live parser scratch, and
forging `VerifiedHello`. Positive tests show reuse after borrows end, input and
parser destruction before independent copies are used, and signing-key destruction
before public signature verification. No C pointer/free ABI equivalence is claimed. The conditional reference covers HELLO hash/signature and representation behavior;
it does not establish PILS identity derivation or the whole conditional GNUnet mode.

The opaque URI scheme validator follows [RFC3986 section3.1](https://www.rfc-editor.org/rfc/rfc3986#section-3.1): an initial ASCII letter, then ASCII letters/digits or `+`, `-`, `.`. It preserves original URI bytes and the existing wire, ordering, signatures and payload opacity. This admits the official HTTP/3 communicator's `http3` prefix. The pinned official C `hello-uri.c::check_address` permits only letters/plus, contradicting that built-in producer; Rust previously copied this defect and rejected HTTP/3 address publication. Leading punctuation or digits correctly fail URI syntax. No fallback scheme, altered signature profile or private address format is introduced.

This explicit reference difference means an unchanged affected C HELLO parser can still reject a valid `http3` address. Correct Rust parsing alone does not establish C HTTP/3 interoperability. Normal publishers/consumers depending on HELLO must be rebuilt from the corrected source before their runtime qualification; old binary receipts keep their original parser behavior. The dedicated regression uses a fixed public test seed and signing/verification plus binary and URL roundtrips; it supplies no native C/network acceptance.
