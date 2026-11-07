# GNUnet v0.29.1 HELLO correspondence

Pinned source: `346358e26d4dcc2dc4f51bef5d52dca29c7d8165`.
The public `src/include/gnunet_hello_uri_lib.h` declares 30 functions, one callback
and two opaque types. The normal built `libgnunethello` exports exactly those 30
function names. This is an API coverage obligation, not proof from a function count.

The implementation is derived from the behavior of `src/lib/hello/hello-uri.c`,
`src/lib/util/strings.c`, `src/lib/util/time.c`,
`src/include/gnunet_container_lib.h`, `src/include/gnunet_protocols.h`,
`src/include/gnunet_signatures.h` and the EdDSA signing construction in
`src/service/pils/gnunet-service-pils.c`.

`HelloBuilder` corresponds to the address-set builder; `Hello` corresponds to a
structurally parsed public value, and `VerifiedHello` records a signature/time
check. Rust separates parsing and verification, so every mapping of a C verified
parser includes the explicit `verify_at(profile, now)` step. The public C parser's
`noverify` integer is replaced by types and an explicit operation, never authority
inferred from a caller-provided Boolean.

| Official function | Rust equivalent |
|---|---|
| `GNUNET_HELLO_builder_new` | `HelloBuilder::new(storage, limits)` |
| `GNUNET_HELLO_builder_free` | Borrow released on Rust drop |
| `GNUNET_HELLO_parser_free` | Borrow released on Rust drop |
| `GNUNET_HELLO_builder_from_parser` | `Hello::to_builder`; `Hello::peer` |
| `GNUNET_HELLO_builder_add_address` | `HelloBuilder::add_address`, including duplicate result |
| `GNUNET_HELLO_builder_del_address` | `HelloBuilder::remove_address`, including missing result |
| `GNUNET_HELLO_builder_iterate` | `HelloBuilder::addresses` |
| `GNUNET_HELLO_parser_iterate` | `Hello::addresses`; `Hello::peer` |
| `GNUNET_HELLO_parser_get_id` | `Hello::peer` |
| `GNUNET_HELLO_builder_address_list_cmp` | `HelloBuilder::is_subset_of` (C is asymmetric) |
| `GNUNET_HELLO_address_to_prefix` | `address_to_prefix` (first hyphen); URI scheme separately `Address::scheme` |
| `GNUNET_HELLO_builder_hash_addresses` | `HelloBuilder::address_hash(profile)` |
| `GNUNET_HELLO_get_builder_to_block_size` | `HelloBuilder::block_len` |
| `GNUNET_HELLO_builder_to_block` | `with_signature(...).encode_block`; explicit clock for C zero-expiry default |
| `GNUNET_HELLO_builder_to_env` | `with_signature(...).encode_message`; message-queue ownership is caller's |
| `GNUNET_HELLO_builder_to_dht_hello_msg` | `with_signature(...).encode_dht_message` |
| `GNUNET_HELLO_build_url` | `with_signature(...).write_url` |
| `GNUNET_HELLO_builder_to_url2` | `with_signature(..., explicit_expiry).write_url` |
| `GNUNET_HELLO_builder_to_url` | `with_signature(..., default_expiration(now)).write_url` |
| `GNUNET_HELLO_parser_from_block` | `parse_block(...).verify_at(profile, now)` |
| `GNUNET_HELLO_parser_from_block_` | Structural `parse_block`; explicit verification when requested |
| `GNUNET_HELLO_parser_from_msg` | `parse_message(..., external_peer).verify_at(profile, now)` |
| `GNUNET_HELLO_parser_from_msg_` | Structural `parse_message`; explicit verification when requested |
| `GNUNET_HELLO_parser_from_url` | `parse_url(...).verify_at(profile, now)` |
| `GNUNET_HELLO_parser_to_block` | `Hello::block_len`; `Hello::encode_block` |
| `GNUNET_HELLO_parser_to_env` | `Hello::message_len`; `Hello::encode_message` |
| `GNUNET_HELLO_parser_to_dht_hello_msg` | `Hello::dht_message_len`; `Hello::encode_dht_message` |
| `GNUNET_HELLO_parser_to_url` | `Hello::url_len`; `Hello::write_url` |
| `GNUNET_HELLO_get_expiration_time_from_msg` | `message_expiration` |
| `GNUNET_HELLO_dht_msg_to_block` | `parse_message(external_peer)`, explicit verification, `encode_block` |

`GNUNET_HELLO_UriCallback` is a normal borrowed iterator item; no closure pointer or
nullable callback ownership is needed. `GNUNET_HELLO_ADDRESS_EXPIRATION` is
`ADDRESS_EXPIRATION`. The live trace compares every callback's exact URI bytes and peer (NULL for a
builder, the parser's identity for a parser); the NULL parser callback return maps
to `Hello::peer`. The C builder implementation unconditionally calls its callback
even though the header suggests NULL is allowed; Rust iteration safely requires
no closure call at all. Iterator items retain their storage borrow and cannot be
used after that storage is moved or overwritten.

C nullable peer/signature builder arguments are representable
by explicit all-zero public values; they remain unverified. `HelloBuilder::sign`
additionally performs the official PILS purpose7 signing step with existing pure
Rust Ed25519 and the exact selected C address-hash profile.

The live normal oracle observes descending sorting despite conflicting comments
in the C DLL insertion macro. It also observes SHA512(empty) in the normal build,
SHA512(canonical address bytes) in the conditional build, count/reserved omission,
C Crockford aliases, percent-decoder behavior, the URL space/plus mismatch, empty
sets, default two-day conversion and asymmetric subset/prefix helpers.
The normal C driver exercises the helper APIs directly; Rust unit/integration
checks cover the corresponding state changes, output refusal, expiry and limits.
Both C profiles emit relation, callback and size-query traces that are
compared with Rust outputs. Numeric two-day lifetime and each C default
serializer's expiration are used to compare explicit-time Rust bytes.
The C invalid-signature/expiry/noverify matrix distinguishes DHT's hidden check.
Compile-fail controls and positive examples test the borrowed Rust ownership
contract; they do not imply preservation of C's unsafe pointer mutation freedom.

Safe and intentional representation differences:

* Rust accepts a bounded slice, so message parsing requires exactly one complete
  frame. A C pointer provides no trailing-input length to inspect.
* Invalid/expired C verified parsers return NULL. Rust preserves structural parsing
  as an explicit unverified operation and classifies authentication/expiry errors.
  Verification still occurs before an expiration result is trusted.
* C `parser_from_msg_(DHT, noverify=YES)` still verifies internally through
  `dht_msg_to_block`. Rust structural parsing remains unverified. No result can be
  mistaken for `VerifiedHello` without executing the verifier.
* C documents that `dht_msg_to_block` returns an expired block with GNUNET_NO, but
  its nested verified parser rejects expiry first. Rust exposes the useful safe
  parse/verify split; it does not claim that this C path successfully returns an
  expired verified block.
* C percent decoding may free a pointer without nulling it on a truncated `%`
  triplet; the caller then accesses that storage. Rust rejects the input without
  reproducing this memory error. Empty/uninitialized or overflowing decimal
  conversions are likewise rejected. Literal embedded NUL in a byte-slice URL is
  rejected rather than hiding its suffix behind C string truncation.
* URL bytes with valid C encoding widths but non-modern UTF-8 remain representable
  and format exactly as C; invalid leading/truncated groups fail safely. Binary
  HELLO addresses are not restricted to text.
* No serializer implicitly reads wall time. C's zero-expiry/default builder
  conveniences are reproduced by passing explicit `default_expiration(now)`.

None of these APIs initiates a transport connection, implements PILS service state
or validates a communicator's support for a URI. There is no private envelope,
protocol version, magic, compatibility layer or additional signature domain.
