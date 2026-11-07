# Public DNSPARSER correspondence

Pinned GNUnet v0.29.1: `346358e26d4dcc2dc4f51bef5d52dca29c7d8165`.
The public parser operations map as follows. Native text conversion composes
with the explicit `gnunet-idna` backend.

| Official operation suffix | Rust operation | Remaining qualification |
|---|---|---|
| check_label / check_name | `check_label`, `check_name` | Compose with explicit `gnunet-idna::Backend` |
| parse | `Packet::parse` | Wire complete; native Unicode text needs backend |
| free_packet | Scope/last-use of Packet/views; caller storage reuse | Caller arena ownership replaces C heap/free |
| pack | `Packet::pack_native`, `native_builder_form` | Native conversion/capacity/section prefixes; true counts and safe RFC corrections. Raw `pack`/`encode` remain lossless |
| builder_add_name | `Name::from_native_text`, `encode_at` | Compose with explicit `gnunet-idna::Backend`; wire-only Name remains independent |
| builder_add_query | Canonical native name + `Query::encode_at`; `pack_native` composes the query | Native conservative reserve4 reproduced by `pack_native`; raw wire encoder remains exact-width |
| builder_add_mx / soa / srv / cert / uri | Typed `encode`, `RData::encode_at` | Atomic refusal; CERT5/URI full tail |
| parse_name / query / record | `Reader::name`, `query`, `record` | Bounded wire values; explicit UTC |
| parse_mx / soa / srv / cert / uri | Named `Reader` methods | Explicit RDATA end, whole-packet pointer context |
| duplicate_record | `Record::duplicate_into` | Deep independent caller storage |
| duplicate_mx_record / soa_record / srv_record / cert_record / uri_record | Typed `duplicate_into` | Scalars preserved; all name/payload bytes copied |
| free_record / mx / soa / srv / cert / uri | Scope/last use of safe borrowed or copied values | No C dangling outer-container distinction |
| bin_to_hex / hex_to_bin | `encode_hex_lower`, `decode_hex_native` | Entire two-byte native conversion domain compared |

Native C IDNA uses libidn2 compatibility ASCII flags25 and Unicode flags16 in the
bound reference build. The interface does not guess a profile. Native C parsing
of names returns allocated text, whereas this core first retains a lossless wire
name. Compose `write_native_text` with the companion `gnunet-idna::Backend` to obtain native text.
Malformed Unicode-label conversion may use explicit raw fallback; missing backend
or capacity errors propagate and cannot silently become an ASCII implementation.

The native full CERT record path is excluded from C probing because it falls
through after consuming the input and can read beyond it. Field-level CERT
construction/parsing plus RFC4398 vectors define the corrected five-byte header.
URI and DNAME native defects and truncated count underflow are recorded in the
original C audit; corresponding Rust corrections are separate corpus classes.
This package adds no private wire envelope or protocol version.

DNSSTUB's seven scheduling/network APIs remain a separate root-owned core module.
The fixed official Resolver daemon parses the full native graph and matches the
transaction ID; it does not filter QR, rcode, question equality or record class.
Its original overall lookup deadline belongs to its owner. This synchronous
packet parser supplies no admission or network authority. Embeddings that require
additional DNS policy must select it explicitly rather than attribute it to that
source profile. No owner `verified` promotion is made by these component implementations.

`NativeScratch` holds explicit caller text work/output slices. Native graph forms
preflight every name, shape, destination slot and independent arena capacity;
backend conversions must be deterministic across planning/copy. `pack_native`
checks all source projections before treating a ToASCII Malformed/InvalidInput
result as native NO, so unrelated source/resource errors cannot become TC. Its
maintained actual-C tool scans3846 capacity/semantic combinations, including SOA
name/name/fixed20 ordering and continuation into later sections.
