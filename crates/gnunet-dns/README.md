# GNUnet DNS packet core

This crate implements the bounded, pure Rust DNS wire/name/
query/record/packet main chain in `crates/gnunet-dns`. It is `no_std`,
uses no allocator or unsafe code, has no default features, and depends only on the
existing internal types/wire crates. It has no network or native-library FFI.

Callers provide UTC, a byte arena, query/record slots, finite work/input limits
and output storage. Parsing expands bounded compression including forward
pointers, limits hops to the native hard maximum33, preserves original label
bytes, parses all four sections and copies every payload into the caller arena. The incoming receive buffer can be dropped or reused before parsed values die. Packet slot lifetime and data-storage lifetime are separate. Failed parsing
spends work/arena space but clears only the slots assigned by that attempt and publishes no Packet. Drop all views/slots before reusing their backing arena; individual Copy values
do not erase or reclaim caller storage.

Structured RDATA covers hostname NS/CNAME/PTR/DNAME, SOA, MX, SRV, CERT and URI. All other type/class values and opaque bytes remain lossless, including A, AAAA,
TXT, CAA and unknown types. The library does not impose resolver-specific address
widths or accept a response as authenticated. CAA flags/tag-length and all native
type/certificate constants are available.

`encoded_len`, complete `encode`, standalone typed encoders, `encode_at` and
`duplicate_into` are checked operations. Every encoder error leaves the
entire output unchanged, and append errors preserve the cursor. `pack` explicitly
returns a truncated result when requested, with true emitted counts and TC. All objects are validated before any output commit. Full `encode` never truncates. These raw operations preserve the parsed wire octets. `native_builder_form`
projects native Unicode/raw text through the selected ToASCII backend into an
independent graph; `pack_native` applies that conversion and native per-section
prefix packing. Semantic lookup refusal sets TC and stops the current section;
resource/unavailable/source-projection errors return Err and preserve wire output. It reproduces the C conservative `strlen(ASCII)+2` name prechecks, including root
and early-empty-label cases. `native_size: Option<usize>` is full emitted wire
size when every lookup succeeds, distinct from minimum no-truncation capacity. Native URI projection refuses interior NUL because C-string values cannot retain
it; raw URI encoding remains lossless and neither path imposes UTF8 on URI bytes. Duplicates copy every name and byte payload into independent arena storage.

UTC is always explicit. TTL parsing uses saturating `now + TTL*1e6`; output
floors nonnegative remaining time to seconds. The native never sentinel retains
GNUnet's defined32-bit narrowing (`4154504685`), tested against C output.

Native text conversion uses the explicit `Idna` backend boundary. The companion
`gnunet-idna` crate supplies complete nontransitional ToASCII25 and decode-only
ToUnicode16 profiles using fixed source tables and caller-owned scratch. Select
its Unicode/library profile explicitly; the packet crate has no default ASCII
or browser backend. Native checker preconditions and first-empty-label writer
behavior remain distinct. `Unavailable` and resource errors never permit a raw
fallback. The previously assessed `idna=1.1.0` browser profile accepted emoji
that native lookup rejects and is not used. See the companion crate's provenance
and scoped C comparison for the exact selected runtime profile.

Corrected standard/safety behavior is deliberate: CERT uses the RFC4398 five-byte
header, URI keeps the full RFC7553 target, DNAME serializes its domain name, and
truncation reports true counts. No native padding leakage, CERT fallthrough,
one-past pointer read, logical URI overwrite or C count underflow is reproduced. Readers restore their cursor on error; low-level C partial cursor writes are not
an unsafe compatibility contract. See `UPSTREAM.md` and the external audit.

Use explicit toolchain/cwd/target isolation:

```sh
cd crates/gnunet-dns
cargo test --locked --offline
cargo clippy --all-targets --locked --offline -- -D warnings
```

The153-row C corpus is linked with explicit native-comparison, protocol-correction,
wire-projection and separately composed native-text categories. A separate actual-C oracle covers all
65536 native two-byte hex inputs. No count is a blanket DNS-completeness claim.

Opaque raw RDATA is not inspected, authenticated or relocated. If a type outside
the structured native set embeds compression pointers, blindly changing packet
layout can invalidate those opaque bytes, as with the C API. Callers that forward
such records should preserve the original packet or provide that type grammar. The parser does not turn AD/DNSSEC flag bits into a verification claim.
