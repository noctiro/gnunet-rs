# DNS packet reference proof

`dns_packet.py` rebuilds a small observer against an existing normal, unchanged
GNUnet v0.29.1 C library. It runs 153 safe C observations, regenerates their
reviewed wire/field projections, compares every checked fixture, and executes
the Rust package. It also compares all 65,536 native two-byte hex inputs
and has normal C open freshly encoded Rust packets with all four sections.
No network or system DNS change is involved.

```sh
python3 -B tools/reference/dns_packet.py \
  --source /absolute/path/to/gnunet-v0.29.1 \
  --build /absolute/path/to/normal-meson-build \
  --library /absolute/path/to/normal/libgnunetutil.23.dylib \
  --idn2-library /absolute/path/to/libidn2.0.dylib \
  --output target/fresh-dns-packet-proof
```

Use the normal build's library paths on the host. The output directory
must be new. The runner binds the whole tracked C tree, current repository and
normative fingerprints, build configuration, libraries, logs and generated
artifacts, and rejects changed inputs. It does not relabel an old report or
update the conformance ledger.

The 153 rows have separate native comparison, IDNA pending, explicit RFC
correction, atomic error, lossless byte, ownership and profile classifications.
Only 68 rows claim native comparison; 56 are outside this wire-only proof and
require the separate native-text composition evidence.
The full CERT record branch, malformed C pointers and known unsafe boundaries
are excluded. CERT's five-byte standard encoding is compared through an explicit
field projection; URI's known native rejection and corrected DNAME output remain
separate observations. A passing wire proof does not complete native text, UDP
stub, DNS service, DNSSEC or resolver requirements.

The pure parser's native operation mapping and ownership qualifications are in
`crates/gnunet-dns/UPSTREAM.md`. The companion `gnunet-idna` backend supplies complete selected native profiles.
Its `verify.py` composes all 55 checker/builder observations and the parsed
Punycode label with fresh normal-C evidence; there is no default ASCII replacement.
