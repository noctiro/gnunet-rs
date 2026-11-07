# Native source correspondence

GNUnet v0.29.1 pinned revision `346358e26d4dcc2dc4f51bef5d52dca29c7d8165`, source `src/lib/util/dnsparser.c` SHA256 `9659bf2c49618c229d0b1ee91ecd1abb4a013708110193724d255e00acbc9ec8`.

| Rust entry | Actual official operation | Important boundary |
| --- | --- | --- |
| `to_ascii` / `Backend::to_ascii` | GNUnet `idna_to_ascii_8z(..., IDNA_ALLOW_UNASSIGNED)` macro → `idn2_to_ascii_8z(...,25)` → `idn2_lookup_u8` | Full mapping/NFC, strict native Punycode basic and roundtrip restrictions,63-byte labels/253-byte name/254-byte final-dot output |
| `to_unicode` / `Backend::to_unicode_label` | `idn2_to_unicode_8z8z(...,16)` → `idn2_to_unicode_8z4z` | Flags unused, no mapping or IDNA validation; decode-only, max63 label/255 domain scalars |
| Fixed tables | `lib/IdnaMappingTable.txt`, `lib/Idna2008.txt`, `lib/DerivedNormalizationProps.txt` in libidn2 2.3.8 | Unicode15.1.0, unassigned remains refused despite compatibility flag16 |
| Native ContextJ | `lib/context.c:_idn2_contextj_rule` and `lookup.c:label` | Immediate virama, otherwise left/dual and right/dual with transparent characters skipped |
| Native ContextO | `idna.c:TEST_CONTEXTO_WITH_RULE` (not `TEST_CONTEXTO_RULE`) | Recognizes only the standardized ContextO identifiers; does not enforce their context |
| Native Bidi | `lib/bidi.c:_idn2_bidi` | Per-label RTL detection; source-derived mixed-digit and terminal-NSM behavior |
| Strict Unicode15.1 label validator | RFC5891/5892/5893, fixed UCD15.1 properties | Explicit separate API; ContextO, EN/AN and final non-NSM rules enforced; caller supplies Bidi-domain context |
| `normalize_nfc` | UAX15 canonical decomposition/order/composition + Hangul algorithm | Separate official15.1/18 profiles; all official normalization input columns checked against specified NFC columns and normal C normalization |

Official source/archive provenance:

- GNU libidn2 2.3.8: <https://ftp.gnu.org/gnu/libidn/libidn2-2.3.8.tar.gz>, SHA256 `f557911bf6171621e1f72ff35f5b1825bb35b52ed45325dcdee931e5d3c0787a`.
- Unicode15.1 UCD: <https://www.unicode.org/Public/zipped/15.1.0/UCD.zip>, SHA256 `cb1c663d053926500cd501229736045752713a066bd75802098598b7a7056177`.
- Unicode18 UCD: <https://www.unicode.org/Public/18.0.0/ucd/UCD.zip>, SHA256 `7b3e555514060b92290d154f53655c5eb0fa62b16eb04c03434ff72d1a66a0d8`.
- Unicode15.1 IDNA test data: <https://www.unicode.org/Public/idna/15.1.0/IdnaTestV2.txt>. Its source ToUnicode expectations describe UTS46, so native decode-only results are compared against the C API rather than falsely requiring all UTS46 ToUnicode behavior.
- GNU libunistring1.5: <https://ftp.gnu.org/gnu/libunistring/libunistring-1.5.tar.gz>, SHA256 `5b0ecd46cbf225375f20ab4056197e66a7ac590e2684c069af407ae3383c9d81`. `lib/unimetadata/u-version.c` and generated property headers explicitly say Unicode18.0.0, matching the runtime metadata `0x1200`.
- Unicode data license: <https://www.unicode.org/license.txt>, retained with original bundled `COPYING.unicode` and source hashes. New Rust algorithms follow the published standards; no libidn2 C implementation is linked into production or copied into Rust.

The normal C build, its unchanged utility library and the libidn2/libunistring dynamic libraries are supplied explicitly to the verifier and recorded by hash. Each fresh proof contains the original Meson compile unit and the exact helper compiler invocations in `native/c-build.json`. No public DNS, NSS lookup, external network protocol or host configuration change is used by any runtime probe. The added `parsed_label` case proves the C wire-name→Unicode relationship against Rust Reader→native-text composition, separately from the55 checker/builder observations.
