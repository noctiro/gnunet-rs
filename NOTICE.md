# Third-party notices

## Bundled data

Original project sources use [MPL-2.0](LICENSE). Bundled data and derived tables
retain the following notices; preserve them in distributions.

| Package | Notices |
| --- | --- |
| `gnunet-idna` | [Unicode license](crates/gnunet-idna/data/LICENSE-UNICODE.txt), [libidn2 Unicode notice](crates/gnunet-idna/data/COPYING.unicode-libidn2) |
| `gnunet-identity` | [Unicode license](crates/gnunet-identity/data/LICENSE-UNICODE.txt), [bundled Unicode notice](crates/gnunet-identity/COPYING.unicode) |
| `gnunet-gnscrypto` | [Unicode license](crates/gnunet-gnscrypto/third-party/UNICODE-LICENSE.txt) |
| `gnunet-fs-host` | [JIS 1978 mapping notice](adapters/fs-std/src/extraction/formats/iptc/encoding/multibyte/JIS-1978-NOTICE.txt), [Project X0213 mapping notice](adapters/fs-std/src/extraction/formats/iptc/encoding/multibyte/JIS0213-NOTICE.txt), [CNS 11643 mapping notice](adapters/fs-std/src/extraction/formats/iptc/encoding/multibyte/CNS11643-NOTICE.txt) |
| `gnunet-native` | [musl copyright](adapters/native-std/licenses/musl-COPYRIGHT) for its protocol-name table |

## Dependencies

The TLS adapter uses `rscrypto` under the
[Apache-2.0](adapters/tls-crypto-std/licenses/rscrypto/LICENSE-APACHE) or
[MIT](adapters/tls-crypto-std/licenses/rscrypto/LICENSE-MIT) license.

Native node and SDK packages include `THIRD_PARTY_LICENSES.txt` for bundled
materials and selected Cargo dependencies. Separately built C reference
programs retain their upstream licenses.
