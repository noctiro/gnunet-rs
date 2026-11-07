# gnunet-gnscrypto

Official GNUnet v0.29.1 PKEY and EDKEY GNS encrypted record blocks in safe,
allocation-free `no_std` Rust. Includes Unicode 18 NFC labels, public/private
label blinding, signature-bound DHT queries, AES256CTR and XSalsa20Poly1305
sealing, authenticated zone/name-bound opening, publication preparation and
record expiry/shadow selection.

All storage and UTC values are explicit caller inputs. See [UPSTREAM.md](UPSTREAM.md)
for the versioned algorithms, C interoperability oracle, Unicode sources and
boundary differences. A successful block verification proves the selected
zone/name signature; application authorization and trusted UTC remain owner
responsibilities.

```sh
cargo test -p gnunet-crypto -p gnunet-gnscrypto --locked --offline
cargo check -p gnunet-gnscrypto --target thumbv6m-none-eabi --no-default-features --locked --offline
```

Authoritative publication preparation shares GNS record-set constraints with
NAMESTORE: supplemental metadata does not invalidate a primary delegation or
redirection, same-type inactive SHADOW values are admitted beside one active
value, and GNS2DNS may carry supported DNS connection-security records. Base
block lifetime uses the maximum expiration for each type, then the minimum
across types as specified by LSD0001/RFC9498 section6.3. This is intentionally
distinct from the fixed C helper's older minimum-ordinary/same-type-shadow rule. The returned record-derived expiry does not reserve an encryption nonce or prove
strict monotonicity across earlier blocks; the publishing owner must durably
establish that authority before `seal`/`seal_for_namecache`.
