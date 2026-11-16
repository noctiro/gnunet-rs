# Fixed source profile and exact constructions

GNUnet v0.29.1, commit346358e26d4dcc2dc4f51bef5d52dca29c7d8165. Every formal
runner input contains the hashes of all tracked C files, generated normal-build
configuration/compile commands, reference receipt and normal libraries.
The runner records dependency versions and ABI widths from the selected normal
reference build. Its local fixtures use no DNS or network.

| Source | Rust boundary |
|---|---|
| `src/lib/util/crypto_ecc.c`: key creation/public and raw/hashed/conversion ECDH | `exchange.rs` |
| `src/lib/util/crypto_hpke.c`: labeled KEM0x0020, conversions, DeriveKeyPair, public codecs | `exchange.rs` |
| `src/lib/util/crypto_hkdf.c` | `kdf.rs` standard SHA256 PRK/expand |
| `src/lib/util/crypto_hash.c` | `transcript.rs` / erased SHA2 HMAC orchestration |
| `src/lib/util/crypto_symmetric.c`: detached XChaCha AEAD | `aead.rs` |
| `src/service/core/gnunet-service-core_kx.c`: derive_* and record protection | `session.rs` CAKE |
| `src/service/transport/gnunet-communicator-tcp.c`: setup_cipher | persistent TCP material/stream |
| `src/service/transport/gnunet-communicator-udp.c`: derive_key/IV/KID/CMAC | UDP KDF only |

## Exchange and conversion

Raw ECDHE generation consumes32 unconditioned entropy bytes. X25519 clamps at
use, masks the public high bit perRFC7748 and rejects all-zero shared secrets.
`ecc_ecdh`, `eddsa_ecdh`, `ecdsa_ecdh` and reverse Edwards-key forms hash the
raw32-byte shared value with SHA512. The raw `ecdh_x25519` / `x25519_ecdh` forms
return32 bytes instead; mixing these values changes the protocol.

An EdDSA seed maps to SHA512(seed)[0..32], then clamps. PKEY conversion copies
its scalar32 bytes, with X25519 clamping at use. Duality tests use actual
source-generated/clamped PKEY scalar profiles; arbitrary imported unclamped
PKEY values must not be assumed to represent the same Edwards/X25519 private
key. EdDSA and PKEY public conversion both decompress an Edwards point, reject
small-order and non-main-subgroup values and map to Montgomery u. This is not
signature verification or peer authorization. The normal libsodium conversion
has no additional explicit re-encoding canonical check, so none is invented.
The finite noncanonical fixtures document observed agreement, not all possible
encoding equivalence classes. Off-subgroup rejection is distinct from X25519's
raw low-order/all-zero rejection.

## Plain DHKEM and HKDF

DHKEM suite0x0020 uses suite bytes `KEM\x00\x20`. Labeled extract is HMAC-SHA256
with `HPKE-v1 || suite || label || ikm`. Labeled expand is standard HKDF-SHA256
with `BE16(output_len) || HPKE-v1 || suite || label || info`. `eae_prk` extracts
raw DH. `shared_secret` expands32 bytes with info `enc32 || recipient_public32`.
The union key type is not inserted into this context. Type0 HPKE public codec
is BE32(0)||Montgomery32,36 bytes, and the reader reports consumed36 despite a
longer supplied buffer.

DeriveKeyPair extracts `dkp_prk` from IKM, expands `sk`, then clamps its serialized
scalar. HPKE key creation obtains64 IKM bytes; encapsulation's ephemeral raw
ECDHE creation obtains32. These entropy calls remain distinct. Caller entropy
failure never manufactures a key. The standard split HKDF uses SHA256 for both
extract and expand, max255 blocks. Expand preflights the complete context sum plus32 digest bytes
and1 counter byte against native size_t before hashing, matching the C rejection
boundary. Synthetic-length tests use the same checked kernel at the32-bit ceiling;
this is not claimed as normal32-bit C execution. The existing GNUnet-specific GNS KDF instead
extracts SHA512 and expands SHA256 and remains separately named.

## CAKE, TCP, UDP

All CAKE expand contexts concatenate `cake10`, the following ASCII labels and
where specified the exact64-byte SHA512 transcript. There are no inserted
lengths or NUL terminators:

- ES=Extract(empty,ss_R); ETS=Expand(ES,`early data`,transcript).
- HS=Extract(Expand(ES,`derived`),ss_E); IHTS/RHTS use `i hs traffic` / `r hs traffic` plus transcript.
- MS=Extract(Expand(HS,`derived`),ss_I); IATS/RATS use `i ap traffic` / `r ap traffic` plus transcript.
- `traffic upd` ratchets an application secret. `i finished` / `r finished`
  expand64-byte HMAC-SHA512 keys; Finished authenticates the transcript.
- `key` expands32 bytes, `iv` expands24; nonce's last8 bytes XOR sequenceBE64.
- `sn` expands32 bytes. Tag[0..4] interpretedBE32 is the IETF ChaCha initial
  counter; tag[4..16] is nonce12. Its first8 keystream bytes XOR sequenceBE64.
- Current source encrypts just the record payload with XChaCha20Poly1305 and
  **empty AAD**; epoch/header are not silently added. It validates the record
  before committing its replay window. This implementation does not implement that
  window or any association state.

TCP material uses labels `gnunet-communicator-tcp-key`32,
`gnunet-communicator-tcp-ctr`16 and `gnunet-communicator-hmac`64. AES256CTR is
one persistent bidirectional-operation stream per direction; partial chunks
retain stream position. MAC is standard SHA512 HMAC. Frame coverage and communicator handshake belong to the TCP engine.

UDP key32/IV12 expand the corresponding `gnunet-communicator-udp-key` / `...-iv`
labels followed by serialBE32. KID extracts with salt serialBE32 and master as
IKM, then expands `gnunet-communicator-udp-kid`32. `...-cmac` expands64 bytes as
a key-acknowledgement marker; this is not an AES-CMAC algorithm. The source UDP
payload cipher is AES256-GCM with IV12, not CTR, and its entrance uses Elligator
suite0x0022. The `gcm`/`udp` modules implement the nonce12/tag16 payload cipher
and exact external prefix layouts. The `elligator` module supplies the
0x0022 KEM. GCM uses empty AAD, with separate expected-KID routing and no
fake identity/replay authority. The verifier compiles unchanged original UDP
crypto functions against normal libraries; it does not execute a UDP peer.

## Protocol composition

The [HPKE contract](HPKE.md) covers typed X25519 and Elligator Base/PSK contexts,
nonce12 and sequence encoding. Source-declared Auth modes refuse, and the header
exposes no Export operation.

Replay windows, identity admission, ACKs, rekey and native I/O belong to the
[CORE](../gnunet-core/README.md),
[TCP](../gnunet-tcp-communicator-core/README.md) and
[UDP](../gnunet-udp-communicator-core/README.md) engines. Broader utility crypto
APIs belong to [gnunet-crypto](../gnunet-crypto/README.md); declaration discovery
is separate from external capability qualification.
