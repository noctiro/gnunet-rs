# GNUnet cryptographic primitives

This crate supplies standard SHA-256/SHA-512, HKDF-SHA256, GNUnet's hybrid
HMAC-SHA512/SHA256 KDF, peer Ed25519, PKEY/EDKEY zone blinding and derived
signatures, AES256CTR and tag-first NaCl XSalsa20Poly1305. It is `no_std`, uses fixed storage, obtains
entropy only from the caller, and contains no unsafe Rust. Secrets cannot be
cloned, debug formatted or serialized through this API.

The signature behavior is pinned to GNUnet v0.29.1, commit
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`,
`src/lib/util/crypto_ecc.c`. `GNUNET_CRYPTO_eddsa_key_get_public` derives the public
key with `crypto_sign_seed_keypair`. `GNUNET_CRYPTO_eddsa_sign_` and
`GNUNET_CRYPTO_eddsa_verify_` pass the entire `ntohl(purpose->size)` region,
beginning at the purpose header, to ordinary detached Ed25519. No additional
digest or private domain is inserted. The Rust API also bounds that region and
requires its advertised size to equal the slice length.

`EddsaPrivateKey` retains its seed inside a zeroizing signing key. `EddsaPublicKey` and `EddsaSignature` retain untrusted bytes; creating them
authenticates nothing. A successful signature check establishes the signature
for that exact expected-purpose region. Service owners must still check identity
bindings, expiry, authorization and replay behavior.

PKEY uses Edwards25519 ECDSA with RFC6979/SHA512 and big-endian r/s. EDKEY uses
an expanded Ed25519 scalar and derived nonce prefix. Blinding hashes are
interpreted big endian before scalar reduction. Secret owners and RFC6979 K/V
are erased on drop. The low-level derivation APIs require NFC-normalized labels;
[`gnunet-gnscrypto`](../gnunet-gnscrypto/UPSTREAM.md) supplies allocation-free
Unicode 18 NFC, complete record blocks, publication preparation and expiry policy. Its oracle checks both supported key types against normal C libraries. CORE and communicator handshake state machines remain separate protocol work.

Run `cargo test -p gnunet-crypto` for RFC 8032, SHA, HKDF, independent signature
vectors, exact-size/purpose/tamper checks and entropy-failure erasure. To
reproduce the retained public vectors independently, run
`python3 crates/gnunet-crypto/tests/official_eddsa_oracle.py --source PATH`, where
`PATH` is the clean pinned C checkout and `openssl` supports Ed25519. This is a
primitive oracle, not a mixed C/Rust daemon interoperability test.

The explicit `pow` feature adds GNUnet's shared Argon2id v1.3 work primitive
(t=3, m=1024 KiB, p=1, output64, salt16), using exactly1024 caller-supplied
aligned1024-byte blocks. The module owns no large buffer and performs no heap or
OS operation. Scratch is reusable public work memory and may change on error;
output changes only on success. Temporary output is erased. Argon2 =0.6.0 is
optional, with defaults disabled and `zeroize` enabled; default crypto does not
activate it. BLOCK selects and re-exports this same implementation for revocation. PoW hashing alone does not establish a valid service proof, difficulty, signature,
identity, round or admission policy.
