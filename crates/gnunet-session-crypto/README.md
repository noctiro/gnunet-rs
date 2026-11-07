# GNUnet v0.29.1 session primitives

This workspace crate supplies the next CORE/TRANSPORT primitive chain:
raw X25519 and legacy SHA512(DH), EdDSA/PKEY conversion, plain DHKEM(X25519,
HKDF-SHA256)0x0020, standard split HKDF, incremental SHA512, HMAC-SHA512,
XChaCha20Poly1305, CAKE role/transcript/record/sequence derivation, and persistent
TCP AES256CTR plus its separate HMAC key. HPKE contexts and UDP AES256-GCM payload
operations extend these primitives with their explicit source contracts below. It has no protocol admission, hidden
RNG, clock, network, allocator, unsafe code or libgnunet production FFI.

The existing repository supplies GNUnet purpose signatures, GNS PKEY/EDKEY
blinding/signatures, the different legacy GNUnet HKDF and XSalsa20 secretbox. Those algorithms are retained as distinct constructions. In particular current
CORE uses CAKE, rather than the historical AES+Twofish session exchange.

`UPSTREAM.md` records exact source contracts and the intentionally unfinished
layers. `tools/inventory.py` inventories every one of the226 public functions in
the fixed crypto header, including its108 nonfunction surfaces and lexical
consumers. Its assessments do not update the acceptance ledger. Many official
crypto APIs remain missing; this package is not a full GNUnet crypto replacement.

## Reproduce against an unchanged normal C utility library

Python3.9+, cached Rust1.99.1 dependencies and the two installed Rust targets
`thumbv6m-none-eabi` / `thumbv7em-none-eabi` are sufficient. Supply the actual
normal Meson build receipt, its unchanged source and dependency prefix:

```sh
python3 tools/compare.py \
  --repository /absolute/gnunet-rs \
  --source /absolute/gnunet-v0.29.1 \
  --reference /absolute/normal-build/build-result.json \
  --deps-prefix /absolute/dependencies/prefix \
  --output /absolute/fresh-proof-output
```

The runner rejects overlapping/existing output, validates the pinned revision,
clean tracked C tree and normal util hash, extracts the compiler flags
from normal Meson `compile_commands.json`, then builds its own small caller with
O0 and O2. Both callers use the same already normally compiled C library; this
does not claim two independently optimized utility libraries. CAKE/TCP recipes
call the public C KDF, MAC and cipher APIs. The UDP key/nonce comparison
extracts the unchanged `get_iv_key` body and macros from the pinned communicator,
including its actual 12-byte nonce; the earlier handwritten 16-byte recipe was
incorrect and its historical evidence remains scoped in the correction audit. ChaCha12 and sequence masking additionally call libsodium APIs
used by those C implementations.

All generated Cargo manifests, locks, binaries, fixtures and logs go under the
fresh output. The template is `Cargo.toml.in`; path dependencies are constructed
from `--repository`. Workspace registry identities are checked; the new
pinned dependency `chacha20=0.10.2` is additionally pinned by checksum in
`reference/dependency.json`. No root lockfile or source is rewritten. Inputs,
generated Rust sources and normal libraries are hashed before/after.

The finite differential contains generated prime-subgroup/torsion mixtures,
noncanonical/raw-coordinate aliases, invalid/low-order points, both scalar key
families, C-random EdDSA encapsulations, independent Rust encapsulations
accepted by C, HKDF lengths through8160/8161, SHA/HMAC block boundaries,
AEAD lengths through65535, every tampered authenticated field, CAKE roles,
BE sequence/counter extremes and split TCP writes. Each C helper profile is
checked independently; C-random encapsulations are expected to differ between
runs. Deterministic rows must also agree across helper profiles. The external
oracle Rust test is ignored by default and is counted only when the runner
actually supplies fresh normal-C observations. Default tests do not silently
skip an absent oracle. Four negative controls alter fresh C outputs
(DH, AEAD tag, CAKE secret and a missing row); each must fail the named actual
Rust comparator test. The selected normal dependency graph is also checked for
absence of std/alloc features, excluding host build/proc-macro dependencies.

## Ownership and resource contract

Secret scalars, DH values, PRKs, HMAC pads/digests, HChaCha state/subkeys,
Poly1305 one-time keys and stream state have explicit erased owners. Secret
owner types expose neither Clone nor Debug nor a general borrowed byte view. The official HPKE private-key persistence codec explicitly writes caller-owned
secret bytes; its caller must erase that output. Caller
inputs are still caller-owned: passing a Copy array by value cannot erase other
copies retained by the caller. AEAD key-slice and UDP key-buffer users must erase
their own copies. Fourteen exact-code compile failures plus a successful control
enforce Clone/Debug refusal for the seven baseline secret owner types using the actual
Cargo-reported library. Compile-fail examples also enforce the exposed scalar
ownership boundary; failure-path tests exercise partial entropy erasure,
authentication rejection erasure and atomic codec capacity refusal.

No claim is made that every compiler register/spill or all private arithmetic
intermediates inside third-party constant-time implementations are erased. `zeroize` applies to explicit owners and dependency Drop implementations. The
manual HChaCha orchestration avoids the non-erased temporary subkey in the
RustCrypto XChaCha wrapper. X25519 uses dalek's constant-time borrowed-bit ladder
to avoid its separate Copy Scalar intermediate. Neither change introduces
another curve or private protocol.

AEAD authenticates before returning plaintext; invalid authentication erases
the complete mutable range. Length preflight leaves it unchanged. The IETF
payload bound includes counters1..2^32-1 inclusive. HKDF over8160 bytes is
rejected and erased. Public-key serialization capacity failures are atomic. These safe output policies differ from unspecified/retained C failed-output
contents, which are never treated as valid outputs in the differential.

`record_material` and generic AEAD methods accept caller-provided AAD. `seal_record` / `open_record` specifically use current official CAKE empty AAD. They do not include an epoch/header field. Callers must enforce sequence
uniqueness, replay windows, epoch ratchets, association ownership and rekeying;
a primitive returning an authenticated sequence is not a replay-admission
result. The protocol state machine remains a separate unfinished task.

The `hpke` module supplies official X25519 and distinct typed Elligator Base/PSK
contexts, sequential seal/open, default-X25519 one-shot encapsulation and
private-key codecs. [HPKE.md](HPKE.md)
records exact source behavior, safe output/ownership decompositions and the
normal-library verifier `tools/hpke_verify.py`. Auth modes retain the source's
explicit refusal. This
does not complete CORE or communicator handshakes.

The `gcm` module supplies AES256-GCM nonce12/tag16 with mature GHASH, explicit
length bounds and authentication before decryption. `udp` uses exactly empty
AAD and the official KID/enc32||tag16||ciphertext payload layouts, without
granting identity, replay, ACK or rekey authority. [GCM.md](GCM.md) and
[GCM_API.md](GCM_API.md) describe the boundary. `tools/gcm_verify.py` checks
literal NIST vectors and unchanged original UDP crypto/layout functions linked
to normal libraries, including C acceptance of independent Rust outputs. Context and GCM owners receive additional precise trait/lifetime controls.
[DEPENDENCIES.md](DEPENDENCIES.md) records the two GHASH backend dependencies
and their explicit memory-erasure limits.
