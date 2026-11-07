# Approved mature GHASH dependencies and erasure audit

AES-GCM uses `ghash=0.6.0` with `default-features=false, zeroize` and
`polyval=0.7.3` with `default-features=false, zeroize, hazmat`.
Archive/index identities:

- ghash0.6.0: 2eecf2d5dc9b66b732b97707a0210906b1d30523eb773193ab777c0c84b3e8d5
- polyval0.7.3: f0fa31d631f2b2cb2a544d0aa321ce847a94764d701ca2becc411138b93d49cd

All transitive normal dependencies were already present. `polyval` is declared directly so zeroize is enabled for the GHASH-owned state; hazmat is required by ghash's FieldElement conversion. Actual cargo metadata feature graph is checked, no normal std/alloc enabled. Both cached archive hashes and every expanded archive file are compared before/after. Cargo source paths, runtime compiler version and generated lock graph are retained. This is not a replacement for root's integration policy/RustSec audit.

Explicit candidate secret memory owners: input local AES key is zeroized; expanded AES member has enabled zeroize Drop; H is Zeroizing<[u8;16]>; per-operation counter, keystream block and tag-mask are Zeroizing. DatagramKey holds no extra key bytes. GHash contains Polyval, and the enabled Polyval Drop invokes zeroize_flat_type over its whole backend state (H/powers/accumulator). No bespoke finite-field multiplication is introduced. Default native and forced software backends both run the finite oracle.

Dependency limitation: GHash::new explicitly zeroizes its named h_polyval FieldElement, but `Polyval::new(&h_polyval.into())` also creates an anonymous converted Array temporary with no explicit erasure Drop. This audit does not promise every internal copy, temporary or register is cleared. The dependency's Clone implementation is not exported through our non-Clone owner. No unsafe post-Drop memory inspection or universal physical erasure claim is used. The candidate itself forbids unsafe code; mature backend internals retain their existing documented unsafe acceleration/zeroize implementations.
