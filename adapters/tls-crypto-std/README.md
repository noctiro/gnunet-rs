# TLS cryptography host

`provider()` supplies an explicit shared Rustls provider for TLS 1.2, TLS 1.3
and QUIC. Configuration callers retain certificate trust, protocol versions,
ALPN and session policy. Random bytes come from the operating system.

## Algorithms

The provider implements AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 record
protection, including QUIC packet and header protection. It uses the Rustls
HKDF and TLS 1.2 PRF with RustCrypto SHA-256 and SHA-384. The default key
exchange order is X25519, P-256, P-384 and X25519MLKEM768. The complete group
list includes P256MLKEM768, MLKEM768 and MLKEM1024 for explicit negotiation
policies.

## Certificate keys

Certificate and handshake verification supports RSA, ECDSA, Ed25519 and
ML-DSA. The private-key provider imports the applicable PKCS#8, PKCS#1 or
SEC1 format, retains the key's SPKI, and blinds RSA signatures with OS entropy.
ML-DSA uses prepared `rscrypto` keys on supported architectures and
`macula-mldsa` on 32-bit x86. Both accept all three RFC 9881 encodings. When
expanded bytes accompany a seed, they must match the key derived from it.
Expanded-only import checks the packed secret coefficient ranges and derives
both the low-order coefficients and the public-key hash before accepting the
signer. A supplied public component must match the derived public key.

`certificate::P256Key` generates local keys for self-signed credentials,
proxy CAs and server leaves. `certificate::ServerIssuer` loads a matching CA key and
certificate and issues DNS or IP leaves with the original issuer identity.
The caller checks CA authorization, supplies the validity interval and owns
the corresponding trust policy.
