# Explicit OIDC signing bridge

The bridge provides RS256 and HS512 signing and verification for caller-owned
keys and messages. `Rsa` generates or imports RSA keys and exposes PKCS#8 export,
public-key export and JWT signing. `Public` imports or writes a public JWK and
verifies signatures. `Hs512` signs and verifies JWTs with a supplied HMAC key.

Verification returns a redacted payload view with explicit access to its bytes.
The caller validates issuer, audience, nonce, time and replay policy. RS256 uses
RustCrypto RSA with OS entropy for key generation and signature blinding.
PKCS#8 and JWK imports verify all two-prime RSA components, including the CRT
values. Imported keys use the public modulus width for private operations,
including when the two factors have different widths. Private key owners and
adapter buffers erase their contents on drop.
[OpenID Connect flow](../rest-std/API.md#conditional-oidc)
