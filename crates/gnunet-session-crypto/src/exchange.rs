//! Source-exact X25519 and Ed25519/PKEY conversion, with separate DH/KEM owners.
use crate::{Prk, hkdf_extract};
use curve25519_dalek::{edwards::CompressedEdwardsY, montgomery::MontgomeryPoint};
use gnunet_crypto::Entropy;
use gnunet_types::Error;
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};
/// Unauthenticated raw Montgomery u-coordinate. RFC7748 masks its high bit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EcdhePublic([u8; 32]);
impl EcdhePublic {
    /// Official compact public-key width, BE32 type0 plus coordinate32.
    #[must_use]
    pub const fn hpke_encoded_length(&self) -> usize {
        36
    }
    /// Retain raw public bytes. Contributory/all-zero checking happens in DH.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    /// Exact native public-key wire bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    /// Convert the official EdDSA or PKEY Edwards public encoding as libsodium
    /// does: decompress, reject low-order/off-main-subgroup points, map to u.
    /// This is not an EdDSA signature or peer authorization check.
    pub fn from_edwards(bytes: &[u8; 32]) -> Result<Self, Error> {
        let point = CompressedEdwardsY(*bytes)
            .decompress()
            .ok_or(Error::Authentication)?;
        if point.is_small_order() || !point.is_torsion_free() {
            return Err(Error::Authentication);
        }
        Ok(Self(point.to_montgomery().to_bytes()))
    }
    /// Official HPKE public-key codec: BE32 type0 then32 Montgomery bytes.
    /// Capacity rejection leaves output unchanged; trailing capacity is untouched.
    pub fn encode_hpke(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < 36 {
            return Err(Error::Capacity);
        }
        out[..4].copy_from_slice(&0_u32.to_be_bytes());
        out[4..36].copy_from_slice(&self.0);
        Ok(36)
    }
    /// Decode one official public key, returning36 consumed bytes; tails remain.
    pub fn decode_hpke(bytes: &[u8]) -> Result<(Self, usize), Error> {
        if bytes.len() < 4 {
            return Err(Error::Truncated);
        }
        if bytes[..4] != [0; 4] {
            return Err(Error::Unsupported);
        }
        let key = bytes
            .get(4..36)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?;
        Ok((Self(key), 36))
    }
}
/// Exclusively owned X25519 scalar input. No Clone/Debug or general byte view.
/// Explicit HPKE private-key serialization releases caller-owned secret bytes.
/// Clamping occurs only for DH; imported raw bytes keep official C semantics.
///
/// ```compile_fail
/// let secret=gnunet_session_crypto::exchange::EcdheSecret::from_bytes([7;32]);
/// let _copy=secret.clone();
/// ```
/// ```compile_fail
/// let secret=gnunet_session_crypto::exchange::EcdheSecret::from_bytes([7;32]);
/// let _printed=format!("{secret:?}");
/// ```
pub struct EcdheSecret(pub(crate) Zeroizing<[u8; 32]>);
/// Raw32-byte X25519 shared secret, before hashing or KDF. Erased on drop.
pub struct DhSecret(pub(crate) Zeroizing<[u8; 32]>);
/// Legacy `GNUNET_CRYPTO_ecc_ecdh` SHA512(DH), not an HPKE PRK.
pub struct KeyMaterial(pub(crate) Zeroizing<[u8; 64]>);
fn clamp(bytes: &mut [u8; 32]) {
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
}
pub(crate) fn fill_secret(entropy: &mut impl Entropy, out: &mut [u8; 32]) -> Result<(), Error> {
    if entropy.fill(out).is_err() {
        out.zeroize();
        return Err(Error::Entropy);
    }
    Ok(())
}
fn digest_secret(parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    let mut hash = Sha512::new();
    for part in parts {
        hash.update(part);
    }
    let mut bytes = hash.finalize();
    let mut out = Zeroizing::new([0; 64]);
    out.copy_from_slice(&bytes);
    bytes.zeroize();
    out
}
fn multiply(secret: &[u8; 32], public: &EcdhePublic) -> Zeroizing<[u8; 32]> {
    let mut scalar = Zeroizing::new(*secret);
    clamp(&mut scalar);
    // Feed borrowed clamped bits directly; do not make dalek's temporary Copy
    // Scalar secret. Its audited constant-time Montgomery ladder handles u input.
    let mut point = MontgomeryPoint(public.0).mul_bits_be(
        (0..255)
            .rev()
            .map(|i| ((scalar[i / 8] >> (i % 8)) & 1) != 0),
    );
    let mut bytes = Zeroizing::new([0; 32]);
    bytes.copy_from_slice(point.as_bytes());
    point.zeroize();
    bytes
}
impl EcdheSecret {
    /// Official compact private-key width, BE32 type0 plus scalar32.
    #[must_use]
    pub const fn hpke_encoded_length(&self) -> usize {
        36
    }
    /// Explicit official private-key persistence codec. The caller must erase
    /// the resulting secret bytes. Capacity refusal is atomic.
    pub fn encode_hpke_private(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < 36 {
            return Err(Error::Capacity);
        }
        out[..4].copy_from_slice(&0_u32.to_be_bytes());
        out[4..36].copy_from_slice(self.0.as_ref());
        Ok(36)
    }
    /// Import one compact official private key; any trailing bytes remain.
    /// Imported scalar bytes are retained as C does, without extra clamping.
    pub fn decode_hpke_private(input: &[u8]) -> Result<(Self, usize), Error> {
        if input.len() < 4 {
            return Err(Error::Truncated);
        }
        if input[..4] != [0; 4] {
            return Err(Error::Unsupported);
        }
        let raw = input.get(4..36).ok_or(Error::Truncated)?;
        let mut bytes = Zeroizing::new([0; 32]);
        bytes.copy_from_slice(raw);
        Ok((Self(bytes), 36))
    }
    /// Consume and erase this owned secret, matching explicit C key clearing.
    pub fn clear(self) {
        drop(self);
    }
    /// Import scalar input and erase this local input copy.
    #[must_use]
    pub fn from_bytes(mut bytes: [u8; 32]) -> Self {
        let key = Self(Zeroizing::new(bytes));
        bytes.zeroize();
        key
    }
    /// Generate exactly32 unconditioned bytes from explicit entropy, as C does.
    pub fn generate(entropy: &mut impl Entropy) -> Result<Self, Error> {
        let mut bytes = Zeroizing::new([0; 32]);
        fill_secret(entropy, &mut bytes)?;
        Ok(Self(bytes))
    }
    /// Convert an Ed25519 seed with SHA512(seed)[0..32] and X25519 clamp.
    /// Used by official typed HPKE private conversion and EdDSA KEM decapsulation.
    #[must_use]
    pub fn from_eddsa_seed(mut seed: [u8; 32]) -> Self {
        let expanded = digest_secret(&[&seed]);
        seed.zeroize();
        let mut bytes = Zeroizing::new([0; 32]);
        bytes.copy_from_slice(&expanded[..32]);
        clamp(&mut bytes);
        Self(bytes)
    }
    /// Official HPKE0x0020 DeriveKeyPair: labeled SHA256 extract/expand of IKM,
    /// then explicit serialized-private-key clamp. Caller retains input ownership.
    pub fn derive_hpke(ikm: &[u8]) -> Result<Self, Error> {
        let prk = hkdf_extract(&[], &[b"HPKE-v1", SUITE, b"dkp_prk", ikm]);
        let sk = prk.derive(&[&32_u16.to_be_bytes(), b"HPKE-v1", SUITE, b"sk"])?;
        let mut bytes = Zeroizing::new(*sk.0);
        clamp(&mut bytes);
        Ok(Self(bytes))
    }
    /// Official HPKE key creation draws64 IKM bytes, unlike raw ECDHE's32.
    pub fn generate_hpke(entropy: &mut impl Entropy) -> Result<Self, Error> {
        let mut ikm = Zeroizing::new([0; 64]);
        if entropy.fill(ikm.as_mut()).is_err() {
            return Err(Error::Entropy);
        }
        Self::derive_hpke(ikm.as_ref())
    }
    /// Official fixed-base X25519 public key. This authenticates no peer.
    #[must_use]
    pub fn public_key(&self) -> EcdhePublic {
        const BASE: EcdhePublic = EcdhePublic([
            9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]);
        let bytes = multiply(&self.0, &BASE);
        EcdhePublic(*bytes)
    }
    /// Raw X25519; reject an all-zero shared value in constant time.
    pub fn exchange_raw(&self, public: EcdhePublic) -> Result<DhSecret, Error> {
        let bytes = multiply(&self.0, &public);
        if bool::from(bytes.ct_eq(&[0; 32])) {
            return Err(Error::Authentication);
        }
        Ok(DhSecret(bytes))
    }
    /// Official legacy SHA512(X25519), distinct from the raw DH and HPKE paths.
    pub fn exchange_hashed(&self, public: EcdhePublic) -> Result<KeyMaterial, Error> {
        let raw = self.exchange_raw(public)?;
        Ok(KeyMaterial(digest_secret(&[raw.0.as_ref()])))
    }
    /// Official ECDH with an EdDSA/PKEY Edwards public point, then SHA512(DH).
    pub fn exchange_edwards_hashed(&self, public: &[u8; 32]) -> Result<KeyMaterial, Error> {
        self.exchange_hashed(EcdhePublic::from_edwards(public)?)
    }
}
impl DhSecret {
    /// Extract a standard SHA256 PRK from this raw DH and explicit salt.
    #[must_use]
    pub fn extract(&self, salt: &[u8]) -> Prk {
        hkdf_extract(salt, &[self.0.as_ref()])
    }
}
impl KeyMaterial {
    /// Consume legacy DH material for an explicit protocol secret transfer.
    /// The receiver owns erasure of any encoded or retained copies.
    #[must_use]
    pub fn into_secret_bytes(self) -> Zeroizing<[u8; 64]> {
        self.0
    }
    /// Preserve the distinct legacy64-byte material as explicit HKDF input.
    #[must_use]
    pub fn extract(&self, salt: &[u8]) -> Prk {
        hkdf_extract(salt, &[self.0.as_ref()])
    }
}
const SUITE: &[u8] = b"KEM\x00\x20";
fn kem_secret(dh: DhSecret, enc: EcdhePublic, recipient: EcdhePublic) -> Result<Prk, Error> {
    let eae = hkdf_extract(&[], &[b"HPKE-v1", SUITE, b"eae_prk", dh.0.as_ref()]);
    eae.derive(&[
        &32_u16.to_be_bytes(),
        b"HPKE-v1",
        SUITE,
        b"shared_secret",
        enc.as_bytes(),
        recipient.as_bytes(),
    ])
}
/// Complete deterministic official0x0020 DHKEM. Caller supplies an ephemeral
/// scalar owner; output is enc32 plus an opaque standard shared-secret PRK.
pub fn kem_encapsulate(
    recipient: EcdhePublic,
    ephemeral: &EcdheSecret,
) -> Result<(EcdhePublic, Prk), Error> {
    let enc = ephemeral.public_key();
    let dh = ephemeral.exchange_raw(recipient)?;
    Ok((enc, kem_secret(dh, enc, recipient)?))
}
/// Generate an ephemeral scalar through explicit entropy, then official0x0020 KEM.
pub fn kem_encapsulate_random(
    recipient: EcdhePublic,
    entropy: &mut impl Entropy,
) -> Result<(EcdhePublic, Prk), Error> {
    let ephemeral = EcdheSecret::generate(entropy)?;
    kem_encapsulate(recipient, &ephemeral)
}
/// Official0x0020 decapsulation. No Elligator suite is silently selected.
pub fn kem_decapsulate(recipient: &EcdheSecret, enc: EcdhePublic) -> Result<Prk, Error> {
    let dh = recipient.exchange_raw(enc)?;
    kem_secret(dh, enc, recipient.public_key())
}
