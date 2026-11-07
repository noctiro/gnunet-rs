//! GNUnet v0.29.1 PKEY/EDKEY zone blinding and derived signatures.
//!
//! GNS str labels must already be NFC normalized by their record owner.
//! Byte helpers preserve raw FS labels; this layer performs no normalization.
//! PKEY is ECDSA on Edwards25519 with RFC6979/SHA512; EDKEY is an expanded
//! Ed25519 scalar and nonce prefix. Neither is a private protocol envelope.
use crate::{Entropy, hash256_parts, hash512, hash512_parts, hkdf_gnunet, kdf::hmac512};
use crypto_bigint::{Choice, CtEq, CtSelect, U256, const_monty_params};
use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::IsIdentity,
};
use gnunet_types::Error;
use gnunet_wire::official::SignaturePurpose;
use zeroize::{Zeroize, Zeroizing};

/// Owner-held little-endian ECDSA zone scalar, erased on drop.
pub struct PkeySecret(Zeroizing<[u8; 32]>);
/// Owner-held Ed25519 zone seed, erased on drop.
pub struct EdkeySecret(Zeroizing<[u8; 32]>);
/// Blinded ECDSA scalar, erased on drop.
pub struct PkeyDerivedSecret(Zeroizing<Scalar>);
/// Blinded Ed25519 scalar and derived nonce prefix, erased on drop.
pub struct EdkeyDerivedSecret {
    scalar: Zeroizing<Scalar>,
    prefix: Zeroizing<[u8; 32]>,
}

fn valid_point(public: &[u8; 32]) -> Result<EdwardsPoint, Error> {
    let point = CompressedEdwardsY(*public)
        .decompress()
        .ok_or(Error::Authentication)?;
    if point.compress().to_bytes() != *public || point.is_identity() || !point.is_torsion_free() {
        return Err(Error::Authentication);
    }
    Ok(point)
}

/// Exact public blinding hash. Its 64 bytes are interpreted **big endian**
/// before reduction modulo the Edwards25519 subgroup order.
pub fn blinding_hash(public: &[u8; 32], label: &str, context: &str) -> Result<[u8; 64], Error> {
    blinding_hash_bytes(public, label.as_bytes(), context.as_bytes())
}
/// Exact blinding hash over raw C-string bytes, without UTF8 or normalization.
/// NUL cannot occur inside either official C-string input.
pub fn blinding_hash_bytes(
    public: &[u8; 32],
    label: &[u8],
    context: &[u8],
) -> Result<[u8; 64], Error> {
    if label.contains(&0) || context.contains(&0) {
        return Err(Error::InvalidInput);
    }
    let mut hash = [0; 64];
    hkdf_gnunet(b"key-derivation", public, &[label, context], &mut hash)?;
    Ok(hash)
}
fn blinding_scalar(hash: &[u8; 64]) -> Scalar {
    let mut reversed = *hash;
    reversed.reverse();
    Scalar::from_bytes_mod_order_wide(&reversed)
}
/// Derive the blinded public key for either supported zone-key type.
pub fn derive_public(public: &[u8; 32], label: &str, context: &str) -> Result<[u8; 32], Error> {
    derive_public_bytes(public, label.as_bytes(), context.as_bytes())
}
/// Derive the blinded public key over exact raw label/context bytes.
pub fn derive_public_bytes(
    public: &[u8; 32],
    label: &[u8],
    context: &[u8],
) -> Result<[u8; 32], Error> {
    let point = valid_point(public)?;
    let h = blinding_scalar(&blinding_hash_bytes(public, label, context)?);
    let derived = point * h;
    if derived.is_identity() {
        return Err(Error::Authentication);
    }
    Ok(derived.compress().to_bytes())
}

impl PkeySecret {
    /// Import the official raw little-endian scalar. Persisted PKEY inputs are
    /// retained exactly; the generated-key clamping rule is not reapplied.
    pub fn from_bytes(mut bytes: [u8; 32]) -> Result<Self, Error> {
        let scalar = Zeroizing::new(Scalar::from_bytes_mod_order(bytes));
        if *scalar == Scalar::ZERO {
            bytes.zeroize();
            return Err(Error::InvalidInput);
        }
        let key = Self(Zeroizing::new(bytes));
        bytes.zeroize();
        Ok(key)
    }
    /// Generate and clamp the same 32-byte scalar as the C zone-key creator.
    pub fn generate(entropy: &mut impl Entropy) -> Result<Self, Error> {
        let mut bytes = Zeroizing::new([0; 32]);
        entropy.fill(bytes.as_mut()).map_err(|_| Error::Entropy)?;
        bytes[0] &= 248;
        bytes[31] &= 127;
        bytes[31] |= 64;
        Self::from_bytes(*bytes)
    }
    /// Raw compressed Edwards public key; the zone type belongs to its owner.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        let scalar = Zeroizing::new(Scalar::from_bytes_mod_order(*self.0));
        EdwardsPoint::mul_base(&scalar).compress().to_bytes()
    }
    /// Sign with the original unblinded ECDSA scalar. GNUnet's blindable-key
    /// signer also uses this path for member/identity keys without a GNS label.
    /// The existing constant-time scalar owner and RFC6979 signer are reused;
    /// no secret scalar, nonce, entropy source or alternative framing is exposed.
    pub fn sign(&self, purpose: u32, parts: &[&[u8]]) -> Result<[u8; 64], Error> {
        let scalar = Zeroizing::new(Scalar::from_bytes_mod_order(*self.0));
        PkeyDerivedSecret(scalar).sign(purpose, parts)
    }
    /// Derive an official PKEY label signing key.
    pub fn derive(&self, label: &str, context: &str) -> Result<PkeyDerivedSecret, Error> {
        let h = blinding_scalar(&blinding_hash(&self.public_key(), label, context)?);
        let mut scalar = Zeroizing::new(Scalar::from_bytes_mod_order(*self.0));
        *scalar *= h;
        if *scalar == Scalar::ZERO {
            return Err(Error::Authentication);
        }
        Ok(PkeyDerivedSecret(scalar))
    }
}
impl EdkeySecret {
    /// Import an ordinary Ed25519 seed, erasing this local input copy.
    #[must_use]
    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let result = Self(Zeroizing::new(seed));
        seed.zeroize();
        result
    }
    /// Generate the official unclamped random seed.
    pub fn generate(entropy: &mut impl Entropy) -> Result<Self, Error> {
        let mut seed = Zeroizing::new([0; 32]);
        entropy.fill(seed.as_mut()).map_err(|_| Error::Entropy)?;
        Ok(Self::from_seed(*seed))
    }
    /// Standard Ed25519 public key for this seed.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&self.0)
            .verifying_key()
            .to_bytes()
    }
    /// Derive the scalar and nonce prefix used by GNUnet's derived EdDSA signer.
    pub fn derive(&self, label: &str, context: &str) -> Result<EdkeyDerivedSecret, Error> {
        self.derive_bytes(label.as_bytes(), context.as_bytes())
    }
    /// Derive an EdDSA signer over raw C-string bytes, with no UTF8/NFC policy.
    pub fn derive_bytes(&self, label: &[u8], context: &[u8]) -> Result<EdkeyDerivedSecret, Error> {
        let h = blinding_hash_bytes(&self.public_key(), label, context)?;
        let mut expanded = Zeroizing::new(hash512(self.0.as_ref()));
        expanded[0] &= 248;
        expanded[31] &= 127;
        expanded[31] |= 64;
        let mut first = Zeroizing::new([0; 32]);
        first.copy_from_slice(&expanded[..32]);
        let scalar = Zeroizing::new(Scalar::from_bytes_mod_order(*first) * blinding_scalar(&h));
        if *scalar == Scalar::ZERO {
            return Err(Error::Authentication);
        }
        let prefix = Zeroizing::new(hash256_parts(&[&expanded[32..], &h]));
        Ok(EdkeyDerivedSecret { scalar, prefix })
    }
}

fn validate_parts(purpose: u32, parts: &[&[u8]]) -> Result<(), Error> {
    let first = parts.first().ok_or(Error::Truncated)?;
    let header = SignaturePurpose::decode(first.get(..8).ok_or(Error::Truncated)?)?;
    let length = parts.iter().try_fold(0_usize, |n, part| {
        n.checked_add(part.len()).ok_or(Error::Overflow)
    })?;
    header.validate_signed_size(length)?;
    if header.purpose() != purpose {
        return Err(Error::Authentication);
    }
    Ok(())
}
impl PkeyDerivedSecret {
    /// Compressed blinded Edwards public key.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        EdwardsPoint::mul_base(&self.0).compress().to_bytes()
    }
    /// Deterministic ECDSA signature, r and s in the official big-endian layout.
    pub fn sign(&self, purpose: u32, parts: &[&[u8]]) -> Result<[u8; 64], Error> {
        validate_parts(purpose, parts)?;
        let digest = hash512_parts(parts);
        let z = bits2scalar(&digest);
        let mut nonce = Rfc6979::new(&self.0, &digest);
        for _ in 0..128 {
            let k = Zeroizing::new(nonce.next()?);
            let r = affine_x_scalar(&EdwardsPoint::mul_base(&k))?;
            let s = Zeroizing::new(k.invert() * (z + r * *self.0));
            if r != Scalar::ZERO && *s != Scalar::ZERO {
                let mut signature = [0; 64];
                let mut rb = r.to_bytes();
                rb.reverse();
                signature[..32].copy_from_slice(&rb);
                let mut sb = Zeroizing::new(s.to_bytes());
                sb.reverse();
                signature[32..].copy_from_slice(sb.as_ref());
                return Ok(signature);
            }
            nonce.reject();
        }
        Err(Error::Entropy)
    }
}
impl EdkeyDerivedSecret {
    /// Compressed blinded Ed25519 public key.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        EdwardsPoint::mul_base(&self.scalar).compress().to_bytes()
    }
    /// Derived Ed25519 signature over the complete official purpose region.
    pub fn sign(&self, purpose: u32, parts: &[&[u8]]) -> Result<[u8; 64], Error> {
        use sha2::{Digest, Sha512};
        validate_parts(purpose, parts)?;
        let mut hash = Sha512::new();
        hash.update(self.prefix.as_ref());
        for part in parts {
            hash.update(part);
        }
        let wide = Zeroizing::new(<[u8; 64]>::from(hash.finalize()));
        let nonce = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&wide));
        let r = EdwardsPoint::mul_base(&nonce).compress().to_bytes();
        let public = self.public_key();
        let mut hash = Sha512::new();
        hash.update(r);
        hash.update(public);
        for part in parts {
            hash.update(part);
        }
        let challenge = Scalar::from_bytes_mod_order_wide(&hash.finalize().into());
        let s = Zeroizing::new(*nonce + challenge * *self.scalar);
        let mut signature = [0; 64];
        signature[..32].copy_from_slice(&r);
        signature[32..].copy_from_slice(&s.to_bytes());
        Ok(signature)
    }
}

/// Verify GNUnet's Edwards ECDSA signature with exact purpose/size checking.
pub fn verify_pkey(
    public: &[u8; 32],
    purpose: u32,
    parts: &[&[u8]],
    signature: &[u8; 64],
) -> Result<(), Error> {
    validate_parts(purpose, parts)?;
    let public = valid_point(public)?;
    let mut rb: [u8; 32] = signature[..32].try_into().map_err(|_| Error::Truncated)?;
    rb.reverse();
    let mut sb: [u8; 32] = signature[32..].try_into().map_err(|_| Error::Truncated)?;
    sb.reverse();
    let r =
        Option::<Scalar>::from(Scalar::from_canonical_bytes(rb)).ok_or(Error::Authentication)?;
    let s =
        Option::<Scalar>::from(Scalar::from_canonical_bytes(sb)).ok_or(Error::Authentication)?;
    if r == Scalar::ZERO || s == Scalar::ZERO {
        return Err(Error::Authentication);
    }
    let inv = s.invert();
    let z = bits2scalar(&hash512_parts(parts));
    let point = EdwardsPoint::mul_base(&(z * inv)) + public * (r * inv);
    if point.is_identity() || affine_x_scalar(&point)? != r {
        return Err(Error::Authentication);
    }
    Ok(())
}
/// Verify derived Ed25519 with canonical, non-small-order prime-subgroup points.
pub fn verify_edkey(
    public: &[u8; 32],
    purpose: u32,
    parts: &[&[u8]],
    signature: &[u8; 64],
) -> Result<(), Error> {
    use sha2::{Digest, Sha512};
    validate_parts(purpose, parts)?;
    let q = valid_point(public)?;
    let rb: [u8; 32] = signature[..32].try_into().map_err(|_| Error::Truncated)?;
    let r = valid_point(&rb)?;
    let sb: [u8; 32] = signature[32..].try_into().map_err(|_| Error::Truncated)?;
    let s =
        Option::<Scalar>::from(Scalar::from_canonical_bytes(sb)).ok_or(Error::Authentication)?;
    let mut hash = Sha512::new();
    hash.update(rb);
    hash.update(public);
    for part in parts {
        hash.update(part);
    }
    let challenge = Scalar::from_bytes_mod_order_wide(&hash.finalize().into());
    if EdwardsPoint::mul_base(&s) != r + q * challenge {
        return Err(Error::Authentication);
    }
    Ok(())
}

// RFC6979 uses the subgroup's 253-bit order. bits2int truncates the *left*
// 253 bits of SHA512, rather than reducing the entire SHA512 digest.
fn bits2bytes(digest: &[u8; 64], bytes: &mut [u8; 32]) {
    for i in 0..32 {
        bytes[i] = digest[i] >> 3;
        if i > 0 {
            bytes[i] |= digest[i - 1] << 5;
        }
    }
}
fn bits2scalar(digest: &[u8; 64]) -> Scalar {
    let mut bytes = Zeroizing::new([0; 32]);
    bits2bytes(digest, &mut bytes);
    bytes.reverse();
    Scalar::from_bytes_mod_order(*bytes)
}
struct Rfc6979 {
    k: Zeroizing<[u8; 64]>,
    v: Zeroizing<[u8; 64]>,
}
impl Rfc6979 {
    fn new(private: &Scalar, digest: &[u8; 64]) -> Self {
        let mut x = Zeroizing::new(private.to_bytes());
        x.reverse();
        let mut h = Zeroizing::new(bits2scalar(digest).to_bytes());
        h.reverse();
        let mut result = Self {
            k: Zeroizing::new([0; 64]),
            v: Zeroizing::new([1; 64]),
        };
        result.k = hmac512(
            result.k.as_ref(),
            &[result.v.as_ref(), &[0], x.as_ref(), h.as_ref()],
        );
        result.v = hmac512(result.k.as_ref(), &[result.v.as_ref()]);
        result.k = hmac512(
            result.k.as_ref(),
            &[result.v.as_ref(), &[1], x.as_ref(), h.as_ref()],
        );
        result.v = hmac512(result.k.as_ref(), &[result.v.as_ref()]);
        result
    }
    fn next(&mut self) -> Result<Scalar, Error> {
        for _ in 0..128 {
            self.v = hmac512(self.k.as_ref(), &[self.v.as_ref()]);
            let mut candidate = Zeroizing::new([0; 32]);
            bits2bytes(&self.v, &mut candidate);
            candidate.reverse();
            if let Some(scalar) =
                Option::<Scalar>::from(Scalar::from_canonical_bytes(*candidate)).map(Zeroizing::new)
                && *scalar != Scalar::ZERO
            {
                return Ok(*scalar);
            }
            self.reject();
        }
        Err(Error::Entropy)
    }
    fn reject(&mut self) {
        self.k = hmac512(self.k.as_ref(), &[self.v.as_ref(), &[0]]);
        self.v = hmac512(self.k.as_ref(), &[self.v.as_ref()]);
    }
}

const_monty_params!(
    EdwardsField,
    U256,
    "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"
);
type Field = crypto_bigint::modular::ConstMontyForm<EdwardsField, { U256::LIMBS }>;
fn affine_x_scalar(point: &EdwardsPoint) -> Result<Scalar, Error> {
    let mut encoded = point.compress().to_bytes();
    let parity = encoded[31] >> 7;
    encoded[31] &= 127;
    let y = Field::new(&U256::from_le_slice(&encoded));
    let d = Field::new(&U256::from_be_hex(
        "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3",
    ));
    let yy = y * y;
    let inverse =
        Option::<Field>::from((d * yy + Field::ONE).invert()).ok_or(Error::Authentication)?;
    let xx = (yy - Field::ONE) * inverse;
    let mut x = xx.pow(&U256::from_be_hex(
        "0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
    ));
    let alternative = x * Field::new(&U256::from_be_hex(
        "2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0",
    ));
    x = Field::ct_select(&alternative, &x, (x * x).ct_eq(&xx));
    if x * x != xx {
        return Err(Error::Authentication);
    }
    x = Field::ct_select(
        &x,
        &-x,
        !Choice::from_u8_eq(x.retrieve().to_le_bytes()[0] & 1, parity),
    );
    Ok(Scalar::from_bytes_mod_order(
        x.retrieve().to_le_bytes().into(),
    ))
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Compare actual unmodified C GNUnet vectors."
    )]
    use super::*;
    use crate::test_support::hex;
    #[test]
    fn normal_c_pkey_edkey_vectors() -> Result<(), Error> {
        {
            let label = "testdelegation";
            let owner = PkeySecret::from_bytes(hex(
                "98fdfa257990fa50d4e7c87821a0712195e58597909673f3dfeaefa452b6d750",
            )?)?;
            assert_eq!(
                owner.public_key(),
                hex("677c477d2d93097c85b195c6f96d84ff61f5982c2c4fe02d5a11fedfb0c2901f")?
            );
            assert_eq!(
                blinding_hash(&owner.public_key(), label, "gns")?,
                hex(
                    "a507175bf3c2571e3eb4ce2cb9695436aa0089d1568cc6cd073e8aceb405293e4af92f1140813bad66d96b4911c681587bde88e125fc8ecf3529b8ca6d03fec1"
                )?
            );
            let derived = owner.derive(label, "gns")?;
            assert_eq!(
                derived.0.to_bytes(),
                hex("9c3edb891fe6aa29a79faccbc2b228860c032cb2f2c7c8dbcedf63000f5e4c0a")?
            );
            assert_eq!(
                derived.public_key(),
                hex("182bb636eda79f795711bc2708adbb242a60446ad3c30803121d03d348b7ceb6")?
            );
            assert_eq!(
                derive_public(&owner.public_key(), label, "gns")?,
                derived.public_key()
            );
            let preimage = hex::<80>(
                "000000500000000f003ff2aa5408db403f9431e147583bc445b3464e4d6d22e9e5e994f746c895a40037161e488e31548cbc0349dbbf20d59966471f65214a80f71c3112de1b0c2a1ec9d51477e9f150",
            )?;
            let signature = hex(
                "0faa24186471bcafa07876a870011f9af133e6c4a2721949be60a58569f0ee730666a7da83acc3a4440fc5978f9f6cab6dfe90cd4c96c6eaf71413da22a0fcf3",
            )?;
            assert_eq!(derived.sign(15, &[&preimage])?, signature);
            verify_pkey(
                &derived.public_key(),
                15,
                &[&preimage[..16], &preimage[16..]],
                &signature,
            )?;
            assert_eq!(
                verify_pkey(&derived.public_key(), 14, &[&preimage], &signature),
                Err(Error::Authentication)
            );
        }
        {
            let label = "testdelegation";
            let owner = EdkeySecret::from_seed(hex(
                "5af7020ee19160328832352bbc6a68a8d71a7cbe1b929969a7c66d415a0d8f65",
            )?);
            assert_eq!(
                owner.public_key(),
                hex("3cf4b924032022f0dc50581453b85d93b047b63d446c5845cb48445ddb96688f")?
            );
            assert_eq!(
                blinding_hash(&owner.public_key(), label, "gns")?,
                hex(
                    "b6736f816b4bf0a775000c2faed8e7eed80211867210a5999415b8c7bd79df296ab57d391584db90e69836d470fae9c07e7f9b70f2754c94c1e2ad5371fd98f4"
                )?
            );
            let derived = owner.derive(label, "gns")?;
            assert_eq!(
                derived.scalar.to_bytes(),
                hex("d1474eb42d16a0a1748df434c01ab78eea88db6ec8a34deca8100b23d4291b0b")?
            );
            assert_eq!(
                *derived.prefix,
                hex("14f2c06bedc3aa2df071139c503934f34bfa6311a852f211f73adf2e0761ec35")?
            );
            assert_eq!(
                derived.public_key(),
                hex("9bf233198c6d53bbdbac495cabd91049a684af3f4051bacab0dcf21c8cf27a1a")?
            );
            assert_eq!(
                derive_public(&owner.public_key(), label, "gns")?,
                derived.public_key()
            );
            let preimage = hex::<96>(
                "000000600000000f003ff2aa5408db40f65baa6d85c42f5afb8d378bc8ee68fdb9d7deb4bc2c6a725bba05c22e65727186e226f9c81e5d44407e1cb17d10d1fd80093cb4c2acd9dedbb53bd8d94cafceb6a01fb00aa654d0c2e8f1dcaeb8f9e0",
            )?;
            let signature = hex(
                "e3c05e2ed7f49f8e357653d3da057462ba51685df36ce5c9707f33f6a18c22deab8b8bc98d1d3ff45e3b46a30ae31be8ea70a8125f63f260ce7c30339a52e30f",
            )?;
            assert_eq!(derived.sign(15, &[&preimage])?, signature);
            verify_edkey(
                &derived.public_key(),
                15,
                &[&preimage[..16], &preimage[16..]],
                &signature,
            )?;
            assert_eq!(
                verify_edkey(&derived.public_key(), 14, &[&preimage], &signature),
                Err(Error::Authentication)
            );
        }
        {
            let label = "éxample";
            let owner = PkeySecret::from_bytes(hex(
                "98fdfa257990fa50d4e7c87821a0712195e58597909673f3dfeaefa452b6d750",
            )?)?;
            assert_eq!(
                owner.public_key(),
                hex("677c477d2d93097c85b195c6f96d84ff61f5982c2c4fe02d5a11fedfb0c2901f")?
            );
            assert_eq!(
                blinding_hash(&owner.public_key(), label, "gns")?,
                hex(
                    "c49e23c019f98f8982f3c21cddb3e0bfc544eb2af3475e2c340b34926e0ca26aa91b693e75f916b4b4115d0e68a9244bea86881d6b1e4d40c4ef3e99c6553961"
                )?
            );
            let derived = owner.derive(label, "gns")?;
            assert_eq!(
                derived.0.to_bytes(),
                hex("78d7d708530e575ea3be7532307600d950a80da2748ab7058543d8713aac4603")?
            );
            assert_eq!(
                derived.public_key(),
                hex("b546927da833001ac5d05888e1970b4756ba560aefe2a153f6efdfaf1059d794")?
            );
            assert_eq!(
                derive_public(&owner.public_key(), label, "gns")?,
                derived.public_key()
            );
            let preimage = hex::<80>(
                "000000500000000f003ff2aa5408db414cbbb35f902951580d2bc2cd1507cff20e85a404f87f2da04a8e5b3c4fc016b234ca78fe91d5b5a1efa9841683dbcb3a123890a40f45c21e140d1c8a03d0c34c",
            )?;
            let signature = hex(
                "079367c14ff2939afd2b4e8e96035cf31b468701ddaf72895c24580f3b03d4880935638d16b22dc5327eb3f0365ca842cb331242050c06974e908dd08939006c",
            )?;
            assert_eq!(derived.sign(15, &[&preimage])?, signature);
            verify_pkey(
                &derived.public_key(),
                15,
                &[&preimage[..16], &preimage[16..]],
                &signature,
            )?;
            assert_eq!(
                verify_pkey(&derived.public_key(), 14, &[&preimage], &signature),
                Err(Error::Authentication)
            );
        }
        {
            let label = "éxample";
            let owner = EdkeySecret::from_seed(hex(
                "5af7020ee19160328832352bbc6a68a8d71a7cbe1b929969a7c66d415a0d8f65",
            )?);
            assert_eq!(
                owner.public_key(),
                hex("3cf4b924032022f0dc50581453b85d93b047b63d446c5845cb48445ddb96688f")?
            );
            assert_eq!(
                blinding_hash(&owner.public_key(), label, "gns")?,
                hex(
                    "454f1f18943cea9b86a3bb6dc8ad7bf56fa3e629e7e903449fba6a8adfa3a01c02840ceb3ce6511bb62eb2d4e919b5f91e705744e1bbf5f57bcf5c927f5aa7a7"
                )?
            );
            let derived = owner.derive(label, "gns")?;
            assert_eq!(
                derived.scalar.to_bytes(),
                hex("c900a14dc936f44fd7bee451e6d8c1980da9396ac9295ca2896616e1eededa02")?
            );
            assert_eq!(
                *derived.prefix,
                hex("a1d75094db7f084fb8f3994615d05e176e326fe3e5cfbdc660ea0a8d1c7e8f01")?
            );
            assert_eq!(
                derived.public_key(),
                hex("42e227223e521d55328e448a5ad174889f210f2518c8e69aa0408d4ba785d01e")?
            );
            assert_eq!(
                derive_public(&owner.public_key(), label, "gns")?,
                derived.public_key()
            );
            let preimage = hex::<96>(
                "000000600000000f003ff2aa5408db416e813ef7bffe09b5fbffa5a4c1b456a068ce37474aa7ac45453d11a771b99f1dc554b19609cc571ede3db82b996d7dc38ab4694b104779ba06d010da3b3c6c90b895316cdd75d788bc72665152946c29",
            )?;
            let signature = hex(
                "68c4009a29949ffe09b09449639defa9d2ebfac3733a48d0cac6e32d458f5f8a32b0ff14cb9c51b2cf60a3ecf2e245dea893f5a7d63c819783b99f9ce92cba0c",
            )?;
            assert_eq!(derived.sign(15, &[&preimage])?, signature);
            verify_edkey(
                &derived.public_key(),
                15,
                &[&preimage[..16], &preimage[16..]],
                &signature,
            )?;
            assert_eq!(
                verify_edkey(&derived.public_key(), 14, &[&preimage], &signature),
                Err(Error::Authentication)
            );
        }
        Ok(())
    }
}
