//! Official v0.29.1 Elligator2 mapping and independent KEM0x0022.
//! No hash-to-curve replacement, implicit entropy or ordinary-KEM fallback.
use crate::{
    Prk,
    exchange::{DhSecret, EcdhePublic, EcdheSecret},
    hkdf_extract,
};
use crypto_bigint::{Choice, CtEq, CtGt, CtLt, CtSelect, U256, const_monty_params};
use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    traits::Identity,
};
use gnunet_crypto::Entropy;
use gnunet_types::Error;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};
#[path = "elligator_torsion.rs"]
mod torsion;
const_monty_params!(
    Prime,
    U256,
    "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"
);
type Field = crypto_bigint::modular::ConstMontyForm<Prime, { U256::LIMBS }>;
const P: U256 =
    U256::from_be_hex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
const INVERSE: U256 =
    U256::from_be_hex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb");
const HALF: U256 =
    U256::from_be_hex("3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6");
const ROOT: U256 =
    U256::from_be_hex("0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe");
fn a() -> Field {
    Field::new(&U256::from_u64(486662))
}
fn inv(x: Field) -> Field {
    x.pow(&INVERSE)
}
fn least_root(x: Field) -> Field {
    let first = x.pow(&ROOT);
    let alt = first
        * Field::new(&U256::from_be_hex(
            "2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0",
        ));
    let candidate = Field::ct_select(&alt, &first, (first * first).ct_eq(&x));
    Field::ct_select(&candidate, &-candidate, candidate.retrieve().ct_gt(&HALF))
}
/// Exact opaque32-byte representative, including the two random top bits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Representative([u8; 32]);
impl Representative {
    /// Retain untrusted representative bytes. Decoding clears the source top2bits.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    /// Borrow all32 original context bytes, including ignored mapping top bits.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
/// Direct-map output and its source `high_y` choice, without peer authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decoded {
    /// Canonical Montgomery u-coordinate; X25519 still rejects low-order DH.
    pub public: EcdhePublic,
    /// Source direct-map residue branch, not the representative's top bits.
    pub high_y: bool,
}
/// Source direct map over a254-bit representative, with top2bits masked.
/// It is total as a public mapping. No DH or low-order admission occurs here.
#[must_use]
pub fn decode(repr: Representative) -> Decoded {
    let mut bytes = repr.0;
    bytes[31] &= 63;
    let r = Field::new(&U256::from_le_slice(&bytes));
    let w = -a() * inv(Field::ONE + Field::new(&U256::from_u64(2)) * r * r);
    let g = w * w * w + a() * w * w + w;
    let leg = g.pow(&HALF);
    let high = leg.ct_eq(&Field::ONE) | leg.ct_eq(&Field::ZERO);
    let point = Field::ct_select(&(-w - a()), &w, high);
    Decoded {
        public: EcdhePublic::from_bytes(point.retrieve().to_le_bytes().into()),
        high_y: bool::from(high),
    }
}
/// Source inverse map for a canonical public Montgomery u-coordinate.
/// `random_tweak` bit0 selects inverse branch and bits1/2 are encoded in the
/// representative's high bits; other tweak bits are ignored as in C.
/// Noncanonical public coordinates are explicitly outside this safe profile.
pub fn encode(public: EcdhePublic, random_tweak: u8) -> Result<Representative, Error> {
    let raw = U256::from_le_slice(public.as_bytes());
    if !bool::from(raw.ct_lt(&P)) {
        return Err(Error::InvalidInput);
    }
    let x = Field::new(&raw);
    let b = -x * inv(x + a());
    let b = Field::ct_select(&b, &inv(b), Choice::from_u8_eq(random_tweak & 1, 1));
    let c = b * inv(Field::new(&U256::from_u64(2)));
    let root = least_root(c);
    let valid = (root * root).ct_eq(&c);
    let mut bytes: [u8; 32] = root.retrieve().to_le_bytes().into();
    bytes[31] |= ((random_tweak >> 1) & 1) << 7;
    bytes[31] |= ((random_tweak >> 2) & 1) << 6;
    if !bool::from(valid) {
        return Err(Error::InvalidInput);
    }
    Ok(Representative(bytes))
}
/// Owner-held unclamped special scalar; original low3bits choose source torsion.
/// Secret bytes erase on drop, cannot clone/format, and are not a seed key.
///
/// ```compile_fail
/// let key=gnunet_session_crypto::elligator::Secret::from_bytes([1;32]);
/// let _copy=key.clone();
/// ```
/// ```compile_fail
/// let key=gnunet_session_crypto::elligator::Secret::from_bytes([1;32]);
/// let _formatted=format!("{key:?}");
/// ```
pub struct Secret(Zeroizing<[u8; 32]>);
impl Secret {
    /// Import source scalar bytes; representability is checked by public/encapsulate.
    #[must_use]
    pub fn from_bytes(mut bytes: [u8; 32]) -> Self {
        let s = Self(Zeroizing::new(bytes));
        bytes.zeroize();
        s
    }
    /// Source special public point: clamped Edwards base multiplication plus one
    /// of8 low-order points selected from original scalar low3bits, then Montgomery.
    /// Constant-time selection avoids secret table indexing; scalar/point scratch
    /// owners erase on drop. Unrepresentable points return an actual error.
    pub fn public(&self, tweak: u8) -> Result<(EcdhePublic, Representative), Error> {
        // Normal libsodium rejects the original all-zero scalar even after
        // applying its clamp. A safe Rust caller receives an error, not abort.
        if bool::from(ConstantTimeEq::ct_eq(self.0.as_ref(), &[0; 32])) {
            return Err(Error::InvalidInput);
        }
        let high = Zeroizing::new(EdwardsPoint::mul_base_clamped(*self.0));
        let mut low = Zeroizing::new(EdwardsPoint::identity());
        let index = self.0[0] & 7;
        for (i, bytes) in torsion::TORSION.iter().enumerate() {
            let point = CompressedEdwardsY(*bytes)
                .decompress()
                .ok_or(Error::InvalidInput)?;
            *low = EdwardsPoint::conditional_select(
                &low,
                &point,
                ConstantTimeEq::ct_eq(&index, &(i as u8)),
            );
        }
        let point = Zeroizing::new(*high + *low);
        let public = EcdhePublic::from_bytes(point.to_montgomery().to_bytes());
        Ok((public, encode(public, tweak)?))
    }
    /// Generate in the source32-byte scalar then1-byte temporary tweak order.
    /// The caller explicitly bounds rejection attempts; source has an unbounded
    /// loop. Exhaustion is a resource failure, never an invented valid key.
    pub fn generate(
        entropy: &mut impl Entropy,
        attempts: core::num::NonZeroUsize,
    ) -> Result<Self, Error> {
        for _ in 0..attempts.get() {
            let mut bytes = Zeroizing::new([0; 32]);
            entropy.fill(bytes.as_mut()).map_err(|_| Error::Entropy)?;
            let mut tweak = [0];
            entropy.fill(&mut tweak).map_err(|_| Error::Entropy)?;
            let candidate = Self::from_bytes(*bytes);
            if candidate.public(tweak[0]).is_ok() {
                return Ok(candidate);
            }
        }
        Err(Error::Capacity)
    }
}
const SUITE: &[u8] = b"KEM\x00\x22";
fn shared(dh: DhSecret, enc: Representative, recipient: EcdhePublic) -> Result<Prk, Error> {
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
/// Deterministic official0x0022 KEM with source representative in kem_context.
pub fn encapsulate(
    recipient: EcdhePublic,
    ephemeral: &Secret,
    tweak: u8,
) -> Result<(Representative, Prk), Error> {
    let (_public, enc) = ephemeral.public(tweak)?;
    let scalar = EcdheSecret::from_bytes(*ephemeral.0);
    let dh = scalar.exchange_raw(recipient)?;
    Ok((enc, shared(dh, enc, recipient)?))
}
/// Source first reserves1 random tweak byte, then creates its special scalar.
/// Rejection-loop resource budget is explicit; all secret owner scratch erases.
pub fn encapsulate_random(
    recipient: EcdhePublic,
    entropy: &mut impl Entropy,
    attempts: core::num::NonZeroUsize,
) -> Result<(Representative, Prk), Error> {
    let mut tweak = [0];
    entropy.fill(&mut tweak).map_err(|_| Error::Entropy)?;
    let ephemeral = Secret::generate(entropy, attempts)?;
    encapsulate(recipient, &ephemeral, tweak[0])
}
/// Official0x0022 decapsulation. All-zero/low-order DH returns Authentication;
/// the C library asserts on that path, so no malformed normal-C case is run.
pub fn decapsulate(recipient: &EcdheSecret, enc: Representative) -> Result<Prk, Error> {
    let public = decode(enc).public;
    shared(recipient.exchange_raw(public)?, enc, recipient.public_key())
}
