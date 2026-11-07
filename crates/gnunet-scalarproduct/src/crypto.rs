use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::Identity,
};
use gnunet_crypto::Entropy;
use gnunet_types::Error;
use zeroize::{Zeroize, Zeroizing};

/// One exact interleaved Alice (g_i, h_i) pair of compressed Edwards points.
pub type PointPair = [[u8; 32]; 2];

/// Canonical prime-subgroup point, including the group's identity.
/// This is structural validation, not authentication of its native sender.
pub fn validate_point(bytes: &[u8; 32]) -> Result<EdwardsPoint, Error> {
    let point = CompressedEdwardsY(*bytes)
        .decompress()
        .ok_or(Error::Malformed)?;
    if point.compress().to_bytes() != *bytes || !point.is_torsion_free() {
        return Err(Error::Authentication);
    }
    Ok(point)
}

pub(crate) fn signed(value: i64) -> Scalar {
    let scalar = Scalar::from(value.unsigned_abs());
    if value < 0 { -scalar } else { scalar }
}

fn random_scalar(entropy: &mut impl Entropy) -> Result<Scalar, Error> {
    // Uniform rejection over [0,2^253), with a finite attempt bound. No modulo
    // bias or substitute entropy. A partial provider fill is wiped on failure.
    let mut bytes = Zeroizing::new([0; 32]);
    for _ in 0..128 {
        if let Err(error) = entropy.fill(&mut bytes[..]) {
            bytes.zeroize();
            return Err(error);
        }
        bytes[31] &= 31;
        if let Some(scalar) = Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes))
            && scalar != Scalar::ZERO
        {
            bytes.zeroize();
            return Ok(scalar);
        }
        bytes.zeroize();
    }
    Err(Error::EntropyUnavailable)
}

/// One private Alice blinding key. It cannot be cloned, formatted or exported.
/// Explicit zeroization covers owned buffers/scalars, not compiler registers.
pub struct AliceKey(Zeroizing<Scalar>);
impl AliceKey {
    /// Sample a fresh nonzero key using the original explicit entropy port.
    pub fn generate(entropy: &mut impl Entropy) -> Result<Self, Error> {
        Ok(Self(Zeroizing::new(random_scalar(entropy)?)))
    }

    /// Encrypt one signed coefficient with a fresh independent nonzero r_i.
    /// g=G*r_i, h=G*(r_i*a+a_i). Identity columns are resampled because the
    /// fixed C peer's libsodium multiplication rejects identity inputs.
    pub fn encrypt(&self, value: i64, entropy: &mut impl Entropy) -> Result<PointPair, Error> {
        for _ in 0..128 {
            let r = Zeroizing::new(random_scalar(entropy)?);
            let mut h = Zeroizing::new(*r * *self.0 + signed(value));
            if *h == Scalar::ZERO {
                h.zeroize();
                continue;
            }
            let g_point = ED25519_BASEPOINT_POINT * *r;
            let h_point = ED25519_BASEPOINT_POINT * *h;
            return Ok([g_point.compress().to_bytes(), h_point.compress().to_bytes()]);
        }
        Err(Error::EntropyUnavailable)
    }

    pub(crate) fn remove(&self, g: &EdwardsPoint, h: &EdwardsPoint) -> EdwardsPoint {
        h - g * *self.0
    }
}

/// Add one validated pair weighted by a signed Bob coefficient to an aggregate.
/// Nothing is committed to the caller's aggregate if either point is invalid.
pub fn aggregate(
    current: PointPair,
    pair: PointPair,
    coefficient: i64,
) -> Result<PointPair, Error> {
    let old_g = validate_point(&current[0])?;
    let old_h = validate_point(&current[1])?;
    let g = validate_point(&pair[0])?;
    let h = validate_point(&pair[1])?;
    if g == EdwardsPoint::identity() || h == EdwardsPoint::identity() {
        return Err(Error::Authentication);
    }
    let weight = Zeroizing::new(signed(coefficient));
    Ok([
        (old_g + g * *weight).compress().to_bytes(),
        (old_h + h * *weight).compress().to_bytes(),
    ])
}

/// Remove Alice's blinding factor, retaining genuine zero as the identity point.
pub fn unblind(key: &AliceKey, aggregates: PointPair) -> Result<[u8; 32], Error> {
    let g = validate_point(&aggregates[0])?;
    let h = validate_point(&aggregates[1])?;
    Ok(key.remove(&g, &h).compress().to_bytes())
}

pub(crate) fn identity_pair() -> PointPair {
    let identity = EdwardsPoint::identity().compress().to_bytes();
    [identity, identity]
}
