//! One-pass ECMQV shared-secret derivation for the admitted prime-order curves.

use p256::elliptic_curve::{
    CurveArithmetic, CurveGroup, FieldBytes, Group, PublicKey, SecretKey,
    group::ff::{Field, PrimeField},
    point::AffineCoordinates,
};
use zeroize::Zeroizing;

pub(super) fn shared<C: CurveArithmetic>(
    key: &SecretKey<C>,
    originator: &PublicKey<C>,
    ephemeral: &PublicKey<C>,
    auxiliary_bits: usize,
) -> Option<Zeroizing<FieldBytes<C>>> {
    let local = key.public_key();
    let local_factor = auxiliary(&local, auxiliary_bits)?;
    let ephemeral_factor = auxiliary(ephemeral, auxiliary_bits)?;
    let private = key.to_nonzero_scalar();

    // NIST SP 800-56A §5.7.2.3.2 reuses V's static pair as its
    // ephemeral pair. Each supported NIST curve has cofactor one.
    let scalar = Zeroizing::new(*private.as_ref() * (C::Scalar::ONE + local_factor));
    let peer = C::ProjectivePoint::from(*ephemeral.as_affine())
        + ephemeral_factor * originator.as_affine();
    let product = Zeroizing::new(*scalar * peer);
    if bool::from(product.is_identity()) {
        return None;
    }
    let affine = Zeroizing::new(product.to_affine());
    Some(Zeroizing::new(affine.x()))
}

fn auxiliary<C: CurveArithmetic>(point: &PublicKey<C>, bits: usize) -> Option<C::Scalar> {
    let x = point.as_affine().x();
    let mut truncated = FieldBytes::<C>::default();
    let first = truncated.len().checked_sub(bits / 8 + 1)?;
    truncated[first..].copy_from_slice(&x[first..]);
    let marker = 1_u8 << (bits % 8);
    truncated[first] = (truncated[first] & (marker - 1)) | marker;
    C::Scalar::from_repr(truncated).into_option()
}
