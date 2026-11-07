use super::*;
use crate::{ShareCheck, Subgroup};

fn require(condition: bool) -> Result<(), Error> {
    if condition {
        Ok(())
    } else {
        Err(Error::InvalidProof)
    }
}

fn key() -> Result<PublicKey, Error> {
    // Public admissible arithmetic modulus, not a key-generation/FAIR fixture.
    let mut bytes = [0; 256];
    bytes[0] = 0x80;
    bytes[255] = 1;
    Ok(PublicKey::from_bytes(&bytes)?)
}
fn job(value: &U2048, key: &PublicKey, group: &Group) -> Result<FairRecoveryJob, Error> {
    FairRecoveryJob::new(
        key,
        key.plaintext(value.to_be_bytes().as_ref())?,
        group,
        Limits::default(),
    )
}
fn ready(job: &mut FairRecoveryJob) -> Result<usize, Error> {
    for turns in 1..=4096 {
        if job.advance(1)? == Progress::Ready {
            return Ok(turns);
        }
    }
    Err(Error::Capacity)
}

#[test]
fn bounded_rationals_canonical_upper_scalar_and_zero_use_one_fixed_schedule() -> Result<(), Error> {
    let key = key()?;
    let group = Group::new()?;
    let n = U2048::from_be_slice(&key.to_bytes());
    let high = Q.wrapping_sub(&U1024::ONE);
    let half_positive = Q.wrapping_add(&U1024::ONE).shr_vartime(1);
    let half_negative = Q.wrapping_sub(&U1024::ONE).shr_vartime(1);
    // 2*((n+1)/2)=1 modn; -2*((n-1)/2)=1 modn. These closed
    // forms independently specify the positive/negative rational outputs.
    for (input, expected) in [
        (U2048::ZERO, U1024::ZERO),
        (high.resize(), high),
        (Q.resize(), U1024::ZERO),
        (n.wrapping_add(&U2048::ONE).shr_vartime(1), half_positive),
        (n.wrapping_sub(&U2048::ONE).shr_vartime(1), half_negative),
    ] {
        let mut recovery = job(&input, &key, &group)?;
        require(matches!(recovery.take_result(), Err(Error::NotReady)))?;
        require((ready(&mut recovery)?) == (3073))?;
        let result = recovery.take_result()?;
        require((U1024::from_be_slice(result.to_bytes().as_ref())) == (expected))?;
        require(matches!(recovery.take_result(), Err(Error::Finished)))?;
        require((recovery.advance(1)) == (Err(Error::Finished)))?;
    }
    // A itself would need a denominator of magnitude2^1023 for this modulus;
    // the512-bit denominator range must not be silently widened.
    let mut invalid = job(&A, &key, &group)?;
    require((ready(&mut invalid)) == (Err(Error::InvalidProof)))?;
    require(matches!(invalid.take_result(), Err(Error::InvalidProof)))?;
    // A valid rational reconstruction still fails an unrelated commitment.
    let input = n.wrapping_add(&U2048::ONE).shr_vartime(1);
    let mut recovery = job(&input, &key, &group)?;
    ready(&mut recovery)?;
    let mut check = ShareCheck::new(
        recovery.take_result()?,
        Subgroup::identity(),
        &group,
        Limits::default(),
    )?;
    let mut refused = false;
    for _ in 0..1024 {
        match check.advance(1) {
            Err(Error::InvalidProof) => {
                refused = true;
                break;
            }
            Ok(Progress::Advanced) => {}
            Ok(Progress::Ready) => return Err(Error::InvalidProof),
            Err(error) => return Err(error),
        }
    }
    require(refused)?;
    Ok(())
}

#[test]
fn cancellation_and_invalid_admission_erase_original_and_partial_inverse() -> Result<(), Error> {
    let key = key()?;
    let group = Group::new()?;
    let mut recovery = job(&U2048::from_u32(7), &key, &group)?;
    for _ in 0..2050 {
        require((recovery.advance(1)?) == (Progress::Advanced))?;
    }
    require(recovery.inverse.is_some())?;
    recovery.cancel();
    require((*recovery.original) == (U2048::ZERO))?;
    require((*recovery.r0) == (U2048::ZERO))?;
    require((*recovery.r1) == (U2048::ZERO))?;
    require((*recovery.t0) == (U4096::ZERO))?;
    require((*recovery.t1) == (U4096::ZERO))?;
    require(
        recovery.inverse.is_none() && recovery.numerator.is_none() && recovery.result.is_none(),
    )?;
    require((recovery.advance(1)) == (Err(Error::Cancelled)))?;
    require(matches!(recovery.take_result(), Err(Error::Cancelled)))?;
    let mut invalid = job(&U2048::from_u32(9), &key, &group)?;
    require((invalid.advance(0)) == (Err(Error::Capacity)))?;
    require((*invalid.original) == (U2048::ZERO))?;
    require(matches!(invalid.take_result(), Err(Error::Capacity)))?;
    // A plaintext object from another modulus grants no association to this one.
    let mut other_bytes = key.to_bytes();
    other_bytes[255] = 3;
    let other = PublicKey::from_bytes(&other_bytes)?;
    let value = other.plaintext(&key.to_bytes())?;
    require(matches!(
        FairRecoveryJob::new(&key, value, &group, Limits::default()),
        Err(Error::InvalidInput)
    ))?;
    Ok(())
}
