//! Actual transcript/algebra and lifecycle cases with deterministic explicit
//! entropy. These legal draws are fixtures, not a production sampling profile,
//! C interoperability or evidence of general1023-bit response representability.
use super::*;
use crate::FairEquationCheck;
use gnunet_types::Error as Fault;
use gnunet_wire::official::secretsharing::FairEncryption;

struct Draws {
    calls: usize,
    wide_beta: bool,
    fail_at: Option<usize>,
}
impl Entropy for Draws {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Fault> {
        let at = self.calls;
        self.calls += 1;
        if self.fail_at == Some(at) {
            bytes.fill(0xa5);
            return Err(Fault::EntropyUnavailable);
        }
        if bytes.len() != 256 {
            return Err(Fault::InvalidInput);
        }
        bytes.fill(0);
        // Actual Paillier u=2, then beta, then commitment randomizer s=2.
        if at == 1 {
            if self.wide_beta {
                bytes[127] = 1;
            }
        } else {
            bytes[255] = 2;
        }
        Ok(())
    }
}
fn key() -> Result<PublicKey, Error> {
    // Legal public2048-bit odd modulus; factorization is not needed to check
    // this public encryption/equation test. No private key is manufactured.
    let mut bytes = [0xff; 256];
    bytes[255] = 0x61;
    Ok(PublicKey::from_bytes(&bytes)?)
}
fn scalar(value: u8) -> Result<Scalar, Error> {
    let mut bytes = Zeroizing::new([0; 128]);
    bytes[127] = value;
    Scalar::from_bytes(&bytes)
}
fn check(value: bool) -> Result<(), Error> {
    if value {
        Ok(())
    } else {
        Err(Error::InvalidProof)
    }
}
fn finish(job: &mut FairProver, draws: &mut Draws) -> Result<(), Error> {
    for _ in 0..1024 {
        if job.advance(draws, 64)? == Progress::Ready {
            return Ok(());
        }
    }
    Err(Error::Capacity)
}
fn policy() -> Limits {
    Limits {
        units_per_turn: 64,
        ..Limits::default()
    }
}

#[test]
fn actual_representable_transcript_passes_the_existing_independent_equations() -> Result<(), Error>
{
    let group = Group::new()?;
    let key = key()?;
    let mut job = FairProver::new(
        scalar(1)?,
        &key,
        &group,
        policy(),
        gnunet_paillier::Limits::default(),
    )?;
    let mut draws = Draws {
        calls: 0,
        wide_beta: false,
        fail_at: None,
    };
    check(matches!(job.take_result(), Err(Error::NotReady)))?;
    finish(&mut job, &mut draws)?;
    check(draws.calls == 3 && job.secrets.is_none())?;
    let proof = job.take_result()?;
    check(matches!(job.take_result(), Err(Error::Finished)))?;
    let fields = FairEncryption::decode(&proof).map_err(Error::Source)?;
    check(fields.h().map_err(Error::Source)? == &group.generator().to_bytes())?;
    check(fields.t1().map_err(Error::Source)? == &crate::Subgroup::identity().to_bytes())?;
    check(fields.ciphertext().map_err(Error::Source)?[..4] == [0; 4])?;
    let digest = gnunet_crypto::hash512(&proof[..1284]);
    check(
        fields.z().map_err(Error::Source)?[..64] == [0; 64]
            && fields.z().map_err(Error::Source)?[64..] == digest,
    )?;
    let mut verifier = FairEquationCheck::new(&key, &proof, &group, policy())?;
    for _ in 0..1024 {
        if verifier.advance(64)? == Progress::Ready {
            let result = verifier.take_result()?;
            return check(
                result.modulus() == &key.to_bytes()
                    && result.h() == group.generator()
                    && result.ciphertext().to_wire()
                        == *fields.ciphertext().map_err(Error::Source)?,
            );
        }
    }
    Err(Error::Capacity)
}

#[test]
fn unrepresentable_actual_attempt_refuses_without_reduction_retry_or_output() -> Result<(), Error> {
    let group = Group::new()?;
    let mut job = FairProver::new(
        scalar(1)?,
        &key()?,
        &group,
        policy(),
        gnunet_paillier::Limits::default(),
    )?;
    let mut draws = Draws {
        calls: 0,
        wide_beta: true,
        fail_at: None,
    };
    let expected = Error::Source(Fault::TooLarge);
    check(finish(&mut job, &mut draws) == Err(expected))?;
    check(draws.calls == 3 && job.secrets.is_none() && matches!(job.work, Work::Closed))?;
    check(job.fields.ciphertext == [0; 516] && job.fields.z == [0; 128])?;
    check(job.advance(&mut draws, 64) == Err(expected))?;
    check(job.take_result() == Err(expected) && draws.calls == 3)
}

#[test]
fn integer_response_checks_full_share_product_and_boundary_carry() -> Result<(), Error> {
    let max = Scalar(Zeroizing::new(Q.wrapping_sub(&U1024::ONE)));
    let e = U2048::ONE.shl(511);
    let expected = Error::Source(Fault::TooLarge);
    check(checked_response(&U2048::ZERO, &e, &max) == Err(expected))?;
    let boundary = U2048::ONE.shl(1024).wrapping_sub(&U2048::ONE);
    check(checked_response(&boundary, &U2048::ONE, &scalar(1)?) == Err(expected))?;
    check(checked_response(&U2048::ZERO, &U2048::ONE, &max)? == encode(&max.0))
}

#[test]
fn entropy_failure_partial_and_ready_cancellation_erase_attempts() -> Result<(), Error> {
    let group = Group::new()?;
    let key = key()?;
    for fail_at in [0, 1, 2] {
        let mut job = FairProver::new(
            scalar(1)?,
            &key,
            &group,
            policy(),
            gnunet_paillier::Limits::default(),
        )?;
        let mut draws = Draws {
            calls: 0,
            wide_beta: false,
            fail_at: Some(fail_at),
        };
        let expected = if fail_at == 0 {
            Error::Paillier(gnunet_paillier::Error::Entropy(Fault::EntropyUnavailable))
        } else {
            Error::Source(Fault::EntropyUnavailable)
        };
        check(finish(&mut job, &mut draws) == Err(expected))?;
        check(
            job.secrets.is_none()
                && job.advance(&mut draws, 1) == Err(expected)
                && job.take_result() == Err(expected),
        )?;
    }
    for ready in [false, true] {
        let mut job = FairProver::new(
            scalar(1)?,
            &key,
            &group,
            policy(),
            gnunet_paillier::Limits::default(),
        )?;
        let mut draws = Draws {
            calls: 0,
            wide_beta: false,
            fail_at: None,
        };
        if ready {
            finish(&mut job, &mut draws)?;
        } else {
            job.advance(&mut draws, 1)?;
        }
        job.cancel();
        check(
            job.secrets.is_none()
                && job.fields.z == [0; 128]
                && job.take_result() == Err(Error::Cancelled)
                && job.advance(&mut draws, 1) == Err(Error::Cancelled),
        )?;
    }
    Ok(())
}
