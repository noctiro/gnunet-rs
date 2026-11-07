//! Original wire/signature boundaries and actual partial-owner retirement.
//! No PreparedReveal, PILS result, Observation or completed DKG is fabricated.
use super::*;

fn check(condition: bool) -> Result<(), Error> {
    if condition {
        Ok(())
    } else {
        Err(Fault::Conflict.into())
    }
}
#[test]
fn signature_attachment_binds_original_peer_purpose_and_exact_region() -> Result<(), Error> {
    let key = gnunet_crypto::EddsaPrivateKey::from_seed([9; 32]);
    let wrong = gnunet_crypto::EddsaPrivateKey::from_seed([10; 32]);
    let peer = *key.public_key().as_bytes();
    // Deliberately unchecked proof bytes test only the signature/wire gate;
    // this helper cannot manufacture the builder's completed material type.
    let mut bytes = vec![0; ipc::reveal_encoded_len(1, 1)?];
    write_header(&mut bytes, &peer, 1, 1)?;
    let signature = key.sign(ipc::DKG2_PURPOSE, &bytes[64..])?;
    attach_signature(&mut bytes, &peer, 1, 1, &signature)?;
    let element = SignedElement::reveal(&bytes, 1, 1)?;
    check(element.peer()? == &peer && element.signature()? == signature.as_bytes())?;
    let mut forged = bytes.clone();
    forged[..64].fill(0);
    let wrong_signature = wrong.sign(ipc::DKG2_PURPOSE, &forged[64..])?;
    check(attach_signature(&mut forged, &peer, 1, 1, &wrong_signature).is_err())?;
    check(forged[..64] == [0; 64])?;
    forged[68..72].copy_from_slice(&ipc::DKG1_PURPOSE.to_be_bytes());
    check(attach_signature(&mut forged, &peer, 1, 1, &signature).is_err())
}
#[test]
fn cancelling_partial_owned_evaluation_releases_the_original_polynomial() -> Result<(), Error> {
    let limits = math::Limits::default();
    let polynomial =
        Polynomial::from_coefficients(vec![math::Scalar::zero(), math::Scalar::zero()], limits)?;
    let group = Group::new()?;
    let mut phase = Phase::Evaluating(Evaluation::new_owned(polynomial, 0, &group));
    let Phase::Evaluating(job) = &mut phase else {
        return Err(Fault::Stale.into());
    };
    check(job.advance(1)? == math::Progress::Advanced)?;
    check(phase.retained_bytes()? > 0)?;
    phase.cancel();
    phase.cancel();
    check(matches!(phase, Phase::Closed) && phase.retained_bytes()? == 0)
}

struct Clock(std::sync::atomic::AtomicU64);
impl RuntimeClock for Clock {
    fn sample(&self) -> Result<gnunet_service_runtime::clock::ClockSample, Fault> {
        Ok(gnunet_service_runtime::clock::ClockSample {
            now: gnunet_types::AbsoluteTime::from_micros(
                self.0.load(std::sync::atomic::Ordering::SeqCst),
            ),
            revision: 0,
        })
    }
    fn subscribe(
        &self,
    ) -> Result<Box<dyn gnunet_service_runtime::clock::ClockSubscription>, Fault> {
        Err(Fault::Unsupported)
    }
}
struct Draw<'a> {
    clock: &'a Clock,
    calls: usize,
    error: Option<Fault>,
}
impl math::Entropy for Draw<'_> {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Fault> {
        self.calls += 1;
        bytes.fill(0x7f);
        self.clock.0.store(101, std::sync::atomic::Ordering::SeqCst);
        self.error.map_or(Ok(()), Err)
    }
}
#[test]
fn expired_provider_boundary_stops_more_draws_and_inner_error_keeps_precedence() -> Result<(), Error>
{
    let clock = Clock(std::sync::atomic::AtomicU64::new(1));
    let bounds = crate::Bounds {
        expires: 100,
        hard: Instant::now()
            .checked_add(std::time::Duration::from_secs(2))
            .ok_or(Fault::Overflow)?,
    };
    let mut bytes = [0; 32];
    let mut draw = Draw {
        clock: &clock,
        calls: 0,
        error: None,
    };
    {
        let mut guarded = GuardedEntropy {
            provider: &mut draw,
            clock: &clock,
            bounds,
            deadline: 100,
            boundary: None,
        };
        check(math::Entropy::fill(&mut guarded, &mut bytes) == Err(Fault::Deadline))?;
        check(guarded.boundary == Some(Fault::Deadline) && bytes == [0; 32])?;
        check(math::Entropy::fill(&mut guarded, &mut bytes) == Err(Fault::Deadline))?;
    }
    check(draw.calls == 1)?;
    clock.0.store(1, std::sync::atomic::Ordering::SeqCst);
    let mut draw = Draw {
        clock: &clock,
        calls: 0,
        error: Some(Fault::EntropyUnavailable),
    };
    {
        let mut guarded = GuardedEntropy {
            provider: &mut draw,
            clock: &clock,
            bounds,
            deadline: 100,
            boundary: None,
        };
        check(math::Entropy::fill(&mut guarded, &mut bytes) == Err(Fault::EntropyUnavailable))?;
        check(guarded.boundary.is_none() && bytes == [0; 32])?;
    }
    check(draw.calls == 1)
}
