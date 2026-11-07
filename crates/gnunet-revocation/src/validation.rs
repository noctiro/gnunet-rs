//! Private actual validation receipts, distinct from recovered durable facts.
use crate::{Certificate, RevocationConfig, Verification};
use gnunet_block::ReturnValue;
use gnunet_types::Error;
/// One immutable original public certificate and its actual signature/work cursor.
/// Owner may place Certificate on a worker stack; no self reference is required.
pub struct Check<'a> {
    certificate: &'a Certificate,
    verification: Verification<'a>,
    policy: RevocationConfig,
}
impl<'a> Check<'a> {
    /// Actually verify the original signature and ordered set, without a work hash.
    pub fn new(
        certificate: &'a Certificate,
        policy: RevocationConfig,
    ) -> Result<Option<Self>, Error> {
        Ok(certificate
            .proof()?
            .verification(policy)?
            .map(|verification| Self {
                certificate,
                verification,
                policy,
            }))
    }
    /// Complete at most one real hash in the original caller-owned1MiB scratch.
    pub fn step(&mut self, memory: &mut [crate::pow::Block]) -> Result<bool, Error> {
        self.verification.step(memory)
    }
    /// Actual work completed, never inferred from a worker enqueue.
    pub fn completed_hashes(&self) -> u8 {
        self.verification.completed_hashes()
    }
    /// Consume actual completed work and check the original policy/lifetime against
    /// one explicitly sampled original clock value. None denotes an invalid proof.
    pub fn finish_at(self, now: u64) -> Result<Option<CheckedCertificate>, Error> {
        let score = self.verification.score().ok_or(Error::NotReady)?;
        if self.verification.outcome(&mut || now)? != ReturnValue::Yes {
            return Ok(None);
        }
        Ok(Some(CheckedCertificate {
            certificate: self.certificate.clone(),
            score,
            policy: self.policy,
            checked_at: now,
        }))
    }
}
/// Only32 actual hashes, actual signature/order checking and current lifetime can
/// construct this receipt. Restored on-disk facts use a separate type/source.
pub struct CheckedCertificate {
    certificate: Certificate,
    score: u32,
    policy: RevocationConfig,
    checked_at: u64,
}
impl CheckedCertificate {
    /// Exact original checked public certificate.
    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }
    /// Actual average score from the original32 hashes.
    pub const fn score(&self) -> u32 {
        self.score
    }
    /// Exact original difficulty/epoch policy that was actually checked.
    pub const fn policy(&self) -> RevocationConfig {
        self.policy
    }
    /// Original sampled acceptance-check time, not a persistence receipt.
    pub const fn checked_at(&self) -> u64 {
        self.checked_at
    }
    /// Recheck only this original verified score and fixed policy at a newer
    /// sample. This never replaces a proof, repeats work or uses a forged score.
    pub fn current_at(&self, policy: RevocationConfig, now: u64) -> Result<bool, Error> {
        Ok(now >= self.checked_at
            && policy.matching_bits == self.policy.matching_bits
            && policy.epoch_duration == self.policy.epoch_duration
            && gnunet_block::revocation::valid_at(
                self.score,
                self.policy,
                self.certificate.proof()?.timestamp(),
                now,
            ) == ReturnValue::Yes)
    }
}
impl core::fmt::Debug for CheckedCertificate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CheckedCertificate")
            .field("score", &self.score)
            .field("checked_at", &self.checked_at)
            .finish_non_exhaustive()
    }
}
