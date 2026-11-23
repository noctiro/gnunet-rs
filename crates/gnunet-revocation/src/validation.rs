//! Private actual validation receipts, distinct from recovered durable facts.
use crate::{Certificate, RevocationConfig, Verification};
use gnunet_block::revocation::{OwnedVerification, expiration_at};
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
        Ok(
            Verification::new(certificate.bytes(), policy)?.map(|verification| Self {
                certificate,
                verification,
                policy,
            }),
        )
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
        let admission = Admission::at(self.certificate.timestamp(), score, self.policy, now)?;
        Ok(admission.map(|admission| CheckedCertificate {
            certificate: self.certificate.clone(),
            admission,
        }))
    }
}

/// Resumable proof verification that owns the exact original certificate.
/// Construct once and keep it across scheduler turns. Caller-owned scratch
/// may be shared with other work between calls.
pub struct OwnedCheck {
    verification: OwnedVerification,
}

impl OwnedCheck {
    /// Take the original certificate and authenticate its signature and nonce
    /// order without executing a work hash.
    pub fn new(certificate: Certificate, policy: RevocationConfig) -> Result<Option<Self>, Error> {
        Ok(OwnedVerification::from_original(certificate.0, policy)?
            .map(|verification| Self { verification }))
    }

    /// Original signed issue time in UTC microseconds.
    #[must_use]
    pub const fn issued_at(&self) -> u64 {
        self.verification.issued_at()
    }

    /// Number of original nonce hashes actually completed.
    #[must_use]
    pub const fn completed_hashes(&self) -> u8 {
        self.verification.completed_hashes()
    }

    /// Execute one actual hash and report whether all original work completed.
    /// A scratch error leaves progress unchanged. Completed work cannot repeat.
    pub fn step(&mut self, memory: &mut [crate::pow::Block]) -> Result<bool, Error> {
        self.verification.step(memory)
    }

    /// Consume completed work at the latest explicitly sampled UTC time.
    /// No hash is repeated. An expired, future or insufficient proof returns None.
    pub fn finish_at(self, now: u64) -> Result<Option<CheckedCertificate>, Error> {
        let issued = self.issued_at();
        let (bytes, score, policy) = self.verification.into_completed()?;
        let admission = Admission::at(issued, score, policy, now)?;
        Ok(admission.map(|admission| CheckedCertificate {
            certificate: Certificate(bytes),
            admission,
        }))
    }
}

struct Admission {
    score: u32,
    policy: RevocationConfig,
    accepted_at: u64,
    expires_at: u64,
}

impl Admission {
    fn at(
        issued: u64,
        score: u32,
        policy: RevocationConfig,
        now: u64,
    ) -> Result<Option<Self>, Error> {
        if now == u64::MAX {
            return Err(Error::TimeUncertain);
        }
        Ok(
            expiration_at(score, policy, issued, now).map(|expires_at| Self {
                score,
                policy,
                accepted_at: now,
                expires_at,
            }),
        )
    }

    fn current_at(&self, policy: RevocationConfig, now: u64) -> Result<bool, Error> {
        if now == u64::MAX {
            return Err(Error::TimeUncertain);
        }
        Ok(policy == self.policy && now >= self.accepted_at && now < self.expires_at)
    }
}

/// The exact original public certificate after signature, ordering, work and
/// admission time validation. The storage owner separately confirms durability.
pub struct CheckedCertificate {
    certificate: Certificate,
    admission: Admission,
}
impl CheckedCertificate {
    /// Exact original checked public certificate.
    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }
    /// Transfer the original public certificate, relinquishing this receipt.
    #[must_use]
    pub fn into_certificate(self) -> Certificate {
        self.certificate
    }
    /// Actual average score from the original32 hashes.
    pub const fn score(&self) -> u32 {
        self.admission.score
    }
    /// Exact original difficulty/epoch policy that was actually checked.
    pub const fn policy(&self) -> RevocationConfig {
        self.admission.policy
    }
    /// Original sampled acceptance-check time, not a persistence receipt.
    pub const fn checked_at(&self) -> u64 {
        self.accepted_at()
    }
    /// UTC sample at successful proof admission.
    pub const fn accepted_at(&self) -> u64 {
        self.admission.accepted_at
    }
    /// Exclusive deadline for admission, with MAX denoting FOREVER. Durable
    /// revocation facts are retained under the service's own storage policy.
    pub const fn expires_at(&self) -> u64 {
        self.admission.expires_at
    }
    /// Recheck only this original verified score and fixed policy at a newer
    /// sample. This never replaces a proof, repeats work or uses a forged score.
    pub fn current_at(&self, policy: RevocationConfig, now: u64) -> Result<bool, Error> {
        self.admission.current_at(policy, now)
    }
}

impl core::fmt::Debug for CheckedCertificate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CheckedCertificate")
            .field("score", &self.score())
            .field("accepted_at", &self.accepted_at())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "boundary assertions cover qualified admission and resumed clock samples"
    )]
    fn resumed_admission_rejects_expiry_policy_changes_and_clock_rollback() -> Result<(), Error> {
        let policy = RevocationConfig {
            matching_bits: 2,
            epoch_duration: 10,
        };
        assert!(Admission::at(100, 2, policy, 99)?.is_none());
        assert!(Admission::at(100, 1, policy, 100)?.is_none());
        assert!(Admission::at(100, 2, policy, 111)?.is_none());
        let admission = Admission::at(100, 2, policy, 105)?.ok_or(Error::NotReady)?;
        assert_eq!(admission.expires_at, 111);
        assert!(!admission.current_at(policy, 104)?);
        assert!(admission.current_at(policy, 105)?);
        assert!(admission.current_at(policy, 110)?);
        assert!(!admission.current_at(policy, 111)?);
        assert!(!admission.current_at(
            RevocationConfig {
                matching_bits: 1,
                ..policy
            },
            105
        )?);
        assert_eq!(
            admission.current_at(policy, u64::MAX),
            Err(Error::TimeUncertain)
        );
        assert!(matches!(
            Admission::at(100, 2, policy, u64::MAX),
            Err(Error::TimeUncertain)
        ));
        Ok(())
    }
}
