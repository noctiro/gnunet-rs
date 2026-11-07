use super::{
    ContributionEvidence, Limits, LocalContribution, OwnEvidence, OwnSignature, Rejection,
};
use crate::{Error, own::ValidationContext};
use gnunet_consensus_client_host as consensus;
use gnunet_paillier as paillier;
use gnunet_secretsharing::{
    self as math, Commitments, Element, FairEquationCheck, MembershipJob, PolynomialCheck, Scalar,
    ShareCheck, Subgroup,
};
use gnunet_types::Error as Fault;
use gnunet_wire::official::secretsharing::{self as ipc, SignedElement};
use std::mem::size_of;
// Exactly one arithmetic cursor owns this reveal's current work. Coefficients
// move into the Horner cursor and back; there is no second allocation or phase
// tag that can disagree with the cursor's presence.
#[expect(
    clippy::large_enum_variant,
    reason = "One inline arithmetic owner avoids a new fallible allocation at each protocol transition"
)]
enum Work {
    Coefficients(Vec<Subgroup>),
    Membership {
        members: Vec<Subgroup>,
        job: MembershipJob,
    },
    Recipients(Commitments),
    Equation {
        coefficients: Commitments,
        sigma: Subgroup,
        job: FairEquationCheck,
    },
    Horner(PolynomialCheck<'static>),
    Decrypt {
        coefficients: Commitments,
        sigma: Subgroup,
        job: paillier::DecryptJob,
    },
    Recover {
        coefficients: Commitments,
        sigma: Subgroup,
        job: math::FairRecoveryJob,
    },
    Share {
        coefficients: Commitments,
        sigma: Subgroup,
        job: ShareCheck,
    },
    Ready {
        coefficients: Commitments,
        local: LocalShare,
    },
    Closed,
}
struct LocalShare {
    scalar: Scalar,
    sigma: Subgroup,
}
impl Work {
    fn retained_bytes(&self) -> Result<usize, Error> {
        match self {
            Self::Coefficients(members) | Self::Membership { members, .. } => members
                .capacity()
                .checked_mul(size_of::<Subgroup>())
                .ok_or_else(|| Fault::Overflow.into()),
            Self::Recipients(coefficients)
            | Self::Equation { coefficients, .. }
            | Self::Decrypt { coefficients, .. }
            | Self::Recover { coefficients, .. }
            | Self::Share { coefficients, .. }
            | Self::Ready { coefficients, .. } => Ok(coefficients.retained_bytes()?),
            Self::Horner(job) => Ok(job.retained_bytes()?),
            Self::Closed => Ok(0),
        }
    }
    fn cancel(&mut self) {
        match self {
            Self::Membership { job, .. } => job.cancel(),
            Self::Equation { job, .. } => job.cancel(),
            Self::Horner(job) => job.cancel(),
            Self::Decrypt { job, .. } => job.cancel(),
            Self::Recover { job, .. } => job.cancel(),
            Self::Share { job, .. } => job.cancel(),
            Self::Coefficients(_) | Self::Recipients(_) | Self::Ready { .. } | Self::Closed => {}
        }
        *self = Self::Closed;
    }
    fn into_ready(self) -> Result<(Commitments, LocalShare), Error> {
        match self {
            Self::Ready {
                coefficients,
                local,
            } => Ok((coefficients, local)),
            _ => Err(Fault::NotReady.into()),
        }
    }
}
/// Local input has actual signing provenance, without a fabricated523.
#[expect(
    clippy::large_enum_variant,
    reason = "Actual signing facts remain inline without another fallible allocation"
)]
pub(super) enum Input<'id> {
    Remote(consensus::Observation),
    Own {
        bytes: Vec<u8>,
        signing: OwnSignature<'id>,
    },
}
impl<'id> Input<'id> {
    fn data(&self) -> Result<(u16, &[u8]), Fault> {
        match self {
            Self::Remote(observation) => match observation.response()? {
                consensus::ClientResponse::Element { element_type, data } => {
                    Ok((element_type, data))
                }
                _ => Err(Fault::Malformed),
            },
            Self::Own { bytes, .. } => Ok((0, bytes)),
        }
    }
    fn retained_bytes(&self) -> usize {
        match self {
            Self::Remote(observation) => observation.retained_bytes(),
            Self::Own { bytes, .. } => bytes.capacity(),
        }
    }
    fn remote_epoch(&self) -> Option<&consensus::Epoch> {
        match self {
            Self::Remote(observation) => Some(observation.epoch()),
            Self::Own { .. } => None,
        }
    }
    fn into_evidence(
        self,
        insertion: Option<consensus::Receipt>,
    ) -> Result<ContributionEvidence<'id>, Error> {
        match (self, insertion) {
            (Self::Remote(observation), None) => Ok(ContributionEvidence::Remote(observation)),
            (Self::Own { bytes, signing }, Some(insertion)) => {
                if !matches!(&insertion.kind, consensus::Kind::Insert(_))
                    || insertion.written != bytes.len().checked_add(6).ok_or(Fault::Overflow)?
                {
                    return Err(Fault::Stale.into());
                }
                Ok(ContributionEvidence::Own(OwnEvidence {
                    bytes,
                    signing,
                    insertion,
                }))
            }
            _ => Err(Fault::Stale.into()),
        }
    }
}
pub(super) struct Job<'id> {
    input: Input<'id>,
    dealer: usize,
    recipient: usize,
    work: Work,
    local: Option<LocalShare>,
    equation_checks: usize,
    missing: Vec<u16>,
}
#[expect(
    clippy::large_enum_variant,
    reason = "Keep the actual bounded job inline without a terminal allocation"
)]
pub(super) enum Start<'id> {
    Job(Job<'id>),
    Rejected {
        peer: Option<[u8; 32]>,
        reason: Rejection,
    },
}
pub(super) enum Step {
    Activity,
    Ready,
    Rejected(Rejection),
}
fn math_refusal(error: math::Error) -> Result<Rejection, Error> {
    if matches!(
        error,
        math::Error::InvalidInput
            | math::Error::InvalidProof
            | math::Error::Roster
            | math::Error::Source(
                Fault::Authentication | Fault::Malformed | Fault::Truncated | Fault::Unsupported
            )
    ) {
        Ok(Rejection::Math(error))
    } else {
        Err(error.into())
    }
}
fn paillier_refusal(error: paillier::Error) -> Result<Rejection, Error> {
    if matches!(
        error,
        paillier::Error::InvalidCipher | paillier::Error::Range
    ) {
        Ok(Rejection::Paillier(error))
    } else {
        Err(error.into())
    }
}
fn reveal<'a>(
    input: &'a Input<'_>,
    round1: &ValidationContext<'_>,
) -> Result<SignedElement<'a>, Fault> {
    let (_, data) = input.data()?;
    SignedElement::reveal(data, round1.roster.len(), round1.threshold)
}
enum StatementAdmission<'a> {
    First {
        dealer: usize,
        element: SignedElement<'a>,
    },
    Rejected {
        peer: Option<[u8; 32]>,
        reason: Rejection,
    },
}
fn admit_statement<'a>(
    element_type: u16,
    data: &'a [u8],
    roster: &[[u8; 32]],
    threshold: usize,
    limits: Limits,
) -> Result<StatementAdmission<'a>, Error> {
    if element_type != 0 {
        return Ok(StatementAdmission::Rejected {
            peer: None,
            reason: Rejection::Shape(Fault::Unsupported),
        });
    }
    if data.len() > limits.reveal_bytes {
        return Err(Fault::Capacity.into());
    }
    let element = match SignedElement::reveal(data, roster.len(), threshold) {
        Ok(element) => element,
        Err(error) => {
            return Ok(StatementAdmission::Rejected {
                peer: None,
                reason: Rejection::Shape(error),
            });
        }
    };
    let peer = *element.peer()?;
    let dealer = match roster.binary_search(&peer) {
        Ok(index) => index,
        Err(_) => {
            return Ok(StatementAdmission::Rejected {
                peer: Some(peer),
                reason: Rejection::Foreign,
            });
        }
    };
    let key = gnunet_crypto::EddsaPublicKey::from_bytes(peer);
    let signature = gnunet_crypto::EddsaSignature::from_bytes(*element.signature()?);
    if let Err(error) = key.verify(ipc::DKG2_PURPOSE, element.signed_bytes(), &signature) {
        return Ok(StatementAdmission::Rejected {
            peer: Some(peer),
            reason: Rejection::Signature(error),
        });
    }
    Ok(StatementAdmission::First { dealer, element })
}
// The only two dynamic work vectors created for one admitted original reveal.
// The caller includes its already-held frame separately. Check both requested
// allocations before either reserve, then actual capacities before the next.
fn work_vectors(
    threshold: usize,
    recipients: usize,
    available: usize,
) -> Result<(Vec<Subgroup>, Vec<u16>), Error> {
    let requested_members = threshold
        .checked_mul(size_of::<Subgroup>())
        .ok_or(Fault::Overflow)?;
    let requested_missing = recipients
        .checked_mul(size_of::<u16>())
        .ok_or(Fault::Overflow)?;
    if requested_members
        .checked_add(requested_missing)
        .ok_or(Fault::Overflow)?
        > available
    {
        return Err(Fault::Capacity.into());
    }
    let mut members = Vec::new();
    members
        .try_reserve_exact(threshold)
        .map_err(|_| Fault::Capacity)?;
    let member_bytes = members
        .capacity()
        .checked_mul(size_of::<Subgroup>())
        .ok_or(Fault::Overflow)?;
    if member_bytes
        .checked_add(requested_missing)
        .ok_or(Fault::Overflow)?
        > available
    {
        return Err(Fault::Capacity.into());
    }
    let mut missing = Vec::new();
    missing
        .try_reserve_exact(recipients)
        .map_err(|_| Fault::Capacity)?;
    let missing_bytes = missing
        .capacity()
        .checked_mul(size_of::<u16>())
        .ok_or(Fault::Overflow)?;
    if member_bytes
        .checked_add(missing_bytes)
        .ok_or(Fault::Overflow)?
        > available
    {
        return Err(Fault::Capacity.into());
    }
    Ok((members, missing))
}
// Independent of recipient-key admission: an unavailable modulus cannot skip
// the original-index polynomial equation. The derived member makes raw h's
// canonical equality sufficient; no unchecked Subgroup is constructed.
fn checked_horner(
    job: PolynomialCheck<'static>,
    h: &[u8; ipc::FIELD_BYTES],
) -> Result<(Commitments, Subgroup), math::Error> {
    let (coefficients, sigma) = job.take_owned_result()?;
    if *h != sigma.to_bytes() {
        return Err(math::Error::InvalidProof);
    }
    Ok((coefficients, sigma))
}
impl<'id> Job<'id> {
    pub(super) fn prepare(
        input: Input<'id>,
        round1: &ValidationContext<'_>,
        candidates: &[Option<LocalContribution<'id>>],
        limits: Limits,
        available: usize,
    ) -> Result<Start<'id>, Error> {
        let (element_type, data) = input.data()?;
        let (dealer, element) =
            match admit_statement(element_type, data, round1.roster, round1.threshold, limits)? {
                StatementAdmission::First { dealer, element } => (dealer, element),
                StatementAdmission::Rejected { peer, reason } => {
                    return Ok(Start::Rejected { peer, reason });
                }
            };
        let peer = *element.peer()?;
        match &input {
            Input::Remote(_) if peer == round1.roster[round1.local] => {
                return Ok(Start::Rejected {
                    peer: Some(peer),
                    reason: Rejection::LocalRequiresOwn,
                });
            }
            Input::Own { signing, .. } => {
                if peer != round1.roster[round1.local]
                    || signing.identity.peer().as_bytes() != &peer
                    || signing.written.operation != signing.operation
                    || signing.written.kind != gnunet_pils::client::OperationKind::Sign
                    || signing.written.canceled
                    || element.signature()? != signing.signature.as_bytes()
                {
                    return Err(Fault::Authentication.into());
                }
            }
            Input::Remote(_) => {}
        }
        if candidates.len() != round1.roster.len() {
            return Err(Fault::Stale.into());
        }
        // The existing complete contribution is the sole first-valid state.
        // Reveals contain no signed SID: later signed bytes cannot withdraw it.
        if candidates[dealer]
            .as_ref()
            .is_some_and(|candidate| candidate.complete_for(round1.roster.len()))
        {
            return Ok(Start::Rejected {
                peer: Some(peer),
                reason: Rejection::Duplicate,
            });
        }
        // A signed reveal from another context cannot reserve this dealer.
        let Some(commit) = round1.commitments.get(dealer).and_then(Option::as_ref) else {
            return Ok(Start::Rejected {
                peer: Some(peer),
                reason: Rejection::NoRound1,
            });
        };
        let constant = element.coefficient(0)?.ok_or(Fault::Malformed)?;
        let original = SignedElement::commitment(&commit.bytes)?;
        if gnunet_crypto::hash512(constant) != *original.commitment_hash()? {
            return Ok(Start::Rejected {
                peer: Some(peer),
                reason: Rejection::Commitment,
            });
        }
        // Invalid context and accepted duplicates need no growth claim. A new
        // opened reveal owns its actual held frame and both work vectors.
        let available = available
            .checked_sub(input.retained_bytes())
            .ok_or(Fault::Capacity)?
            .min(limits.math.retained_bytes);
        let (members, missing) = work_vectors(round1.threshold, round1.roster.len(), available)?;
        let job = Self {
            input,
            dealer,
            recipient: 0,
            work: Work::Coefficients(members),
            local: None,
            equation_checks: 0,
            missing,
        };
        if job.retained_bytes()? > limits.math.retained_bytes {
            return Err(Fault::Capacity.into());
        }
        Ok(Start::Job(job))
    }
    pub(super) const fn dealer(&self) -> usize {
        self.dealer
    }
    pub(super) const fn recipient(&self) -> usize {
        self.recipient
    }
    pub(super) fn retained_bytes(&self) -> Result<usize, Error> {
        let work = self.work.retained_bytes()?;
        self.missing
            .capacity()
            .checked_mul(size_of::<u16>())
            .and_then(|bytes| bytes.checked_add(work))
            .ok_or_else(|| Fault::Overflow.into())
    }
    fn advance_work(
        &mut self,
        round1: &ValidationContext<'_>,
        group: &math::Group,
        limits: Limits,
    ) -> Result<Step, Error> {
        // Arithmetic advances in place. Only a real stage transition moves its
        // original job/coefficient owners; a pending budget copies no large enum.
        let next = match &mut self.work {
            Work::Coefficients(members) => {
                if members.len() == round1.threshold {
                    Work::Recipients(Commitments::from_members(
                        std::mem::take(members),
                        limits.math,
                    )?)
                } else {
                    let raw = *reveal(&self.input, round1)?
                        .coefficient(members.len())?
                        .ok_or(Fault::Malformed)?;
                    let value = match Element::from_bytes(&raw) {
                        Ok(value) => value,
                        Err(error) => return Ok(Step::Rejected(math_refusal(error)?)),
                    };
                    let mut job = MembershipJob::new(value, group, limits.math)?;
                    // Starting and advancing the first coefficient check share
                    // the same original turn, with exactly one arithmetic budget.
                    match job.advance(limits.math.units_per_turn) {
                        Ok(math::Progress::Ready) => {
                            members.push(job.take_result()?);
                            return Ok(Step::Activity);
                        }
                        Ok(math::Progress::Advanced) => Work::Membership {
                            members: std::mem::take(members),
                            job,
                        },
                        Err(error) => return Ok(Step::Rejected(math_refusal(error)?)),
                    }
                }
            }
            Work::Membership { members, job } => match job.advance(limits.math.units_per_turn) {
                Ok(math::Progress::Ready) => {
                    members.push(job.take_result()?);
                    Work::Coefficients(std::mem::take(members))
                }
                Ok(math::Progress::Advanced) => return Ok(Step::Activity),
                Err(error) => return Ok(Step::Rejected(math_refusal(error)?)),
            },
            Work::Recipients(_) => {
                if self.recipient == round1.roster.len() {
                    let local = self.local.take().ok_or(Fault::NotReady)?;
                    let Work::Recipients(coefficients) =
                        std::mem::replace(&mut self.work, Work::Closed)
                    else {
                        return Err(Fault::NotReady.into());
                    };
                    self.work = Work::Ready {
                        coefficients,
                        local,
                    };
                    return Ok(Step::Ready);
                }
                // Every original recipient gets the same checked Horner job,
                // even if its Round1 modulus is unavailable. Comparing the raw
                // h with the derived member establishes membership without a
                // separate exponentiation or a second polynomial algorithm.
                let Work::Recipients(coefficients) =
                    std::mem::replace(&mut self.work, Work::Closed)
                else {
                    return Err(Fault::NotReady.into());
                };
                Work::Horner(PolynomialCheck::new_owned(
                    coefficients,
                    u16::try_from(self.recipient).map_err(|_| Fault::Overflow)?,
                    None,
                    group,
                ))
            }
            Work::Horner(job) => match job.advance(limits.math.units_per_turn) {
                Ok(math::Progress::Ready) => {
                    let Work::Horner(job) = std::mem::replace(&mut self.work, Work::Closed) else {
                        return Err(Fault::NotReady.into());
                    };
                    let element = reveal(&self.input, round1)?;
                    let proof = element
                        .encryption(self.recipient)?
                        .ok_or(Fault::Malformed)?;
                    let (coefficients, sigma) = match checked_horner(job, proof.h()?) {
                        Ok(value) => value,
                        Err(error) => return Ok(Step::Rejected(math_refusal(error)?)),
                    };
                    let Some(recipient) = round1
                        .commitments
                        .get(self.recipient)
                        .and_then(Option::as_ref)
                    else {
                        self.missing
                            .push(u16::try_from(self.recipient).map_err(|_| Fault::Overflow)?);
                        self.recipient += 1;
                        self.work = Work::Recipients(coefficients);
                        return Ok(Step::Activity);
                    };
                    let job = match FairEquationCheck::new(
                        &recipient.key,
                        proof.bytes(),
                        group,
                        limits.math,
                    ) {
                        Ok(job) => job,
                        Err(error) => return Ok(Step::Rejected(math_refusal(error)?)),
                    };
                    Work::Equation {
                        coefficients,
                        sigma,
                        job,
                    }
                }
                Ok(math::Progress::Advanced) => return Ok(Step::Activity),
                Err(error) => return Ok(Step::Rejected(math_refusal(error)?)),
            },
            Work::Equation { job, .. } => match job.advance(limits.math.units_per_turn) {
                Ok(math::Progress::Ready) => {
                    let checked = job.take_result()?.h();
                    let Work::Equation {
                        coefficients,
                        sigma,
                        ..
                    } = std::mem::replace(&mut self.work, Work::Closed)
                    else {
                        return Err(Fault::NotReady.into());
                    };
                    if checked != sigma {
                        return Err(Fault::Stale.into());
                    }
                    self.equation_checks =
                        self.equation_checks.checked_add(1).ok_or(Fault::Overflow)?;
                    if self.recipient == round1.local {
                        let element = reveal(&self.input, round1)?;
                        let proof = element
                            .encryption(self.recipient)?
                            .ok_or(Fault::Malformed)?;
                        let cipher = paillier::Ciphertext::from_wire(*proof.ciphertext()?);
                        let job = match round1.keypair.private_key().decrypt(
                            round1.keypair.public_key(),
                            &cipher,
                            limits.paillier,
                        ) {
                            Ok(job) => job,
                            Err(error) => return Ok(Step::Rejected(paillier_refusal(error)?)),
                        };
                        Work::Decrypt {
                            coefficients,
                            sigma,
                            job,
                        }
                    } else {
                        self.recipient += 1;
                        Work::Recipients(coefficients)
                    }
                }
                Ok(math::Progress::Advanced) => return Ok(Step::Activity),
                Err(error) => return Ok(Step::Rejected(math_refusal(error)?)),
            },
            Work::Decrypt { job, .. } => match job.advance(limits.paillier.units_per_turn) {
                Ok(paillier::Progress::Ready) => {
                    let value = job.take_result()?;
                    let Work::Decrypt {
                        coefficients,
                        sigma,
                        ..
                    } = std::mem::replace(&mut self.work, Work::Closed)
                    else {
                        return Err(Fault::NotReady.into());
                    };
                    Work::Recover {
                        coefficients,
                        sigma,
                        job: math::FairRecoveryJob::new(
                            round1.keypair.public_key(),
                            value,
                            group,
                            limits.math,
                        )?,
                    }
                }
                Ok(paillier::Progress::Advanced) => return Ok(Step::Activity),
                Err(error) => return Ok(Step::Rejected(paillier_refusal(error)?)),
            },
            Work::Recover { job, .. } => match job.advance(limits.math.units_per_turn) {
                Ok(math::Progress::Ready) => {
                    let scalar = job.take_result()?;
                    let Work::Recover {
                        coefficients,
                        sigma,
                        ..
                    } = std::mem::replace(&mut self.work, Work::Closed)
                    else {
                        return Err(Fault::NotReady.into());
                    };
                    Work::Share {
                        coefficients,
                        sigma,
                        job: ShareCheck::new(scalar, sigma, group, limits.math)?,
                    }
                }
                Ok(math::Progress::Advanced) => return Ok(Step::Activity),
                Err(error) => return Ok(Step::Rejected(math_refusal(error)?)),
            },
            Work::Share { job, .. } => match job.advance(limits.math.units_per_turn) {
                Ok(math::Progress::Ready) => {
                    let scalar = job.take_result()?;
                    let Work::Share {
                        coefficients,
                        sigma,
                        ..
                    } = std::mem::replace(&mut self.work, Work::Closed)
                    else {
                        return Err(Fault::NotReady.into());
                    };
                    self.local = Some(LocalShare { scalar, sigma });
                    self.recipient += 1;
                    Work::Recipients(coefficients)
                }
                Ok(math::Progress::Advanced) => return Ok(Step::Activity),
                Err(error) => return Ok(Step::Rejected(math_refusal(error)?)),
            },
            Work::Ready { .. } => return Ok(Step::Ready),
            Work::Closed => return Err(Fault::NotReady.into()),
        };
        self.work = next;
        Ok(Step::Activity)
    }
    pub(super) fn advance(
        &mut self,
        round1: &ValidationContext<'_>,
        group: &math::Group,
        limits: Limits,
    ) -> Result<Step, Error> {
        let result = self.advance_work(round1, group, limits);
        if matches!(&result, Err(_) | Ok(Step::Rejected(_))) {
            // Preserve the original refusal/error while retiring its unique
            // cursor, coefficients and any earlier local secret immediately.
            self.cancel();
        }
        result
    }
    pub(super) fn remote_epoch(&self) -> Option<&consensus::Epoch> {
        self.input.remote_epoch()
    }
    pub(super) fn input_retained_bytes(&self) -> usize {
        self.input.retained_bytes()
    }
    pub(super) fn reveal_bytes(&self) -> Result<&[u8], Fault> {
        self.input.data().map(|(_, data)| data)
    }
    pub(super) fn take_result(
        self,
        local: usize,
        recipients: usize,
        insertion: Option<consensus::Receipt>,
    ) -> Result<LocalContribution<'id>, Error> {
        let (coefficients, share) = self.work.into_ready()?;
        if recipients != self.recipient
            || self.equation_checks.checked_add(self.missing.len()) != Some(recipients)
        {
            return Err(Fault::Stale.into());
        }
        Ok(LocalContribution {
            dealer: self.dealer,
            recipient: local,
            evidence: self.input.into_evidence(insertion)?,
            scalar: share.scalar,
            sigma: share.sigma,
            coefficients,
            equation_checks: self.equation_checks,
            missing: self.missing,
        })
    }
    pub(super) fn cancel(&mut self) {
        self.work.cancel();
        self.local = None;
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    fn signed(key: &gnunet_crypto::EddsaPrivateKey, marker: u8) -> Result<Vec<u8>, Error> {
        let proofs = [[0; ipc::FAIR_ENCRYPTION_BYTES]];
        let coefficients = [[marker; ipc::FIELD_BYTES]];
        let mut out = vec![0; ipc::REVEAL_PREFIX + ipc::FAIR_ENCRYPTION_BYTES + ipc::FIELD_BYTES];
        ipc::RevealFields {
            signature: &[0; 64],
            peer: key.public_key().as_bytes(),
            encryptions: &proofs,
            coefficients: &coefficients,
        }
        .encode(&mut out)?;
        let signature = key.sign(ipc::DKG2_PURPOSE, &out[64..])?;
        out[..64].copy_from_slice(signature.as_bytes());
        Ok(out)
    }
    fn check(value: bool) -> Result<(), Error> {
        if value {
            Ok(())
        } else {
            Err(Fault::Conflict.into())
        }
    }
    #[test]
    fn authentication_observes_replays_without_creating_candidate_authority() -> Result<(), Error> {
        let key = gnunet_crypto::EddsaPrivateKey::from_seed([9; 32]);
        let roster = [*key.public_key().as_bytes()];
        let a = signed(&key, 1)?;
        let b = signed(&key, 2)?;
        // Both real signatures cover deliberately invalid algebra. The gate
        // observes them in either order, without any writable candidate/history
        // authority. Only owner submission of a completed job can retain one.
        for (first, second) in [(&a, &b), (&b, &a)] {
            for bytes in [first, second, first] {
                check(matches!(
                    admit_statement(0, bytes, &roster, 1, Limits::default())?,
                    StatementAdmission::First { dealer: 0, .. }
                ))?;
            }
        }
        let mut forged = b;
        forged[0] ^= 1;
        check(matches!(
            admit_statement(0, &forged, &roster, 1, Limits::default())?,
            StatementAdmission::Rejected {
                reason: Rejection::Signature(_),
                ..
            }
        ))?;
        check(matches!(
            admit_statement(0, &a[..100], &roster, 1, Limits::default())?,
            StatementAdmission::Rejected {
                reason: Rejection::Shape(_),
                ..
            }
        ))
    }
    fn polynomial(index: u16, group: &math::Group) -> Result<PolynomialCheck<'static>, Error> {
        let mut limits = Limits::default();
        limits.math.units_per_turn = 64;
        let coefficients =
            Commitments::from_members(vec![group.generator(), group.generator()], limits.math)?;
        let mut job = PolynomialCheck::new_owned(coefficients, index, None, group);
        // Two degree-one coefficient steps each use32 public exponent bits.
        for _ in 0..4 {
            if job.advance(64)? == math::Progress::Ready {
                return Ok(job);
            }
        }
        Err(Fault::NotReady.into())
    }
    #[test]
    fn original_index_horner_rejects_zero_or_other_recipient_h_without_a_paillier_key()
    -> Result<(), Error> {
        let group = math::Group::new()?;
        // A(X)=g^(1+X); original index2 means X=3, hence h=g^4.
        let square = group.generator().multiply(group.generator(), &group);
        let h = square.multiply(square, &group).to_bytes();
        let (_, sigma) = checked_horner(polynomial(2, &group)?, &h)?;
        check(sigma.to_bytes() == h)?;
        check(matches!(
            checked_horner(polynomial(1, &group)?, &h),
            Err(math::Error::InvalidProof)
        ))?;
        // Official missing-key producer slots are zero. They must still fail
        // this unconditional Horner equation, before any optional key check.
        check(matches!(
            checked_horner(polynomial(2, &group)?, &[0; ipc::FIELD_BYTES]),
            Err(math::Error::InvalidProof)
        ))
    }
}

#[cfg(test)]
mod allocation_tests {
    use super::*;
    #[test]
    fn reveal_work_pair_refuses_short_budget_and_overflow_before_reserving() -> Result<(), Error> {
        // No Observation/candidate/proof is fabricated. This exercises the
        // actual post-admission allocation boundary with an ordinary threshold
        // and roster extent, not a second implementation of the planner.
        let needed = 2 * size_of::<Subgroup>() + 3 * size_of::<u16>();
        if !matches!(
            work_vectors(2, 3, needed - 1),
            Err(Error::Protocol(Fault::Capacity))
        ) {
            return Err(Fault::Conflict.into());
        }
        // A count whose typed byte extent overflows must be rejected before
        // an allocator can be asked for it, even with the largest allowance.
        if !matches!(
            work_vectors(usize::MAX, 3, usize::MAX),
            Err(Error::Protocol(Fault::Overflow))
        ) {
            return Err(Fault::Conflict.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod work_tests {
    use super::*;

    fn coefficients(limits: Limits) -> Result<Commitments, Error> {
        Ok(Commitments::from_members(
            vec![Subgroup::identity()],
            limits.math,
        )?)
    }

    #[test]
    fn cancel_active_share_releases_coefficients_and_blocks_result() -> Result<(), Error> {
        let limits = Limits::default();
        let group = math::Group::new()?;
        let mut job = ShareCheck::new(Scalar::zero(), Subgroup::identity(), &group, limits.math)?;
        // This is an actual partial arithmetic cursor, without fabricating a
        // Consensus Observation, authenticated reveal or FAIR certificate.
        if job.advance(1)? != math::Progress::Advanced {
            return Err(Fault::Conflict.into());
        }
        let mut work = Work::Share {
            coefficients: coefficients(limits)?,
            sigma: Subgroup::identity(),
            job,
        };
        if work.retained_bytes()? == 0 {
            return Err(Fault::Conflict.into());
        }
        work.cancel();
        work.cancel();
        if !matches!(work, Work::Closed) || work.retained_bytes()? != 0 {
            return Err(Fault::Conflict.into());
        }
        if !matches!(work.into_ready(), Err(Error::Protocol(Fault::NotReady))) {
            return Err(Fault::Conflict.into());
        }
        Ok(())
    }

    #[test]
    fn cancel_horner_releases_its_moved_coefficient_allocation() -> Result<(), Error> {
        let limits = Limits::default();
        let group = math::Group::new()?;
        let coefficients = coefficients(limits)?;
        let retained = coefficients.retained_bytes()?;
        let mut work = Work::Horner(PolynomialCheck::new_owned(coefficients, 0, None, &group));
        let Work::Horner(job) = &mut work else {
            return Err(Fault::Conflict.into());
        };
        if job.advance(1)? != math::Progress::Advanced || work.retained_bytes()? != retained {
            return Err(Fault::Conflict.into());
        }
        work.cancel();
        if work.retained_bytes()? != 0
            || !matches!(work.into_ready(), Err(Error::Protocol(Fault::NotReady)))
        {
            return Err(Fault::Conflict.into());
        }
        Ok(())
    }
}
