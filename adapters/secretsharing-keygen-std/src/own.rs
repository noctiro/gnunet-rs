//! Build one original local reveal without creating a PILS or CONSENSUS source.
//! Signing proves only the supplied signature; actual SIGN/INSERT receipts remain
//! the enclosing native owner's responsibility.
use crate::{Error, PeerCommitment, Transcript, round2::Limits};
use gnunet_crypto::{EddsaPublicKey, EddsaSignature};
use gnunet_secretsharing::{self as math, Commitments, Evaluation, FairProver, Group, Polynomial};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as Fault;
use gnunet_wire::official::secretsharing::{self as ipc, SignedElement};
use std::{
    mem::{replace, size_of, take},
    sync::Arc,
    time::Instant,
};

// The original polynomial lives exclusively in Phase while all other original
// material stays here. No dummy polynomial or second secret owner is needed.
struct Context {
    bounds: crate::Bounds,
    clock: Arc<dyn RuntimeClock>,
    session: [u8; 64],
    start: u64,
    deadline: u64,
    threshold: usize,
    local: usize,
    roster: Vec<[u8; 32]>,
    commitments: Vec<Option<PeerCommitment>>,
    coefficients: Commitments,
    keypair: gnunet_paillier::KeyPair,
}
/// Ephemeral access to the actual unique Round1 material. A validator stores
/// none of these borrows; producer phase transitions can therefore move the
/// original polynomial/context without copying either private owner.
pub(crate) struct ValidationContext<'a> {
    pub(crate) threshold: usize,
    pub(crate) local: usize,
    pub(crate) roster: &'a [[u8; 32]],
    pub(crate) commitments: &'a [Option<PeerCommitment>],
    pub(crate) keypair: &'a gnunet_paillier::KeyPair,
}
impl<'a> From<&'a Transcript> for ValidationContext<'a> {
    fn from(transcript: &'a Transcript) -> Self {
        Self {
            threshold: transcript.threshold,
            local: transcript.local,
            roster: &transcript.roster,
            commitments: &transcript.commitments,
            keypair: &transcript.keypair,
        }
    }
}
impl Context {
    fn view(&self) -> ValidationContext<'_> {
        ValidationContext {
            threshold: self.threshold,
            local: self.local,
            roster: &self.roster,
            commitments: &self.commitments,
            keypair: &self.keypair,
        }
    }
    fn split(transcript: Transcript) -> (Self, Polynomial) {
        let Transcript {
            bounds,
            clock,
            session,
            start,
            deadline,
            threshold,
            local,
            roster,
            commitments,
            polynomial,
            coefficients,
            keypair,
        } = transcript;
        (
            Self {
                bounds,
                clock,
                session,
                start,
                deadline,
                threshold,
                local,
                roster,
                commitments,
                coefficients,
                keypair,
            },
            polynomial,
        )
    }
    fn join(self, polynomial: Polynomial) -> Transcript {
        let Self {
            bounds,
            clock,
            session,
            start,
            deadline,
            threshold,
            local,
            roster,
            commitments,
            coefficients,
            keypair,
        } = self;
        Transcript {
            bounds,
            clock,
            session,
            start,
            deadline,
            threshold,
            local,
            roster,
            commitments,
            polynomial,
            coefficients,
            keypair,
        }
    }
    fn retained_bytes(&self) -> Result<usize, Failure> {
        let coefficients = self.coefficients.retained_bytes()?;
        self.roster
            .capacity()
            .checked_mul(size_of::<[u8; 32]>())
            .and_then(|n| {
                self.commitments
                    .capacity()
                    .checked_mul(size_of::<Option<PeerCommitment>>())
                    .and_then(|m| n.checked_add(m))
            })
            .and_then(|n| n.checked_add(coefficients))
            .ok_or_else(|| Fault::Overflow.into())
    }
    fn check_target(&self) -> Result<(), Fault> {
        check_target(self.bounds, self.deadline, self.clock.as_ref())
    }
}

#[expect(
    clippy::large_enum_variant,
    reason = "Exclusive original math jobs share fixed storage without another fallible allocation"
)]
enum Phase {
    Evaluating(Evaluation<'static>),
    Proving {
        polynomial: Polynomial,
        job: FairProver,
    },
    Ready(Polynomial),
    Closed,
}
impl Phase {
    fn retained_bytes(&self) -> Result<usize, math::Error> {
        match self {
            Self::Evaluating(job) => job.retained_bytes(),
            Self::Proving { polynomial, .. } | Self::Ready(polynomial) => {
                polynomial.retained_bytes()
            }
            Self::Closed => Ok(0),
        }
    }
    fn cancel(&mut self) {
        match self {
            Self::Evaluating(job) => job.cancel(),
            Self::Proving { job, .. } => job.cancel(),
            Self::Ready(_) | Self::Closed => {}
        }
        *self = Self::Closed;
    }
}

#[derive(Clone, Copy)]
enum Failure {
    Protocol(Fault),
    Math(math::Error),
}
impl From<Fault> for Failure {
    fn from(error: Fault) -> Self {
        Self::Protocol(error)
    }
}
impl From<math::Error> for Failure {
    fn from(error: math::Error) -> Self {
        Self::Math(error)
    }
}
impl From<Failure> for Error {
    fn from(error: Failure) -> Self {
        match error {
            Failure::Protocol(error) => error.into(),
            Failure::Math(error) => error.into(),
        }
    }
}

// One batch may request several entropy draws. Stop at the first real provider
// boundary that crosses the original target, without changing its coordinates
// or misclassifying an inner provider refusal as a clock error.
struct GuardedEntropy<'a, E> {
    provider: &'a mut E,
    clock: &'a dyn RuntimeClock,
    bounds: crate::Bounds,
    deadline: u64,
    boundary: Option<Fault>,
}
impl<E: math::Entropy> math::Entropy for GuardedEntropy<'_, E> {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Fault> {
        if let Some(error) = self.boundary {
            bytes.fill(0);
            return Err(error);
        }
        if let Err(error) = check_target(self.bounds, self.deadline, self.clock) {
            self.boundary = Some(error);
            bytes.fill(0);
            return Err(error);
        }
        if let Err(error) = self.provider.fill(bytes) {
            bytes.fill(0);
            return Err(error);
        }
        if let Err(error) = check_target(self.bounds, self.deadline, self.clock) {
            self.boundary = Some(error);
            bytes.fill(0);
            return Err(error);
        }
        Ok(())
    }
}

/// Unique original Round1 material and one checked per-recipient producer job.
/// Constructor admission performs no entropy draw, source operation or signing.
pub struct OwnRevealBuilder {
    context: Option<Context>,
    phase: Phase,
    group: Group,
    bytes: Vec<u8>,
    recipient: usize,
    limits: Limits,
    failure: Option<Failure>,
    taken: bool,
}
impl OwnRevealBuilder {
    pub(crate) fn validation_context(&self) -> Result<ValidationContext<'_>, Error> {
        self.context
            .as_ref()
            .map(Context::view)
            .ok_or_else(|| Fault::Closed.into())
    }
    /// Keep every original roster slot. Missing Round1 keys are a refusal, never
    /// a zero proof, reduced roster or a changed threshold.
    pub fn new(transcript: Transcript, limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        check_target(
            transcript.bounds,
            transcript.deadline,
            transcript.clock.as_ref(),
        )?;
        let count = transcript.roster.len();
        if count == 0
            || count > limits.math.participants
            || transcript.threshold == 0
            || transcript.threshold > count
            || transcript.local >= count
            || transcript.commitments.len() != count
            || transcript.polynomial.threshold() != transcript.threshold
            || transcript.coefficients.threshold() != transcript.threshold
            || transcript.roster.windows(2).any(|w| w[0] >= w[1])
        {
            return Err(Fault::InvalidInput.into());
        }
        let extent = crate::admission::round2_reveal_extent(
            &transcript.roster,
            transcript.threshold,
            limits.reveal_bytes,
            limits.consensus.frame_bytes,
        )?;
        for row in &transcript.commitments {
            if row.is_none() {
                return Err(math::Error::Roster.into());
            }
        }
        let local = transcript.commitments[transcript.local]
            .as_ref()
            .ok_or(Fault::NotReady)?;
        if local.key.to_bytes() != transcript.keypair.public_key().to_bytes()
            || *SignedElement::commitment(&local.bytes)?.peer()?
                != transcript.roster[transcript.local]
            || *SignedElement::commitment(&local.bytes)?.commitment_hash()?
                != transcript.coefficients.presecret_hash()?
        {
            return Err(Fault::Authentication.into());
        }
        let (context, polynomial) = Context::split(transcript);
        let heap = context
            .retained_bytes()?
            .checked_add(polynomial.retained_bytes()?)
            .ok_or(Fault::Overflow)?;
        bounded(size_of::<Self>(), heap, extent, limits.retained_bytes)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(extent)
            .map_err(|_| Fault::Capacity)?;
        bounded(
            size_of::<Self>(),
            heap,
            bytes.capacity(),
            limits.retained_bytes,
        )?;
        bytes.resize(extent, 0);
        write_header(
            &mut bytes,
            &context.roster[context.local],
            count,
            context.threshold,
        )?;
        let coefficient_start = coefficient_start(count)?;
        for index in 0..context.threshold {
            let coefficient = context
                .coefficients
                .get(index)
                .ok_or(Fault::Stale)?
                .to_bytes();
            let at = coefficient_start
                .checked_add(index.checked_mul(ipc::FIELD_BYTES).ok_or(Fault::Overflow)?)
                .ok_or(Fault::Overflow)?;
            bytes
                .get_mut(at..at + ipc::FIELD_BYTES)
                .ok_or(Fault::Stale)?
                .copy_from_slice(&coefficient);
        }
        context.check_target()?;
        let group = Group::new()?;
        let phase = Phase::Evaluating(Evaluation::new_owned(polynomial, 0, &group));
        let owner = Self {
            context: Some(context),
            phase,
            group,
            bytes,
            recipient: 0,
            limits,
            failure: None,
            taken: false,
        };
        owner.account()?;
        Ok(owner)
    }
    /// Actual retained allocations plus the active job's fixed inline storage.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        self.retained_measure().map_err(Into::into)
    }
    fn retained_measure(&self) -> Result<usize, Failure> {
        let context = self
            .context
            .as_ref()
            .map(Context::retained_bytes)
            .transpose()?
            .unwrap_or(0);
        let phase = self.phase.retained_bytes()?;
        size_of::<Self>()
            .checked_add(context)
            .and_then(|n| n.checked_add(self.bytes.capacity()))
            .and_then(|n| n.checked_add(phase))
            .ok_or_else(|| Fault::Overflow.into())
    }
    fn account(&self) -> Result<(), Failure> {
        if self.retained_measure()? > self.limits.retained_bytes {
            Err(Fault::Capacity.into())
        } else {
            Ok(())
        }
    }
    fn erase(&mut self) {
        self.phase.cancel();
        self.context = None;
        self.bytes = Vec::new();
    }
    fn fail(&mut self, failure: Failure) -> Error {
        let original = *self.failure.get_or_insert(failure);
        self.erase();
        original.into()
    }
    fn advance_inner(
        &mut self,
        entropy: &mut impl math::Entropy,
        units: u16,
    ) -> Result<math::Progress, Failure> {
        if units == 0 || units > self.limits.math.units_per_turn {
            return Err(math::Error::Capacity.into());
        }
        self.context.as_ref().ok_or(Fault::Closed)?.check_target()?;
        match &mut self.phase {
            Phase::Evaluating(job) => {
                if job.advance(units)? == math::Progress::Ready {
                    let Phase::Evaluating(job) = replace(&mut self.phase, Phase::Closed) else {
                        return Err(Fault::Stale.into());
                    };
                    let (polynomial, scalar) = job.take_owned_result()?;
                    let context = self.context.as_ref().ok_or(Fault::Closed)?;
                    let recipient = context
                        .commitments
                        .get(self.recipient)
                        .and_then(Option::as_ref)
                        .ok_or(Fault::NotReady)?;
                    let job = FairProver::new(
                        scalar,
                        &recipient.key,
                        &self.group,
                        self.limits.math,
                        self.limits.paillier,
                    )?;
                    self.phase = Phase::Proving { polynomial, job };
                }
            }
            Phase::Proving { job, .. } => {
                let progress = {
                    let context = self.context.as_ref().ok_or(Fault::Closed)?;
                    let mut guarded = GuardedEntropy {
                        provider: entropy,
                        clock: context.clock.as_ref(),
                        bounds: context.bounds,
                        deadline: context.deadline,
                        boundary: None,
                    };
                    let result = job.advance(&mut guarded, units);
                    if let Some(error) = guarded.boundary {
                        return Err(error.into());
                    }
                    result?
                };
                if progress == math::Progress::Ready {
                    let proof = job.take_result()?;
                    let Phase::Proving { polynomial, .. } = replace(&mut self.phase, Phase::Closed)
                    else {
                        return Err(Fault::Stale.into());
                    };
                    let at = ipc::REVEAL_PREFIX
                        .checked_add(
                            self.recipient
                                .checked_mul(ipc::FAIR_ENCRYPTION_BYTES)
                                .ok_or(Fault::Overflow)?,
                        )
                        .ok_or(Fault::Overflow)?;
                    self.bytes
                        .get_mut(at..at + ipc::FAIR_ENCRYPTION_BYTES)
                        .ok_or(Fault::Stale)?
                        .copy_from_slice(&proof);
                    self.recipient = self.recipient.checked_add(1).ok_or(Fault::Overflow)?;
                    let context = self.context.as_ref().ok_or(Fault::Closed)?;
                    self.phase = if self.recipient == context.roster.len() {
                        Phase::Ready(polynomial)
                    } else {
                        Phase::Evaluating(Evaluation::new_owned(
                            polynomial,
                            u16::try_from(self.recipient).map_err(|_| Fault::Overflow)?,
                            &self.group,
                        ))
                    };
                }
            }
            Phase::Ready(_) => return Ok(math::Progress::Ready),
            Phase::Closed => return Err(Fault::Closed.into()),
        }
        self.context.as_ref().ok_or(Fault::Closed)?.check_target()?;
        Ok(if matches!(self.phase, Phase::Ready(_)) {
            math::Progress::Ready
        } else {
            math::Progress::Advanced
        })
    }
    /// Advance at most the requested original work budget. A producer profile
    /// refusal is sticky: no retry, plaintext reduction or replacement proof.
    pub fn advance(
        &mut self,
        entropy: &mut impl math::Entropy,
        units: u16,
    ) -> Result<math::Progress, Error> {
        if let Some(failure) = self.failure {
            return Err(failure.into());
        }
        if self.taken {
            return Err(math::Error::Finished.into());
        }
        match self.advance_inner(entropy, units) {
            Ok(progress) => match self.account() {
                Ok(()) => Ok(progress),
                Err(failure) => Err(self.fail(failure)),
            },
            Err(failure) => Err(self.fail(failure)),
        }
    }
    /// Transfer the unchanged polynomial and transcript once all original slots
    /// contain actual completed checked proofs. This performs no signing.
    pub fn take_result(&mut self) -> Result<PreparedReveal, Error> {
        if let Some(failure) = self.failure {
            return Err(failure.into());
        }
        if self.taken {
            return Err(math::Error::Finished.into());
        }
        if !matches!(self.phase, Phase::Ready(_)) {
            return Err(math::Error::NotReady.into());
        }
        if let Err(error) = self.context.as_ref().ok_or(Fault::Closed)?.check_target() {
            return Err(self.fail(error.into()));
        }
        let Phase::Ready(polynomial) = replace(&mut self.phase, Phase::Closed) else {
            return Err(Fault::Stale.into());
        };
        let context = self.context.take().ok_or(Fault::Closed)?;
        self.taken = true;
        Ok(PreparedReveal {
            transcript: context.join(polynomial),
            bytes: take(&mut self.bytes),
        })
    }
    /// Cancel this unique original job and erase every retained private owner.
    pub fn cancel(&mut self) {
        if !self.taken {
            let _failure = self.fail(math::Error::Cancelled.into());
        }
    }
}
impl Drop for OwnRevealBuilder {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Actual completed local proofs and the unchanged unique Round1 material.
/// This does not establish a PILS operation, native INSERT or completed DKG.
pub struct PreparedReveal {
    transcript: Transcript,
    bytes: Vec<u8>,
}
impl PreparedReveal {
    pub(crate) fn validation_context(&self) -> ValidationContext<'_> {
        ValidationContext::from(&self.transcript)
    }
    /// Actual unique material and public reveal allocations, including spare
    /// capacity, for the enclosing native owner's next admission budget.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        output_retained(size_of::<Self>(), &self.transcript, self.bytes.capacity())
    }
    /// Exact standard purpose22 region to submit to an actual signing source.
    pub fn signed_bytes(&self) -> &[u8] {
        &self.bytes[64..]
    }
    /// Original local roster peer, never a later active-key substitution.
    pub fn peer(&self) -> &[u8; 32] {
        &self.transcript.roster[self.transcript.local]
    }
    /// Verify the actual signature under that original peer before attaching it.
    /// A supplied signature is not evidence of a PILS request/whole write.
    pub fn accept_signature(mut self, signature: EddsaSignature) -> Result<SignedOwnReveal, Error> {
        check_target(
            self.transcript.bounds,
            self.transcript.deadline,
            self.transcript.clock.as_ref(),
        )?;
        attach_signature(
            &mut self.bytes,
            &self.transcript.roster[self.transcript.local],
            self.transcript.roster.len(),
            self.transcript.threshold,
            &signature,
        )?;
        check_target(
            self.transcript.bounds,
            self.transcript.deadline,
            self.transcript.clock.as_ref(),
        )?;
        Ok(SignedOwnReveal {
            transcript: self.transcript,
            bytes: self.bytes,
        })
    }
}
/// Original signed standard reveal; no fabricated remote523 or source closure.
pub struct SignedOwnReveal {
    transcript: Transcript,
    bytes: Vec<u8>,
}
impl SignedOwnReveal {
    /// Actual retained capacity before the native owner adopts these materials.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        output_retained(size_of::<Self>(), &self.transcript, self.bytes.capacity())
    }
    /// Transfer actual material and exact bytes to the future native owner.
    pub fn into_parts(self) -> (Transcript, Vec<u8>) {
        (self.transcript, self.bytes)
    }
}

fn output_retained(fixed: usize, transcript: &Transcript, bytes: usize) -> Result<usize, Error> {
    let polynomial = transcript.polynomial.retained_bytes()?;
    let coefficients = transcript.coefficients.retained_bytes()?;
    transcript
        .roster
        .capacity()
        .checked_mul(size_of::<[u8; 32]>())
        .and_then(|n| {
            transcript
                .commitments
                .capacity()
                .checked_mul(size_of::<Option<PeerCommitment>>())
                .and_then(|m| n.checked_add(m))
        })
        .and_then(|n| n.checked_add(polynomial))
        .and_then(|n| n.checked_add(coefficients))
        .and_then(|n| n.checked_add(bytes))
        .and_then(|n| n.checked_add(fixed))
        .ok_or_else(|| Fault::Overflow.into())
}

fn check_target(
    bounds: crate::Bounds,
    deadline: u64,
    clock: &dyn RuntimeClock,
) -> Result<(), Fault> {
    if Instant::now() >= bounds.hard {
        return Err(Fault::Deadline);
    }
    let now = clock.sample()?.now.as_micros();
    if Instant::now() >= bounds.hard || now >= bounds.expires || now >= deadline {
        return Err(Fault::Deadline);
    }
    Ok(())
}
fn bounded(fixed: usize, heap: usize, extra: usize, maximum: usize) -> Result<(), Fault> {
    if fixed
        .checked_add(heap)
        .and_then(|n| n.checked_add(extra))
        .ok_or(Fault::Overflow)?
        > maximum
    {
        Err(Fault::Capacity)
    } else {
        Ok(())
    }
}
fn coefficient_start(recipients: usize) -> Result<usize, Fault> {
    recipients
        .checked_mul(ipc::FAIR_ENCRYPTION_BYTES)
        .and_then(|n| ipc::REVEAL_PREFIX.checked_add(n))
        .ok_or(Fault::Overflow)
}
fn write_header(
    bytes: &mut [u8],
    peer: &[u8; 32],
    recipients: usize,
    threshold: usize,
) -> Result<(), Fault> {
    if bytes.len() != ipc::reveal_encoded_len(recipients, threshold)? {
        return Err(Fault::Malformed);
    }
    ipc::encode_reveal_prefix(bytes, &[0; 64], peer, recipients, threshold)?;
    Ok(())
}
fn attach_signature(
    bytes: &mut [u8],
    peer: &[u8; 32],
    recipients: usize,
    threshold: usize,
    signature: &EddsaSignature,
) -> Result<(), Fault> {
    let reveal = SignedElement::reveal(bytes, recipients, threshold)?;
    if reveal.peer()? != peer {
        return Err(Fault::Authentication);
    }
    EddsaPublicKey::from_bytes(*peer).verify(
        ipc::DKG2_PURPOSE,
        reveal.signed_bytes(),
        signature,
    )?;
    bytes[..64].copy_from_slice(signature.as_bytes());
    Ok(())
}

#[cfg(test)]
mod tests;
