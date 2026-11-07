use crate::{Error, Transcript};
use gnunet_consensus_client_host as consensus;
use gnunet_pils::client as pc;
use gnunet_secretsharing as math;
use gnunet_types::Error as Fault;
/// Finite original producer/receiver/source policy. No field changes the wire.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Existing finite membership/Horner/equation/secret-share work units.
    pub math: math::Limits,
    /// Existing actual local Paillier decryption policy.
    pub paillier: gnunet_paillier::Limits,
    /// Actual native original CONSENSUS source policy.
    pub consensus: consensus::Limits,
    /// Maximum complete signed reveal, including every original proof/coefficient.
    pub reveal_bytes: usize,
    /// Aggregate stage/native/evidence reservation, not process RSS.
    pub retained_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            math: Default::default(),
            paillier: Default::default(),
            consensus: Default::default(),
            reveal_bytes: 65529,
            retained_bytes: 32 << 20,
        }
    }
}
impl Limits {
    /// Validate representable finite policies before an actual source is created.
    pub fn validate(self) -> Result<(), Error> {
        self.math.validate()?;
        self.paillier.validate()?;
        if self.reveal_bytes < 1900
            || self.reveal_bytes > 65529
            || self.retained_bytes == 0
            || self.consensus.frame_bytes
                < self.reveal_bytes.checked_add(6).ok_or(Fault::Overflow)?
            || self.consensus.queued_frames < 2
            || self.consensus.queued_bytes < self.consensus.frame_bytes
        {
            return Err(Fault::InvalidInput.into());
        }
        Ok(())
    }
}
/// Actual signature/algebra refusal. Resource/time/source refusal stays Error;
/// it is never fabricated as an invalid mathematical proof.
#[derive(Debug)]
pub enum Rejection {
    /// Actual original shape or unsupported element type.
    Shape(Fault),
    /// Original signed dealer is outside the original roster.
    Foreign,
    /// A remote523 cannot establish the local peer's actual SIGN/INSERT path.
    LocalRequiresOwn,
    /// No checked original Round1 commitment exists for this dealer.
    NoRound1,
    /// A later statement from an already protocol-valid dealer, whether its
    /// signed region is identical or different. The first contribution remains.
    Duplicate,
    /// Actual purpose22 signature failed under that original dealer.
    Signature(Fault),
    /// Original constant-term hash does not open the original Round1 commitment.
    Commitment,
    /// Existing original membership/equation/Horner/scalar check failed.
    Math(math::Error),
    /// Actual original local ciphertext/decryption refused its original modulus.
    Paillier(gnunet_paillier::Error),
}
/// Matched original local signing facts, derived only from the actual PILS
/// operation, successful signature completion and corresponding whole write.
#[derive(Clone, Copy)]
pub struct OwnSignature<'id> {
    pub(super) operation: pc::OperationId<'id>,
    pub(super) identity: pc::Identity<'id>,
    pub(super) written: pc::Written<'id>,
    pub(super) signature: gnunet_crypto::EddsaSignature,
}
impl<'id> OwnSignature<'id> {
    /// Original branded operation, never an unscoped numeric surrogate.
    pub const fn operation(&self) -> pc::OperationId<'id> {
        self.operation
    }
    /// Exact source identity selected for this signature.
    pub const fn identity(&self) -> pc::Identity<'id> {
        self.identity
    }
    /// Actual whole SIGN request write.
    pub const fn written(&self) -> pc::Written<'id> {
        self.written
    }
    /// Actual independently verified returned signature.
    pub const fn signature(&self) -> gnunet_crypto::EddsaSignature {
        self.signature
    }
}
/// Exact local reveal and its matched original whole CONSENSUS INSERT.
/// No remote523 or processing acknowledgement is manufactured for this path.
pub struct OwnEvidence<'id> {
    pub(super) bytes: Vec<u8>,
    pub(super) signing: OwnSignature<'id>,
    pub(super) insertion: consensus::Receipt,
}
impl<'id> OwnEvidence<'id> {
    /// Exact signed standard reveal bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Original matched signing source facts.
    pub const fn signature(&self) -> &OwnSignature<'id> {
        &self.signing
    }
    /// Actual original whole INSERT write, independent of CONCLUDE.
    pub const fn insertion(&self) -> &consensus::Receipt {
        &self.insertion
    }
}
/// Honest provenance of a checked contribution. The local path is represented
/// by actual signing/insertion facts, never by a fabricated remote observation.
#[expect(
    clippy::large_enum_variant,
    reason = "Public local facts remain inline without another fallible allocation"
)]
pub enum ContributionEvidence<'id> {
    /// Actual original remote523 and retired/current source epoch.
    Remote(consensus::Observation),
    /// Actual local SIGN and whole INSERT of the exact checked bytes.
    Own(OwnEvidence<'id>),
}
impl ContributionEvidence<'_> {
    /// Original CONSENSUS source shared with the final closed-source receipts.
    pub fn epoch(&self) -> &consensus::Epoch {
        match self {
            Self::Remote(observation) => observation.epoch(),
            Self::Own(own) => &own.insertion.epoch,
        }
    }
    /// Exact signed reveal, without assigning a fabricated523 to local bytes.
    pub fn reveal_bytes(&self) -> Result<&[u8], Fault> {
        match self {
            Self::Remote(observation) => match observation.response()? {
                consensus::ClientResponse::Element {
                    element_type: 0,
                    data,
                } => Ok(data),
                _ => Err(Fault::Malformed),
            },
            Self::Own(own) => Ok(&own.bytes),
        }
    }
    /// Actual retained raw payload/frame capacity, including spare allocation.
    pub fn retained_bytes(&self) -> usize {
        match self {
            Self::Remote(observation) => observation.retained_bytes(),
            Self::Own(own) => own.bytes.capacity(),
        }
    }
}
/// Actual checked local scalar and its uniquely owned original provenance.
/// Closed-source selection/aggregation remains with the standard finalizer.
pub struct LocalContribution<'id> {
    pub(crate) dealer: usize,
    pub(crate) recipient: usize,
    pub(crate) evidence: ContributionEvidence<'id>,
    pub(crate) scalar: math::Scalar,
    pub(crate) sigma: math::Subgroup,
    pub(crate) coefficients: math::Commitments,
    pub(crate) equation_checks: usize,
    pub(crate) missing: Vec<u16>,
}
impl<'id> LocalContribution<'id> {
    pub(crate) fn complete_for(&self, recipients: usize) -> bool {
        self.missing.is_empty() && self.equation_checks == recipients
    }
    /// Original dealer index, never a reduced candidate position.
    pub const fn dealer_index(&self) -> usize {
        self.dealer
    }
    /// Actual local recipient's unchanged original index.
    pub const fn recipient_index(&self) -> usize {
        self.recipient
    }
    /// Real remote or own provenance of this exact checked reveal.
    pub const fn evidence(&self) -> &ContributionEvidence<'id> {
        &self.evidence
    }
    /// Original indices without complete recipient-key verification.
    pub fn missing_recipient_indices(&self) -> &[u16] {
        &self.missing
    }
    /// Actual complete equation/Horner checks; not a general knowledge proof.
    pub const fn equation_checks(&self) -> usize {
        self.equation_checks
    }
    /// Actual g^local_share matched to the original polynomial commitments.
    pub const fn local_sigma(&self) -> math::Subgroup {
        self.sigma
    }
    /// Original checked coefficient allocation, without reparsing or cloning.
    pub const fn coefficients(&self) -> &math::Commitments {
        &self.coefficients
    }
    /// Move original secret and public evidence owners once.
    pub fn into_parts(self) -> ContributionParts<'id> {
        ContributionParts {
            dealer: self.dealer,
            recipient: self.recipient,
            evidence: self.evidence,
            scalar: self.scalar,
            sigma: self.sigma,
            coefficients: self.coefficients,
            equation_checks: self.equation_checks,
            missing: self.missing,
        }
    }
}
/// Unique scalar, coefficients and exact original contribution provenance.
pub struct ContributionParts<'id> {
    /// Original dealer index.
    pub dealer: usize,
    /// Actual local original recipient index.
    pub recipient: usize,
    /// Actual remote or own source/signing/insertion evidence.
    pub evidence: ContributionEvidence<'id>,
    /// Actual zeroizing local scalar.
    pub scalar: math::Scalar,
    /// Its checked original public value.
    pub sigma: math::Subgroup,
    /// Unique checked coefficient allocation.
    pub coefficients: math::Commitments,
    /// Completed recipient equation/Horner checks.
    pub equation_checks: usize,
    /// Original recipient indices without complete key verification.
    pub missing: Vec<u16>,
}
/// Closed original round material, created only after actual525, all validation,
/// matched whole own INSERT and physical closure of both persistent sources.
pub struct LocalTranscript<'id> {
    pub(crate) round1: Transcript,
    pub(crate) candidates: Vec<Option<LocalContribution<'id>>>,
    pub(crate) source: ClosedSource,
}
/// Original Round2 source facts retained only after its actual525 and physical
/// retirement. There is no public constructor from a boolean or bare peer ID.
pub struct ClosedSource {
    pub(super) epoch: consensus::Epoch,
    pub(super) join: consensus::Receipt,
    pub(super) conclude: consensus::Receipt,
}
impl ClosedSource {
    /// Original retired physical source shared by every accepted observation.
    pub const fn epoch(&self) -> &consensus::Epoch {
        &self.epoch
    }
    /// Actual whole JOIN write, with its unchanged original bounds.
    pub const fn join(&self) -> &consensus::Receipt {
        &self.join
    }
    /// Actual whole CONCLUDE write preceding the original525.
    pub const fn conclude(&self) -> &consensus::Receipt {
        &self.conclude
    }
}
impl<'id> LocalTranscript<'id> {
    /// Borrow unchanged original roster/session/private-material ownership.
    pub const fn round1(&self) -> &Transcript {
        &self.round1
    }
    /// Candidate at its unchanged original dealer index.
    pub fn candidate(&self, index: usize) -> Option<&LocalContribution<'id>> {
        self.candidates.get(index).and_then(Option::as_ref)
    }
    /// Actual closed source and original whole-write receipts.
    pub const fn closed_source(&self) -> &ClosedSource {
        &self.source
    }
    /// Transfer the original unique Round1 owner and unqualified candidate rows.
    pub fn into_parts(
        self,
    ) -> (
        Transcript,
        Vec<Option<LocalContribution<'id>>>,
        ClosedSource,
    ) {
        (self.round1, self.candidates, self.source)
    }
}
/// Actual source/stage facts, without copying secret contributions.
#[derive(Default)]
pub struct Report<'id> {
    /// Original Round1 facts transferred only after the same PILS source closes.
    pub round1: Option<crate::Report<'id>>,
    /// Actual post-close idle state of the persistent PILS client.
    pub pils_idle: bool,
    /// Actual original purpose22 signing operation.
    pub signature_operation: Option<pc::OperationId<'id>>,
    /// Matched actual whole SIGN request write.
    pub signature_written: Option<pc::Written<'id>>,
    /// Actual original completion, retained once without cloning its enum.
    pub signature_completion: Option<pc::Completion<'id>>,
    /// The original admitted signature had no result at physical source close.
    pub signature_result_unknown: bool,
    /// Actual persistent PILS source loss, separate from CONSENSUS facts.
    pub pils_loss: Option<crate::PilsLoss<'id>>,
    /// First actual PILS socket retry observation.
    pub pils_retry: Option<std::io::Error>,
    /// Actual whole local contribution INSERT, not inferred from CONCLUDE.
    pub own_insert: Option<consensus::Receipt>,
    /// Exact entropy-provider error retained separately from its math refusal.
    pub entropy_error: Option<getrandom::Error>,
    /// Actual local validator refusal; never silently treated as a remote miss.
    pub own_rejection: Option<Rejection>,
    /// Actual source epoch for this original Round2 JOIN.
    pub epoch: Option<consensus::Epoch>,
    /// Actual original JOIN whole-write.
    pub join: Option<consensus::Receipt>,
    /// Actual original CONCLUDE whole-write following the own INSERT.
    pub conclude: Option<consensus::Receipt>,
    /// Actual original525; never EOF/deadline interpreted as completion.
    pub done: bool,
    /// Actual source loss/partial/pending-write facts.
    pub loss: Option<consensus::Loss>,
    /// First actual preattachment retry, independent of later outcome.
    pub retry: Option<std::io::Error>,
    /// Current retained locally validated candidates, including diagnostic
    /// rows with missing recipient proofs; not a count of qualified dealers.
    pub candidates: usize,
    /// Actual rejected original inputs.
    pub rejected: u64,
    /// Explicit caller close request.
    pub cancelled: bool,
    /// Original dealer with an unfinished local validation cursor at close.
    pub unfinished_dealer: Option<usize>,
    /// Original recipient cursor at that same close.
    pub unfinished_recipient: Option<usize>,
    /// Stage-only owned transfer after real525 and physical source close.
    pub completed: bool,
}
impl Report<'_> {
    /// Actual owned protocol-history storage. PILS loss metadata is fixed inline;
    /// opaque native error internals are not a whole-process/RSS measurement.
    pub fn retained_storage_bytes(&self) -> Result<usize, Error> {
        let round1 = self
            .round1
            .as_ref()
            .map(crate::Report::retained_storage_bytes)
            .transpose()?
            .unwrap_or(0);
        let loss = self
            .loss
            .as_ref()
            .map(consensus::Loss::retained_storage_bytes)
            .transpose()?
            .unwrap_or(0);
        round1
            .checked_add(loss)
            .ok_or_else(|| Fault::Overflow.into())
    }
}
/// One finite source/arithmetic event, with no invented fairness or DKG credit.
#[expect(
    clippy::large_enum_variant,
    reason = "Transfer original owned private Round1 and local materials without a late fallible boxing allocation"
)]
pub enum Progress<'id> {
    /// Actual bounded scheduling/arithmetic/IO progress only.
    Activity,
    /// An actual original reveal failed its concrete admission/check.
    Rejected {
        /// Original claimed dealer when available.
        peer: Option<[u8; 32]>,
        /// Actual original refusal.
        reason: Rejection,
    },
    /// One actual local value and its recipient-check evidence completed.
    Candidate {
        /// Original dealer index.
        dealer: usize,
    },
    /// Actual original525 received; local/source closure still precedes transfer.
    ConsensusDone,
    /// Closed receiver transcript for the standard protocol finalizer.
    Complete(LocalTranscript<'id>),
}

/// Constructor refusal with the actual physically retired persistent-source facts.
#[must_use]
pub struct BuildFailure<'id> {
    /// Original refusal; no report replaces it.
    pub error: Error,
    /// Actual source cleanup, including the original Round1 branded facts.
    pub report: Report<'id>,
}
