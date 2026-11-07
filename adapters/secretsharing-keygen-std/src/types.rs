use gnunet_client_host::EndpointSource;
use gnunet_consensus_client_host as consensus;
use gnunet_pils::client::{Completion, Epoch, Identity, LossReport, OperationId};
use gnunet_pils_host::client as pils;
use gnunet_secretsharing as math;
use gnunet_types::Error as Fault;
use gnunet_wire::official::{
    Frame,
    secretsharing::{self as ipc},
};
use std::{fmt, sync::Arc};
/// Original classified refusal/source failure, retaining actual error objects.
#[derive(Debug)]
pub enum Error {
    /// Actual pure resource/time/protocol refusal.
    Protocol(Fault),
    /// Original shared configuration/Clock/Resolver/PILS failure.
    Client(gnunet_client_host::ConnectError),
    /// Actual original CONSENSUS owner failure.
    Consensus(consensus::Error),
    /// Actual original threshold/group/proof failure.
    Math(math::Error),
    /// Actual original Paillier key-generation failure.
    Paillier(gnunet_paillier::Error),
    /// Actual locally produced commitment failed the same original admission.
    LocalCommitment(Rejection),
}
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self::Protocol(e)
    }
}
impl From<gnunet_client_host::ConnectError> for Error {
    fn from(e: gnunet_client_host::ConnectError) -> Self {
        Self::Client(e)
    }
}
impl From<consensus::Error> for Error {
    fn from(e: consensus::Error) -> Self {
        Self::Consensus(e)
    }
}
impl From<math::Error> for Error {
    fn from(e: math::Error) -> Self {
        Self::Math(e)
    }
}
impl From<gnunet_paillier::Error> for Error {
    fn from(e: gnunet_paillier::Error) -> Self {
        Self::Paillier(e)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(e) => e.fmt(f),
            Self::Client(e) => e.fmt(f),
            Self::Consensus(e) => e.fmt(f),
            Self::Math(e) => e.fmt(f),
            Self::Paillier(e) => e.fmt(f),
            Self::LocalCommitment(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(e) => Some(e),
            Self::Client(e) => Some(e),
            Self::Consensus(e) => Some(e),
            Self::Math(e) => Some(e),
            Self::Paillier(e) => Some(e),
            Self::LocalCommitment(e) => Some(e),
        }
    }
}
/// Coherently frozen actual PILS/CONSENSUS endpoint selections, same Clock.
/// There is deliberately no Clone/Debug or implicit runtime/resolver creation.
pub struct Sources {
    pub(crate) pils: EndpointSource,
    pub(crate) consensus: EndpointSource,
}
impl Sources {
    /// Freeze actual selected endpoints after a coherent source snapshot.
    pub fn new(pils: EndpointSource, consensus: EndpointSource) -> Result<Self, Error> {
        if !Arc::ptr_eq(&pils.clock(), &consensus.clock()) {
            return Err(Fault::InvalidInput.into());
        }
        let [pils, consensus] = EndpointSource::snapshot_all([&pils, &consensus])?;
        let pils = pils.fixed_endpoint()?;
        let consensus = consensus.fixed_endpoint()?;
        Ok(Self { pils, consensus })
    }
}
/// Original native and arithmetic resource policy; no value changes official wire.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Existing threshold arithmetic policy.
    pub math: math::Limits,
    /// Actual Paillier prime-search/work policy.
    pub paillier: gnunet_paillier::Limits,
    /// Maximum complete original780 request.
    pub frame_bytes: usize,
    /// Maximum normalized original roster including the actual local identity.
    pub peers: usize,
    /// Aggregate owner/source/vector reservation, not a measured process RSS cap.
    pub retained_bytes: usize,
    /// One original PILS signing operation slot.
    pub pils: pils::Limits,
    /// Actual public announcement parsing limits.
    pub hello: gnunet_pils::HelloLimits,
    /// Explicit actual PILS identity profile; never aliases a legacy master peer.
    pub profile: gnunet_pils::Profile,
    /// Actual native CONSENSUS source policy.
    pub consensus: consensus::Limits,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            math: math::Limits::default(),
            paillier: gnunet_paillier::Limits::default(),
            frame_bytes: 65535,
            peers: 1024,
            retained_bytes: 32 << 20,
            pils: pils::Limits {
                pending_operations: 1,
                ..Default::default()
            },
            hello: gnunet_pils::HelloLimits {
                maximum_input_bytes: 65535,
                maximum_address_bytes: 65535,
                maximum_addresses: 256,
            },
            profile: gnunet_pils::Profile::Reference029,
            consensus: consensus::Limits::default(),
        }
    }
}
impl Limits {
    /// Validate finite original policies before source construction or entropy.
    pub fn validate(self) -> Result<(), Error> {
        self.math.validate()?;
        self.paillier.validate()?;
        if !(88..=65535).contains(&self.frame_bytes)
            || self.peers == 0
            || self.peers > self.math.participants
            || self.retained_bytes == 0
            || self.pils.pending_operations != 1
            || !(368..=65535).contains(&self.pils.frame_bytes)
            || self.pils.io_slice_bytes == 0
            || self.consensus.frame_bytes < 430
            || self.consensus.queued_frames < 3
            || self.consensus.local_elements < 1
            || self.consensus.queued_bytes < self.consensus.frame_bytes
            || self.hello.maximum_input_bytes < 176
            || self.hello.maximum_address_bytes == 0
            || self.hello.maximum_addresses == 0
        {
            return Err(Fault::InvalidInput.into());
        }
        Ok(())
    }
}
/// Exclusive original780 intent. Shape does not imply a usable DKG or roster.
pub struct Request {
    pub(crate) bytes: Vec<u8>,
    pub(crate) session: [u8; 64],
    pub(crate) start: u64,
    pub(crate) deadline: u64,
    pub(crate) threshold: usize,
}
impl Request {
    /// Adopt one exact original780 without parsing an alternate protocol.
    pub fn from_frame(bytes: Vec<u8>, limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        if bytes.len() > limits.frame_bytes || bytes.capacity() > limits.frame_bytes {
            return Err(Fault::Capacity.into());
        }
        let ipc::Request::Generate(request) = ipc::Request::decode(Frame::decode(&bytes)?)? else {
            return Err(Fault::Unsupported.into());
        };
        if request.start >= request.deadline
            || request.threshold == 0
            || usize::from(request.threshold) > limits.peers
            || request.peers.len() / 32 > limits.peers
        {
            return Err(Fault::InvalidInput.into());
        }
        let (session, start, deadline, threshold) = (
            *request.session,
            request.start,
            request.deadline,
            usize::from(request.threshold),
        );
        Ok(Self {
            bytes,
            session,
            start,
            deadline,
            threshold,
        })
    }
}
/// Exact signature/shape/modulus-checked original participant commitment.
/// This is not proof of Paillier factorization or future reveal/fairness.
pub struct PeerCommitment {
    pub(crate) bytes: [u8; ipc::COMMIT_BYTES],
    pub(crate) key: gnunet_paillier::PublicKey,
}
impl PeerCommitment {
    /// Exact original424 bytes, including the verified signature.
    pub const fn bytes(&self) -> &[u8; ipc::COMMIT_BYTES] {
        &self.bytes
    }
    /// Original admitted odd2047/2048-bit modulus, without a factorization claim.
    pub const fn public_key(&self) -> &gnunet_paillier::PublicKey {
        &self.key
    }
}
/// Stage-only owned material. Secret owners deliberately have no Clone/Debug.
/// Drop erases the actual Polynomial/Paillier private owners. No782 is produced.
pub struct Transcript {
    pub(crate) bounds: consensus::Bounds,
    pub(crate) clock: Arc<dyn gnunet_service_runtime::clock::RuntimeClock>,
    pub(crate) session: [u8; 64],
    pub(crate) start: u64,
    pub(crate) deadline: u64,
    pub(crate) threshold: usize,
    pub(crate) local: usize,
    pub(crate) roster: Vec<[u8; 32]>,
    pub(crate) commitments: Vec<Option<PeerCommitment>>,
    pub(crate) polynomial: math::Polynomial,
    pub(crate) coefficients: math::Commitments,
    pub(crate) keypair: gnunet_paillier::KeyPair,
}
impl Transcript {
    /// Original whole native/canonical targets, unchanged by stage completion.
    pub const fn bounds(&self) -> consensus::Bounds {
        self.bounds
    }
    /// Same original selected clock; cloning creates no new subscription.
    pub fn clock(&self) -> Arc<dyn gnunet_service_runtime::clock::RuntimeClock> {
        self.clock.clone()
    }
    /// Original normalized/sorted roster; its indices never shrink on rejection.
    pub fn roster(&self) -> &[[u8; 32]] {
        &self.roster
    }
    /// Actual local index in that original roster.
    pub const fn local_index(&self) -> usize {
        self.local
    }
    /// Original requested threshold, not a count of received elements.
    pub const fn threshold(&self) -> usize {
        self.threshold
    }
    /// One actual checked commitment in the unchanged original index space.
    pub fn commitment(&self, index: usize) -> Option<&PeerCommitment> {
        self.commitments.get(index).and_then(Option::as_ref)
    }
    /// Transfer the actual private material once for a later explicitly gated phase.
    pub fn into_parts(self) -> TranscriptParts {
        TranscriptParts {
            bounds: self.bounds,
            clock: self.clock,
            session: self.session,
            start: self.start,
            deadline: self.deadline,
            threshold: self.threshold,
            local: self.local,
            roster: self.roster,
            commitments: self.commitments,
            polynomial: self.polynomial,
            coefficients: self.coefficients,
            keypair: self.keypair,
        }
    }
}
/// Exclusive actual Round1 material transferred by Transcript; still no final share.
pub struct TranscriptParts {
    /// Same original whole native/canonical targets, never renewed per phase.
    pub bounds: consensus::Bounds,
    /// Same actual selected Clock authority; no replacement provider is inferred.
    pub clock: Arc<dyn gnunet_service_runtime::clock::RuntimeClock>,
    /// Original exact Consensus session.
    pub session: [u8; 64],
    /// Original absolute request start.
    pub start: u64,
    /// Original absolute request deadline.
    pub deadline: u64,
    /// Original threshold.
    pub threshold: usize,
    /// Original local index.
    pub local: usize,
    /// Original sorted normalized peers.
    pub roster: Vec<[u8; 32]>,
    /// Actual checked commitments at original indices.
    pub commitments: Vec<Option<PeerCommitment>>,
    /// Actual original zeroizing polynomial.
    pub polynomial: math::Polynomial,
    /// Actual exponentiated coefficients in original order.
    pub coefficients: math::Commitments,
    /// Actual original ephemeral Paillier public/private material.
    pub keypair: gnunet_paillier::KeyPair,
}
/// The same actual PILS owner, observed identity and original Round1 facts.
/// Construction is sealed to the completed original Round1 path. Moving this
/// session does not create a connection, identity epoch or signing operation.
pub struct SigningSession<'a> {
    pub(crate) client: pils::Client<'a, 1>,
    pub(crate) identity: Identity<'a>,
    round1: Option<Report<'a>>,
    closed: bool,
}
impl<'a> SigningSession<'a> {
    pub(crate) fn new(
        client: pils::Client<'a, 1>,
        identity: Identity<'a>,
        report: Report<'a>,
    ) -> Self {
        Self {
            client,
            identity,
            round1: Some(report),
            closed: false,
        }
    }
    /// Original observed identity, retaining its actual source/instance brand.
    #[must_use]
    pub const fn identity(&self) -> Identity<'a> {
        self.identity
    }
    /// Original Round1 operation, signature and source facts. Closing transfers
    /// these once; no numeric surrogate replaces their branded operation IDs.
    #[must_use]
    pub fn round1_report(&self) -> Option<&Report<'a>> {
        self.round1.as_ref()
    }
    /// Actual original PILS storage plus its finite future-frame allowance.
    /// Re-read retained capacities after later signing/announcement progress;
    /// inline client, identity and report storage belongs to its owner size.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        let client = self.client.storage_reservation_bytes()?;
        let report = self
            .round1
            .as_ref()
            .map_or(Ok(0), Report::retained_storage_bytes)?;
        client
            .checked_add(report)
            .ok_or_else(|| Fault::Overflow.into())
    }
    /// Physically retire this same PILS session before returning all original
    /// Round1 facts and the actual branded IDs retired by that close, once.
    pub fn close(&mut self) -> Option<Report<'a>> {
        if !self.closed {
            let retired = self.client.close();
            let idle = self.client.is_idle();
            if let Some(report) = &mut self.round1 {
                report.signature_result_unknown = report.signature_result_missing();
                report.pils_retired = retired;
                report.pils_idle = idle;
            }
            self.closed = true;
        }
        self.round1.take()
    }
}
impl Drop for SigningSession<'_> {
    fn drop(&mut self) {
        let _report = self.close();
    }
}
/// Original first-round material and the still-live original signing session.
/// Dropping an unconsumed handoff closes that actual session and erases secrets.
pub struct CompletedRound1<'a> {
    pub(crate) transcript: Transcript,
    pub(crate) session: SigningSession<'a>,
}
impl<'a> CompletedRound1<'a> {
    /// Unchanged original roster, threshold, bounds and mathematical owners.
    #[must_use]
    pub const fn transcript(&self) -> &Transcript {
        &self.transcript
    }
    /// Same original PILS owner and actual first-round signing/source facts.
    #[must_use]
    pub const fn signing_session(&self) -> &SigningSession<'a> {
        &self.session
    }
    /// Move both original owners into the next phase without reopening PILS.
    #[must_use]
    pub fn into_parts(self) -> (Transcript, SigningSession<'a>) {
        (self.transcript, self.session)
    }
}
/// Original physical PILS source loss, independent of any signing result.
pub struct PilsLoss<'a> {
    /// Original actual source epoch.
    pub epoch: Epoch<'a>,
    /// Actual source cause.
    pub cause: pils::LossCause,
    /// Actual retained original operation/feed facts.
    pub report: LossReport<'a, 1>,
}
/// Stage observations. No secret result, physical delivery or DKG is inferred.
#[derive(Default)]
pub struct Report<'a> {
    /// Original actual active identity; never relabelled as a legacy master key.
    pub identity: Option<Identity<'a>>,
    /// Original signing operation.
    pub signature_operation: Option<OperationId<'a>>,
    /// Actual original whole SIGN frame write.
    pub signature_written: bool,
    /// Actual independently verified returned signature result.
    pub signature_completion: Option<Completion<'a>>,
    /// Missing original result at physical close, without an Unsent guess.
    pub signature_result_unknown: bool,
    /// Actual original PILS source loss.
    pub pils_loss: Option<PilsLoss<'a>>,
    /// First actual preattachment failure.
    pub pils_retry: Option<std::io::Error>,
    /// Actual signing IDs retired when the persistent PILS session physically
    /// closes. Following a successful handoff these may include later-round IDs.
    pub pils_retired: [Option<OperationId<'a>>; 1],
    /// Actual persistent PILS idle state observed at physical close; a live
    /// successful handoff does not manufacture a close observation here.
    pub pils_idle: bool,
    /// Actual original INSERT whole-write receipt.
    pub contribution: Option<consensus::Receipt>,
    /// Actual original CONCLUDE whole-write.
    pub conclude_written: bool,
    /// Actual525 for the original source and whole CONCLUDE.
    pub consensus_done: bool,
    /// Actual original consensus loss/pending/cursor facts.
    pub consensus_loss: Option<consensus::Loss>,
    /// First actual preattachment retry.
    pub consensus_retry: Option<std::io::Error>,
    /// First actual entropy failure, independent of pure error classification.
    pub entropy_error: Option<getrandom::Error>,
    /// Distinct original peers with a retained complete valid commitment.
    pub verified: usize,
    /// Actual rejected invalid/duplicate/foreign elements.
    pub rejected: u64,
    /// Actual explicit caller cancellation request.
    pub cancelled: bool,
    /// Actual stage material/session transferred after525 and original
    /// CONSENSUS closure. PILS remains live until its session owner closes.
    pub completed: bool,
}
impl Report<'_> {
    pub(crate) fn signature_result_missing(&self) -> bool {
        self.signature_operation.is_some_and(|operation| {
            self.signature_completion
                .as_ref()
                .is_none_or(|completion| completion.operation() != operation)
        })
    }
    /// Actual owned failure-report buffers retained after source retirement.
    /// Inline facts and shared tokens remain in their containing owner layout.
    pub fn retained_storage_bytes(&self) -> Result<usize, Error> {
        Ok(self
            .consensus_loss
            .as_ref()
            .map_or(Ok(0), consensus::Loss::retained_storage_bytes)?)
    }
}

#[cfg(test)]
mod report_tests {
    use super::*;

    #[test]
    fn foreign_branded_completion_does_not_hide_the_original_missing_sign_result()
    -> Result<(), Error> {
        let mut a = gnunet_pils::client::Instance::new();
        let mut b = gnunet_pils::client::Instance::new();
        let mut left = gnunet_pils::client::Client::<1, 512, 512>::new(
            &mut a,
            gnunet_pils::Profile::Reference029,
            gnunet_pils::HelloLimits {
                maximum_input_bytes: 512,
                maximum_address_bytes: 512,
                maximum_addresses: 16,
            },
        )?;
        let mut right = gnunet_pils::client::Client::<1, 512, 512>::new(
            &mut b,
            gnunet_pils::Profile::Reference029,
            gnunet_pils::HelloLimits {
                maximum_input_bytes: 512,
                maximum_address_bytes: 512,
                maximum_addresses: 16,
            },
        )?;
        let mut region = [0; 9];
        region[..4].copy_from_slice(&9u32.to_be_bytes());
        region[4..8].copy_from_slice(&ipc::DKG1_PURPOSE.to_be_bytes());
        let original = left.sign(&region, gnunet_pils::client::KeyTarget::ServiceCurrent)?;
        let foreign = right.sign(&region, gnunet_pils::client::KeyTarget::ServiceCurrent)?;
        if original.value() != foreign.value() || original == foreign {
            return Err(Fault::Conflict.into());
        }
        // A supplied failure is a classification precondition only. This test
        // creates no signature success, native completion or source epoch.
        let mut report = Report {
            signature_operation: Some(original),
            ..Report::default()
        };
        report.signature_completion = Some(gnunet_pils::client::Completion::Failed {
            operation: foreign,
            kind: gnunet_pils::client::OperationKind::Sign,
            reason: gnunet_pils::client::Failure::CryptoRejected,
        });
        if !report.signature_result_missing() {
            return Err(Fault::Conflict.into());
        }
        report.signature_completion = Some(gnunet_pils::client::Completion::Failed {
            operation: original,
            kind: gnunet_pils::client::OperationKind::Sign,
            reason: gnunet_pils::client::Failure::CryptoRejected,
        });
        if report.signature_result_missing() {
            return Err(Fault::Conflict.into());
        }
        report.signature_completion = None;
        if !report.signature_result_missing() {
            return Err(Fault::Conflict.into());
        }
        Ok(())
    }
}
/// Exact reason an actual peer element failed admission; no resource/source error
/// is silently reclassified as a negative cryptographic proof.
#[derive(Debug)]
pub enum Rejection {
    /// Actual shape/unknown element type refusal.
    Shape(Fault),
    /// Original claimed signer is not in the normalized original roster.
    Foreign,
    /// This peer already has a retained complete valid commitment. Later signed
    /// regions do not replace it or revoke that original row.
    Duplicate,
    /// A remote element claims the local identity. Only the original locally
    /// signed INSERT path may establish that peer's own commitment row.
    LocalStatement,
    /// Actual original signature refused verification.
    Signature(Fault),
    /// Actual supplied modulus refused the existing Paillier admission.
    Modulus(gnunet_paillier::Error),
}
impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Round1 commitment refusal: {self:?}")
    }
}
impl std::error::Error for Rejection {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Shape(error) | Self::Signature(error) => Some(error),
            Self::Modulus(error) => Some(error),
            Self::Foreign | Self::Duplicate | Self::LocalStatement => None,
        }
    }
}
/// One bounded actual stage event. Only Complete carries the owned stage result.
#[expect(
    clippy::large_enum_variant,
    reason = "Transfer original actual secret polynomial/key material directly without a new fallible terminal boxing allocation"
)]
pub enum Progress<'a> {
    /// Real finite CPU/IO progress, never publication or protocol success.
    Activity,
    /// Actual invalid/foreign/duplicate peer element was rejected.
    Rejected {
        /// Original signer when available from the exact frame.
        peer: Option<[u8; 32]>,
        /// Actual original refusal.
        reason: Rejection,
    },
    /// Actual original whole INSERT written; not a service ACK.
    ContributionWritten,
    /// Actual525 observed; final local retirement still precedes Complete.
    ConsensusDone,
    /// Move original Round1 material and its same actual PILS session onward;
    /// this is not a Share/782/FAIR/DKG completion.
    Complete(CompletedRound1<'a>),
}
