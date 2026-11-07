use gnunet_client_host::{ConnectError, EndpointSource};
use gnunet_secretsharing_decrypt_host as decrypt;
use gnunet_secretsharing_keygen_host as keygen;
use gnunet_service_runtime::{accepted::SocketEvent, clock::RuntimeClock, service::PeerAddress};
use gnunet_types::Error as Fault;
use std::{fmt, sync::Arc, time::Duration};
/// Actual original native/protocol/owner failure, without private frame logging.
#[derive(Debug)]
pub enum Error {
    /// Actual accepted socket IO error.
    Io(std::io::Error),
    /// Shared configuration, clock or Resolver error.
    Native(ConnectError),
    /// Actual installed native decrypt owner refusal/source/math error.
    Decrypt(decrypt::Error),
    /// Actual complete generation pipeline refusal/source/proof error.
    Generate(keygen::Error),
    /// Explicit resource/time/wire refusal.
    Protocol(Fault),
    /// Actual singleton polynomial/commitment/Horner refusal.
    Math(gnunet_secretsharing::Error),
    /// Client EOF before its complete original response; no peer result implied.
    Eof,
    /// One original MQ cannot adopt a second operation.
    DuplicateRequest,
}
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self::Protocol(e)
    }
}
impl From<ConnectError> for Error {
    fn from(e: ConnectError) -> Self {
        Self::Native(e)
    }
}
impl From<decrypt::Error> for Error {
    fn from(e: decrypt::Error) -> Self {
        Self::Decrypt(e)
    }
}
impl From<keygen::Error> for Error {
    fn from(error: keygen::Error) -> Self {
        Self::Generate(error)
    }
}
impl From<gnunet_secretsharing::Error> for Error {
    fn from(e: gnunet_secretsharing::Error) -> Self {
        Self::Math(e)
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => e.fmt(f),
            Self::Native(e) => e.fmt(f),
            Self::Decrypt(e) => e.fmt(f),
            Self::Generate(e) => e.fmt(f),
            Self::Protocol(e) => e.fmt(f),
            Self::Math(e) => e.fmt(f),
            Self::Eof => f.write_str("original SS client EOF before complete782/783"),
            Self::DuplicateRequest => f.write_str("one original SS MQ accepts one780 or781 only"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Native(e) => Some(e),
            Self::Decrypt(e) => Some(e),
            Self::Generate(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Math(e) => Some(e),
            _ => None,
        }
    }
}
/// Coherent selected service endpoints and one original shared clock.
pub struct Sources {
    pub(crate) pils: EndpointSource,
    pub(crate) consensus: EndpointSource,
    pub(crate) clock: Arc<dyn RuntimeClock>,
    pub(crate) fixed_bytes: usize,
}
impl Sources {
    /// Freeze configured endpoints; no socket, crypto work or task starts here.
    pub fn new(pils: EndpointSource, consensus: EndpointSource) -> Result<Self, Error> {
        let clock = pils.clock();
        if !Arc::ptr_eq(&clock, &consensus.clock()) {
            return Err(Fault::Conflict.into());
        }
        let [pils, consensus] = EndpointSource::snapshot_all([&pils, &consensus])?;
        let pils = pils.fixed_endpoint()?;
        let consensus = consensus.fixed_endpoint()?;
        let fixed_bytes = pils
            .fixed_endpoint_storage_bytes()?
            .ok_or(Fault::NotReady)?
            .checked_add(
                consensus
                    .fixed_endpoint_storage_bytes()?
                    .ok_or(Fault::NotReady)?,
            )
            .ok_or(Fault::Overflow)?;
        Ok(Self {
            pils,
            consensus,
            clock,
            fixed_bytes,
        })
    }
    pub(crate) fn duplicate(&self) -> Result<Self, Error> {
        Ok(Self {
            pils: self.pils.duplicate()?,
            consensus: self.consensus.duplicate()?,
            clock: self.clock.clone(),
            fixed_bytes: self.fixed_bytes,
        })
    }
    pub(crate) fn native(&self) -> Result<decrypt::Sources, Error> {
        Ok(decrypt::Sources::new(
            self.pils.duplicate()?,
            self.consensus.duplicate()?,
        )?)
    }
    pub(crate) fn generation(&self) -> Result<keygen::Sources, Error> {
        Ok(keygen::Sources::new(
            self.pils.duplicate()?,
            self.consensus.duplicate()?,
        )?)
    }
    /// Clone the original clock Arc without reserving a subscription.
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
}
/// Finite native admission/resource policies, separate from standard wire data.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Original IPC owners, including queued requests and output/cleanup debt.
    pub clients: usize,
    /// Simultaneous admitted original780/781 operations through whole output.
    pub operations: usize,
    /// Conservative allocation reservation per original generation/decrypt operation.
    pub operation_bytes: usize,
    /// Aggregate service metadata/buffer/operation reservation.
    pub total_retained_bytes: usize,
    /// Complete original IPC frame, at most65535.
    pub frame_bytes: usize,
    /// Maximum offered accepted socket syscall quantum.
    pub io_slice_bytes: usize,
    /// Admission to complete initial request target, never renewed.
    pub first_input: Duration,
    /// First positive byte to complete frame target, never renewed.
    pub partial_input: Duration,
    /// Admission to complete response whole bound, capped by the original780/781 deadline.
    pub operation: Duration,
    /// Queue through whole782/783 write bound, capped by the original whole bound.
    pub output: Duration,
    /// Explicit ABI for the share's actual memcpy'd uint16 original indices.
    pub index_order: decrypt::IndexOrder,
    /// Actual original PILS/CONSENSUS/threshold-owner resources and profile.
    pub decrypt: decrypt::Limits,
}
impl Default for Limits {
    fn default() -> Self {
        let decrypt = decrypt::Limits::default();
        Self {
            clients: 16,
            operations: 8,
            operation_bytes: decrypt.retained_bytes,
            total_retained_bytes: 512 << 20,
            frame_bytes: 65535,
            io_slice_bytes: 65535,
            first_input: Duration::from_secs(30),
            partial_input: Duration::from_secs(15),
            operation: Duration::from_secs(300),
            output: Duration::from_secs(15),
            index_order: decrypt::IndexOrder::native(),
            decrypt,
        }
    }
}
impl Limits {
    /// The same selected work/source policies apply to both standard operations.
    /// The enclosing generation owner supplies its remaining whole reservation.
    pub(crate) fn generation(self, retained_bytes: usize) -> keygen::Limits {
        keygen::Limits {
            math: self.decrypt.math,
            frame_bytes: self.frame_bytes,
            peers: self.decrypt.peers,
            retained_bytes,
            pils: self.decrypt.pils,
            hello: self.decrypt.hello,
            profile: self.decrypt.profile,
            consensus: self.decrypt.consensus,
            ..keygen::Limits::default()
        }
    }
    /// Validate impossible profiles before normal source/crypto admission.
    pub fn validate(self) -> Result<(), Error> {
        self.decrypt.validate()?;
        if self.clients == 0
            || self.clients > 65536
            || self.operations == 0
            || self.operations > self.clients
            || self.operation_bytes < self.decrypt.retained_bytes
            || self.total_retained_bytes < self.operation_bytes
            || !(702..=65535).contains(&self.frame_bytes)
            || self.decrypt.frame_bytes < self.frame_bytes
            || self.io_slice_bytes == 0
        {
            return Err(Fault::InvalidInput.into());
        }
        self.frame_bytes.checked_mul(8).ok_or(Fault::Overflow)?;
        for duration in [
            self.first_input,
            self.partial_input,
            self.operation,
            self.output,
        ] {
            if duration.is_zero()
                || duration.as_micros() >= u128::from(u64::MAX)
                || std::time::Instant::now().checked_add(duration).is_none()
            {
                return Err(Fault::InvalidInput.into());
            }
        }
        Ok(())
    }
}
/// Actual original local contribution receipt, without cloning its source token.
#[derive(Debug)]
pub struct Contribution {
    /// Original physical CONSENSUS epoch.
    pub epoch: gnunet_consensus_client_host::Epoch,
    /// Original exact native operation kind/continuation.
    pub kind: gnunet_consensus_client_host::Kind,
    /// Actual whole local written bytes.
    pub written: usize,
    /// Original fixed canonical/native write targets.
    pub original: gnunet_consensus_client_host::Bounds,
}
impl From<gnunet_consensus_client_host::Receipt> for Contribution {
    fn from(r: gnunet_consensus_client_host::Receipt) -> Self {
        Self {
            epoch: r.epoch,
            kind: r.kind,
            written: r.written,
            original: r.original,
        }
    }
}
/// Actual original PILS completion metadata, without private result material.
#[derive(Debug)]
pub enum SignatureResult {
    /// Original independently verified signature observation.
    Signature {
        /// Original operation numeric diagnostic.
        operation: u64,
        /// Actual returned signer, never replaced by current identity.
        peer: [u8; 32],
        /// Actual matching announcement peer and epoch when supplied.
        announced: Option<([u8; 32], u64)>,
    },
    /// Actual native crypto refusal, not replaced by EOF or a negative proof.
    Failed {
        /// Original operation numeric diagnostic.
        operation: u64,
        /// Original actual operation family.
        kind: gnunet_pils::client::OperationKind,
        /// Actual explicit crypto refusal.
        reason: gnunet_pils::client::Failure,
    },
    /// Unexpected result kind; its owned secret is erased, never logged.
    Unexpected {
        /// Original result operation numeric diagnostic.
        operation: u64,
    },
}
pub(crate) fn signature_fact(completion: &gnunet_pils::client::Completion<'_>) -> SignatureResult {
    match completion {
        gnunet_pils::client::Completion::Signature {
            operation,
            peer,
            announced,
            ..
        } => SignatureResult::Signature {
            operation: operation.value(),
            peer: *peer.as_bytes(),
            announced: announced
                .map(|identity| (*identity.peer().as_bytes(), identity.epoch().value())),
        },
        gnunet_pils::client::Completion::Failed {
            operation,
            kind,
            reason,
        } => SignatureResult::Failed {
            operation: operation.value(),
            kind: *kind,
            reason: *reason,
        },
        other => SignatureResult::Unexpected {
            operation: other.operation().value(),
        },
    }
}
/// Static original decrypt diagnostics after scoped branded tokens retire.
/// Numeric IDs are diagnostic and cannot authorize another source/operation.
#[derive(Debug)]
pub struct DecryptFacts {
    /// Actual ciphertext-derived original CONSENSUS session hash.
    pub session: [u8; 64],
    /// Original start/deadline, participant count and threshold.
    pub original: (u64, u64, usize, usize),
    /// Selected threshold-one local path, not a successful quorum/525 receipt.
    /// Actual verified partials and completed remain independent below.
    pub local_threshold_one: bool,
    /// First real entropy-provider error, independently retained.
    pub entropy_error: Option<getrandom::Error>,
    /// Explicit native owner close/cancel, not a wire cancellation ACK.
    pub cancelled: bool,
    /// Missing original signature result remains unknown.
    pub signature_unknown: bool,
    /// Actually observed peer, epoch and HELLO expiration.
    pub identity: Option<([u8; 32], u64, u64)>,
    /// Original signing operation numeric diagnostic.
    pub sign_operation: Option<u64>,
    /// Actual whole local signing write.
    pub sign_written: bool,
    /// Actual completion operation and signer when a signature was returned.
    pub sign_completion: Option<SignatureResult>,
    /// Original independently observed PILS lost-source cause.
    pub pils_loss: Option<gnunet_pils_host::client::LossCause>,
    /// Original lost epoch and retained crypto count.
    pub pils_lost: Option<(u64, usize)>,
    /// First actual initial PILS retry error.
    pub pils_retry: Option<std::io::Error>,
    /// Actual original IDs from physical PILS close, numeric diagnostics only.
    pub pils_retired: [Option<u64>; 1],
    /// Actual no-pending/no-output postcondition.
    pub pils_idle: bool,
    /// Actual whole local contribution receipt, not remote processing.
    pub contribution: Option<Contribution>,
    /// Actual whole Conclude and actual525, kept distinct.
    pub consensus: (bool, bool),
    /// Original CONSENSUS loss/exposure metadata.
    pub consensus_loss: Option<gnunet_consensus_client_host::Loss>,
    /// Actual initial CONSENSUS retry error.
    pub consensus_retry: Option<std::io::Error>,
    /// Distinct verified partial and rejected-element counts.
    pub partials: (usize, u64),
    /// Real Combine completion was delivered by the installed owner.
    pub completed: bool,
}
impl From<decrypt::Report<'_>> for DecryptFacts {
    fn from(r: decrypt::Report<'_>) -> Self {
        let identity = r.identity.map(|i| {
            (
                *i.peer().as_bytes(),
                i.epoch().value(),
                i.expiration().as_micros(),
            )
        });
        let sign_completion = r.signature_completion.as_ref().map(signature_fact);
        let (pils_loss, pils_lost) = match r.pils_loss {
            Some(lost) => (
                Some(lost.cause),
                Some((lost.epoch.value(), lost.report.retained())),
            ),
            None => (None, None),
        };
        Self {
            session: r.session,
            original: (r.start, r.deadline, r.participants, r.threshold),
            local_threshold_one: r.local_threshold_one,
            entropy_error: r.entropy_error,
            cancelled: r.cancelled,
            signature_unknown: r.signature_result_unknown,
            identity,
            sign_operation: r.signature_operation.map(|id| id.value()),
            sign_written: r.signature_written,
            sign_completion,
            pils_loss,
            pils_lost,
            pils_retry: r.pils_retry,
            pils_retired: r.pils_retired.map(|id| id.map(|id| id.value())),
            pils_idle: r.pils_idle,
            contribution: r.contribution.map(Contribution::from),
            consensus: (r.conclude_written, r.consensus_done),
            consensus_loss: r.consensus_loss,
            consensus_retry: r.consensus_retry,
            partials: (r.verified, r.rejected),
            completed: r.completed,
        }
    }
}
/// Actual one-round CONSENSUS observations after its original source retires.
#[derive(Debug, Default)]
pub struct GenerationConsensusFacts {
    /// Actual whole local reveal/commitment INSERT, never a peer ACK.
    pub contribution: Option<Contribution>,
    /// Actual whole CONCLUDE and actual525, kept separate.
    pub completion: (bool, bool),
    /// Original source loss/pending/exposure information.
    pub loss: Option<gnunet_consensus_client_host::Loss>,
    /// First actual preattachment failure.
    pub retry: Option<std::io::Error>,
}
/// Actual signature-operation history after its branded native owner retires.
/// Numeric operation values here are diagnostics and grant no source authority.
#[derive(Debug)]
pub struct GenerationSignatureFacts {
    /// Original admitted operation, even when its result remained unknown.
    pub operation: Option<u64>,
    /// Actual matched whole SIGN write.
    pub written: bool,
    /// Actual original completion, including its signer or explicit refusal.
    pub completion: Option<SignatureResult>,
    /// An admitted operation had no result at physical retirement.
    pub unknown: bool,
}
/// Original generation facts; no scalar, polynomial or783 is formatted.
#[derive(Debug)]
pub struct GenerateFacts {
    /// Exact original session context, never used as a random seed.
    pub session: [u8; 64],
    /// Original absolute communication start hint.
    pub start: u64,
    /// Original absolute deadline, capped by original service admission.
    pub deadline: u64,
    /// Verified actual PILS peer, original epoch and announcement expiry.
    pub identity: Option<([u8; 32], u64, u64)>,
    /// Actual initial connection retry, without a replacement source result.
    pub pils_retry: Option<std::io::Error>,
    /// Original physical PILS loss and its real cause.
    pub pils_loss: Option<gnunet_pils_host::client::LossCause>,
    /// Original lost epoch and retained operation count, as diagnostics only.
    pub pils_lost: Option<(u64, usize)>,
    /// Original operation IDs returned by actual physical source close.
    pub pils_retired: [Option<u64>; 1],
    /// Actual post-close no-pending/no-output state.
    pub pils_idle: bool,
    /// First actual entropy provider failure, without secret bytes.
    pub entropy_error: Option<getrandom::Error>,
    /// Actual identity classification selected the general native pipeline.
    pub multiparty: bool,
    /// Original distinct Round1 and Round2 source facts, when those rounds ran.
    pub rounds: [Option<GenerationConsensusFacts>; 2],
    /// Actual Round1 and Round2 signature histories, when those stages ran.
    pub signatures: [Option<GenerationSignatureFacts>; 2],
    /// Actual ready count and local selected position; insufficient and nonmember
    /// standard results are distinct from a usable threshold-decryption roster.
    pub selection: Option<(usize, Option<usize>)>,
    /// Actual math/response formation and dependency retirement completed.
    /// This is neither a whole IPC write nor a usable-roster certificate.
    pub completed: bool,
}
impl GenerateFacts {
    pub(crate) fn new(session: [u8; 64], start: u64, deadline: u64) -> Self {
        Self {
            session,
            start,
            deadline,
            identity: None,
            pils_retry: None,
            pils_loss: None,
            pils_lost: None,
            pils_retired: [None],
            pils_idle: false,
            entropy_error: None,
            multiparty: false,
            rounds: [None, None],
            signatures: [None, None],
            selection: None,
            completed: false,
        }
    }
}
/// One original IPC terminal report; no private share/plaintext is formatted.
#[derive(Debug, Default)]
pub struct ClientReport {
    /// First actual original IPC/owner failure.
    pub primary: Option<Error>,
    /// Independent source retirement/report invariant error.
    pub cleanup: Option<Error>,
    /// Actual original complete780/781 admissions, at most1.
    pub requests: u64,
    /// Actual operation quota admitted, distinct from a merely queued request.
    pub operation_admitted: bool,
    /// Actual original native generation/decrypt owner constructed.
    pub owner_started: bool,
    /// Actual whole local782/783 writes, never a client callback ACK.
    pub results_written: u64,
    /// Actual completed singleton/threshold math, distinct from IPC output.
    pub mathematical_done: bool,
    /// Actual total accepted IPC read/write bytes.
    pub bytes: (u64, u64),
    /// Original response total extent and real written prefix.
    pub response: (usize, usize),
    /// Real original source diagnostics after physical retirement.
    pub decrypt: Option<DecryptFacts>,
    /// Original generation source/math facts after physical close.
    pub generate: Option<GenerateFacts>,
    /// Original request selected standard generation rather than decryption.
    pub generating: bool,
    /// Actual complete frame received, independent of semantic admission.
    pub input_complete: bool,
    /// Original client physically closed before report delivery.
    pub physical_closed: bool,
    /// Incomplete original output retired without claiming whole completion.
    pub output_retired: bool,
    /// Original debts not actually retired; prohibit clean service shutdown.
    pub undrained: usize,
}
/// Bounded service totals, not an interoperability or crypto certificate.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report {
    /// Actually admitted physical clients.
    pub accepted: u64,
    /// Actually physically closed clients.
    pub closed: u64,
    /// Original complete780/781 operations admitted.
    pub requests: u64,
    /// Original whole local782/783 writes.
    pub results_written: u64,
    /// Original clients with an actual failure.
    pub failed: u64,
    /// Original cleanup debts, never guessed zero.
    pub undrained: usize,
}
/// Real native SERVICE observation; original private frames never implement Debug.
#[derive(Debug)]
pub enum Event {
    /// Original accepted socket diagnostic.
    Socket(SocketEvent),
    /// Real access-policy refusal.
    Rejected(PeerAddress),
    /// Original non-recycled local client number.
    Accepted(u64),
    /// Original native stream admission failed and was retired.
    AdmissionFailed(Error),
    /// Actual original client terminal report, preallocated before its IO.
    Closed {
        /// Original service-local client number.
        client: u64,
        /// Original preserved source/native/math/output facts.
        report: Box<ClientReport>,
    },
}
/// One bounded caller-polled SERVICE step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// Real finite native/math/retirement activity.
    Activity,
    /// Only the caller's native observation wait ended.
    WaitDeadline,
    /// Admission stopped and all original physical/native owners retired.
    Stopped,
}
