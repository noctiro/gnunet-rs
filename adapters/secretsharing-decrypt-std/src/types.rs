use gnunet_client_host::EndpointSource;
use gnunet_consensus_client_host as consensus;
use gnunet_pils::client::{Completion, Epoch, Identity, LossReport, OperationId};
use gnunet_pils_host::client as pils;
use gnunet_secretsharing as math;
use gnunet_types::Error as Fault;
use gnunet_wire::official::{
    Frame,
    secretsharing::{self as ipc, IndexOrder},
};
use std::{fmt, sync::Arc};
use zeroize::Zeroizing;
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
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(e) => e.fmt(f),
            Self::Client(e) => e.fmt(f),
            Self::Consensus(e) => e.fmt(f),
            Self::Math(e) => e.fmt(f),
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
        }
    }
}
/// Coherently frozen actual PILS/CONSENSUS endpoint selections, same Clock.
/// There is deliberately no Clone/Debug or implicit runtime/resolver creation.
pub struct Sources {
    pub(crate) pils: EndpointSource,
    pub(crate) consensus: EndpointSource,
    pub(crate) bytes: usize,
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
        let bytes = pils
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
            bytes,
        })
    }
}
/// Explicit finite owner and child-source policy; no limit alters wire bytes.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Original threshold arithmetic work, entropy and participant limits.
    pub math: math::Limits,
    /// Maximum complete original781 frame/capacity.
    pub frame_bytes: usize,
    /// Maximum actual original share peer count.
    pub peers: usize,
    /// Conservative native reservation plus actual owner allocation capacities.
    pub retained_bytes: usize,
    /// Actual identity/signature source limits, exactly one operation slot.
    pub pils: pils::Limits,
    /// Actual HELLO parse/announcement limits.
    pub hello: gnunet_pils::HelloLimits,
    /// One exact selected PILS source profile, no fallback.
    pub profile: gnunet_pils::Profile,
    /// Actual standard CONSENSUS native source limits.
    pub consensus: consensus::Limits,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            math: math::Limits::default(),
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
    /// Reject impossible source/crypto/frame policies before creating work.
    pub fn validate(self) -> Result<(), Error> {
        self.math.validate()?;
        if !(540..=65535).contains(&self.frame_bytes)
            || self.peers == 0
            || self.peers > self.math.participants
            || self.retained_bytes == 0
            || self.pils.pending_operations != 1
            || !(816..=65535).contains(&self.pils.frame_bytes)
            || self.pils.io_slice_bytes == 0
            || self.consensus.frame_bytes < 878
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
/// Exclusive zeroizing owner of one actual original781 and its private share.
/// Shape admission does not create a qualified roster or validated share.
pub struct Request {
    pub(crate) bytes: Zeroizing<Vec<u8>>,
    pub(crate) order: IndexOrder,
    pub(crate) start: u64,
    pub(crate) deadline: u64,
    pub(crate) cipher: [u8; 256],
    pub(crate) count: usize,
    pub(crate) local: usize,
}
impl Request {
    /// Adopt the exact complete private request; no secret/data Clone is used.
    pub fn from_frame(
        bytes: Zeroizing<Vec<u8>>,
        order: IndexOrder,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if bytes.len() > limits.frame_bytes || bytes.capacity() > limits.frame_bytes {
            return Err(Fault::Capacity.into());
        }
        let ipc::Request::Decrypt {
            start,
            deadline,
            ciphertext,
            share,
        } = ipc::Request::decode(Frame::decode(&bytes)?)?
        else {
            return Err(Fault::InvalidInput.into());
        };
        let count = share.len();
        let local = usize::from(share.my_peer());
        if count == 0
            || count > limits.peers
            || local >= count
            || share.threshold() == 0
            || usize::from(share.threshold()) > count
            || start >= deadline
        {
            return Err(math::Error::Roster.into());
        }
        let cipher = *ciphertext;
        Ok(Self {
            bytes,
            order,
            start,
            deadline,
            cipher,
            count,
            local,
        })
    }
    pub(crate) fn share(&self) -> Result<ipc::Share<'_>, Error> {
        let ipc::Request::Decrypt { share, .. } =
            ipc::Request::decode(Frame::decode(&self.bytes)?)?
        else {
            return Err(Fault::Malformed.into());
        };
        Ok(share)
    }
}
/// Original actual PILS lost-source event, not a cancelled-operation guess.
pub struct PilsLoss<'a> {
    /// Original native MQ epoch.
    pub epoch: Epoch<'a>,
    /// Actual native cause.
    pub cause: pils::LossCause,
    /// Original pending-operation/feed outcome facts.
    pub report: LossReport<'a, 1>,
}
/// Original operation facts. Secret results are not printable or cloneable.
pub struct Report<'a> {
    /// Original exact public ciphertext; never a substituted arithmetic residue.
    pub ciphertext: [u8; 256],
    /// Actual SHA512 of that original ciphertext, the fixed C Consensus session.
    pub session: [u8; 64],
    /// Original absolute request start.
    pub start: u64,
    /// Original absolute request deadline.
    pub deadline: u64,
    /// Original share participant count and threshold, without a secret clone.
    pub participants: usize,
    /// Original unchanged required threshold.
    pub threshold: usize,
    /// Selected threshold-one local path only; verified/completed separately
    /// record actual proof/quorum work. This is not a Consensus receipt.
    pub local_threshold_one: bool,
    /// First actual entropy-provider failure, independent of the pure refusal.
    pub entropy_error: Option<getrandom::Error>,
    /// Explicit caller close was requested, not inferred from an error/EOF.
    pub cancelled: bool,
    /// A signing operation lacked an actual result when its source retired;
    /// partial/exposure details unavailable through PILS are not guessed Unsent.
    pub signature_result_unknown: bool,
    /// First real local identity used for this original share.
    pub identity: Option<Identity<'a>>,
    /// Original actual signing operation, independent of local write/receipt.
    pub signature_operation: Option<OperationId<'a>>,
    /// Actual signing frame whole-written, not a signature result.
    pub signature_written: bool,
    /// Actual original owned PILS completion, with signer/announcement metadata.
    pub signature_completion: Option<Completion<'a>>,
    /// Original independently observed PILS loss.
    pub pils_loss: Option<PilsLoss<'a>>,
    /// Actual pre-attachment retry error, never substituted for completion.
    pub pils_retry: Option<std::io::Error>,
    /// Actual IDs retired by physical PILS close.
    pub pils_retired: [Option<OperationId<'a>>; 1],
    /// Actual post-close local no-pending/no-output state.
    pub pils_idle: bool,
    /// Original whole local contribution write receipt, never a peer ACK.
    pub contribution: Option<consensus::Receipt>,
    /// Actual original whole CONCLUDE local write.
    pub conclude_written: bool,
    /// Actual original525 observed after its whole CONCLUDE.
    pub consensus_done: bool,
    /// Original source loss/unfinished write facts.
    pub consensus_loss: Option<consensus::Loss>,
    /// Actual initial native retry error.
    pub consensus_retry: Option<std::io::Error>,
    /// Distinct actual verified original-peer partials, including own proof.
    pub verified: usize,
    /// Rejected invalid/duplicate/unrelated partial elements; no negative proof
    /// is synthesized from resource/entropy/source failure.
    pub rejected: u64,
    /// Real completed CombineJob result was returned exactly once.
    pub completed: bool,
}
impl Default for Report<'_> {
    fn default() -> Self {
        Self {
            ciphertext: [0; 256],
            session: [0; 64],
            start: 0,
            deadline: 0,
            participants: 0,
            threshold: 0,
            local_threshold_one: false,
            entropy_error: None,
            cancelled: false,
            signature_result_unknown: false,
            identity: None,
            signature_operation: None,
            signature_written: false,
            signature_completion: None,
            pils_loss: None,
            pils_retry: None,
            pils_retired: [None],
            pils_idle: false,
            contribution: None,
            conclude_written: false,
            consensus_done: false,
            consensus_loss: None,
            consensus_retry: None,
            verified: 0,
            rejected: 0,
            completed: false,
        }
    }
}
/// One finite actual owner step. Only Done contains a real plaintext owner.
pub enum Progress {
    /// Finite real CPU/source scheduling, never wire or business success.
    Activity,
    /// Invalid or duplicate peer contribution was rejected intact.
    Rejected {
        /// Original claimed peer when structurally available.
        peer: Option<[u8; 32]>,
        /// Actual proof/roster refusal.
        reason: math::Error,
    },
    /// Original local Insert was actually whole-written.
    ContributionWritten,
    /// Actual original525 was observed; combination can now begin.
    ConsensusDone,
    /// Real original quorum/association/Combine completed; owned secret erases
    /// on Drop and is not a service782/784 write receipt.
    Done(math::Plaintext),
}
