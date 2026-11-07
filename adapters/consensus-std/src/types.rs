//! Actual original core/native receipts and finite bridge policy.
use crate::core::{self, EffectId, Outcome, SetId, TaskId, Terminal};
use gnunet_set_client_host as set;
use gnunet_types::Error as Fault;
use std::fmt;
/// Exact source cause; original native errors are not replaced by their text.
#[derive(Debug)]
pub enum Error {
    /// Pure source, policy, protocol or allocation refusal.
    Protocol(Fault),
    /// Actual generic SET SDK failure, including shared clock/Resolver/IO chain.
    Set(set::Error),
    /// Actual configured CLIENT/shared clock/Resolver failure.
    Native(gnunet_client_host::ConnectError),
    /// Actual original IPC/credential IO error.
    Io(std::io::Error),
}
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self::Protocol(e)
    }
}
impl From<set::Error> for Error {
    fn from(e: set::Error) -> Self {
        Self::Set(e)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(e) => fmt::Display::fmt(e, f),
            Self::Set(e) => fmt::Display::fmt(e, f),
            Self::Native(e) => fmt::Display::fmt(e, f),
            Self::Io(e) => fmt::Display::fmt(e, f),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(e) => Some(e),
            Self::Set(e) => Some(e),
            Self::Native(e) => Some(e),
            Self::Io(e) => Some(e),
        }
    }
}
/// First important physical SET loss, captured before its pure source labels
/// are retired. Observations and copied targets grant no new source authority.
#[derive(Clone, Copy, Debug)]
pub struct SourceLossContext {
    /// Original immutable source labels, absent only if they were unavailable.
    pub source: Option<core::SetContext>,
    /// Actual SDK boundary, independent of a numeric error value.
    pub origin: set::LossOrigin,
    /// Exact deadline check when supplied by the SDK; no target is reconstructed.
    pub deadline: Option<set::DeadlineContext>,
    /// Canonical high-water mark from samples already obtained by this host.
    /// It may be newer than the pure core's sample; it is not a fresh clock
    /// observation at this boundary and cannot replace the SDK's actual sample.
    pub last_host_canonical: u64,
    /// Actual native observation when these loss facts were first recorded.
    pub observed_native: std::time::Instant,
}

/// One population-local admission refusal, independent of physical SET loss.
/// These copied observations neither renew a budget nor grant source authority.
#[derive(Debug)]
pub struct SourceRefusal {
    /// Original immutable source labels at the refusal boundary.
    pub source: Option<core::SetContext>,
    /// Original business/provider error; no native loss is fabricated from it.
    pub error: Error,
    /// Canonical high-water mark from samples already obtained by the host;
    /// this is not a fresh clock observation at the refusal boundary.
    pub last_host_canonical: u64,
    /// Native observation when this local refusal was recorded.
    pub observed_native: std::time::Instant,
}

/// Original per-session finite resources. Native source buffers remain separately
/// bounded by actual SET Limits; these values do not claim measured whole RSS.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Actual pure session/payload/task/offer bounds.
    pub core: core::Limits,
    /// Actual generic SET frame/queue/source operation limits and explicit ABI.
    pub set: set::Limits,
    /// Bridge-owned token/slot metadata capacity bound.
    pub retained_bytes: usize,
    /// Finite pure scheduling units per class turn, from1 through64.
    pub work_budget: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            core: core::Limits::default(),
            set: set::Limits::default(),
            retained_bytes: 4 * 1024 * 1024,
            work_budget: 32,
        }
    }
}
impl Limits {
    /// Validate core and bridge policy before any session or native source.
    pub fn validate(self) -> Result<(), Error> {
        self.core.validate()?;
        self.set.validate()?;
        if self.retained_bytes == 0 || self.work_budget == 0 || self.work_budget > 64 {
            return Err(Fault::InvalidInput.into());
        }
        Ok(())
    }
}
/// Original progress. All native events remain available to the normal Reporter;
/// local writes and cleanup never become a remote SET DONE or consensus525.
pub enum Progress<'id> {
    /// Finite scheduling/native progress, with no ACK or acceptance claim.
    Activity,
    /// Exact original pure action and its actual disposition.
    Terminal(Terminal<'id>),
    /// Exact original core/native operation binding after local commit admission;
    /// this is not a whole write, service ACK or peer acceptance.
    OperationBound {
        /// Original core operation.
        task: TaskId<'id>,
        /// Original immutable source.
        set: SetId<'id>,
        /// Actual original native source epoch.
        epoch: set::Epoch,
        /// Actual native continuation, never a raw recreated RID.
        operation: set::OperationId,
    },
    /// Exact original SET source event, already applied to the same core owner.
    Set {
        /// Original immutable core source.
        set: SetId<'id>,
        /// Actual source epoch/operation/receipt/cause, unmodified.
        event: set::SetProgress,
    },
    /// Actual original listener event; accepted preparation is held by Bridge,
    /// so Accepted itself is represented as Activity rather than moved twice.
    Listener(set::ListenProgress),
    /// Actual original local cancellation disposition, with its own receipt.
    Cancelled {
        /// Original pure operation.
        task: TaskId<'id>,
        /// Actual native continuation, not a remote cancellation ACK.
        receipt: set::OperationReceipt,
    },
    /// An original verified listener request was actually prepared locally.
    Offer {
        /// Original core incoming token.
        offer: core::OfferId<'id>,
        /// Actual original native listener source.
        epoch: set::Epoch,
        /// Actual peer carried by that native request.
        peer: [u8; 32],
        /// Exact official547 context.
        context: gnunet_wire::official::consensus::RoundContext,
    },
    /// Original invalid/unadmitted incoming context; the actual RejectQueued and
    /// whole rejection writes are returned separately through Listener events.
    Rejected {
        /// Actual incoming peer on the original native listener.
        peer: [u8; 32],
        /// Exact core/context admission refusal.
        cause: Fault,
    },
    /// Original operation-specific result refusal; core cancels this actual task
    /// while other quorum tasks can continue. This is not a global source loss.
    TaskFault {
        /// Original affected task.
        task: TaskId<'id>,
        /// Exact first result/protocol/resource refusal.
        cause: Fault,
    },
    /// One source's local admission refusal. Other populations may continue;
    /// this diagnostic is not a whole-session error or a native loss receipt.
    SourceRefused {
        /// Exact original logical source.
        set: SetId<'id>,
        /// Original error and separately labelled observations.
        refusal: SourceRefusal,
    },
    /// Actual native/policy error retained independently from core's first cause.
    Fault(Error),
    /// Root must enqueue this exact frame on the original CONSENSUS IPC client,
    /// retain its cursor, then call complete_client with its actual disposition.
    ClientFrame {
        /// Original immutable output effect.
        effect: EffectId<'id>,
        /// Exact standard523/525 bytes, owned until caller reports disposition.
        bytes: Vec<u8>,
    },
    /// Core requests physical retirement of that original IPC client. The caller
    /// must stop it before complete_client(Retired/Lost/Unsent); no new frame.
    CloseClient {
        /// Original cleanup effect.
        effect: EffectId<'id>,
        /// Original session failure, independent of actual cleanup errors.
        cause: Fault,
    },
    /// All actual bridge sources and core debts have retired. Returned once.
    Stopped(Outcome),
}

impl From<gnunet_client_host::ConnectError> for Error {
    fn from(e: gnunet_client_host::ConnectError) -> Self {
        Self::Native(e)
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl Error {
    pub(crate) fn classified(&self) -> Fault {
        match self {
            Self::Protocol(e) => *e,
            Self::Set(set::Error::Protocol(e)) => *e,
            Self::Set(set::Error::Deadline(_)) => Fault::Deadline,
            Self::Set(set::Error::UnexpectedStatus(_)) => Fault::Malformed,
            Self::Native(gnunet_client_host::ConnectError::Protocol(e)) => *e,
            _ => Fault::Io,
        }
    }
}
