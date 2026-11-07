use gnunet_regex_service::{ClientId, OutputId};
use gnunet_service_runtime::{
    accepted::SocketEvent,
    clock::RuntimeClock,
    credentials::UnixAccess,
    framing::{Accounting, Budget, Limits as FrameLimits},
    service::{PeerAddress, ServiceOptions},
};
use gnunet_types::Error as Fault;
use std::{fmt, io, sync::Arc, time::Duration};
use tokio::time::Instant;
/// Native failure retaining its original protocol/core/OS cause.
#[derive(Debug)]
pub enum Failure {
    /// Local framing/time/resource refusal.
    Protocol(Fault),
    /// Original distributed-core refusal.
    Core(gnunet_regex_service::Error),
    /// Original socket or reactor error.
    Io(io::Error),
    /// Original failure and independent metadata cleanup error.
    Cleanup {
        /// First original error.
        original: Box<Failure>,
        /// First independent core cleanup refusal; per-source events retain others.
        cleanup: Box<Failure>,
    },
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(e) => write!(f, "REGEX host: {e}"),
            Self::Core(e) => e.fmt(f),
            Self::Io(e) => e.fmt(f),
            Self::Cleanup { original, cleanup } => {
                write!(f, "{original}; independent source cleanup: {cleanup}")
            }
        }
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(e) => Some(e),
            Self::Core(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Cleanup { original, .. } => Some(original.as_ref()),
        }
    }
}
impl From<Fault> for Failure {
    fn from(e: Fault) -> Self {
        Self::Protocol(e)
    }
}
impl From<gnunet_regex_service::Error> for Failure {
    fn from(e: gnunet_regex_service::Error) -> Self {
        Self::Core(e)
    }
}
impl From<io::Error> for Failure {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
/// Explicit physical MQ resource and original native phase bounds.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum accepted/closing MQ rows; closing rows retain original Core debts.
    pub clients: usize,
    /// Complete legal IPC frame cap, at most 65535.
    pub frame_bytes: usize,
    /// Retained output wire bytes per MQ (one original result at a time).
    pub output_bytes: usize,
    /// Maximum bytes in one actual read/write syscall poll.
    pub io_slice_bytes: usize,
    /// First request bound, fixed at actual accept/admission.
    pub first_input: Duration,
    /// Original partial request lifetime from its first positive byte.
    pub partial_input: Duration,
    /// Original result lifetime from first availability, including queue waiting.
    pub output_lifetime: Duration,
    /// Bounded number of MQ turns per poll; all rows rotate fairly.
    pub quantum: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            clients: 32,
            frame_bytes: 65535,
            output_bytes: 65535,
            io_slice_bytes: 65535,
            first_input: Duration::from_secs(15),
            partial_input: Duration::from_secs(15),
            output_lifetime: Duration::from_secs(30),
            quantum: 64,
        }
    }
}
impl Limits {
    pub(crate) fn framing(self) -> FrameLimits {
        FrameLimits {
            frame_bytes: self.frame_bytes,
            ordinary: Budget {
                frames: 1,
                bytes: self.output_bytes,
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.io_slice_bytes,
        }
    }
    pub(crate) fn validate(self) -> Result<(), Fault> {
        self.framing().validate()?;
        if self.clients == 0
            || self.clients > 1024
            || !(17..=65535).contains(&self.frame_bytes)
            || self.output_bytes < self.frame_bytes
            || self.output_bytes > 4 * 1024 * 1024
            || self.quantum == 0
            || self.quantum > 4096
        {
            return Err(Fault::Capacity);
        }
        for d in [self.first_input, self.partial_input, self.output_lifetime] {
            if d.is_zero() || Instant::now().checked_add(d).is_none() {
                return Err(Fault::Deadline);
            }
        }
        Ok(())
    }
}
/// Explicit process ports. No default successful backend or detached work exists.
pub struct Ports {
    /// Original shared canonical absolute UTC authority and exclusive subscription.
    pub clock: Arc<dyn RuntimeClock>,
    /// Actual service TCP ACL/admission policy.
    pub options: ServiceOptions,
    /// Actual kernel Unix credential policy, after filesystem listener policy.
    pub unix: UnixAccess,
}
/// Physical close cause. EOF never means a successful DHT cancellation.
#[derive(Debug)]
pub enum CloseCause {
    /// Explicit caller retirement.
    Requested,
    /// Clean EOF of the original MQ.
    Eof,
    /// Original first/partial/output native hard expired.
    Deadline,
    /// Source's original protocol/core/I/O refusal.
    Fault(Failure),
    /// Service allocation is shutting down.
    Shutdown,
    /// Core requires the original source to close.
    CoreRequested,
}
/// Truthful state of one original result at physical source retirement.
#[derive(Debug)]
pub struct OutputLoss {
    /// Original immutable Core output coordinate.
    pub output: OutputId,
    /// Original complete frame byte count.
    pub total: usize,
    /// Actual positive bytes reported before physical retirement.
    pub written: usize,
    /// Original frame was admitted to the actual MQ.
    pub queued: bool,
}
/// Synchronous committed observations. Callbacks cannot reenter the borrowed owner.
#[derive(Debug)]
pub enum Event {
    /// Original actual accept/socket initialization diagnostic.
    Socket(SocketEvent),
    /// Actual accepted stream rejected before Core attachment.
    Rejected(PeerAddress),
    /// Original source/framing admission failed; no wire response was fabricated.
    AdmissionFailed(Failure),
    /// Original physical MQ is attached to this exact Core client.
    Accepted(ClientId),
    /// Original complete input was admitted by the real distributed Core.
    Input {
        /// Actual original client.
        client: ClientId,
        /// Actual request kind, never a publication receipt.
        admission: gnunet_regex_service::Admission,
    },
    /// An unknown message was consumed under the actual TOLERANT policy. It
    /// grants no Core admission or success and does not renew first-input hard.
    Ignored(ClientId),
    /// Actual immutable result was queued and bound to the original Core output.
    Queued(OutputId),
    /// Original native positive result-frame progress.
    Write {
        /// Original output coordinate.
        output: OutputId,
        /// Actual positive bytes.
        bytes: usize,
        /// Whole original frame physically written.
        complete: bool,
    },
    /// Physical MQ retired before core disconnect/aborted bookkeeping.
    Closed {
        /// Original attached client.
        client: ClientId,
        /// Actual close cause.
        cause: CloseCause,
        /// Original retained output facts, if any.
        output: Option<OutputLoss>,
    },
    /// Actual source cleanup failed; Core retains its original debt.
    Cleanup {
        /// Original client.
        client: ClientId,
        /// Original pure bookkeeping refusal.
        error: gnunet_regex_service::Error,
    },
    /// Core released this already-closed client after actual backend/output debts.
    Released(ClientId),
}
/// Local observations. PhysicalStopped is explicitly weaker than backend drain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// At least one bounded original operation progressed.
    Activity,
    /// Only the caller's wait ended; no original deadline was renewed.
    WaitDeadline,
    /// All local MQs are closed, while original Core/backend debt may remain.
    PhysicalStopped,
    /// Every Host client was also released by Core after original debt retirement.
    Stopped,
}
/// Actual source counters; no remote acceptance/delivery or fsync is inferred.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report {
    /// Actual accepted and Core-attached MQs.
    pub accepted: u64,
    /// Sources rejected before Core attachment.
    pub rejected: u64,
    /// Actual original physical MQ closes.
    pub closed: u64,
    /// Clients released after Core's no-outstanding-debt check.
    pub released: u64,
    /// Original inputs actually admitted by Core.
    pub inputs: u64,
    /// Actual immutable output admissions to MQ/Core.
    pub queued: u64,
    /// Actual positive result bytes written.
    pub written_bytes: u64,
    /// Actual original whole result frames written.
    pub written_frames: u64,
}
