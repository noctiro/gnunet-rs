//! Explicit actual native limits, failures and local observations.
use super::*;
/// Original native/dependency cause, retained independently of pure completion.
#[derive(Debug)]
pub enum Error {
    /// Original native socket failure.
    Io(io::Error),
    /// Original resource/protocol/clock classification.
    Protocol(Fault),
    /// Original CADET CLIENT cause.
    Cadet(cadet::Error),
    /// Original native randomness provider failure.
    Entropy(getrandom::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => e.fmt(out),
            Self::Protocol(e) => e.fmt(out),
            Self::Cadet(e) => e.fmt(out),
            Self::Entropy(e) => e.fmt(out),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Cadet(e) => Some(e),
            Self::Entropy(_) => None,
        }
    }
}
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<Fault> for Error {
    fn from(error: Fault) -> Self {
        Self::Protocol(error)
    }
}
impl From<cadet::Error> for Error {
    fn from(error: cadet::Error) -> Self {
        Self::Cadet(error)
    }
}
/// Explicit independent original source/queue bounds, not algorithm claims.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Simultaneously owned original IPC clients.
    pub clients: usize,
    /// Simultaneously retained actual CADET application port bindings.
    pub ports: usize,
    /// Actual incoming/outgoing CADET channel generations.
    pub channels: usize,
    /// Complete app frame extent,4..65535.
    pub frame_bytes: usize,
    /// Maximum bytes in one actual app syscall.
    pub io_slice_bytes: usize,
    /// Actual queued response frames per original IPC source.
    pub output_frames: usize,
    /// Actual retained response bytes per source.
    pub output_bytes: usize,
    /// Original admitted peer payloads waiting for actual send credit.
    pub peer_frames: usize,
    /// Actual allocated bytes of those waiting payloads together.
    pub peer_bytes: usize,
    /// Original first client-input lifetime.
    pub first_input: Duration,
    /// Original partial client/CADET-input lifetime, not renewed by progress.
    pub partial_input: Duration,
    /// Original immutable control/payload/retirement write lifetime.
    pub retirement_grace: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            clients: 64,
            ports: 64,
            channels: 256,
            frame_bytes: 65535,
            io_slice_bytes: 65535,
            output_frames: 4,
            output_bytes: 262140,
            peer_frames: 1024,
            peer_bytes: 8 * 1024 * 1024,
            first_input: Duration::from_secs(30),
            partial_input: Duration::from_secs(15),
            retirement_grace: Duration::from_secs(5),
        }
    }
}
impl Limits {
    /// Check the finite native IO profile before opening any source.
    pub fn validate(self) -> Result<(), Error> {
        if self.clients == 0
            || self.ports == 0
            || self.channels == 0
            || self.clients > 65536
            || self.ports > 65536
            || self.channels > 1048576
            || !(4..=65535).contains(&self.frame_bytes)
            || self.io_slice_bytes == 0
            || self.output_frames == 0
            || self.output_bytes < self.frame_bytes
            || self.peer_frames == 0
            || self.peer_bytes < 4
        {
            return Err(Fault::InvalidInput.into());
        }
        for duration in [self.first_input, self.partial_input, self.retirement_grace] {
            if duration.is_zero() || Instant::now().checked_add(duration).is_none() {
                return Err(Fault::Deadline.into());
            }
        }
        Ok(())
    }
}
/// Actual original IPC-source retirement, without fabricated protocol status.
#[derive(Debug)]
pub enum CloseCause {
    /// Native clean EOF.
    Eof,
    /// Original IO/protocol/dependency refusal.
    Fault(Error),
    /// Explicit service shutdown.
    Shutdown,
    /// Original fixed phase bound expired.
    Deadline,
}
/// Actual local reason for detaching a shared CADET MQ. Numeric channel/port
/// values are diagnostics only and grant no native or peer authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetirementTrigger {
    /// An original pending frame belongs to a locally closing owner.
    CancelledPending,
    /// Original partial/blocked CADET input target expired.
    ReadHard,
    /// Original pending native/control output target expired.
    PendingHard,
    /// Original port retirement target expired.
    ClosingPortHard {
        /// Original logical port allocation generation.
        port: u64,
    },
    /// Original channel retirement target expired.
    ChannelHard {
        /// Original host channel allocation generation.
        channel: u64,
        /// Original channel number on this MQ.
        wire: u32,
    },
    /// A real incoming channel exceeded the configured host slots.
    IncomingCapacity {
        /// Actual refused incoming channel allocation generation.
        channel: u64,
        /// Actual refused incoming channel number on this MQ.
        wire: u32,
    },
    /// A real incoming channel did not match an original bound host port.
    IncomingPortMismatch {
        /// Actual refused incoming channel allocation generation.
        channel: u64,
        /// Actual refused incoming channel number on this MQ.
        wire: u32,
    },
}
/// Fixed inline snapshot captured before the actual forced detach. It retains
/// original error provenance independently of CLIENT's Requested loss cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForcedRetirement {
    /// Same actual Fault used to retire the original SET peer owners.
    pub reason: Fault,
    /// First actual local predicate that forced this detach.
    pub trigger: RetirementTrigger,
    /// Original host/native pending frame diagnostic ID and kind, if any.
    pub pending: Option<(u64, cadet::TransmitKind)>,
    /// Already observed native terminal awaiting logical settlement, if any.
    pub pending_terminal: Option<Completion>,
    /// Actual original channel peer, copied only from a matching host row.
    pub peer: Option<[u8; 32]>,
    /// Actual host channel rows retained before physical detach.
    pub channels: usize,
    /// Actual immutable peer sends retained before physical detach.
    pub queued_sends: usize,
}
/// Original final FAILURE cause paired with the response's actual local
/// terminal disposition. Unsent or Lost does not claim a whole response write;
/// even Written grants no remote delivery or peer-completion authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FailedOperation {
    /// Read-only original final response and engine failure provenance.
    pub failure: gnunet_set::OperationFailure,
    /// Actual terminal disposition returned by the original effect owner.
    pub completion: Completion,
}
/// Actual synchronous observations; local Written never proves a peer online.
#[derive(Debug)]
pub enum Event<'id> {
    /// Shared socket diagnostic.
    Socket(SocketEvent),
    /// Actual accepted source refused by configured ACL/credentials.
    Rejected(PeerAddress),
    /// Actual source could not be admitted.
    AdmissionFailed(Error),
    /// Original IPC source attached to the pure service.
    Accepted(Client<'id>),
    /// Original complete request was accepted.
    Input(Client<'id>),
    /// Original immutable response admitted to its actual bounded IPC queue.
    Queued {
        /// Original client generation.
        client: Client<'id>,
        /// Original retained effect, not a wire RID.
        effect: EffectId<'id>,
    },
    /// Actual positive bytes on the original IPC source.
    Write {
        /// Original client generation.
        client: Client<'id>,
        /// Original immutable effect token.
        effect: EffectId<'id>,
        /// Actual positive bytes.
        bytes: usize,
        /// Actual whole original frame written.
        complete: bool,
    },
    /// Original source physically closed before pure retirement.
    Closed {
        /// Original client generation.
        client: Client<'id>,
        /// Original cause retained without replacing it by cleanup state.
        cause: CloseCause,
    },
    /// Actual original CADET source physically detached.
    CadetLost {
        /// Exact original epoch and partial exposure report.
        report: cadet::Loss<'id>,
        /// Original loss cause.
        cause: cadet::LossCause,
        /// Actual local forced-detach provenance, absent on ordinary shutdown.
        forced: Option<ForcedRetirement>,
    },
    /// Actual endpoint attempt refusal and original retry policy.
    CadetRetry {
        /// Original native cause.
        error: io::Error,
        /// Original CLIENT-selected retry delay.
        retry_after: Duration,
    },
    /// Original owned action plus its actual local terminal disposition.
    EffectTerminal(Terminal<'id>),
    /// Original final FAILURE response actually reached its local terminal
    /// boundary. Its disposition is independent of its original engine cause.
    OperationFailed(FailedOperation),
    /// Actual peer message/source refusal; no private wire error is emitted.
    PeerRefused {
        /// Original listener, absent after an actual accepted-channel adoption.
        listener: Option<Client<'id>>,
        /// Original peer owner, absent before its first operation request.
        owner: Option<PeerOwner<'id>>,
        /// Actual channel-provided sender.
        peer: [u8; 32],
        /// Original checked refusal.
        error: Fault,
    },
}
/// One bounded caller-driven reactor result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// Actual local IO/algorithm/control progress.
    Activity,
    /// Only the caller observation deadline elapsed.
    WaitDeadline,
    /// Physical resources and all original effects actually retired.
    Stopped,
}
/// Local cumulative facts; no field proves remote storage or reachability.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report {
    /// Actual IPC sources attached.
    pub accepted: u64,
    /// Actual IPC sources physically closed.
    pub closed: u64,
    /// Actual complete client requests accepted.
    pub inputs: u64,
    /// Positive bytes written on original IPC sources.
    pub written_bytes: u64,
    /// Whole original IPC responses written.
    pub written_frames: u64,
    /// Whole original peer payload IPC frames written.
    pub peer_frames: u64,
    /// Whole original receive_done IPC frames written.
    pub receive_done: u64,
    /// Actual original CADET sources detached.
    pub cadet_losses: u64,
}
/// Synchronous actual retirement facts, retaining a refused cleanup cause.
#[must_use]
pub struct Shutdown {
    /// Actual local counters.
    pub report: Report,
    /// First original independent cleanup error; remaining owners stay retained.
    pub failure: Option<Error>,
    /// True only after physical closure and pure original debt quiescence.
    pub drained: bool,
}
