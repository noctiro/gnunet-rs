//! Original public progress/failures and finite internal source/job metadata.
use crate::clock::Span;
use gnunet_messenger_client_host as native;
use gnunet_messenger_core::{self as domain, Binding, MemberSession, Operation, Room, Source};
use gnunet_types::Error as Fault;
use std::fmt;
/// Actual failure classification. The owned native error is never replaced by
/// an invented successful callback or an unrelated later cleanup failure.
pub enum Error {
    /// Actual original native endpoint/socket/framing refusal.
    Native(native::Error),
    /// Actual retained room/member/message/crypto refusal.
    Domain(domain::Error),
    /// Actual canonical clock/source port refusal.
    Clock(Fault),
    /// Actual bounded high-level admission/ownership refusal.
    Local(Fault),
}
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native(e) => f.debug_tuple("Native").field(e).finish(),
            Self::Domain(e) => f.debug_tuple("Domain").field(e).finish(),
            Self::Clock(e) => f.debug_tuple("Clock").field(e).finish(),
            Self::Local(e) => f.debug_tuple("Local").field(e).finish(),
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Messenger API: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<native::Error> for Error {
    fn from(e: native::Error) -> Self {
        Self::Native(e)
    }
}
impl From<domain::Error> for Error {
    fn from(e: domain::Error) -> Self {
        Self::Domain(e)
    }
}
impl From<domain::crypto::Error> for Error {
    fn from(e: domain::crypto::Error) -> Self {
        Self::Domain(e.into())
    }
}
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self::Local(e)
    }
}
/// Actual native exposure of one original high-level job. Only the local-write
/// fact is represented; no remote delivery or business ACK exists for SEND.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Exposure {
    /// No immutable frame was admitted to native IO for this original job.
    NotSubmitted,
    /// Its immutable frame is admitted, with zero actual written bytes.
    Unsent,
    /// Positive original native prefix.
    Partial {
        /// Actual exposed original prefix length.
        bytes: usize,
        /// Complete original immutable frame length.
        total: usize,
    },
    /// The complete original local frame wrote; remote processing is unknown.
    Written {
        /// Complete locally written frame length.
        bytes: usize,
    },
}
/// Actual reason the higher owner physically stopped its original MQ. Native
/// causes/prefixes remain in Loss::native; cleanup observations stay separate.
#[derive(Clone, Copy, Debug)]
pub enum StopCause<'id> {
    /// Read the actual original low-level native loss cause.
    Native,
    /// Original native hard/logical high-level job lifetime elapsed.
    Deadline(Operation<'id>),
    /// Original room initialization/retained-notification lifetime elapsed.
    Initialization,
    /// Actual caller cancellation of this original high-level job.
    Cancelled(Operation<'id>),
    /// Explicit permanent close, with no canonical clock access.
    Closed,
    /// Actual original clock port failure.
    Clock(Fault),
    /// Actual original domain or crypto failure requiring source retirement.
    Domain(domain::Error),
    /// Actual original high-level ownership/resource failure.
    Local(Fault),
}
/// Borrowed exact original job fact after physical source loss.
pub struct JobReport<'r, 'id> {
    pub(crate) lease: &'r Lease<'id>,
}
impl<'r, 'id> JobReport<'r, 'id> {
    /// Original immutable high-level operation generation.
    pub const fn operation(&self) -> Operation<'id> {
        self.lease.operation
    }
    /// Original room generation.
    pub const fn room(&self) -> Room<'id> {
        self.lease.room
    }
    /// Original physical room-source generation.
    pub const fn source(&self) -> Source<'id> {
        self.lease.source
    }
    /// Sealed original work binding once the domain actually supplied it.
    pub const fn binding(&self) -> Option<Binding<'id>> {
        self.lease.binding
    }
    /// Original native operation, never rebound to a later epoch.
    pub const fn native_operation(&self) -> Option<native::Operation<'id>> {
        self.lease.native
    }
    /// Exact original admitted/written exposure observation.
    pub const fn exposure(&self) -> Exposure {
        self.lease.exposure
    }
}
impl fmt::Debug for JobReport<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JobReport")
            .field("operation", &self.lease.operation)
            .field("exposure", &self.lease.exposure)
            .finish_non_exhaustive()
    }
}
/// Actual original CREATE/DESTROY control exposure at physical source stop.
#[derive(Clone, Copy, Debug)]
pub struct ControlReport<'a> {
    pub(crate) operation: native::Operation<'a>,
    pub(crate) epoch: native::Epoch<'a>,
    pub(crate) kind: native::Kind,
    pub(crate) exposure: Exposure,
}
impl<'a> ControlReport<'a> {
    /// Original actual operation.
    pub const fn operation(&self) -> native::Operation<'a> {
        self.operation
    }
    /// Original actual source epoch.
    pub const fn epoch(&self) -> native::Epoch<'a> {
        self.epoch
    }
    /// Exact control family.
    pub const fn kind(&self) -> native::Kind {
        self.kind
    }
    /// Real local prefix/whole-write only, never a service acknowledgement.
    pub const fn exposure(&self) -> Exposure {
        self.exposure
    }
}
/// Original native loss plus original high-level ownership and independent
/// cleanup/state observations. Physical stop precedes construction of this value.
pub struct Loss<'id> {
    pub(crate) layout: Option<crate::LayoutNeed<'id>>,
    pub(crate) control: Option<ControlReport<'id>>,
    pub(crate) records: Option<crate::RecordLoss<'id>>,
    pub(crate) original: native::Loss<'id>,
    pub(crate) cause: StopCause<'id>,
    // Exact stopped internally admitted established-subscription effect only.
    pub(crate) subscription_deadline: bool,
    pub(crate) jobs: Vec<Lease<'id>>,
    pub(crate) observations: Vec<domain::Event<'id>>,
    pub(crate) cleanup: Vec<(Room<'id>, domain::Error)>,
    pub(crate) failure: Option<Error>,
}
/// Consumed physically stopped source. Original instance-branded tickets stay
/// in the caller's live scope; actual owned errors can be retained separately.
/// None of these diagnostic facts grants quiescence, authentication or replay.
pub struct LossParts<'id> {
    /// Original native source retirement and each original pending prefix.
    pub native: native::Loss<'id>,
    /// Actual high-level physical-stop reason.
    pub cause: StopCause<'id>,
    /// Original CREATE/DESTROY local exposure, without a remote ACK.
    pub control: Option<ControlReport<'id>>,
    /// Independent physically stopped record owners and pending bindings.
    pub records: Option<crate::RecordLoss<'id>>,
    /// Original domain observations retained during physical stop.
    pub observations: Vec<domain::Event<'id>>,
    /// Independent original domain cleanup failures.
    pub cleanup: Vec<(Room<'id>, domain::Error)>,
    /// Actual first higher API error, with its original owned native cause.
    pub failure: Option<Error>,
}
impl<'id> Loss<'id> {
    /// Consume the stopped owner without replacing owned native errors with
    /// formatted text. Inspect jobs() first if their domain/exposure metadata is
    /// required; all their physical source work has already retired here.
    pub fn into_parts(self) -> LossParts<'id> {
        LossParts {
            native: self.original,
            cause: self.cause,
            control: self.control,
            records: self.records,
            observations: self.observations,
            cleanup: self.cleanup,
            failure: self.failure,
        }
    }
    /// First actual higher owner error, independently of physical native close.
    pub fn primary_error(&self) -> Option<&Error> {
        self.failure.as_ref()
    }
    /// Original input whose layout was still unresolved at physical source stop.
    pub const fn layout_need(&self) -> Option<&crate::LayoutNeed<'id>> {
        self.layout.as_ref()
    }
    /// Actual original CREATE/DESTROY exposure, including a graceful whole local
    /// DESTROY write before physical close. No wire ACK exists.
    pub const fn control(&self) -> Option<&ControlReport<'id>> {
        self.control.as_ref()
    }
    /// Actual independently stopped NAMESTORE sources and original record jobs.
    pub const fn records(&self) -> Option<&crate::RecordLoss<'id>> {
        self.records.as_ref()
    }
    /// Actual original low-level cause and every retained native partial prefix.
    pub const fn native(&self) -> &native::Loss<'id> {
        &self.original
    }
    /// Actual higher source-stop cause, independent of native transport cause.
    pub const fn cause(&self) -> StopCause<'id> {
        self.cause
    }
    /// Original high-level jobs, including whole-written jobs absent from the
    /// low-level pending native queue while waiting for asynchronous responses.
    pub fn jobs(&self) -> impl Iterator<Item = JobReport<'_, 'id>> {
        self.jobs.iter().map(|lease| JobReport { lease })
    }
    /// Actual state observations retained while physical-stop cleanup freed the
    /// domain event queue; no observation is silently rewritten as success.
    pub fn observations(&self) -> &[domain::Event<'id>] {
        &self.observations
    }
    /// Independent original domain cleanup failures; none replaces first cause.
    pub fn cleanup_errors(&self) -> &[(Room<'id>, domain::Error)] {
        &self.cleanup
    }
}
impl fmt::Debug for Loss<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessengerLoss")
            .field("native", &self.original)
            .field("cause", &self.cause)
            .field("jobs", &self.jobs.len())
            .field("cleanup_failures", &self.cleanup.len())
            .finish_non_exhaustive()
    }
}
/// Original private message and optional separately encrypted sender transcript.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateSend<'id> {
    pub(crate) message: Operation<'id>,
    pub(crate) transcript: Option<Operation<'id>>,
}
impl<'id> PrivateSend<'id> {
    /// Original actual recipient PRIVATE job.
    pub const fn message(&self) -> Operation<'id> {
        self.message
    }
    /// Separate original sender transcript, absent only for a self recipient.
    pub const fn transcript(&self) -> Option<Operation<'id>> {
        self.transcript
    }
}
/// One admitted high-level close sequence. Its LEAVE operation is distinct
/// from actual room closure; only Progress::RoomClosed confirms the latter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Closing<'id> {
    pub(crate) room: Room<'id>,
    pub(crate) leave: Operation<'id>,
}
impl<'id> Closing<'id> {
    /// Original room generation whose close was requested.
    pub const fn room(&self) -> Room<'id> {
        self.room
    }
    /// Original signed LEAVE job, whose actual local whole-write permits CLOSE.
    pub const fn leave_operation(&self) -> Operation<'id> {
        self.leave
    }
}
/// One actual caller-driven progress observation. Dropping a wait future keeps
/// the original frame/notification/lease owned; it does not cancel native work.
pub enum Progress<'id> {
    /// Exact original input awaits caller-selected grammar facts. It has no
    /// invented wire ACK and retains its original finite deadline/physical MQ.
    LayoutNeeded(crate::LayoutNeed<'id>),
    /// Actual native attachment; no CREATE ACK is implied.
    Attached(native::Epoch<'id>),
    /// Actual local whole CREATE write permits room requests on this epoch.
    Ready(native::Epoch<'id>),
    /// Actual original immutable native frame entered its source queue.
    Queued {
        /// Original actual epoch.
        epoch: native::Epoch<'id>,
        /// Exact original native frame token.
        native: native::Operation<'id>,
        /// Original domain binding, absent for CREATE/DESTROY.
        binding: Option<Binding<'id>>,
        /// Exact official frame family.
        kind: native::Kind,
    },
    /// Actual original whole local write, without a fabricated service ACK.
    Written {
        /// Original actual epoch.
        epoch: native::Epoch<'id>,
        /// Exact original native frame token.
        native: native::Operation<'id>,
        /// Original domain work binding.
        binding: Option<Binding<'id>>,
        /// Actual official frame family.
        kind: native::Kind,
        /// Complete actual local-write length.
        bytes: usize,
    },
    /// One actual original native byte step.
    Activity {
        /// Actual positive bytes read.
        read_bytes: usize,
        /// Actual positive bytes written.
        written_bytes: usize,
    },
    /// Actual domain state transition, after its real input/provider result.
    State(domain::Event<'id>),
    /// Actual matching CLOSE notification and room-lease retirement, after
    /// original room-specific debts settled. The shared MQ remains alive.
    RoomClosed {
        /// Original admitted LEAVE/close sequence.
        closing: Closing<'id>,
        /// Original actual CLOSE operation.
        close_operation: Operation<'id>,
    },
    /// Actual independent NAMESTORE result/monitor observation.
    Records(crate::RecordProgress<'id>),
    /// Physical source stop, original facts and independent cleanup observations.
    Lost(Loss<'id>),
}
impl fmt::Debug for Progress<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LayoutNeeded(_) => "MessengerLayoutNeeded([REDACTED])",
            Self::Attached(_) => "MessengerAttached",
            Self::Ready(_) => "MessengerReady",
            Self::Queued { .. } => "MessengerQueued",
            Self::Written { .. } => "MessengerWritten",
            Self::Activity { .. } => "MessengerActivity",
            Self::State(_) => "MessengerState([REDACTED])",
            Self::RoomClosed { .. } => "MessengerRoomClosed",
            Self::Records(_) => "MessengerRecords([REDACTED])",
            Self::Lost(_) => "MessengerLost",
        })
    }
}
pub(crate) enum Intent {
    User,
    Initialization,
    Epoch,
    Subscription,
    LeaveClose,
    Transcript,
    Membership,
}
pub(crate) struct Lease<'id> {
    pub layout: Option<domain::ClientLayout>,
    pub operation: Operation<'id>,
    pub room: Room<'id>,
    pub source: Source<'id>,
    pub epoch: native::Epoch<'id>,
    pub span: Span,
    pub binding: Option<Binding<'id>>,
    pub native: Option<native::Operation<'id>>,
    pub native_serial: Option<u64>,
    pub kind: Option<native::Kind>,
    pub queued: bool,
    pub exposure: Exposure,
    pub intent: Intent,
    pub frame_len: usize,
    pub serial: u64,
}
pub(crate) struct Join {
    pub span: Span,
    pub recipient: Option<domain::crypto::EcdheSecret>,
    pub id: domain::ShortHash,
}
pub(crate) struct LiveRoom<'id> {
    pub room: Room<'id>,
    pub key: domain::Hash,
    pub source: Option<Source<'id>>,
    pub epoch: Option<native::Epoch<'id>>,
    pub signer: crate::Identity,
    pub join: Option<Join>,
    pub auto_epoch: bool,
    pub close_after: Option<Operation<'id>>,
    pub close_child: Option<Operation<'id>>,
    pub closing_span: Option<Span>,
    pub member: Option<MemberSession<'id>>,
    pub recipient_public: Option<domain::PublicKey>,
    pub pending_identity: Option<crate::Identity>,
    pub replacement_key: Option<domain::crypto::EcdheSecret>,
    pub identity_operation: Option<Operation<'id>>,
}
pub(crate) struct HeldNotification<'id> {
    pub serial: u64,
    pub layout: Option<domain::ClientLayout>,
    pub need: Option<crate::LayoutNeed<'id>>,
    pub need_reported: bool,
    pub epoch: native::Epoch<'id>,
    pub notification: native::Notification,
    pub span: Span,
    pub job_span: Span,
    pub applied: bool,
}
