use crate::{Control, Epoch, Error, Operation, ipc};
use gnunet_service_runtime::framing::{Accounting, Budget, Limits as Framing, OwnedFrame};
use gnunet_types::Error as Fault;
use std::{fmt, io, time::Duration};

/// Finite retained resources and original source/partial-frame bounds.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Live general requests INCLUDING undelivered owned replies.
    pub operations: usize,
    /// Maximum logical outbound bytes, held or admitted, on this one source.
    pub source_bytes: usize,
    /// Maximum complete native input/output frame, at most65535.
    pub frame_bytes: usize,
    /// Positive actual read/write quantum per poll.
    pub io_slice_bytes: usize,
    /// Maximum objects in one incoming/submitted list, at most1365.
    pub list_items: usize,
    /// Original incomplete-input lifetime, fixed on its FIRST positive byte.
    pub input_lifetime: Duration,
    /// Partial canceled request's original suffix grace. First anchor is
    /// min(first cancel observation,original native hard deadline), never renewed.
    pub retirement_grace: Duration,
    /// General source replacement only; old requests never replay. Dedicated
    /// iterators force false. Default false requires explicit reconnect.
    pub reconnect: bool,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            operations: 32,
            source_bytes: 262140,
            frame_bytes: 65535,
            io_slice_bytes: 65535,
            list_items: 1365,
            input_lifetime: Duration::from_secs(5),
            retirement_grace: Duration::from_secs(5),
            reconnect: false,
        }
    }
}
impl Limits {
    pub(crate) fn validate(self) -> Result<(), Fault> {
        if self.operations == 0
            || self.source_bytes < 64
            || self.frame_bytes < 64
            || self.frame_bytes > 65535
            || self.io_slice_bytes == 0
            || self.list_items == 0
            || self.list_items > 1365
            || self.input_lifetime.is_zero()
            || self.retirement_grace.is_zero()
            || std::time::Instant::now()
                .checked_add(self.input_lifetime)
                .is_none()
            || std::time::Instant::now()
                .checked_add(self.retirement_grace)
                .is_none()
        {
            return Err(Fault::InvalidInput);
        }
        self.framing().validate()
    }
    pub(crate) fn framing(self) -> Framing {
        Framing {
            frame_bytes: self.frame_bytes,
            ordinary: Budget {
                frames: 1,
                bytes: self.frame_bytes,
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.io_slice_bytes,
        }
    }
}
/// Actual active public operations; none implies cryptographic verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// One attribute store.
    StoreAttribute,
    /// One credential store.
    StoreCredential,
    /// One attribute deletion.
    DeleteAttribute,
    /// One credential deletion.
    DeleteCredential,
    /// Ticket issuance request, not local issuance success.
    IssueTicket,
    /// Ticket revocation request.
    RevokeTicket,
    /// Ticket consumption request.
    ConsumeTicket,
    /// Dedicated attribute iteration.
    Attributes,
    /// Dedicated credential iteration.
    Credentials,
    /// Dedicated ticket iteration.
    Tickets,
}
impl Kind {
    pub(crate) fn iteration(self) -> Option<ipc::Iteration> {
        match self {
            Self::Attributes => Some(ipc::Iteration::Attributes),
            Self::Credentials => Some(ipc::Iteration::Credentials),
            Self::Tickets => Some(ipc::Iteration::Tickets),
            _ => None,
        }
    }
}
/// One actual immutable iterator control. There is no operation CANCEL frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlKind {
    /// Request exactly one additional iterator item.
    Next,
    /// Actual original iterator STOP; no acknowledgement exists.
    Stop,
}
/// Exact local exposure of one original immutable frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Submission {
    /// Zero bytes exposed.
    Unsent,
    /// A positive original prefix reached the socket.
    Partial {
        /// Actual exposed bytes.
        bytes: usize,
        /// Complete original frame length.
        total: usize,
    },
    /// All bytes wrote locally, with no service/durability inference.
    Written {
        /// Original frame length.
        bytes: usize,
    },
}
/// Local completion distinct from an actual RECLAIM response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalReason {
    /// Callback suppressed locally. Exposed service work may still happen.
    Cancelled,
    /// Original finite operation deadline.
    Deadline,
    /// Original physical source ended.
    Lost,
    /// Owner explicitly closed.
    Closed,
}
/// One actual checked reply, retained in a single zeroizing owned frame.
/// No Clone/Hash/raw Debug or unzeroized frame extraction is provided.
pub struct Reply {
    pub(crate) frame: OwnedFrame,
}
impl Reply {
    /// Borrow the exact response until this original owner drops. Raw status
    /// words, public identity and sensitive payloads remain explicit in the view.
    pub fn view(&self) -> Result<ipc::Response<'_>, Fault> {
        ipc::Response::decode(self.frame.bytes())
    }
    /// Byte length only; never payload/name/ticket bytes in diagnostics.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.frame.len()
    }
}
impl fmt::Debug for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reply")
            .field("bytes", &self.frame.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}
/// Actual response ownership or explicit local termination.
#[derive(Debug)]
pub enum Outcome {
    /// Actual original checked service reply. GNUNET_OK is1; ticket responses
    /// have no success word, and consumed-result raw defects are NOT normalized.
    Reply(Reply),
    /// No service result; a written mutating operation may have committed.
    Local {
        /// Exact local cause.
        reason: LocalReason,
        /// Original actual byte exposure.
        submission: Submission,
    },
}
/// One original terminal operation/iterator. Iterator items are separate events.
#[derive(Debug)]
pub struct Completion<'id> {
    /// Private Rust allocation token, not a reused wire RID.
    pub operation: Operation<'id>,
    /// Original attached source, if it reached admission.
    pub epoch: Option<Epoch<'id>>,
    /// Original official request ID.
    pub request_id: u32,
    /// Original operation family.
    pub kind: Kind,
    /// Actual reply or explicitly local result.
    pub outcome: Outcome,
}
/// Local callback cancellation is never a remote transaction rollback receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cancellation {
    /// Original zero-exposure frame removed.
    Unsent,
    /// Original partial suffix is retained under a finite nonrenewable drain.
    Draining,
    /// Whole original frame wrote; callback retired and late RID ignored.
    Unknown,
    /// Actual/local terminal outcome was already available.
    Completed,
}
/// Original NEXT/STOP exposure when its source stops.
#[derive(Clone, Copy, Debug)]
pub struct ControlLoss<'id> {
    /// Original immutable control token.
    pub control: Control<'id>,
    /// Original control semantics.
    pub kind: ControlKind,
    /// Exact actual exposure.
    pub submission: Submission,
}
/// Physical source was stopped before publishing these local observations.
#[derive(Clone, Copy, Debug)]
pub struct Loss<'id> {
    /// Actual original source, if attached.
    pub epoch: Option<Epoch<'id>>,
    /// Original live operation rows retired locally.
    pub operations: usize,
    /// Those with positive byte exposure.
    pub exposed: usize,
    /// Original pending iterator control, if any.
    pub control: Option<ControlLoss<'id>>,
}
/// Concrete original reason for physical source retirement.
#[derive(Debug)]
pub enum LossCause {
    /// Actual EOF.
    Eof,
    /// Actual syscall failure.
    Io(io::Error),
    /// Malformed, unexpected-family, pre-write or excess-credit response.
    Protocol(Fault),
    /// Actual bounded memory/frame refusal.
    Resource(Fault),
    /// Shared clock/Resolver/CLIENT refusal.
    Ports(Error),
    /// Explicit general-source replacement.
    Requested,
    /// Original suffix/control could not retire in its original finite budget.
    RetirementDeadline,
    /// Incomplete original RX exceeded its first-positive-byte lifetime.
    InputDeadline,
}
/// One caller-driven native observation, with no synthetic service readiness.
#[derive(Debug)]
pub enum Progress<'id> {
    /// Actual native attachment; no protocol initialization ACK exists.
    Connected(Epoch<'id>),
    /// Original frame admitted into this actual source's bounded queue.
    Queued {
        /// Original source.
        epoch: Epoch<'id>,
        /// Original private request/iterator.
        operation: Operation<'id>,
        /// Original wire RID.
        request_id: u32,
    },
    /// Whole original frame wrote LOCALLY, not a service result.
    Written {
        /// Original source.
        epoch: Epoch<'id>,
        /// Original request/iterator.
        operation: Operation<'id>,
        /// Original wire RID.
        request_id: u32,
    },
    /// One actual credit-consuming iterator item.
    Item {
        /// Actual original source.
        epoch: Epoch<'id>,
        /// Original iterator.
        operation: Operation<'id>,
        /// Actual response, with one immutable zeroizing payload owner.
        reply: Reply,
    },
    /// Original NEXT/STOP admitted locally.
    ControlQueued {
        /// Original source.
        epoch: Epoch<'id>,
        /// Original immutable control token.
        control: Control<'id>,
        /// Exact original semantics.
        kind: ControlKind,
    },
    /// Original whole NEXT/STOP locally written; not a service ACK.
    ControlWritten {
        /// Original source.
        epoch: Epoch<'id>,
        /// Original immutable control.
        control: Control<'id>,
        /// Exact semantics.
        kind: ControlKind,
    },
    /// Actual/local terminal observation.
    Completed(Completion<'id>),
    /// A bounded native syscall moved these bytes.
    Activity {
        /// Actual input bytes.
        read_bytes: usize,
        /// Actual output bytes.
        written_bytes: usize,
    },
    /// A late/unknown original RID consumed without delivery to a new owner.
    Ignored {
        /// Actual source.
        epoch: Epoch<'id>,
        /// Original response RID.
        request_id: u32,
    },
    /// Physical original source has already stopped; original local outcomes remain.
    Lost {
        /// Exact original accounting.
        report: Loss<'id>,
        /// Original cause.
        cause: LossCause,
    },
    /// Actual preattachment attempt failed.
    ConnectRetry {
        /// Original I/O error.
        error: io::Error,
        /// Shared CLIENT backoff.
        retry_after: Duration,
    },
    /// Explicit endpoint source cannot select a usable endpoint now.
    Unavailable(Error),
    /// Caller observation-only wait expired.
    WaitDeadline,
    /// Permanently closed and original terminal observations drained.
    Closed,
}
