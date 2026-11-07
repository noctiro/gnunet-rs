use crate::{Control, Epoch, Error, Operation, ipc};
use gnunet_service_runtime::framing::{Accounting, Budget, Limits as Framing, OwnedFrame};
use gnunet_types::Error as Fault;
use std::{fmt, io, time::Duration};
/// Explicit retained resources, response policy and finite native drain.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Live general operations including undelivered results.
    pub operations: usize,
    /// All immutable logical/physical outbound bytes.
    pub source_bytes: usize,
    /// Native maximum complete frame.
    pub frame_bytes: usize,
    /// Actual syscall quantum, nonzero.
    pub io_slice_bytes: usize,
    /// Maximum record sets in one STORE frame.
    pub record_sets: usize,
    /// Maximum records in one returned/individual submitted set.
    pub records: usize,
    /// Maximum label bytes excluding NUL (official public bound255).
    pub label_bytes: usize,
    /// Maximum advisory hint bytes excluding NUL.
    pub hint_bytes: usize,
    /// Maximum outstanding stream record credit including a pending NEXT.
    pub credit: u64,
    /// First partial suffix retirement grace, never renewed by late polling.
    pub retirement_grace: Duration,
    /// General source replacement only; no old request replay. Streams never replay.
    pub reconnect: bool,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            operations: 32,
            source_bytes: 256 * 1024,
            frame_bytes: 65535,
            io_slice_bytes: 65535,
            record_sets: 512,
            records: 4096,
            label_bytes: 255,
            hint_bytes: 4096,
            credit: 256,
            retirement_grace: Duration::from_secs(5),
            reconnect: true,
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
            || self.record_sets == 0
            || self.records == 0
            || self.label_bytes > 255
            || self.hint_bytes > 65534
            || self.credit == 0
            || self.retirement_grace.is_zero()
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
/// Original active official operation; there is no standalone TX_CONTROL RPC.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// One atomic-or-sequential STORE frame of complete sets.
    Store,
    /// Label lookup.
    Lookup,
    /// Reverse zone delegation lookup.
    ZoneToName,
    /// Set/replace editor hint, returns records and previous hint.
    EditBegin,
    /// Conditional hint replacement; distinct from local callback cancel.
    EditCancel,
    /// Dedicated zone iterator.
    Iterator,
    /// Dedicated zone monitor.
    Monitor,
}
/// One real stream control frame. Credit is added only after whole native write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlKind {
    /// Request the next bounded number of record sets.
    Next {
        /// Exact official u64 grant.
        limit: u64,
    },
    /// Actual iterator STOP (no server acknowledgement).
    Stop,
}
/// Original actual byte exposure; a full write is not a database result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Submission {
    /// No byte exposed.
    Unsent,
    /// An immutable original prefix was written.
    Partial {
        /// Actual prefix bytes.
        bytes: usize,
        /// Original frame length.
        total: usize,
    },
    /// The entire original frame wrote locally.
    Written {
        /// Exact original frame length.
        bytes: usize,
    },
}
/// Original local termination without pretending to receive a normal response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalReason {
    /// Callback locally suppressed; advisory lock is unaffected.
    Cancelled,
    /// Original finite operation/stream deadline.
    Deadline,
    /// Physical original source ended.
    Lost,
    /// Owner explicitly closed.
    Closed,
}
/// One exact actual service response in zeroizing owned storage. It never
/// implements ordinary Clone, serialization, or raw-byte Debug. The typed view
/// explicitly borrows opaque zone key and record data until the owner drops.
pub struct Reply {
    pub(crate) frame: OwnedFrame,
}
impl Reply {
    /// Borrow the checked official response, including opaque key views.
    pub fn view(&self) -> Result<ipc::Response<'_>, Fault> {
        ipc::Response::decode(self.frame.bytes())
    }
    /// Diagnostic length only, no private key/name/record/hint bytes.
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
/// Actual original reply or explicitly local result.
#[derive(Debug)]
pub enum Outcome {
    /// Actual checked original response. Inspect its raw official code/found value;
    /// code0 does not independently prove fsync, monitor consumption or publication.
    Reply(Reply),
    /// No business response; exposed writes/locks may have committed.
    Local {
        /// Exact local cause.
        reason: LocalReason,
        /// Original actual exposure.
        submission: Submission,
    },
}
/// One original terminal general request or stream.
#[derive(Debug)]
pub struct Completion<'id> {
    /// Exact original Rust token, not a wire RID.
    pub operation: Operation<'id>,
    /// Original actual source, if attached.
    pub epoch: Option<Epoch<'id>>,
    /// Original official RID (monitor uses no RID).
    pub request_id: Option<u32>,
    /// Original kind.
    pub kind: Kind,
    /// Actual/local outcome with opaque sensitive ownership.
    pub outcome: Outcome,
}
/// Callback cancellation state, never a database/advisory-lock rollback receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cancellation {
    /// Wholly unwritten original removed.
    Unsent,
    /// Original partial frame remains under finite source drain.
    Draining,
    /// Entire original wrote and is retired locally; late RID ignored.
    Unknown,
    /// Terminal response already available.
    Completed,
}
/// Original control exposure preserved when a source stops.
#[derive(Clone, Copy, Debug)]
pub struct ControlLoss<'id> {
    /// Exact original control token.
    pub control: Control<'id>,
    /// Original control semantics.
    pub kind: ControlKind,
    /// Actual original exposure, no ACK inference.
    pub submission: Submission,
}
/// Native source stopped before these local results were published.
#[derive(Clone, Copy, Debug)]
pub struct Loss<'id> {
    /// Exact original source if attached.
    pub epoch: Option<Epoch<'id>>,
    /// Pending request/stream rows retired locally.
    pub operations: usize,
    /// Those with actual positive byte exposure.
    pub exposed: usize,
    /// Original partial/unwritten NEXT or STOP, if any.
    pub control: Option<ControlLoss<'id>>,
}
/// Original cause before physical source retirement; no private data in diagnostics.
#[derive(Debug)]
pub enum LossCause {
    /// Actual clean EOF.
    Eof,
    /// Actual I/O error.
    Io(io::Error),
    /// Malformed/unexpected response, credit violation or wrong zone/source.
    Protocol(Fault),
    /// Actual finite memory/frame/resource refusal.
    Resource(Fault),
    /// Canonical source clock/Resolver/CLIENT refusal.
    Ports(Error),
    /// Caller explicitly requested a new general source.
    Requested,
    /// An original partial/control could not retire in its first finite budget.
    RetirementDeadline,
}
/// One source/operation/control/stream observation with sensitive data redacted.
#[derive(Debug)]
pub enum Progress<'id> {
    /// Actual native attachment, no private Init/readiness.
    Connected(Epoch<'id>),
    /// Immutable original actually queued locally.
    Queued {
        /// Original source.
        epoch: Epoch<'id>,
        /// Original request/stream.
        operation: Operation<'id>,
        /// Original official RID if present.
        request_id: Option<u32>,
    },
    /// Whole original local write, not database success.
    Written {
        /// Original source.
        epoch: Epoch<'id>,
        /// Original request/stream.
        operation: Operation<'id>,
        /// Original official RID if present.
        request_id: Option<u32>,
    },
    /// One actual credit-consuming record set.
    Record {
        /// Exact original source.
        epoch: Epoch<'id>,
        /// Original iterator/monitor.
        operation: Operation<'id>,
        /// Opaque checked returned key/label/records/expiration.
        reply: Reply,
    },
    /// Actual MONITOR_SYNC, not a record and consumes no credit.
    Synchronized {
        /// Actual source.
        epoch: Epoch<'id>,
        /// Original monitor.
        operation: Operation<'id>,
    },
    /// Actual original immutable NEXT/STOP queued.
    ControlQueued {
        /// Actual source.
        epoch: Epoch<'id>,
        /// Exact private control token.
        control: Control<'id>,
        /// Actual control semantics.
        kind: ControlKind,
    },
    /// Whole original NEXT/STOP locally written; not a server ACK.
    ControlWritten {
        /// Actual source.
        epoch: Epoch<'id>,
        /// Exact original control.
        control: Control<'id>,
        /// Exact control semantics.
        kind: ControlKind,
    },
    /// Actual/local terminal outcome.
    Completed(Completion<'id>),
    /// Concrete native bytes moved.
    Activity {
        /// Actual read bytes.
        read_bytes: usize,
        /// Actual write bytes.
        written_bytes: usize,
    },
    /// Unknown/locally canceled RID consumed on this source.
    Ignored {
        /// Actual original source.
        epoch: Epoch<'id>,
        /// Original response RID.
        request_id: u32,
    },
    /// Original physical source already stopped.
    Lost {
        /// Original cause/exposure accounting.
        report: Loss<'id>,
        /// Known preceding cause.
        cause: LossCause,
    },
    /// Actual pre-attachment syscall failed.
    ConnectRetry {
        /// Original actual error.
        error: io::Error,
        /// Source's retry delay.
        retry_after: Duration,
    },
    /// Endpoint selection currently unavailable.
    Unavailable(Error),
    /// Caller-only observation deadline.
    WaitDeadline,
    /// Permanent source close and terminal observations drained.
    Closed,
}
/// Explicit count of complete record sets admitted by one bulk STORE frame.
#[derive(Clone, Copy, Debug)]
pub struct Stored<'id> {
    /// Original STORE request.
    pub operation: Operation<'id>,
    /// Exact complete prefix in this frame; caller handles remainder.
    pub sets_sent: u16,
}
