//! Public bounded policies and original wire/local observations.
use crate::{
    Epoch, Error, Operation, WriteId,
    ipc::{Envelope, Response},
};
use gnunet_service_runtime::framing::{Accounting, Budget, Limits as FrameLimits, OwnedFrame};
use gnunet_types::Error as ProtocolError;
use std::{io, time::Duration};
/// Explicit independent native/source limits, never new protocol fields.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Fixed original logical/debt metadata slots.
    pub operations: usize,
    /// Maximum incoming/outgoing official frame size.
    pub frame_bytes: usize,
    /// Total original request/filter bytes retained outside the physical FIFO.
    pub source_bytes: usize,
    /// Retained immutable physical output records and bytes.
    pub output: Budget,
    /// Maximum bytes offered to a native syscall.
    pub io_slice_bytes: usize,
    /// Finite drain grace after original cancellation/deadline/terminal input.
    /// Failure to drain closes the original MQ before logical settlement.
    pub retirement_grace_micros: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            operations: 64,
            frame_bytes: 65535,
            source_bytes: 1024 * 1024,
            output: Budget {
                frames: 64,
                bytes: 1024 * 1024,
            },
            io_slice_bytes: 65535,
            retirement_grace_micros: 5_000_000,
        }
    }
}
impl Limits {
    pub(crate) fn framing(self) -> FrameLimits {
        FrameLimits {
            frame_bytes: self.frame_bytes,
            ordinary: self.output,
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.io_slice_bytes,
        }
    }
    pub(crate) fn validate(self) -> Result<(), ProtocolError> {
        self.framing().validate()?;
        if self.operations == 0
            || self.frame_bytes < 60
            || self.source_bytes < 48
            || self.retirement_grace_micros == 0
        {
            return Err(ProtocolError::Capacity);
        }
        self.operations
            .checked_add(1)
            .ok_or(ProtocolError::Capacity)?;
        Ok(())
    }
}
/// Original operation family. Monitors have a dedicated explicitly created MQ.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// A single record STORE with an actual result reply.
    Store,
    /// A finite snapshot-like iterator; MQ loss interrupts it.
    Iteration,
    /// A live monitor with explicit initial/live credit and SYNC.
    Monitor,
}
/// Immutable original command written on its original MQ.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    /// Original STORE/ITERATE_START/MONITOR_START.
    Start,
    /// Original bounded credit grant.
    Next {
        /// Actual clamped official grant.
        limit: u64,
    },
    /// Original ITERATE_STOP, which has no ACK.
    Stop,
}
/// Actual local exposure, never a fabricated saved/finished response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Submission {
    /// No original request byte was transferred.
    Unsent,
    /// Original request bytes may have been processed; STORE is not replayed.
    Unknown,
    /// The exact ITERATE_STOP was fully locally written, without an ACK.
    StopSubmitted,
}
/// Why original logical work ended without an authoritative wire result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reason {
    /// Explicit caller cancellation.
    Cancelled,
    /// Original absolute deadline expired.
    Deadline,
    /// Original MQ physically retired.
    Lost,
    /// Permanent local owner shutdown.
    Closed,
}
/// An actual service result or explicitly local terminal observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Original signed i32 STORE_RESULT, including failure.
    StoreResult(i32),
    /// Original signed i32 ITERATE_END.
    IterationEnd(i32),
    /// A local retirement without service success inference.
    Local {
        /// Original local reason.
        reason: Reason,
        /// Original actual exposure.
        submission: Submission,
    },
}
/// An explicit cancellation observation, distinct from service completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cancel {
    /// Original unexposed frames removed and operation retired.
    Unsent,
    /// Original immutable suffix/STOP still drains under a finite hard bound.
    Draining,
    /// Original request may have reached the service, now locally retired.
    Unknown,
    /// Monitor's original physical MQ has already been closed.
    MonitorClosed,
}
/// Actual cause of original physical retirement, not an invented service result.
#[derive(Debug)]
pub enum LossCause {
    /// Clean native EOF.
    Eof,
    /// Original read/write error.
    Io(io::Error),
    /// Original malformed/credit-invalid service input.
    Protocol(ProtocolError),
    /// Original local output allocation/admission failure.
    Resource(ProtocolError),
    /// Original canonical clock or deadline port failure.
    Clock(ProtocolError),
    /// Original shared CLIENT port error, requiring explicit recovery.
    Ports(Error),
    /// Explicit caller physical reconnect.
    Requested,
    /// Original finite retirement bound reached.
    Deadline,
    /// Permanent owner shutdown.
    Closed,
}
/// Which actual original stream stage produced a cache record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordPhase {
    /// An iterator's explicit current round.
    Iteration,
    /// Monitor enumeration before this MQ's actual SYNC.
    Initial,
    /// Live monitor notification after this MQ's actual SYNC.
    Live,
}
/// An original opaque cache record copied before logical credit is consumed.
pub struct Observation<'a> {
    pub(crate) epoch: Epoch<'a>,
    pub(crate) operation: Operation<'a>,
    pub(crate) phase: RecordPhase,
    pub(crate) frame: OwnedFrame,
}
impl<'a> Observation<'a> {
    /// Actual original physical MQ.
    #[must_use]
    pub const fn epoch(&self) -> Epoch<'a> {
        self.epoch
    }
    /// Original iterator/monitor operation.
    #[must_use]
    pub const fn operation(&self) -> Operation<'a> {
        self.operation
    }
    /// Actual original enumeration/live stage, not reconstructed cache history.
    #[must_use]
    pub const fn phase(&self) -> RecordPhase {
        self.phase
    }
    /// Exact original official RECORD bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.frame.bytes()
    }
    /// Borrow this structurally validated opaque record. No authenticity is added.
    pub fn record(&self) -> Result<Envelope<'_>, ProtocolError> {
        match Response::decode(self.frame.bytes())? {
            Response::Record(record) => Ok(record),
            _ => Err(ProtocolError::Malformed),
        }
    }
}
/// One original bounded native/protocol observation.
pub enum Progress<'a> {
    /// An actual native MQ attached; it is not peer authentication.
    Connected(Epoch<'a>),
    /// Actual record consumed one granted unit on its original operation/MQ.
    Record(Observation<'a>),
    /// Actual initial monitor enumeration reached SYNC; live records may follow.
    Sync {
        /// Original physical monitor MQ.
        epoch: Epoch<'a>,
        /// Original monitor intent.
        operation: Operation<'a>,
    },
    /// One actual wire result or explicitly local terminal observation.
    Completed {
        /// Original MQ, absent for never-attached work.
        epoch: Option<Epoch<'a>>,
        /// Original operation.
        operation: Operation<'a>,
        /// Original family.
        kind: Kind,
        /// Exact actual/local outcome.
        outcome: Outcome,
    },
    /// A whole original frame was actually locally written.
    Written {
        /// Original physical MQ.
        epoch: Epoch<'a>,
        /// Original operation, possibly already canceled.
        operation: Operation<'a>,
        /// Original immutable write identity.
        write: WriteId<'a>,
        /// Exact original command.
        command: Command,
    },
    /// Original physical IO bytes, with no service outcome assertion.
    Activity {
        /// Original MQ.
        epoch: Epoch<'a>,
        /// Actual received bytes.
        read_bytes: usize,
        /// Actual locally written bytes.
        written_bytes: usize,
    },
    /// Original MQ closed before logical retirement or safe monitor restoration.
    Lost {
        /// Actual retired MQ, if one attached.
        epoch: Option<Epoch<'a>>,
        /// Actual original cause.
        cause: LossCause,
        /// Monitor intent retained for fresh initial-credit/SYNC on a new MQ.
        monitor_retained: bool,
    },
    /// Original failed connection attempt and its source-selected retry delay.
    ConnectRetry {
        /// Actual native cause.
        error: io::Error,
        /// Source-selected delay.
        retry_after: Duration,
    },
    /// Original endpoint selection failure; no STORE success is inferred.
    Unavailable(Error),
    /// Exact complete RX retained while fallible observation allocation is refused.
    Capacity(Epoch<'a>),
    /// Well-framed unknown/late/canceled response ignored on its original MQ.
    Ignored(Epoch<'a>),
    /// Caller wait ended; original operation deadlines are independent.
    WaitDeadline,
    /// Permanently closed after retained original completion observations drain.
    Closed,
}
