use crate::{Epoch, Error, Operation, Profile, ipc};
use gnunet_service_runtime::framing::{Accounting, Budget, Limits as Framing, OwnedFrame};
use gnunet_types::Error as Fault;
use std::{fmt, time::Duration};
/// Bounded retained queue, individual frame, initial source and partial input.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Original service producer order for its native member-reset IPC field.
    pub profile: Profile,
    /// Outstanding frames including their exact partial-write metadata.
    pub operations: usize,
    /// Actual allocated outbound payload capacity, outside one fixed RX buffer.
    pub source_bytes: usize,
    /// Largest complete IPC frame, at most65535.
    pub frame_bytes: usize,
    /// Actual per-poll read/write byte quantum.
    pub io_slice_bytes: usize,
    /// Fixed initial connection+CREATE lifetime; explicit reconnect starts anew.
    pub initial_lifetime: Duration,
    /// Partial RX lifetime from its first positive byte, never a moving idle timer.
    pub input_lifetime: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            profile: Profile::NATIVE_255,
            operations: 32,
            source_bytes: 262140,
            frame_bytes: 65535,
            io_slice_bytes: 65535,
            initial_lifetime: Duration::from_secs(10),
            input_lifetime: Duration::from_secs(5),
        }
    }
}
impl Limits {
    pub(crate) fn validate(self) -> Result<(), Fault> {
        self.profile.validate()?;
        if self.operations == 0
            || self.source_bytes < 4
            || self.frame_bytes < ipc::RECV_PREFIX
            || self.frame_bytes > 65535
            || self.io_slice_bytes == 0
            || self.initial_lifetime.is_zero()
            || self.input_lifetime.is_zero()
            || std::time::Instant::now()
                .checked_add(self.initial_lifetime)
                .is_none()
            || std::time::Instant::now()
                .checked_add(self.input_lifetime)
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
/// Actual active outgoing frame family. This is not a remote operation ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Actual handle CREATE, with no corresponding ACK.
    Create,
    /// Actual handle DESTROY, followed by physical local close.
    Destroy,
    /// Actual room OPEN.
    Open,
    /// Actual room ENTRY.
    Entry,
    /// Actual room CLOSE.
    Close,
    /// Actual room SYNC.
    Sync,
    /// Encoded message SEND, with no corresponding generic ACK.
    Send,
    /// Original room/hash GET, whose notification may arrive asynchronously.
    Get,
}
impl From<ipc::Request<'_>> for Kind {
    fn from(request: ipc::Request<'_>) -> Self {
        match request {
            ipc::Request::Create => Self::Create,
            ipc::Request::Destroy => Self::Destroy,
            ipc::Request::Open { .. } => Self::Open,
            ipc::Request::Entry { .. } => Self::Entry,
            ipc::Request::Close { .. } => Self::Close,
            ipc::Request::Sync { .. } => Self::Sync,
            ipc::Request::Send { .. } => Self::Send,
            ipc::Request::Get { .. } => Self::Get,
        }
    }
}
/// Exact original physical write state; none proves remote receipt or processing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Submission {
    /// No byte exposed to the source.
    Unsent,
    /// A positive original prefix reached the socket.
    Partial {
        /// Original prefix actually exposed to the socket.
        bytes: usize,
        /// Complete immutable original frame length.
        total: usize,
    },
}
/// Original unsettled frame after physical source retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Report<'a> {
    /// Original local operation, never remapped to another source.
    pub operation: Operation<'a>,
    /// Original outgoing family.
    pub kind: Kind,
    /// Actual original prefix. Written frames already have their separate event.
    pub submission: Submission,
}
/// Original reason a source physically ended. No business rollback is implied.
pub enum LossCause<'a> {
    /// Native, configuration, clock, allocation or malformed input failure.
    Failure(Error),
    /// Actual clean EOF, not a DESTROY ACK.
    Eof,
    /// Fixed first-byte input lifetime.
    InputDeadline,
    /// Original fixed connection+CREATE lifetime.
    InitialDeadline,
    /// Original immutable frame's finite deadline.
    FrameDeadline(Operation<'a>),
    /// Explicit cancellation physically stops the whole original MQ.
    Cancelled(Operation<'a>),
    /// Explicit owner close.
    Closed,
}
impl fmt::Debug for LossCause<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failure(e) => f.debug_tuple("Failure").field(e).finish(),
            Self::Eof => f.write_str("Eof"),
            Self::InputDeadline => f.write_str("InputDeadline"),
            Self::InitialDeadline => f.write_str("InitialDeadline"),
            Self::FrameDeadline(op) => f.debug_tuple("FrameDeadline").field(op).finish(),
            Self::Cancelled(op) => f.debug_tuple("Cancelled").field(op).finish(),
            Self::Closed => f.write_str("Closed"),
        }
    }
}
/// Physical retirement precedes publication. Frames are erased, and old rooms
/// and operations must be invalidated by their higher owner; nothing replays.
#[derive(Debug)]
pub struct Loss<'a> {
    /// Original source, absent if no native attachment occurred.
    pub epoch: Option<Epoch<'a>>,
    /// Original reason, without replacement by later cleanup observations.
    pub cause: LossCause<'a>,
    /// Every still-unwritten original frame and its actual exposed prefix.
    pub reports: Vec<Report<'a>>,
}
/// Single zeroizing copy of one actual service notification. This grants no
/// hash/signature validity, member identity or room/message authorization.
pub struct Notification {
    pub(crate) frame: OwnedFrame,
    pub(crate) profile: Profile,
}
impl Notification {
    /// Checked original outer IPC fields, borrowing this retained owner.
    pub fn view(&self) -> Result<ipc::Response<'_>, Fault> {
        ipc::Response::decode(self.frame.bytes(), self.profile)
    }
    /// Complete original frame length, without disclosing payload bytes.
    pub fn len(&self) -> usize {
        self.frame.len()
    }
    /// An admitted notification is never empty.
    pub fn is_empty(&self) -> bool {
        self.frame.is_empty()
    }
}
impl fmt::Debug for Notification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Notification")
            .field("bytes", &self.len())
            .finish_non_exhaustive()
    }
}
/// Caller-observed original source and byte progress. Notifications carry no
/// fabricated request ID/correlation or generic successful SEND completion.
#[derive(Debug)]
pub enum Progress<'a> {
    /// Native socket attached; CREATE is still required.
    Attached(Epoch<'a>),
    /// Original immutable frame entered its actual source's native queue.
    Queued {
        /// Original actually attached source.
        epoch: Epoch<'a>,
        /// Exact original local frame token.
        operation: Operation<'a>,
        /// Actual outgoing frame family.
        kind: Kind,
    },
    /// One actual partial native read/write.
    Activity {
        /// Bytes returned by one actual native read.
        read_bytes: usize,
        /// Bytes returned by one actual native write.
        written_bytes: usize,
    },
    /// All original frame bytes wrote locally. DESTROY physically closes this
    /// source before the event; no service or peer ACK is claimed.
    Written {
        /// Source on which this original frame wrote.
        epoch: Epoch<'a>,
        /// Exact original local frame token.
        operation: Operation<'a>,
        /// Actual outgoing frame family.
        kind: Kind,
        /// Complete original frame length, now wholly written locally.
        bytes: usize,
    },
    /// One asynchronous original service notification, independent of writes.
    Notification {
        /// Original source that supplied this frame.
        epoch: Epoch<'a>,
        /// Single retained zeroizing original notification.
        notification: Notification,
    },
    /// Original source is physically stopped; explicit reconnect is required.
    Lost(Loss<'a>),
}
