//! Finite policies and observations that distinguish IPC from REGEX processing.
use crate::{Epoch, Error, Job, WriteId, ipc::SearchResult};
use gnunet_service_runtime::framing::{Accounting, Budget, Limits as FrameLimits};
use gnunet_types::Error as ProtocolError;
use std::{io, time::Duration};
/// Independent logical deadlines in the endpoint's original clock domain.
#[derive(Clone, Copy, Debug)]
pub struct Deadlines {
    /// Absolute first whole-request send deadline, including endpoint selection.
    /// A completed first send discharges this bound; restoration still obeys
    /// the unchanged first-result and whole-job targets.
    pub send_until: u64,
    /// Required for searches, forbidden for announcements. Ends local interest
    /// if no complete valid RESULT was observed by this absolute time.
    pub first_result_until: Option<u64>,
    /// Finite absolute original job lifetime, never refreshed by results.
    pub until: u64,
}
impl Deadlines {
    pub(crate) fn validate(self, now: u64, search: bool) -> Result<(), ProtocolError> {
        if self.send_until <= now || self.send_until > self.until || self.until == u64::MAX {
            return Err(ProtocolError::Deadline);
        }
        match (search, self.first_result_until) {
            (true, Some(first)) if first >= self.send_until && first <= self.until => Ok(()),
            (false, None) => Ok(()),
            _ => Err(ProtocolError::InvalidInput),
        }
    }
}
/// One RX frame, one retained TX frame and bounded native syscall quanta.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum original frame bytes, including the official four-byte header.
    pub frame_bytes: usize,
    /// Maximum bytes offered by one native read/write call.
    pub io_slice_bytes: usize,
    /// Optional explicit send-suffix shutdown grace. Cancellation never waits.
    pub retirement_grace_micros: u64,
    /// Maximum total GET and PUT peer identities in any one result.
    pub path_entries: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            frame_bytes: 65535,
            io_slice_bytes: 65535,
            retirement_grace_micros: 5_000_000,
            path_entries: 2046,
        }
    }
}
impl Limits {
    pub(crate) fn framing(self) -> FrameLimits {
        FrameLimits {
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
    pub(crate) fn validate(self) -> Result<(), ProtocolError> {
        self.framing().validate()?;
        if self.frame_bytes < crate::ipc::RESULT_PREFIX
            || self.retirement_grace_micros == 0
            || self.path_entries > (65535 - crate::ipc::RESULT_PREFIX) / 32
        {
            return Err(ProtocolError::Capacity);
        }
        Ok(())
    }
}
/// Original local byte exposure; none of these is an acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Submission {
    /// No original request byte transferred to the local socket.
    Unsent,
    /// Only this original prefix transferred; the service may reject or act.
    Partial {
        /// Actual positive local byte count.
        bytes: usize,
        /// Original total frame length.
        total: usize,
    },
    /// Whole original frame transferred locally; service processing is unknown.
    Written {
        /// Original frame length.
        bytes: usize,
    },
}
/// Why this original physical owner ended. No variant is a service DONE.
#[derive(Debug)]
pub enum EndCause {
    /// Explicit cancellation physically closed the original MQ.
    Cancelled,
    /// Explicit owner shutdown physically closed the original MQ.
    Closed,
    /// Explicit suffix-only grace completed its original local write.
    Graceful,
    /// Original finite job lifetime expired.
    LifetimeDeadline,
    /// Original whole-request send deadline expired.
    SendDeadline,
    /// No complete first RESULT arrived by the original local deadline.
    FirstResultDeadline,
    /// Original finite optional suffix grace expired.
    GraceDeadline,
    /// Actual EOF, not an empty successful result set.
    Eof,
    /// Original native read/write error.
    Io(io::Error),
    /// Malformed or unexpected original service message.
    Protocol(ProtocolError),
    /// Local resource failure, without a service result.
    Resource(ProtocolError),
    /// Canonical original clock or deadline registration failed.
    Clock(ProtocolError),
    /// Original CLIENT/Resolver/clock-subscription port refused.
    Ports(Error),
}
/// Physical closure precedes publication of every local ending observation.
#[derive(Debug)]
pub struct End<'id> {
    /// Original logical intent.
    pub job: Job<'id>,
    /// Original actually attached MQ, absent if it never attached.
    pub epoch: Option<Epoch<'id>>,
    /// This observation actually retired an attached MQ. False retains the
    /// last source receipt while ending a detached/reconnecting logical intent.
    pub retired_mq: bool,
    /// This exact physical request entered the retired MQ queue, even if no
    /// byte or only a prefix was written. Whole writes retain this fact too.
    pub queued: bool,
    /// Exact admitted request write, absent before physical queue admission.
    pub write: Option<WriteId<'id>>,
    /// Exact local request exposure before closure.
    pub submission: Submission,
    /// Local/native cause, never an invented wire completion.
    pub cause: EndCause,
}
/// One bounded physical/protocol step.
#[derive(Debug)]
pub enum Progress<'id> {
    /// Actual MQ attached; no announcement/search acceptance is implied.
    Connected {
        /// Original intent.
        job: Job<'id>,
        /// Actual original source.
        epoch: Epoch<'id>,
    },
    /// Immutable original request actually admitted to its original MQ queue.
    /// No native byte transfer or service acceptance is implied.
    Queued {
        /// Original intent.
        job: Job<'id>,
        /// Actual original source.
        epoch: Epoch<'id>,
        /// Immutable original physical request.
        write: WriteId<'id>,
    },
    /// Whole request actually written locally. No processing/DHT claim.
    Submitted {
        /// Original intent.
        job: Job<'id>,
        /// Actual original source.
        epoch: Epoch<'id>,
        /// Immutable original physical request.
        write: WriteId<'id>,
    },
    /// Complete validated RESULT retained for result()/take_result(). Until
    /// consumed, native RX is backpressured and the original deadline still runs.
    ResultReady {
        /// Original intent.
        job: Job<'id>,
        /// Source that supplied the bytes.
        epoch: Epoch<'id>,
        /// Per-original-job ordinal, not a freshness claim.
        ordinal: u64,
    },
    /// Actual native bytes only, not service progress.
    Activity {
        /// Actual original MQ.
        epoch: Epoch<'id>,
        /// Actual read bytes.
        read_bytes: usize,
        /// Actual written bytes.
        written_bytes: usize,
    },
    /// Failed pre-attachment attempt. No application request was replayed.
    ConnectRetry {
        /// Actual native attempt error.
        error: io::Error,
        /// Source-selected retry delay.
        retry_after: Duration,
    },
    /// Endpoint selection failed; original finite send deadline still applies.
    Unavailable(Error),
    /// Actual EOF or native source error. The old MQ is physically closed and
    /// its exact write exposure is retained here. The SAME registration intent
    /// will reconnect with new epoch/write identities and unchanged deadlines.
    /// Earlier DHT announcements may remain visible; no publication ACK exists.
    SourceLost {
        /// Original source, byte exposure and actual typed error/EOF.
        end: End<'id>,
        /// Existing CLIENT source-selected reconnect delay.
        retry_after: Duration,
    },
    /// This logical intent ended; no reconnect follows cancellation, protocol,
    /// clock, resource, deadline or explicit suffix-only retirement.
    Ended(End<'id>),
    /// This observation budget ended, preserving all original cursors/deadlines.
    WaitDeadline,
    /// Already permanently closed after its one End observation.
    Closed,
}
/// Borrowed actual result, valid only while its original retained RX remains.
pub struct ResultView<'buf, 'id> {
    /// Original intent, never rebound by a later search.
    pub job: Job<'id>,
    /// Actual provider MQ generation.
    pub epoch: Epoch<'id>,
    /// Original result ordinal.
    pub ordinal: u64,
    /// Source-clock sample at the bounded read/dispatch turn; no perpetual freshness.
    pub observed_at: u64,
    /// Actual official peer and GET/PUT paths.
    pub result: SearchResult<'buf>,
}
/// One owned combined path allocation, preserving the original source identity.
#[derive(Debug)]
pub struct OwnedResult<'id> {
    pub(crate) job: Job<'id>,
    pub(crate) epoch: Epoch<'id>,
    pub(crate) ordinal: u64,
    pub(crate) observed_at: u64,
    pub(crate) peer: [u8; 32],
    pub(crate) path: Vec<[u8; 32]>,
    pub(crate) get_len: usize,
}
impl<'id> OwnedResult<'id> {
    /// Borrow exact original bytes/identities after one explicit ownership copy.
    #[must_use]
    pub fn view(&self) -> ResultView<'_, 'id> {
        ResultView {
            job: self.job,
            epoch: self.epoch,
            ordinal: self.ordinal,
            observed_at: self.observed_at,
            result: SearchResult {
                peer: self.peer,
                get_path: &self.path[..self.get_len],
                put_path: &self.path[self.get_len..],
            },
        }
    }
}
