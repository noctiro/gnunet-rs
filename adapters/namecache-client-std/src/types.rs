use crate::{AbsoluteTime, Epoch, Error, Operation};
use gnunet_service_runtime::framing::{Accounting, Budget, Limits as Framing};
use gnunet_types::Error as Fault;
use std::{fmt, io, time::Duration};
/// Explicit retained resources and finite physical retirement policy.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Live original operations plus undelivered completions.
    pub operations: usize,
    /// Total immutable pending and physically queued outbound bytes.
    pub source_bytes: usize,
    /// Maximum returned or submitted complete encrypted block. This configurable
    /// budget can reach the official IPC wire bound, including crypto overhead;
    /// its conservative default retains the C API's declared value-size budget.
    pub block_bytes: usize,
    /// Native complete frame bound.
    pub frame_bytes: usize,
    /// One actual syscall's maximum bytes, nonzero.
    pub io_slice_bytes: usize,
    /// First partial-cancel/deadline through original suffix drain hard bound.
    pub retirement_grace: Duration,
    /// Reconnect fresh sources after physical loss, without replaying requests.
    pub reconnect: bool,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            operations: 32,
            source_bytes: 256 * 1024,
            block_bytes: 63 * 1024,
            frame_bytes: 65535,
            io_slice_bytes: 65535,
            retirement_grace: Duration::from_secs(5),
            reconnect: true,
        }
    }
}
impl Limits {
    pub(crate) fn validate(self) -> Result<(), Fault> {
        if self.operations == 0
            || self.source_bytes < 72
            || self.block_bytes == 0
            || self.block_bytes > crate::ipc::MAX_WIRE_BLOCK_BYTES
            || self.frame_bytes < 72
            || self.frame_bytes > 65535
            || self.io_slice_bytes == 0
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
/// Actual request kind; replies are matched by both original RID and kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Encrypted block lookup.
    Lookup,
    /// Cache an encrypted signed block.
    Cache,
    /// Delete an exact query.
    Delete,
}
/// Actual original local byte exposure, never a cache/durability acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Submission {
    /// No byte written.
    Unsent,
    /// Positive original prefix; service outcome is unknown.
    Partial {
        /// Actual prefix length.
        bytes: usize,
        /// Original frame length.
        total: usize,
    },
    /// Full original request wrote; service response is separate.
    Written {
        /// Actual full length.
        bytes: usize,
    },
}
/// Why an original operation ended locally without a normal service result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalReason {
    /// Callback suppressed, no wire CANCEL.
    Cancelled,
    /// Original finite local response deadline expired.
    Deadline,
    /// Physical original MQ ended.
    Lost,
    /// Owner permanently closed.
    Closed,
}
/// Actual lookup ciphertext validated against its original query, carried-key
/// signature and inner/outer expiry. This is not decryption or zone ownership.
pub struct Block {
    pub(crate) bytes: Vec<u8>,
    pub(crate) query: [u8; 64],
    pub(crate) expiration: AbsoluteTime,
}
impl Block {
    /// Exact signed encrypted block bytes, never decrypted by this client.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Exact original lookup query authenticated by the carried block key.
    #[must_use]
    pub const fn query(&self) -> &[u8; 64] {
        &self.query
    }
    /// Expiration from the actual response, equal to the verified signed block.
    #[must_use]
    pub const fn expiration(&self) -> AbsoluteTime {
        self.expiration
    }
    /// Transfer original ciphertext storage without a second copy.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Block")
            .field("encrypted_bytes", &self.bytes.len())
            .field("expiration", &self.expiration)
            .finish_non_exhaustive()
    }
}
/// Actual official response or explicit local termination.
#[derive(Debug)]
pub enum Outcome {
    /// Actual LOOKUP_BLOCK_RESPONSE. None is actual expire0 miss.
    Lookup(Option<Block>),
    /// Raw signed official BLOCK_CACHE_RESPONSE result.
    Cache(i32),
    /// Raw signed official BLOCK_DELETE_RESPONSE result.
    Delete(i32),
    /// No normal result; an exposed mutation may have committed.
    Local {
        /// Exact local cause.
        reason: LocalReason,
        /// Actual original exposure.
        submission: Submission,
    },
}
/// One original terminal operation. No RID is reused within this client owner.
#[derive(Debug)]
pub struct Completion<'id> {
    /// Exact original private Rust token.
    pub operation: Operation<'id>,
    /// Actual original native epoch, if admitted.
    pub epoch: Option<Epoch<'id>>,
    /// Official original BE32 request ID, exposed only as metadata.
    pub request_id: u32,
    /// Exact original operation.
    pub kind: Kind,
    /// Actual/local result.
    pub outcome: Outcome,
}
/// Cancellation's actual local physical state, no remote revoke proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cancellation {
    /// Zero-written original removed.
    Unsent,
    /// Partial suffix remains on the exact MQ under finite hard drain.
    Draining,
    /// Whole original wrote and is retired locally; late RID response ignored.
    Unknown,
    /// Terminal completion already available.
    Completed,
}
/// Original source physically stopped before local completion publication.
#[derive(Clone, Copy, Debug)]
pub struct Loss<'id> {
    /// Exact old native epoch, if attached.
    pub epoch: Option<Epoch<'id>>,
    /// Number of unfinished originals retired.
    pub operations: usize,
    /// Number with actual positive byte exposure.
    pub exposed: usize,
}
/// Known cause preceding physical owner retirement.
#[derive(Debug)]
pub enum LossCause {
    /// Actual clean EOF.
    Eof,
    /// Actual native I/O failure.
    Io(io::Error),
    /// Invalid response, wrong kind/query, or failed block signature.
    Protocol(Fault),
    /// Explicit finite memory/frame refusal.
    Resource(Fault),
    /// Canonical CLIENT/Resolver/clock port failure.
    Ports(Error),
    /// Caller explicitly requested a fresh source.
    Requested,
    /// Original partial frame could not drain before hard deadline.
    RetirementDeadline,
}
/// One bounded actual/native step. No frame write is promoted to service success.
#[derive(Debug)]
pub enum Progress<'id> {
    /// Actual source attached; no private INIT exists.
    Connected(Epoch<'id>),
    /// Actual immutable original admitted to native queue.
    Queued {
        /// Original source.
        epoch: Epoch<'id>,
        /// Original operation.
        operation: Operation<'id>,
        /// Original official RID.
        request_id: u32,
    },
    /// Whole original local write, not its service result.
    Written {
        /// Original source.
        epoch: Epoch<'id>,
        /// Original operation.
        operation: Operation<'id>,
        /// Exact official RID.
        request_id: u32,
    },
    /// Original actual/local result.
    Completed(Completion<'id>),
    /// Native bytes moved, no delivery/result claim.
    Activity {
        /// Actual read bytes.
        read_bytes: usize,
        /// Actual write bytes.
        written_bytes: usize,
    },
    /// Structurally valid unknown/late RID ignored on this source.
    Ignored {
        /// Actual source.
        epoch: Epoch<'id>,
        /// Actual response RID.
        request_id: u32,
    },
    /// Original physical owner stopped.
    Lost {
        /// Original counts/exposure.
        report: Loss<'id>,
        /// Preceding actual cause.
        cause: LossCause,
    },
    /// Actual pre-attachment syscall failed.
    ConnectRetry {
        /// Actual native error.
        error: io::Error,
        /// Original source retry delay.
        retry_after: Duration,
    },
    /// Actual endpoint selection unavailable.
    Unavailable(Error),
    /// Caller observation deadline only; request remains original.
    WaitDeadline,
    /// Permanent close and all completion records drained.
    Closed,
}
