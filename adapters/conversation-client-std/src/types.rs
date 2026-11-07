use gnunet_service_runtime::framing::{Accounting, Budget, Limits as Framing, OwnedFrame};
use gnunet_types::Error as Fault;
use std::{fmt, io, sync::Arc, time::Duration};

/// Actual selected native/protocol/syscall cause, without payload formatting.
#[derive(Debug)]
pub enum Error {
    /// Shared CLIENT/configuration/clock/Resolver failure.
    Native(gnunet_client_host::ConnectError),
    /// Original finite protocol/resource/ownership error.
    Protocol(Fault),
    /// Actual original OS error.
    Io(io::Error),
}
impl From<Fault> for Error {
    fn from(v: Fault) -> Self {
        Self::Protocol(v)
    }
}
impl From<gnunet_client_host::ConnectError> for Error {
    fn from(v: gnunet_client_host::ConnectError) -> Self {
        Self::Native(v)
    }
}
impl From<io::Error> for Error {
    fn from(v: io::Error) -> Self {
        Self::Io(v)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native(e) => fmt::Display::fmt(e, f),
            Self::Protocol(e) => fmt::Display::fmt(e, f),
            Self::Io(e) => fmt::Display::fmt(e, f),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Native(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Io(e) => Some(e),
        }
    }
}

/// Original Line identity; equal counters on independent MQs grant no authority.
#[derive(Clone)]
pub(crate) struct Domain(pub Arc<()>);
impl PartialEq for Domain {
    fn eq(&self, v: &Self) -> bool {
        Arc::ptr_eq(&self.0, &v.0)
    }
}
impl Eq for Domain {}
impl fmt::Debug for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OriginalLine")
    }
}
/// Actual physical attachment; never a remote pickup/readiness receipt.
#[derive(Clone)]
pub struct Epoch(pub(crate) Arc<()>);
impl PartialEq for Epoch {
    fn eq(&self, v: &Self) -> bool {
        Arc::ptr_eq(&self.0, &v.0)
    }
}
impl Eq for Epoch {}
impl fmt::Debug for Epoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OriginalEpoch")
    }
}
/// Opaque original call owner, independent of numeric wire CID and its high bit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Call {
    pub(crate) domain: Domain,
    pub(crate) serial: u64,
}
impl Call {
    /// Original in-process serial; no wire or cross-Line authority.
    pub const fn serial(&self) -> u64 {
        self.serial
    }
}
/// Opaque immutable original write; no mutation is replayed in a new Line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Operation {
    pub(crate) domain: Domain,
    pub(crate) serial: u64,
}
impl Operation {
    /// Original in-process FIFO serial, never a wire field.
    pub const fn serial(&self) -> u64 {
        self.serial
    }
}
/// Call direction established by this original Line and actual notifications.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Created by original outgoing734.
    Outgoing,
    /// Observed by actual incoming735 on a registered Line.
    Incoming,
}
/// Observed/local state, without converting local writes into remote pickup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Outgoing init queued/written; no remote pickup observed.
    Calling,
    /// Actual735 awaits local pickup.
    Ringing,
    /// Actual738 or whole local732 permits local media.
    Connected,
    /// Local hangup intent is retained in its original FIFO.
    Ending,
    /// Actual733 or whole local733 ended the local call owner.
    Ended,
}
/// Actual original caller-visible facts. The ring ego key is not a peer ID.
#[derive(Clone, Debug)]
pub struct CallInfo {
    /// Original opaque call.
    pub call: Call,
    /// Actual attachment if observed.
    pub epoch: Option<Epoch>,
    /// Original Line role.
    pub role: Role,
    /// Actual current/local phase.
    pub phase: Phase,
    /// Raw CID bytes observed on the original MQ, excluding any interpretation.
    pub cid: Option<[u8; 4]>,
    /// Supported typed public ego36 from actual735, not an independently verified signature.
    pub caller: Option<[u8; 36]>,
    /// Caller-selected network target for an outgoing Line only.
    pub target: Option<[u8; 32]>,
    /// Original local suspension whole write.
    pub suspended_local: bool,
    /// Actual source notification736 state.
    pub suspended_remote: bool,
    /// Whole local732, not a remote acknowledgement.
    pub pickup_written: bool,
    /// Actual738, never inferred from EOF or local734.
    pub remote_pickup: bool,
    /// Whole local733.
    pub hangup_written: bool,
    /// Actual733, not inferred from source loss.
    pub hangup_notified: bool,
}
/// Exact original outbound frame kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Original731.
    Register,
    /// Original734, containing zeroizing private material.
    Call,
    /// Local732.
    PickUp,
    /// Local733.
    HangUp,
    /// Local736.
    Suspend,
    /// Local737.
    Resume,
    /// Local739 opaque audio.
    Audio,
}
/// Actual original physical write facts; whole write is not processing/pickup.
#[derive(Clone, Debug)]
pub struct Receipt {
    /// Original per-write canonical/native targets captured at admission.
    pub bounds: crate::Bounds,
    /// Original operation.
    pub operation: Operation,
    /// Original optional call.
    pub call: Option<Call>,
    /// Original complete message kind.
    pub kind: Kind,
    /// Actual physical attachment, if it happened.
    pub epoch: Option<Epoch>,
    /// Immutable official frame length.
    pub total_bytes: usize,
    /// Actual positive original prefix written.
    pub written_bytes: usize,
    /// Actual complete original local write.
    pub complete: bool,
}
/// Why the original Line was physically retired, separate from peer733.
#[derive(Debug)]
pub enum Cause {
    /// Actual original provider/protocol/syscall error.
    Failure(Error),
    /// Real EOF; never a pickup or hangup notification.
    Eof,
    /// Original whole/initial/write/partial target expired.
    Deadline,
    /// Explicit local cancellation/physical close.
    Cancelled,
    /// Actual733 invalidated an already partial original call write.
    CallEnded(Call),
}
/// Clock-free physical retirement and all original retained write/call facts.
#[derive(Debug)]
pub struct Loss {
    /// Original whole-Line targets, never renewed.
    pub overall: crate::Bounds,
    /// Original attachment-through-initializer target if still live.
    pub initial: Option<crate::Bounds>,
    /// Original first-byte-through-complete-frame target if present.
    pub input: Option<crate::Bounds>,
    /// Actual initiating source/local cause.
    pub cause: Cause,
    /// Original initializer receipt, including partial/whole exposure.
    pub initializer: Receipt,
    /// Still-retained original writes; partial exposure remains unknown.
    pub pending: Vec<Receipt>,
    /// Original call snapshots, including actual peer notifications.
    pub calls: Vec<CallInfo>,
    /// Outstanding caller-owned audio (count, actual byte capacity); None means
    /// its independent quota lock could not be read, never zero debt.
    pub audio: Option<(usize, usize)>,
    /// Actual bytes of the partial/complete current input frame.
    pub input_bytes: usize,
}
impl fmt::Display for Loss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CONVERSATION original source {:?}; initializer {:?}; pending={} calls={} input={}",
            self.cause,
            self.initializer,
            self.pending.len(),
            self.calls.len(),
            self.input_bytes
        )
    }
}
impl std::error::Error for Loss {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Cause::Failure(e) = &self.cause {
            Some(e)
        } else {
            None
        }
    }
}
/// One immutable zeroizing actual audio frame, with no Debug/Clone/payload log.
pub struct Audio {
    pub(crate) frame: OwnedFrame,
    pub(crate) _lease: crate::audio::Lease,
}
impl Audio {
    /// Exact compressed source audio, excluding original header/CID.
    pub fn bytes(&self) -> &[u8] {
        &self.frame.bytes()[8..]
    }
    /// Actual retained allocation charged to its original Line quota until Drop.
    pub fn retained_bytes(&self) -> usize {
        self.frame.retained_bytes()
    }
}
/// One real original native/notification observation; none is synthesized readiness.
pub enum Progress {
    /// Actual native attachment before any initializer bytes are implied.
    Attached(Epoch),
    /// Original pre-attachment syscall failed; no attached request is replayed.
    Retry {
        /// Actual original error.
        error: io::Error,
        /// Source-selected backoff.
        retry_after: Duration,
    },
    /// Actual positive partial/whole original transfer, applied before later errors.
    Written {
        /// Original exact write receipt.
        receipt: Receipt,
        /// Positive syscall transfer.
        bytes: usize,
    },
    /// Provably unexposed queued call work suppressed after actual733.
    Unsent {
        /// Actual original zero-prefix receipt.
        receipt: Receipt,
    },
    /// Actual validated735 on a registered Line.
    Ring {
        /// Original call snapshot.
        info: CallInfo,
    },
    /// Actual738 on this outgoing Line.
    PickedUp {
        /// Original call snapshot.
        info: CallInfo,
    },
    /// Actual733, also retained independently of later source loss.
    HangUp {
        /// Original call snapshot.
        info: CallInfo,
    },
    /// Actual736.
    Suspended {
        /// Original call snapshot.
        info: CallInfo,
    },
    /// Actual737.
    Resumed {
        /// Original call snapshot.
        info: CallInfo,
    },
    /// Exact739 from this original call and epoch.
    Audio {
        /// Original call snapshot.
        info: CallInfo,
        /// Owned bounded zeroizing payload.
        audio: Audio,
    },
    /// Positive actual incoming syscall bytes, not a notification.
    Activity {
        /// Actual source epoch.
        epoch: Epoch,
        /// Positive byte count.
        bytes: usize,
    },
    /// Actual late notification for a missing/retired CID; no new call was created.
    Ignored {
        /// Actual source epoch.
        epoch: Epoch,
        /// Raw original CID bytes.
        cid: [u8; 4],
    },
    /// Source physically closed before exposing these original facts.
    Lost(Loss),
}
/// Explicit finite Line/media resources; limits are not an RSS guarantee.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Simultaneously retained calls, including ended calls until release.
    pub calls: usize,
    /// Total CID history per original Line; IDs are never recycled on that MQ.
    pub call_ids: usize,
    /// Retained immutable outbound originals, including initializer.
    pub pending: usize,
    /// Complete official local frame extent.
    pub frame_bytes: usize,
    /// Maximum compressed media bytes in one original frame.
    pub audio_bytes: usize,
    /// Maximum outstanding owned incoming audio observations.
    pub audio_frames: usize,
    /// Maximum actual byte capacity of all outstanding owned audio.
    pub audio_retained_bytes: usize,
    /// Maximum total actual pending frame capacities.
    pub queued_bytes: usize,
    /// Actual SDK table/payload/framing capacities; shared ports/OS are separate.
    pub retained_bytes: usize,
    /// Maximum offered native syscall bytes per step.
    pub io_slice_bytes: usize,
    /// Original attachment through whole731/734 target.
    pub initial_timeout: Duration,
    /// Fixed target of each write, captured on admission rather than FIFO head.
    pub write_timeout: Duration,
    /// Original first positive input byte through complete frame target.
    pub input_timeout: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            calls: 32,
            call_ids: 65536,
            pending: 64,
            frame_bytes: 65535,
            audio_bytes: gnunet_wire::official::cadet::MAX_APPLICATION_MESSAGE_SIZE - 4,
            audio_frames: 8,
            audio_retained_bytes: 8 * 65535,
            queued_bytes: 1048576,
            retained_bytes: 4194304,
            io_slice_bytes: 65535,
            initial_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(10),
            input_timeout: Duration::from_secs(15),
        }
    }
}
impl Limits {
    /// Validate bounded profiles before any native attachment.
    pub fn validate(self) -> Result<(), Error> {
        if self.calls == 0
            || self.calls > 1024
            || self.call_ids < self.calls
            || self.call_ids > 1048576
            || self.pending == 0
            || self.pending > 4096
            || !(144..=65535).contains(&self.frame_bytes)
            || self.audio_bytes > gnunet_wire::official::cadet::MAX_APPLICATION_MESSAGE_SIZE - 4
            || self.audio_bytes > self.frame_bytes - 8
            || self.audio_frames == 0
            || self.audio_frames > 4096
            || self.audio_retained_bytes < self.frame_bytes
            || self.queued_bytes < self.frame_bytes
            || self.retained_bytes < self.queued_bytes
            || self.io_slice_bytes == 0
        {
            return Err(Fault::InvalidInput.into());
        }
        for d in [self.initial_timeout, self.write_timeout, self.input_timeout] {
            if d.is_zero() || std::time::Instant::now().checked_add(d).is_none() {
                return Err(Fault::InvalidInput.into());
            }
        }
        self.framing().validate()?;
        Ok(())
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
