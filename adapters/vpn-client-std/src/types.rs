//! Bounded policies and honest wire/local allocation outcomes.
use crate::{Address, Epoch, Error, Operation, WriteId};
use gnunet_service_runtime::framing::{Accounting, Budget, Limits as FrameLimits};
use gnunet_types::Error as ProtocolError;
use std::{io, time::Duration};
/// Independent physical and logical ownership bounds.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Fixed allocation/debt slots; every request is at most128 bytes.
    pub operations: usize,
    /// Retained physical output bounds.
    pub output: Budget,
    /// Maximum bytes offered to one native syscall.
    pub io_slice_bytes: usize,
    /// Finite drain grace for a partially exposed original request.
    pub retirement_grace_micros: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            operations: 64,
            output: Budget {
                frames: 32,
                bytes: 4096,
            },
            io_slice_bytes: 128,
            retirement_grace_micros: 5_000_000,
        }
    }
}
impl Limits {
    pub(crate) fn framing(self) -> FrameLimits {
        FrameLimits {
            frame_bytes: 128,
            ordinary: self.output,
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.io_slice_bytes,
        }
    }
    pub(crate) fn validate(self) -> Result<(), ProtocolError> {
        self.framing().validate()?;
        if self.operations == 0
            || self.output.frames == 0
            || self.output.bytes < 128
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
/// Official service redirection IPPROTO values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    /// IPPROTO_TCP(6).
    Tcp,
    /// IPPROTO_UDP(17).
    Udp,
}
impl Protocol {
    pub(crate) const fn value(self) -> u32 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
        }
    }
}
/// Actual named peer service selected by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Service {
    /// Expected peer identity.
    pub peer: [u8; 32],
    /// Official shared service descriptor hash.
    pub descriptor: [u8; 64],
    /// Official TCP or UDP service protocol.
    pub protocol: Protocol,
}
/// Actual local request exposure, without an invented allocation result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Submission {
    /// No original request byte was transferred.
    Unsent,
    /// Some bytes were written; an allocation may already exist.
    Unknown,
}
/// Why local interest ended without an original USE_IP result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reason {
    /// Caller suppressed the original callback.
    Cancelled,
    /// Original finite response deadline expired.
    Deadline,
    /// Original physical MQ retired.
    Lost,
    /// Permanent local owner shutdown.
    Closed,
}
/// Actual allocation response or explicitly local termination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Actual matching USE_IP address. None is actual allocation failure.
    /// Some does not assert forwarding, route installation or peer delivery.
    Allocation(Option<Address>),
    /// Local callback retirement; no wire cancellation or lease revocation.
    Local {
        /// Original reason.
        reason: Reason,
        /// Original request exposure.
        submission: Submission,
    },
}
/// Local callback cancellation, never a lease revocation ACK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cancel {
    /// Wholly unwritten original request was removed.
    Unsent,
    /// Original partial frame must finish on its MQ or that MQ must close.
    Draining,
    /// Fully exposed original request retired locally; lease may exist.
    Unknown,
}
/// Cause of actual physical retirement.
#[derive(Debug)]
pub enum LossCause {
    /// Native EOF.
    Eof,
    /// Original native read/write error.
    Io(io::Error),
    /// Invalid original service input.
    Protocol(ProtocolError),
    /// Local allocation/admission failure.
    Resource(ProtocolError),
    /// Original canonical clock/deadline port failure.
    Clock(ProtocolError),
    /// Original CLIENT configuration/clock/Resolver port refusal.
    Ports(Error),
    /// Caller explicitly replaced the original connection.
    Requested,
    /// Original partial-drain hard deadline reached.
    Deadline,
    /// Permanent owner shutdown.
    Closed,
}
/// One bounded original native/protocol observation.
pub enum Progress<'a> {
    /// Actual MQ attached; this does not authenticate a remote peer.
    Connected(Epoch<'a>),
    /// Whole original request actually locally written.
    Written {
        /// Original MQ.
        epoch: Epoch<'a>,
        /// Original allocation operation.
        operation: Operation<'a>,
        /// Immutable original physical frame.
        write: WriteId<'a>,
    },
    /// Actual allocation or an explicitly local terminal observation.
    Completed {
        /// Original MQ, absent for never-attached work.
        epoch: Option<Epoch<'a>>,
        /// Original allocation operation.
        operation: Operation<'a>,
        /// Exact wire/local outcome.
        outcome: Outcome,
    },
    /// Original physical IO progress, without an allocation claim.
    Activity {
        /// Original MQ.
        epoch: Epoch<'a>,
        /// Actual read byte count.
        read_bytes: usize,
        /// Actual written byte count.
        written_bytes: usize,
    },
    /// Physical MQ closed before local completions; no request was replayed.
    Lost {
        /// Actual retired MQ, if one attached.
        epoch: Option<Epoch<'a>>,
        /// Original loss.
        cause: LossCause,
    },
    /// Actual failed native connection attempt.
    ConnectRetry {
        /// Original native error.
        error: io::Error,
        /// Source-selected retry delay.
        retry_after: Duration,
    },
    /// Original endpoint could not be selected.
    Unavailable(Error),
    /// Unknown or canceled response consumed on the original MQ.
    Ignored(Epoch<'a>),
    /// Caller observation budget ended; operation deadlines stay unchanged.
    WaitDeadline,
    /// Permanently closed after retained completions drain.
    Closed,
}
