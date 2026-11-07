//! Caller-driven official SETI set and listener MQs with original ownership.
#![forbid(unsafe_code)]
mod client;
mod scope;
pub use client::{Client, Incoming, ResultRecord};
/// Original CLIENT/clock/configuration failure.
pub use gnunet_client_host::ConnectError as Error;
/// Explicit endpoint selectors; no Resolver or service is constructed here.
pub use gnunet_client_host::{EndpointSource, LiveConfiguration, resolution};
/// Canonical source-clock and deadline ports.
pub use gnunet_service_runtime::clock;
use gnunet_service_runtime::framing::{Accounting, Budget, Limits as FrameLimits};
use gnunet_types::Error as ProtocolError;
/// Complete official SETI IPC/P2P codecs and explicit C RESULT ABI layout.
pub use gnunet_wire::official::seti as ipc;
pub use scope::{Epoch, Instance, Operation, WriteId};
use std::{io, time::Duration};

/// Explicit policy for the pinned C producer's omitted element-type htons.
#[derive(Clone, Copy, Debug)]
pub enum ElementTypeOrder {
    /// Correct standard network-order element type, used by Rust providers.
    Network,
    /// Raw little-endian native u16 from the pinned C producer.
    CNativeLittle,
    /// Raw big-endian native u16 from the pinned C producer.
    CNativeBig,
}
impl ElementTypeOrder {
    /// Choose the caller's known native C ABI, without inspecting input bytes.
    #[must_use]
    pub const fn native_c() -> Self {
        if cfg!(target_endian = "little") {
            Self::CNativeLittle
        } else {
            Self::CNativeBig
        }
    }
}
/// Finite metadata, byte and source-lifetime policy.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Fixed concurrent operation metadata slots.
    pub operations: usize,
    /// Fixed pending listener suggestion slots.
    pub incoming: usize,
    /// Sum of retained unconsumed incoming frames, including context.
    pub incoming_bytes: usize,
    /// Original physical FIFO retained bytes/frames.
    pub output: Budget,
    /// Maximum official frame.
    pub frame_bytes: usize,
    /// Maximum bytes per native read/write syscall.
    pub io_slice_bytes: usize,
    /// Finite cancellation/suffix retirement grace.
    pub retirement_grace_micros: u64,
    /// Unaccepted suggestion lifetime; dropped/expired suggestions are rejected.
    pub incoming_lifetime_micros: u64,
    /// Explicit source ABI, independent of element type order.
    pub result_layout: ipc::ResultLayout,
    /// Explicit source producer profile; raw bytes remain available unchanged.
    pub element_type_order: ElementTypeOrder,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            operations: 64,
            incoming: 16,
            incoming_bytes: 1024 * 1024,
            output: Budget {
                frames: 64,
                bytes: 1024 * 1024,
            },
            frame_bytes: 65535,
            io_slice_bytes: 65535,
            retirement_grace_micros: 5_000_000,
            incoming_lifetime_micros: 30_000_000,
            result_layout: ipc::ResultLayout::native(),
            element_type_order: ElementTypeOrder::Network,
        }
    }
}
impl Limits {
    fn framing(self) -> FrameLimits {
        FrameLimits {
            frame_bytes: self.frame_bytes,
            ordinary: self.output,
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.io_slice_bytes,
        }
    }
    fn validate(self) -> Result<(), ProtocolError> {
        self.framing().validate()?;
        if !(1..=4096).contains(&self.operations)
            || !(1..=4096).contains(&self.incoming)
            || self.incoming_bytes < 40
            || self.frame_bytes < 108
            || self.retirement_grace_micros == 0
            || self.incoming_lifetime_micros == 0
        {
            return Err(ProtocolError::InvalidInput);
        }
        Ok(())
    }
}
/// Exact original fully locally written command, not a service ACK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// Original CREATE.
    Create,
    /// Original ADD; no wire ACK exists.
    Add,
    /// Original LISTEN.
    Listen,
    /// Original EVALUATE.
    Evaluate,
    /// Original ACCEPT.
    Accept,
    /// Original REJECT; no wire ACK exists.
    Reject,
    /// Original CANCEL; no wire ACK exists.
    Cancel,
}
/// Local retirement cause, never a fabricated protocol FAILURE/DONE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// Explicit exact-operation cancellation.
    Cancelled,
    /// Original absolute operation deadline.
    Deadline,
    /// An ACCEPT suggestion's original source retired before full writing.
    IncomingLost,
    /// Original physical set MQ was lost.
    Lost,
    /// Permanent local owner shutdown.
    Closed,
}
/// Original request exposure, separate from service computation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Submission {
    /// No original EVALUATE/ACCEPT byte was transferred.
    Unsent,
    /// Original request may have reached the service.
    Unknown,
    /// Exact CANCEL was fully locally written, without an ACK.
    CancelSubmitted,
}
/// Actual physical retirement cause.
#[derive(Debug)]
pub enum Cause {
    /// Original native EOF.
    Eof,
    /// Original socket error.
    Io(io::Error),
    /// Actual malformed source frame or ownership failure.
    Protocol(ProtocolError),
    /// Actual CLIENT/clock/Resolver port failure.
    Ports(Error),
    /// Original finite source/write bound.
    Deadline,
    /// Explicit physical close.
    Closed,
}
/// One actual native/protocol observation. Tokens belong to the original client.
pub enum Step<'id> {
    /// Actual native MQ attachment, without service/peer authentication.
    Connected(Epoch<'id>),
    /// Exact original frame fully locally written; never a peer/service ACK.
    Written(Epoch<'id>, WriteId<'id>, Command),
    /// Actual listener suggestion; dropping it requests an original REJECT.
    Incoming(Incoming<'id>),
    /// Actual correlated RESULT, including FAILURE/DONE and unchanged bytes.
    Result(ResultRecord<'id>),
    /// Local operation retirement, without a fabricated RESULT.
    LocalEnd(Operation<'id>, Reason, Submission),
    /// Original physical bytes read/written.
    Activity(usize, usize),
    /// Physical owner closed before logical retirement observations.
    Lost(Option<Epoch<'id>>, Cause),
    /// Actual failed native attempt and source-selected retry delay.
    Retry(io::Error, Duration),
    /// Caller wait ended; original logical deadlines remain independent.
    WaitDeadline,
    /// Complete input retained while bounded observation capacity is unavailable.
    Capacity,
    /// Permanently/source-closed after queued local results are consumed.
    Closed,
}
