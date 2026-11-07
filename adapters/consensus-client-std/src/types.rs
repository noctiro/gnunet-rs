//! Native facts and finite source-local resources; none is a private wire field.
use crate::{Bounds, budget::Bound};
use gnunet_service_runtime::framing::{self, OwnedFrame};
use gnunet_types::Error as Fault;
use std::{
    collections::VecDeque,
    fmt, io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
/// Actual cause without a string-only replacement.
#[derive(Debug)]
pub enum Error {
    /// Exact protocol/resource refusal.
    Protocol(Fault),
    /// Actual configuration, shared clock, Resolver or CLIENT error.
    Client(gnunet_client_host::ConnectError),
    /// Actual native read/write error.
    Io(io::Error),
}
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self::Protocol(e)
    }
}
impl From<gnunet_client_host::ConnectError> for Error {
    fn from(e: gnunet_client_host::ConnectError) -> Self {
        Self::Client(e)
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(e) => e.fmt(f),
            Self::Client(e) => e.fmt(f),
            Self::Io(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Protocol(e) => e,
            Self::Client(e) => e,
            Self::Io(e) => e,
        })
    }
}
/// One actual physical MQ, created only after native attachment.
#[derive(Clone, Debug)]
pub struct Epoch(pub(crate) Arc<AtomicBool>);
impl Epoch {
    /// Whether this exact physical source has not been retired.
    #[must_use]
    pub fn live(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
    pub(crate) fn retire(&self) {
        self.0.store(false, Ordering::Release);
    }
}
impl PartialEq for Epoch {
    fn eq(&self, r: &Self) -> bool {
        Arc::ptr_eq(&self.0, &r.0)
    }
}
impl Eq for Epoch {}
/// Original local insertion continuation; raw serials grant no source authority.
#[derive(Clone, Debug)]
pub struct InsertId {
    pub(crate) owner: Arc<()>,
    pub(crate) serial: u64,
}
impl PartialEq for InsertId {
    fn eq(&self, r: &Self) -> bool {
        Arc::ptr_eq(&self.owner, &r.owner) && self.serial == r.serial
    }
}
impl Eq for InsertId {}
/// Original standard request kind; a whole write is not service processing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Official520.
    Join,
    /// Official521 with original local continuation.
    Insert(InsertId),
    /// Official524.
    Conclude,
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Tag {
    Join,
    Insert(u64),
    Conclude,
}
/// Retained original unfinished request, exposed only after physical close.
pub struct Pending {
    /// Original request kind/token.
    pub kind: Kind,
    /// Original encoded request length.
    pub length: usize,
    /// Prefix actually written to the original MQ.
    pub written: usize,
    /// Whether the original whole frame was written.
    pub whole: bool,
    /// Original immutable write target.
    pub original: Bounds,
    pub(crate) tag: Tag,
    pub(crate) bytes: Option<Vec<u8>>,
    pub(crate) bound: Option<Bound>,
    pub(crate) capacity: usize,
}
/// Whole local write of an original request, never a processing/peer ACK.
#[derive(Clone)]
pub struct Receipt {
    /// Actual original physical source.
    pub epoch: Epoch,
    /// Original local request/token.
    pub kind: Kind,
    /// Actual whole frame bytes.
    pub written: usize,
    /// Original fixed write target.
    pub original: Bounds,
}
/// Why the original MQ was closed. No loss is a successful conclude.
#[derive(Debug)]
pub enum Cause {
    /// Caller explicitly canceled/destroyed its original handle.
    Cancelled,
    /// Physical EOF without the required525.
    Eof,
    /// Exact original failure.
    Failure(Error),
}
impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("consensus cancelled"),
            Self::Eof => f.write_str("consensus EOF before525"),
            Self::Failure(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for Cause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Self::Failure(e) = self {
            Some(e)
        } else {
            None
        }
    }
}
/// Physically retired original source and unfinished independent request facts.
pub struct Loss {
    /// Actual original epoch, absent before connection attachment.
    pub epoch: Option<Epoch>,
    /// Exact original source/cancel/error cause.
    pub cause: Cause,
    /// Whole JOIN was actually written.
    pub joined: bool,
    /// Whole CONCLUDE was actually written, without a response claim.
    pub concluded: bool,
    /// Actual already whole-written insertions; not durable or peer accepted.
    pub inserts_written: u64,
    /// Actual selected remote elements exposed before loss.
    pub elements: u64,
    /// Current unfinished input prefix.
    pub partial_input: usize,
    /// Actual unfinished writes, moved without an allocation at failure.
    pub pending: VecDeque<Pending>,
}
impl Loss {
    /// Actual retained request-table and still-owned payload capacities after
    /// physical retirement. A body transferred to the now-closed native stream
    /// is not charged through its old cached capacity a second time. Fixed
    /// report layout and opaque error/native allocations remain separate.
    pub fn retained_storage_bytes(&self) -> Result<usize, Fault> {
        let table = self
            .pending
            .capacity()
            .checked_mul(std::mem::size_of::<Pending>())
            .ok_or(Fault::Overflow)?;
        self.pending.iter().try_fold(table, |bytes, request| {
            bytes
                .checked_add(request.bytes.as_ref().map_or(0, Vec::capacity))
                .ok_or(Fault::Overflow)
        })
    }
}
impl fmt::Display for Loss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (joined={}, concluded={}, insert-writes={}, elements={}, pending={})",
            self.cause,
            self.joined,
            self.concluded,
            self.inserts_written,
            self.elements,
            self.pending.len()
        )
    }
}
impl fmt::Debug for Loss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for Loss {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
/// One actual official523 frame owned independently of future IO.
pub struct Observation {
    pub(crate) epoch: Epoch,
    pub(crate) ordinal: u64,
    pub(crate) frame: OwnedFrame,
}
impl Observation {
    /// Original physical source, never a replacement epoch.
    #[must_use]
    pub const fn epoch(&self) -> &Epoch {
        &self.epoch
    }
    /// Selected remote-element sequence, not a wire request ID.
    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }
    /// Actual original full frame.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.frame.bytes()
    }
    /// Actual retained original frame capacity, including spare bytes. The
    /// enclosing owner charges this allocation after native-source handoff.
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        self.frame.retained_bytes()
    }
    /// Borrow its actual typed response, without a new parser/profile guess.
    pub fn response(&self) -> Result<crate::ClientResponse<'_>, Fault> {
        crate::ClientResponse::decode(self.bytes())
    }
}
/// Actual caller-driven source progress.
pub enum Progress {
    /// Physical MQ attached; JOIN has not necessarily written.
    Attached(Epoch),
    /// Actual failed pre-attachment attempt; every mutation is still unexposed.
    Retry(io::Error),
    /// Actual whole original JOIN/INSERT/CONCLUDE write.
    Written(Receipt),
    /// Actual non-local official523 value.
    Element(Observation),
    /// Actual525 after the original whole CONCLUDE; physical MQ is now closed.
    Done {
        /// Original physical source.
        epoch: Epoch,
        /// Actual selected remote elements already exposed.
        elements: u64,
    },
    /// Bounded scheduling or physical partial progress, not completion.
    Activity,
    /// Actual physical close before successful525.
    Lost(Loss),
}
/// Explicit finite queue/input policy. No value changes the official wire.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum complete official frame.
    pub frame_bytes: usize,
    /// Maximum bytes per native read/write slice.
    pub io_slice_bytes: usize,
    /// Maximum original writes retained in FIFO.
    pub queued_frames: usize,
    /// Maximum encoded bytes retained for those original writes.
    pub queued_bytes: usize,
    /// Maximum distinct locally inserted application fingerprints.
    pub local_elements: usize,
    /// Actual SDK-owned request payload, queue metadata and local-fingerprint bound.
    /// Common native Framed input/output metadata has its separate frame/queue limits; this is not RSS.
    pub retained_bytes: usize,
    /// Fixed original setup timeout.
    pub initial_timeout: Duration,
    /// Fixed original write timeout, starting at local request admission.
    pub write_timeout: Duration,
    /// Fixed partial input timeout; positive bytes never renew it.
    pub input_timeout: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            frame_bytes: 65535,
            io_slice_bytes: 65535,
            queued_frames: 64,
            queued_bytes: 1024 * 1024,
            local_elements: 8192,
            retained_bytes: 4 * 1024 * 1024,
            initial_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            input_timeout: Duration::from_secs(10),
        }
    }
}
impl Limits {
    pub(crate) fn framing(self) -> Result<framing::Limits, Error> {
        if !(88..=65535).contains(&self.frame_bytes)
            || self.io_slice_bytes == 0
            || self.queued_frames == 0
            || self.queued_bytes < self.frame_bytes
            || self.local_elements == 0
            || self.initial_timeout.is_zero()
            || self.write_timeout.is_zero()
            || self.input_timeout.is_zero()
        {
            return Err(Fault::InvalidInput.into());
        }
        Ok(framing::Limits {
            frame_bytes: self.frame_bytes,
            ordinary: framing::Budget {
                frames: self.queued_frames,
                bytes: self.queued_bytes,
            },
            reserved: framing::Budget {
                frames: 0,
                bytes: 0,
            },
            accounting: framing::Accounting::Retained,
            io_slice_bytes: self.io_slice_bytes,
        })
    }
}
