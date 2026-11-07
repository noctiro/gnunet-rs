//! Persistent bounded official framing on one uniquely owned physical MQ.
//!
//! Framing reports bytes, never service credit, authentication or processing.
//! Ready RX storage is retained until explicitly released. A started TX frame
//! can only drain on its original socket or be discarded by retiring that MQ.
use crate::connection::Connection;
use gnunet_types::{Error, Rejected};
use gnunet_wire::official::{Frame, MessageHeader};
use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, ReadBuf};
use zeroize::{Zeroize, Zeroizing};

/// Frozen original bytes. Every drop path wipes their owned storage.
/// Admitting this value never calls a payload generator or exposes mutable bytes.
pub struct OwnedFrame(Zeroizing<Vec<u8>>);
impl OwnedFrame {
    /// Freeze caller-owned bytes without allocating or changing their contents.
    /// The caller's allocation capacity remains part of its storage choice.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }
    /// Allocate and freeze one exact copy, without performing I/O.
    pub fn copy_from(bytes: &[u8]) -> Result<Self, Error> {
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| Error::Capacity)?;
        owned.extend_from_slice(bytes);
        Ok(Self::new(owned))
    }
    /// Immutable original wire bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
    /// Original wire length, independent of its physical write cursor.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Actual retained byte-vector capacity, including its unused spare bytes.
    /// This reveals no payload, allocator overhead or process/OS memory usage.
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        self.0.capacity()
    }
    /// Whether the supplied bytes are empty; empty official frames are rejected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
/// Queue accounting selected by the enclosing domain's original budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Accounting {
    /// Charge whole admitted frame lengths until each completes.
    Retained,
    /// Charge remaining wire bytes, reclaiming every actual positive write.
    /// Physical storage also includes one written prefix and caller Vec capacity.
    Remaining,
}
/// Explicit queue resources; these fields carry no protocol meaning.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Budget {
    /// Maximum original frame records.
    pub frames: usize,
    /// Maximum charged wire bytes under the selected accounting policy.
    pub bytes: usize,
}
/// Original owner limits. A domain decides which messages may use extra budget.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Receive and outgoing single-frame limit, from4 through65535.
    pub frame_bytes: usize,
    /// Ordinary shared frame/byte capacity.
    pub ordinary: Budget,
    /// Additional capacity, explicitly selected by the domain for control work.
    pub reserved: Budget,
    /// Domain's original wire-byte accounting policy.
    pub accounting: Accounting,
    /// Maximum bytes offered in one native read/write operation; nonzero.
    pub io_slice_bytes: usize,
}
impl Limits {
    /// Validate native frame/queue resources without allocating or opening IO.
    pub fn validate(self) -> Result<(), Error> {
        if !(4..=65535).contains(&self.frame_bytes)
            || self.ordinary.frames == 0
            || self.ordinary.bytes < 4
            || self.io_slice_bytes == 0
        {
            return Err(Error::Capacity);
        }
        self.ordinary
            .frames
            .checked_add(self.reserved.frames)
            .ok_or(Error::Capacity)?;
        let bytes = self
            .ordinary
            .bytes
            .checked_add(self.reserved.bytes)
            .ok_or(Error::Capacity)?;
        if self.accounting == Accounting::Remaining {
            bytes.checked_add(self.frame_bytes).ok_or(Error::Capacity)?;
        }
        Ok(())
    }
}
/// Queue budget selection, without inspecting any business message type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Class {
    /// Use only ordinary limits.
    Ordinary,
    /// Use the ordinary limits plus the explicit additional budget.
    Reserved,
}
/// One physical RX step. EOF is not a processed frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadStep {
    /// Actual positive native input; complete storage stays until explicit release.
    Progress {
        /// Actual byte count from this native read.
        bytes: usize,
        /// Whether the complete current frame is now available.
        complete: bool,
    },
    /// Clean EOF between frames. A partial frame instead returns UnexpectedEof.
    Eof,
}
/// Distinguish transport wait from a locally deferred RX step. This carries no
/// epoch or application authority; an enclosing owner checks its retained input.
#[derive(Debug)]
pub enum ReadPoll {
    /// The original connection's native read returned Pending on this poll.
    NativePending,
    /// Existing complete/ended input or an interrupted read requires a later
    /// owner step; this is not evidence of a waiting native receive source.
    Deferred,
    /// One actual read result, with the same partial-cursor semantics as ReadStep.
    Ready(io::Result<ReadStep>),
}
/// Actual progress of one original frame, carrying the caller's opaque identity.
/// A completed physical write grants no service/window/delivery authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteProgress<Origin> {
    /// Exact caller-supplied original operation identity; framing never creates it.
    pub origin: Origin,
    /// Actual positive native transferred byte count.
    pub bytes: usize,
    /// Whether all bytes of this original frame have physically transferred.
    pub complete: bool,
}
/// One actual native write for a stream with no per-operation origin authority.
/// This deliberately supplies no synthetic per-frame operation receipts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamWriteProgress {
    /// Actual positive bytes transferred by exactly one native write operation.
    pub bytes: usize,
    /// Number of original frame records fully drained by that operation.
    pub completed_frames: usize,
}
/// Admission failure returns the unchanged original bytes and opaque identity.
pub type AdmissionFailure<Origin> = Rejected<(OwnedFrame, Origin)>;
struct Out<Origin> {
    frame: OwnedFrame,
    at: usize,
    origin: Origin,
}
struct FrameRx {
    input: Zeroizing<Vec<u8>>,
    used: usize,
    need: usize,
    ready: bool,
    ended: bool,
}
struct FrameTx<Origin> {
    output: VecDeque<Out<Origin>>,
    remaining: usize,
    retained: usize,
}
/// One physical connection with private persistent RX/TX state.
///
/// Removing a started frame, swapping the socket or clearing its queue is not
/// exposed. Construct another owner after retiring a physical MQ. Opaque origins
/// retain the enclosing domain's brands/epochs; this layer grants none of them.
/// Report every returned positive write to that original owner before processing
/// further service frames. Dropping a waiting future preserves all these fields.
pub struct Framed<Origin: Copy> {
    // Close the physical owner (and its dependent lease) before wiping buffers.
    connection: Option<Connection>,
    rx: FrameRx,
    tx: FrameTx<Origin>,
    limits: Limits,
}
impl<Origin: Copy> Framed<Origin> {
    /// Own one original connection. Validation/allocation performs no I/O.
    pub fn new(connection: Connection, limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        let mut input = Vec::new();
        input
            .try_reserve_exact(limits.frame_bytes)
            .map_err(|_| Error::Capacity)?;
        input.resize(limits.frame_bytes, 0);
        Ok(Self {
            connection: Some(connection),
            rx: FrameRx {
                input: Zeroizing::new(input),
                used: 0,
                need: 4,
                ready: false,
                ended: false,
            },
            tx: FrameTx {
                output: VecDeque::new(),
                remaining: 0,
                retained: 0,
            },
            limits,
        })
    }
    /// Actual retained dynamic storage: RX byte capacity, TX owner-table
    /// capacity and every original queued frame's byte capacity. Inline owner
    /// metadata, allocator overhead, socket buffers and process RSS are separate.
    /// This reads no payload and performs no allocation, native IO or mutation.
    pub fn retained_storage_bytes(&self) -> Result<usize, Error> {
        let table = self
            .tx
            .output
            .capacity()
            .checked_mul(std::mem::size_of::<Out<Origin>>())
            .ok_or(Error::Overflow)?;
        let initial = self
            .rx
            .input
            .capacity()
            .checked_add(table)
            .ok_or(Error::Overflow)?;
        self.tx.output.iter().try_fold(initial, |n, frame| {
            n.checked_add(frame.frame.retained_bytes())
                .ok_or(Error::Overflow)
        })
    }
    /// Change only the explicit extra budget, without reordering admitted work.
    pub fn set_reserved(&mut self, budget: Budget) -> Result<(), Error> {
        self.limits
            .ordinary
            .frames
            .checked_add(budget.frames)
            .ok_or(Error::Capacity)?;
        let total = self
            .limits
            .ordinary
            .bytes
            .checked_add(budget.bytes)
            .ok_or(Error::Capacity)?;
        if self.limits.accounting == Accounting::Remaining {
            total
                .checked_add(self.limits.frame_bytes)
                .ok_or(Error::Capacity)?;
        }
        let charged = self.charged_bytes();
        if self.tx.output.len() > self.limits.ordinary.frames + budget.frames
            || charged > self.limits.ordinary.bytes + budget.bytes
        {
            return Err(Error::WouldBlock);
        }
        self.limits.reserved = budget;
        Ok(())
    }
    /// Charged wire bytes under this owner's declared accounting policy.
    #[must_use]
    pub fn charged_bytes(&self) -> usize {
        match self.limits.accounting {
            Accounting::Retained => self.tx.retained,
            Accounting::Remaining => self.tx.remaining,
        }
    }
    /// Actual queued suffix bytes, independent of accounting and peer delivery.
    #[must_use]
    pub fn remaining_bytes(&self) -> usize {
        self.tx.remaining
    }
    /// Original queued frame count, including a partially written head.
    #[must_use]
    pub fn queued_frames(&self) -> usize {
        self.tx.output.len()
    }
    /// Explicit logical wire capacity. This is not an exact RSS bound.
    #[must_use]
    pub fn capacity(&self, bytes: usize, class: Class) -> bool {
        if self.connection.is_none() || !(4..=self.limits.frame_bytes).contains(&bytes) {
            return false;
        }
        let (frames, limit) = match class {
            Class::Ordinary => (self.limits.ordinary.frames, self.limits.ordinary.bytes),
            Class::Reserved => (
                self.limits.ordinary.frames + self.limits.reserved.frames,
                self.limits.ordinary.bytes + self.limits.reserved.bytes,
            ),
        };
        self.tx.output.len() < frames && bytes <= limit.saturating_sub(self.charged_bytes())
    }
    /// Preflight queue metadata without admitting bytes or consuming an origin.
    /// Preallocate the final immutable body too before irreversible domain work.
    pub fn reserve(&mut self, bytes: usize, class: Class) -> Result<(), Error> {
        if self.connection.is_none() {
            return Err(Error::Closed);
        }
        if !self.capacity(bytes, class) {
            return Err(Error::WouldBlock);
        }
        self.tx.output.try_reserve(1).map_err(|_| Error::Capacity)
    }
    /// Admit one immutable original frame and identity, with no body allocation.
    pub fn enqueue_owned(
        &mut self,
        frame: OwnedFrame,
        origin: Origin,
        class: Class,
    ) -> Result<(), AdmissionFailure<Origin>> {
        let checked = self
            .reserve(frame.len(), class)
            .and_then(|()| Frame::decode(frame.bytes()).map(|_| ()));
        if let Err(reason) = checked {
            return Err(Rejected {
                reason,
                value: (frame, origin),
            });
        }
        self.tx.remaining += frame.len();
        self.tx.retained += frame.len();
        self.tx.output.push_back(Out {
            frame,
            at: 0,
            origin,
        });
        Ok(())
    }
    /// Preflight and copy one borrowed frame into securely owned storage.
    pub fn enqueue_copy(
        &mut self,
        bytes: &[u8],
        origin: Origin,
        class: Class,
    ) -> Result<(), Error> {
        self.reserve(bytes.len(), class)?;
        Frame::decode(bytes)?;
        let frame = OwnedFrame::copy_from(bytes)?;
        self.enqueue_owned(frame, origin, class)
            .map_err(|rejected| rejected.reason)
    }
    /// Remove only zero-written originals; report each original identity once.
    /// The callbacks are synchronous and must not perform protocol I/O/reentry.
    pub fn remove_unwritten(
        &mut self,
        mut matches: impl FnMut(Origin, &[u8]) -> bool,
        mut removed: impl FnMut(Origin, usize),
    ) -> usize {
        let mut index = 0;
        let mut count = 0;
        while index < self.tx.output.len() {
            let remove = self
                .tx
                .output
                .get(index)
                .is_some_and(|out| out.at == 0 && matches(out.origin, out.frame.bytes()));
            if remove {
                if let Some(out) = self.tx.output.remove(index) {
                    let len = out.frame.len();
                    let origin = out.origin;
                    self.tx.remaining -= len;
                    self.tx.retained -= len;
                    count += 1;
                    // Complete removal, accounting and secure disposal before
                    // invoking caller code; a caught panic cannot poison them.
                    drop(out);
                    removed(origin, len);
                }
            } else {
                index += 1;
            }
        }
        count
    }
    /// Actual native bytes retained for the current input head, complete or
    /// partial. This includes a malformed header read before `poll_read`
    /// reports InvalidData. Explicit release or physical retirement resets it;
    /// the count grants no frame-processing or delivery authority.
    #[must_use]
    pub fn read_progress_bytes(&self) -> usize {
        self.rx.used
    }
    /// Current complete frame. Dropping this borrow does not release its storage.
    #[must_use]
    pub fn frame(&self) -> Option<&[u8]> {
        self.rx.ready.then_some(&self.rx.input[..self.rx.need])
    }
    /// Mutable complete-frame access for typed consumers that erase secret fields.
    /// It cannot change its retained length or touch a following frame.
    #[must_use]
    pub fn frame_mut(&mut self) -> Option<&mut [u8]> {
        self.rx.ready.then_some(&mut self.rx.input[..self.rx.need])
    }
    /// Wipe/release only complete current storage. This sends no ACK and reports
    /// no processing result. A premature call leaves any partial cursor intact.
    pub fn release_frame(&mut self) -> bool {
        if !self.rx.ready {
            return false;
        }
        self.rx.input[..self.rx.used].zeroize();
        self.rx.used = 0;
        self.rx.need = 4;
        self.rx.ready = false;
        true
    }
    /// Poll at most one exact native RX operation on this original connection.
    /// A terminal error requires retiring or dropping this owner before a new
    /// epoch/connection. It retains partial storage until then; canceled waits
    /// and Interrupted must retain the original cursor and are not terminal.
    pub fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<ReadStep>> {
        match self.poll_read_observed(cx) {
            ReadPoll::NativePending | ReadPoll::Deferred => Poll::Pending,
            ReadPoll::Ready(result) => Poll::Ready(result),
        }
    }
    /// The same single RX operation with an explicit distinction between a
    /// transport wait and local deferral. Interrupted input never grants native
    /// idleness. No extra storage, read, clock sample or frame decode is added.
    pub fn poll_read_observed(&mut self, cx: &mut Context<'_>) -> ReadPoll {
        if self.rx.ready || self.rx.ended {
            return ReadPoll::Deferred;
        }
        let Some(connection) = self.connection.as_mut() else {
            return ReadPoll::Ready(Err(io::ErrorKind::NotConnected.into()));
        };
        let end = self
            .rx
            .need
            .min(self.rx.used.saturating_add(self.limits.io_slice_bytes));
        let mut buf = ReadBuf::new(&mut self.rx.input[self.rx.used..end]);
        match Pin::new(connection).poll_read(cx, &mut buf) {
            Poll::Pending => ReadPoll::NativePending,
            Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {
                cx.waker().wake_by_ref();
                ReadPoll::Deferred
            }
            Poll::Ready(Err(e)) => ReadPoll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                let n = buf.filled().len();
                if n == 0 {
                    self.rx.ended = true;
                    return if self.rx.used == 0 {
                        ReadPoll::Ready(Ok(ReadStep::Eof))
                    } else {
                        ReadPoll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
                    };
                }
                self.rx.used += n;
                if self.rx.used == 4 && self.rx.need == 4 {
                    match MessageHeader::decode(&self.rx.input[..4]) {
                        Ok(header) if header.size() <= self.rx.input.len() => {
                            self.rx.need = header.size()
                        }
                        _ => {
                            self.rx.ended = true;
                            return ReadPoll::Ready(Err(io::ErrorKind::InvalidData.into()));
                        }
                    }
                }
                self.rx.ready = self.rx.used == self.rx.need;
                ReadPoll::Ready(Ok(ReadStep::Progress {
                    bytes: n,
                    complete: self.rx.ready,
                }))
            }
        }
    }
    /// Poll one original frame write; return exact native progress before the
    /// domain processes further service input. No credit or delivery is inferred.
    pub fn poll_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<WriteProgress<Origin>>> {
        let Some(connection) = self.connection.as_ref() else {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        };
        let Some(front) = self.tx.output.front_mut() else {
            return Poll::Pending;
        };
        match connection.poll_write_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        let end = front
            .frame
            .len()
            .min(front.at.saturating_add(self.limits.io_slice_bytes));
        match connection.try_write(&front.frame.bytes()[front.at..end]) {
            Ok(0) => Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
            Ok(n) => {
                front.at += n;
                self.tx.remaining -= n;
                let progress = WriteProgress {
                    origin: front.origin,
                    bytes: n,
                    complete: front.at == front.frame.len(),
                };
                if progress.complete {
                    self.tx.retained -= front.frame.len();
                    drop(self.tx.output.pop_front());
                }
                Poll::Ready(Ok(progress))
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
    /// Close this physical MQ before discarding partial originals and secrets.
    /// No reconnect, operation completion, replay or application callback occurs.
    pub fn retire(&mut self) {
        drop(self.connection.take());
        self.tx.output.clear();
        self.tx.remaining = 0;
        self.tx.retained = 0;
        self.rx.input.as_mut_slice().zeroize();
        self.rx.used = 0;
        self.rx.need = 4;
        self.rx.ready = false;
        self.rx.ended = true;
    }
}

impl Framed<()> {
    /// Write up to64 original frame suffixes with one native vectored operation,
    /// bounded by the same byte quantum as tagged writes. This path is only for
    /// owners without per-operation origins; tagged `poll_write` remains one
    /// frame/one exact opaque identity. Every successful poll reports exactly
    /// one actual positive native write, with no intermediate synthetic receipt.
    pub fn poll_write_untracked_batch(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<StreamWriteProgress>> {
        let Some(connection) = self.connection.as_ref() else {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        };
        if self.tx.output.is_empty() {
            return Poll::Pending;
        }
        match connection.poll_write_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        let written = {
            let mut slices = [io::IoSlice::new(&[]); 64];
            let mut count = 0;
            let mut remaining = self.limits.io_slice_bytes;
            for out in self.tx.output.iter().take(slices.len()) {
                let end = out.frame.len().min(out.at.saturating_add(remaining));
                slices[count] = io::IoSlice::new(&out.frame.bytes()[out.at..end]);
                remaining -= end - out.at;
                count += 1;
                if remaining == 0 {
                    break;
                }
            }
            connection.try_write_vectored(&slices[..count])
        };
        match written {
            Ok(0) => Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
            Ok(bytes) => {
                let mut left = bytes;
                let mut completed_frames = 0;
                self.tx.remaining -= bytes;
                while left > 0 {
                    // Native progress cannot exceed the offered original slices.
                    if let Some(front) = self.tx.output.front_mut() {
                        let advanced = left.min(front.frame.len() - front.at);
                        front.at += advanced;
                        left -= advanced;
                        if front.at == front.frame.len() {
                            self.tx.retained -= front.frame.len();
                            drop(self.tx.output.pop_front());
                            completed_frames += 1;
                        }
                    }
                }
                Poll::Ready(Ok(StreamWriteProgress {
                    bytes,
                    completed_frames,
                }))
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

#[cfg(test)]
#[path = "framing_tests.rs"]
mod tests;
