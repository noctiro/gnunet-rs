//! TRANSPORT's original remaining-wire-byte budget over shared framing.
use gnunet_service_runtime::{
    connection::Connection,
    framing::{Accounting, Budget, Class, Framed as Shared, Limits, OwnedFrame, ReadStep},
};
use gnunet_transport::dv_bridge::SendId;
use gnunet_types::Error;
use std::collections::VecDeque;
use std::{
    io,
    task::{Context, Poll},
};
struct Tag {
    start: u64,
    end: u64,
    send: SendId,
}
pub(crate) struct Framed {
    io: Shared<()>,
    // Only DV needs metadata. Ordinary batched frames use two checked byte
    // cursors, without an extra metadata row or allocation per ordinary frame.
    tags: VecDeque<Tag>,
    queued: u64,
    written: u64,
}
impl Framed {
    pub(crate) fn new(connection: Connection, capacity: usize) -> Result<Self, Error> {
        if capacity < 65535 {
            return Err(Error::Capacity);
        }
        // At most one original head may be partial. Every remaining complete
        // official frame needs at least4 bytes, so this adds no new concurrency cap.
        let frames = capacity / 4 + 1;
        let mut io = Shared::new(
            connection,
            Limits {
                frame_bytes: 65535,
                ordinary: Budget {
                    frames,
                    bytes: capacity,
                },
                reserved: Budget::default(),
                accounting: Accounting::Remaining,
                io_slice_bytes: usize::MAX,
            },
        )?;
        // Reserve the first metadata allocation before the domain admits this
        // physical client. Later metadata growth is explicitly fallible.
        io.reserve(4, Class::Ordinary)?;
        Ok(Self {
            io,
            tags: VecDeque::new(),
            queued: 0,
            written: 0,
        })
    }
    pub(crate) fn reserve(&mut self, bytes: usize) -> Result<(), Error> {
        self.queued
            .checked_add(u64::try_from(bytes).map_err(|_| Error::Overflow)?)
            .ok_or(Error::Overflow)?;
        self.io.reserve(bytes, Class::Ordinary)
    }
    pub(crate) fn reserve_tagged(&mut self, bytes: usize) -> Result<(), Error> {
        self.reserve(bytes)?;
        self.tags.try_reserve(1).map_err(|_| Error::Capacity)
    }
    pub(crate) fn queue_frame(
        &mut self,
        frame: OwnedFrame,
    ) -> Result<(), gnunet_types::Rejected<OwnedFrame>> {
        self.queue_tagged(frame, None)
    }
    pub(crate) fn queue_tagged(
        &mut self,
        frame: OwnedFrame,
        send: Option<SendId>,
    ) -> Result<(), gnunet_types::Rejected<OwnedFrame>> {
        if let Err(reason) = self.reserve(frame.len()) {
            return Err(gnunet_types::Rejected {
                reason,
                value: frame,
            });
        }
        if send.is_some()
            && let Err(reason) = self.tags.try_reserve(1).map_err(|_| Error::Capacity)
        {
            return Err(gnunet_types::Rejected {
                reason,
                value: frame,
            });
        }
        // reserve() already checked this cursor before any actual enqueue.
        let end = self.queued + frame.len() as u64;
        self.io
            .enqueue_owned(frame, (), Class::Ordinary)
            .map_err(|rejected| gnunet_types::Rejected {
                reason: rejected.reason,
                value: rejected.value.0,
            })?;
        if let Some(send) = send {
            self.tags.push_back(Tag {
                start: self.queued,
                end,
                send,
            });
        }
        self.queued = end;
        Ok(())
    }
    pub(crate) fn queue_owned(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
        self.queue_frame(OwnedFrame::new(bytes))
            .map_err(|rejected| rejected.reason)
    }
    /// Checked actual cumulative byte cursor, without per-frame sidecars.
    pub(crate) fn queued_cursor(&self) -> u64 {
        self.queued
    }
    /// Checked actual cumulative positive-write cursor on this original MQ.
    pub(crate) fn written_cursor(&self) -> u64 {
        self.written
    }
    pub(crate) fn frame(&self) -> Option<&[u8]> {
        self.io.frame()
    }
    pub(crate) fn release(&mut self) {
        self.io.release_frame();
    }
    pub(crate) fn queued_frames(&self) -> usize {
        self.io.queued_frames()
    }
    /// Original DV tags already admitted to this physical native queue.
    /// Whole writes remove tags only after their synchronous exposure callback.
    pub(crate) fn tagged_sends(&self) -> impl Iterator<Item = &SendId> {
        self.tags.iter().map(|tag| &tag.send)
    }
    pub(crate) fn poll_read_status(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<ReadStep>> {
        self.io.poll_read(cx)
    }
    pub(crate) fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_read_status(cx).map(|result| {
            result.and_then(|step| match step {
                ReadStep::Progress { .. } => Ok(()),
                ReadStep::Eof => Err(io::ErrorKind::UnexpectedEof.into()),
            })
        })
    }
    pub(crate) fn poll_write_status(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<gnunet_service_runtime::framing::StreamWriteProgress>> {
        self.poll_write_observed(cx, |_, _, _| {})
    }
    pub(crate) fn poll_write_observed(
        &mut self,
        cx: &mut Context<'_>,
        mut actual: impl FnMut(&SendId, usize, bool),
    ) -> Poll<io::Result<gnunet_service_runtime::framing::StreamWriteProgress>> {
        let progress = match self.io.poll_write_untracked_batch(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(p)) => p,
        };
        let before = self.written;
        let after = before
            .checked_add(progress.bytes as u64)
            .filter(|n| *n <= self.queued);
        let Some(after) = after else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "physical TX cursor exceeds admitted bytes",
            )));
        };
        while let Some(tag) = self.tags.front() {
            if tag.start >= after {
                break;
            }
            let n = after.min(tag.end).saturating_sub(before.max(tag.start));
            if n > 0 {
                actual(&tag.send, n as usize, after >= tag.end);
            }
            if after >= tag.end {
                self.tags.pop_front();
            } else {
                break;
            }
        }
        self.written = after;
        Poll::Ready(Ok(progress))
    }
    pub(crate) fn poll_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_write_status(cx).map(|result| result.map(|_| ()))
    }
}
