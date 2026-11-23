//! Native whole-packet I/O with one source-bound DNS effect and fixed deadline.
use super::{PacketExposure, Retirement, SourceEvent, Write, raw};
use crate::{Error, core};
use gnunet_service_runtime::framing::OwnedFrame;
use gnunet_tun_host::{AsyncTun, Loss, ReadEvent, Unsent, WriteEvent, WriteId};
use gnunet_types::Error as Fault;
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};
struct Pending<'id> {
    effect: core::Effect<'id>,
    write: WriteId,
    bytes: usize,
    until: Instant,
}
struct Stopped<'id> {
    effect: core::Effect<'id>,
    total: usize,
    reason: Unsent,
}
impl<'id> Stopped<'id> {
    fn into_event(self) -> SourceEvent<'id> {
        let reason = match self.reason {
            Unsent::Cancelled => Fault::Cancelled,
            Unsent::Deadline => Fault::Deadline,
        };
        SourceEvent::OutputStopped {
            effect: self.effect,
            exposure: PacketExposure::UnsubmittedPacket,
            total: self.total,
            reason: reason.into(),
        }
    }
}
pub(super) struct Device<'id> {
    tun: AsyncTun,
    pending: Option<Pending<'id>>,
    stopped: Option<Stopped<'id>>,
    retirement: Option<Loss>,
    closed: bool,
    timer: Pin<Box<Sleep>>,
    read_first: bool,
}
impl<'id> Device<'id> {
    pub fn new(tun: AsyncTun) -> Self {
        Self {
            tun,
            pending: None,
            stopped: None,
            retirement: None,
            closed: false,
            timer: Box::pin(tokio::time::sleep_until(Instant::now())),
            read_first: false,
        }
    }
    pub fn initialized(&self) -> bool {
        !self.closed && self.tun.epoch().current()
    }
    pub fn writable(&self) -> bool {
        self.initialized() && self.pending.is_none() && self.stopped.is_none()
    }
    pub fn packet_capacity(&self) -> usize {
        self.tun.packet_capacity()
    }
    pub fn pending(&self) -> Option<(core::Effect<'id>, usize, usize)> {
        self.pending
            .as_ref()
            .map(|pending| (pending.effect, 0, pending.bytes))
            .or_else(|| {
                self.stopped
                    .as_ref()
                    .map(|stopped| (stopped.effect, 0, stopped.total))
            })
    }
    pub fn cancel_output(&mut self, request: core::Request<'id>) -> Result<(), Error> {
        if self
            .stopped
            .as_ref()
            .is_some_and(|stopped| stopped.effect.request() == request)
        {
            return Ok(());
        }
        let pending = self
            .pending
            .as_ref()
            .filter(|pending| pending.effect.request() == request)
            .ok_or(Fault::StaleGeneration)?;
        match self.tun.cancel(&pending.write)? {
            WriteEvent::Unsent { write, reason } if write == pending.write => {
                let pending = self.pending.take().ok_or(Fault::StaleGeneration)?;
                self.stopped = Some(Stopped {
                    effect: pending.effect,
                    total: pending.bytes,
                    reason,
                });
                Ok(())
            }
            _ => Err(Fault::Conflict.into()),
        }
    }
    pub fn queue(
        &mut self,
        effect: core::Effect<'id>,
        frame: OwnedFrame,
        until: Instant,
    ) -> Result<(), (Error, OwnedFrame)> {
        if self.closed {
            return Err((Fault::Closed.into(), frame));
        }
        if self.pending.is_some() || self.stopped.is_some() {
            return Err((Fault::WouldBlock.into(), frame));
        }
        if Instant::now() >= until {
            return Err((Fault::Deadline.into(), frame));
        }
        let bytes = frame.len();
        match self.tun.queue(frame.bytes(), until) {
            Ok(write) => {
                self.pending = Some(Pending {
                    effect,
                    write,
                    bytes,
                    until,
                });
                Ok(())
            }
            Err(error) => Err((error.into(), frame)),
        }
    }
    fn lost(&mut self, loss: Loss) {
        self.closed = true;
        self.retirement = Some(loss);
    }
    pub fn close(&mut self) {
        if !self.closed {
            let loss = self.tun.close();
            self.lost(loss);
        }
    }
    pub fn poll_retirement(&mut self) -> Poll<Retirement> {
        self.retirement
            .take()
            .map_or(Poll::Pending, |loss| Poll::Ready(Retirement::Device(loss)))
    }
    pub fn poll_guard(&mut self, cx: &mut Context<'_>) -> Poll<SourceEvent<'id>> {
        if let Some(stopped) = self.stopped.take() {
            return Poll::Ready(stopped.into_event());
        }
        if let Poll::Ready(retired) = self.poll_retirement() {
            return Poll::Ready(SourceEvent::Retired(retired));
        }
        if let Some(pending) = &self.pending {
            if Instant::now() >= pending.until {
                return Poll::Ready(match self.cancel_output(pending.effect.request()) {
                    Ok(()) => SourceEvent::Activity,
                    Err(error) => SourceEvent::Failed(io::Error::other(error)),
                });
            }
            self.timer.as_mut().reset(pending.until);
            if self.timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
        Poll::Pending
    }
    fn read(&mut self, cx: &mut Context<'_>) -> Poll<SourceEvent<'id>> {
        match self.tun.poll_read(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(ReadEvent::Packet(packet)) => {
                Poll::Ready(SourceEvent::Input(raw::device(packet)))
            }
            Poll::Ready(ReadEvent::Lost(loss)) => {
                self.lost(loss);
                self.poll_guard(cx)
            }
            Poll::Ready(ReadEvent::WriteExpired(write)) => self.unsent(write, Unsent::Deadline),
            Poll::Ready(ReadEvent::Rejected(_) | ReadEvent::WaitDeadline) => {
                Poll::Ready(SourceEvent::Activity)
            }
            Poll::Ready(ReadEvent::Closed) => Poll::Ready(SourceEvent::Failed(io::Error::other(
                "DNS original TUN closed without a retirement receipt",
            ))),
        }
    }
    fn unsent(&mut self, write: WriteId, reason: Unsent) -> Poll<SourceEvent<'id>> {
        if !self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.write == write)
        {
            return Poll::Ready(SourceEvent::Failed(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS native write lost original correlation",
            )));
        }
        let Some(pending) = self.pending.take() else {
            return Poll::Pending;
        };
        let stopped = Stopped {
            effect: pending.effect,
            total: pending.bytes,
            reason,
        };
        Poll::Ready(stopped.into_event())
    }
    fn write(&mut self, cx: &mut Context<'_>) -> Poll<SourceEvent<'id>> {
        if self.pending.is_none() {
            return Poll::Pending;
        }
        match self.tun.poll_write(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(WriteEvent::Written {
                write,
                raw_bytes: bytes,
            }) => {
                let Some(pending) = self.pending.as_ref() else {
                    return Poll::Ready(SourceEvent::Failed(io::Error::other(
                        "DNS native write metadata missing",
                    )));
                };
                if pending.write != write || pending.bytes != bytes {
                    return Poll::Ready(SourceEvent::Failed(io::Error::other(
                        "DNS native write result did not match its original packet",
                    )));
                }
                let effect = pending.effect;
                self.pending = None;
                Poll::Ready(SourceEvent::Written {
                    effect,
                    observation: Write::Device { bytes },
                })
            }
            Poll::Ready(WriteEvent::Lost(loss)) => {
                self.lost(loss);
                self.poll_guard(cx)
            }
            Poll::Ready(WriteEvent::Unsent { write, reason }) => self.unsent(write, reason),
            Poll::Ready(WriteEvent::WaitDeadline) => Poll::Pending,
            Poll::Ready(WriteEvent::Idle | WriteEvent::Closed) => Poll::Ready(SourceEvent::Failed(
                io::Error::other("DNS original native write disappeared"),
            )),
        }
    }
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<SourceEvent<'id>> {
        if let ready @ Poll::Ready(_) = self.poll_guard(cx) {
            return ready;
        }
        if self.closed {
            return Poll::Pending;
        }
        for read in [self.read_first, !self.read_first] {
            let event = if read { self.read(cx) } else { self.write(cx) };
            if event.is_ready() {
                self.read_first = !read;
                return event;
            }
        }
        Poll::Pending
    }
}
impl Drop for Device<'_> {
    fn drop(&mut self) {
        self.close();
    }
}
