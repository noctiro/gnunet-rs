//! Shared actual CLIENT/framing reactor; no SET state machine is duplicated here.
use crate::{
    Bounds, DeadlineContext, DeadlineScope, DeadlineWrite, Epoch, Error, Limits,
    budget::NativeAlarm,
};
use gnunet_client_host::{
    EndpointSource,
    channel::{Channel, ConnectionStep},
};
use gnunet_service_runtime::{
    clock::RuntimeClock,
    framing::{self, Class, OwnedFrame, ReadStep},
};
use gnunet_types::Error as Fault;
use std::{
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};
pub(crate) trait WriteLabel: Copy + Eq {
    fn write_label(self) -> DeadlineWrite;
}
impl WriteLabel for u32 {
    fn write_label(self) -> DeadlineWrite {
        DeadlineWrite::Reject { accept_id: self }
    }
}
#[cfg(test)]
impl WriteLabel for u8 {
    fn write_label(self) -> DeadlineWrite {
        DeadlineWrite::Operation {
            request_id: u32::from(self),
        }
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
struct Origin<T: Copy> {
    tag: Option<T>,
}
struct Write<T: Copy> {
    tag: T,
    bound: Bounds,
}
/// Original actual transport exposure; local whole write is not processing.
#[derive(Clone, Debug)]
pub struct TransportLoss {
    /// Original attached physical source, if any.
    pub epoch: Option<Epoch>,
    /// Original initializer prefix actually written.
    pub initializer_bytes: usize,
    /// Original initializer whole write, without service acknowledgement.
    pub initializer_written: bool,
    /// Current original partial response bytes.
    pub partial_input: usize,
    /// Frames actually retained on this old native source.
    pub pending_frames: usize,
    /// Original queued wire bytes, without processing certainty.
    pub pending_bytes: usize,
}
pub(crate) enum Step<T: Copy> {
    Attached(Epoch),
    Retry(std::io::Error),
    Written {
        epoch: Epoch,
        tag: Option<T>,
        bytes: usize,
        complete: bool,
    },
    Frame {
        epoch: Epoch,
        bytes: Vec<u8>,
    },
    Activity,
    Eof,
}
pub(crate) struct Session<T: WriteLabel> {
    source: EndpointSource,
    channel: Channel<Origin<T>>,
    limits: Limits,
    overall: Bounds,
    initial: Option<Bounds>,
    input: Option<Bounds>,
    alarm: NativeAlarm,
    writes: Vec<Write<T>>,
    initializer: Vec<u8>,
    epoch: Option<Epoch>,
    initial_bytes: usize,
    initialized: bool,
    input_bytes: usize,
    read_first: bool,
    closed: bool,
}
impl<T: WriteLabel> Session<T> {
    pub fn new(
        source: EndpointSource,
        initializer: Vec<u8>,
        limits: Limits,
        original: Bounds,
    ) -> Result<Self, Error> {
        limits.validate()?;
        original.check_scoped(source.clock().as_ref(), DeadlineScope::Overall)?;
        if initializer.len() > limits.frame_bytes {
            return Err(Fault::TooLarge.into());
        }
        let native = framing::Limits {
            frame_bytes: limits.frame_bytes,
            ordinary: framing::Budget {
                frames: limits.queued_frames,
                bytes: limits.queued_bytes,
            },
            reserved: framing::Budget {
                frames: 2,
                bytes: limits.frame_bytes.checked_mul(2).ok_or(Fault::Overflow)?,
            },
            accounting: framing::Accounting::Retained,
            io_slice_bytes: limits.io_slice_bytes,
        };
        let initial = Bounds::phase(source.clock().as_ref(), limits.initial_timeout, original)?;
        // Channel construction has only validation and its actual Clock
        // subscription. Validate here so the remaining boundary is explicit.
        native.validate()?;
        let channel = Channel::new(source.duplicate()?, native).map_err(Error::Clock)?;
        Ok(Self {
            source,
            channel,
            limits,
            overall: original,
            initial: Some(initial),
            input: None,
            alarm: NativeAlarm::default(),
            writes: Vec::new(),
            initializer,
            epoch: None,
            initial_bytes: 0,
            initialized: false,
            input_bytes: 0,
            read_first: false,
            closed: false,
        })
    }
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.source.clock()
    }
    pub fn epoch(&self) -> Option<&Epoch> {
        self.epoch.as_ref()
    }
    pub fn ready(&self) -> bool {
        !self.closed && self.initialized && self.epoch.as_ref().is_some_and(Epoch::live)
    }
    pub fn original(&self) -> Bounds {
        self.overall
    }
    fn first_expired(&self, native: Instant, canonical: Option<u64>) -> Option<DeadlineContext> {
        let expired = |scope, bound: Bounds| {
            (native >= bound.hard || canonical.is_some_and(|now| now >= bound.expires))
                .then(|| DeadlineContext::at(scope, bound, native, canonical))
        };
        expired(DeadlineScope::Overall, self.overall)
            .or_else(|| {
                self.initial
                    .and_then(|bound| expired(DeadlineScope::Initial, bound))
            })
            .or_else(|| {
                self.input
                    .and_then(|bound| expired(DeadlineScope::PartialInput, bound))
            })
            .or_else(|| {
                self.writes.iter().find_map(|write| {
                    expired(DeadlineScope::Write(write.tag.write_label()), write.bound)
                })
            })
    }
    pub fn check(&self) -> Result<(), Error> {
        if self.closed {
            return Err(Fault::Closed.into());
        }
        if let Some(context) = self.first_expired(Instant::now(), None) {
            return Err(Error::deadline(context));
        }
        let now = self
            .source
            .clock()
            .sample()
            .map_err(Error::clock)?
            .now
            .as_micros();
        if let Some(context) = self.first_expired(Instant::now(), Some(now)) {
            return Err(Error::deadline(context));
        }
        Ok(())
    }
    pub fn native_expired(&mut self, cx: &mut Context<'_>) -> Option<DeadlineContext> {
        if self.closed {
            self.alarm.clear();
            return None;
        }
        // Preserve the original earliest native target and its first-owner tie
        // order. This guard records only native time; it never samples Clock.
        let (scope, bound) = core::iter::once((DeadlineScope::Overall, self.overall))
            .chain(self.initial.map(|bound| (DeadlineScope::Initial, bound)))
            .chain(self.input.map(|bound| (DeadlineScope::PartialInput, bound)))
            .chain(
                self.writes
                    .iter()
                    .map(|write| (DeadlineScope::Write(write.tag.write_label()), write.bound)),
            )
            .min_by_key(|(_, bound)| bound.hard)?;
        self.alarm
            .poll(cx, Some(bound.hard))
            .then(|| DeadlineContext::at(scope, bound, Instant::now(), None))
    }
    #[cfg(test)]
    pub(crate) fn input_state(&self) -> (Option<Bounds>, bool) {
        (
            self.input,
            self.channel
                .framing()
                .is_some_and(|framed| framed.frame().is_some()),
        )
    }
    pub fn enqueue(
        &mut self,
        bytes: Vec<u8>,
        tag: T,
        bounds: Bounds,
        control: bool,
    ) -> Result<(), Error> {
        self.check()?;
        if !self.ready() {
            return Err(Fault::NotReady.into());
        }
        bounds.check_scoped(
            self.source.clock().as_ref(),
            DeadlineScope::Write(tag.write_label()),
        )?;
        if self.writes.len() >= self.limits.queued_frames.saturating_add(2) {
            return Err(Fault::Capacity.into());
        }
        let mut bounded = Bounds::new(self.source.clock().as_ref(), self.limits.write_timeout)?;
        bounded.hard = bounded.hard.min(bounds.hard).min(self.overall.hard);
        bounded.expires = bounded
            .expires
            .min(bounds.expires)
            .min(self.overall.expires);
        self.writes.try_reserve(1).map_err(|_| Fault::Capacity)?;
        let frame = OwnedFrame::new(bytes);
        let class = if control {
            Class::Reserved
        } else {
            Class::Ordinary
        };
        self.channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .enqueue_owned(frame, Origin { tag: Some(tag) }, class)
            .map_err(|e| e.reason)?;
        self.writes.push(Write {
            tag,
            bound: bounded,
        });
        Ok(())
    }
    pub fn remove_unwritten(&mut self, tag: T) -> bool {
        let removed = self
            .channel
            .framing_mut()
            .is_some_and(|f| f.remove_unwritten(|o, _| o.tag == Some(tag), |_, _| {}) > 0);
        if removed {
            self.writes.retain(|w| w.tag != tag);
        }
        removed
    }
    pub fn contains(&self, tag: T) -> bool {
        self.writes.iter().any(|w| w.tag == tag)
    }
    pub fn phase(&self) -> Result<Bounds, Error> {
        let mut bounds = Bounds::new(self.source.clock().as_ref(), self.limits.write_timeout)?;
        bounds.expires = bounds.expires.min(self.overall.expires);
        bounds.hard = bounds.hard.min(self.overall.hard);
        Ok(bounds)
    }
    fn read(&mut self, cx: &mut Context<'_>) -> Poll<Result<Step<T>, Error>> {
        if !self.initialized {
            return Poll::Pending;
        }
        let framed = self.channel.framing_mut().ok_or(Fault::NotReady)?;
        if let Some(frame) = framed.frame() {
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(frame.len())
                .map_err(|_| Fault::Capacity)?;
            bytes.extend_from_slice(frame);
            if !framed.release_frame() {
                return Poll::Ready(Err(Fault::NotReady.into()));
            }
            self.input = None;
            self.input_bytes = 0;
            self.read_first = false;
            return Poll::Ready(Ok(Step::Frame {
                epoch: self.epoch.clone().ok_or(Fault::NotReady)?,
                bytes,
            }));
        }
        match framed.poll_read(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(Error::Io(e))),
            Poll::Ready(Ok(ReadStep::Eof)) => Poll::Ready(Ok(Step::Eof)),
            Poll::Ready(Ok(ReadStep::Progress { bytes, complete })) => {
                if bytes > 0 && !complete && self.input.is_none() {
                    self.input = Some(Bounds::phase(
                        self.source.clock().as_ref(),
                        self.limits.input_timeout,
                        self.overall,
                    )?);
                }
                self.input_bytes = self.input_bytes.checked_add(bytes).ok_or(Fault::Overflow)?;
                if let Some(context) = self.native_expired(cx) {
                    return Poll::Ready(Err(Error::deadline(context)));
                }
                self.check()?;
                // A complete frame ends only this partial-response phase. An
                // existing partial target was checked above before clearing;
                // overall/operation/write bounds remain independently active.
                if complete {
                    self.input = None;
                }
                self.read_first = false;
                Poll::Ready(Ok(Step::Activity))
            }
        }
    }
    fn write(&mut self, cx: &mut Context<'_>) -> Poll<Result<Step<T>, Error>> {
        match self
            .channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .poll_write(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(Error::Io(e))),
            Poll::Ready(Ok(w)) => {
                if w.origin.tag.is_none() {
                    self.initial_bytes = self
                        .initial_bytes
                        .checked_add(w.bytes)
                        .ok_or(Fault::Overflow)?;
                    if w.complete {
                        self.initialized = true;
                        self.initial = None;
                    }
                } else if w.complete {
                    let tag = w.origin.tag.ok_or(Fault::NotReady)?;
                    let at = self
                        .writes
                        .iter()
                        .position(|r| r.tag == tag)
                        .ok_or(Fault::Stale)?;
                    self.writes.remove(at);
                }
                self.read_first = true;
                Poll::Ready(Ok(Step::Written {
                    epoch: self.epoch.clone().ok_or(Fault::NotReady)?,
                    tag: w.origin.tag,
                    bytes: w.bytes,
                    complete: w.complete,
                }))
            }
        }
    }
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Step<T>, Error>> {
        if let Some(context) = self.native_expired(cx) {
            return Poll::Ready(Err(Error::deadline(context)));
        }
        self.check()?;
        match self.channel.poll_clock(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(r) => r.map_err(Error::Clock)?,
        }
        self.check()?;
        if self.epoch.is_none() {
            return match self.channel.poll_connect(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(e)) => Poll::Ready(Err(Error::Client(e))),
                Poll::Ready(Ok(ConnectionStep::Unavailable(e))) => {
                    Poll::Ready(Err(Error::Client(e)))
                }
                Poll::Ready(Ok(ConnectionStep::Retry { error, .. })) => {
                    Poll::Ready(Ok(Step::Retry(error)))
                }
                Poll::Ready(Ok(ConnectionStep::Attached)) => {
                    if let Some(context) = self.native_expired(cx) {
                        return Poll::Ready(Err(Error::deadline(context)));
                    }
                    self.check()?;
                    self.channel
                        .framing_mut()
                        .ok_or(Fault::NotReady)?
                        .enqueue_copy(&self.initializer, Origin { tag: None }, Class::Reserved)?;
                    let epoch = Epoch::new();
                    self.epoch = Some(epoch.clone());
                    Poll::Ready(Ok(Step::Attached(epoch)))
                }
            };
        }
        for offset in 0..2 {
            if let Some(context) = self.native_expired(cx) {
                return Poll::Ready(Err(Error::deadline(context)));
            }
            self.check()?;
            let result = if self.read_first == (offset == 0) {
                self.read(cx)
            } else {
                self.write(cx)
            };
            if result.is_ready() {
                return result;
            }
        }
        Poll::Pending
    }
    pub fn retire(&mut self, permanent: bool) -> TransportLoss {
        // Framed can retain a malformed header before returning an error,
        // without producing ReadStep::Progress. Capture that actual original
        // prefix before closing/detaching the shared Set/Listener source. The
        // counters describe the same head, so take max rather than add them.
        let (pending_frames, pending_bytes, partial_input) =
            self.channel
                .framing()
                .map_or((0, 0, self.input_bytes), |f| {
                    (
                        f.queued_frames(),
                        f.charged_bytes(),
                        self.input_bytes.max(f.read_progress_bytes()),
                    )
                });
        let loss = TransportLoss {
            epoch: self.epoch.clone(),
            initializer_bytes: self.initial_bytes,
            initializer_written: self.initialized,
            partial_input,
            pending_frames,
            pending_bytes,
        };
        if permanent {
            self.channel.close();
            self.closed = true;
        } else {
            self.channel.detach();
        }
        if let Some(epoch) = self.epoch.take() {
            epoch.retire();
        }
        self.initial = None;
        self.input = None;
        self.writes.clear();
        self.alarm.clear();
        self.input_bytes = 0;
        self.initialized = false;
        loss
    }
    pub fn retry(&mut self) -> Result<(), Error> {
        if self.closed {
            return Err(Fault::Closed.into());
        }
        self.channel.schedule_retry()?;
        self.initial = Some(Bounds::phase(
            self.source.clock().as_ref(),
            self.limits.initial_timeout,
            self.overall,
        )?);
        self.initial_bytes = 0;
        Ok(())
    }
}
impl<T: WriteLabel> Drop for Session<T> {
    fn drop(&mut self) {
        let _actual = self.retire(true);
    }
}

#[cfg(all(test, unix))]
mod tests;

#[cfg(all(test, unix))]
mod provenance_tests;
