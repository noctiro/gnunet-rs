//! Shared original-MQ I/O; no NAT business callback is invented by this layer.
use crate::*;
use gnunet_client_host::channel::{Channel, ConnectionStep};
use gnunet_service_runtime::{
    clock::{Deadline, RuntimeClock},
    framing::{Accounting, Budget, Class, Limits as FrameLimits, OwnedFrame, ReadStep},
};
use gnunet_types::Error as Fault;
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
#[derive(Clone, Copy)]
struct Origin<'id> {
    epoch: Epoch<'id>,
    write: WriteId<'id>,
}
struct Pending<'id> {
    id: WriteId<'id>,
    command: Command,
    source: Option<OwnedFrame>,
    total: usize,
    sent: usize,
    until: u64,
    hard: Instant,
    queued: bool,
}
impl Pending<'_> {
    fn submission(&self) -> Submission {
        if self.sent == 0 {
            Submission::Unsent
        } else if self.sent == self.total {
            Submission::Written { bytes: self.total }
        } else {
            Submission::Partial {
                bytes: self.sent,
                total: self.total,
            }
        }
    }
}
pub(crate) enum Step<'id> {
    Connected(Epoch<'id>),
    Queued(WriteId<'id>, Epoch<'id>, Command),
    Written(WriteId<'id>, Epoch<'id>, Command, usize),
    Activity(usize, usize),
    Input,
    Retired(WriteEnd<'id>),
    Ended(SourceEnd<'id>),
    Retry(std::io::Error, Duration),
    WaitDeadline,
    Closed,
}
pub(crate) struct Io<'id> {
    pub session: Session<'id>,
    pub epoch: Option<Epoch<'id>>,
    channel: Channel<Origin<'id>>,
    pub clock: Arc<dyn RuntimeClock>,
    limits: Limits,
    deadlines: Deadlines,
    hard: Option<Instant>,
    send_hard: Instant,
    first_hard: Option<Instant>,
    input_hard: Option<Instant>,
    input_until: Option<u64>,
    input_seen: bool,
    pub initial_written: bool,
    initial_total: usize,
    initial_sent: usize,
    pending: VecDeque<Pending<'id>>,
    source_bytes: usize,
    next: u64,
    end_storage: Vec<WriteEnd<'id>>,
    deferred: Option<SourceEnd<'id>>,
    alarm: Option<Pin<Box<Deadline>>>,
    alarm_at: Option<u64>,
    native: Option<Pin<Box<Sleep>>>,
    pause: Option<Instant>,
    pub closed: bool,
    read_first: bool,
}
impl<'id> Io<'id> {
    pub fn new(
        instance: &'id Instance,
        source: EndpointSource,
        first: OwnedFrame,
        command: Command,
        deadlines: Deadlines,
        limits: Limits,
    ) -> Result<Self, Error> {
        // Native maximum for a long-lived observer starts before any source or
        // canonical sampling. Caller-derived absolute targets may span rollback.
        let started = Instant::now();
        limits.validate()?;
        if first.len() > limits.frame_bytes || first.len() > limits.source_bytes {
            return Err(Fault::Capacity.into());
        }
        let source = source.snapshot()?;
        let clock = source.clock();
        let at = if deadlines.until == u64::MAX {
            started
        } else {
            Instant::now()
        };
        let now = clock.sample().map_err(Error::Clock)?.now.as_micros();
        if deadlines.send_until <= now
            || deadlines.send_until > deadlines.until
            || deadlines.send_until == u64::MAX
            || deadlines.until == u64::MAX && command != Command::Register
            || deadlines
                .first_input_until
                .is_some_and(|d| d == u64::MAX || d < deadlines.send_until || d > deadlines.until)
        {
            return Err(Fault::Deadline.into());
        }
        let hard = if deadlines.until == u64::MAX {
            None
        } else {
            Some(
                at.checked_add(Duration::from_micros(deadlines.until - now))
                    .ok_or(Fault::Overflow)?,
            )
        };
        let send_delay = Duration::from_micros(deadlines.send_until - now);
        let send_delay = if hard.is_none() {
            send_delay.min(limits.write_lifetime)
        } else {
            send_delay
        };
        let send_hard = at.checked_add(send_delay).ok_or(Fault::Overflow)?;
        let send_hard = hard.map_or(send_hard, |bound| send_hard.min(bound));
        let first_hard = deadlines
            .first_input_until
            .map(|d| {
                let delay = Duration::from_micros(d - now);
                let delay = if hard.is_none() {
                    delay.min(limits.input_lifetime)
                } else {
                    delay
                };
                at.checked_add(delay).ok_or(Fault::Overflow)
            })
            .transpose()?;
        let brand = types::Brand::new(instance)?;
        let session = Session { brand, serial: 0 };
        let id = WriteId { brand, serial: 1 };
        let total = first.len();
        let mut pending = VecDeque::new();
        pending
            .try_reserve_exact(limits.writes)
            .map_err(|_| Fault::Capacity)?;
        pending.push_back(Pending {
            id,
            command,
            source: Some(first),
            total,
            sent: 0,
            until: deadlines.send_until,
            hard: send_hard,
            queued: false,
        });
        let mut end_storage = Vec::new();
        end_storage
            .try_reserve_exact(limits.writes)
            .map_err(|_| Fault::Capacity)?;
        let channel = Channel::new(
            source,
            FrameLimits {
                frame_bytes: limits.frame_bytes,
                ordinary: Budget {
                    frames: 1,
                    bytes: limits.frame_bytes,
                },
                reserved: Budget::default(),
                accounting: Accounting::Retained,
                io_slice_bytes: limits.io_slice_bytes,
            },
        )?;
        Ok(Self {
            session,
            epoch: None,
            channel,
            clock,
            limits,
            deadlines,
            hard,
            send_hard,
            first_hard,
            input_hard: None,
            input_until: None,
            input_seen: false,
            initial_written: false,
            initial_total: total,
            initial_sent: 0,
            pending,
            source_bytes: total,
            next: 1,
            end_storage,
            deferred: None,
            alarm: None,
            alarm_at: None,
            native: None,
            pause: None,
            closed: false,
            read_first: false,
        })
    }
    pub fn initial(&self) -> Submission {
        if self.initial_sent == 0 {
            Submission::Unsent
        } else if self.initial_sent == self.initial_total {
            Submission::Written {
                bytes: self.initial_total,
            }
        } else {
            Submission::Partial {
                bytes: self.initial_sent,
                total: self.initial_total,
            }
        }
    }
    pub fn initial_id(&self) -> WriteId<'id> {
        WriteId {
            brand: self.session.brand,
            serial: 1,
        }
    }
    fn end(&mut self, cause: Cause, trigger: Option<WriteId<'id>>) -> SourceEnd<'id> {
        self.channel.close();
        self.closed = true;
        self.alarm = None;
        self.native = None;
        self.pause = None;
        self.input_hard = None;
        self.input_until = None;
        for p in self.pending.drain(..) {
            self.end_storage.push(WriteEnd {
                write: p.id,
                command: p.command,
                submission: p.submission(),
            });
        }
        self.source_bytes = 0;
        SourceEnd {
            session: self.session,
            epoch: self.epoch,
            cause,
            trigger,
            initial: self.initial(),
            writes: std::mem::take(&mut self.end_storage),
        }
    }
    pub fn close(&mut self, cause: Cause, trigger: Option<WriteId<'id>>) -> Option<SourceEnd<'id>> {
        if let Some(end) = self.deferred.take() {
            return Some(end);
        }
        if self.closed {
            None
        } else {
            Some(self.end(cause, trigger))
        }
    }
    pub fn pending_writes(&self) -> usize {
        self.pending.len()
    }
    pub fn admit(
        &mut self,
        frame: OwnedFrame,
        command: Command,
        until: u64,
    ) -> Result<WriteId<'id>, Error> {
        let started = Instant::now();
        if self.closed {
            return Err(Fault::Closed.into());
        }
        if self.input_hard.is_some_and(|at| Instant::now() >= at) {
            let end = self.end(Cause::InputDeadline, None);
            self.deferred = Some(end);
            return Err(Fault::Deadline.into());
        }
        if self.pending.len() == self.limits.writes
            || frame.len() > self.limits.frame_bytes
            || self
                .source_bytes
                .checked_add(frame.len())
                .is_none_or(|n| n > self.limits.source_bytes)
        {
            return Err(Fault::Capacity.into());
        }
        let at = if self.hard.is_none() {
            started
        } else {
            Instant::now()
        };
        let now = match self.clock.sample() {
            Ok(s) => s.now.as_micros(),
            Err(error) => {
                let end = self.end(Cause::Clock(error), None);
                self.deferred = Some(end);
                return Err(Error::Clock(error));
            }
        };
        if self.input_until.is_some_and(|bound| now >= bound) {
            let end = self.end(Cause::InputDeadline, None);
            self.deferred = Some(end);
            return Err(Fault::Deadline.into());
        }
        if until <= now || until > self.deadlines.until || until == u64::MAX {
            return Err(Fault::Deadline.into());
        }
        let delay = Duration::from_micros(until - now);
        let delay = if self.hard.is_none() {
            delay.min(self.limits.write_lifetime)
        } else {
            delay
        };
        let hard = at.checked_add(delay).ok_or(Fault::Overflow)?;
        let hard = self.hard.map_or(hard, |bound| hard.min(bound));
        let next = self.next.checked_add(1).ok_or(Fault::Overflow)?;
        let id = WriteId {
            brand: self.session.brand,
            serial: next,
        };
        let total = frame.len();
        self.pending.push_back(Pending {
            id,
            command,
            source: Some(frame),
            total,
            sent: 0,
            until,
            hard,
            queued: false,
        });
        self.next = next;
        self.source_bytes += total;
        Ok(id)
    }
    pub fn submission(&self, id: WriteId<'id>) -> Result<Submission, Error> {
        if !self.session.brand.owns(id.brand) {
            return Err(Fault::Stale.into());
        }
        self.pending
            .iter()
            .find(|p| p.id == id)
            .map(Pending::submission)
            .ok_or_else(|| Fault::Stale.into())
    }
    fn remove(&mut self, index: usize) -> Result<WriteEnd<'id>, Error> {
        let p = self.pending.get(index).ok_or(Fault::Stale)?;
        if p.sent != 0 {
            return Err(Fault::Conflict.into());
        }
        if p.queued {
            let id = p.id;
            let count = self
                .channel
                .framing_mut()
                .ok_or(Fault::Stale)?
                .remove_unwritten(|o, _| o.write == id, |_, _| {});
            if count != 1 {
                return Err(Fault::Stale.into());
            }
        }
        let p = self.pending.remove(index).ok_or(Fault::Stale)?;
        self.source_bytes -= p.total;
        Ok(WriteEnd {
            write: p.id,
            command: p.command,
            submission: Submission::Unsent,
        })
    }
    pub fn cancel(
        &mut self,
        id: WriteId<'id>,
    ) -> Result<Result<WriteEnd<'id>, SourceEnd<'id>>, Error> {
        if self.closed {
            return Err(Fault::Closed.into());
        }
        let i = self
            .pending
            .iter()
            .position(|p| p.id == id)
            .ok_or(Fault::Stale)?;
        if id == self.initial_id() || self.pending[i].sent > 0 {
            Ok(Err(self.end(Cause::Cancelled, Some(id))))
        } else {
            Ok(Ok(self.remove(i)?))
        }
    }
    pub fn frame(&self) -> Option<&[u8]> {
        self.channel.framing().and_then(|f| f.frame())
    }
    pub fn copy_input(&mut self) -> Result<OwnedFrame, Fault> {
        let frame = OwnedFrame::copy_from(self.frame().ok_or(Fault::NotReady)?)?;
        self.channel
            .framing_mut()
            .ok_or(Fault::Stale)?
            .release_frame();
        self.input_seen = true;
        Ok(frame)
    }
    pub fn release_input(&mut self) -> Result<(), Error> {
        if self.closed {
            return Err(Fault::Closed.into());
        }
        let Some(hard) = self.input_hard else {
            return Ok(());
        };
        // Native guard first, even if the canonical source cannot be sampled.
        // On failure the domain retains its actual held notification until the
        // deferred original SourceEnd is observed (or explicit close takes it).
        if Instant::now() >= hard {
            let end = self.end(Cause::InputDeadline, None);
            self.deferred = Some(end);
            return Err(Fault::Deadline.into());
        }
        let now = match self.clock.sample() {
            Ok(sample) => sample.now.as_micros(),
            Err(error) => {
                let end = self.end(Cause::Clock(error), None);
                self.deferred = Some(end);
                return Err(Error::Clock(error));
            }
        };
        if Instant::now() >= hard || self.input_until.is_some_and(|bound| now >= bound) {
            let end = self.end(Cause::InputDeadline, None);
            self.deferred = Some(end);
            return Err(Fault::Deadline.into());
        }
        self.input_hard = None;
        self.input_until = None;
        Ok(())
    }
    pub fn pause_capacity(&mut self) -> Result<(), Error> {
        self.pause = Some(
            Instant::now()
                .checked_add(self.limits.capacity_retry)
                .ok_or(Fault::Overflow)?,
        );
        Ok(())
    }
    fn expiry(&mut self, now: Option<u64>) -> Result<Option<Step<'id>>, Error> {
        let at = Instant::now();
        if self.hard.is_some_and(|bound| at >= bound)
            || now.is_some_and(|n| self.deadlines.until != u64::MAX && n >= self.deadlines.until)
        {
            return Ok(Some(Step::Ended(self.end(Cause::Deadline, None))));
        }
        if self.input_hard.is_some_and(|bound| at >= bound)
            || now.is_some_and(|n| self.input_until.is_some_and(|bound| n >= bound))
        {
            return Ok(Some(Step::Ended(self.end(Cause::InputDeadline, None))));
        }
        if !self.initial_written
            && (at >= self.send_hard || now.is_some_and(|n| n >= self.deadlines.send_until))
        {
            return Ok(Some(Step::Ended(
                self.end(Cause::WriteDeadline, Some(self.initial_id())),
            )));
        }
        if !self.input_seen
            && (self.first_hard.is_some_and(|h| at >= h)
                || now.is_some_and(|n| self.deadlines.first_input_until.is_some_and(|d| n >= d)))
        {
            return Ok(Some(Step::Ended(self.end(Cause::FirstInputDeadline, None))));
        }
        if let Some(i) = self
            .pending
            .iter()
            .position(|p| at >= p.hard || now.is_some_and(|n| n >= p.until))
        {
            let id = self.pending[i].id;
            if id == self.initial_id() || self.pending[i].sent > 0 {
                return Ok(Some(Step::Ended(self.end(Cause::WriteDeadline, Some(id)))));
            }
            return Ok(Some(Step::Retired(self.remove(i)?)));
        }
        Ok(None)
    }
    fn native_target(&self) -> Option<Instant> {
        self.pending
            .iter()
            .map(|p| p.hard)
            .chain((!self.initial_written).then_some(self.send_hard))
            .chain((!self.input_seen).then_some(self.first_hard).flatten())
            .chain(self.pause.filter(|at| *at > Instant::now()))
            .chain(self.hard)
            .chain(self.input_hard)
            .min()
    }
    fn register_native(&mut self, cx: &mut Context<'_>, wait: Option<Instant>) {
        let Some(target) = self.native_target().into_iter().chain(wait).min() else {
            self.native = None;
            return;
        };
        let native = self
            .native
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(target)));
        native.as_mut().reset(target);
        let _ready = native.as_mut().poll(cx);
    }
    fn read_one(
        &mut self,
        cx: &mut Context<'_>,
        now: u64,
        wait: Option<Instant>,
    ) -> Poll<Result<Step<'id>, Error>> {
        self.pause = None;
        if self.frame().is_some() {
            if !self.initial_written {
                return Poll::Ready(Err(Fault::Malformed.into()));
            }
            return Poll::Ready(Ok(Step::Input));
        }
        let started = Instant::now();
        match self
            .channel
            .framing_mut()
            .ok_or(Fault::Stale)?
            .poll_read(cx)
        {
            Poll::Ready(Ok(ReadStep::Eof)) => {
                Poll::Ready(Ok(Step::Ended(self.end(Cause::Eof, None))))
            }
            Poll::Ready(Err(error)) => {
                Poll::Ready(Ok(Step::Ended(self.end(Cause::Io(error), None))))
            }
            Poll::Ready(Ok(ReadStep::Progress { bytes, complete })) => {
                if self.hard.is_none() && bytes > 0 && self.input_hard.is_none() {
                    let micros = u64::try_from(self.limits.input_lifetime.as_micros())
                        .map_err(|_| Fault::Overflow)?;
                    let until = now
                        .checked_add(micros)
                        .filter(|n| *n != u64::MAX)
                        .ok_or(Fault::Overflow)?;
                    let hard = started
                        .checked_add(self.limits.input_lifetime)
                        .ok_or(Fault::Overflow)?;
                    self.input_until = Some(until);
                    self.input_hard = Some(hard);
                    self.register_native(cx, wait);
                }
                if self.input_hard.is_some_and(|bound| Instant::now() >= bound) {
                    return Poll::Ready(Ok(Step::Ended(self.end(Cause::InputDeadline, None))));
                }
                if complete {
                    if !self.initial_written {
                        return Poll::Ready(Err(Fault::Malformed.into()));
                    }
                    self.input_seen = true;
                    Poll::Ready(Ok(Step::Input))
                } else {
                    Poll::Ready(Ok(Step::Activity(bytes, 0)))
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn native_guard(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
    ) -> Result<Option<Step<'id>>, Error> {
        if let Some(end) = self.deferred.take() {
            return Ok(Some(Step::Ended(end)));
        }
        if self.closed {
            return Ok(None);
        }
        if let Some(step) = self.expiry(None)? {
            return Ok(Some(step));
        }
        self.register_native(cx, wait);
        Ok(None)
    }
    /// Native-only source guard, sharing the exact ordinary poll prefix. No
    /// clock sample, socket read/write or synthetic waiting event is produced.
    pub fn poll_native_guard(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
    ) -> Poll<Step<'id>> {
        match self.native_guard(cx, wait) {
            Ok(Some(step)) => Poll::Ready(step),
            Ok(None) => Poll::Pending,
            Err(error) => Poll::Ready(self.failed(error)),
        }
    }
    fn failed(&mut self, error: Error) -> Step<'id> {
        let cause = match error {
            Error::Clock(e) => Cause::Clock(e),
            other => Cause::Error(other),
        };
        Step::Ended(self.end(cause, None))
    }
    fn inner(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
        read: bool,
    ) -> Poll<Result<Step<'id>, Error>> {
        if let Some(step) = self.native_guard(cx, wait)? {
            return Poll::Ready(Ok(step));
        }
        if self.closed {
            return Poll::Ready(Ok(Step::Closed));
        }
        match self.channel.poll_clock(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Ok(Step::Ended(self.end(Cause::Ports(e), None))));
            }
            Poll::Pending => {
                return self
                    .channel
                    .poll_wait(cx, wait)
                    .map_ok(|()| Step::WaitDeadline)
                    .map_err(Error::from);
            }
        }
        let now = self.clock.sample().map_err(Error::Clock)?.now.as_micros();
        if let Some(step) = self.expiry(Some(now))? {
            return Poll::Ready(Ok(step));
        }
        if wait.is_some_and(|w| Instant::now() >= w) {
            return Poll::Ready(Ok(Step::WaitDeadline));
        }
        let target = self
            .pending
            .iter()
            .map(|p| p.until)
            .chain((!self.initial_written).then_some(self.deadlines.send_until))
            .chain(
                (!self.input_seen)
                    .then_some(self.deadlines.first_input_until)
                    .flatten(),
            )
            .chain((self.deadlines.until != u64::MAX).then_some(self.deadlines.until))
            .chain(self.input_until)
            .min();
        if self.alarm_at != target {
            self.alarm = target
                .map(|target| {
                    Deadline::at(
                        self.clock.clone(),
                        gnunet_types::AbsoluteTime::from_micros(target),
                    )
                    .map(Box::pin)
                    .map_err(Error::Clock)
                })
                .transpose()?;
            self.alarm_at = target;
        }
        if let Some(alarm) = &mut self.alarm {
            match alarm.as_mut().poll(cx) {
                Poll::Ready(Err(e)) => return Poll::Ready(Err(Error::Clock(e))),
                Poll::Ready(Ok(())) => {
                    self.alarm = None;
                    self.alarm_at = None;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Pending => {}
            }
        }
        if self.channel.framing().is_none() {
            return match self.channel.poll_connect(cx) {
                Poll::Pending => self
                    .channel
                    .poll_wait(cx, wait)
                    .map_ok(|()| Step::WaitDeadline)
                    .map_err(Error::from),
                Poll::Ready(Err(e)) => {
                    Poll::Ready(Ok(Step::Ended(self.end(Cause::Ports(e), None))))
                }
                Poll::Ready(Ok(ConnectionStep::Attached)) => {
                    let epoch = Epoch {
                        brand: self.session.brand,
                        serial: 1,
                    };
                    self.epoch = Some(epoch);
                    Poll::Ready(Ok(Step::Connected(epoch)))
                }
                Poll::Ready(Ok(ConnectionStep::Retry { error, retry_after })) => {
                    Poll::Ready(Ok(Step::Retry(error, retry_after)))
                }
                Poll::Ready(Ok(ConnectionStep::Unavailable(e))) => {
                    Poll::Ready(Ok(Step::Ended(self.end(Cause::Ports(e), None))))
                }
            };
        }
        if read
            && self.read_first
            && self.initial_written
            && !self.pause.is_some_and(|until| Instant::now() < until)
        {
            let result = self.read_one(cx, now, wait);
            if result.is_ready() {
                self.read_first = false;
                return result;
            }
        }
        let epoch = self.epoch.ok_or(Fault::Stale)?;
        if let Some(p) = self.pending.front_mut() {
            if !p.queued {
                let frame = p.source.take().ok_or(Fault::Stale)?;
                if let Err(rejected) = self
                    .channel
                    .framing_mut()
                    .ok_or(Fault::Stale)?
                    .enqueue_owned(frame, Origin { epoch, write: p.id }, Class::Ordinary)
                {
                    p.source = Some(rejected.value.0);
                    return Poll::Ready(Err(rejected.reason.into()));
                }
                p.queued = true;
                self.read_first = true;
                return Poll::Ready(Ok(Step::Queued(p.id, epoch, p.command)));
            }
            match self
                .channel
                .framing_mut()
                .ok_or(Fault::Stale)?
                .poll_write(cx)
            {
                Poll::Ready(Ok(w)) => {
                    if w.origin.epoch != epoch || w.origin.write != p.id {
                        return Poll::Ready(Err(Fault::Stale.into()));
                    }
                    self.read_first = true;
                    p.sent = p.sent.checked_add(w.bytes).ok_or(Fault::Overflow)?;
                    if p.sent > p.total {
                        return Poll::Ready(Err(Fault::Stale.into()));
                    }
                    if p.id.serial == 1 {
                        self.initial_sent = p.sent;
                    }
                    if w.complete {
                        if p.sent != p.total {
                            return Poll::Ready(Err(Fault::Stale.into()));
                        }
                        let p = self.pending.pop_front().ok_or(Fault::Stale)?;
                        self.source_bytes -= p.total;
                        if p.id.serial == 1 {
                            self.initial_written = true;
                        }
                        return Poll::Ready(Ok(Step::Written(p.id, epoch, p.command, p.total)));
                    }
                    return Poll::Ready(Ok(Step::Activity(0, w.bytes)));
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Ok(Step::Ended(self.end(Cause::Io(e), None))));
                }
                Poll::Pending => {}
            }
        }
        if read && !self.pause.is_some_and(|until| Instant::now() < until) {
            let result = self.read_one(cx, now, wait);
            if result.is_ready() {
                self.read_first = false;
                return result;
            }
        }
        self.channel
            .poll_wait(cx, wait)
            .map_ok(|()| Step::WaitDeadline)
            .map_err(Error::from)
    }
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
        read: bool,
    ) -> Poll<Step<'id>> {
        match self.inner(cx, wait, read) {
            Poll::Ready(Err(error)) => Poll::Ready(self.failed(error)),
            Poll::Ready(Ok(step)) => Poll::Ready(step),
            Poll::Pending => Poll::Pending,
        }
    }
}
impl Drop for Io<'_> {
    fn drop(&mut self) {
        self.channel.close();
    }
}
