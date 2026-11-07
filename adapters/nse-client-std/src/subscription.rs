use crate::{EndpointSource, Epoch, Error, Instance, Observation};
use gnunet_client::nse::{Client as Pure, START_LEN, Start};
use gnunet_client_host::channel::{Channel, ConnectionStep};
use gnunet_service_runtime::{
    clock::{Deadline, RuntimeClock},
    framing::{Accounting, Budget, Class, Limits as FrameLimits, OwnedFrame, ReadStep},
};
use gnunet_types::Error as Fault;
use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
/// Two original targets for a finite subscription; neither is reminted on retry.
#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    /// Finite canonical absolute microseconds.
    pub expires: u64,
    /// Independent original native target.
    pub hard: Instant,
}
impl Bounds {
    /// Mint once at explicit admission from the original actual clock.
    pub fn after(clock: &dyn RuntimeClock, timeout: Duration) -> Result<Self, Error> {
        if timeout.is_zero() {
            return Err(Fault::Deadline.into());
        }
        let delta = u64::try_from(timeout.as_micros()).map_err(|_| Fault::Overflow)?;
        if delta == 0 {
            return Err(Fault::Deadline.into());
        }
        let expires = clock
            .sample()?
            .now
            .as_micros()
            .checked_add(delta)
            .filter(|n| *n != u64::MAX)
            .ok_or(Fault::Overflow)?;
        Ok(Self {
            expires,
            hard: Instant::now().checked_add(timeout).ok_or(Fault::Overflow)?,
        })
    }
}
/// Explicit bounded receive resources and finite original phase lifetimes.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum complete received frame including unknown types (32..=65535).
    pub frame_bytes: usize,
    /// Maximum bytes offered in one real syscall, nonzero.
    pub io_slice_bytes: usize,
    /// Finite original connection/selection/session lease. Replacement is a new
    /// actual source, with a fresh START, never replay of old callbacks.
    pub source_lifetime: Duration,
    /// Actual attachment through first valid estimate hard bound.
    pub initial_timeout: Duration,
    /// First byte through complete frame hard bound, never renewed by progress.
    pub input_timeout: Duration,
    /// Allow actual new original sources after old physical retirement.
    pub reconnect: bool,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            frame_bytes: 65535,
            io_slice_bytes: 65535,
            source_lifetime: Duration::from_secs(86400),
            initial_timeout: Duration::from_secs(30),
            input_timeout: Duration::from_secs(10),
            reconnect: true,
        }
    }
}
impl Limits {
    fn framing(self) -> Result<FrameLimits, Error> {
        if !(32..=65535).contains(&self.frame_bytes) || self.io_slice_bytes == 0 {
            return Err(Fault::Capacity.into());
        }
        for d in [
            self.source_lifetime,
            self.initial_timeout,
            self.input_timeout,
        ] {
            if d.as_micros() == 0
                || d.as_micros() >= u128::from(u64::MAX)
                || Instant::now().checked_add(d).is_none()
            {
                return Err(Fault::InvalidInput.into());
            }
        }
        let limits = FrameLimits {
            frame_bytes: self.frame_bytes,
            ordinary: Budget {
                frames: 1,
                bytes: START_LEN,
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.io_slice_bytes,
        };
        limits.validate()?;
        Ok(limits)
    }
}
/// Original physical source's actual local exposure at retirement.
#[derive(Clone, Copy, Debug)]
pub struct Loss<'a> {
    /// Actual attached source, absent only for a not-yet-attached attempt.
    pub epoch: Option<Epoch<'a>>,
    /// Exact START prefix actually written, from0 through4.
    pub start_bytes: usize,
    /// Full START write occurred; this is not a processing ACK.
    pub start_written: bool,
}
/// Actual original-source termination, never an estimate or peer proof.
#[derive(Debug)]
pub enum Cause {
    /// Actual socket failure.
    Io(io::Error),
    /// Actual source EOF.
    Eof,
    /// Known malformed frame/pure original-source rejection.
    Protocol(Fault),
    /// Original finite canonical source target reached.
    SourceDeadline,
    /// Original source/INIT/partial-input native bound reached.
    NativeDeadline,
    /// Original clock/Resolver/configuration port failed; explicit recovery only.
    Port(Error),
    /// Canonical source sample failed outside shared CLIENT stabilization.
    Clock(Fault),
    /// Caller explicitly retired the original MQ.
    Requested,
}
/// A permanent local subscription end; no wire STOP/CANCEL exists.
#[derive(Clone, Copy, Debug)]
pub enum Stop {
    /// Caller permanently disconnected.
    Closed,
    /// Original finite subscription target reached.
    Deadline,
}
/// One real original event; delivery/age/NaN are preserved from the NSE service.
pub enum Progress<'a> {
    /// Actual original native MQ attached, without an application handshake.
    Connected(Epoch<'a>),
    /// Exact immutable header-only START queued once on that MQ.
    Queued(Epoch<'a>),
    /// The same START fully wrote. No server ACK is invented.
    Written(Epoch<'a>),
    /// Real complete statistical observation from this currently listening MQ.
    Estimate(Observation<'a>),
    /// Well-framed unhandled message ignored on its actual source.
    Ignored(Epoch<'a>),
    /// Positive actual byte movement only.
    Activity {
        /// Exact source.
        epoch: Epoch<'a>,
        /// Actual receive bytes.
        read: usize,
        /// Actual send bytes.
        written: usize,
    },
    /// Physical retirement occurred before pure original epoch invalidation.
    Lost {
        /// Original prefix/epoch facts.
        report: Loss<'a>,
        /// Actual independent cause.
        cause: Cause,
    },
    /// Actual connection syscall failed; shared CLIENT backoff is pending.
    Retry {
        /// Actual syscall failure.
        error: io::Error,
        /// Original retry policy observation.
        delay: Duration,
    },
    /// Actual endpoint selection/configuration refusal.
    Unavailable(Error),
    /// Permanent end after actual physical close.
    Stopped {
        /// Actual stop reason.
        reason: Stop,
        /// Last original source exposure if any.
        report: Loss<'a>,
    },
    /// Only the caller's observation wait expired; no cancellation occurred.
    Wait,
}
/// Caller-driven original subscription owner. No task, Resolver, key, PoW or
/// NSE service is created. Drop closes the actual original MQ synchronously.
pub struct Subscription<'a> {
    pure: Pure<'a>,
    channel: Channel<Epoch<'a>>,
    clock: Arc<dyn RuntimeClock>,
    limits: Limits,
    total: Option<Bounds>,
    session: Option<Bounds>,
    epoch: Option<Epoch<'a>>,
    start: Option<Start<'a>>,
    start_bytes: usize,
    written: bool,
    initial: Option<Instant>,
    input: Option<Instant>,
    alarm: Option<Pin<Box<Sleep>>>,
    logical: Option<Pin<Box<Deadline>>>,
    logical_at: Option<u64>,
    blocked: bool,
    direct_clock_refused: bool,
    closed: Option<Stop>,
}
impl<'a> Subscription<'a> {
    /// Reserve one real CLIENT/clock source. Optional original total bounds are
    /// finite and never renewed, including reconnect. None permits monitoring
    /// until explicit cancellation while each actual source/phase stays finite.
    pub fn new(
        instance: &'a mut Instance,
        source: EndpointSource,
        total: Option<Bounds>,
        limits: Limits,
    ) -> Result<Self, Error> {
        let frame = limits.framing()?;
        let clock = source.clock();
        if let Some(b) = total
            && (b.hard <= Instant::now()
                || b.expires == u64::MAX
                || b.expires <= clock.sample()?.now.as_micros())
        {
            return Err(Fault::Deadline.into());
        }
        let channel = Channel::new(source, frame)?;
        Ok(Self {
            pure: Pure::new(instance),
            channel,
            clock,
            limits,
            total,
            session: None,
            epoch: None,
            start: None,
            start_bytes: 0,
            written: false,
            initial: None,
            input: None,
            alarm: None,
            logical: None,
            logical_at: None,
            blocked: false,
            direct_clock_refused: false,
            closed: None,
        })
    }
    /// Same actual source clock; no replacement clock is created.
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    /// Latest public observation only while its original epoch remains live.
    pub fn latest(&self) -> Option<Observation<'a>> {
        self.pure.latest()
    }
    /// Actual attached epoch; no reconnect intent is exposed as attachment.
    pub const fn epoch(&self) -> Option<Epoch<'a>> {
        self.epoch
    }
    fn report(&self) -> Loss<'a> {
        Loss {
            epoch: self.epoch,
            start_bytes: self.start_bytes,
            start_written: self.written,
        }
    }
    fn clear(&mut self) {
        self.start = None;
        self.start_bytes = 0;
        self.written = false;
        self.initial = None;
        self.input = None;
        self.session = None;
        self.alarm = None;
        self.logical = None;
        self.logical_at = None;
    }
    fn lost(&mut self, cause: Cause, retry: bool) -> Result<Progress<'a>, Error> {
        let report = self.report();
        self.channel.detach();
        if let Some(epoch) = self.epoch.take() {
            self.pure.retire(epoch)?;
        }
        self.clear();
        self.blocked = !retry || !self.limits.reconnect;
        if !self.blocked {
            self.channel.schedule_retry()?;
        }
        Ok(Progress::Lost { report, cause })
    }
    /// Permanently cancel: physical detach occurs before pure invalidation.
    /// Returned prefix facts assert no service processing or wire cancellation.
    pub fn close(&mut self) -> Loss<'a> {
        let report = self.report();
        self.channel.close();
        self.pure.close();
        self.epoch = None;
        self.clear();
        self.closed = Some(Stop::Closed);
        report
    }
    /// Explicit new source request after physically closing the old MQ. No
    /// observation/START suffix/callback is moved to the new epoch.
    pub fn reconnect(&mut self) -> Result<Progress<'a>, Error> {
        if self.closed.is_some() {
            return Err(Fault::Closed.into());
        }
        self.lost(Cause::Requested, true)
    }
    /// Recover an actual shared clock/Resolver port refusal explicitly. Original
    /// total bounds remain unchanged and are checked before any new native IO.
    pub fn recover_ports(&mut self) -> Result<(), Error> {
        if self.closed.is_some() {
            return Err(Fault::Closed.into());
        }
        match self.channel.recover_ports() {
            Ok(()) => {}
            Err(Error::Protocol(Fault::NotReady)) if self.direct_clock_refused => {
                self.clock.sample()?;
            }
            Err(error) => return Err(error),
        }
        self.direct_clock_refused = false;
        self.blocked = false;
        Ok(())
    }
    fn deadline(&mut self) -> Progress<'a> {
        let report = self.close();
        self.closed = Some(Stop::Deadline);
        Progress::Stopped {
            reason: Stop::Deadline,
            report,
        }
    }
    /// Check/register original native bounds only; no clock sample, decode or
    /// socket/crypto IO. Compose this before an enclosing canonical clock wait.
    pub fn poll_native_guard(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Option<Result<Progress<'a>, Error>> {
        if self.closed.is_some() {
            return None;
        }
        let now = Instant::now();
        if self.total.is_some_and(|b| now >= b.hard) {
            return Some(Ok(self.deadline()));
        }
        if self.session.is_some_and(|b| now >= b.hard)
            || self.initial.is_some_and(|at| now >= at)
            || self.input.is_some_and(|at| now >= at)
        {
            return Some(self.lost(Cause::NativeDeadline, true));
        }
        let at = self
            .total
            .map(|b| b.hard)
            .into_iter()
            .chain(self.session.map(|b| b.hard))
            .chain(self.initial)
            .chain(self.input)
            .min();
        if let Some(at) = at {
            let alarm = self
                .alarm
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(at)));
            alarm.as_mut().reset(at);
            if alarm.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        } else {
            self.alarm = None;
        }
        None
    }
    fn logical_guard(&mut self, cx: &mut Context<'_>) -> Result<(), Error> {
        let at = self
            .total
            .map(|b| b.expires)
            .into_iter()
            .chain(self.session.map(|b| b.expires))
            .min();
        if at != self.logical_at {
            self.logical_at = at;
            self.logical = at
                .map(|at| {
                    Deadline::at(
                        self.clock.clone(),
                        gnunet_types::AbsoluteTime::from_micros(at),
                    )
                    .map(Box::pin)
                })
                .transpose()?;
        }
        if let Some(alarm) = &mut self.logical {
            match alarm.as_mut().poll(cx) {
                Poll::Ready(Err(error)) => return Err(error.into()),
                Poll::Ready(Ok(())) => cx.waker().wake_by_ref(),
                Poll::Pending => {}
            }
        }
        Ok(())
    }
    fn prepare(&mut self) -> Result<bool, Error> {
        if self.start.is_some() || self.written {
            return Ok(false);
        }
        let epoch = self.epoch.ok_or(Fault::NotReady)?;
        let start = self.pure.prepare_start(epoch)?;
        let frame = OwnedFrame::copy_from(start.bytes())?;
        match self
            .channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .enqueue_owned(frame, epoch, Class::Ordinary)
        {
            Ok(()) => {}
            Err(error) => return Err(error.reason.into()),
        }
        self.start = Some(start);
        Ok(true)
    }
    fn write(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress<'a>, Error>> {
        let epoch = self.epoch.ok_or(Fault::NotReady)?;
        match self
            .channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .poll_write(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(self.lost(Cause::Io(error), true)),
            Poll::Ready(Ok(progress)) => {
                if progress.origin != epoch {
                    return Poll::Ready(Err(Fault::Stale.into()));
                }
                self.start_bytes = self
                    .start_bytes
                    .checked_add(progress.bytes)
                    .ok_or(Fault::Overflow)?;
                if progress.complete {
                    if self.start_bytes != START_LEN {
                        return Poll::Ready(Err(Fault::Conflict.into()));
                    }
                    self.pure
                        .written(self.start.as_ref().ok_or(Fault::NotReady)?)?;
                    self.start = None;
                    self.written = true;
                    return Poll::Ready(Ok(Progress::Written(epoch)));
                }
                Poll::Ready(Ok(Progress::Activity {
                    epoch,
                    read: 0,
                    written: progress.bytes,
                }))
            }
        }
    }
    fn read(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress<'a>, Error>> {
        let epoch = self.epoch.ok_or(Fault::NotReady)?;
        let step = match self
            .channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .poll_read(cx)
        {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(self.lost(Cause::Io(error), true)),
            Poll::Ready(Ok(step)) => step,
        };
        match step {
            ReadStep::Eof => Poll::Ready(self.lost(Cause::Eof, true)),
            ReadStep::Progress { bytes, complete } => {
                if self.input.is_none() {
                    self.input = Some(
                        Instant::now()
                            .checked_add(self.limits.input_timeout)
                            .ok_or(Fault::Overflow)?,
                    );
                }
                if !complete {
                    return Poll::Ready(Ok(Progress::Activity {
                        epoch,
                        read: bytes,
                        written: 0,
                    }));
                }
                let result = self.pure.receive(
                    epoch,
                    self.channel
                        .framing()
                        .and_then(|f| f.frame())
                        .ok_or(Fault::NotReady)?,
                );
                self.channel
                    .framing_mut()
                    .ok_or(Fault::NotReady)?
                    .release_frame();
                self.input = None;
                match result {
                    Ok(Some(observation)) => {
                        self.channel.reset_backoff();
                        self.initial = None;
                        Poll::Ready(Ok(Progress::Estimate(observation)))
                    }
                    Ok(None) => Poll::Ready(Ok(Progress::Ignored(epoch))),
                    Err(error) => Poll::Ready(self.lost(Cause::Protocol(error), true)),
                }
            }
        }
    }
    fn inner(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
    ) -> Poll<Result<Progress<'a>, Error>> {
        if let Some(reason) = self.closed {
            return Poll::Ready(Ok(Progress::Stopped {
                reason,
                report: self.report(),
            }));
        }
        if let Some(progress) = self.poll_native_guard(cx) {
            return Poll::Ready(progress);
        }
        if wait.is_some_and(|at| at <= Instant::now()) {
            return Poll::Ready(Ok(Progress::Wait));
        }
        match self.channel.poll_clock(cx) {
            Poll::Pending => {
                return self
                    .channel
                    .poll_wait(cx, wait)
                    .map(|r| r.map(|()| Progress::Wait));
            }
            Poll::Ready(Err(error)) => return Poll::Ready(self.lost(Cause::Port(error), false)),
            Poll::Ready(Ok(())) => {}
        }
        let now = match self.clock.sample() {
            Ok(s) => s.now.as_micros(),
            Err(error) => {
                self.direct_clock_refused = true;
                return Poll::Ready(self.lost(Cause::Clock(error), false));
            }
        };
        if self.total.is_some_and(|b| b.expires <= now) {
            return Poll::Ready(Ok(self.deadline()));
        }
        if self.session.is_some_and(|b| b.expires <= now) {
            return Poll::Ready(self.lost(Cause::SourceDeadline, true));
        }
        if self.blocked {
            return self
                .channel
                .poll_wait(cx, wait)
                .map(|r| r.map(|()| Progress::Wait));
        }
        if self.session.is_none() {
            let delta = u64::try_from(self.limits.source_lifetime.as_micros())
                .map_err(|_| Fault::Overflow)?;
            self.session = Some(Bounds {
                expires: now
                    .checked_add(delta)
                    .filter(|n| *n != u64::MAX)
                    .ok_or(Fault::Overflow)?,
                hard: Instant::now()
                    .checked_add(self.limits.source_lifetime)
                    .ok_or(Fault::Overflow)?,
            });
        }
        self.logical_guard(cx)?;
        if self.epoch.is_none() {
            match self.channel.poll_connect(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(self.lost(Cause::Port(error), false));
                }
                Poll::Ready(Ok(ConnectionStep::Attached)) => {
                    let epoch = self.pure.begin_connection()?;
                    self.epoch = Some(epoch);
                    self.initial = Some(
                        Instant::now()
                            .checked_add(self.limits.initial_timeout)
                            .ok_or(Fault::Overflow)?,
                    );
                    if let Some(progress) = self.poll_native_guard(cx) {
                        return Poll::Ready(progress);
                    }
                    return Poll::Ready(Ok(Progress::Connected(epoch)));
                }
                Poll::Ready(Ok(ConnectionStep::Retry { error, retry_after })) => {
                    return Poll::Ready(Ok(Progress::Retry {
                        error,
                        delay: retry_after,
                    }));
                }
                Poll::Ready(Ok(ConnectionStep::Unavailable(error))) => {
                    return Poll::Ready(Ok(Progress::Unavailable(error)));
                }
            }
        } else {
            if self.prepare()? {
                return Poll::Ready(Ok(Progress::Queued(self.epoch.ok_or(Fault::NotReady)?)));
            }
            let progress = if self.written {
                self.read(cx)
            } else {
                self.write(cx)
            };
            if let Poll::Ready(result) = progress {
                // Register a first partial-frame deadline during this same turn.
                if !matches!(
                    &result,
                    Ok(Progress::Lost { .. } | Progress::Stopped { .. })
                ) && let Some(guarded) = self.poll_native_guard(cx)
                {
                    return Poll::Ready(guarded);
                }
                return Poll::Ready(result);
            }
        }
        if let Some(progress) = self.poll_native_guard(cx) {
            return Poll::Ready(progress);
        }
        self.channel
            .poll_wait(cx, wait)
            .map(|r| r.map(|()| Progress::Wait))
    }
    /// Poll one real event. Any unexpected failure physically closes the
    /// original native source before exposing the error; canceled waits retain IO.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
    ) -> Poll<Result<Progress<'a>, Error>> {
        let result = self.inner(cx, wait);
        if matches!(&result, Poll::Ready(Err(_))) {
            let _actual = self.close();
        }
        result
    }
    /// Canceling this wait does not cancel the original source/START/subscription.
    pub async fn drive(&mut self, wait: Option<Instant>) -> Result<Progress<'a>, Error> {
        poll_fn(|cx| self.poll(cx, wait)).await
    }
}
impl Drop for Subscription<'_> {
    fn drop(&mut self) {
        let _original = self.close();
    }
}
