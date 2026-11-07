//! Native local DATASTORE IPC over the pure caller-buffer owner and shared
//! CLIENT channel. No service process or background driver is created.
#![forbid(unsafe_code)]
#[cfg(all(unix, feature = "server"))]
pub mod backend;
#[cfg(feature = "server")]
pub mod server;
use gnunet_client::datastore::{self as pure, Transmission, UnwrittenCause};
pub use gnunet_client::datastore::{
    Client as ProtocolClient, Completion, Instance, Limits as ProtocolLimits, Operation,
    ReservationSlot, Response, Slot,
};
pub use gnunet_client::datastore::{Interruption, Outcome, Request, Reservation};
use gnunet_client_host::channel::{Channel, ConnectionStep};
pub use gnunet_client_host::{ConnectError as Error, EndpointSource};
use gnunet_service_runtime::{
    clock::RuntimeClock,
    framing::{Accounting, Budget, Class, Limits as FrameLimits, OwnedFrame, ReadStep},
};
use gnunet_types::{Duration as Timeout, Error as ProtocolError, MonoInstant};
use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

/// Native memory/IO policy, independent of service storage reservations.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum inbound/outbound complete frame; must cover pure admission policy.
    pub frame_bytes: usize,
    /// Maximum retained actual reply frames, freed only by take().
    pub reply_frames: usize,
    /// Maximum complete bytes of those retained frames.
    pub reply_bytes: usize,
    /// Nonzero maximum bytes in one native read/write syscall.
    pub io_slice_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            frame_bytes: 65535,
            reply_frames: 16,
            reply_bytes: 16 * 65535,
            io_slice_bytes: 65535,
        }
    }
}
impl Limits {
    fn framing(self) -> FrameLimits {
        FrameLimits {
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
struct Answer<'a> {
    operation: Operation<'a>,
    frame: OwnedFrame,
}
/// An explicitly taken terminal result. A lost/local completion has no fabricated
/// STATUS/END frame; actual service values and diagnostics retain their bytes.
pub struct Taken<'a> {
    /// Original pure certainty and current reservation authority.
    pub completion: Completion<'a>,
    frame: Option<OwnedFrame>,
}
impl Taken<'_> {
    /// Original actual response bytes, if one was received.
    #[must_use]
    pub fn bytes(&self) -> Option<&[u8]> {
        self.frame.as_ref().map(OwnedFrame::bytes)
    }
    /// Decode already accepted actual fields; this grants no block authentication.
    pub fn response(&self) -> Result<Option<Response<'_>>, ProtocolError> {
        self.bytes().map(Response::decode).transpose()
    }
    /// Transfer the already owned actual reply without another allocation/copy.
    /// Read the Copy completion first when retaining both cause and raw bytes.
    #[must_use]
    pub fn into_frame(self) -> Option<OwnedFrame> {
        self.frame
    }
}
/// Actual reason for retirement of one original physical connection.
#[derive(Debug)]
pub enum Loss {
    /// Original native syscall/EOF failure.
    Io(io::Error),
    /// Original protocol/framing refusal.
    Protocol(ProtocolError),
    /// Original partial-write deadline or bounded drain interval expired.
    Deadline,
    /// Caller explicitly requested another physical connection.
    Requested,
}
/// One bounded drive action. Reply indicates retained storage, retrieved by take.
pub enum Step<'a> {
    /// Actual service socket attached; there is no DATASTORE START handshake.
    Connected(pure::Epoch<'a>),
    /// Exact original frame admitted with zero bytes transferred so far.
    Queued(Operation<'a>),
    /// Positive original native transfer, immediately reported to the pure owner.
    Written {
        /// Original local operation.
        operation: Operation<'a>,
        /// Actual transferred bytes.
        bytes: usize,
        /// Full frame transfer, not a service acknowledgment.
        complete: bool,
    },
    /// Positive native input retained by Framed.
    Read {
        /// Actual transferred bytes.
        bytes: usize,
    },
    /// Actual matched service reply retained for this operation.
    Reply(Operation<'a>),
    /// Well-framed unknown message ignored like MQ.
    Ignored,
    /// Complete input retained because owned reply delivery capacity is exhausted.
    Capacity,
    /// Original deadline wake; operations retain their original targets.
    Timer,
    /// Original MQ physically retired before pure loss classification.
    Lost {
        /// Original connection identity.
        epoch: pure::Epoch<'a>,
        /// Actual local cause.
        cause: Loss,
        /// Existing CLIENT reconnect delay.
        retry_after: Duration,
    },
    /// Original connection attempt failed; retry is retained in Channel.
    ConnectRetry {
        /// Actual socket cause.
        error: io::Error,
        /// Existing CLIENT delay.
        retry_after: Duration,
    },
    /// Current endpoint selection failed; no negative datastore reply is inferred.
    Unavailable(Error),
    /// This observation wait ended; no operation or partial cursor was canceled.
    WaitDeadline,
    /// Permanent close, or full unacknowledged DROP followed by physical closure.
    Closed,
}
struct Outbound<'a> {
    token: Transmission<'a>,
    deadline: MonoInstant,
}
/// Movable host consuming an externally constructed borrowed pure owner. All
/// partial writes/reads, original request tags and accepted replies survive a
/// dropped drive future. Exposed mutations never migrate to a replacement MQ.
pub struct Client<'id, 'slots, 'buffers> {
    core: pure::Client<'id, 'slots, 'buffers>,
    channel: Channel<Transmission<'id>>,
    epoch: Option<pure::Epoch<'id>>,
    outbound: Option<Outbound<'id>>,
    clock: Arc<dyn RuntimeClock>,
    anchor: Instant,
    now: MonoInstant,
    timer: Option<(MonoInstant, Pin<Box<Sleep>>)>,
    limits: Limits,
    answers: Vec<Answer<'id>>,
    answer_bytes: usize,
    awaiting_reply: bool,
    rx_idle: bool,
    closed: bool,
}
impl<'id, 'slots, 'buffers> Client<'id, 'slots, 'buffers> {
    /// Reserve retained reply records and CLIENT clock ownership. Adopt only an
    /// empty, unattached pure owner at its native origin; submit requests through
    /// this host after construction so their original native deadlines are bound
    /// to this owner's fixed epoch.
    pub fn new(
        mut core: pure::Client<'id, 'slots, 'buffers>,
        source: EndpointSource,
        limits: Limits,
    ) -> Result<Self, Error> {
        if !core.connection_needed()
            || core.needs_retire()
            || core.pending() != 0
            || limits.frame_bytes < core.limits().max_frame_bytes
            || limits.reply_frames == 0
            || limits.reply_bytes < limits.frame_bytes
        {
            return Err(ProtocolError::Capacity.into());
        }
        limits.framing().validate()?;
        let mut answers = Vec::new();
        answers
            .try_reserve_exact(limits.reply_frames)
            .map_err(|_| ProtocolError::Capacity)?;
        let clock = source.clock();
        clock.sample()?;
        let anchor = Instant::now();
        let now = MonoInstant(0);
        core.advance(now)?;
        let channel = Channel::new(source, limits.framing())?;
        Ok(Self {
            core,
            channel,
            epoch: None,
            outbound: None,
            clock,
            anchor,
            now,
            timer: None,
            limits,
            answers,
            answer_bytes: 0,
            awaiting_reply: false,
            rx_idle: false,
            closed: false,
        })
    }
    fn sample(&mut self) -> Result<MonoInstant, Error> {
        // Validate the real absolute provider while local timeout/drain
        // scheduling stays on one fixed native elapsed coordinate.
        self.clock.sample()?;
        let elapsed = Instant::now()
            .checked_duration_since(self.anchor)
            .ok_or(ProtocolError::TimeUncertain)?;
        let now =
            MonoInstant(u64::try_from(elapsed.as_micros()).map_err(|_| ProtocolError::Overflow)?);
        now.duration_since(self.now)?;
        self.now = now;
        Ok(now)
    }
    /// Admit copied request bytes under both native and pure limits. The returned
    /// ID remains owned even while endpoint selection/connection is unavailable.
    pub fn submit(
        &mut self,
        request: Request<'_>,
        authorization: Option<Reservation<'id>>,
        timeout: Timeout,
    ) -> Result<Operation<'id>, Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        if request.encoded_len()? > self.limits.frame_bytes {
            return Err(ProtocolError::TooLarge.into());
        }
        let now = self.sample()?;
        let _maintenance = self.maintain(now)?;
        Ok(self.core.submit(request, authorization, now, timeout)?)
    }
    /// Remove only an actual zero-written frame; otherwise retain the pure
    /// request to drain or retire its original partial-write connection.
    pub fn cancel(&mut self, operation: Operation<'id>) -> Result<(), Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        let now = self.sample()?;
        let _maintenance = self.maintain(now)?;
        if self.remove_unwritten(Some(operation), now, UnwrittenCause::Cancelled)? {
            return Ok(());
        }
        self.core.cancel(operation, now)?;
        if self.core.needs_retire() {
            self.retire(now, Loss::Requested)?;
        }
        Ok(())
    }
    /// Cancel one original operation and physically retire its shared current
    /// MQ/connection attempt without sampling a new clock. The last validated
    /// timestamp is used only for retirement, never to authorize new IO. Actual
    /// terminal outcomes (including other operations' Unknown/reservation loss)
    /// and accepted reply bytes remain available through `take`.
    ///
    /// Some returns the actual original MQ retirement; None means there was no
    /// protocol epoch, not that no native connection attempt had existed.
    pub fn cancel_and_retire(
        &mut self,
        operation: Operation<'id>,
    ) -> Result<Option<Step<'id>>, Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        let now = self.now;
        if !self.remove_unwritten(Some(operation), now, UnwrittenCause::Cancelled)? {
            self.core.cancel(operation, now)?;
        }
        if self.epoch.is_some() {
            self.retire(now, Loss::Requested).map(Some)
        } else {
            self.channel.detach();
            self.outbound = None;
            self.timer = None;
            self.awaiting_reply = false;
            self.rx_idle = false;
            Ok(None)
        }
    }
    /// Take one actual terminal outcome and its optional immutable reply bytes.
    /// This remains available after physical/permanent close.
    pub fn take(&mut self, operation: Operation<'id>) -> Result<Taken<'id>, Error> {
        let completion = self.core.take(operation)?;
        let frame = self
            .answers
            .iter()
            .position(|answer| answer.operation == operation)
            .map(|index| {
                let answer = self.answers.swap_remove(index);
                self.answer_bytes -= answer.frame.len();
                answer.frame
            });
        Ok(Taken { completion, frame })
    }
    /// Queued/active request count; completed results remain until take().
    #[must_use]
    pub fn pending(&self) -> usize {
        self.core.pending()
    }
    /// Number/bytes of actual immutable service replies retained for take().
    #[must_use]
    pub fn retained_replies(&self) -> (usize, usize) {
        (self.answers.len(), self.answer_bytes)
    }
    /// Share the original source for one overall caller deadline. This only
    /// clones its Arc; it performs no sampling, protocol work or native IO.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    /// Pure admission limits, including the maximum finite operation lifetime.
    #[must_use]
    pub fn protocol_limits(&self) -> pure::Limits {
        self.core.limits()
    }
    fn remove_unwritten(
        &mut self,
        operation: Option<Operation<'id>>,
        now: MonoInstant,
        cause: UnwrittenCause,
    ) -> Result<bool, ProtocolError> {
        let mut removed = None;
        if let Some(framed) = self.channel.framing_mut() {
            framed.remove_unwritten(
                |tag, _| operation.is_none_or(|operation| tag.operation() == operation),
                |tag, _| removed = Some(tag),
            );
        }
        if let Some(tag) = removed {
            self.core.discard_unwritten(tag, now, cause)?;
            self.outbound = None;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn retire(&mut self, now: MonoInstant, cause: Loss) -> Result<Step<'id>, Error> {
        let epoch = self.epoch.ok_or(ProtocolError::NotReady)?;
        let unwritten = self.remove_unwritten(None, now, UnwrittenCause::ConnectionLost);
        self.channel.detach();
        self.outbound = None;
        self.timer = None;
        self.awaiting_reply = false;
        self.rx_idle = false;
        let retired = self.core.retire(epoch, now);
        self.epoch = None;
        unwritten?;
        retired?;
        let retry_after = if self.core.connection_needed() {
            self.channel.schedule_retry()?
        } else {
            self.channel.close();
            self.closed = true;
            Duration::ZERO
        };
        Ok(Step::Lost {
            epoch,
            cause,
            retry_after,
        })
    }
    fn maintain(&mut self, now: MonoInstant) -> Result<Option<Step<'id>>, Error> {
        if let Some(operation) = self
            .outbound
            .as_ref()
            .filter(|out| out.deadline <= now)
            .map(|out| out.token.operation())
        {
            self.remove_unwritten(Some(operation), now, UnwrittenCause::TimedOut)?;
        }
        self.core.advance(now)?;
        if self.core.needs_retire() {
            Ok(Some(self.retire(now, Loss::Deadline)?))
        } else {
            Ok(None)
        }
    }
    /// Explicitly retire a physical connection. Only still-unsent, unreserved
    /// work remains eligible for a replacement; actual unknown outcomes persist.
    pub fn reconnect(&mut self) -> Result<Step<'id>, Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        let now = self.sample()?;
        self.retire(now, Loss::Requested)
    }
    /// Physically close before retiring pure authority. The last validated time
    /// classifies closure without inventing a fresh timestamp after clock failure.
    pub fn close(&mut self) -> Result<(), Error> {
        if self.closed {
            return Ok(());
        }
        let unwritten = self.remove_unwritten(None, self.now, UnwrittenCause::ConnectionLost);
        self.channel.close();
        self.outbound = None;
        self.timer = None;
        self.awaiting_reply = false;
        self.rx_idle = false;
        let retired = self
            .epoch
            .take()
            .map(|epoch| self.core.retire(epoch, self.now))
            .transpose();
        let closed = self.core.close(self.now);
        self.closed = true;
        unwritten?;
        let _retired = retired?;
        closed?;
        Ok(())
    }
    fn timer(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let next = self.core.next_deadline();
        if self.timer.as_ref().map(|(target, _)| *target) != next {
            let replacement = next
                .map(|target| {
                    let original = self
                        .anchor
                        .checked_add(Duration::from_micros(target.0))
                        .ok_or(ProtocolError::Overflow)?;
                    Ok::<_, ProtocolError>((target, Box::pin(tokio::time::sleep_until(original))))
                })
                .transpose()?;
            self.timer = replacement;
        }
        match &mut self.timer {
            Some((_, timer)) => match timer.as_mut().poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(()) => {
                    self.timer = None;
                    Poll::Ready(Ok(()))
                }
            },
            None => Poll::Pending,
        }
    }
    fn queue(&mut self, now: MonoInstant) -> Result<Option<Operation<'id>>, Error> {
        let Some((operation, length, deadline)) = self.core.next_request() else {
            return Ok(None);
        };
        let framed = self.channel.framing_mut().ok_or(ProtocolError::NotReady)?;
        framed.reserve(length, Class::Ordinary)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| ProtocolError::Capacity)?;
        bytes.resize(length, 0);
        let tag = {
            let send = self
                .core
                .next_send(self.epoch.ok_or(ProtocolError::NotReady)?, now)?
                .ok_or(ProtocolError::NotReady)?;
            bytes.copy_from_slice(send.bytes());
            send.token()
        };
        match framed.enqueue_owned(OwnedFrame::new(bytes), tag, Class::Ordinary) {
            Ok(()) => {
                self.outbound = Some(Outbound {
                    token: tag,
                    deadline,
                });
                Ok(Some(operation))
            }
            Err(rejected) => {
                let reason = rejected.reason;
                let (_, original) = rejected.value;
                self.core
                    .discard_unwritten(original, now, UnwrittenCause::ConnectionLost)?;
                self.retire(now, Loss::Protocol(reason))?;
                Err(reason.into())
            }
        }
    }
    fn dispatch(&mut self, now: MonoInstant) -> Result<Option<Operation<'id>>, Error> {
        let framed = self.channel.framing_mut().ok_or(ProtocolError::NotReady)?;
        let bytes = framed.frame().ok_or(ProtocolError::NotReady)?;
        if self.answers.len() >= self.limits.reply_frames
            || bytes.len() > self.limits.reply_bytes.saturating_sub(self.answer_bytes)
        {
            return Err(ProtocolError::Capacity.into());
        }
        // Reserve all owned delivery resources before receive commits terminal state.
        self.answers
            .try_reserve(1)
            .map_err(|_| ProtocolError::Capacity)?;
        let frame = OwnedFrame::copy_from(bytes)?;
        let operation = self
            .core
            .receive(
                self.epoch.ok_or(ProtocolError::NotReady)?,
                frame.bytes(),
                now,
            )?
            .map(|reply| reply.completion.operation);
        framed.release_frame();
        self.rx_idle = false;
        if let Some(operation) = operation {
            self.awaiting_reply = false;
            self.answer_bytes += frame.len();
            self.answers.push(Answer { operation, frame });
        }
        Ok(operation)
    }
    fn wait(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
    ) -> Poll<Result<Step<'id>, Error>> {
        self.channel
            .poll_wait(cx, deadline)
            .map(|result| result.map(|()| Step::WaitDeadline))
    }
    fn dispatch_step(&mut self, now: MonoInstant) -> Poll<Result<Step<'id>, Error>> {
        match self.dispatch(now) {
            Ok(Some(operation)) => Poll::Ready(Ok(Step::Reply(operation))),
            Ok(None) => Poll::Ready(Ok(Step::Ignored)),
            Err(Error::Protocol(ProtocolError::Capacity)) => Poll::Ready(Ok(Step::Capacity)),
            Err(Error::Protocol(error)) => Poll::Ready(self.retire(now, Loss::Protocol(error))),
            Err(error) => Poll::Ready(Err(error)),
        }
    }
    fn poll_drive(
        &mut self,
        cx: &mut Context<'_>,
        observation_deadline: Option<Instant>,
    ) -> Poll<Result<Step<'id>, Error>> {
        if self.closed {
            return Poll::Ready(Ok(Step::Closed));
        }
        if observation_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Poll::Ready(Ok(Step::WaitDeadline));
        }
        match self.channel.poll_clock(cx) {
            // The caller's fixed native observation target remains live even
            // while the canonical clock is waiting for a consistent revision.
            Poll::Pending => {
                return self.wait(cx, observation_deadline);
            }
            Poll::Ready(result) => result?,
        }
        if observation_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Poll::Ready(Ok(Step::WaitDeadline));
        }
        let now = self.sample()?;
        if observation_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Poll::Ready(Ok(Step::WaitDeadline));
        }
        if let Some(step) = self.maintain(now)? {
            return Poll::Ready(Ok(step));
        }
        if observation_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Poll::Ready(Ok(Step::WaitDeadline));
        }
        if let Poll::Ready(result) = self.timer(cx) {
            result?;
            return Poll::Ready(Ok(Step::Timer));
        }
        if observation_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Poll::Ready(Ok(Step::WaitDeadline));
        }
        if self.core.connection_needed() && self.core.pending() != 0 {
            return match self.channel.poll_connect(cx) {
                Poll::Pending => self.wait(cx, observation_deadline),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(ConnectionStep::Attached)) => {
                    let epoch = match self.core.begin_connection(now) {
                        Ok(epoch) => epoch,
                        Err(error) => {
                            self.channel.detach();
                            return Poll::Ready(Err(error.into()));
                        }
                    };
                    self.epoch = Some(epoch);
                    Poll::Ready(Ok(Step::Connected(epoch)))
                }
                Poll::Ready(Ok(ConnectionStep::Retry { error, retry_after })) => {
                    Poll::Ready(Ok(Step::ConnectRetry { error, retry_after }))
                }
                Poll::Ready(Ok(ConnectionStep::Unavailable(error))) => {
                    Poll::Ready(Ok(Step::Unavailable(error)))
                }
            };
        }
        if self.epoch.is_none() {
            return self.wait(cx, observation_deadline);
        }
        if self
            .channel
            .framing()
            .is_some_and(|framed| framed.frame().is_some() && framed.queued_frames() == 0)
        {
            return self.dispatch_step(now);
        }
        // A partial unsolicited idle frame must be completed/rejected before
        // leasing another request; it cannot become that new request's reply.
        if !self.rx_idle
            && let Some(operation) = self.queue(now)?
        {
            return Poll::Ready(Ok(Step::Queued(operation)));
        }
        let framed = self.channel.framing_mut().ok_or(ProtocolError::NotReady)?;
        match framed.poll_write(cx) {
            Poll::Ready(Err(error)) => return Poll::Ready(self.retire(now, Loss::Io(error))),
            Poll::Ready(Ok(progress)) => {
                if progress.complete {
                    // Do not read or dispatch anything between actual full write
                    // and reporting the exact original token to its pure owner.
                    self.core.written(progress.origin)?;
                    self.outbound = None;
                    self.awaiting_reply = true;
                    if self.core.needs_retire() {
                        self.channel.detach();
                        let epoch = self.epoch.take().ok_or(ProtocolError::NotReady)?;
                        self.core.retire(epoch, now)?;
                        self.channel.close();
                        self.timer = None;
                        self.awaiting_reply = false;
                        self.closed = true;
                    }
                }
                return Poll::Ready(Ok(Step::Written {
                    operation: progress.origin.operation(),
                    bytes: progress.bytes,
                    complete: progress.complete,
                }));
            }
            Poll::Pending => {}
        }
        if framed.queued_frames() != 0 {
            return self.wait(cx, observation_deadline);
        }
        if framed.frame().is_some() {
            return self.dispatch_step(now);
        }
        match framed.poll_read(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(self.retire(now, Loss::Io(error))),
            Poll::Ready(Ok(ReadStep::Eof)) => Poll::Ready(self.retire(
                now,
                Loss::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "DATASTORE MQ closed",
                )),
            )),
            Poll::Ready(Ok(ReadStep::Progress { bytes, .. })) => {
                if !self.awaiting_reply {
                    self.rx_idle = true;
                }
                Poll::Ready(Ok(Step::Read { bytes }))
            }
            Poll::Pending => self.wait(cx, observation_deadline),
        }
    }
    /// Drive one bounded real action. Dropping this future retains native partial
    /// cursors, actual request tags, original deadlines and owned accepted replies.
    pub async fn drive(
        &mut self,
        observation_deadline: Option<Instant>,
    ) -> Result<Step<'id>, Error> {
        poll_fn(|cx| self.poll_drive(cx, observation_deadline)).await
    }
}
impl Drop for Client<'_, '_, '_> {
    fn drop(&mut self) {
        let _closed = self.close();
    }
}
