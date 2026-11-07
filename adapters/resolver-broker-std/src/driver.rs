//! Unique physical owner; all poll cursors survive canceled wait futures.
use crate::{BrokerError, ClockSubscription, Context, Limits};
use gnunet_client::resolver_handle::ConnectionEpoch;
use gnunet_client_host::{ConnectionAttempt, Endpoint};
use gnunet_service_runtime::connection::Connection;
use gnunet_types::{AbsoluteTime, Error};
use gnunet_wire::official::{Frame, MessageHeader, message_type};
use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, ReadBuf},
    time::{Instant, Sleep},
};
/// Actual host observations, distinct from the public DNS callbacks.
#[derive(Clone, Copy, Debug)]
pub enum DriverEvent {
    /// Physical stream established inside this original logical MQ.
    Connected(ConnectionEpoch),
    /// Initial socket failure retains original epoch, TX and queued requests.
    SocketRetry {
        /// Original logical MQ.
        epoch: ConnectionEpoch,
        /// Absolute logical next physical attempt.
        at: AbsoluteTime,
    },
    /// Actual configuration prevented creation of an MQ; request deadlines persist.
    Unavailable,
    /// Actual original stream/protocol epoch retired before retrying its head ID.
    Lost {
        /// Original retired epoch.
        epoch: ConnectionEpoch,
        /// Observable local cause; not DNS END.
        cause: Error,
    },
    /// Native one-millisecond idle shutdown retired this original MQ.
    IdleClosed(ConnectionEpoch),
}
/// Result of one wait. A real wait budget does not replace query deadlines.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// I/O, timer, or callback became available.
    Activity,
    /// No work, physical resource, or timer remains.
    Idle,
    /// This drive call's real Tokio wait budget elapsed.
    WaitDeadline,
}
/// One shared process driver. It owns every actual MQ socket, immutable envelope
/// and partial read/write cursor. Drop closes them and reports owner loss rather
/// than manufacturing public DNS termination callbacks.
pub struct Driver<const R: usize, const N: usize> {
    context: Context<R, N>,
    limits: Limits,
    epoch: Option<ConnectionEpoch>,
    endpoint: Option<Endpoint>,
    stream: Option<Connection>,
    connecting: Option<ConnectionAttempt>,
    pending_native_error: Option<io::Error>,
    socket_retry: Option<AbsoluteTime>,
    // Initial CLIENT add_now is ready even at MAX; a saturated delayed retry
    // is FOREVER. Never infer registration-ready from a deadline value.
    socket_ready: bool,
    socket_backoff: u64,
    socket_round: u64,
    output: Vec<u8>,
    input: Vec<u8>,
    used: usize,
    expected: usize,
    timer: Option<Pin<Box<Sleep>>>,
    read_first: bool,
    clock_revision: u64,
    clock_subscription: Box<dyn ClockSubscription>,
    last_io_error: Option<io::Error>,
    last_connect_error: Option<BrokerError>,
}
fn buffer(size: usize) -> Result<Vec<u8>, Error> {
    let mut data = Vec::new();
    data.try_reserve_exact(size).map_err(|_| Error::Capacity)?;
    data.resize(size, 0);
    Ok(data)
}
impl<const R: usize, const N: usize> Driver<R, N> {
    pub(crate) fn build(context: Context<R, N>, limits: Limits) -> Result<Self, BrokerError> {
        let clock_subscription = context.shared.clock.subscribe()?;
        Ok(Self {
            clock_subscription,
            context,
            limits,
            epoch: None,
            endpoint: None,
            stream: None,
            connecting: None,
            pending_native_error: None,
            socket_retry: None,
            socket_ready: false,
            socket_backoff: 0,
            socket_round: 0,
            output: buffer(limits.max_frame_bytes)?,
            input: buffer(limits.max_frame_bytes)?,
            used: 0,
            expected: 4,
            timer: None,
            read_first: false,
            clock_revision: 0,
            last_io_error: None,
            last_connect_error: None,
        })
    }
    /// Access the same shared admission/configuration context without creating a MQ.
    #[must_use]
    pub fn context(&self) -> Context<R, N> {
        self.context.clone()
    }
    /// Immutable envelopes held by this actual MQ, including older timed-out
    /// requests. This is queue ownership, not proof of physical transmission.
    pub fn queued_frames(&self) -> Result<usize, BrokerError> {
        Ok(self.context.lock()?.mq.queue.len())
    }
    /// Take the actual most recent physical failure, with no synthetic DNS status.
    pub fn take_io_error(&mut self) -> Option<io::Error> {
        self.last_io_error.take()
    }
    /// Take the actual most recent endpoint/MQ construction failure.
    pub fn take_connect_error(&mut self) -> Option<BrokerError> {
        self.last_connect_error.take()
    }
    fn clear(&mut self) {
        self.stream = None;
        self.connecting = None;
        self.pending_native_error = None;
        self.endpoint = None;
        self.socket_retry = None;
        self.socket_ready = false;
        self.socket_backoff = 0;
        self.socket_round = 0;
        if let Ok(mut state) = self.context.lock() {
            state.clear_mq();
        }
        self.used = 0;
        self.expected = 4;
    }
    fn sync(&mut self) -> Result<(), BrokerError> {
        let epoch = { self.context.lock()?.core.connection_epoch() };
        if epoch != self.epoch {
            self.clear();
            self.epoch = epoch;
        }
        Ok(())
    }
    /// The public disconnect's real ownership boundary: requires all remote requests
    /// canceled/completed, and closes the physical owner synchronously. Independent
    /// numeric tasks remain scheduled in the shared core. No callback is invented.
    pub fn disconnect(&mut self) -> Result<(), BrokerError> {
        {
            self.context.lock()?.core.disconnect()?;
        }
        self.sync()
    }
    fn lost(
        &mut self,
        epoch: ConnectionEpoch,
        cause: Error,
        now: AbsoluteTime,
        observer: &mut impl FnMut(DriverEvent),
    ) -> Result<Progress, BrokerError> {
        {
            let mut state = self.context.lock()?;
            if state.core.connection_epoch() == Some(epoch) {
                state.core.connection_lost(epoch, now)?;
            }
            state.core.reconnect_inline(now)?;
        }
        self.sync()?;
        observer(DriverEvent::Lost { epoch, cause });
        Ok(Progress::Activity)
    }
    fn timer(
        &mut self,
        cx: &mut TaskContext<'_>,
        now: AbsoluteTime,
        budget: Option<Instant>,
        callbacks_blocked: bool,
    ) -> Poll<Result<Progress, BrokerError>> {
        let logical = if callbacks_blocked {
            None
        } else {
            { self.context.lock()?.core.next_wakeup() }
                .into_iter()
                .chain(self.socket_retry)
                .filter(|at| at.as_micros() != u64::MAX)
                .min()
        };
        let target = logical
            .map(|at| {
                Instant::now()
                    .checked_add(Duration::from_micros(
                        at.as_micros().saturating_sub(now.as_micros()),
                    ))
                    .ok_or(Error::Overflow)
            })
            .transpose()?
            .into_iter()
            .chain(budget)
            .min();
        let Some(target) = target else {
            return Poll::Pending;
        };
        if let Some(timer) = &mut self.timer {
            timer.as_mut().reset(target);
        } else {
            self.timer = Some(Box::pin(tokio::time::sleep_until(target)));
        }
        let Some(timer) = &mut self.timer else {
            return Poll::Ready(Err(Error::NotReady.into()));
        };
        if timer.as_mut().poll(cx).is_ready() {
            Poll::Ready(Ok(if budget.is_some_and(|at| Instant::now() >= at) {
                Progress::WaitDeadline
            } else {
                Progress::Activity
            }))
        } else {
            Poll::Pending
        }
    }
    fn poll_write(
        &mut self,
        cx: &mut TaskContext<'_>,
        epoch: ConnectionEpoch,
        now: AbsoluteTime,
        observer: &mut impl FnMut(DriverEvent),
    ) -> Poll<Result<Progress, BrokerError>> {
        let Some(stream) = self.stream.as_ref() else {
            return Poll::Pending;
        };
        match stream.poll_write_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => {
                self.last_io_error = Some(error);
                return Poll::Ready(self.lost(epoch, Error::Io, now, observer));
            }
            Poll::Ready(Ok(())) => {}
        }
        let copied = {
            let state = self.context.lock()?;
            if let Some(envelope) = state.mq.queue.front() {
                let end = envelope
                    .written
                    .saturating_add(self.limits.io_chunk_bytes)
                    .min(envelope.len);
                let count = end - envelope.written;
                self.output[..count].copy_from_slice(&envelope.bytes[envelope.written..end]);
                Some((envelope.request, envelope.written, count))
            } else {
                None
            }
        };
        let Some((id, offset, count)) = copied else {
            return Poll::Pending;
        };
        match stream.try_write(&self.output[..count]) {
            Ok(0) => Poll::Ready(self.lost(epoch, Error::Io, now, observer)),
            Ok(n) => {
                let mut state = self.context.lock()?;
                let front = state.mq.queue.front_mut().ok_or(Error::NotReady)?;
                if front.request != id || front.written != offset {
                    return Poll::Ready(Err(Error::Stale.into()));
                }
                front.written += n;
                if front.written == front.len {
                    let envelope = state.mq.queue.pop_front().ok_or(Error::NotReady)?;
                    state.mq.free.push(envelope.bytes);
                    if let Some(credit) = state.credits.iter_mut().find(|credit| credit.id == id) {
                        credit.pending_tx = false;
                    } else {
                        return Poll::Ready(Err(Error::Stale.into()));
                    }
                    state.reconcile_credits();
                }
                Poll::Ready(Ok(Progress::Activity))
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) =>
            {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(error) => {
                self.last_io_error = Some(error);
                Poll::Ready(self.lost(epoch, Error::Io, now, observer))
            }
        }
    }
    fn poll_read(
        &mut self,
        cx: &mut TaskContext<'_>,
        epoch: ConnectionEpoch,
        now: AbsoluteTime,
        observer: &mut impl FnMut(DriverEvent),
    ) -> Poll<Result<Progress, BrokerError>> {
        let Some(stream) = self.stream.as_mut() else {
            return Poll::Pending;
        };
        let end = self
            .expected
            .min(self.used.saturating_add(self.limits.io_chunk_bytes));
        let mut output = ReadBuf::new(&mut self.input[self.used..end]);
        match Pin::new(stream).poll_read(cx, &mut output) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Ready(Err(e)) => {
                self.last_io_error = Some(e);
                return Poll::Ready(self.lost(epoch, Error::Io, now, observer));
            }
            Poll::Ready(Ok(())) => {}
        }
        let n = output.filled().len();
        if n == 0 {
            return Poll::Ready(self.lost(
                epoch,
                if self.used == 0 {
                    Error::Io
                } else {
                    Error::Truncated
                },
                now,
                observer,
            ));
        }
        self.used += n;
        if self.used == 4 {
            let header = match MessageHeader::decode(&self.input[..4]) {
                Ok(h) => h,
                Err(e) => return Poll::Ready(self.lost(epoch, e, now, observer)),
            };
            if header.size() > self.input.len() {
                return Poll::Ready(self.lost(epoch, Error::Capacity, now, observer));
            }
            self.expected = header.size();
        }
        if self.used != self.expected {
            return Poll::Ready(Ok(Progress::Activity));
        }
        let size = self.expected;
        self.used = 0;
        self.expected = 4;
        let frame = Frame::decode(&self.input[..size])?;
        if frame.header().message_type() != message_type::RESOLVER_RESPONSE {
            return Poll::Ready(Ok(Progress::Activity));
        }
        let result = { self.context.lock()?.core.receive(epoch, frame, now) };
        match result {
            Ok(Some(event)) => self.context.publish(event)?,
            Ok(None) => {
                let continuation = {
                    let mut state = self.context.lock()?;
                    if state.core.terminal_callbacks_pending() {
                        state.core.next_event(now)
                    } else {
                        None
                    }
                };
                if let Some(event) = continuation {
                    self.context.publish(event)?;
                } else {
                    self.context.lock()?.pump(now);
                }
            }
            Err(cause) => return Poll::Ready(self.lost(epoch, cause, now, observer)),
        };
        Poll::Ready(Ok(Progress::Activity))
    }
    fn poll_connect(
        &mut self,
        cx: &mut TaskContext<'_>,
        epoch: ConnectionEpoch,
        observer: &mut impl FnMut(DriverEvent),
    ) -> Poll<Result<Progress, BrokerError>> {
        if self.pending_native_error.is_some() {
            return Poll::Ready(self.register_native_failure(epoch, observer));
        }
        if let Some(connecting) = &mut self.connecting {
            match Pin::new(connecting).poll(cx) {
                Poll::Pending => {}
                Poll::Ready(Ok(stream)) => {
                    self.connecting = None;
                    self.stream = Some(stream);
                    self.socket_retry = None;
                    observer(DriverEvent::Connected(epoch));
                    return Poll::Ready(Ok(Progress::Activity));
                }
                Poll::Ready(Err(e)) => {
                    if gnunet_client_host::resolution::PortError::from_io(&e).is_some() {
                        return Poll::Ready(Err(BrokerError::Io(e)));
                    }
                    self.connecting = None;
                    self.pending_native_error = Some(e);
                    return Poll::Ready(self.register_native_failure(epoch, observer));
                }
            }
        }
        Poll::Pending
    }
    fn register_native_failure(
        &mut self,
        epoch: ConnectionEpoch,
        observer: &mut impl FnMut(DriverEvent),
    ) -> Result<Progress, BrokerError> {
        // add_delayed samples source time after the actual native failure. A
        // source error keeps this original OS error, epoch and immutable frames;
        // retry only registration, never the already consumed connect future.
        let now = self.context.sample()?.now;
        let error = self.pending_native_error.take().ok_or(Error::NotReady)?;
        self.socket_backoff = self
            .socket_backoff
            .max(1000)
            .saturating_mul(2)
            .min(900_000_000);
        let at = AbsoluteTime::from_micros(now.as_micros().saturating_add(self.socket_backoff));
        self.socket_retry = Some(at);
        self.last_io_error = Some(error);
        observer(DriverEvent::SocketRetry { epoch, at });
        Ok(Progress::Activity)
    }
    fn poll_step(
        &mut self,
        cx: &mut TaskContext<'_>,
        budget: Option<Instant>,
        observer: &mut impl FnMut(DriverEvent),
    ) -> Poll<Result<Progress, BrokerError>> {
        if budget.is_some_and(|at| Instant::now() >= at) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        match self
            .clock_subscription
            .poll_changed(cx, self.clock_revision)
        {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(sample)) => self.clock_revision = sample.revision,
            Poll::Pending => {}
        }
        let sample = self.context.sample()?;
        self.clock_revision = sample.revision;
        match self.clock_subscription.poll_changed(cx, sample.revision) {
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
            Poll::Ready(Ok(_)) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Pending => {}
        }
        let now = sample.now;
        let pending = {
            let mut state = self.context.lock()?;
            if !state.alive {
                return Poll::Ready(Err(BrokerError::OwnerLost));
            }
            if let Some(error) = state.pending_error.take() {
                return Poll::Ready(Err(error.into()));
            }
            state.driver_waker = Some(cx.waker().clone());
            state.pending.is_some()
        };
        if pending {
            if self.context.inline_pending()? {
                let epoch = self.epoch.ok_or(Error::NotReady)?;
                if let Poll::Ready(result) = self.poll_connect(cx, epoch, observer) {
                    return Poll::Ready(result);
                }
                if self.context.lock()?.pending.is_none() {
                    return Poll::Ready(Ok(Progress::Activity));
                }
            }
            return self.timer(cx, now, budget, true);
        }
        self.sync()?;
        let event = { self.context.lock()?.core.next_event(now) };
        if let Some(event) = event {
            self.context.publish(event)?;
            return Poll::Ready(Ok(Progress::Activity));
        }
        let idle = { self.context.lock()?.core.poll_idle_close(now) };
        if let Some(epoch) = idle {
            self.sync()?;
            observer(DriverEvent::IdleClosed(epoch));
            return Poll::Ready(Ok(Progress::Activity));
        }
        let need = { self.context.lock()?.core.connection_needed(now) };
        if need {
            let selected = { self.context.lock()?.selected.clone() };
            match Endpoint::configuration_live(
                selected,
                b"resolver",
                self.context.inline_resolution(),
            ) {
                Ok(endpoint) => {
                    let epoch = {
                        let mut state = self.context.lock()?;
                        if !state.core.connection_needed(now) {
                            None
                        } else {
                            {
                                let epoch = state.core.begin_connection(now)?;
                                state.pump(now);
                                Some(epoch)
                            }
                        }
                    };
                    if let Some(epoch) = epoch {
                        // The previous epoch was synchronized before begin_connection.
                        // Newly admitted envelopes now belong to this MQ; clearing
                        // here would discard the synchronous source MQ ownership.
                        self.epoch = Some(epoch);
                        self.endpoint = Some(endpoint);
                        self.socket_retry = Some(now);
                        self.socket_ready = true;
                    }
                }
                Err(error) => {
                    let mut state = self.context.lock()?;
                    if state.core.connection_needed(now) {
                        state.core.connection_unavailable(now)?;
                    }
                    drop(state);
                    self.last_connect_error = Some(error.into());
                    observer(DriverEvent::Unavailable);
                    return Poll::Ready(Ok(Progress::Activity));
                }
            }
        }
        let Some(epoch) = self.epoch else {
            let wake = { self.context.lock()?.core.next_wakeup() };
            if wake.is_none() && self.context.lock()?.core.pending_requests() == 0 {
                return Poll::Ready(Ok(Progress::Idle));
            }
            return self.timer(cx, now, budget, false);
        };

        if self.stream.is_none() {
            if self.connecting.is_none()
                && self.pending_native_error.is_none()
                && (self.socket_ready
                    || self
                        .socket_retry
                        .is_some_and(|at| at.as_micros() != u64::MAX && at <= now))
            {
                self.connecting = Some(
                    self.endpoint
                        .as_ref()
                        .ok_or(Error::NotReady)?
                        .attempt(self.socket_round),
                );
                self.socket_round = self.socket_round.wrapping_add(1);
                self.socket_ready = false;
                self.socket_retry = None;
            }
            if let Poll::Ready(result) = self.poll_connect(cx, epoch, observer) {
                return Poll::Ready(result);
            }
            return self.timer(cx, now, budget, false);
        }
        self.read_first = !self.read_first;
        let first = if self.read_first {
            self.poll_read(cx, epoch, now, observer)
        } else {
            self.poll_write(cx, epoch, now, observer)
        };
        if first.is_ready() {
            return first;
        }
        let second = if self.read_first {
            self.poll_write(cx, epoch, now, observer)
        } else {
            self.poll_read(cx, epoch, now, observer)
        };
        if second.is_ready() {
            return second;
        }
        self.timer(cx, now, budget, false)
    }
    /// Wait for real broker work, its original timers, or the supplied real
    /// budget. An empty broker registers the shared admission waker instead of
    /// repeatedly returning Idle; suitable for a process reactor with other MQs.
    pub async fn drive_waiting(
        &mut self,
        budget: Option<Instant>,
        mut observer: impl FnMut(DriverEvent),
    ) -> Result<Progress, BrokerError> {
        let progress = poll_fn(|cx| match self.poll_step(cx, budget, &mut observer) {
            Poll::Ready(Ok(Progress::Idle)) => Poll::Pending,
            other => other,
        })
        .await?;
        if progress == Progress::Activity {
            tokio::task::yield_now().await;
        }
        Ok(progress)
    }
    /// Drive one original shared owner's I/O/timer/effect step. Dropping this future
    /// retains all cursors and original query deadlines. A callback Delivery lease
    /// must return before another callback/timer effect is processed.
    pub async fn drive(
        &mut self,
        budget: Option<Instant>,
        mut observer: impl FnMut(DriverEvent),
    ) -> Result<Progress, BrokerError> {
        let progress = poll_fn(|cx| self.poll_step(cx, budget, &mut observer)).await?;
        if progress == Progress::Activity {
            tokio::task::yield_now().await;
        }
        Ok(progress)
    }
}
impl<const R: usize, const N: usize> Drop for Driver<R, N> {
    fn drop(&mut self) {
        self.clear();
        self.context.owner_lost();
    }
}
