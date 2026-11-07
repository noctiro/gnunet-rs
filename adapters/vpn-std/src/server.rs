//! Actual local SERVICE sockets. Each partial original belongs to one MQ until
//! whole writing or physical close; the pure engine and its pools are external.
use gnunet_service_runtime::{
    accepted::{AcceptState, AcceptedConnection, SocketEvent},
    clock::{ClockSubscription, RuntimeClock},
    credentials::UnixAccess,
    framing::{Accounting, Budget, Class, Framed, Limits as FrameLimits, OwnedFrame, ReadStep},
    service::{Listener, PeerAddress, ServiceOptions, ShutdownMode},
};
use gnunet_types::{AbsoluteTime, Error as Fault, MonoInstant};
use gnunet_vpn::{Client, Effect, Engine, Outcome, Request, RequestInfo, WireRequest};
use gnunet_wire::official::{Frame, message_type as mt};
use std::{
    fmt,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
mod types;
pub use types::{CloseCause, Error, Event, Limits, Progress, Report, Shutdown};
mod apps;
#[derive(Clone, Copy)]
struct Output<'id> {
    effect: Effect<'id>,
    request: Request<'id>,
    hard: Instant,
}
struct Held<'id> {
    frame: OwnedFrame,
    output: Output<'id>,
}
struct App<'id> {
    client: Client<'id>,
    io: Framed<Effect<'id>>,
    requests: usize,
    blocked: bool,
    held: Option<Held<'id>>,
    queued: Option<Output<'id>>,
    read_hard: Option<Instant>,
    send_hard: Option<Instant>,
    cursor: usize,
}
/// One bounded production local SERVICE port. No listener, TUN, route, discovery,
/// CADET source, private key or worker is created by this owner. The caller owns
/// all pure pools and supplies the same canonical clock as its coordinator.
pub struct Server<'id, 'store, 'bytes> {
    core: Engine<'id, 'store, 'bytes>,
    apps: Vec<Option<App<'id>>>,
    limits: Limits,
    options: ServiceOptions,
    unix: UnixAccess,
    clock: Arc<dyn RuntimeClock>,
    subscription: Box<dyn ClockSubscription>,
    revision: u64,
    anchor: Instant,
    accept: AcceptState,
    app_cursor: usize,
    listener_cursor: usize,
    class: usize,
    shutdown: Option<ShutdownMode>,
    stop_at: Option<Instant>,
    timer: Pin<Box<Sleep>>,
    maintenance: Instant,
    stopped: bool,
    report: Report,
}
impl<'id, 'store, 'bytes> Server<'id, 'store, 'bytes> {
    /// Bind an untouched pure owner to one fixed native activity epoch, reserve
    /// bounded metadata and one original clock subscription. Prior sampling or
    /// retired work is refused before native setup; every physical backend
    /// remains the caller's work.
    pub fn new(
        core: Engine<'id, 'store, 'bytes>,
        clock: Arc<dyn RuntimeClock>,
        limits: Limits,
        options: ServiceOptions,
        unix: UnixAccess,
    ) -> Result<Self, Error> {
        if !core.is_pristine() {
            return Err(Fault::InvalidInput.into());
        }
        limits.validate()?;
        tokio::runtime::Handle::try_current().map_err(|e| io::Error::other(e.to_string()))?;
        let subscription = clock.subscribe()?;
        let revision = clock.sample()?.revision;
        let mut apps = Vec::new();
        apps.try_reserve_exact(limits.clients)
            .map_err(|_| Fault::Capacity)?;
        apps.resize_with(limits.clients, || None);
        let now = Instant::now();
        Ok(Self {
            core,
            apps,
            limits,
            options,
            unix,
            clock,
            subscription,
            revision,
            anchor: now,
            accept: AcceptState::default(),
            app_cursor: 0,
            listener_cursor: 0,
            class: 0,
            shutdown: None,
            stop_at: None,
            timer: Box::pin(tokio::time::sleep_until(now)),
            maintenance: now,
            stopped: false,
            report: Report::default(),
        })
    }
    /// Pure engine facts without granting native endpoint success.
    #[must_use]
    pub const fn engine(&self) -> &Engine<'id, 'store, 'bytes> {
        &self.core
    }
    /// Explicit coordinator access to real TUN/routing/discovery/CADET ports.
    /// The coordinator must not take over this owner's Client/effect ports or
    /// retire its request rows. Local cancellation via cancel_request is valid;
    /// the original queued/exposed response still drains on its original MQ.
    pub const fn engine_mut(&mut self) -> &mut Engine<'id, 'store, 'bytes> {
        &mut self.core
    }
    /// Shared canonical source; cloning reserves no hidden subscription.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    /// Actual local counters, with no full VPN or remote completion claim.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.report
    }
    /// Whether every owned actual local MQ has physically retired.
    #[must_use]
    pub fn ipc_quiescent(&self) -> bool {
        self.apps.iter().all(Option::is_none)
    }
    fn framing(&self) -> FrameLimits {
        FrameLimits {
            frame_bytes: self.limits.frame_bytes,
            ordinary: Budget {
                frames: 1,
                bytes: 32,
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.limits.io_slice_bytes,
        }
    }
    fn hard(duration: Duration) -> Result<Instant, Error> {
        Instant::now()
            .checked_add(duration)
            .ok_or(Fault::Overflow.into())
    }
    fn activity(&self) -> Result<MonoInstant, Error> {
        let elapsed = Instant::now()
            .checked_duration_since(self.anchor)
            .ok_or(Fault::TimeUncertain)?;
        Ok(MonoInstant(
            u64::try_from(elapsed.as_micros()).map_err(|_| Fault::Overflow)?,
        ))
    }
    /// The coordinator samples through this owner so all flow activity belongs
    /// to the exact same native epoch as local SERVICE maintenance. No second
    /// wall offset, clock subscription or activity anchor is constructed.
    pub(super) fn sample(&self) -> Result<(AbsoluteTime, MonoInstant), Error> {
        let absolute = self.clock.sample()?.now;
        Ok((absolute, self.activity()?))
    }
    fn now(&mut self, cx: &mut Context<'_>) -> Result<(AbsoluteTime, MonoInstant), Error> {
        match self.subscription.poll_changed(cx, self.revision) {
            Poll::Ready(Err(e)) => return Err(e.into()),
            Poll::Ready(Ok(sample)) => self.revision = sample.revision,
            Poll::Pending => {}
        }
        let mut sample = self.clock.sample()?;
        self.revision = sample.revision;
        match self.subscription.poll_changed(cx, sample.revision) {
            Poll::Ready(Err(e)) => return Err(e.into()),
            Poll::Ready(Ok(changed)) => {
                sample = changed;
                self.revision = changed.revision;
                cx.waker().wake_by_ref();
            }
            Poll::Pending => {}
        }
        Ok((sample.now, self.activity()?))
    }
    /// Pause acceptance and new request reads. Existing actual response debt
    /// drains under its original send bound and one original shutdown grace.
    /// Repeated requests do not extend that grace. Immediate requires no clock.
    pub fn request_shutdown(&mut self, mode: ShutdownMode) {
        if self.shutdown == Some(ShutdownMode::Immediate) {
            return;
        }
        if mode == ShutdownMode::Immediate {
            self.shutdown = Some(mode);
            self.stop_at = Some(Instant::now());
        } else if self.shutdown.is_none() {
            self.stop_at = Instant::now().checked_add(self.limits.shutdown_grace);
            self.shutdown = Some(if self.stop_at.is_some() {
                mode
            } else {
                ShutdownMode::Immediate
            });
        }
    }
    fn accept(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        if self.shutdown.is_some() || !self.accept.ready() || self.apps.iter().all(Option::is_some)
        {
            return Poll::Pending;
        }
        for n in 0..listeners.len() {
            let i = (self.listener_cursor + n) % listeners.len();
            match listeners[i].poll_canonical_connection(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(e)) => {
                    self.listener_cursor = (i + 1) % listeners.len();
                    observe(Event::Socket(self.accept.failed(e)));
                    return Poll::Ready(Ok(Progress::Activity));
                }
                Poll::Ready(Ok(a)) => {
                    self.listener_cursor = (i + 1) % listeners.len();
                    if let Err(e) = self.admit(a, observe) {
                        observe(Event::AdmissionFailed(e));
                    }
                    return Poll::Ready(Ok(Progress::Activity));
                }
            }
        }
        Poll::Pending
    }
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        deadline: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        if self.stopped {
            return Poll::Ready(Ok(Progress::Stopped));
        }
        if self.shutdown == Some(ShutdownMode::Immediate)
            || self.stop_at.is_some_and(|at| Instant::now() >= at)
        {
            let done = self.shutdown(&mut *observe);
            return Poll::Ready(match done.failure {
                Some(e) => Err(e),
                None => Ok(Progress::Stopped),
            });
        }
        let (absolute, activity) = self.now(cx)?;
        let expired = self.core.expire(absolute, activity)?;
        if self.hard_limits(observe)? {
            return Poll::Ready(Ok(Progress::Activity));
        }
        if self.shutdown.is_some() && self.ipc_quiescent() {
            self.stopped = true;
            return Poll::Ready(Ok(Progress::Stopped));
        }
        if deadline.is_some_and(|at| Instant::now() >= at) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        for n in 0..2 {
            let class = (self.class + n) % 2;
            let result = if class == 0 {
                self.poll_apps(cx, absolute, observe)
            } else {
                self.accept(cx, listeners, observe)
            };
            if result.is_ready() {
                self.class = (class + 1) % 2;
                return result;
            }
        }
        if expired != 0 {
            return Poll::Ready(Ok(Progress::Activity));
        }
        let at = Instant::now();
        if at >= self.maintenance {
            self.maintenance = at
                .checked_add(self.limits.maintenance_interval)
                .ok_or(Fault::Overflow)?;
        }
        let wake = Some(self.maintenance)
            .into_iter()
            .chain(deadline)
            .chain(self.stop_at)
            .chain(self.apps.iter().flatten().flat_map(|app| {
                app.read_hard
                    .into_iter()
                    .chain(app.send_hard)
                    .chain(app.held.as_ref().map(|h| h.output.hard))
                    .chain(app.queued.map(|q| q.hard))
            }))
            .min()
            .ok_or(Fault::NotReady)?;
        self.timer.as_mut().reset(wake);
        if self.timer.as_mut().poll(cx).is_ready() {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
    /// One bounded fair scheduling step. Any original fatal clock/core error
    /// physically closes every actual MQ before the original error is returned.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        deadline: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        match self.poll_inner(cx, listeners, deadline, observe) {
            Poll::Ready(Err(original)) => {
                let fault = match &original {
                    Error::Protocol(e) => *e,
                    Error::Io(_) => Fault::Closed,
                };
                let done = self.close_all(Some(fault), &mut *observe);
                if let Some(error) = done.failure {
                    match error {
                        Error::Protocol(e) => observe(Event::CleanupFailed(e)),
                        Error::Io(_) => {}
                    }
                }
                Poll::Ready(Err(original))
            }
            other => other,
        }
    }
    /// Await one event on the caller's runtime. Dropping this future preserves
    /// partial RX/TX, original request debts and original finite send deadlines.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        deadline: Option<Instant>,
        mut observe: impl FnMut(Event<'id>),
    ) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll(cx, listeners, deadline, &mut observe)).await
    }
    /// Independently close all actual MQs without sampling the logical clock,
    /// then settle original client/request debt. Other engine ports stay owned
    /// by the coordinator; local IPC shutdown is not full VPN quiescence.
    pub fn shutdown(&mut self, mut observe: impl FnMut(Event<'id>)) -> Shutdown {
        self.close_all(None, &mut observe)
    }
    fn close_all(
        &mut self,
        cause: Option<Fault>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Shutdown {
        self.shutdown = Some(ShutdownMode::Immediate);
        // First stop every independent physical source. A callback failure below
        // cannot strand another MQ or require a functioning clock to close it.
        for app in self.apps.iter_mut().flatten() {
            app.io.retire();
        }
        let mut failure = None;
        for i in 0..self.apps.len() {
            if self.apps[i].is_some()
                && let Err(e) = self.stop(
                    i,
                    cause.map_or(CloseCause::Shutdown, |e| CloseCause::Fault(e.into())),
                    observe,
                )
                && failure.is_none()
            {
                failure = Some(e);
            }
        }
        self.stopped = true;
        Shutdown {
            report: self.report,
            failure,
        }
    }
}

#[cfg(test)]
mod time_tests;
impl Drop for Server<'_, '_, '_> {
    fn drop(&mut self) {
        for app in self.apps.iter_mut().flatten() {
            app.io.retire();
        }
        for app in &mut self.apps {
            if let Some(app) = app.take() {
                let _lost = self.core.client_lost(app.client, Fault::Closed);
                loop {
                    let next = self
                        .core
                        .requests()
                        .find(|r| self.core.request_client(*r) == Ok(app.client));
                    let Some(request) = next else {
                        break;
                    };
                    if self.core.retire_request(request).is_err() {
                        break;
                    }
                }
            }
        }
    }
}
