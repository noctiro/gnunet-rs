//! Actual caller-polled SERVICE admission and local pinned original sessions.
use crate::{
    Error, Event, Report, ServerLimits, ServerProgress, SessionReport, Sources,
    run::{Control, Registry},
};
use gnunet_service_runtime::{
    accepted::{AcceptState, AcceptedConnection, SocketEvent},
    credentials::UnixAccess,
    framing::{Accounting, Budget, Framed, Limits as FrameLimits},
    service::{Listener, PeerAddress, ServiceOptions, ShutdownMode},
};
use gnunet_types::Error as Fault;
use std::{
    cell::RefCell,
    future::{Future, poll_fn},
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll, Waker},
};
use tokio::time::{Instant, Sleep};
struct Running {
    id: u64,
    control: Rc<Control>,
    future: Pin<Box<dyn Future<Output = SessionReport>>>,
}
/// Real ordinary SERVICE owner. Every original local future is polled here;
/// there is no spawn, hidden runtime, cross-session PILS identity or source reuse.
pub struct Server {
    sources: Sources,
    limits: ServerLimits,
    options: ServiceOptions,
    unix: UnixAccess,
    accept: AcceptState,
    apps: Vec<Option<Running>>,
    registry: Rc<RefCell<Registry>>,
    next: Option<u64>,
    cursor: usize,
    listener_cursor: usize,
    shutdown: Option<ShutdownMode>,
    timer: Option<Pin<Box<Sleep>>>,
    waker: Option<Waker>,
    report: Report,
}
impl Server {
    /// Reserve only bounded session/registry metadata. No socket, PILS, SET,
    /// native timer, secret or implicit source is started before actual polling.
    pub fn new(
        sources: Sources,
        limits: ServerLimits,
        options: ServiceOptions,
        unix: UnixAccess,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let available = limits
            .total_retained_bytes
            .checked_sub(sources.retained_bytes())
            .ok_or(Fault::Capacity)?;
        let count = limits.clients.min(available / limits.session_bytes);
        if count == 0 {
            return Err(Fault::Capacity.into());
        }
        let mut apps = Vec::new();
        apps.try_reserve_exact(count).map_err(|_| Fault::Capacity)?;
        let registry = Registry::new(count)?;
        let registry_bytes = registry.retained_bytes()?;
        let fixed = sources
            .retained_bytes()
            .checked_add(std::mem::size_of::<Self>())
            .and_then(|n| {
                apps.capacity()
                    .checked_mul(std::mem::size_of::<Option<Running>>())
                    .and_then(|m| n.checked_add(m))
            })
            .and_then(|n| n.checked_add(registry_bytes))
            .ok_or(Fault::Overflow)?;
        let count = count.min(
            limits
                .total_retained_bytes
                .checked_sub(fixed)
                .ok_or(Fault::Capacity)?
                / limits.session_bytes,
        );
        if count == 0 {
            return Err(Fault::Capacity.into());
        }
        apps.resize_with(count, || None);
        let registry = Rc::new(RefCell::new(registry));
        Ok(Self {
            sources,
            limits,
            options,
            unix,
            accept: AcceptState::default(),
            apps,
            registry,
            next: Some(1),
            cursor: 0,
            listener_cursor: 0,
            shutdown: None,
            timer: None,
            waker: None,
            report: Report::default(),
        })
    }
    /// Actual caller-owned shared clock, without a new domain or subscriber.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn gnunet_service_runtime::clock::RuntimeClock> {
        self.sources.clock()
    }
    /// SERVICE IPC admission is active. This does not assert a live PILS/SET
    /// dependency, consensus result, peer acceptance or runtime interop proof.
    #[must_use]
    pub fn ready(&self) -> bool {
        self.shutdown.is_none()
    }
    /// Actual terminal aggregate counters; exact causes stay in Closed events.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.report
    }
    /// Admit one actual initialized socket under standard ACL/Unix credentials.
    /// First/whole hard targets start before fallible admission providers.
    pub fn admit(
        &mut self,
        accepted: AcceptedConnection,
        observe: &mut impl FnMut(Event),
    ) -> Result<Option<u64>, Error> {
        let admitted_at = std::time::Instant::now();
        let origin = crate::run::origin(self.sources.clock().as_ref(), self.limits, admitted_at)?;
        let (connection, address, diagnostics) = accepted.into_parts();
        for diagnostic in diagnostics {
            observe(Event::Socket(SocketEvent::Diagnostic(diagnostic)));
        }
        let allowed = match address {
            PeerAddress::Tcp(ip) => self.options.access.allows(ip.ip()),
            PeerAddress::Unix => self.unix.allows(&connection)?,
        };
        if !allowed {
            drop(connection);
            observe(Event::Rejected(address));
            return Ok(None);
        }
        if self.shutdown.is_some() {
            return Err(Fault::Closed.into());
        }
        let at = self
            .apps
            .iter()
            .position(Option::is_none)
            .ok_or(Fault::Capacity)?;
        let id = self.next.ok_or(Fault::Overflow)?;
        let sources = self.sources.duplicate()?;
        let io = Framed::new(
            connection,
            FrameLimits {
                frame_bytes: self.limits.frame_bytes,
                ordinary: Budget {
                    frames: 1,
                    bytes: self.limits.frame_bytes,
                },
                reserved: Budget::default(),
                accounting: Accounting::Retained,
                io_slice_bytes: self.limits.io_slice_bytes,
            },
        )?;
        if std::time::Instant::now() >= origin.first.hard {
            return Err(Fault::Deadline.into());
        }
        let control = Rc::new(Control::new());
        let future = Box::pin(crate::run::session(
            id,
            io,
            sources,
            self.limits,
            origin,
            self.registry.clone(),
            control.clone(),
        ));
        self.apps[at] = Some(Running {
            id,
            control,
            future,
        });
        self.next = id.checked_add(1);
        self.report.accepted = self.report.accepted.saturating_add(1);
        observe(Event::Accepted(id));
        Ok(Some(id))
    }
    fn finished(
        &mut self,
        index: usize,
        report: SessionReport,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Error> {
        let owner = self.apps[index].take().ok_or(Fault::StaleGeneration)?;
        if report.physical_closed {
            self.accept.client_closed();
            self.report.closed = self.report.closed.saturating_add(1);
        }
        if report.outcome.is_some_and(|o| o.client_done_written) {
            self.report.results_written = self.report.results_written.saturating_add(1);
        }
        if report.primary.is_some() || report.outcome.is_some_and(|o| o.failure.is_some()) {
            self.report.failed = self.report.failed.saturating_add(1);
        }
        self.report.undrained = self.report.undrained.saturating_add(report.undrained);
        let undrained = report.undrained != 0;
        observe(Event::Closed {
            client: owner.id,
            report,
        });
        if undrained {
            self.request_shutdown(ShutdownMode::Immediate);
            return Err(Fault::NotReady.into());
        }
        Ok(())
    }
    /// Stop admission. Immediate flags each original session's clock-free close;
    /// Soft preserves its original bound until foreground grace requests Immediate.
    pub fn request_shutdown(&mut self, mode: ShutdownMode) {
        if self.shutdown != Some(ShutdownMode::Immediate) {
            self.shutdown = Some(mode);
        }
        if self.shutdown == Some(ShutdownMode::Immediate) {
            for app in self.apps.iter().flatten() {
                app.control.cancel(Fault::Cancelled);
            }
        }
        if let Some(waker) = &self.waker {
            waker.wake_by_ref();
        }
    }
    /// Poll actual retained local sessions/listeners with stable fairness cursors.
    /// Canceling observation never drops or relaunches any original future.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        wait: Option<Instant>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<ServerProgress, Error>> {
        self.waker = Some(cx.waker().clone());
        if wait.is_some_and(|at| Instant::now() >= at) {
            return Poll::Ready(Ok(ServerProgress::WaitDeadline));
        }
        let count = self.apps.len();
        for offset in 0..count {
            let at = (self.cursor + offset) % count;
            if let Some(app) = self.apps[at].as_mut()
                && let Poll::Ready(report) = app.future.as_mut().poll(cx)
            {
                self.cursor = (at + 1) % count;
                self.finished(at, report, observe)?;
                return Poll::Ready(Ok(
                    if self.shutdown.is_some() && self.apps.iter().all(Option::is_none) {
                        ServerProgress::Stopped
                    } else {
                        ServerProgress::Activity
                    },
                ));
            }
        }
        self.cursor = (self.cursor + 1) % count;
        if self.shutdown.is_some() && self.apps.iter().all(Option::is_none) {
            return Poll::Ready(Ok(ServerProgress::Stopped));
        }
        if self.shutdown.is_none() && self.accept.ready() && self.apps.iter().any(Option::is_none) {
            for offset in 0..listeners.len() {
                let at = (self.listener_cursor + offset) % listeners.len();
                match listeners[at].poll_canonical_connection(cx) {
                    Poll::Pending => {}
                    Poll::Ready(Err(error)) => {
                        self.listener_cursor = (at + 1) % listeners.len();
                        observe(Event::Socket(self.accept.failed(error)));
                        return Poll::Ready(Ok(ServerProgress::Activity));
                    }
                    Poll::Ready(Ok(accepted)) => {
                        self.listener_cursor = (at + 1) % listeners.len();
                        if let Err(error) = self.admit(accepted, observe) {
                            observe(Event::AdmissionFailed(error));
                        }
                        return Poll::Ready(Ok(ServerProgress::Activity));
                    }
                }
            }
        }
        if let Some(at) = wait {
            let timer = self
                .timer
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(at)));
            timer.as_mut().reset(at);
            if timer.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Ok(ServerProgress::WaitDeadline));
            }
        }
        Poll::Pending
    }
    /// Cancellation-safe actual owner observation, never an implicit service run.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        wait: Option<Instant>,
        mut observe: impl FnMut(Event),
    ) -> Result<ServerProgress, Error> {
        poll_fn(|cx| self.poll(cx, listeners, wait, &mut observe)).await
    }
    /// Clock-free physical shutdown of every original session. Its cleanup branch
    /// closes actual sockets first, then drains within original retirement grace;
    /// any remaining debt returns NotReady and is reported, never successful.
    pub fn shutdown(&mut self, mut observe: impl FnMut(Event)) -> Result<Report, Error> {
        self.request_shutdown(ShutdownMode::Immediate);
        let mut cx = Context::from_waker(Waker::noop());
        let mut first = None;
        // Pass1 stops every original physical owner before any session's
        // potentially large pure bookkeeping pass. Pass2 returns its report.
        for pass in 0..2 {
            for at in 0..self.apps.len() {
                let progress = self.apps[at]
                    .as_mut()
                    .map(|a| a.future.as_mut().poll(&mut cx));
                match progress {
                    Some(Poll::Ready(report)) => {
                        if let Err(error) = self.finished(at, report, &mut observe) {
                            first.get_or_insert(error);
                        }
                    }
                    Some(Poll::Pending) if pass == 1 => {
                        first.get_or_insert_with(|| Fault::NotReady.into());
                    }
                    Some(Poll::Pending) | None => {}
                }
            }
        }
        if let Some(error) = first {
            Err(error)
        } else {
            Ok(self.report)
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _actual = self.shutdown(|_| {});
    }
}
