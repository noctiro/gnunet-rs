use crate::run::{self, Control, Events, LineLease, LocalEvent, Mailbox, Origin, Registry};
use crate::{Error, Event, Limits, LineReport, Progress, Report, Sources};
use gnunet_service_runtime::{
    accepted::{AcceptState, AcceptedConnection, SocketEvent},
    credentials::UnixAccess,
    framing::{Accounting, Budget, Framed, Limits as Framing},
    service::{Listener, PeerAddress, ServiceOptions, ShutdownMode},
};
use gnunet_types::Error as Fault;
use std::{
    future::{Future, poll_fn},
    mem::{size_of, size_of_val},
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll, Waker},
};
use tokio::time::{Instant, Sleep};
struct Running {
    id: u64,
    control: Arc<Control>,
    events: Mailbox,
    future: Pin<Box<dyn Future<Output = LineReport>>>,
    terminal: Option<LineReport>,
    _lease: LineLease,
}
/// Fair explicitly polled native service. Each Line owns one pinned local
/// future; neither native dependency nor media work is spawned or detached.
pub struct Server {
    sources: Sources,
    limits: Limits,
    options: ServiceOptions,
    unix: UnixAccess,
    accept: AcceptState,
    clients: Vec<Option<Running>>,
    registry: Rc<Registry>,
    next: Option<u64>,
    cursor: usize,
    listener_cursor: usize,
    shutdown: Option<ShutdownMode>,
    timer: Pin<Box<Sleep>>,
    waker: Option<Waker>,
    report: Report,
}
impl Server {
    /// Reserve bounded owner metadata and selected endpoints. READY describes
    /// IPC admission only; no PILS identity, channel, media or device is implied.
    pub fn new(
        sources: Sources,
        limits: Limits,
        options: ServiceOptions,
        unix: UnixAccess,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let mut clients = Vec::new();
        clients
            .try_reserve_exact(limits.clients)
            .map_err(|_| Fault::Capacity)?;
        clients.resize_with(limits.clients, || None);
        let table = clients
            .capacity()
            .checked_mul(size_of::<Option<Running>>())
            .ok_or(Fault::Overflow)?;
        let fixed = sources
            .fixed_bytes
            .checked_add(table)
            .and_then(|n| n.checked_add(size_of::<Self>()))
            .and_then(|n| {
                n.checked_add(size_of::<Registry>() + 2 * size_of::<usize>() + size_of::<Sleep>())
            })
            .ok_or(Fault::Overflow)?;
        let registry = Rc::new(Registry::new(limits, fixed)?);
        Ok(Self {
            sources,
            limits,
            options,
            unix,
            accept: AcceptState::default(),
            clients,
            registry,
            next: Some(1),
            cursor: 0,
            listener_cursor: 0,
            shutdown: None,
            timer: Box::pin(tokio::time::sleep(std::time::Duration::ZERO)),
            waker: None,
            report: Report::default(),
        })
    }
    /// Same caller-selected shared clock, without another subscription.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn gnunet_service_runtime::clock::RuntimeClock> {
        self.sources.clock()
    }
    /// Actual IPC admission initialization only. Caller must bind real listeners.
    #[must_use]
    pub fn ready(&self) -> bool {
        self.shutdown.is_none() && self.registry.healthy()
    }
    /// Actual bounded aggregate terminal facts.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.report
    }
    /// Admit an actual canonical stream after standard TCP/Unix access policy.
    /// First original time is captured before diagnostics/providers/allocation.
    pub fn admit(
        &mut self,
        accepted: AcceptedConnection,
        observe: &mut impl FnMut(Event),
    ) -> Result<Option<u64>, Error> {
        let origin = Origin::new(self.sources.clock.as_ref())?;
        let first = origin
            .at(u64::try_from(self.limits.first_input.as_micros()).map_err(|_| Fault::Overflow)?)?;
        let startup = origin
            .at(u64::try_from(self.limits.startup.as_micros()).map_err(|_| Fault::Overflow)?)?;
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
        if !self.ready() {
            return Err(Fault::Closed.into());
        }
        let slot = self
            .clients
            .iter()
            .position(Option::is_none)
            .ok_or(Fault::Capacity)?;
        let id = self.next.ok_or(Fault::Overflow)?;
        let lease = self.registry.line()?;
        let control = Arc::new(Control::new(
            u64::try_from(self.limits.utc_uncertainty.as_micros()).map_err(|_| Fault::Overflow)?,
        ));
        control.targets(Some(if first.hard < startup.hard {
            first
        } else {
            startup
        }))?;
        control.check(self.sources.clock.as_ref(), false)?;
        let io = Framed::new(
            connection,
            Framing {
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
        let events = Rc::new(Events::new(
            self.limits
                .core
                .calls
                .checked_add(2)
                .ok_or(Fault::Overflow)?,
        )?);
        let future = run::run(
            io,
            self.sources.duplicate()?,
            self.limits,
            origin,
            first,
            startup,
            control.clone(),
            self.registry.clone(),
            events.clone(),
            self.options.tolerant,
        );
        let buffers = self
            .limits
            .core
            .calls
            .checked_mul(self.limits.cadet.frame_bytes)
            .and_then(|n| {
                n.checked_add(
                    8 * self
                        .limits
                        .frame_bytes
                        .max(self.limits.cadet.frame_bytes)
                        .max(self.limits.pils.frame_bytes),
                )
            })
            .and_then(|n| n.checked_add(self.limits.hello.maximum_address_bytes + 256 * 1024))
            .ok_or(Fault::Overflow)?;
        let event_bytes = events.retained()?;
        if size_of_val(&future)
            .checked_add(self.limits.core.retained_bytes)
            .and_then(|n| n.checked_add(buffers))
            .and_then(|n| n.checked_add(event_bytes))
            .is_none_or(|n| n > self.limits.line_bytes)
        {
            return Err(Fault::Capacity.into());
        }
        control.check(self.sources.clock.as_ref(), false)?;
        self.clients[slot] = Some(Running {
            id,
            control,
            events,
            future: Box::pin(future),
            terminal: None,
            _lease: lease,
        });
        self.next = id.checked_add(1);
        self.report.accepted = self.report.accepted.saturating_add(1);
        observe(Event::Accepted(id));
        Ok(Some(id))
    }
    fn event(row: &Running, observe: &mut impl FnMut(Event)) -> bool {
        if let Some(event) = row.events.take() {
            row.events.take_activity();
            observe(match event {
                LocalEvent::RegistrationAccepted => Event::RegistrationAccepted { client: row.id },
                LocalEvent::Identity { peer, epoch } => Event::Identity {
                    client: row.id,
                    peer,
                    epoch,
                },
                LocalEvent::ChannelDestroyed {
                    call,
                    cid,
                    channel,
                    epoch,
                    mq_current,
                } => Event::ChannelDestroyed {
                    client: row.id,
                    call,
                    cid,
                    channel,
                    epoch,
                    mq_current,
                },
                LocalEvent::CallClosed(report) => Event::CallClosed {
                    client: row.id,
                    report,
                },
            });
            true
        } else {
            false
        }
    }
    fn finished(&mut self, index: usize, observe: &mut impl FnMut(Event)) -> Result<(), Error> {
        let mut row = self.clients[index].take().ok_or(Fault::Stale)?;
        let report = row.terminal.take().ok_or(Fault::NotReady)?;
        if report.physical_closed {
            self.accept.client_closed();
            self.report.closed = self.report.closed.saturating_add(1);
        }
        self.report.calls_started = self
            .report
            .calls_started
            .saturating_add(report.calls_started);
        self.report.calls_closed = self.report.calls_closed.saturating_add(report.calls_closed);
        self.report.client_frames_written = self
            .report
            .client_frames_written
            .saturating_add(report.client_frames_written);
        self.report.peer_frames_written = self
            .report
            .peer_frames_written
            .saturating_add(report.peer_frames_written);
        if report.primary.is_some() {
            self.report.failed = self.report.failed.saturating_add(1);
        }
        self.report.undrained = self.report.undrained.saturating_add(report.undrained);
        let fatal = report.undrained != 0
            || !report.physical_closed
            || !report.cadet_closed
            || !report.pils_closed;
        observe(Event::Closed {
            client: row.id,
            report,
        });
        drop(row);
        if fatal || !self.registry.healthy() {
            self.request_shutdown(ShutdownMode::Immediate);
            Err(Fault::NotReady.into())
        } else {
            Ok(())
        }
    }
    /// Stop admission; Immediate fences all old native IO before any new poll.
    pub fn request_shutdown(&mut self, mode: ShutdownMode) {
        if self.shutdown != Some(ShutdownMode::Immediate) {
            self.shutdown = Some(mode);
        }
        if self.shutdown == Some(ShutdownMode::Immediate) {
            for row in self.clients.iter().flatten() {
                row.control.cancel(Fault::Cancelled);
            }
        }
        if let Some(w) = &self.waker {
            w.wake_by_ref();
        }
    }
    /// Fair observation of retained Lines and caller-owned real listeners.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        wait: Option<Instant>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        self.waker = Some(cx.waker().clone());
        if wait.is_some_and(|t| Instant::now() >= t) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        if !self.registry.healthy() {
            self.request_shutdown(ShutdownMode::Immediate);
        }
        let count = self.clients.len();
        for offset in 0..count {
            let index = (self.cursor + offset) % count;
            if let Some(row) = self.clients[index].as_mut() {
                if Self::event(row, observe) {
                    self.cursor = (index + 1) % count;
                    return Poll::Ready(Ok(Progress::Activity));
                }
                if row.terminal.is_none()
                    && let Poll::Ready(report) = row.future.as_mut().poll(cx)
                {
                    row.terminal = Some(report);
                }
                if Self::event(row, observe) || row.events.take_activity() {
                    self.cursor = (index + 1) % count;
                    return Poll::Ready(Ok(Progress::Activity));
                }
                if row.terminal.is_some() {
                    self.cursor = (index + 1) % count;
                    self.finished(index, observe)?;
                    return Poll::Ready(Ok(Progress::Activity));
                }
            }
        }
        self.cursor = (self.cursor + 1) % count;
        if self.shutdown.is_some() && self.clients.iter().all(Option::is_none) {
            return Poll::Ready(
                if self.registry.pending() == 0 && self.report.undrained == 0 {
                    Ok(Progress::Stopped)
                } else {
                    Err(Fault::NotReady.into())
                },
            );
        }
        if self.shutdown.is_none()
            && self.accept.ready()
            && self.clients.iter().any(Option::is_none)
        {
            for offset in 0..listeners.len() {
                let index = (self.listener_cursor + offset) % listeners.len();
                match listeners[index].poll_canonical_connection(cx) {
                    Poll::Pending => {}
                    Poll::Ready(Err(error)) => {
                        self.listener_cursor = (index + 1) % listeners.len();
                        observe(Event::Socket(self.accept.failed(error)));
                        return Poll::Ready(Ok(Progress::Activity));
                    }
                    Poll::Ready(Ok(accepted)) => {
                        self.listener_cursor = (index + 1) % listeners.len();
                        if let Err(error) = self.admit(accepted, observe) {
                            observe(Event::AdmissionFailed(error));
                        }
                        return Poll::Ready(Ok(Progress::Activity));
                    }
                }
            }
        }
        if let Some(at) = wait {
            self.timer.as_mut().reset(at);
            if self.timer.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Ok(Progress::WaitDeadline));
            }
        }
        Poll::Pending
    }
    /// Cancellation-safe wait; it retains all original cursors and call/source IDs.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        wait: Option<Instant>,
        mut observe: impl FnMut(Event),
    ) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll(cx, listeners, wait, &mut observe)).await
    }
    /// Independently attempt every original physical/core retirement clock-free.
    /// A first failure never skips later owners; no fake Stopped receipt is made.
    pub fn shutdown(&mut self, mut observe: impl FnMut(Event)) -> Result<Report, Error> {
        self.request_shutdown(ShutdownMode::Immediate);
        let mut cx = Context::from_waker(Waker::noop());
        let mut first = None;
        for index in 0..self.clients.len() {
            if let Some(row) = self.clients[index].as_mut() {
                // Free bounded diagnostic slots before synchronous retirement
                // can publish the remaining actual Call summaries.
                while Self::event(row, &mut observe) {}
                if row.terminal.is_none() {
                    match row.future.as_mut().poll(&mut cx) {
                        Poll::Ready(report) => row.terminal = Some(report),
                        Poll::Pending => {
                            first.get_or_insert_with(|| Fault::NotReady.into());
                        }
                    }
                }
                while Self::event(row, &mut observe) {}
                if row.terminal.is_some()
                    && let Err(error) = self.finished(index, &mut observe)
                {
                    first.get_or_insert(error);
                }
            }
        }
        if self.registry.pending() != 0 || self.report.undrained != 0 || !self.registry.healthy() {
            first.get_or_insert_with(|| Fault::NotReady.into());
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
        let _retired = self.shutdown(|_| {});
    }
}
