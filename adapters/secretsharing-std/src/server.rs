use crate::run::Session;
use crate::run::{Admission, Control, Registry, Storage};
use crate::{Error, Event, Limits, Progress, Report, Sources};
use gnunet_service_runtime::{
    accepted::{AcceptState, AcceptedConnection, SocketEvent},
    credentials::UnixAccess,
    framing::{Accounting, Budget, Framed, Limits as Framing},
    service::{Listener, PeerAddress, ServiceOptions, ShutdownMode},
};
use gnunet_types::Error as Fault;
use std::{
    future::{Future, poll_fn},
    mem::size_of,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll, Waker},
};
use tokio::time::{Instant, Sleep};

struct Running {
    id: u64,
    control: Rc<Control>,
    future: Pin<Box<Session>>,
    _storage: Storage,
}
/// Actual caller-polled SERVICE. Each original IPC MQ owns one original780 or781;
/// every native operation future is polled inside that owner and never spawned.
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
    /// Validate and reserve actual bounded owner metadata. Sources are explicit
    /// fixed endpoint selections; no PILS/CONSENSUS MQ, threshold work or entropy starts here.
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
    /// Same explicit original shared process clock, without a new subscription.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn gnunet_service_runtime::clock::RuntimeClock> {
        self.sources.clock()
    }
    /// IPC admission is active. Normal caller must bind actual listeners before
    /// READY. This proves no current PILS identity, quorum or cryptographic completion.
    #[must_use]
    pub fn ready(&self) -> bool {
        self.shutdown.is_none() && self.registry.healthy()
    }
    /// Actual aggregate terminal observations, not a conformance certificate.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.report
    }
    /// Admit one actual canonical stream after original address/credential policy.
    pub fn admit(
        &mut self,
        accepted: AcceptedConnection,
        observe: &mut impl FnMut(Event),
    ) -> Result<Option<u64>, Error> {
        // Preserve admission entry before diagnostics, credential providers or
        // allocations; none of those may renew the first-input lifetime.
        let first = Admission::new(self.sources.clock.as_ref(), self.limits)?;
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
        let control = Rc::new(Control::new());
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
        let future = crate::run::session(
            io,
            self.sources.duplicate()?,
            self.limits,
            self.registry.clone(),
            control.clone(),
            self.options.tolerant,
            first,
        )?;
        // Reserve actual boxed future/report metadata plus a conservative
        // bounded client framing/private queued request allowance. The native
        // operation uses a separate permit through its original output debt.
        let future_bytes = crate::run::future_bytes(&future)?;
        let storage_bytes = self
            .limits
            .frame_bytes
            .checked_mul(8)
            .and_then(|n| n.checked_add(future_bytes))
            .ok_or(Fault::Overflow)?;
        let storage = self.registry.storage(storage_bytes)?;
        self.clients[slot] = Some(Running {
            id,
            control,
            future: Box::pin(future),
            _storage: storage,
        });
        self.next = id.checked_add(1);
        self.report.accepted = self.report.accepted.saturating_add(1);
        observe(Event::Accepted(id));
        Ok(Some(id))
    }
    fn finished(
        &mut self,
        index: usize,
        report: Box<crate::ClientReport>,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Error> {
        let owner = self.clients[index].take().ok_or(Fault::Stale)?;
        if report.physical_closed {
            self.accept.client_closed();
            self.report.closed = self.report.closed.saturating_add(1);
        }
        self.report.requests = self.report.requests.saturating_add(report.requests);
        self.report.results_written = self
            .report
            .results_written
            .saturating_add(report.results_written);
        if report.primary.is_some()
            || report.cleanup.is_some()
            || report.undrained != 0
            || !report.physical_closed
        {
            self.report.failed = self.report.failed.saturating_add(1);
        }
        self.report.undrained = self.report.undrained.saturating_add(report.undrained);
        let fatal = report.undrained != 0 || !self.registry.healthy();
        observe(Event::Closed {
            client: owner.id,
            report,
        });
        if fatal {
            self.request_shutdown(ShutdownMode::Immediate);
            return Err(Fault::NotReady.into());
        }
        Ok(())
    }
    /// Stop admission. Soft retains existing original finite operation/output bounds;
    /// Immediate wakes each original clock-free retirement path before old IO.
    pub fn request_shutdown(&mut self, mode: ShutdownMode) {
        if self.shutdown != Some(ShutdownMode::Immediate) {
            self.shutdown = Some(mode);
        }
        if self.shutdown == Some(ShutdownMode::Immediate) {
            for row in self.clients.iter().flatten() {
                row.control.cancel(Fault::Cancelled);
            }
        }
        if let Some(waker) = &self.waker {
            waker.wake_by_ref();
        }
    }
    /// Fairly poll original owned MQs and actual standard listeners. Cancelling
    /// this observation does not replace cursors, sources, deadlines or private IDs.
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
            if let Some(row) = self.clients[index].as_mut()
                && let Poll::Ready(report) = row.future.as_mut().poll(cx)
            {
                self.cursor = (index + 1) % count;
                self.finished(index, report, observe)?;
                return Poll::Ready(Ok(
                    if self.shutdown.is_some()
                        && self.clients.iter().all(Option::is_none)
                        && self.registry.pending() == 0
                    {
                        Progress::Stopped
                    } else {
                        Progress::Activity
                    },
                ));
            }
        }
        self.cursor = (self.cursor + 1) % count;
        if self.shutdown.is_some() && self.clients.iter().all(Option::is_none) {
            if self.registry.pending() != 0 || self.report.undrained != 0 {
                return Poll::Ready(Err(Fault::NotReady.into()));
            }
            return Poll::Ready(Ok(Progress::Stopped));
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
    /// Cancellation-safe bounded observation of this same original native owner.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        wait: Option<Instant>,
        mut observe: impl FnMut(Event),
    ) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll(cx, listeners, wait, &mut observe)).await
    }
    /// Independently retire every original owner without clock/provider samples.
    /// The first failure is returned only after all other owners were attempted.
    pub fn shutdown(&mut self, mut observe: impl FnMut(Event)) -> Result<Report, Error> {
        self.request_shutdown(ShutdownMode::Immediate);
        let mut cx = Context::from_waker(Waker::noop());
        let mut first = None;
        for index in 0..self.clients.len() {
            let result = self.clients[index]
                .as_mut()
                .map(|row| row.future.as_mut().poll(&mut cx));
            match result {
                Some(Poll::Ready(report)) => {
                    if let Err(error) = self.finished(index, report, &mut observe) {
                        first.get_or_insert(error);
                    }
                }
                Some(Poll::Pending) => {
                    first.get_or_insert_with(|| Fault::NotReady.into());
                }
                None => {}
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
