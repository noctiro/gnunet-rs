use crate::profile::KeyOwner;
use crate::run::{Control, Registry};
use crate::{Error, Event, Limits, Profile, Progress, Report, Role, SessionReport, Sources};
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
/// Caller-polled native SERVICE. Every future is polled here; none is spawned.
pub struct Server {
    role: Role,
    profile: Profile,
    key_owner: KeyOwner,
    sources: Sources,
    limits: Limits,
    options: ServiceOptions,
    unix: UnixAccess,
    accept: AcceptState,
    apps: Vec<Option<Running>>,
    registry: Rc<RefCell<Registry>>,
    next: Option<u64>,
    cursor: usize,
    listener_cursor: usize,
    shutdown: Option<ShutdownMode>,
    timer: Pin<Box<Sleep>>,
    waker: Option<Waker>,
    report: Report,
}
impl Server {
    /// Reserve bounded owner metadata. No socket/source/crypto work is started.
    pub fn new(
        role: Role,
        sources: Sources,
        limits: Limits,
        options: ServiceOptions,
        unix: UnixAccess,
    ) -> Result<Self, Error> {
        Self::new_with_profile(role, Profile::Ecc, sources, limits, options, unix)
    }
    /// Select an actual installed peer profile. Paillier Alice polls one real
    /// original shared Keygen before ready/admission; no socket or entropy is
    /// run in this constructor. Profile errors never fall back to ECC.
    pub fn new_with_profile(
        role: Role,
        profile: Profile,
        sources: Sources,
        limits: Limits,
        options: ServiceOptions,
        unix: UnixAccess,
    ) -> Result<Self, Error> {
        profile.validate(limits)?;
        let key_owner = KeyOwner::new(profile, role, limits, sources.clock.as_ref())?;
        let global_key = profile.key_reservation(role)?;
        let available = limits
            .total_retained_bytes
            .checked_sub(global_key)
            .ok_or(Fault::Capacity)?;
        let slots = limits.clients.min(available / limits.session_bytes);
        if slots == 0 {
            return Err(Fault::Capacity.into());
        }
        let mut apps = Vec::new();
        apps.try_reserve_exact(slots).map_err(|_| Fault::Capacity)?;
        apps.resize_with(slots, || None);
        let registry = Rc::new(RefCell::new(Registry::new(slots)?));
        let table_bytes = registry
            .try_borrow()
            .map_err(|_| Fault::Conflict)?
            .retained_bytes()?;
        let selected_storage = sources.retained_bytes()?;
        let metadata = std::mem::size_of::<Self>()
            .checked_add(
                apps.capacity()
                    .checked_mul(std::mem::size_of::<Option<Running>>())
                    .ok_or(Fault::Overflow)?,
            )
            .and_then(|n| n.checked_add(table_bytes))
            .and_then(|n| n.checked_add(selected_storage))
            .ok_or(Fault::Overflow)?;
        if metadata
            .checked_add(key_owner.retained_bytes()?)
            .is_none_or(|n| n > limits.total_retained_bytes)
        {
            return Err(Fault::Capacity.into());
        }
        while !apps.is_empty()
            && apps
                .len()
                .checked_mul(limits.session_bytes)
                .and_then(|n| n.checked_add(global_key))
                .and_then(|n| n.checked_add(metadata))
                .is_none_or(|n| n > limits.total_retained_bytes)
        {
            apps.pop();
        }
        if apps.is_empty() {
            return Err(Fault::Capacity.into());
        }
        Ok(Self {
            role,
            profile,
            key_owner,
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
            timer: Box::pin(tokio::time::sleep(std::time::Duration::ZERO)),
            waker: None,
            report: Report::default(),
        })
    }
    /// Original caller-owned clock used by all original source MQs.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn gnunet_service_runtime::clock::RuntimeClock> {
        self.sources.clock()
    }
    /// SERVICE admission and the selected shared Alice key are actually ready.
    /// Computation ports exist only after a normal
    /// Bob client supplies its entire vector; this proves no remote computation.
    #[must_use]
    pub fn ready(&self) -> bool {
        self.shutdown.is_none() && self.key_owner.ready()
    }
    /// Actual terminal aggregate counters; original causes are in Closed events.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.report
    }
    /// Accept one actual initialized connection using standard ACL/credentials.
    pub fn admit(
        &mut self,
        accepted: AcceptedConnection,
        observe: &mut impl FnMut(Event),
    ) -> Result<Option<u64>, Error> {
        let started = Instant::now();
        let now = self.sources.clock().sample()?.now.as_micros();
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
        if !self.key_owner.ready() {
            return Err(Fault::NotReady.into());
        }
        let index = self
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
        let control = Rc::new(Control::new());
        let future = Box::pin(crate::run::session(
            crate::run::Session {
                admission: crate::input::Admission {
                    id,
                    role: self.role,
                    profile: self.profile,
                    limits: self.limits,
                    started,
                    now,
                },
                key: self.key_owner.key(),
                registry: self.registry.clone(),
                control: control.clone(),
            },
            io,
            sources,
        ));
        self.apps[index] = Some(Running {
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
        let owner = self.apps[index].take().ok_or(Fault::Stale)?;
        if report.physical_closed {
            self.accept.client_closed();
            self.report.closed = self.report.closed.saturating_add(1);
        }
        if report.outcome.is_some_and(|outcome| outcome.client_written) {
            self.report.results_written = self.report.results_written.saturating_add(1);
        }
        if report.primary.is_some()
            || report
                .outcome
                .is_some_and(|outcome| outcome.failure.is_some())
        {
            self.report.failed = self.report.failed.saturating_add(1);
        }
        self.report.undrained = self.report.undrained.saturating_add(report.undrained);
        let undrained = report.undrained > 0;
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
    /// Stop admission. Immediate triggers each original clock-free close branch;
    /// Soft retains original fixed operation bounds until foreground grace ends.
    pub fn request_shutdown(&mut self, mode: ShutdownMode) {
        if self.key_owner.pending() {
            self.report.key_generation_cancelled = true;
        }
        self.key_owner.cancel();
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
    /// Fairly poll bounded original sessions and real standard listeners. No
    /// future or endpoint source is replaced when an observation is cancelled.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        wait: Option<Instant>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        self.waker = Some(cx.waker().clone());
        if wait.is_some_and(|at| Instant::now() >= at) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        if self.shutdown.is_none() && !self.key_owner.ready() {
            return match self.key_owner.poll(self.sources.clock.as_ref(), cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(error)) => {
                    self.report.key_generation_cancelled = true;
                    Poll::Ready(Err(error))
                }
                Poll::Ready(Ok(_)) => {
                    if self.key_owner.ready() {
                        self.report.key_generated = true;
                    }
                    Poll::Ready(Ok(Progress::Activity))
                }
            };
        }
        let count = self.apps.len();
        for offset in 0..count {
            let index = (self.cursor + offset) % count;
            if let Some(app) = self.apps[index].as_mut()
                && let Poll::Ready(report) = app.future.as_mut().poll(cx)
            {
                self.cursor = (index + 1) % count;
                self.finished(index, report, observe)?;
                return Poll::Ready(Ok(
                    if self.shutdown.is_some() && self.apps.iter().all(Option::is_none) {
                        Progress::Stopped
                    } else {
                        Progress::Activity
                    },
                ));
            }
        }
        self.cursor = (self.cursor + 1) % count;
        if self.shutdown.is_some() && self.apps.iter().all(Option::is_none) {
            return Poll::Ready(Ok(Progress::Stopped));
        }
        if self.shutdown.is_none() && self.accept.ready() && self.apps.iter().any(Option::is_none) {
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
    /// Cancellation-safe observation of this same actual caller-driven owner.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        wait: Option<Instant>,
        mut observe: impl FnMut(Event),
    ) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll(cx, listeners, wait, &mut observe)).await
    }
    /// Clock-free physical close and original effect retirement. Local futures
    /// check the cancellation flag before clock/IO; they do not spawn or wait.
    pub fn shutdown(&mut self, mut observe: impl FnMut(Event)) -> Result<Report, Error> {
        self.request_shutdown(ShutdownMode::Immediate);
        let mut cx = Context::from_waker(Waker::noop());
        let mut first_error = None;
        for index in 0..self.apps.len() {
            let result = self.apps[index]
                .as_mut()
                .map(|app| app.future.as_mut().poll(&mut cx));
            match result {
                Some(Poll::Ready(report)) => {
                    if let Err(error) = self.finished(index, report, &mut observe) {
                        first_error.get_or_insert(error);
                    }
                }
                Some(Poll::Pending) => {
                    first_error.get_or_insert_with(|| Fault::NotReady.into());
                }
                None => {}
            }
        }
        if let Some(error) = first_error {
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
