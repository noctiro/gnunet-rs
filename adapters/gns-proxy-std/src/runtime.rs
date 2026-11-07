//! Two numeric SOCKS listeners and bounded original session futures, without tasks.
use crate::{
    Error, Limits, Options, Ports, SessionReport, Sources,
    budget::{Budget, Stop},
    types::SessionInput,
};
use gnunet_service_runtime::accepted::{AcceptError, AcceptState, SocketEvent};
use gnunet_types::{Error as Fault, Rejected};
use std::{
    future::Future,
    io,
    net::SocketAddr,
    os::fd::AsFd,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    net::TcpListener,
    time::{Instant, Sleep},
};
/// Diagnostic identity of one actually admitted session. It grants no native
/// socket, key, TLS authentication or lease-completion authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionId(u64);
impl SessionId {
    /// Original monotonically assigned diagnostic serial.
    pub const fn diagnostic(self) -> u64 {
        self.0
    }
}
/// A real original owner observation. No event claims remote delivery.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "One owned terminal report is delivered inline without an extra allocation per session"
)]
pub enum Event {
    /// Original accepted stream entered bounded session ownership.
    Accepted {
        /// Diagnostic original session identity.
        session: SessionId,
        /// Actual address returned by native accept.
        peer: SocketAddr,
        /// Actual local address of the original listener.
        local: SocketAddr,
    },
    /// Only this unadmitted stream was physically closed.
    Refused {
        /// Actual native peer address.
        peer: SocketAddr,
        /// Original local resource reason.
        reason: Fault,
        /// Earlier original socket diagnostics, if initialization occurred.
        diagnostics: Option<gnunet_native::network::Diagnostics>,
    },
    /// Actual native accept/socket-initialization error.
    AcceptFailed(SocketEvent),
    /// Original hard elapsed; cancellation is fenced and real cleanup is pending.
    GuardExpired {
        /// Original diagnostic session identity.
        session: SessionId,
    },
    /// Actual session terminal report, after its finally path ran.
    Session(SessionReport),
    /// All session futures relinquished their actual resources and listeners
    /// were physically retired; the shared process Resolver is a separate scope.
    Closed,
}
/// Bounded local runtime facts after original owner consumption.
#[derive(Debug)]
pub struct Report {
    /// Actual listener addresses obtained from the OS.
    pub bound: Vec<SocketAddr>,
    /// Actual alternative bind failures, never fabricated success.
    pub bind_failures: Vec<io::Error>,
    /// Actually admitted original sessions.
    pub accepted: u64,
    /// Actually returned session reports; caller owns those reports separately.
    pub completed: u64,
    /// Original native-hard fences, independently of native cleanup completion.
    pub expired: u64,
    /// Unadmitted resource refusals.
    pub refused: u64,
    /// Runtime's actual original listener/session-future retirement scope.
    pub closed: bool,
}
struct Slot {
    id: SessionId,
    budget: Budget,
    stop: Stop,
    guarded: bool,
    future: Pin<Box<dyn Future<Output = SessionReport>>>,
}
struct SharedPorts {
    configuration: std::sync::Arc<gnunet_config::Configuration>,
    context: gnunet_resolver_broker::Context<128, 256>,
    clock: std::sync::Arc<dyn gnunet_service_runtime::clock::RuntimeClock>,
    authority: std::sync::Arc<crate::tls::Authority>,
    roots: std::sync::Arc<crate::tls::TrustRoots>,
    startup_guard: crate::tls::Guard,
}
impl From<Ports> for SharedPorts {
    fn from(p: Ports) -> Self {
        Self {
            configuration: std::sync::Arc::new(p.configuration),
            context: p.context,
            clock: p.clock,
            authority: p.authority,
            roots: p.roots,
            startup_guard: p.startup_guard,
        }
    }
}
/// Caller-driven ordinary proxy, sharing exactly the supplied Resolver broker.
pub struct Runtime {
    ports: SharedPorts,
    sources: Sources,
    options: Options,
    limits: Limits,
    listeners: Vec<TcpListener>,
    bound: Vec<SocketAddr>,
    bind_failures: Vec<io::Error>,
    slots: Vec<Slot>,
    accept: AcceptState,
    cursor: usize,
    listener_cursor: usize,
    phase: usize,
    serial: u64,
    accepted: u64,
    completed: u64,
    expired: u64,
    refused: u64,
    closing: bool,
    closed: bool,
    closed_announced: bool,
    cleanup_hard: Option<Instant>,
    native_alarm: Option<Pin<Box<Sleep>>>,
    native_at: Option<Instant>,
}
impl Runtime {
    /// Bind actual numeric listeners in the caller's entered runtime. Each
    /// mutation is guarded by the same original startup capability. One family
    /// may remain usable while the other's original error is retained.
    pub fn bind(
        ports: Ports,
        sources: Sources,
        options: Options,
        limits: Limits,
    ) -> Result<Self, Error> {
        let ports = SharedPorts::from(ports);
        (ports.startup_guard)()?;
        if options.bind.is_empty()
            || options.bind.len() > 2
            || limits.sessions == 0
            || limits.sessions > 1024
            || limits.session_timeout.is_zero()
            || limits.cleanup_grace.is_zero()
            || Instant::now().checked_add(limits.session_timeout).is_none()
            || Instant::now().checked_add(limits.cleanup_grace).is_none()
            || !std::sync::Arc::ptr_eq(&ports.clock, &sources.gns.clock())
            || !std::sync::Arc::ptr_eq(&ports.clock, &sources.identity.clock())
            || !std::sync::Arc::ptr_eq(&ports.clock, &sources.vpn.clock())
            || !std::sync::Arc::ptr_eq(&ports.clock, &ports.context.resolution_context().clock())
        {
            return Err(Fault::InvalidInput.into());
        }
        limits.vpn_profile.validate()?;
        limits.http.validate()?;
        let mut listeners = Vec::new();
        let mut bound = Vec::new();
        let mut failures = Vec::new();
        let mut slots = Vec::new();
        listeners
            .try_reserve_exact(options.bind.len())
            .map_err(Error::Allocation)?;
        bound
            .try_reserve_exact(options.bind.len())
            .map_err(Error::Allocation)?;
        failures
            .try_reserve_exact(options.bind.len())
            .map_err(Error::Allocation)?;
        slots
            .try_reserve_exact(limits.sessions)
            .map_err(Error::Allocation)?;
        for address in &options.bind {
            if let Err(error) = (ports.startup_guard)() {
                return Err(Error::Construction {
                    cause: Box::new(error.into()),
                    bind_failures: failures,
                });
            }
            let result = (|| -> Result<(TcpListener, SocketAddr), Error> {
                let guard = &ports.startup_guard;
                guard()?;
                let socket = socket2::Socket::new(
                    if address.is_ipv4() {
                        socket2::Domain::IPV4
                    } else {
                        socket2::Domain::IPV6
                    },
                    socket2::Type::STREAM,
                    Some(socket2::Protocol::TCP),
                )?;
                guard()?;
                if address.is_ipv6() {
                    socket.set_only_v6(true)?;
                    guard()?;
                }
                socket.set_reuse_address(true)?;
                guard()?;
                socket.set_nonblocking(true)?;
                guard()?;
                socket.bind(&(*address).into())?;
                guard()?;
                socket.listen(128)?;
                guard()?;
                let listener = TcpListener::from_std(socket.into())?;
                let local = listener.local_addr()?;
                guard()?;
                Ok((listener, local))
            })();
            match result {
                Ok((listener, local)) => {
                    listeners.push(listener);
                    bound.push(local)
                }
                Err(Error::Io(error)) => failures.push(error),
                Err(error) => {
                    return Err(Error::Construction {
                        cause: Box::new(error),
                        bind_failures: failures,
                    });
                }
            }
        }
        if listeners.is_empty() {
            return Err(Error::Binding(failures));
        }
        Ok(Self {
            ports,
            sources,
            options,
            limits,
            listeners,
            bound,
            bind_failures: failures,
            slots,
            accept: AcceptState::default(),
            cursor: 0,
            listener_cursor: 0,
            phase: 0,
            serial: 0,
            accepted: 0,
            completed: 0,
            expired: 0,
            refused: 0,
            closing: false,
            closed: false,
            closed_announced: false,
            cleanup_hard: None,
            native_alarm: None,
            native_at: None,
        })
    }
    /// Actual bound addresses, including real ephemeral ports.
    pub fn local_addresses(&self) -> &[SocketAddr] {
        &self.bound
    }
    /// Original failed family attempts, independent of the usable listeners.
    pub fn bind_failures(&self) -> &[io::Error] {
        &self.bind_failures
    }
    /// No fresh native/clock work; only register/fence original session hards.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Event> {
        let now = Instant::now();
        for slot in &mut self.slots {
            if !slot.guarded && now >= slot.budget.hard() {
                slot.guarded = true;
                let cleanup = now.checked_add(self.limits.cleanup_grace).unwrap_or(now);
                slot.stop.request_at(cleanup);
                self.expired = self.expired.saturating_add(1);
                return Some(Event::GuardExpired { session: slot.id });
            }
        }
        let at = self
            .slots
            .iter()
            .filter(|s| !s.guarded)
            .map(|s| s.budget.hard())
            .min();
        if self.native_at != at {
            self.native_at = at;
            self.native_alarm = at.map(|at| Box::pin(tokio::time::sleep_until(at)));
        }
        if let Some(alarm) = &mut self.native_alarm
            && alarm.as_mut().poll(cx).is_ready()
        {
            cx.waker().wake_by_ref();
        }
        None
    }
    fn sessions(&mut self, cx: &mut Context<'_>) -> Option<Event> {
        for _ in 0..self.slots.len() {
            let i = self.cursor % self.slots.len();
            self.cursor = (i + 1) % self.slots.len();
            if let Poll::Ready(report) = self.slots[i].future.as_mut().poll(cx) {
                let original = self.slots.swap_remove(i);
                drop(original);
                self.accept.client_closed();
                self.completed = self.completed.saturating_add(1);
                return Some(Event::Session(report));
            }
        }
        None
    }
    fn accept(&mut self, cx: &mut Context<'_>) -> Result<Option<Event>, Error> {
        if self.closing || !self.accept.ready() {
            return Ok(None);
        }
        for _ in 0..self.listeners.len() {
            let i = self.listener_cursor % self.listeners.len();
            self.listener_cursor = (i + 1) % self.listeners.len();
            let (socket, peer) = match self.listeners[i].poll_accept(cx) {
                Poll::Pending => continue,
                Poll::Ready(Ok(v)) => v,
                Poll::Ready(Err(e)) => {
                    return Ok(Some(Event::AcceptFailed(
                        self.accept.failed(AcceptError::Accept(e)),
                    )));
                }
            };
            if self.slots.len() == self.limits.sessions {
                drop(socket);
                self.refused = self.refused.saturating_add(1);
                return Ok(Some(Event::Refused {
                    peer,
                    reason: Fault::Capacity,
                    diagnostics: None,
                }));
            }
            let diagnostics = match gnunet_native::network::initialize_reactor_stream(
                socket.as_fd(),
                gnunet_native::network::StreamKind::Tcp,
            ) {
                Ok(v) => v,
                Err(e) => {
                    drop(socket);
                    return Ok(Some(Event::AcceptFailed(
                        self.accept.failed(AcceptError::Initialization(e)),
                    )));
                }
            };
            let serial = self.serial.checked_add(1).ok_or(Fault::Overflow)?;
            let stop = Stop::new();
            let budget = Budget::new(
                self.ports.clock.clone(),
                self.limits.session_timeout,
                stop.clone(),
            )?;
            let sources = Sources {
                gns: self.sources.gns.duplicate().map_err(Error::Connect)?,
                identity: self.sources.identity.duplicate().map_err(Error::Connect)?,
                vpn: self.sources.vpn.duplicate().map_err(Error::Connect)?,
            };
            let input = SessionInput {
                socket: Some(socket),
                sources,
                configuration: self.ports.configuration.clone(),
                context: self.ports.context.clone(),
                authority: self.ports.authority.clone(),
                roots: self.ports.roots.clone(),
                budget: budget.clone(),
                stop: stop.clone(),
                disable_ipv6: self.options.disable_ipv6,
                limits: self.limits.clone(),
                diagnostics: Some(diagnostics),
            };
            self.slots.push(Slot {
                id: SessionId(serial),
                budget,
                stop,
                guarded: false,
                future: Box::pin(crate::session::run(input)),
            });
            self.serial = serial;
            self.accepted = self.accepted.saturating_add(1);
            return Ok(Some(Event::Accepted {
                session: SessionId(serial),
                peer,
                local: self.bound[i],
            }));
        }
        Ok(None)
    }
    /// Fair bounded live session/accept polling. Caller gates its original Stop
    /// and Reporter before calling; the host starts no detached task or broker.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event, Error>> {
        if self.closing {
            return self.poll_close(cx);
        }
        if let Some(event) = self.poll_native_guard(cx) {
            return Poll::Ready(Ok(event));
        }
        for _ in 0..2 {
            let phase = self.phase;
            self.phase = (phase + 1) % 2;
            let event = if phase == 0 {
                self.sessions(cx)
            } else {
                self.accept(cx)?
            };
            if let Some(event) = event {
                return Poll::Ready(Ok(event));
            }
        }
        Poll::Pending
    }
    /// One-way stop. Retire original listeners and fence every original session
    /// with one native cleanup target; later calls never renew it.
    pub fn begin_close(&mut self) -> Result<(), Error> {
        if self.closing {
            return Ok(());
        }
        self.closing = true;
        self.listeners.clear();
        let now = Instant::now();
        let hard = now.checked_add(self.limits.cleanup_grace);
        self.cleanup_hard = Some(hard.unwrap_or(now));
        for slot in &self.slots {
            slot.stop.request_at(self.cleanup_hard.unwrap_or(now));
        }
        if hard.is_none() {
            return Err(Fault::Overflow.into());
        }
        Ok(())
    }
    /// Drive only original finally work. Every session receives the original
    /// cleanup hard, even when canonical clocks or Reporter have failed.
    pub fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event, Error>> {
        if !self.closing {
            return Poll::Ready(Err(Fault::NotReady.into()));
        }
        if self.closed_announced {
            return Poll::Pending;
        }
        if let Some(event) = self.sessions(cx) {
            return Poll::Ready(Ok(event));
        }
        if self.slots.is_empty() {
            self.closed = true;
            self.closed_announced = true;
            self.native_alarm = None;
            return Poll::Ready(Ok(Event::Closed));
        }
        Poll::Pending
    }
    /// Actual local future/listener retirement only; shared Driver is separate.
    pub fn is_closed(&self) -> bool {
        self.closed
    }
    /// Consume real final owner facts. A live runtime is returned unchanged.
    #[expect(
        clippy::result_large_err,
        reason = "Refused consumption returns the exact live runtime and its source authority without allocating a replacement owner"
    )]
    pub fn into_report(self) -> Result<Report, Rejected<Self>> {
        if !self.closed {
            return Err(Rejected {
                reason: Fault::WouldBlock,
                value: self,
            });
        }
        Ok(Report {
            bound: self.bound,
            bind_failures: self.bind_failures,
            accepted: self.accepted,
            completed: self.completed,
            expired: self.expired,
            refused: self.refused,
            closed: true,
        })
    }
}
