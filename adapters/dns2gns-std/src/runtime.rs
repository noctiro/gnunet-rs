//! Bounded fair caller polling. No native request future is detached or spawned.
use crate::{
    BindOptions, Binding, Event, Failure, Limits, Ports, Progress, Report, RequestError,
    RequestReport, StopReason,
    budget::{Budget, duration_micros},
    request::{self, Completion},
};
use gnunet_types::Error as Fault;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    cell::Cell,
    future::Future,
    io,
    net::{SocketAddr, UdpSocket as StdSocket},
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::ReadBuf,
    net::UdpSocket,
    time::{Instant, Sleep},
};

#[expect(
    clippy::large_enum_variant,
    reason = "Bounded slots transfer the original send budget and native outcomes inline without another allocation"
)]
enum State {
    Running(Pin<Box<dyn Future<Output = Completion>>>),
    Sending {
        bytes: Vec<u8>,
        budget: Budget,
        report: RequestReport,
    },
}
struct Task {
    hard: Instant,
    alarm: Pin<Box<Sleep>>,
    cancel: Rc<Cell<Option<StopReason>>>,
    state: State,
}
/// One original gateway. Every active slot retains its exact original future
/// through cancellation; diagnostic serials never reconstruct native authority.
pub struct Runtime {
    listeners: [Option<UdpSocket>; 2],
    ports: Arc<Ports>,
    limits: Limits,
    tasks: Vec<Option<Task>>,
    buffer: Vec<u8>,
    serial: u64,
    task_cursor: usize,
    listener_cursor: usize,
    receive_first: bool,
    closing: bool,
    closed: bool,
    report: Report,
}
impl Runtime {
    /// Bind both original configured families independently. IPv6 is explicitly
    /// V6ONLY before bind. A successful other family preserves a failed errno.
    pub fn new(bindings: BindOptions, ports: Ports, limits: Limits) -> Result<Self, Failure> {
        let fail = |cause| Failure {
            cause,
            report: None,
        };
        if limits.requests == 0
            || limits.requests > 4096
            || !(12..=65507).contains(&limits.packet.maximum_packet_bytes)
            || limits.packet.maximum_records > u16::MAX as usize
            || limits.packet.maximum_arena_bytes == 0
            || limits.packet.maximum_work == 0
            || limits.packet.maximum_gns_bytes == 0
        {
            return Err(fail(RequestError::Protocol(Fault::InvalidInput)));
        }
        duration_micros(limits.request_lifetime).map_err(|e| fail(RequestError::Protocol(e)))?;
        duration_micros(limits.vpn_lease).map_err(|e| fail(RequestError::Protocol(e)))?;
        limits
            .vpn_profile
            .validate()
            .map_err(|e| fail(RequestError::Protocol(e)))?;
        for source in [&ports.gns, &ports.identity, &ports.vpn] {
            if !Arc::ptr_eq(&ports.clock, &source.clock()) {
                return Err(fail(RequestError::Protocol(Fault::Conflict)));
            }
        }
        let mut tasks = Vec::new();
        tasks
            .try_reserve_exact(limits.requests)
            .map_err(|_| fail(RequestError::Protocol(Fault::Capacity)))?;
        tasks.resize_with(limits.requests, || None);
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(limits.packet.maximum_packet_bytes + 1)
            .map_err(|_| fail(RequestError::Protocol(Fault::Capacity)))?;
        buffer.resize(limits.packet.maximum_packet_bytes + 1, 0);
        let (v4, b4) = bind(SocketAddr::V4(bindings.ipv4));
        let (v6, b6) = bind(SocketAddr::V6(bindings.ipv6));
        let report = Report {
            bindings: [b4, b6],
            received: 0,
            sent: 0,
            failed: 0,
            active: 0,
            first_failure: None,
            listener_errors: [None, None],
            unresolved: 0,
            quiescent: false,
            listeners_released: false,
        };
        if v4.is_none() && v6.is_none() {
            return Err(Failure {
                cause: RequestError::Closed,
                report: Some(Box::new(Report {
                    quiescent: true,
                    listeners_released: true,
                    ..report
                })),
            });
        }
        Ok(Self {
            listeners: [v4, v6],
            ports: Arc::new(ports),
            limits,
            tasks,
            buffer,
            serial: 0,
            task_cursor: 0,
            listener_cursor: 0,
            receive_first: true,
            closing: false,
            closed: false,
            report,
        })
    }
    /// Actual bounded snapshot; local quiescence is distinct from remote work.
    #[must_use]
    pub fn report(&self) -> &Report {
        &self.report
    }
    /// Permanent caller stop. No clock sample, new request or new timer occurs.
    /// Listener release and cancellation do not revoke already allocated VPN leases.
    pub fn begin_close(&mut self) {
        if self.closing {
            return;
        }
        self.closing = true;
        self.listeners = [None, None];
        self.report.listeners_released = true;
        for task in self.tasks.iter_mut().flatten() {
            if task.cancel.get().is_none() {
                task.cancel.set(Some(StopReason::Shutdown));
            }
        }
    }
    /// Native first: register original timers and drive only expired/canceled
    /// original futures through synchronous source retirement. No clock is needed.
    pub fn poll_native_guard(
        &mut self,
        cx: &mut Context<'_>,
        observer: &mut impl FnMut(Event),
    ) -> Option<Progress> {
        if self.closed {
            return None;
        }
        for offset in 0..self.tasks.len() {
            let index = (self.task_cursor + offset) % self.tasks.len();
            let Some(task) = self.tasks[index].as_mut() else {
                continue;
            };
            if task.cancel.get().is_none()
                && (Instant::now() >= task.hard || task.alarm.as_mut().poll(cx).is_ready())
            {
                task.cancel.set(Some(StopReason::NativeDeadline));
            }
            if task.cancel.get().is_some()
                && let Poll::Ready(progress) = self.poll_task(index, cx, observer)
            {
                self.task_cursor = (index + 1) % self.tasks.len();
                return Some(progress);
            }
        }
        None
    }
    /// Drive one fair native/query/send step. Each observable event returns
    /// immediately, allowing the original caller's permanent Logger gate.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        observer: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Failure>> {
        if self.closing {
            return self.poll_close(cx, observer);
        }
        if let Some(progress) = self.poll_native_guard(cx, observer) {
            return Poll::Ready(Ok(progress));
        }
        if self.listeners.iter().all(Option::is_none) {
            self.begin_close();
            return Poll::Ready(Err(Failure {
                cause: RequestError::Closed,
                report: None,
            }));
        }
        let receive_first = self.receive_first;
        self.receive_first = !self.receive_first;
        for class in 0..2 {
            if (class == 0) == receive_first {
                if let Poll::Ready(progress) = self.receive(cx, observer) {
                    return Poll::Ready(Ok(progress));
                }
            } else {
                for offset in 0..self.tasks.len() {
                    let index = (self.task_cursor + offset) % self.tasks.len();
                    if self.tasks[index].is_some()
                        && let Poll::Ready(progress) = self.poll_task(index, cx, observer)
                    {
                        self.task_cursor = (index + 1) % self.tasks.len();
                        return Poll::Ready(Ok(progress));
                    }
                }
            }
        }
        Poll::Pending
    }
    /// Clock-free original-owner close. Cancellation is rechecked at every
    /// retained future poll; no timeout is reported as an observed completion.
    pub fn poll_close(
        &mut self,
        cx: &mut Context<'_>,
        observer: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Failure>> {
        self.begin_close();
        if self.closed {
            return Poll::Ready(Ok(Progress::Closed));
        }
        if let Some(progress) = self.poll_native_guard(cx, observer) {
            return Poll::Ready(Ok(progress));
        }
        if self.tasks.iter().any(Option::is_some) {
            return Poll::Pending;
        }
        self.closed = true;
        self.report.quiescent = true;
        self.report.active = 0;
        observer(Event::Closed);
        Poll::Ready(Ok(Progress::Closed))
    }
    /// Only an actual local terminal observation, never a lease-revocation ACK.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }
    /// Consume all remaining physical owners. If the caller stops observing
    /// before close completes, unresolved counts remain explicit and quiescent
    /// stays false. Dropping an original future is not a successful retirement.
    #[must_use]
    pub fn into_report(mut self) -> Report {
        self.begin_close();
        let unresolved = self.tasks.iter().filter(|task| task.is_some()).count();
        self.tasks.clear();
        self.report.unresolved = unresolved;
        self.report.active = 0;
        self.report.quiescent = self.closed && unresolved == 0;
        self.report
    }
    fn finish(&mut self, report: RequestReport, observer: &mut impl FnMut(Event)) {
        let report = Arc::new(report);
        {
            let runtime = &mut self.report;
            runtime.active = runtime.active.saturating_sub(1);
            if report.sent_bytes.is_some() {
                runtime.sent = runtime.sent.saturating_add(1);
            } else {
                runtime.failed = runtime.failed.saturating_add(1);
            }
            if has_diagnostics(&report) && runtime.first_failure.is_none() {
                runtime.first_failure = Some(report.clone());
            }
        }
        observer(Event::Request(report));
    }
    fn poll_task(
        &mut self,
        index: usize,
        cx: &mut Context<'_>,
        observer: &mut impl FnMut(Event),
    ) -> Poll<Progress> {
        let Some(mut task) = self.tasks[index].take() else {
            return Poll::Pending;
        };
        match task.state {
            State::Running(mut future) => match future.as_mut().poll(cx) {
                Poll::Pending => {
                    task.state = State::Running(future);
                    self.tasks[index] = Some(task);
                    Poll::Pending
                }
                Poll::Ready(Completion {
                    mut report,
                    reply,
                    budget,
                }) => {
                    if let (Some(bytes), Some(budget)) = (reply, budget) {
                        task.state = State::Sending {
                            bytes,
                            budget,
                            report,
                        };
                        self.tasks[index] = Some(task);
                        cx.waker().wake_by_ref();
                    } else {
                        if report.error.is_none() {
                            report.error = Some(RequestError::Closed);
                        }
                        self.finish(report, observer);
                    }
                    Poll::Ready(Progress::Activity)
                }
            },
            State::Sending {
                bytes,
                mut budget,
                mut report,
            } => {
                let error = budget
                    .poll_guard(cx)
                    .and_then(|()| budget.now().map(|_| ()));
                if let Err(error) = error {
                    report.error = Some(error);
                } else if let Some(socket) = self.listeners[report.listener].as_ref() {
                    // now() rechecks the original native bound after its clock
                    // sample; no new request/effect follows an elapsed hard.
                    match socket.poll_send_to(cx, &bytes, report.peer) {
                        Poll::Pending => {
                            task.state = State::Sending {
                                bytes,
                                budget,
                                report,
                            };
                            self.tasks[index] = Some(task);
                            return Poll::Pending;
                        }
                        Poll::Ready(Ok(written)) if written == bytes.len() => {
                            report.sent_bytes = Some(written)
                        }
                        Poll::Ready(Ok(_)) => {
                            report.error = Some(RequestError::Send(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "short DNS UDP datagram send",
                            )))
                        }
                        Poll::Ready(Err(error)) => report.error = Some(RequestError::Send(error)),
                    }
                } else {
                    report.error = Some(RequestError::Closed);
                }
                self.finish(report, observer);
                Poll::Ready(Progress::Activity)
            }
        }
    }
    fn receive(
        &mut self,
        cx: &mut Context<'_>,
        observer: &mut impl FnMut(Event),
    ) -> Poll<Progress> {
        let Some(slot) = self.tasks.iter().position(Option::is_none) else {
            return Poll::Pending;
        };
        for offset in 0..2 {
            let index = (self.listener_cursor + offset) % 2;
            let Some(socket) = self.listeners[index].as_ref() else {
                continue;
            };
            let mut buffer = ReadBuf::new(&mut self.buffer);
            let result = socket.poll_recv_from(cx, &mut buffer);
            match result {
                Poll::Pending => {}
                Poll::Ready(Err(error)) => {
                    self.listeners[index] = None;
                    self.report.listener_errors[index] = Some(error);
                    self.listener_cursor = (index + 1) % 2;
                    observer(Event::ListenerLost(index));
                    return Poll::Ready(Progress::Activity);
                }
                Poll::Ready(Ok(peer)) => {
                    // Capture native hard before source sampling or name work.
                    let started = Instant::now();
                    let hard = started.checked_add(self.limits.request_lifetime);
                    let filled = buffer.filled();
                    let id = filled.get(..2).and_then(|bytes| bytes.try_into().ok());
                    self.serial = match self.serial.checked_add(1) {
                        Some(serial) => serial,
                        None => {
                            self.begin_close();
                            return Poll::Ready(Progress::Activity);
                        }
                    };
                    let mut request_report = RequestReport {
                        serial: self.serial,
                        listener: index,
                        peer,
                        id,
                        route: None,
                        gns_records: None,
                        skipped_records: 0,
                        packed: None,
                        lookup: None,
                        gns_connect_error: None,
                        gns_connect_failures: 0,
                        identity_connect_error: None,
                        identity_connect_failures: 0,
                        dns_admitted: false,
                        dns_cancelled: false,
                        dns_stopped: false,
                        dns_stop: None,
                        dns_rejected: 0,
                        dns_io: None,
                        dns_cancel_error: None,
                        vpn: Vec::new(),
                        reply_bytes: 0,
                        sent_bytes: None,
                        error: None,
                    };
                    let admitted = (|| {
                        if filled.len() > self.limits.packet.maximum_packet_bytes {
                            return Err(RequestError::Protocol(Fault::TooLarge));
                        }
                        let hard = hard.ok_or(RequestError::Protocol(Fault::Overflow))?;
                        if Instant::now() >= hard {
                            return Err(RequestError::Stopped(StopReason::NativeDeadline));
                        }
                        let sample = self.ports.clock.sample().map_err(RequestError::Protocol)?;
                        let micros = duration_micros(self.limits.request_lifetime)
                            .map_err(RequestError::Protocol)?;
                        let until = sample
                            .now
                            .as_micros()
                            .checked_add(micros)
                            .filter(|until| *until != u64::MAX)
                            .ok_or(RequestError::Protocol(Fault::Overflow))?;
                        if Instant::now() >= hard {
                            return Err(RequestError::Stopped(StopReason::NativeDeadline));
                        }
                        let mut bytes = Vec::new();
                        bytes
                            .try_reserve_exact(filled.len())
                            .map_err(|_| RequestError::Protocol(Fault::Capacity))?;
                        bytes.extend_from_slice(filled);
                        Ok((bytes, until, hard))
                    })();
                    self.listener_cursor = (index + 1) % 2;
                    self.report.received = self.report.received.saturating_add(1);
                    self.report.active += 1;
                    match admitted {
                        Err(error) => {
                            request_report.error = Some(error);
                            self.finish(request_report, observer);
                        }
                        Ok((bytes, until, hard)) => {
                            let cancel = Rc::new(Cell::new(None));
                            let future = request::run(
                                bytes,
                                self.ports.clone(),
                                self.limits,
                                until,
                                hard,
                                cancel.clone(),
                                request_report,
                            );
                            self.tasks[slot] = Some(Task {
                                hard,
                                alarm: Box::pin(tokio::time::sleep_until(hard)),
                                cancel,
                                state: State::Running(Box::pin(future)),
                            });
                            cx.waker().wake_by_ref();
                        }
                    }
                    return Poll::Ready(Progress::Activity);
                }
            }
        }
        Poll::Pending
    }
}
fn has_diagnostics(report: &RequestReport) -> bool {
    report.error.is_some()
        || report.gns_connect_error.is_some()
        || report.identity_connect_error.is_some()
        || report.dns_io.is_some()
        || report.dns_cancel_error.is_some()
        || report.lookup.as_ref().is_some_and(|facts| {
            facts.gns_cancel_error.is_some() || facts.identity_cancel_error.is_some()
        })
        || report.vpn.iter().any(|facts| {
            facts.loss.is_some()
                || facts.connect_error.is_some()
                || facts.close_error.is_some()
                || matches!(&facts.cancel, Some(Err(_)))
        })
}
fn bind(requested: SocketAddr) -> (Option<UdpSocket>, Binding) {
    let result = (|| {
        let domain = if requested.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        if requested.is_ipv6() {
            socket.set_only_v6(true)?;
        }
        socket.set_nonblocking(true)?;
        socket.bind(&requested.into())?;
        let socket = UdpSocket::from_std(StdSocket::from(socket))?;
        let actual = socket.local_addr()?;
        Ok::<_, io::Error>((socket, actual))
    })();
    match result {
        Ok((socket, actual)) => (
            Some(socket),
            Binding {
                requested,
                local: Some(actual),
                error: None,
            },
        ),
        Err(error) => (
            None,
            Binding {
                requested,
                local: None,
                error: Some(error),
            },
        ),
    }
}
