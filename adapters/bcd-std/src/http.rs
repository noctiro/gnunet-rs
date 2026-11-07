use crate::{
    provider::{self, Artifact, Bounds, RenderFailure, RenderRequest, Retirement, Stop},
    request,
};
use bytes::Bytes;
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_types::AbsoluteTime;
use http_body_util::Full;
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Body, Incoming},
    header::{self, HeaderValue},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use std::{
    cell::RefCell,
    collections::VecDeque,
    convert::Infallible,
    future::Future,
    io,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    time::{Instant, Sleep},
};

#[derive(Clone, Copy, Debug)]
/// Finite HTTP/application reservations and immutable phase lifetimes.
pub struct Limits {
    /// Maximum concurrently owned TCP connection futures.
    pub connections: usize,
    /// Maximum queued/render/retirement owners, including unresolved cleanup.
    pub jobs: usize,
    /// Maximum Hyper HTTP/1 input-buffer bytes, at least 8192.
    pub header_bytes: usize,
    /// Maximum parsed HTTP header entries.
    pub headers: usize,
    /// Maximum encoded GET query bytes.
    pub query_bytes: usize,
    /// Maximum decoded UTF-8 bytes per recognized form field.
    pub field_bytes: usize,
    /// Aggregate declared application reservation in bytes; not native RSS.
    pub retained_bytes: usize,
    /// Complete-head lifetime from actual TCP admission.
    pub head_timeout: Duration,
    /// Original full connection lifetime, including render and output.
    pub whole_timeout: Duration,
    /// Response-write lifetime intersected with the original whole target.
    pub output_timeout: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            connections: 8,
            jobs: 2,
            header_bytes: 16384,
            headers: 64,
            query_bytes: 16384,
            field_bytes: 1024,
            retained_bytes: 256 << 20,
            head_timeout: Duration::from_secs(10),
            whole_timeout: Duration::from_secs(120),
            output_timeout: Duration::from_secs(15),
        }
    }
}
impl Limits {
    /// Validate checked aggregate reservations and representable finite limits.
    pub fn validate(self, renderer: &provider::Settings) -> io::Result<()> {
        renderer.validate().map_err(io::Error::other)?;
        if self.connections == 0
            || self.connections > 512
            || self.jobs == 0
            || self.jobs > self.connections
            || !(8192..=65536).contains(&self.header_bytes)
            || self.headers == 0
            || self.headers > 128
            || self.query_bytes == 0
            || self.query_bytes > self.header_bytes
            || self.field_bytes == 0
            || self.field_bytes > self.query_bytes
        {
            return Err(io::Error::other("invalid BCD finite HTTP limits"));
        }
        for duration in [self.head_timeout, self.whole_timeout, self.output_timeout] {
            if duration.is_zero() || duration > Duration::from_secs(86400) {
                return Err(io::Error::other("invalid BCD lifetime"));
            }
        }
        let connection = self
            .header_bytes
            .checked_mul(2)
            .and_then(|n| n.checked_add(self.query_bytes))
            .and_then(|n| n.checked_add(renderer.limits.output_bytes))
            .and_then(|n| n.checked_add(16384))
            .ok_or_else(|| io::Error::other("BCD reservation overflow"))?;
        let required = connection
            .checked_mul(self.connections)
            .and_then(|n| {
                renderer
                    .limits
                    .reservation_bytes()
                    .ok()
                    .and_then(|j| j.checked_mul(self.jobs))
                    .and_then(|j| n.checked_add(j))
            })
            .ok_or_else(|| io::Error::other("BCD reservation overflow"))?;
        if required > self.retained_bytes {
            return Err(io::Error::other(
                "BCD aggregate application reservation exceeded",
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Default)]
/// Actual cumulative local facts and current independently owned slots.
pub struct Report {
    /// Actual TCP streams admitted into the connection pool.
    pub accepted: u64,
    /// Original HTTP futures completing without a native or framing failure.
    pub completed: u64,
    /// Original connection guard/HTTP failures.
    pub connection_errors: u64,
    /// Actual sockets dropped by explicit server shutdown.
    pub cancelled_connections: u64,
    /// Real checked artifacts produced; not remote download acknowledgements.
    pub rendered: u64,
    /// Actual render refusals/failures, including cancellation and deadline.
    pub failed: u64,
    /// Deferred original cleanup owners subsequently observed clean.
    pub retired: u64,
    /// Terminal unconfirmed reaping/directory reports; never clean retirement.
    pub undrained: u64,
    /// Actual bytes read on retired original sockets.
    pub read_bytes: u64,
    /// Actual bytes written on retired sockets, including HTTP headers.
    pub written_bytes: u64,
    /// Current independently owned connection count.
    pub active_connections: usize,
    /// Current queued/render/retirement count.
    pub active_jobs: usize,
    /// Admission stopped and all remaining waitable owners finished.
    /// A nonzero `undrained` still means fatal, unconfirmed cleanup.
    pub stopped: bool,
}
#[derive(Debug)]
/// Independent original reason an HTTP socket physically ended.
pub enum ConnectionCause {
    /// Explicit server stop, without synthetic response completion.
    Requested,
    /// Original native/canonical/cancellation/clock guard error.
    Guard(io::Error),
    /// Actual Hyper framing/socket error retaining its source chain.
    Http(hyper::Error),
}
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "Bounded events retain original cleanup ownership without an allocation during failure handoff"
)]
/// One bounded original transition, without card payload fields.
pub enum Event {
    /// A real TCP stream entered the bounded connection pool.
    Accepted {
        /// Server-local original connection serial.
        connection: u64,
    },
    /// The original socket closed, preserving its independent positive prefix.
    ConnectionClosed {
        /// Server-local original connection serial.
        connection: u64,
        /// Whether the original response completed locally in Hyper.
        complete: bool,
        /// Actual input bytes observed before physical close.
        read_bytes: u64,
        /// Actual output bytes observed before physical close.
        written_bytes: u64,
        /// Independent requested, native, clock or HTTP close cause.
        cause: Option<ConnectionCause>,
    },
    /// The original provider produced a real checked artifact.
    Rendered {
        /// Original server-local render serial, not a retry attempt.
        job: u64,
        /// Actual child, artifact and cleanup observations.
        report: provider::Report,
    },
    /// The original provider failed; unresolved cleanup stays in Server.
    RenderFailed {
        /// Original server-local render serial, not a retry attempt.
        job: u64,
        /// Original failure and report; any cleanup owner remains retained.
        error: RenderFailure,
    },
    /// An independently retained original cleanup owner actually completed.
    Retired {
        /// Original server-local render serial, not a retry attempt.
        job: u64,
        /// Actual child, artifact and cleanup observations.
        report: provider::Report,
    },
    /// Original cleanup ended unconfirmed; admission is stopped.
    RetirementFailed {
        /// Original server-local render serial, not a retry attempt.
        job: u64,
        /// Original error and retained directory; not a clean reaping receipt.
        report: provider::Report,
    },
    /// Bounded local progress requiring another original owner turn.
    Activity,
    /// Admission stopped and no waitable owner remains; inspect `Report::undrained`.
    Stopped,
}

struct Alarm {
    clock: Arc<dyn RuntimeClock>,
    original: Bounds,
    current: Bounds,
    logical: Pin<Box<Deadline>>,
    native: Pin<Box<Sleep>>,
    stop: Stop,
    read: u64,
    written: u64,
    failure: Option<io::Error>,
}
impl Alarm {
    fn bounds(
        now: u64,
        entered: Instant,
        cap: Option<Bounds>,
        life: Duration,
    ) -> io::Result<Bounds> {
        let hard = entered
            .checked_add(life)
            .ok_or_else(|| io::Error::other("BCD native deadline overflow"))?;
        let expires = now
            .checked_add(u64::try_from(life.as_micros()).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("BCD logical deadline overflow"))?;
        let value = cap.map_or(Bounds { expires, hard }, |b| Bounds {
            expires: expires.min(b.expires),
            hard: hard.min(b.hard),
        });
        if Instant::now() >= value.hard || now >= value.expires {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original BCD deadline",
            ));
        }
        Ok(value)
    }
    fn new(clock: Arc<dyn RuntimeClock>, limits: Limits) -> io::Result<Self> {
        let entered = Instant::now();
        let now = clock.sample().map_err(io::Error::other)?.now.as_micros();
        let original = Self::bounds(now, entered, None, limits.whole_timeout)?;
        let current = Self::bounds(now, entered, Some(original), limits.head_timeout)?;
        Ok(Self {
            logical: Box::pin(
                Deadline::at(clock.clone(), AbsoluteTime::from_micros(current.expires))
                    .map_err(io::Error::other)?,
            ),
            native: Box::pin(tokio::time::sleep_until(current.hard)),
            clock,
            original,
            current,
            stop: Stop::new(),
            read: 0,
            written: 0,
            failure: None,
        })
    }
    fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.stop.is_stopped() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "original BCD connection stopped",
            ));
        }
        if Instant::now() >= self.current.hard || self.native.as_mut().poll(cx).is_ready() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original BCD native deadline",
            ));
        }
        match self.logical.as_mut().poll(cx) {
            Poll::Ready(Err(e)) => return Err(io::Error::other(e)),
            Poll::Ready(Ok(())) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "original BCD logical deadline",
                ));
            }
            Poll::Pending => {}
        }
        let now = self
            .clock
            .sample()
            .map_err(io::Error::other)?
            .now
            .as_micros();
        if Instant::now() >= self.current.hard || now >= self.current.expires {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original BCD deadline",
            ));
        }
        Ok(())
    }
    fn phase(&mut self, life: Duration, output: bool) -> io::Result<Bounds> {
        match self.phase_inner(life, output) {
            Ok(bounds) => Ok(bounds),
            Err(error) => {
                let kind = error.kind();
                self.failure.get_or_insert(error);
                self.stop.request_stop();
                Err(io::Error::new(
                    kind,
                    "original BCD phase provider failed; connection retired",
                ))
            }
        }
    }
    fn phase_inner(&mut self, life: Duration, output: bool) -> io::Result<Bounds> {
        let entered = Instant::now();
        if self.stop.is_stopped() || entered >= self.current.hard {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original BCD head/whole expired",
            ));
        }
        let old_now = self
            .clock
            .sample()
            .map_err(io::Error::other)?
            .now
            .as_micros();
        if old_now >= self.current.expires || Instant::now() >= self.current.hard {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original BCD phase expired",
            ));
        }
        let current = Self::bounds(
            old_now,
            entered,
            Some(if output { self.current } else { self.original }),
            life,
        )?;
        let logical = Deadline::at(
            self.clock.clone(),
            AbsoluteTime::from_micros(current.expires),
        )
        .map_err(io::Error::other)?;
        if Instant::now() >= current.hard {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "BCD phase provider consumed original deadline",
            ));
        }
        self.current = current;
        self.logical = Box::pin(logical);
        self.native = Box::pin(tokio::time::sleep_until(current.hard));
        Ok(current)
    }
}
struct Io {
    stream: TcpStream,
    alarm: Rc<RefCell<Alarm>>,
}
impl AsyncRead for Io {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Err(e) = self.alarm.borrow_mut().check(cx) {
            return Poll::Ready(Err(e));
        }
        let before = buf.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(cx, buf);
        let count = buf.filled().len() - before;
        let mut alarm = self.alarm.borrow_mut();
        alarm.read = alarm.read.saturating_add(count as u64);
        result
    }
}
impl AsyncWrite for Io {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(e) = self.alarm.borrow_mut().check(cx) {
            return Poll::Ready(Err(e));
        }
        let result = Pin::new(&mut self.stream).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            let mut a = self.alarm.borrow_mut();
            a.written = a.written.saturating_add(*n as u64);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(e) = self.alarm.borrow_mut().check(cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
struct Ticket {
    stop: Stop,
    result: Option<Result<Vec<u8>, ()>>,
    waiter: Option<Waker>,
}
struct Waiting(Rc<RefCell<Ticket>>);
impl Future for Waiting {
    type Output = Result<Vec<u8>, ()>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut t = self.0.borrow_mut();
        if let Some(r) = t.result.take() {
            Poll::Ready(r)
        } else {
            t.waiter = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}
impl Drop for Waiting {
    fn drop(&mut self) {
        self.0.borrow().stop.request_stop();
    }
}
struct Queued {
    id: u64,
    request: RenderRequest,
    bounds: Bounds,
    ticket: Rc<RefCell<Ticket>>,
}
struct Shared {
    queue: VecDeque<Queued>,
    active: usize,
    next: u64,
    limits: Limits,
}
type Rendering = Pin<Box<dyn Future<Output = Result<Artifact, RenderFailure>>>>;
#[expect(
    clippy::large_enum_variant,
    reason = "The fixed job pool retains original child and directory ownership inline during failure handoff"
)]
enum Work {
    Rendering(Rendering),
    Retiring(Retirement),
}
struct Job {
    id: u64,
    stop: Stop,
    ticket: Rc<RefCell<Ticket>>,
    work: Work,
}
type ConnectionFuture = Pin<Box<dyn Future<Output = Result<(), hyper::Error>>>>;
struct Connection {
    id: u64,
    alarm: Rc<RefCell<Alarm>>,
    future: ConnectionFuture,
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.alarm.borrow().stop.request_stop();
    }
}

fn response(
    status: StatusCode,
    bytes: Vec<u8>,
    mime: &'static str,
    head: bool,
) -> Response<Full<Bytes>> {
    let length = bytes.len();
    let mut response = Response::new(Full::new(if head {
        Bytes::new()
    } else {
        Bytes::from(bytes)
    }));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(mime));
    response
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    if let Ok(n) = HeaderValue::from_str(&length.to_string()) {
        response.headers_mut().insert(header::CONTENT_LENGTH, n);
    }
    response
}
async fn handle(
    req: Request<Incoming>,
    shared: Rc<RefCell<Shared>>,
    alarm: Rc<RefCell<Alarm>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let limits = shared.borrow().limits;
    let error = |status| {
        response(
            status,
            b"BCD request failed\n".to_vec(),
            "text/plain; charset=utf-8",
            false,
        )
    };
    let head = req.method() == Method::HEAD;
    if req.method() != Method::GET && !head {
        return Ok(error(StatusCode::NOT_IMPLEMENTED));
    }
    if req.body().size_hint().lower() != 0
        || req.headers().contains_key(header::TRANSFER_ENCODING)
        || req
            .headers()
            .get(header::CONTENT_LENGTH)
            .is_some_and(|v| v.as_bytes() != b"0")
    {
        return Ok(error(StatusCode::BAD_REQUEST));
    }
    let bounds = match alarm.borrow_mut().phase(limits.whole_timeout, false) {
        Ok(b) => b,
        Err(_) => return Ok(error(StatusCode::REQUEST_TIMEOUT)),
    };
    let path = req.uri().path();
    if head || path == "/" || path == "/full" {
        let body = request::form(!head && path == "/full").into_bytes();
        if alarm
            .borrow_mut()
            .phase(limits.output_timeout, true)
            .is_err()
        {
            return Ok(error(StatusCode::REQUEST_TIMEOUT));
        }
        return Ok(response(
            StatusCode::OK,
            body,
            "text/html; charset=utf-8",
            head,
        ));
    }
    if path != "/submit/simple" && path != "/submit/full" {
        return Ok(error(StatusCode::NOT_FOUND));
    }
    let query = req.uri().query().unwrap_or("");
    if query.len() > limits.query_bytes {
        return Ok(error(StatusCode::URI_TOO_LONG));
    }
    let request = match request::parse(
        query,
        path == "/submit/full",
        limits.query_bytes,
        limits.field_bytes,
    ) {
        Ok(r) => r,
        Err(_) => return Ok(error(StatusCode::BAD_REQUEST)),
    };
    let png = request.png;
    let stop = Stop::new();
    let ticket = Rc::new(RefCell::new(Ticket {
        stop: stop.clone(),
        result: None,
        waiter: None,
    }));
    {
        let mut state = shared.borrow_mut();
        if state.active == state.limits.jobs {
            return Ok(error(StatusCode::SERVICE_UNAVAILABLE));
        }
        let id = state.next;
        let Some(next) = id.checked_add(1) else {
            return Ok(error(StatusCode::SERVICE_UNAVAILABLE));
        };
        state.next = next;
        state.active += 1;
        state.queue.push_back(Queued {
            id,
            request,
            bounds,
            ticket: ticket.clone(),
        });
    }
    let result = Waiting(ticket).await;
    if alarm
        .borrow_mut()
        .phase(limits.output_timeout, true)
        .is_err()
    {
        return Ok(error(StatusCode::REQUEST_TIMEOUT));
    }
    match result {
        Ok(bytes) => {
            let mut r = response(
                StatusCode::OK,
                bytes,
                if png { "image/png" } else { "application/pdf" },
                false,
            );
            r.headers_mut().insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_static(if png {
                    "attachment; filename=\"gns-qr-code.png\""
                } else {
                    "attachment; filename=\"gns-business-card.pdf\""
                }),
            );
            Ok(r)
        }
        Err(()) => Ok(error(StatusCode::INTERNAL_SERVER_ERROR)),
    }
}

/// Owns all HTTP connection futures and all independent original render futures.
/// No connection or job is spawned. Closing a socket cancels its ticket, while
/// this owner continues real renderer retirement instead of dropping its child.
pub struct Server {
    listener: Option<TcpListener>,
    renderer: Arc<provider::Settings>,
    clock: Arc<dyn RuntimeClock>,
    limits: Limits,
    shared: Rc<RefCell<Shared>>,
    connections: Vec<Connection>,
    jobs: Vec<Job>,
    events: VecDeque<Event>,
    cursor: usize,
    next: u64,
    stopping: bool,
    report: Report,
}
impl Server {
    /// Adopt the actual listener with one clock and fixed finite reservations.
    pub fn new(
        listener: TcpListener,
        renderer: Arc<provider::Settings>,
        clock: Arc<dyn RuntimeClock>,
        limits: Limits,
    ) -> io::Result<Self> {
        limits.validate(&renderer)?;
        let mut connections = Vec::new();
        connections
            .try_reserve_exact(limits.connections)
            .map_err(io::Error::other)?;
        let mut jobs = Vec::new();
        jobs.try_reserve_exact(limits.jobs)
            .map_err(io::Error::other)?;
        let mut queue = VecDeque::new();
        queue
            .try_reserve_exact(limits.jobs)
            .map_err(io::Error::other)?;
        let mut events = VecDeque::new();
        events
            .try_reserve_exact(limits.connections)
            .map_err(io::Error::other)?;
        Ok(Self {
            listener: Some(listener),
            renderer,
            clock,
            limits,
            shared: Rc::new(RefCell::new(Shared {
                queue,
                active: 0,
                next: 1,
                limits,
            })),
            connections,
            jobs,
            events,
            cursor: 0,
            next: 1,
            stopping: false,
            report: Report::default(),
        })
    }
    /// Stop admission/sockets first and request every original job cleanup; continue polling.
    pub fn request_shutdown(&mut self) {
        if self.stopping {
            return;
        }
        self.stopping = true;
        self.listener = None;
        for c in self.connections.drain(..) {
            let mut a = c.alarm.borrow_mut();
            let cause = a
                .failure
                .take()
                .map_or(ConnectionCause::Requested, ConnectionCause::Guard);
            self.report.cancelled_connections = self.report.cancelled_connections.saturating_add(1);
            self.report.read_bytes = self.report.read_bytes.saturating_add(a.read);
            self.report.written_bytes = self.report.written_bytes.saturating_add(a.written);
            self.events.push_back(Event::ConnectionClosed {
                connection: c.id,
                complete: false,
                read_bytes: a.read,
                written_bytes: a.written,
                cause: Some(cause),
            });
        }
        for job in &self.jobs {
            job.stop.request_stop();
        }
        for job in &self.shared.borrow().queue {
            job.ticket.borrow().stop.request_stop();
        }
    }
    /// Snapshot cumulative facts and exact current independently owned slots.
    pub fn report(&self) -> Report {
        let mut report = self.report;
        report.active_connections = self.connections.len();
        report.active_jobs = self.shared.borrow().active;
        report
    }
    /// Whether explicit stop has no remaining waitable owner; unconfirmed cleanup stays in Report.
    pub fn is_stopped(&self) -> bool {
        self.stopping
            && self.connections.is_empty()
            && self.jobs.is_empty()
            && self.shared.borrow().queue.is_empty()
    }
    /// Drive original jobs/streams without spawning; dropping only a wait preserves ownership.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Event>> {
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(Ok(event));
        }
        while let Some(q) = self.shared.borrow_mut().queue.pop_front() {
            let stop = q.ticket.borrow().stop.clone();
            let work = provider::render(
                q.request,
                self.renderer.clone(),
                self.clock.clone(),
                q.bounds,
                stop.clone(),
            );
            self.jobs.push(Job {
                id: q.id,
                stop,
                ticket: q.ticket,
                work: Work::Rendering(Box::pin(work)),
            });
        }
        self.report.active_jobs = self.shared.borrow().active;
        for i in 0..self.jobs.len() {
            let result = match &mut self.jobs[i].work {
                Work::Rendering(f) => match f.as_mut().poll(cx) {
                    Poll::Ready(r) => Some(r),
                    Poll::Pending => None,
                },
                Work::Retiring(r) => {
                    if let Poll::Ready(report) = r.poll(cx) {
                        let job = self.jobs.swap_remove(i);
                        self.shared.borrow_mut().active -= 1;
                        if report.undrained {
                            self.report.undrained = self.report.undrained.saturating_add(1);
                            self.request_shutdown();
                            return Poll::Ready(Ok(Event::RetirementFailed {
                                job: job.id,
                                report,
                            }));
                        }
                        self.report.retired = self.report.retired.saturating_add(1);
                        return Poll::Ready(Ok(Event::Retired {
                            job: job.id,
                            report,
                        }));
                    }
                    None
                }
            };
            if let Some(result) = result {
                let job = self.jobs.swap_remove(i);
                let mut t = job.ticket.borrow_mut();
                let event = match result {
                    Ok(artifact) => {
                        self.report.rendered = self.report.rendered.saturating_add(1);
                        let report = artifact.report;
                        t.result = Some(Ok(artifact.bytes));
                        self.shared.borrow_mut().active -= 1;
                        Event::Rendered {
                            job: job.id,
                            report,
                        }
                    }
                    Err(mut error) => {
                        self.report.failed = self.report.failed.saturating_add(1);
                        t.result = Some(Err(()));
                        if let Some(retirement) = error.take_retirement() {
                            self.jobs.push(Job {
                                id: job.id,
                                stop: job.stop,
                                ticket: job.ticket.clone(),
                                work: Work::Retiring(retirement),
                            });
                        } else {
                            self.shared.borrow_mut().active -= 1;
                            if error.report.undrained {
                                self.report.undrained = self.report.undrained.saturating_add(1);
                            }
                        }
                        Event::RenderFailed { job: job.id, error }
                    }
                };
                if let Some(w) = t.waiter.take() {
                    w.wake();
                }
                // Closing HTTP futures can drop Waiting and borrow this ticket.
                // Release the original borrow before physically closing sockets.
                drop(t);
                if self.report.undrained != 0 {
                    self.request_shutdown();
                }
                return Poll::Ready(Ok(event));
            }
        }
        for _ in 0..self.connections.len() {
            self.cursor %= self.connections.len();
            let i = self.cursor;
            self.cursor += 1;
            let permitted = self.connections[i].alarm.borrow_mut().check(cx);
            let mut result = match permitted {
                Ok(()) => self.connections[i]
                    .future
                    .as_mut()
                    .poll(cx)
                    .map(|r| r.map_err(ConnectionCause::Http)),
                Err(error) => Poll::Ready(Err(ConnectionCause::Guard(error))),
            };
            // The service may have replaced the head alarm with its original
            // whole/output cap while this HTTP future became pending. Register
            // that new earliest alarm now, without a second socket operation.
            if result.is_pending()
                && let Err(error) = self.connections[i].alarm.borrow_mut().check(cx)
            {
                result = Poll::Ready(Err(ConnectionCause::Guard(error)));
            }
            if let Poll::Ready(result) = result {
                let result = match self.connections[i].alarm.borrow_mut().failure.take() {
                    Some(error) => Err(ConnectionCause::Guard(error)),
                    None => result,
                };
                let complete = result.is_ok();
                let c = self.connections.swap_remove(i);
                let a = c.alarm.borrow();
                self.report.completed = self.report.completed.saturating_add(u64::from(complete));
                self.report.connection_errors = self
                    .report
                    .connection_errors
                    .saturating_add(u64::from(!complete));
                self.report.read_bytes = self.report.read_bytes.saturating_add(a.read);
                self.report.written_bytes = self.report.written_bytes.saturating_add(a.written);
                return Poll::Ready(Ok(Event::ConnectionClosed {
                    connection: c.id,
                    complete,
                    read_bytes: a.read,
                    written_bytes: a.written,
                    cause: result.err(),
                }));
            }
        }
        if !self.stopping
            && self.connections.len() < self.limits.connections
            && let Some(listener) = &self.listener
        {
            match listener.poll_accept(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok((stream, _))) => {
                    let id = self.next;
                    self.next = id
                        .checked_add(1)
                        .ok_or_else(|| io::Error::other("BCD connection serial exhausted"))?;
                    let alarm = Rc::new(RefCell::new(Alarm::new(self.clock.clone(), self.limits)?));
                    let state = self.shared.clone();
                    let guard = alarm.clone();
                    let service = service_fn(move |r| handle(r, state.clone(), guard.clone()));
                    let mut builder = http1::Builder::new();
                    builder
                        .keep_alive(false)
                        .half_close(true)
                        .header_read_timeout(None)
                        .max_headers(self.limits.headers)
                        .max_buf_size(self.limits.header_bytes);
                    let connection = builder.serve_connection(
                        TokioIo::new(Io {
                            stream,
                            alarm: alarm.clone(),
                        }),
                        service,
                    );
                    self.connections.push(Connection {
                        id,
                        alarm,
                        future: Box::pin(connection),
                    });
                    self.report.accepted = self.report.accepted.saturating_add(1);
                    return Poll::Ready(Ok(Event::Accepted { connection: id }));
                }
            }
        }
        self.report.active_connections = self.connections.len();
        self.report.active_jobs = self.shared.borrow().active;
        // A connection polled above can enqueue its first render after this
        // turn's job-adoption class. Exactly one cooperative wake transfers it
        // to that class next turn; an empty queue has no self-wake.
        if !self.shared.borrow().queue.is_empty() {
            cx.waker().wake_by_ref();
            return Poll::Ready(Ok(Event::Activity));
        }
        if self.is_stopped() {
            self.report.stopped = true;
            return Poll::Ready(Ok(Event::Stopped));
        }
        Poll::Pending
    }
}
