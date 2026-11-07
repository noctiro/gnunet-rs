//! Caller-driven HTTP/1 proxy streaming over actual connected plain/TLS IO.
//!
//! Hyper parses/fragments HTTP. No body is collected, connection is spawned,
//! request is replayed, raw tunnel substituted, or response promoted to remote
//! delivery. The surrounding session retains its original Wire Controls.
use crate::{Error, budget::Budget, wire::Io};
use gnunet_types::Error as Fault;
use hyper::{
    Request, Response, StatusCode,
    body::{Body, Bytes, Frame, Incoming, SizeHint},
    header::HeaderName,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use std::{
    cell::RefCell,
    fmt,
    future::{Future, poll_fn},
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};
use tokio::time::Instant;
mod rewrite;
mod stream;
pub use stream::Snapshot as StreamSnapshot;

/// One actual new upstream, already connected and, where required, verified by
/// the original TLS owner. It must not replay an exposed earlier request.
pub(crate) trait Connector {
    fn connect(&self) -> Pin<Box<dyn Future<Output = Result<Io, Error>> + '_>>;
}
/// Original browser origin and actual LEHO/upstream origin. Hosts are bare
/// ASCII names or numeric addresses; port belongs to both selected origins.
#[derive(Clone, Debug)]
pub(crate) struct View {
    pub browser_host: String,
    pub upstream_host: String,
    pub port: u16,
    pub tls: bool,
}
/// Streaming resource policy; none of these bounds allocates an entire body.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum actual fields and Connection-nominated names per header block.
    pub maximum_headers: usize,
    /// Bounded Hyper read buffer and complete HTTP metadata ceiling.
    pub maximum_head_bytes: usize,
    /// Bounded new upstreams retained by one original browser session.
    pub maximum_requests: usize,
    /// Optional actual data-byte limit per request body and response body.
    /// None allows streaming until the original session budget, not unbounded
    /// in-memory buffering or a new renewable request lifetime.
    pub maximum_body_bytes: Option<u64>,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            maximum_headers: 128,
            maximum_head_bytes: 65_536,
            maximum_requests: 128,
            maximum_body_bytes: None,
        }
    }
}
impl Limits {
    /// Validate policy before the surrounding session creates native resources.
    pub fn validate(self) -> Result<(), Error> {
        if !(1..=1024).contains(&self.maximum_headers)
            || !(8192..=1024 * 1024).contains(&self.maximum_head_bytes)
            || !(1..=4096).contains(&self.maximum_requests)
        {
            return Err(Fault::InvalidInput.into());
        }
        Ok(())
    }
}
/// Actual body-interface observations. Yielding a frame means handing it to
/// Hyper; it does not prove a socket write or application-level remote receipt.
#[derive(Clone, Copy, Debug, Default)]
pub struct BodyFacts {
    /// Actual data bytes consumed from Incoming, including a rejected last frame.
    pub observed_bytes: u64,
    /// Data bytes actually yielded to the other Hyper HTTP state machine.
    pub yielded_bytes: u64,
    /// Actual trailers consumed from Incoming.
    pub observed_trailers: u64,
    /// Actual trailers yielded onward after hop-by-hop filtering.
    pub yielded_trailers: u64,
    /// Actual Incoming end-of-stream observations, including genuinely empty bodies.
    pub input_ends: u64,
    /// Source body owners dropped before observing original Incoming EOS.
    pub abandoned: u64,
}
/// Aggregate observations of the exact original stream API values. Native FD
/// closure and wire delivery remain independently reported by parent Controls.
#[derive(Clone, Copy, Debug, Default)]
pub struct StreamFacts {
    /// Actual stream values admitted to this HTTP scope.
    pub count: u64,
    /// Original Hyper leases still live at observation.
    pub live_leases: u64,
    /// Actual stream shutdown methods polled.
    pub shutdown_attempts: u64,
    /// Actual stream shutdown successes.
    pub shutdown_completions: u64,
    /// Actual stream IO shutdown failures.
    pub shutdown_failures: u64,
    /// Actual cleanup native hard expirations.
    pub shutdown_timeouts: u64,
    /// Original stream API values actually released.
    pub released: u64,
    /// Actual bytes consumed from original stream APIs.
    pub read_bytes: u64,
    /// Bytes accepted by original stream APIs; not remote delivery.
    pub accepted_write_bytes: u64,
    /// Any actual byte/metadata counter overflow.
    pub counter_overflow: bool,
}
/// Independent source/control/HTTP/retirement errors and observed progress.
/// Errors remain owned but Debug deliberately prints no HTTP payload/header data.
#[derive(Default)]
pub struct Report {
    /// Actual parsed browser request headers observed.
    pub requests: u64,
    /// Original send_request calls, each made once. An invocation does not
    /// prove queue admission, writing or processing; original IO facts are separate.
    pub send_calls: u64,
    /// Actual upstream response headers received, not browser delivery.
    pub responses: u64,
    /// Actual original body-interface facts.
    pub request_body: BodyFacts,
    /// Actual original body-interface facts.
    pub response_body: BodyFacts,
    /// Actual client connection drivers constructed.
    pub drivers_started: u64,
    /// Drivers whose original without_shutdown future genuinely terminated.
    pub drivers_ended: u64,
    /// Drivers relinquished before original termination; no completion claimed.
    pub drivers_abandoned: u64,
    /// Actual original browser HTTP driver returned success.
    pub browser_http_ended: bool,
    /// Unprocessed bytes actually returned by original Hyper connection parts.
    pub discarded_read_bytes: u64,
    /// Bounded first original errors by HTTP, IO, protocol, clock, other and
    /// cleanup category. Later causes are explicitly counted, not copied.
    pub errors: [Option<Error>; 6],
    /// Actual total error observations for each bounded category.
    pub error_counts: [u64; 6],
    /// Counts above the retained first original cause in each category.
    pub omitted_errors: [u64; 6],
    /// Actual browser stream API observations.
    pub browser: Option<StreamSnapshot>,
    /// Aggregate actual upstream stream API observations.
    pub upstreams: StreamFacts,
    /// Every original Hyper lease and stream API value was actually released.
    /// This grants no parent TCP closure or remote delivery proof.
    pub streams_released: bool,
    /// Any HTTP/body diagnostic count saturated instead of silently wrapping.
    pub counter_overflow: bool,
}
impl fmt::Debug for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpReport")
            .field("requests", &self.requests)
            .field("send_calls", &self.send_calls)
            .field("responses", &self.responses)
            .field("request_body", &self.request_body)
            .field("response_body", &self.response_body)
            .field("drivers_started", &self.drivers_started)
            .field("drivers_ended", &self.drivers_ended)
            .field("drivers_abandoned", &self.drivers_abandoned)
            .field("browser_http_ended", &self.browser_http_ended)
            .field("discarded_read_bytes", &self.discarded_read_bytes)
            .field("error_counts", &self.error_counts)
            .field("omitted_errors", &self.omitted_errors)
            .field("browser", &self.browser)
            .field("upstreams", &self.upstreams)
            .field("streams_released", &self.streams_released)
            .field("counter_overflow", &self.counter_overflow)
            .finish()
    }
}
impl Report {
    /// Actual source/control/close errors, not hidden by successful status/body.
    pub fn has_diagnostics(&self) -> bool {
        self.errors.iter().any(Option::is_some)
            || self.drivers_abandoned != 0
            || !self.streams_released
    }
}
struct State {
    report: Report,
    active: usize,
    browser: Option<stream::Control>,
    upstreams: Vec<stream::Control>,
}
/// Shared observations/cleanup authority created before the original HTTP
/// future. Clones grant no additional IO lease and start no task or source.
#[derive(Clone)]
pub struct Observer(Rc<RefCell<State>>);
impl fmt::Debug for Observer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = f.debug_struct("HttpObserver");
        out.field("owners", &Rc::strong_count(&self.0));
        if let Ok(state) = self.0.try_borrow() {
            out.field("active", &state.active)
                .field("upstream_streams", &state.upstreams.len())
                .field("error_counts", &state.report.error_counts);
        }
        out.finish_non_exhaustive()
    }
}
impl Default for Observer {
    fn default() -> Self {
        Self::new()
    }
}
fn add(value: &mut u64, overflow: &mut bool, n: u64) {
    match value.checked_add(n) {
        Some(next) => *value = next,
        None => {
            *value = u64::MAX;
            *overflow = true;
        }
    }
}
fn category(error: &Error) -> Fault {
    match error {
        Error::Protocol(error) | Error::Clock(error) => *error,
        Error::Stopped => Fault::Cancelled,
        Error::Deadline => Fault::Timeout,
        Error::Allocation(_) => Fault::Capacity,
        _ => Fault::Io,
    }
}
/// Hyper's Body/Service error must be Send+Sync. The full original non-Send
/// proxy cause is retained in Observer instead of being discarded or echoed.
#[derive(Clone, Copy, Debug)]
struct BridgeError(Fault);
impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GNS proxy HTTP stream: {}", self.0)
    }
}
impl std::error::Error for BridgeError {}
impl Observer {
    /// Construct fixed diagnostic storage without native effects.
    pub fn new() -> Self {
        Self(Rc::new(RefCell::new(State {
            report: Report::default(),
            active: 0,
            browser: None,
            upstreams: Vec::new(),
        })))
    }
    fn record(&self, error: Error, cleanup: bool) -> BridgeError {
        let code = category(&error);
        let index = if cleanup {
            5
        } else {
            match &error {
                Error::Http(_) => 0,
                Error::Io(_) => 1,
                Error::Protocol(_) => 2,
                Error::Clock(_) => 3,
                _ => 4,
            }
        };
        let mut state = self.0.borrow_mut();
        let report = &mut state.report;
        add(
            &mut report.error_counts[index],
            &mut report.counter_overflow,
            1,
        );
        if report.errors[index].is_none() {
            report.errors[index] = Some(error);
        } else {
            add(
                &mut report.omitted_errors[index],
                &mut report.counter_overflow,
                1,
            );
        }
        BridgeError(code)
    }
    fn returned(&self, error: Error) -> Error {
        let returned = match &error {
            Error::Stopped => Error::Stopped,
            Error::Deadline => Error::Deadline,
            Error::Clock(e) => Error::Clock(*e),
            Error::Protocol(e) => Error::Protocol(*e),
            _ => Error::Protocol(category(&error)),
        };
        self.record(error, false);
        returned
    }
    fn update(&self, update: impl FnOnce(&mut Report)) {
        update(&mut self.0.borrow_mut().report);
    }
    fn body(&self, response: bool, update: impl FnOnce(&mut BodyFacts, &mut bool)) {
        let mut state = self.0.borrow_mut();
        let report = &mut state.report;
        update(
            if response {
                &mut report.response_body
            } else {
                &mut report.request_body
            },
            &mut report.counter_overflow,
        );
    }
    fn reserve_upstream(&self, limits: Limits) -> Result<(), Error> {
        let mut state = self.0.borrow_mut();
        if state.upstreams.len() >= limits.maximum_requests {
            return Err(Fault::Capacity.into());
        }
        state.upstreams.try_reserve(1).map_err(Error::Allocation)
    }
    fn upstream(&self, io: Io) -> (stream::Control, stream::Lease) {
        let (control, lease) = stream::Control::new(io);
        self.0.borrow_mut().upstreams.push(control.clone());
        (control, lease)
    }
    /// After releasing the original HTTP future, finish the same actual TLS/IO
    /// values under the parent's once-captured native cleanup hard. No canonical
    /// clock, new admission or new duration is used. Timeout relinquishes the
    /// stream with explicit incomplete-shutdown facts, never a success receipt.
    pub async fn retire(&self, original_cleanup_hard: Instant) -> Result<(), Error> {
        let count = self.0.borrow().upstreams.len();
        let mut failure = None;
        for i in 0..=count {
            let control = {
                let state = self.0.borrow();
                if i == 0 {
                    state.browser.clone()
                } else {
                    state.upstreams.get(i - 1).cloned()
                }
            };
            if let Some(control) = control {
                let result = poll_fn(|cx| control.poll_retire(cx, original_cleanup_hard)).await;
                if let Err(error) = result {
                    let code = category(&error);
                    self.record(error, true);
                    if failure.is_none() {
                        failure = Some(Error::Protocol(code));
                    }
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }
    /// Consume only after all original futures/clones/leases ended and the same
    /// streams were actually released. Failure returns this still-owned Observer,
    /// rather than manufacturing an immutable successful shutdown snapshot.
    pub fn into_report(self) -> Result<Report, Self> {
        let ready = Rc::strong_count(&self.0) == 1 && {
            let state = self.0.borrow();
            state.active == 0
                && state
                    .browser
                    .iter()
                    .chain(state.upstreams.iter())
                    .all(|control| {
                        control
                            .snapshot()
                            .is_ok_and(|facts| !facts.lease_live && facts.io_released)
                    })
        };
        if !ready {
            return Err(self);
        }
        match Rc::try_unwrap(self.0) {
            Ok(inner) => {
                let mut state = inner.into_inner();
                state.report.browser = state
                    .browser
                    .as_ref()
                    .and_then(|control| control.snapshot().ok());
                for control in &state.upstreams {
                    if let Ok(facts) = control.snapshot() {
                        combine(&mut state.report.upstreams, facts);
                    }
                }
                state.report.streams_released = true;
                Ok(state.report)
            }
            Err(inner) => Err(Self(inner)),
        }
    }
}
fn combine(total: &mut StreamFacts, facts: StreamSnapshot) {
    let overflow = &mut total.counter_overflow;
    add(&mut total.count, overflow, 1);
    add(
        &mut total.live_leases,
        overflow,
        u64::from(facts.lease_live),
    );
    add(
        &mut total.shutdown_attempts,
        overflow,
        u64::from(facts.shutdown_attempted),
    );
    add(
        &mut total.shutdown_completions,
        overflow,
        u64::from(facts.shutdown_completed),
    );
    add(
        &mut total.shutdown_failures,
        overflow,
        u64::from(facts.shutdown_failed),
    );
    add(
        &mut total.shutdown_timeouts,
        overflow,
        u64::from(facts.shutdown_timed_out),
    );
    add(&mut total.released, overflow, u64::from(facts.io_released));
    add(&mut total.read_bytes, overflow, facts.read);
    add(
        &mut total.accepted_write_bytes,
        overflow,
        facts.accepted_write,
    );
    total.counter_overflow |= facts.counter_overflow;
}
struct Active(Observer);
impl Drop for Active {
    fn drop(&mut self) {
        let mut state = self.0.0.borrow_mut();
        state.active = state.active.saturating_sub(1);
    }
}
struct SourceBody {
    input: Pin<Box<Incoming>>,
    observer: Observer,
    budget: Budget,
    limits: Limits,
    nominated: Vec<HeaderName>,
    response: bool,
    observed: u64,
    done: bool,
    trailer: Option<Frame<Bytes>>,
    failed: bool,
}
impl SourceBody {
    fn new(
        input: Incoming,
        response: bool,
        nominated: Vec<HeaderName>,
        limits: Limits,
        budget: Budget,
        observer: Observer,
    ) -> Result<Self, Error> {
        if limits
            .maximum_body_bytes
            .is_some_and(|cap| input.size_hint().exact().is_some_and(|n| n > cap))
        {
            return Err(Fault::Capacity.into());
        }
        let done = input.is_end_stream();
        if done {
            observer.body(response, |facts, overflow| {
                add(&mut facts.input_ends, overflow, 1)
            });
        }
        Ok(Self {
            input: Box::pin(input),
            observer,
            budget,
            limits,
            nominated,
            response,
            observed: 0,
            done,
            trailer: None,
            failed: false,
        })
    }
    fn end(&mut self) {
        if !self.done {
            self.done = true;
            self.observer.body(self.response, |facts, overflow| {
                add(&mut facts.input_ends, overflow, 1)
            });
        }
    }
    fn fail(&mut self, error: Error) -> Poll<Option<Result<Frame<Bytes>, BridgeError>>> {
        self.failed = true;
        Poll::Ready(Some(Err(self.observer.record(error, false))))
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BridgeError>>> {
        if self.failed {
            return Poll::Ready(None);
        }
        if let Err(error) = self.budget.check() {
            return self.fail(error);
        }
        if self.done {
            return Poll::Ready(self.trailer.take().map(Ok));
        }
        match self.input.as_mut().poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Err(error))) => self.fail(Error::Http(error)),
            Poll::Ready(None) => {
                self.end();
                Poll::Ready(self.trailer.take().map(Ok))
            }
            Poll::Ready(Some(Ok(mut frame))) => {
                if self.trailer.is_some() {
                    return self.fail(Fault::Malformed.into());
                }
                if let Some(data) = frame.data_ref() {
                    let size = data.len() as u64;
                    self.observer.body(self.response, |facts, overflow| {
                        add(&mut facts.observed_bytes, overflow, size)
                    });
                    let Some(next) = self.observed.checked_add(size) else {
                        return self.fail(Fault::Overflow.into());
                    };
                    self.observed = next;
                    if self.limits.maximum_body_bytes.is_some_and(|cap| next > cap) {
                        return self.fail(Fault::Capacity.into());
                    }
                    if self.input.is_end_stream() {
                        self.end();
                    }
                    Poll::Ready(Some(Ok(frame)))
                } else if let Some(trailers) = frame.trailers_mut() {
                    self.observer.body(self.response, |facts, overflow| {
                        add(&mut facts.observed_trailers, overflow, 1)
                    });
                    if let Err(error) = rewrite::trailers(trailers, &self.nominated, self.limits) {
                        return self.fail(error);
                    }
                    self.trailer = Some(frame);
                    // Preserve the original final-trailers owner until its actual
                    // source EOS, even if Hyper would otherwise drop after it.
                    if let Err(error) = self.budget.check() {
                        return self.fail(error);
                    }
                    match self.input.as_mut().poll_frame(cx) {
                        Poll::Ready(None) => {
                            self.end();
                            Poll::Ready(self.trailer.take().map(Ok))
                        }
                        Poll::Ready(Some(Err(error))) => self.fail(Error::Http(error)),
                        Poll::Ready(Some(Ok(_))) => self.fail(Fault::Malformed.into()),
                        Poll::Pending => Poll::Pending,
                    }
                } else {
                    self.fail(Fault::Malformed.into())
                }
            }
        }
    }
    fn yielded(&self, frame: &Frame<Bytes>) {
        self.observer.body(self.response, |facts, overflow| {
            if let Some(data) = frame.data_ref() {
                add(&mut facts.yielded_bytes, overflow, data.len() as u64);
            }
            if frame.trailers_ref().is_some() {
                add(&mut facts.yielded_trailers, overflow, 1);
            }
        });
    }
}
impl Drop for SourceBody {
    fn drop(&mut self) {
        if !self.done {
            self.observer.body(self.response, |facts, overflow| {
                add(&mut facts.abandoned, overflow, 1)
            });
        }
    }
}
struct RequestBody(SourceBody);
impl Body for RequestBody {
    type Data = Bytes;
    type Error = BridgeError;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BridgeError>>> {
        let inner = &mut self.get_mut().0;
        let result = inner.poll(cx);
        if let Poll::Ready(Some(Ok(frame))) = &result {
            inner.yielded(frame);
        }
        result
    }
    fn is_end_stream(&self) -> bool {
        self.0.done && self.0.trailer.is_none()
    }
    fn size_hint(&self) -> SizeHint {
        self.0.input.size_hint()
    }
}
type ClientParts = hyper::client::conn::http1::Parts<TokioIo<stream::Lease>>;
type ClientFuture = Pin<Box<dyn Future<Output = Result<ClientParts, hyper::Error>>>>;
struct Driver {
    future: Option<ClientFuture>,
    observer: Observer,
    done: bool,
    failed: bool,
}
impl Driver {
    fn new(future: ClientFuture, observer: Observer) -> Self {
        observer.update(|report| add(&mut report.drivers_started, &mut report.counter_overflow, 1));
        Self {
            future: Some(future),
            observer,
            done: false,
            failed: false,
        }
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), BridgeError>> {
        if self.done {
            return Poll::Ready(if self.failed {
                Err(BridgeError(Fault::Io))
            } else {
                Ok(())
            });
        }
        let Some(future) = &mut self.future else {
            return Poll::Ready(Err(BridgeError(Fault::Closed)));
        };
        let result = match future.as_mut().poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result,
        };
        self.done = true;
        self.future = None;
        self.observer
            .update(|report| add(&mut report.drivers_ended, &mut report.counter_overflow, 1));
        match result {
            Ok(parts) => {
                let extra = parts.read_buf.len();
                self.observer.update(|report| {
                    add(
                        &mut report.discarded_read_bytes,
                        &mut report.counter_overflow,
                        extra as u64,
                    )
                });
                drop(parts); // original Hyper lease ends; Observer still owns IO
                if extra != 0 {
                    self.failed = true;
                    Poll::Ready(Err(self.observer.record(Fault::Malformed.into(), false)))
                } else {
                    Poll::Ready(Ok(()))
                }
            }
            Err(error) => {
                self.failed = true;
                Poll::Ready(Err(self.observer.record(Error::Http(error), false)))
            }
        }
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        if !self.done {
            self.observer.update(|report| {
                add(
                    &mut report.drivers_abandoned,
                    &mut report.counter_overflow,
                    1,
                )
            });
        }
    }
}
struct ResponseBody {
    source: SourceBody,
    driver: Driver,
    control: stream::Control,
    pending: Option<Frame<Bytes>>,
    finished: bool,
    failed: bool,
}
impl ResponseBody {
    fn finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), BridgeError>> {
        match self.driver.poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        match self.control.poll_normal(cx, &self.source.budget) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(_)) => {
                self.finished = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.source.observer.record(error, true))),
        }
    }
    fn fail(&mut self, error: BridgeError) -> Poll<Option<Result<Frame<Bytes>, BridgeError>>> {
        self.failed = true;
        Poll::Ready(Some(Err(error)))
    }
}
impl Body for ResponseBody {
    type Data = Bytes;
    type Error = BridgeError;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BridgeError>>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(None);
        }
        if this.finished {
            let frame = this.pending.take();
            if let Some(frame) = &frame {
                this.source.yielded(frame);
            }
            return Poll::Ready(frame.map(Ok));
        }
        if let Err(error) = this.source.budget.check() {
            let error = this.source.observer.record(error, false);
            return this.fail(error);
        }
        let driven = this.driver.poll(cx);
        if let Poll::Ready(Err(error)) = driven {
            return this.fail(error);
        }
        if this.pending.is_none() && !this.source.done {
            match this.source.poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(error))) => return this.fail(error),
                Poll::Ready(Some(Ok(frame))) if !this.source.done => {
                    this.source.yielded(&frame);
                    return Poll::Ready(Some(Ok(frame)));
                }
                Poll::Ready(Some(Ok(frame))) => this.pending = Some(frame),
                Poll::Ready(None) => {}
            }
        }
        // A final length-delimited data frame or trailer is held until its
        // original driver terminates. Hyper cannot drop it early and thereby
        // turn incomplete upstream ownership into a BodyComplete claim.
        match this.finish(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => this.fail(error),
            Poll::Ready(Ok(())) => {
                let frame = this.pending.take();
                if let Some(frame) = &frame {
                    this.source.yielded(frame);
                }
                Poll::Ready(frame.map(Ok))
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        self.finished && self.pending.is_none()
    }
    fn size_hint(&self) -> SizeHint {
        self.source.input.size_hint()
    }
}
async fn exchange(
    mut request: Request<Incoming>,
    connector: Rc<dyn Connector>,
    view: Rc<View>,
    limits: Limits,
    budget: Budget,
    observer: Observer,
) -> Result<Response<ResponseBody>, BridgeError> {
    let result: Result<Response<ResponseBody>, Error> = async {
        budget.check()?;
        observer.update(|report| add(&mut report.requests, &mut report.counter_overflow, 1));
        let names = rewrite::request(&mut request, &view, limits)?;
        let (parts, input) = request.into_parts();
        let body = RequestBody(SourceBody::new(
            input,
            false,
            names,
            limits,
            budget.clone(),
            observer.clone(),
        )?);
        let request = Request::from_parts(parts, body);
        observer.reserve_upstream(limits)?;
        budget.check()?;
        let io = budget.wait(connector.connect()).await??;
        let (control, lease) = observer.upstream(io);
        budget.check()?;
        let mut builder = hyper::client::conn::http1::Builder::new();
        builder
            .max_headers(limits.maximum_headers)
            .max_header_size(limits.maximum_head_bytes)
            .max_buf_size(limits.maximum_head_bytes);
        let (mut sender, connection) = budget
            .wait(builder.handshake::<_, RequestBody>(TokioIo::new(lease)))
            .await?
            .map_err(Error::Http)?;
        let mut driver = Driver::new(Box::pin(connection.without_shutdown()), observer.clone());
        budget
            .wait(poll_fn(|cx| {
                let driven = driver.poll(cx);
                match sender.poll_ready(cx) {
                    Poll::Ready(result) => Poll::Ready(result.map_err(Error::Http)),
                    Poll::Pending => match driven {
                        Poll::Ready(_) => Poll::Ready(Err(Fault::Closed.into())),
                        Poll::Pending => Poll::Pending,
                    },
                }
            }))
            .await??;
        budget.check()?;
        observer.update(|report| add(&mut report.send_calls, &mut report.counter_overflow, 1));
        let mut sent = Box::pin(sender.send_request(request));
        let response = budget
            .wait(poll_fn(|cx| {
                let driven = driver.poll(cx);
                match sent.as_mut().poll(cx) {
                    Poll::Ready(response) => Poll::Ready(response.map_err(Error::Http)),
                    Poll::Pending => match driven {
                        Poll::Ready(_) => Poll::Ready(Err(Fault::Closed.into())),
                        Poll::Pending => Poll::Pending,
                    },
                }
            }))
            .await??;
        drop(sent);
        drop(sender); // no second request is queued on this upstream
        observer.update(|report| add(&mut report.responses, &mut report.counter_overflow, 1));
        budget.check()?;
        if response.status() == StatusCode::SWITCHING_PROTOCOLS {
            return Err(Fault::Unsupported.into());
        }
        let (mut parts, incoming) = response.into_parts();
        let names = rewrite::response(&mut parts.headers, &view, limits)?;
        let source = SourceBody::new(
            incoming,
            true,
            names,
            limits,
            budget.clone(),
            observer.clone(),
        )?;
        let mut body = ResponseBody {
            source,
            driver,
            control,
            pending: None,
            finished: false,
            failed: false,
        };
        if body.source.done {
            // HEAD, 204, 304 and genuine zero-length bodies may be dropped by
            // Hyper without polling. Finish their actual original driver now.
            budget
                .wait(poll_fn(|cx| body.finish(cx)))
                .await?
                .map_err(|e| Error::Protocol(e.0))?;
        }
        Ok(Response::from_parts(parts, body))
    }
    .await;
    result.map_err(|error| observer.record(error, false))
}
/// Serve one original browser stream. Caller constructs Observer first and
/// keeps it after cancellation; all Hyper futures remain inside this original
/// future. After it finishes or is relinquished, call Observer::retire with the
/// parent's fixed cleanup target, then close the parent's same Wire Controls.
/// No synthetic HTTP success or automatic request replay is emitted on failure.
pub(crate) async fn serve(
    browser: Io,
    connector: Rc<dyn Connector>,
    view: View,
    limits: Limits,
    budget: Budget,
    observer: Observer,
) -> Result<(), Error> {
    let (control, lease) = stream::Control::new(browser);
    {
        let mut state = observer.0.borrow_mut();
        if state.browser.is_some() {
            drop(state);
            return Err(observer.returned(Fault::Conflict.into()));
        }
        state.browser = Some(control.clone());
        state.active = state.active.checked_add(1).ok_or(Fault::Overflow)?;
    }
    let _active = Active(observer.clone());
    let result: Result<(), Error> = async {
        limits.validate()?;
        rewrite::validate(&view, limits)?;
        budget.check()?;
        let view = Rc::new(view);
        let service_observer = observer.clone();
        let service_budget = budget.clone();
        let service = service_fn(move |request| {
            exchange(
                request,
                connector.clone(),
                view.clone(),
                limits,
                service_budget.clone(),
                service_observer.clone(),
            )
        });
        let mut builder = hyper::server::conn::http1::Builder::new();
        builder
            .max_headers(limits.maximum_headers)
            .max_buf_size(limits.maximum_head_bytes)
            .auto_date_header(false);
        let connection = builder.serve_connection(TokioIo::new(lease), service);
        let parts = budget
            .wait(connection.without_shutdown())
            .await?
            .map_err(Error::Http)?;
        observer.update(|report| {
            report.browser_http_ended = true;
            add(
                &mut report.discarded_read_bytes,
                &mut report.counter_overflow,
                parts.read_buf.len() as u64,
            );
        });
        drop(parts);
        budget
            .wait(poll_fn(|cx| control.poll_normal(cx, &budget)))
            .await??;
        Ok(())
    }
    .await;
    result.map_err(|error| observer.returned(error))
}
