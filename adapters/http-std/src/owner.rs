use crate::{
    Counters, Error, Fault, HttpLimits, IoLease, Job, Method, Progress, Proxy, Redirects, Request,
    SocketDiagnostic, Tls, WireReport,
    exchange::{Exchange, exchange},
    gate::{Gate, cooperate},
    transport::{basic, socket, unescape, validate_uri},
};
use gnunet_client_host::resolution::SharedResolution;
use std::{
    cell::Cell,
    fmt,
    future::{Future, poll_fn},
    pin::Pin,
    rc::Rc,
    sync::{Arc, atomic::Ordering},
    task::{Context, Poll},
};
use tokio::time::Instant;
use zeroize::Zeroizing;

/// Bounded selected response metadata used by GET/HEAD/SOAP consumers. No cookie
/// jar, authentication provider or arbitrary response-header framework is added.
pub struct Head {
    pub(crate) length: Option<u64>,
    pub(crate) kind: Option<Zeroizing<Vec<u8>>>,
    pub(crate) location: Option<Zeroizing<Vec<u8>>>,
}
impl Head {
    /// Actual declared entity length; HEAD may declare a body larger than the
    /// read allowance because its response has no entity body to allocate/read.
    pub fn content_length(&self) -> Option<u64> {
        self.length
    }
    /// Exact bounded Content-Type bytes, with no MIME/charset inference.
    pub fn content_type(&self) -> Option<&[u8]> {
        self.kind.as_deref().map(Vec::as_slice)
    }
    /// Actual bounded Location bytes. An exposed SOAP POST is never repeated or
    /// redirected merely because this value is present.
    pub fn location(&self) -> Option<&[u8]> {
        self.location.as_deref().map(Vec::as_slice)
    }
}
impl fmt::Debug for Head {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpHead")
            .field("content_length", &self.length)
            .field("content_type_bytes", &self.kind.as_ref().map(|v| v.len()))
            .field("location_bytes", &self.location.as_ref().map(|v| v.len()))
            .finish()
    }
}
/// Actual fully received original final HTTP response. A non-2xx SOAP fault is
/// retained for the actual SOAP consumer; HTTP status alone is never a mapping ACK.
pub struct Response {
    job: Job,
    /// Bounded fully received decoded body, wiped when its owner drops.
    pub body: Zeroizing<Vec<u8>>,
    /// Actual original final HTTP status.
    pub status: u16,
    /// Actual bounded original selected HTTP metadata, including HEAD length.
    pub head: Head,
    /// Actual safe GET/HEAD redirects followed under the same original bounds.
    pub redirects: usize,
    /// Actual native counts, including negotiation/TLS overhead.
    pub wire: WireReport,
    /// Original actual nonfatal socket initialization diagnostics.
    pub diagnostics: Vec<SocketDiagnostic>,
}
impl Response {
    /// Exact original request identity; it is not a replacement connection token.
    pub fn job(&self) -> &Job {
        &self.job
    }
}
impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse")
            .field("job", &self.job)
            .field("status", &self.status)
            .field("bytes", &self.body.len())
            .field("redirects", &self.redirects)
            .field("wire", &self.wire)
            .finish()
    }
}
/// A fully framed response and the independently observed post-response guard.
/// Receiving the response is factual; a post-guard failure still denies normal
/// request success and any further work under this original request.
pub struct ObservedResponse {
    /// Actual fully received response, without a copied body or replacement job.
    pub response: Response,
    /// First actual failure observed after response framing completed.
    pub post_guard: Option<Error>,
}
impl ObservedResponse {
    /// Preserve the ordinary consumer contract: a failed guard is still an error.
    pub fn into_result(self) -> Result<Response, Error> {
        match self.post_guard {
            Some(error) => Err(error),
            None => Ok(self.response),
        }
    }
}
struct Finished {
    body: Zeroizing<Vec<u8>>,
    status: u16,
    head: Head,
    redirects: usize,
    wire: WireReport,
    post_guard: Option<Error>,
}
type Task = Pin<Box<dyn Future<Output = Result<Finished, Error>>>>;
/// One foreground-polled original HTTP request owner. Borrowed drive-future drop
/// preserves the same IO cursor. Actual cancellation drops its whole connection.
pub struct Client {
    request: Request,
    gate: Gate,
    task: Option<Task>,
    result: Option<ObservedResponse>,
    counts: Arc<Counters>,
    progress: Progress,
    stopped: bool,
}
impl Drop for Client {
    fn drop(&mut self) {
        // Physical IO and its Resolver leases stop before the clock waiter,
        // immutable intent and retained metadata fields are released.
        self.cancel();
    }
}
impl Client {
    /// Admit exactly one immutable original intent. Cloned Request handles cannot
    /// re-admit it after success/cancel/loss; an explicit new Request is required.
    /// Both caller targets are fixed before any DNS/socket/TLS/HTTP operation.
    pub fn new(
        request: Request,
        resolution: SharedResolution,
        tls: Tls,
        proxy: Option<Arc<Proxy>>,
        limits: HttpLimits,
        original_hard: Instant,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if request.uri().len() > limits.uri_bytes {
            return Err(Fault::Capacity.into());
        }
        if request.0.body.len() > limits.request_body_bytes {
            return Err(Fault::Capacity.into());
        }
        if request.method() == Method::SoapPost && request.redirects() != Redirects::None {
            return Err(Fault::InvalidInput.into());
        }
        // Claim this original attempt before invoking caller clock/Resolver ports,
        // so a reentrant port cannot admit the same cloned intent twice. Later
        // admission errors require an explicit fresh Request, never an old replay.
        if request.0.admitted.replace(true) {
            return Err(Fault::StaleGeneration.into());
        }
        let clock = resolution.clock();
        if Instant::now() >= original_hard {
            return Err(Fault::Deadline.into());
        }
        let mut gate = Gate::new(clock.clone(), request.until())?;
        gate.hard = gate.hard.min(original_hard);
        if Instant::now() >= gate.hard {
            return Err(Fault::Deadline.into());
        }
        let mut url = validate_uri(request.uri())?;
        let https_only = url.scheme() == "https";
        let origin = url.origin();
        let auth = if !url.username().is_empty() || url.password().is_some() {
            Some(basic(
                &unescape(url.username().as_bytes())?,
                &unescape(url.password().unwrap_or("").as_bytes())?,
            )?)
        } else {
            None
        };
        let lease = Rc::new(IoLease {
            clock,
            until: Cell::new(request.until()),
            hard: Cell::new(gate.hard),
            checked: Cell::new(0),
        });
        let progress = Progress::new(request.job().clone());
        let counts = Arc::new(Counters::reserved(limits.probes, progress.state.clone())?);
        let recording = counts.clone();
        let observations = progress.state.clone();
        let intent = request.clone();
        let task = Box::pin(async move {
            for redirects in 0..=limits.redirects {
                lease.check()?;
                let (io, absolute) = socket(
                    &url,
                    proxy.as_deref(),
                    &resolution,
                    &tls,
                    lease.clone(),
                    recording.clone(),
                    limits,
                )
                .await?;
                let inherited = if url.origin() == origin {
                    auth.as_deref().map(|a| a.as_slice())
                } else {
                    None
                };
                let reply = exchange(
                    io,
                    Exchange {
                        url: &url,
                        absolute,
                        proxy: proxy.as_deref(),
                        inherited_auth: inherited,
                        request: &intent,
                        lease: lease.clone(),
                        progress: observations.clone(),
                        limits,
                    },
                )
                .await?;
                if reply.post_guard.is_none()
                    && intent.redirects() == Redirects::Follow
                    && matches!(reply.status, 301 | 302 | 303 | 307 | 308)
                {
                    if redirects == limits.redirects {
                        return Err(Fault::Capacity.into());
                    }
                    let location = reply.head.location.ok_or(Fault::Malformed)?;
                    if location.len() > limits.uri_bytes {
                        return Err(Fault::Capacity.into());
                    }
                    let next =
                        url.join(std::str::from_utf8(&location).map_err(|_| Fault::Malformed)?)?;
                    if next.as_str().len() > limits.uri_bytes {
                        return Err(Fault::Capacity.into());
                    }
                    if !matches!(next.scheme(), "http" | "https")
                        || https_only && next.scheme() != "https"
                    {
                        return Err(Fault::PermissionDenied.into());
                    }
                    url = validate_uri(next.as_str().as_bytes())?;
                    cooperate().await;
                    continue;
                }
                return Ok(Finished {
                    body: reply.body,
                    status: reply.status,
                    head: reply.head,
                    redirects,
                    wire: recording.report(),
                    post_guard: reply.post_guard,
                });
            }
            Err(Fault::Capacity.into())
        });
        progress.state.queued.store(true, Ordering::Release);
        Ok(Self {
            request,
            gate,
            task: Some(task),
            result: None,
            counts,
            progress,
            stopped: false,
        })
    }
    /// Original immutable request handle.
    pub fn request(&self) -> &Request {
        &self.request
    }
    /// Original allocation-bound progress, retained across cancel or source loss.
    pub fn progress(&self) -> Progress {
        self.progress.clone()
    }
    /// Immutable native target retained across all negotiation/redirect phases.
    pub fn hard_deadline(&self) -> Instant {
        self.gate.hard
    }
    /// Exact native byte/socket counts; TLS plaintext is reported separately.
    pub fn wire(&self) -> WireReport {
        self.counts.report()
    }
    /// Move original warnings only after its actual connection task has stopped.
    pub fn take_diagnostics(&mut self) -> Result<Vec<SocketDiagnostic>, Error> {
        if self.task.is_some() {
            return Err(Fault::NotReady.into());
        }
        self.counts.take_diagnostics()
    }
    /// Physical close of only this owned request, independent of fresh clocks.
    /// No mutation is automatically repeated or rebound to another source.
    pub fn cancel(&mut self) {
        self.task = None;
        self.result = None;
        self.stopped = true;
    }
    /// Independent original hard alarm is registered before canonical clock
    /// stabilization. Completed results are retained through a revision race.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Response, Error>> {
        self.poll_observed(cx, &mut |_| {})
            .map(|result| result.and_then(ObservedResponse::into_result))
    }
    /// Observe a fully framed response exactly once before the final guard can
    /// wait or fail. The callback may record bounded response facts; it grants
    /// no permission for subsequent IO or overall request success. If a guard
    /// then waits, this owner retains the same response until its original
    /// completion or cancellation, without replaying the callback or request.
    /// The observer must be selected for the poll that first forms the response;
    /// switching from ordinary poll later does not replay an earlier observation.
    pub fn poll_observed(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(&Response),
    ) -> Poll<Result<ObservedResponse, Error>> {
        if self.stopped {
            return Poll::Ready(Err(Fault::Closed.into()));
        }
        match self.gate.poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => {
                if self.result.is_some() {
                    return self.finish_observed(Some(e));
                }
                self.cancel();
                return Poll::Ready(Err(e));
            }
            Poll::Ready(Ok(_)) => {}
        }
        if self.result.is_none() {
            let Some(task) = &mut self.task else {
                return Poll::Ready(Err(Fault::Closed.into()));
            };
            match task.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => {
                    // Actual IO has stopped; a later clock error must not replace
                    // the original transport failure observed by this poll.
                    self.task = None;
                    self.stopped = true;
                    return Poll::Ready(Err(error));
                }
                Poll::Ready(Ok(result)) => {
                    self.task = None;
                    let mut post_guard = result.post_guard;
                    let diagnostics = match self.counts.take_diagnostics() {
                        Ok(diagnostics) => diagnostics,
                        Err(error) => {
                            if post_guard.is_none() {
                                post_guard = Some(error);
                            }
                            Vec::new()
                        }
                    };
                    let observed = ObservedResponse {
                        response: Response {
                            job: self.request.job().clone(),
                            body: result.body,
                            status: result.status,
                            head: result.head,
                            redirects: result.redirects,
                            wire: result.wire,
                            diagnostics,
                        },
                        post_guard,
                    };
                    // This is the single point where a complete response is
                    // formed. No callback is replayed on later guard polls.
                    observe(&observed.response);
                    self.result = Some(observed);
                }
            }
        }
        if let Some(completed) = &self.result
            && completed.post_guard.is_some()
        {
            return self.finish_observed(None);
        }
        match self.gate.poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return self.finish_observed(Some(e)),
            Poll::Ready(Ok(_)) => {}
        }
        self.finish_observed(None)
    }
    fn finish_observed(
        &mut self,
        post_guard: Option<Error>,
    ) -> Poll<Result<ObservedResponse, Error>> {
        self.stopped = true;
        let result = match self.result.take() {
            Some(mut result) => {
                if result.post_guard.is_none() {
                    result.post_guard = post_guard;
                }
                Ok(result)
            }
            None => Err(Fault::NotReady.into()),
        };
        Poll::Ready(result)
    }
    /// Cancellation-safe borrowed wait; no global task or pool takes the source.
    pub async fn drive(&mut self) -> Result<Response, Error> {
        poll_fn(|cx| self.poll(cx)).await
    }
}
