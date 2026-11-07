//! Actual bounded one-request HTTP connections, with no detached tasks.
mod cors;
use crate::{
    Context as Handlers, Error, OwnedRequest, Response,
    output::{Json, bytes, copy},
};
pub use cors::Cors;
use gnunet_rest::{
    http::{self, Expectation, Header, Request, RequestHead},
    route::{self, Endpoint, Family, Resolution},
};
use gnunet_service_runtime::{
    accepted::{AcceptState, AcceptedConnection, SocketEvent},
    clock::Deadline,
    connection::Connection,
    credentials::UnixAccess,
    service::{Listener, PeerAddress, ServiceOptions, ShutdownMode},
};
use gnunet_types::Error as Fault;
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Instant, Sleep},
};
use zeroize::{Zeroize, Zeroizing};
/// Explicit HTTP authorization. Credentials are never printed or retained in RX
/// after framing. No ambient username, password file or credential is imported.
pub struct Authorization {
    expected: Option<Zeroizing<Vec<u8>>>,
}
impl Authorization {
    /// Explicitly expose handlers without Basic authentication. Caller selects the
    /// network/filesystem ACL; this is never an implicit fallback on auth failure.
    pub const fn disabled() -> Self {
        Self { expected: None }
    }
    /// Exact HTTP Basic username/password. Inputs may contain UTF-8, not NUL/CR/LF;
    /// username cannot contain ':'. Owner keeps one zeroizing bounded credential.
    pub fn basic(username: &[u8], password: &[u8]) -> Result<Self, Error> {
        if username.is_empty()
            || username.contains(&b':')
            || username
                .len()
                .checked_add(password.len())
                .is_none_or(|n| n > 4096)
            || username
                .iter()
                .chain(password)
                .any(|b| matches!(b, 0 | b'\r' | b'\n'))
        {
            return Err(Fault::InvalidInput.into());
        }
        let mut expected = bytes(username.len() + 1 + password.len())?;
        expected[..username.len()].copy_from_slice(username);
        expected[username.len()] = b':';
        expected[username.len() + 1..].copy_from_slice(password);
        Ok(Self {
            expected: Some(expected),
        })
    }
    fn allows(&self, headers: http::Headers<'_>) -> Result<bool, Error> {
        let Some(expected) = &self.expected else {
            return Ok(true);
        };
        let mut auth = None;
        for header in headers {
            let header = header?;
            if header.name.eq_ignore_ascii_case(b"authorization") {
                if auth.is_some() {
                    return Ok(false);
                }
                auth = Some(header.value);
            }
        }
        let Some(auth) = auth else { return Ok(false) };
        let Some(mark) = auth.iter().position(|b| *b == b' ') else {
            return Ok(false);
        };
        let (kind, rest) = auth.split_at(mark);
        let encoded = &rest[1..];
        if !kind.eq_ignore_ascii_case(b"Basic") {
            return Ok(false);
        }
        let mut actual = bytes(4096)?;
        let Some(n) = decode_basic(encoded, &mut actual) else {
            return Ok(false);
        };
        let mut difference = n ^ expected.len();
        for (at, b) in expected.iter().enumerate() {
            difference |= usize::from(*b ^ actual.get(at).copied().unwrap_or(0));
        }
        Ok(difference == 0)
    }
}
impl std::fmt::Debug for Authorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Authorization([REDACTED])")
    }
}
/// Explicit immutable HTTP admission and CORS policies.
pub struct Policy {
    /// Explicit Basic authentication selection.
    pub authorization: Authorization,
    /// Validated origin alternatives, extension selection and response fields.
    pub cors: Cors,
}
/// Finite native HTTP connection resources. There is no keepalive/pipeline owner:
/// each accepted connection gets one response and an explicit Connection:close.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum simultaneous original accepted connections.
    pub clients: usize,
    /// Actual framing quotas, including total encoded wire bytes.
    pub framing: http::Limits,
    /// Maximum syscall payload/scratch bytes per read/write attempt.
    pub io_bytes: usize,
    /// Whole original input+handler native/logical lifetime.
    pub lifetime: Duration,
    /// Finite output suffix drain, anchored before the first output write.
    pub send_lifetime: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            clients: 16,
            framing: Default::default(),
            io_bytes: 4096,
            lifetime: Duration::from_secs(30),
            send_lifetime: Duration::from_secs(5),
        }
    }
}
/// Original connection finish. A full HTTP write proves local bytes only.
#[derive(Debug)]
pub struct Report {
    /// Actual selected status, absent if no complete request was handled.
    pub status: Option<u16>,
    /// Actual final-response bytes written before physical close.
    pub written: usize,
    /// Actual 100-continue bytes written on this original connection, including
    /// a partial failed prefix. Not a final status or backend/remote receipt.
    pub continue_written: usize,
    /// Original raw service status if this response carried one.
    pub service_status: Option<i64>,
    /// Original cause, even if an error response was physically written.
    pub failure: Option<Error>,
}
/// Caller-observable actual native events; no private payloads are printed.
#[derive(Debug)]
pub enum Event {
    /// Actual shared accept initialization diagnostics.
    Socket(SocketEvent),
    /// This original accepted peer failed actual ACL/Unix credential admission.
    Rejected(PeerAddress),
    /// A finished original physical connection, already closed.
    Closed(Report),
}
/// One bounded foreground polling step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// Actual accept, completion or other work happened.
    Activity,
    /// Caller observation/shutdown deadline, without inventing service success.
    WaitDeadline,
    /// Acceptance stopped and every original HTTP/native job physically dropped.
    Stopped,
}
struct Job<'a> {
    future: Pin<Box<dyn Future<Output = Report> + 'a>>,
}
/// Fixed-capacity owner of accepted connections and their original native jobs.
/// Constructor starts no task and opens no listener; caller drives Resolver.
pub struct Server<'a, 'id, I: gnunet_dns::Idna> {
    handlers: &'a Handlers<'id, I>,
    policy: &'a Policy,
    limits: Limits,
    options: ServiceOptions,
    unix: UnixAccess,
    jobs: Vec<Option<Job<'a>>>,
    accept: AcceptState,
    stopping: bool,
    closed: bool,
    cursor: usize,
    alarm: Option<Pin<Box<Sleep>>>,
    alarm_at: Option<Instant>,
}
impl<'a, 'id, I: gnunet_dns::Idna> Server<'a, 'id, I> {
    /// Reserve only bounded rows. Actual native endpoints and auth remain explicit.
    pub fn new(
        handlers: &'a Handlers<'id, I>,
        policy: &'a Policy,
        limits: Limits,
        options: ServiceOptions,
        unix: UnixAccess,
    ) -> Result<Self, Error> {
        if limits.clients == 0
            || limits.io_bytes == 0
            || limits.framing.wire_bytes < limits.framing.header_bytes
            || limits.lifetime.is_zero()
            || limits.send_lifetime.is_zero()
        {
            return Err(Fault::InvalidInput.into());
        }
        let mut jobs = Vec::new();
        jobs.try_reserve_exact(limits.clients)
            .map_err(|_| Fault::Capacity)?;
        jobs.resize_with(limits.clients, || None);
        Ok(Self {
            handlers,
            policy,
            limits,
            options,
            unix,
            jobs,
            accept: AcceptState::default(),
            stopping: false,
            closed: false,
            cursor: 0,
            alarm: None,
            alarm_at: None,
        })
    }
    /// Actual accepted connection admission. Rejection drops only this original
    /// descriptor. Unix UID/GID checks use the shared kernel credential checker.
    pub fn admit(
        &mut self,
        accepted: AcceptedConnection,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Error> {
        let peer = accepted.peer();
        let allowed = match peer {
            PeerAddress::Tcp(addr) => self.options.access.allows(addr.ip()),
            PeerAddress::Unix => self.unix.allows(accepted.connection())?,
        };
        if !allowed || self.stopping || self.closed {
            drop(accepted);
            observe(Event::Rejected(peer));
            return Ok(());
        }
        let Some(row) = self.jobs.iter().position(Option::is_none) else {
            drop(accepted);
            return Err(Fault::Capacity.into());
        };
        let sample = match self.handlers.clock.sample() {
            Ok(sample) => sample,
            Err(error) => {
                drop(accepted);
                self.close_all();
                return Err(Error::Clock(error));
            }
        };
        let us = u64::try_from(self.limits.lifetime.as_micros()).map_err(|_| Fault::Overflow)?;
        let until = sample
            .now
            .as_micros()
            .checked_add(us)
            .ok_or(Fault::Overflow)?;
        let hard = Instant::now()
            .checked_add(self.limits.lifetime)
            .ok_or(Fault::Overflow)?;
        let logical = match Deadline::at(
            self.handlers.clock.clone(),
            gnunet_types::AbsoluteTime::from_micros(until),
        ) {
            Ok(timer) => timer,
            Err(error) => {
                drop(accepted);
                self.close_all();
                return Err(Error::Clock(error));
            }
        };
        let (connection, _, diagnostics) = accepted.into_parts();
        for diagnostic in diagnostics {
            observe(Event::Socket(SocketEvent::Diagnostic(diagnostic)));
        }
        let handlers = self.handlers;
        let policy = self.policy;
        let limits = self.limits;
        let future = Box::pin(connection_job(
            connection, handlers, policy, limits, until, hard, logical,
        ));
        self.jobs[row] = Some(Job { future });
        Ok(())
    }
    /// Poll every original owner fairly. A clock sampling failure independently
    /// drops ALL physical HTTP/native MQ owners before returning that same error.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        until: Option<Instant>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        if self.closed {
            return Poll::Ready(Ok(Progress::Stopped));
        }
        if let Err(error) = self.handlers.clock.sample() {
            self.close_all();
            return Poll::Ready(Err(Error::Clock(error)));
        }
        if let Some(target) = until {
            if self.alarm_at != Some(target) {
                self.alarm = Some(Box::pin(tokio::time::sleep_until(target)));
                self.alarm_at = Some(target);
            }
            if self
                .alarm
                .as_mut()
                .is_some_and(|timer| timer.as_mut().poll(cx).is_ready())
            {
                return Poll::Ready(Ok(Progress::WaitDeadline));
            }
        } else {
            self.alarm = None;
            self.alarm_at = None;
        }
        let mut activity = false;
        let count = self.jobs.len();
        for offset in 0..count {
            let row = (self.cursor + offset) % count;
            let ready =
                self.jobs[row]
                    .as_mut()
                    .and_then(|job| match job.future.as_mut().poll(cx) {
                        Poll::Ready(report) => Some(report),
                        Poll::Pending => None,
                    });
            if let Some(report) = ready {
                self.jobs[row] = None;
                self.accept.client_closed();
                let clock_failure = report.failure.as_ref().and_then(Error::clock_failure);
                observe(Event::Closed(report));
                if let Some(error) = clock_failure {
                    self.close_all();
                    return Poll::Ready(Err(Error::Clock(error)));
                }
                activity = true;
            }
        }
        self.cursor = (self.cursor + 1) % count;
        if self.stopping && self.jobs.iter().all(Option::is_none) {
            self.closed = true;
            return Poll::Ready(Ok(Progress::Stopped));
        }
        if !self.stopping && self.accept.ready() && self.jobs.iter().any(Option::is_none) {
            for listener in listeners {
                match listener.poll_canonical_connection(cx) {
                    Poll::Ready(Ok(accepted)) => {
                        if let Err(error) = self.admit(accepted, observe) {
                            return Poll::Ready(Err(error));
                        }
                        activity = true;
                        break;
                    }
                    Poll::Ready(Err(error)) => {
                        observe(Event::Socket(self.accept.failed(error)));
                        activity = true;
                        break;
                    }
                    Poll::Pending => {}
                }
            }
        }
        if activity {
            Poll::Ready(Ok(Progress::Activity))
        } else {
            Poll::Pending
        }
    }
    /// Drive without replacing any cursor if this observation future is canceled.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        until: Option<Instant>,
        mut observe: impl FnMut(Event),
    ) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll(cx, listeners, until, &mut observe)).await
    }
    /// Stop accepting. Soft keeps only original jobs; Immediate drops them now.
    pub fn request_shutdown(&mut self, mode: ShutdownMode) {
        self.stopping = true;
        if mode == ShutdownMode::Immediate {
            self.close_all();
        }
    }
    /// Clock-independent physical cancellation. Return the number of original jobs
    /// dropped; exposed native mutations may still have committed remotely.
    pub fn close_all(&mut self) -> usize {
        let mut count = 0;
        for job in &mut self.jobs {
            if job.take().is_some() {
                count += 1;
            }
        }
        self.closed = true;
        self.stopping = true;
        self.alarm = None;
        self.alarm_at = None;
        count
    }
}
async fn connection_job<I: gnunet_dns::Idna>(
    mut connection: Connection,
    handlers: &Handlers<'_, I>,
    policy: &Policy,
    limits: Limits,
    until: u64,
    hard: Instant,
    logical: Deadline,
) -> Report {
    let mut native = Box::pin(tokio::time::sleep_until(hard));
    let mut logical = Box::pin(logical);
    let mut written = 0;
    let mut continue_written = 0;
    let mut status = None;
    let mut service_status = None;
    let mut original = None;
    let result = {
        let work = async {
            let mut input = bytes(limits.framing.wire_bytes)?;
            let mut used = 0;
            let mut path = bytes(limits.framing.target_bytes)?;
            let mut preflight = false;
            let mut rejection = None;
            let mut rejected_cause = None;
            let mut header_response = None;
            let mut origin = None;
            let (owned, endpoint, allow, origin) = loop {
                if !preflight {
                    match RequestHead::parse(&input[..used], limits.framing) {
                        Ok(head) => {
                            if !policy.authorization.allows(head.headers())? {
                                rejection = Some(401);
                                break (None, None, None, None);
                            }
                            origin = matched_origin(head.headers(), policy)?;
                            if head.expectation() == Expectation::Unsupported {
                                rejection = Some(417);
                                rejected_cause = Some(Error::Core(Fault::Unsupported));
                                break (None, None, None, origin);
                            }
                            match route::resolve_head(&head, &mut path)? {
                                Resolution::Found(route) => {
                                    if let Endpoint::Options(family) = route.endpoint() {
                                        let response = match handlers.options(family) {
                                            Ok(response) => response,
                                            Err(error) => {
                                                let response = error_response(
                                                    &error,
                                                    Some(route.endpoint()),
                                                    handlers.limits.output_bytes,
                                                )?;
                                                rejected_cause = Some(error);
                                                response
                                            }
                                        };
                                        header_response = Some(response);
                                        break (
                                            None,
                                            Some(route.endpoint()),
                                            Some(allow_methods(family)),
                                            origin,
                                        );
                                    }
                                }
                                Resolution::NotFound => {
                                    break (None, None, Some(b"404".as_slice()), origin);
                                }
                                Resolution::MethodNotAllowed(family) => {
                                    break (None, None, Some(allow_methods(family)), origin);
                                }
                            }
                            // Header admission happens once. No body byte was
                            // already received, and the original framing says
                            // actual content will follow on HTTP/1.1.
                            let send_continue =
                                head.continue_expected() && used == head.header_len();
                            preflight = true;
                            if send_continue {
                                write_continue(
                                    &mut connection,
                                    limits,
                                    hard,
                                    &mut continue_written,
                                )
                                .await?;
                            }
                        }
                        Err(Fault::Truncated) => {}
                        Err(Fault::TooLarge | Fault::Capacity) => {
                            rejection = Some(413);
                            rejected_cause = Some(Error::Core(Fault::TooLarge));
                            break (None, None, None, None);
                        }
                        Err(error) => return Err(Error::Core(error)),
                    }
                }
                if preflight {
                    match Request::parse(&input[..used], limits.framing) {
                        Ok(request) => {
                            // Exactly the same method/target/header parser and
                            // route resolver are used after the body completes.
                            let Resolution::Found(route) = route::resolve(&request, &mut path)?
                            else {
                                return Err(Fault::Conflict.into());
                            };
                            let endpoint = route.endpoint();
                            let mut body = bytes(request.body().len())?;
                            request.body().decode(&mut body)?;
                            let mut owned = OwnedRequest::new(route, &body, handlers.limits.bytes)?
                                .with_headers(&request, handlers.limits.bytes)?;
                            if policy.authorization.expected.is_some() {
                                owned.authorization = None;
                            }
                            break (
                                Some(owned),
                                Some(endpoint),
                                match endpoint {
                                    Endpoint::Options(family) => Some(allow_methods(family)),
                                    _ => None,
                                },
                                origin,
                            );
                        }
                        Err(Fault::Truncated) => {}
                        Err(error) => return Err(Error::Core(error)),
                    }
                }
                if used == input.len() {
                    return Err(Fault::TooLarge.into());
                }
                let end = (used + limits.io_bytes).min(input.len());
                let n = poll_fn(|cx| {
                    let mut buf = ReadBuf::new(&mut input[used..end]);
                    match Pin::new(&mut connection).poll_read(cx, &mut buf) {
                        Poll::Ready(Ok(())) => {
                            Poll::Ready(Ok::<usize, std::io::Error>(buf.filled().len()))
                        }
                        Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                        Poll::Pending => Poll::Pending,
                    }
                })
                .await?;
                if n == 0 {
                    return Err(Fault::Closed.into());
                }
                used += n;
            };
            // Erase headers/auth/body before awaiting native service completion.
            input.zeroize();
            let unauthorized = rejection == Some(401);
            let mut failure = rejected_cause;
            let response = if let Some(response) = header_response {
                response
            } else if let Some(owned) = owned {
                let mut backend = Box::pin(handlers.process(owned, until, hard));
                let mut discard = [0u8; 1];
                let mut drained = 0usize;
                let mut read_ended = false;
                let result = poll_fn(|cx| {
                    if let Poll::Ready(result) = backend.as_mut().poll(cx) {
                        return Poll::Ready(result);
                    }
                    if read_ended {
                        return Poll::Pending;
                    }
                    let mut buf = ReadBuf::new(&mut discard);
                    match Pin::new(&mut connection).poll_read(cx, &mut buf) {
                        Poll::Ready(Ok(())) if buf.filled().is_empty() => {
                            // FIN ends only the peer's write direction. A valid
                            // HTTP client may still read the actual response.
                            read_ended = true;
                            Poll::Pending
                        }
                        Poll::Ready(Ok(())) => {
                            drained += 1;
                            if drained > limits.framing.wire_bytes {
                                return Poll::Ready(Err(Fault::TooLarge.into()));
                            }
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                        Poll::Ready(Err(error)) => Poll::Ready(Err(Error::Io(error))),
                        Poll::Pending => Poll::Pending,
                    }
                })
                .await;
                drop(backend);
                match result {
                    Ok(response) => response,
                    Err(error) if error.clock_failure().is_some() => return Err(error),
                    Err(error) => {
                        // Keep an actual consumed word even if the bounded
                        // error representation itself cannot be constructed.
                        service_status = error.service_status();
                        let response =
                            error_response(&error, endpoint, handlers.limits.output_bytes)?;
                        failure = Some(error);
                        response
                    }
                }
            } else if let Some(status) = rejection {
                Response::empty(status)
            } else {
                if allow == Some(b"501") {
                    failure = Some(Error::Capability);
                    Response::empty(501)
                } else {
                    Response::empty(if allow == Some(b"404") { 404 } else { 405 })
                }
            };
            status = Some(response.status);
            service_status = response.service_status;
            original = failure;
            let mut headers = Vec::new();
            headers.try_reserve_exact(15).map_err(|_| Fault::Capacity)?;
            if unauthorized {
                headers.push(Header {
                    name: b"WWW-Authenticate",
                    value: b"Basic realm=\"gnunet\"",
                });
            }
            if let Some(allow) = allow.filter(|value| *value != b"404" && *value != b"501") {
                headers.push(Header {
                    name: b"Allow",
                    value: allow,
                });
                if response.status == 200 && matches!(endpoint, Some(Endpoint::Options(_))) {
                    headers.push(Header {
                        name: b"Access-Control-Allow-Methods",
                        value: allow,
                    });
                }
            }
            if policy.cors.varies() {
                headers.push(Header {
                    name: b"Vary",
                    value: b"Origin",
                });
            }
            if let Some(origin) = &origin {
                headers.push(Header {
                    name: b"Access-Control-Allow-Origin",
                    value: origin,
                });
                if policy.cors.credentials() {
                    headers.push(Header {
                        name: b"Access-Control-Allow-Credentials",
                        value: b"true",
                    });
                }
                if let Some(allowed) = policy.cors.allow_headers() {
                    headers.push(Header {
                        name: b"Access-Control-Allow-Headers",
                        value: allowed,
                    });
                }
            }
            for header in &response.headers {
                headers.push(Header {
                    name: header.name,
                    value: &header.value,
                });
            }
            let framed = http::Response {
                status: response.status,
                body: &response.body,
                content_type: response.content_type,
                head_only: false,
                headers: &headers,
            };
            let mut output = bytes(framed.encoded_len()?)?;
            framed.encode(&mut output)?;
            let send_at = Instant::now()
                .checked_add(limits.send_lifetime)
                .ok_or(Fault::Overflow)?;
            let mut send = Box::pin(tokio::time::sleep_until(send_at));
            while written < output.len() {
                let end = (written + limits.io_bytes).min(output.len());
                let n = poll_fn(|cx| {
                    if send.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Err(Error::Deadline));
                    }
                    Pin::new(&mut connection)
                        .poll_write(cx, &output[written..end])
                        .map_err(Error::Io)
                })
                .await?;
                if n == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "original HTTP write returned zero",
                    )
                    .into());
                }
                written += n;
            }
            Ok::<(), Error>(())
        };
        let mut work = Box::pin(work);
        poll_fn(|cx| {
            if native.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(Error::Deadline));
            }
            match logical.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => return Poll::Ready(Err(Error::Deadline)),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(Error::Clock(error))),
                Poll::Pending => {}
            }
            work.as_mut().poll(cx)
        })
        .await
    };
    drop(connection);
    service_status =
        service_status.or_else(|| result.as_ref().err().and_then(Error::service_status));
    Report {
        status,
        written,
        continue_written,
        service_status,
        failure: result.err().or(original),
    }
}
async fn write_continue(
    connection: &mut Connection,
    limits: Limits,
    hard: Instant,
    written: &mut usize,
) -> Result<(), Error> {
    const CONTINUE: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";
    let send_at = Instant::now()
        .checked_add(limits.send_lifetime)
        .ok_or(Fault::Overflow)?
        .min(hard);
    let mut send = Box::pin(tokio::time::sleep_until(send_at));
    while *written < CONTINUE.len() {
        let end = (*written + limits.io_bytes).min(CONTINUE.len());
        let n = poll_fn(|cx| {
            if Instant::now() >= send_at || send.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(Error::Deadline));
            }
            Pin::new(&mut *connection)
                .poll_write(cx, &CONTINUE[*written..end])
                .map_err(Error::Io)
        })
        .await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "original HTTP100 write returned zero",
            )
            .into());
        }
        *written += n;
    }
    Ok(())
}
fn matched_origin(
    headers: http::Headers<'_>,
    policy: &Policy,
) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
    let mut origin = None;
    for field in headers {
        let field = field?;
        if field.name.eq_ignore_ascii_case(b"origin") {
            if origin.is_some() {
                return Err(Fault::Conflict.into());
            }
            origin = Some(field.value);
        }
    }
    match origin {
        Some(actual) => policy.cors.matched(actual),
        None => Ok(None),
    }
}
fn allow_methods(family: Family) -> &'static [u8] {
    match family {
        Family::Identity => b"GET, POST, PUT, DELETE, OPTIONS",
        Family::Namestore => b"GET, POST, PUT, DELETE, OPTIONS",
        Family::Reclaim => b"GET, POST, DELETE, OPTIONS",
        Family::Copying => b"GET, OPTIONS",
        Family::Config => b"GET, POST, OPTIONS",
        Family::Gns => b"GET, OPTIONS",
        Family::Openid => b"GET, POST, OPTIONS",
    }
}
pub(crate) fn error_response(
    error: &Error,
    endpoint: Option<Endpoint>,
    cap: usize,
) -> Result<Response, Error> {
    if let Error::ConsumeReply { raw, original } = error {
        let mut response = error_response(original, endpoint, cap)?;
        response.service_status = Some(i64::from(*raw));
        return Ok(response);
    }
    if let Error::OAuth {
        status,
        error,
        description,
        challenge,
        service_status,
    } = error
    {
        let mut json = Json::new(cap)?;
        json.raw(b"{\"error\":")?;
        json.string(error.as_bytes())?;
        json.raw(b",\"error_description\":")?;
        json.string(description.as_bytes())?;
        json.raw(b"}")?;
        let mut response = Response::json(json.bytes);
        response.status = *status;
        response.service_status = *service_status;
        // A challenge is selected by its actual flow owner, then constrained
        // to that endpoint. An unrelated/global 401 never acquires one here.
        let challenge = match (challenge, endpoint, *status) {
            (Some(crate::OAuthChallenge::ClientBasic), Some(Endpoint::Token), 401) => {
                Some(b"Basic".as_slice())
            }
            (Some(crate::OAuthChallenge::ResourceBearer), Some(Endpoint::Userinfo), 401) => {
                Some(b"Bearer".as_slice())
            }
            _ => None,
        };
        if let Some(challenge) = challenge {
            response = response.header(b"WWW-Authenticate", challenge)?;
        }
        return response
            .header(b"Cache-Control", b"no-store")?
            .header(b"Pragma", b"no-cache");
    }
    let (status, code, hint) = match error {
        Error::Service(200) => (404, 200, "Ego not found"),
        Error::Service(201) => (409, 201, "Identifier already in use"),
        Error::Service(202) => (500, 202, "The given ego is invalid or malformed."),
        Error::Service(5002) => (404, 5002, "Zone not found"),
        Error::Service(5003) => (404, 5003, "Record not found"),
        Error::Service(5005) => (404, 5005, "Zone empty"),
        Error::Service(5007) => (400, 5007, "No records given"),
        Error::Service(5008) => (400, 5008, "Record data invalid"),
        Error::Service(5009) => (400, 5009, "No label given"),
        Error::Service(5010) => (404, 5010, "No results"),
        Error::Service(5011) => (409, 5011, "Record exists"),
        Error::Service(5015) => (400, 5015, "Label invalid"),
        Error::Service(code) => (500, *code, "Service error"),
        Error::Core(Fault::Capacity | Fault::TooLarge) => (413, 1, "Resource limit"),
        Error::Core(Fault::Malformed | Fault::InvalidInput | Fault::Conflict) => {
            (400, 1, "Invalid request")
        }
        Error::GnsNotFound => (404, 1, "Name is not in GNS"),
        Error::Deadline if endpoint == Some(Endpoint::GnsGet) => (408, 1, "GNS query timed out"),
        Error::Deadline => (504, 1, "Original deadline expired"),
        Error::Status(_) => (400, 1, "Service operation failed"),
        Error::Consume { cause, .. } => match cause {
            crate::ConsumeFailure::Denied => (403, 1, "Ticket authorization was denied"),
            crate::ConsumeFailure::Service => (502, 1, "Ticket consumption provider failed"),
            crate::ConsumeFailure::Unknown => (502, 1, "Unrecognized ticket consumption status"),
            crate::ConsumeFailure::IssuerMismatch => (502, 1, "Ticket consumption issuer mismatch"),
        },
        Error::Core(Fault::Unsupported) => (400, 1, "Unsupported input type"),
        Error::Capability => (501, 1, "Required capability is not connected"),
        _ => (502, 101, "Original service operation failed"),
    };
    let reclaim = endpoint.is_some_and(|e| {
        matches!(
            e,
            Endpoint::Attributes
                | Endpoint::AttributeStore
                | Endpoint::AttributeDelete
                | Endpoint::Credentials
                | Endpoint::CredentialStore
                | Endpoint::CredentialDelete
                | Endpoint::Tickets
                | Endpoint::Revoke
                | Endpoint::Consume
        )
    });
    let mut json = Json::new(cap)?;
    json.raw(b"{\"error\":")?;
    json.string(hint.as_bytes())?;
    if !reclaim && endpoint != Some(Endpoint::GnsGet) {
        json.raw(b",\"error_code\":")?;
        json.number(u64::from(code))?;
    }
    json.raw(b"}")?;
    let response = Response {
        status,
        body: json.bytes,
        content_type: b"application/json",
        service_status: error.service_status(),
        headers: Vec::new(),
    };
    if matches!(
        endpoint,
        Some(Endpoint::Consume | Endpoint::Userinfo | Endpoint::Token)
    ) {
        response
            .header(b"Cache-Control", b"no-store")?
            .header(b"Pragma", b"no-cache")
    } else {
        Ok(response)
    }
}
pub(crate) fn decode_basic(input: &[u8], out: &mut [u8]) -> Option<usize> {
    if !input.len().is_multiple_of(4) {
        return None;
    }
    let padding = input.iter().rev().take_while(|b| **b == b'=').count();
    if padding > 2 {
        return None;
    }
    let data = input.len().checked_sub(padding)?;
    let mut bits = 0u32;
    let mut nbits = 0;
    let mut at = 0;
    for b in &input[..data] {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(v);
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            *out.get_mut(at)? = (bits >> nbits) as u8;
            at += 1;
        }
        bits &= (1 << nbits) - 1;
    }
    if bits != 0 || nbits != ((padding * 2) as u32) {
        return None;
    }
    Some(at)
}
