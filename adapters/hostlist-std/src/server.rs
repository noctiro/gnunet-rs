//! Public HTTP provider over shared canonical accepted streams and bounded Hyper.
use crate::{
    Error, Fault,
    gate::Gate,
    http::{Counted, Counters, HttpLimits, IoLease, WireReport},
    publication::View,
};
use bytes::Bytes;
use gnunet_service_runtime::{
    clock::RuntimeClock,
    service::{Listener, PeerAddress},
};
use http_body_util::Full;
use hyper::{
    Method, Request, Response,
    body::{Body, Incoming},
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use std::{
    cell::Cell,
    future::{Future, poll_fn},
    net::IpAddr,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{net::TcpListener, time::Instant};

/// HTTP provider source id; each accepted descriptor consumes a checked serial.
#[derive(Clone)]
pub struct HttpId {
    domain: Rc<()>,
    serial: u64,
}
impl PartialEq for HttpId {
    fn eq(&self, o: &Self) -> bool {
        Rc::ptr_eq(&self.domain, &o.domain) && self.serial == o.serial
    }
}
impl Eq for HttpId {}
impl std::fmt::Debug for HttpId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("HostlistHttp")
            .field(&Rc::as_ptr(&self.domain))
            .field(&self.serial)
            .finish()
    }
}
/// Actual provider observations, not remote receipt or peer authentication.
#[derive(Debug)]
pub enum HttpEvent {
    /// Actual accepted original HTTP source.
    Accepted {
        /// Original source id.
        id: HttpId,
        /// Kernel peer endpoint.
        peer: PeerAddress,
    },
    /// Actual request parsed and response prepared locally.
    Prepared {
        /// Original source id.
        id: HttpId,
        /// Actual local selected publication revision, if any.
        revision: Option<u64>,
        /// Local HTTP status.
        status: u16,
    },
    /// Actual original source dropped after native parser/IO outcome.
    Closed {
        /// Original source id.
        id: HttpId,
        /// Actual native byte counters.
        wire: WireReport,
        /// Original failure, if any.
        failure: Option<Error>,
    },
    /// Actual shared accepted-stream diagnostic.
    Socket(gnunet_service_runtime::accepted::SocketEvent),
}
type ConnectionFuture = Pin<Box<dyn Future<Output = Result<(), Error>>>>;
type PreparedResponse = Rc<Cell<Option<(Option<u64>, u16)>>>;
pub(crate) struct Options {
    pub limits: HttpLimits,
    pub connections: usize,
    pub per_ip: usize,
    pub lifetime: Duration,
}
struct Session {
    id: HttpId,
    ip: IpAddr,
    gate: Gate,
    lease: Rc<IoLease>,
    future: Option<ConnectionFuture>,
    counts: Arc<Counters>,
    prepared: PreparedResponse,
}
/// Bounded public HTTP owner. All connections are driven by the caller task;
/// Connection:close is explicit and no per-connection task is spawned.
pub(crate) struct Server {
    domain: Rc<()>,
    next: u64,
    listeners: Vec<TcpListener>,
    sessions: Vec<Session>,
    view: View,
    clock: Arc<dyn RuntimeClock>,
    limits: HttpLimits,
    connections: usize,
    per_ip: usize,
    lifetime: Duration,
    daemon_until: u64,
    daemon_hard: Instant,
    cursor: usize,
    closed: bool,
}
fn cors(builder: hyper::http::response::Builder) -> hyper::http::response::Builder {
    builder
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Methods", "GET, OPTIONS")
        .header("Access-Control-Max-Age", "86400")
        .header("Connection", "close")
}
fn response(status: u16, bytes: Bytes, json: bool) -> Result<Response<Full<Bytes>>, Error> {
    let builder = cors(Response::builder().status(status));
    let builder = if json {
        builder.header("Content-Type", "application/json")
    } else {
        builder.header("Content-Type", "application/octet-stream")
    };
    Ok(builder.body(Full::new(bytes))?)
}
async fn answer(
    mut request: Request<Incoming>,
    view: View,
    lease: Rc<IoLease>,
    prepared: PreparedResponse,
    clock: Arc<dyn RuntimeClock>,
) -> Result<Response<Full<Bytes>>, Error> {
    lease.check()?;
    if request.method() == Method::OPTIONS {
        prepared.set(Some((None, 200)));
        return response(200, Bytes::new(), false);
    }
    if request.method() != Method::GET {
        prepared.set(Some((None, 405)));
        return response(405, Bytes::new(), false);
    }
    let mut frames = 0usize;
    loop {
        let frame = poll_fn(|cx| Pin::new(request.body_mut()).poll_frame(cx)).await;
        let Some(frame) = frame else { break };
        let frame = frame?;
        frames += 1;
        if frames > 16 {
            return Err(Fault::Capacity.into());
        }
        if frame.data_ref().is_some_and(|bytes| !bytes.is_empty()) {
            prepared.set(Some((None, 400)));
            return response(400, Bytes::new(), false);
        }
        crate::gate::cooperate().await;
    }
    let now = clock.sample().map_err(Error::Clock)?.now.as_micros();
    let publication = view
        .borrow()
        .as_ref()
        .filter(|p| p.observed <= now && now < p.expires)
        .cloned()
        .ok_or(Fault::NotReady)?;
    lease.until.set(lease.until.get().min(publication.expires));
    lease.checked.set(publication.observed);
    if publication.expires != u64::MAX {
        let bound = Instant::now()
            .checked_add(Duration::from_micros(publication.expires - now))
            .ok_or(Fault::Overflow)?;
        lease.hard.set(lease.hard.get().min(bound));
    }
    let json = request
        .headers()
        .get_all(hyper::header::ACCEPT)
        .iter()
        .any(|value| value.as_bytes().eq_ignore_ascii_case(b"application/json"));
    let bytes = if json {
        publication.json
    } else {
        publication.binary
    };
    prepared.set(Some((Some(publication.revision), 200)));
    response(200, bytes, json)
}
impl Server {
    pub fn new(
        listeners: Vec<TcpListener>,
        view: View,
        clock: Arc<dyn RuntimeClock>,
        options: Options,
        daemon_bound: (u64, Instant),
    ) -> Result<Self, Error> {
        let Options {
            limits,
            connections,
            per_ip,
            lifetime,
        } = options;
        limits.validate()?;
        if connections == 0 || per_ip == 0 || per_ip > connections || lifetime.is_zero() {
            return Err(Fault::InvalidInput.into());
        }
        let mut sessions = Vec::new();
        sessions
            .try_reserve_exact(connections)
            .map_err(|_| Fault::Capacity)?;
        Ok(Self {
            domain: Rc::new(()),
            next: 0,
            listeners,
            sessions,
            view,
            clock,
            limits,
            connections,
            per_ip,
            lifetime,
            daemon_until: daemon_bound.0,
            daemon_hard: daemon_bound.1,
            cursor: 0,
            closed: false,
        })
    }
    pub fn listeners(&self) -> usize {
        self.listeners.len()
    }
    pub fn idle(&self) -> bool {
        self.sessions.is_empty()
    }
    pub fn stop_accepting(&mut self) {
        self.listeners.clear()
    }
    pub fn close(&mut self, observe: &mut impl FnMut(HttpEvent)) {
        self.closed = true;
        self.listeners.clear();
        for mut session in self.sessions.drain(..) {
            session.future = None;
            observe(HttpEvent::Closed {
                id: session.id,
                wire: session.counts.report(),
                failure: Some(Fault::Cancelled.into()),
            })
        }
    }
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(HttpEvent),
    ) -> Poll<Result<(), Error>> {
        if self.closed {
            return Poll::Pending;
        }
        // Every active original lease is polled, even before current publication
        // availability, so loss/expiry can release a held historical body charge.
        for offset in 0..self.sessions.len() {
            let index = (self.cursor + offset) % self.sessions.len();
            let session = &mut self.sessions[index];
            session.gate.until = session.gate.until.min(session.lease.until.get());
            session.gate.hard = session.gate.hard.min(session.lease.hard.get());
            let result = match session.gate.poll(cx) {
                Poll::Pending => continue,
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(_)) => match &mut session.future {
                    Some(future) => future.as_mut().poll(cx),
                    None => Poll::Ready(Err(Fault::Closed.into())),
                },
            };
            if let Some((revision, status)) = session.prepared.take() {
                observe(HttpEvent::Prepared {
                    id: session.id.clone(),
                    revision,
                    status,
                })
            }
            if let Poll::Ready(result) = result {
                let mut session = self.sessions.swap_remove(index);
                session.future = None;
                let wire = session.counts.report();
                observe(HttpEvent::Closed {
                    id: session.id,
                    wire,
                    failure: result.err(),
                });
                self.cursor = if self.sessions.is_empty() {
                    0
                } else {
                    index % self.sessions.len()
                };
                return Poll::Ready(Ok(()));
            }
        }
        if self.sessions.len() >= self.connections || self.view.borrow().is_none() {
            return Poll::Pending;
        }
        for listener in &self.listeners {
            let accepted_at = Instant::now();
            let accepted = match Listener::Tcp(listener).poll_canonical_connection(cx) {
                Poll::Pending => continue,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(Error::Accept(error))),
                Poll::Ready(Ok(accepted)) => accepted,
            };
            let (connection, peer, diagnostics) = accepted.into_parts();
            for diagnostic in diagnostics.into_iter() {
                observe(HttpEvent::Socket(
                    gnunet_service_runtime::accepted::SocketEvent::Diagnostic(diagnostic),
                ))
            }
            let ip = match peer {
                PeerAddress::Tcp(address) => address.ip(),
                PeerAddress::Unix => {
                    drop(connection);
                    return Poll::Ready(Err(Fault::InvalidInput.into()));
                }
            };
            if self.sessions.iter().filter(|s| s.ip == ip).count() >= self.per_ip {
                drop(connection);
                return Poll::Ready(Ok(()));
            }
            let next = self.next.checked_add(1).ok_or(Fault::Overflow)?;
            let id = HttpId {
                domain: self.domain.clone(),
                serial: next,
            };
            let now = self.clock.sample().map_err(Error::Clock)?.now.as_micros();
            let duration = u64::try_from(self.lifetime.as_micros()).map_err(|_| Fault::Overflow)?;
            let until = now
                .checked_add(duration)
                .filter(|n| *n < u64::MAX)
                .ok_or(Fault::Overflow)?
                .min(self.daemon_until);
            let mut gate = Gate::new(self.clock.clone(), until)?;
            gate.hard = gate
                .hard
                .min(
                    accepted_at
                        .checked_add(self.lifetime)
                        .ok_or(Fault::Overflow)?,
                )
                .min(self.daemon_hard);
            let lease = Rc::new(IoLease {
                clock: self.clock.clone(),
                until: Cell::new(until),
                hard: Cell::new(gate.hard),
                checked: Cell::new(0),
            });
            let counts = Arc::new(Counters::default());
            let io = TokioIo::new(Counted {
                inner: connection,
                lease: lease.clone(),
                counts: counts.clone(),
                maximum: self.limits.wire_bytes,
            });
            let prepared = Rc::new(Cell::new(None));
            let service_prepared = prepared.clone();
            let service_view = self.view.clone();
            let service_lease = lease.clone();
            let clock = self.clock.clone();
            let service = service_fn(move |request| {
                let view = service_view.clone();
                let lease = service_lease.clone();
                let prepared = service_prepared.clone();
                let clock = clock.clone();
                async move {
                    match answer(request, view, lease, prepared, clock).await {
                        Ok(response) => Ok::<_, Error>(response),
                        Err(error) => Err(error),
                    }
                }
            });
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .keep_alive(false)
                .max_headers(self.limits.headers)
                .max_buf_size(self.limits.header_bytes);
            let connection = builder.serve_connection(io, service);
            let future = Box::pin(async move { connection.await.map_err(Error::Http) });
            self.sessions.push(Session {
                id: id.clone(),
                ip,
                gate,
                lease,
                future: Some(future),
                counts,
                prepared,
            });
            self.next = next;
            observe(HttpEvent::Accepted { id, peer });
            return Poll::Ready(Ok(()));
        }
        Poll::Pending
    }
}
