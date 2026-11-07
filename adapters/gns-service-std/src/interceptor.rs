//! Ordinary DNS PRE_RESOLUTION callbacks bound to this same GNS Manager.
//! No UDP listener, self-RPC, worker, second resolver or replacement receipt.
use crate::{Bounds, Manager, Provider, QueryId};
use gnunet_config::Configuration;
use gnunet_dns_client_host as dns;
use gnunet_gns::{Lookup, Policy, ZoneKey};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::{AbsoluteTime, Error as Fault};
use std::{
    error::Error as StdError,
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
mod packet;
pub use dns::{Cause as SourceCause, Progress as SourceProgress};

/// Independent finite callback, packet and actual source queue budgets.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Original callbacks, including queued output and retiring GNS operations.
    pub requests: usize,
    /// Maximum DNS payload;16 further bytes belong to the native DNS IPC frame.
    pub packet_bytes: usize,
    /// Maximum parsed/projected records for one packet.
    pub records: usize,
    /// Maximum actual GNS value/header bytes considered for one response.
    pub record_bytes: usize,
    /// Maximum temporary shared DNS parser/name arena.
    pub arena_bytes: usize,
    /// Maximum shared DNS reader work per complete packet.
    pub work: usize,
    /// Aggregate immutable DNS-client output bytes.
    pub source_bytes: usize,
    /// One original callback lifetime, never renewed when GNS gains capacity.
    pub timeout: Duration,
    /// Original INIT and partial-frame lifetime.
    pub input_timeout: Duration,
    /// Existing DNS client's original finite drop drain.
    pub drain_grace: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            requests: 64,
            packet_bytes: 65507,
            records: 2048,
            record_bytes: 64512,
            arena_bytes: 2 * 1024 * 1024,
            work: 8 * 1024 * 1024,
            source_bytes: 4 * 1024 * 1024,
            timeout: Duration::from_secs(60),
            input_timeout: Duration::from_secs(10),
            drain_grace: Duration::from_secs(2),
        }
    }
}
impl Limits {
    fn packet(self) -> packet::Limits {
        packet::Limits {
            packet_bytes: self.packet_bytes,
            records: self.records,
            record_bytes: self.record_bytes,
            arena_bytes: self.arena_bytes,
            work: self.work,
        }
    }
    fn validate(self) -> Result<(), Fault> {
        self.packet().validate()?;
        if self.requests == 0
            || self.requests > 4096
            || self.packet_bytes > 65519
            || self.source_bytes < 16
            || self.source_bytes > 64 * 1024 * 1024
        {
            return Err(Fault::InvalidInput);
        }
        for value in [self.timeout, self.input_timeout, self.drain_grace] {
            if value.is_zero()
                || u64::try_from(value.as_micros()).is_err()
                || Instant::now().checked_add(value).is_none()
            {
                return Err(Fault::InvalidInput);
            }
        }
        Ok(())
    }
}
/// Actual original interceptor errors, without packet/name/payload diagnostics.
#[derive(Debug)]
pub enum Error {
    /// Original native CLIENT configuration/channel failure.
    Source(dns::Error),
    /// Original local capacity/protocol/clock failure.
    Protocol(Fault),
    /// Selected administrator namespace mapping is invalid; never DNS fallback.
    Mapping(Fault),
    /// Original DNS response conversion refusal.
    Response(Fault),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(e) => e.fmt(f),
            Self::Protocol(e) => write!(f, "GNS interception: {e}"),
            Self::Mapping(e) => write!(f, "GNS interception configured namespace: {e}"),
            Self::Response(e) => write!(f, "GNS interception DNS projection: {e}"),
        }
    }
}
impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(match self {
            Self::Source(e) => e as _,
            Self::Protocol(e) | Self::Mapping(e) | Self::Response(e) => e as _,
        })
    }
}
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self::Protocol(e)
    }
}
/// Local reply admission facts, independent of whole-write or IP delivery.
#[derive(Clone, Copy, Debug)]
pub enum Action {
    /// Preserve the DNS service's original packet and ordinary resolver path.
    Forward,
    /// Explicit original callback drop.
    Drop,
    /// Actual GNS-result projection, with its real bounded packing observations.
    Answer {
        /// Actual DNS return code.
        rcode: u8,
        /// Original projection did not fit the selected response bound.
        truncated: bool,
        /// GNS values without a DNS representation.
        omitted: usize,
    },
}
/// One original observation. Sources and all owned causes are transferred once.
pub enum Event<'d> {
    /// Actual original DNS CLIENT event, including full-write, loss and retry.
    Source(SourceProgress<'d>),
    /// A real callback was retained within its original finite lifetime.
    Received(dns::Request<'d>),
    /// The same Manager admitted the original explicit-zone lookup.
    Lookup(dns::Request<'d>),
    /// A response was admitted to the actual original DNS callback queue.
    Admitted {
        /// Original physical-source callback.
        request: dns::Request<'d>,
        /// Actual selected decision.
        action: Action,
    },
    /// Original callback and GNS cleanup ownership have both retired.
    Retired(dns::Request<'d>),
    /// Original failure; an intentional forwarding decision may still be made.
    Failed {
        /// Original callback if the error belongs to one.
        request: Option<dns::Request<'d>>,
        /// Actual retained cause.
        error: Error,
    },
    /// Actual DNS source closed and every original Manager query was taken.
    Stopped,
}
struct Route {
    zone: ZoneKey,
    name: String,
}
enum Decision {
    Forward,
    Drop,
    Answer(packet::Reply),
}
struct Row<'d, 'q> {
    token: dns::Request<'d>,
    live: bool,
    bounds: Bounds,
    question: Option<packet::Question>,
    route: Option<Route>,
    query: Option<QueryId<'q>>,
    decision: Option<Decision>,
    admitted: bool,
    cancelled: bool,
    cancel_error: Option<Fault>,
}
/// Bounded caller-driven composition; all lookup work belongs to the same Manager.
pub struct Interceptor<'d, 'q> {
    client: dns::Client<'d>,
    configuration: Configuration,
    limits: Limits,
    rows: Vec<Row<'d, 'q>>,
    cursor: usize,
    read_first: bool,
    stopping: bool,
    closed: bool,
    stopped: bool,
    pending: Option<SourceProgress<'d>>,
    reconnect_error: Option<dns::Error>,
    retry: Option<Pin<Box<Sleep>>>,
}
impl<'d, 'q> Interceptor<'d, 'q> {
    /// Configure the actual PRE_RESOLUTION CLIENT; construction performs no IO.
    pub fn new(
        domain: &'d dns::Instance,
        source: dns::EndpointSource,
        clock: &Arc<dyn RuntimeClock>,
        configuration: Configuration,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if !Arc::ptr_eq(clock, &source.clock()) {
            return Err(Fault::Conflict.into());
        }
        let client = dns::Client::new(
            domain,
            source,
            dns::ipc::PRE_RESOLUTION,
            dns::Limits {
                requests: limits.requests,
                frame_bytes: limits.packet_bytes + 16,
                source_bytes: limits.source_bytes,
                io_slice_bytes: limits.packet_bytes + 16,
                request_timeout: limits.timeout,
                input_timeout: limits.input_timeout,
                drain_grace: limits.drain_grace,
            },
        )
        .map_err(Error::Source)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(limits.requests)
            .map_err(|_| Fault::Capacity)?;
        Ok(Self {
            client,
            configuration,
            limits,
            rows,
            cursor: 0,
            read_first: false,
            stopping: false,
            closed: false,
            stopped: false,
            pending: None,
            reconnect_error: None,
            retry: None,
        })
    }
    /// Actual complete local retirement, not merely a requested stop.
    pub fn is_stopped(&self) -> bool {
        self.closed && self.rows.is_empty() && self.pending.is_none()
    }
    fn cancel<P: Provider>(row: &mut Row<'d, 'q>, manager: &mut Manager<'q, P>) {
        if !row.cancelled
            && let Some(query) = row.query
        {
            row.cancelled = true;
            if let Err(e) = manager.cancel(query) {
                row.cancel_error.get_or_insert(e);
            }
        }
    }
    fn invalidate<P: Provider>(&mut self, manager: &mut Manager<'q, P>) {
        for row in &mut self.rows {
            row.live = false;
            row.decision = None;
            row.route = None;
            row.question = None;
            Self::cancel(row, manager);
        }
    }
    /// Fence new work and cancel only original lookups. Soft drains admitted
    /// decisions; immediate physically closes this MQ before discarding suffixes.
    pub fn begin_close<P: Provider>(&mut self, manager: &mut Manager<'q, P>, immediate: bool) {
        self.stopping = true;
        self.retry = None;
        for row in &mut self.rows {
            Self::cancel(row, manager);
            row.route = None;
            row.question = None;
            if !row.admitted && row.live {
                row.decision = Some(Decision::Drop);
            }
        }
        if immediate && !self.closed {
            let closed = self.client.close();
            // A prior explicit retirement already owns the real old epoch and
            // callback count. Escalation closes IO without overwriting it with
            // a second empty-source close observation.
            if self.pending.is_none() {
                self.pending = Some(closed);
            }
            self.closed = true;
            self.invalidate(manager);
        }
    }
    fn source<P: Provider>(
        &mut self,
        progress: SourceProgress<'d>,
        manager: &mut Manager<'q, P>,
    ) -> Event<'d> {
        match &progress {
            SourceProgress::Written(token) => {
                if let Some(row) = self.rows.iter_mut().find(|r| r.token == *token) {
                    row.live = false;
                }
            }
            SourceProgress::Dropping(token) => {
                if let Some(row) = self.rows.iter_mut().find(|r| r.token == *token) {
                    row.admitted = true;
                    row.decision = None;
                    row.route = None;
                    row.question = None;
                    Self::cancel(row, manager);
                }
            }
            SourceProgress::Lost { .. } => {
                self.invalidate(manager);
                if self.stopping {
                    let _close = self.client.close();
                    self.closed = true;
                } else if let Err(error) = self.client.reconnect() {
                    self.reconnect_error = Some(error);
                }
            }
            SourceProgress::Closed => {
                self.closed = true;
                self.invalidate(manager);
            }
            SourceProgress::Unavailable(_) => {
                self.retry = Some(Box::pin(tokio::time::sleep_until(
                    Instant::now() + Duration::from_secs(1),
                )));
            }
            _ => {}
        }
        Event::Source(progress)
    }
    /// Original DNS native deadlines precede any canonical clock capability use.
    pub fn poll_native_guard<P: Provider>(
        &mut self,
        cx: &mut Context<'_>,
        manager: &mut Manager<'q, P>,
    ) -> Option<Event<'d>> {
        if let Some(progress) = self.pending.take() {
            return Some(self.source(progress, manager));
        }
        self.client
            .poll_native_guard(cx)
            .map(|p| self.source(p, manager))
    }
    fn receive(&mut self, n: dns::Notification<'d>, now: AbsoluteTime) -> Result<Event<'d>, Error> {
        let token = n.request();
        let bounds = Bounds::new(AbsoluteTime::from_micros(n.expires()), n.hard())?;
        if self.rows.len() == self.limits.requests {
            return Err(Fault::Capacity.into());
        }
        let mut row = Row {
            token,
            live: true,
            bounds,
            question: None,
            route: None,
            query: None,
            decision: None,
            admitted: false,
            cancelled: false,
            cancel_error: None,
        };
        let mut failure = None;
        if self.stopping {
            row.decision = Some(Decision::Drop);
        } else {
            let mut workspace = gnunet_idna::Workspace::new();
            let idna = gnunet_idna::Backend::new(
                &mut workspace,
                gnunet_idna::Limits::GNUNET,
                gnunet_idna::NativeProfile::Libunistring1_5Unicode18_0,
            );
            match packet::Question::parse(n.dns(), now.as_micros(), self.limits.packet(), &idna) {
                Err(_) => row.decision = Some(Decision::Forward),
                Ok(question) => match route(&self.configuration, question.name()) {
                    Ok(Some(route)) => {
                        row.question = Some(question);
                        row.route = Some(route);
                    }
                    Ok(None) => row.decision = Some(Decision::Forward),
                    Err(error) => {
                        row.decision = Some(Decision::Drop);
                        failure = Some(Error::Mapping(error));
                    }
                },
            }
        }
        self.rows.push(row);
        Ok(match failure {
            Some(error) => Event::Failed {
                request: Some(token),
                error,
            },
            None => Event::Received(token),
        })
    }
    fn rows<P: Provider>(
        &mut self,
        manager: &mut Manager<'q, P>,
        now: Option<AbsoluteTime>,
    ) -> Result<Option<Event<'d>>, Error> {
        for _ in 0..self.rows.len() {
            let i = self.cursor % self.rows.len();
            self.cursor = (i + 1) % self.rows.len();
            let row = &mut self.rows[i];
            if let Some(error) = row.cancel_error.take() {
                return Ok(Some(Event::Failed {
                    request: Some(row.token),
                    error: Error::Protocol(error),
                }));
            }
            let expired =
                Instant::now() >= row.bounds.hard() || now.is_some_and(|n| n >= row.bounds.until());
            if !row.live || self.stopping || expired {
                Self::cancel(row, manager);
                row.route = None;
                row.question = None;
                if !row.admitted && row.live {
                    row.decision = Some(Decision::Drop);
                }
            }
            if let Some(query) = row.query
                && (now.is_some() || row.cancelled || !row.live || self.stopping)
                && let Some(outcome) = manager.take_result(query)?
            {
                row.query = None;
                if row.live && !row.cancelled && !expired && !self.stopping {
                    let question = row.question.take().ok_or(Fault::Conflict)?;
                    let Some(now) = now else {
                        return Err(Fault::Conflict.into());
                    };
                    match question.reply(&outcome, now.as_micros(), self.limits.packet()) {
                        Ok(reply) => row.decision = Some(Decision::Answer(reply)),
                        Err(error) => {
                            row.decision = Some(Decision::Drop);
                            return Ok(Some(Event::Failed {
                                request: Some(row.token),
                                error: Error::Response(error),
                            }));
                        }
                    }
                }
            }
            if !row.live && row.query.is_none() {
                let token = row.token;
                self.rows.swap_remove(i);
                return Ok(Some(Event::Retired(token)));
            }
            let Some(now) = now else {
                continue;
            };
            if expired {
                continue;
            }
            if row.query.is_none()
                && row.decision.is_none()
                && let Some(route) = row.route.as_ref()
            {
                let question = row.question.as_ref().ok_or(Fault::Conflict)?;
                let kind = if question.kind() == 255 {
                    gnunet_gns::RecordType::ANY
                } else {
                    gnunet_gns::RecordType::new(u32::from(question.kind()))
                };
                match manager.lookup(
                    Lookup {
                        zone: route.zone,
                        name: &route.name,
                        record_type: kind,
                        policy: Policy::CacheThenRemote,
                        recursion_limit: 256,
                    },
                    row.bounds,
                    now,
                ) {
                    Ok(query) => {
                        row.query = Some(query);
                        row.route = None;
                        return Ok(Some(Event::Lookup(row.token)));
                    }
                    Err(Fault::WouldBlock) => {}
                    Err(error) => {
                        row.route = None;
                        row.question = None;
                        row.decision = Some(Decision::Drop);
                        return Ok(Some(Event::Failed {
                            request: Some(row.token),
                            error: Error::Protocol(error),
                        }));
                    }
                }
            }
            if row.admitted {
                continue;
            }
            let Some(decision) = row.decision.as_ref() else {
                continue;
            };
            let (wire, action) = match decision {
                Decision::Forward => (dns::ipc::Decision::Forward, Action::Forward),
                Decision::Drop => (dns::ipc::Decision::Drop, Action::Drop),
                Decision::Answer(reply) => (
                    dns::ipc::Decision::Answer(&reply.bytes),
                    Action::Answer {
                        rcode: reply.rcode,
                        truncated: reply.truncated,
                        omitted: reply.omitted,
                    },
                ),
            };
            match self.client.reply(row.token, wire) {
                Ok(()) => {
                    row.admitted = true;
                    row.decision = None;
                    return Ok(Some(Event::Admitted {
                        request: row.token,
                        action,
                    }));
                }
                Err(dns::Error::Protocol(Fault::Capacity | Fault::WouldBlock)) => {}
                Err(error) => return Err(Error::Source(error)),
            }
        }
        Ok(None)
    }
    /// One fair original-source/business turn; Manager polling remains with Server.
    pub fn poll<P: Provider>(
        &mut self,
        cx: &mut Context<'_>,
        manager: &mut Manager<'q, P>,
        now: Option<AbsoluteTime>,
    ) -> Poll<Event<'d>> {
        if let Some(event) = self.poll_native_guard(cx, manager) {
            return Poll::Ready(event);
        }
        if let Some(error) = self.reconnect_error.take() {
            return Poll::Ready(Event::Failed {
                request: None,
                error: Error::Source(error),
            });
        }
        if self.stopping && !self.closed && self.rows.iter().all(|r| !r.live) {
            self.closed = true;
            let progress = self.client.close();
            return Poll::Ready(self.source(progress, manager));
        }
        if self.is_stopped() {
            if !self.stopped {
                self.stopped = true;
                return Poll::Ready(Event::Stopped);
            }
            return Poll::Pending;
        }
        self.read_first = !self.read_first;
        for offset in 0..2 {
            if (usize::from(self.read_first) + offset) % 2 == 0 {
                match self.rows(manager, now) {
                    Ok(Some(event)) => return Poll::Ready(event),
                    Ok(None) => {}
                    Err(error) => {
                        let progress = self.client.retire(SourceCause::Cancelled);
                        self.invalidate(manager);
                        self.pending = Some(progress);
                        return Poll::Ready(Event::Failed {
                            request: None,
                            error,
                        });
                    }
                }
            } else if now.is_some() && !self.closed {
                if let Some(retry) = self.retry.as_mut() {
                    if retry.as_mut().poll(cx).is_pending() {
                        continue;
                    }
                    self.retry = None;
                }
                match self.client.poll(cx, None) {
                    Poll::Pending => {}
                    Poll::Ready(Ok(SourceProgress::Request(n))) => {
                        match self.receive(n, now.unwrap_or(AbsoluteTime::from_micros(0))) {
                            Ok(event) => return Poll::Ready(event),
                            Err(error) => {
                                let progress = self.client.retire(SourceCause::Cancelled);
                                self.invalidate(manager);
                                self.pending = Some(progress);
                                return Poll::Ready(Event::Failed {
                                    request: None,
                                    error,
                                });
                            }
                        }
                    }
                    Poll::Ready(Ok(progress)) => {
                        return Poll::Ready(self.source(progress, manager));
                    }
                    Poll::Ready(Err(error)) => {
                        let progress = self.client.retire(SourceCause::Cancelled);
                        self.invalidate(manager);
                        self.pending = Some(progress);
                        return Poll::Ready(Event::Failed {
                            request: None,
                            error: Error::Source(error),
                        });
                    }
                }
            }
        }
        Poll::Pending
    }
}
fn route(configuration: &Configuration, name: &str) -> Result<Option<Route>, Fault> {
    let (relative, last) = name.rsplit_once('.').unwrap_or(("", name));
    if let Ok(zone) = ZoneKey::from_ztld(last) {
        return Ok(Some(Route {
            zone,
            name: if relative.is_empty() {
                "@".into()
            } else {
                relative.into()
            },
        }));
    }
    let mut offset = 0;
    loop {
        let suffix = &name[offset..];
        let mut key = Vec::new();
        key.try_reserve_exact(suffix.len() + 1)
            .map_err(|_| Fault::Capacity)?;
        key.push(b'.');
        key.extend_from_slice(suffix.as_bytes());
        if let Some(value) = configuration.get(b"gns", &key) {
            let zone =
                ZoneKey::from_ztld(std::str::from_utf8(value).map_err(|_| Fault::Malformed)?)?;
            let relative = if suffix.len() == name.len() {
                "@"
            } else {
                &name[..name.len() - suffix.len() - 1]
            };
            return Ok(Some(Route {
                zone,
                name: relative.to_owned(),
            }));
        }
        let Some(dot) = suffix.find('.') else {
            return Ok(None);
        };
        offset += dot + 1;
    }
}
