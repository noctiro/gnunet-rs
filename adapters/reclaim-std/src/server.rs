//! Real accepted-MQ ownership and caller-driven original provider coordination.
use crate::{SystemProviders, gns, namestore as ns};
use gnunet_reclaim::{
    business::{
        self, Action, Completion, Effect, End, Exposure, Factory, Job, Output, Provider, Source,
    },
    ipc::{Iteration, Request},
};
use gnunet_service_runtime::{
    accepted::{AcceptState, AcceptedConnection},
    clock::ClockSubscription,
    framing::{Accounting, Budget, Class, Framed, Limits as FrameLimits, OwnedFrame, ReadStep},
    service::{Listener, PeerAddress, ShutdownMode},
};
use gnunet_types::Error as Fault;
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
use zeroize::Zeroizing;
mod backend;
mod lifecycle;
mod metrics;
pub use metrics::{METRIC_NAMES, Metrics};
mod types;
pub use types::*;
type GnsClient<'g> = gns::BoundedClient<'g, 1, { gns::MAX_NAME_BYTES }>;
#[derive(Clone, Copy, Eq, PartialEq)]
struct Tag {
    row: usize,
    serial: u64,
}
#[derive(Clone, Copy, Eq, PartialEq)]
struct Origin {
    client: u64,
    job: Tag,
    sequence: u64,
    rid: u32,
}
struct OutputSend {
    origin: Origin,
    token: Output,
    total: usize,
    sent: usize,
}
struct Peer {
    client: Client,
    io: Framed<Origin>,
    first: bool,
    first_until: Instant,
    input_until: Option<Instant>,
    read_first: bool,
    output: Option<OutputSend>,
}
struct Entry {
    tag: Tag,
    client: Option<Client>,
    rid: u32,
    iteration: Option<Iteration>,
    readonly: bool,
    stopped: bool,
    job: Job,
    hard: Instant,
    output_until: Option<Instant>,
}
struct Native<T> {
    tag: Tag,
    effect: Effect,
    source: Source,
    epoch: T,
    total: usize,
    sent: usize,
    cancelling: bool,
    retire_at: Option<Instant>,
    forced: bool,
}
struct Store<'n> {
    binding: Native<ns::Epoch<'n>>,
    operation: ns::Operation<'n>,
    known_code: Option<u32>,
}
struct Query<'g> {
    binding: Native<gns::Epoch<'g>>,
    query: gns::QueryId<'g>,
    // Same native read remains queued after genuine old-MQ retirement.
    reconnecting: bool,
    kind: business::LookupKind,
    started: Instant,
    callback_recorded: bool,
}
struct Scan<'n> {
    tag: Tag,
    effect: Effect,
    iterator: ns::ZoneIterator<'n>,
    source: Option<Source>,
    epoch: Option<ns::Epoch<'n>>,
    total: usize,
    sent: usize,
}
/// A bounded production RECLAIM SERVICE. Caller storage brands outlive it; a
/// single shared NAMESTORE MQ and a single existing GNS-client MQ serve all jobs.
/// One additional real NAMESTORE scan MQ exists only during its original scan.
pub struct Server<'n, 'g> {
    factory: Factory,
    limits: Limits,
    ports: Ports,
    providers: SystemProviders,
    peers: Vec<Option<Peer>>,
    jobs: Vec<Option<Entry>>,
    domain: Rc<Domain>,
    next_client: u64,
    next_job: u64,
    next_output: u64,
    ns_instance: &'n ns::Instance,
    ns: ns::Client<'n>,
    ns_limits: ns::Limits,
    ns_source: Option<(ns::Epoch<'n>, Source)>,
    ns_active: Option<Store<'n>>,
    ns_retry: Option<Instant>,
    gns: GnsClient<'g>,
    gns_source: Option<(gns::Epoch<'g>, Source)>,
    gns_active: Option<Query<'g>>,
    gns_retry: Option<Instant>,
    scan: Option<Scan<'n>>,
    writer: Option<Tag>,
    identity: Source,
    entropy: Source,
    credential: Source,
    accept: AcceptState,
    subscription: Box<dyn ClockSubscription>,
    revision: u64,
    last_now: u64,
    timer: Pin<Box<Sleep>>,
    class: usize,
    peer_cursor: usize,
    job_cursor: usize,
    listener_cursor: usize,
    shutdown: Option<ShutdownMode>,
    closed: bool,
    yield_due: bool,
    report: Report,
    metrics: Metrics,
}
impl Limits {
    fn framing(self) -> FrameLimits {
        FrameLimits {
            frame_bytes: self.frame_bytes,
            ordinary: Budget {
                frames: 1,
                bytes: self.frame_bytes,
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.io_slice_bytes,
        }
    }
    fn validate(self) -> Result<(), Fault> {
        self.framing().validate()?;
        if self.clients == 0
            || self.clients > 1024
            || self.operations == 0
            || self.operations > 1024
            || self.per_client == 0
            || self.per_client > self.operations
            || self.frame_bytes < 128
        {
            return Err(Fault::InvalidInput);
        }
        for d in [
            self.first_input,
            self.input_lifetime,
            self.output_lifetime,
            self.operation_lifetime,
            self.retirement_grace,
        ] {
            if d.is_zero()
                || Instant::now().checked_add(d).is_none()
                || d.as_micros() > u128::from(u64::MAX - 1)
            {
                return Err(Fault::Deadline);
            }
        }
        Ok(())
    }
}
impl<'n, 'g> Server<'n, 'g> {
    /// Construct actual bounded clients with explicit shared sources/clock and
    /// supplied real system provider owner. No socket or background task opens
    /// here; actual Connected callbacks authorize source bindings later.
    pub fn new(
        ns_instance: &'n ns::Instance,
        gns_instance: &'g mut gns::Instance,
        core: business::Limits,
        limits: Limits,
        ports: Ports,
        providers: SystemProviders,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if core.jobs != limits.operations
            || core.frame_bytes != limits.frame_bytes
            || core.sources < 6
            || !Arc::ptr_eq(&ports.clock, &ports.namestore.clock())
            || !Arc::ptr_eq(&ports.clock, &ports.gns.clock())
        {
            return Err(Fault::Conflict.into());
        }
        let factory = Factory::new(core)?;
        let identity = factory.bind(Provider::Identity)?;
        let entropy = factory.bind(Provider::Entropy)?;
        let credential = factory.bind(Provider::Credential)?;
        let ns_limits = ns::Limits {
            operations: 1,
            source_bytes: limits.frame_bytes,
            frame_bytes: limits.frame_bytes,
            io_slice_bytes: limits.io_slice_bytes,
            records: core.records,
            label_bytes: 255,
            record_sets: 1,
            retirement_grace: limits.retirement_grace,
            reconnect: true,
            ..ns::Limits::default()
        };
        let ns = ns::Client::new(ns_instance, ports.namestore.duplicate()?, ns_limits)?;
        let gns = GnsClient::new(
            gns_instance,
            ports.gns.duplicate()?,
            gns::Limits {
                frame_bytes: limits.frame_bytes,
                records: core.records,
                output: Budget {
                    frames: 1,
                    bytes: limits.frame_bytes,
                },
                io_slice_bytes: limits.io_slice_bytes,
            },
        )?;
        let sample = ports.clock.sample().map_err(Error::Clock)?;
        let subscription = ports.clock.subscribe().map_err(Error::Clock)?;
        let mut peers = Vec::new();
        peers
            .try_reserve_exact(limits.clients)
            .map_err(|_| Fault::Capacity)?;
        peers.resize_with(limits.clients, || None);
        let mut jobs = Vec::new();
        jobs.try_reserve_exact(limits.operations)
            .map_err(|_| Fault::Capacity)?;
        jobs.resize_with(limits.operations, || None);
        Ok(Self {
            factory,
            limits,
            ports,
            providers,
            peers,
            jobs,
            domain: Rc::new(Domain { _private: 0 }),
            next_client: 0,
            next_job: 0,
            next_output: 0,
            ns_instance,
            ns,
            ns_limits,
            ns_source: None,
            ns_active: None,
            ns_retry: None,
            gns,
            gns_source: None,
            gns_active: None,
            gns_retry: None,
            scan: None,
            writer: None,
            identity,
            entropy,
            credential,
            accept: AcceptState::default(),
            subscription,
            revision: sample.revision,
            last_now: sample.now.as_micros(),
            timer: Box::pin(tokio::time::sleep(Duration::ZERO)),
            class: 0,
            peer_cursor: 0,
            job_cursor: 0,
            listener_cursor: 0,
            shutdown: None,
            closed: false,
            yield_due: false,
            report: Report::default(),
            metrics: Metrics::default(),
        })
    }
    fn entry(&self, tag: Tag) -> Result<&Entry, Fault> {
        self.jobs
            .get(tag.row)
            .and_then(Option::as_ref)
            .filter(|e| e.tag == tag)
            .ok_or(Fault::StaleGeneration)
    }
    fn entry_mut(&mut self, tag: Tag) -> Result<&mut Entry, Fault> {
        self.jobs
            .get_mut(tag.row)
            .and_then(Option::as_mut)
            .filter(|e| e.tag == tag)
            .ok_or(Fault::StaleGeneration)
    }
    /// Current actual local counters; no secret-bearing diagnostics.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.report
    }
    /// Actual GNS callback counters, including empty results, on this same owner.
    /// Reading does no provider IO or timestamp synthesis.
    #[must_use]
    pub const fn metrics(&self) -> Metrics {
        self.metrics
    }
    /// Actually enforce configured ACL and kernel Unix credentials before any
    /// private request allocation, then adopt one original Framed owner.
    pub fn admit(
        &mut self,
        accepted: AcceptedConnection,
        observe: &mut impl FnMut(Event),
    ) -> Result<Option<Client>, Error> {
        let (connection, address, diagnostics) = accepted.into_parts();
        for d in diagnostics {
            observe(Event::Socket(
                gnunet_service_runtime::accepted::SocketEvent::Diagnostic(d),
            ));
        }
        let allowed = match address {
            PeerAddress::Tcp(p) => self.ports.options.access.allows(p.ip()),
            PeerAddress::Unix => self.ports.unix.allows(&connection)?,
        };
        if !allowed {
            drop(connection);
            observe(Event::Rejected(address));
            return Ok(None);
        }
        if self.shutdown.is_some() {
            drop(connection);
            return Err(Fault::Closed.into());
        }
        let row = self
            .peers
            .iter()
            .position(Option::is_none)
            .ok_or(Fault::Capacity)?;
        let serial = self.next_client.checked_add(1).ok_or(Fault::Overflow)?;
        let client = Client {
            domain: self.domain.clone(),
            serial,
        };
        let io = Framed::new(connection, self.limits.framing())?;
        let first_until = Instant::now()
            .checked_add(self.limits.first_input)
            .ok_or(Fault::Overflow)?;
        self.next_client = serial;
        self.peers[row] = Some(Peer {
            client: client.clone(),
            io,
            first: true,
            first_until,
            input_until: None,
            read_first: false,
            output: None,
        });
        self.report.accepted = self.report.accepted.saturating_add(1);
        observe(Event::Accepted(client.clone()));
        Ok(Some(client))
    }
    fn close_peer(&mut self, row: usize, cause: CloseCause, observe: &mut impl FnMut(Event)) {
        if let Some(mut peer) = self.peers[row].take() {
            peer.io.retire(); // Actual physical original owner fence, no clock.
            for entry in self.jobs.iter_mut().flatten() {
                if entry.client.as_ref() == Some(&peer.client) {
                    entry.client = None;
                    if entry.job.status().output_debt {
                        self.report.dropped_outputs = self.report.dropped_outputs.saturating_add(1);
                    }
                    entry.job.output_lost();
                }
            }
            if let Some(output) = peer.output.take() {
                let exposure = if output.sent == output.total {
                    Exposure::Written { bytes: output.sent }
                } else if output.sent > 0 {
                    Exposure::Partial { bytes: output.sent }
                } else {
                    Exposure::Unsent
                };
                observe(Event::OutputRetired {
                    client: peer.client.clone(),
                    job: output.origin.job.serial,
                    rid: output.origin.rid,
                    exposure,
                });
            }
            self.accept.client_closed();
            self.report.closed = self.report.closed.saturating_add(1);
            observe(Event::Closed {
                client: peer.client,
                cause,
            });
        }
    }
    /// Close this exact original app source. Provider mutations remain owned
    /// until their original actual SDK result or physical retirement.
    pub fn close_client(
        &mut self,
        client: &Client,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Error> {
        let row = self
            .peers
            .iter()
            .position(|p| p.as_ref().is_some_and(|p| p.client == *client))
            .ok_or(Fault::StaleGeneration)?;
        self.close_peer(row, CloseCause::Shutdown, observe);
        Ok(())
    }
    /// Stop admission. Soft still accepts actual NEXT/STOP of existing iterators;
    /// an outer finite grace eventually calls close_all for physical shutdown.
    pub fn request_shutdown(&mut self, mode: ShutdownMode) {
        if self.shutdown != Some(ShutdownMode::Immediate) {
            self.shutdown = Some(mode)
        }
    }
    fn process(&mut self, row: usize, observe: &mut impl FnMut(Event)) -> Result<(), Error> {
        let peer = self.peers[row].as_ref().ok_or(Fault::Stale)?;
        let client = peer.client.clone();
        let input = peer.io.frame().ok_or(Fault::NotReady)?;
        let request = Request::decode(input)?;
        let rid = request.request_id();
        let existing = self.jobs.iter().position(|e| {
            e.as_ref()
                .is_some_and(|e| e.client.as_ref() == Some(&client) && e.rid == rid)
        });
        match request {
            Request::IterateNext { kind, .. } | Request::IterateStop { kind, .. } => {
                let index = existing.ok_or(Fault::StaleGeneration)?;
                let entry = self.jobs[index].as_mut().ok_or(Fault::Stale)?;
                if entry.iteration != Some(kind) {
                    return Err(Fault::Conflict.into());
                }
                if matches!(request, Request::IterateStop { .. }) {
                    entry.stopped = true;
                    entry.job.cancel();
                } else {
                    entry.job.grant_next()?;
                }
            }
            _ => {
                if self.shutdown.is_some() {
                    return Err(Fault::Closed.into());
                }
                if existing.is_some() {
                    return Err(Fault::Conflict.into());
                }
                if self
                    .jobs
                    .iter()
                    .flatten()
                    .filter(|e| e.client.as_ref() == Some(&client))
                    .count()
                    >= self.limits.per_client
                {
                    return Err(Fault::Capacity.into());
                }
                let index = self
                    .jobs
                    .iter()
                    .position(Option::is_none)
                    .ok_or(Fault::Capacity)?;
                let now = self.last_now;
                let duration = u64::try_from(self.limits.operation_lifetime.as_micros())
                    .map_err(|_| Fault::Overflow)?;
                let until = now
                    .checked_add(duration)
                    .filter(|n| *n != u64::MAX)
                    .ok_or(Fault::Overflow)?;
                let hard = Instant::now()
                    .checked_add(self.limits.operation_lifetime)
                    .ok_or(Fault::Overflow)?;
                let job = self.factory.start(request, now, until)?;
                let serial = self.next_job.checked_add(1).ok_or(Fault::Overflow)?;
                let iteration = if let Request::IterateStart { kind, .. } = request {
                    Some(kind)
                } else {
                    None
                };
                self.jobs[index] = Some(Entry {
                    tag: Tag { row: index, serial },
                    client: Some(client),
                    rid,
                    iteration,
                    readonly: matches!(
                        request,
                        Request::ConsumeTicket { .. } | Request::IterateStart { .. }
                    ),
                    stopped: false,
                    job,
                    hard,
                    output_until: None,
                });
                self.next_job = serial;
                self.report.requests = self.report.requests.saturating_add(1);
            }
        }
        let peer = self.peers[row].as_mut().ok_or(Fault::Stale)?;
        if !peer.io.release_frame() {
            return Err(Fault::Conflict.into());
        }
        peer.input_until = None;
        peer.first = false;
        let _observer = observe;
        Ok(())
    }
    fn queue_output(&mut self, row: usize, observe: &mut impl FnMut(Event)) -> Result<bool, Error> {
        let peer = self.peers[row].as_ref().ok_or(Fault::Stale)?;
        if peer.io.queued_frames() != 0 {
            return Ok(false);
        }
        let client = peer.client.clone();
        let Some(index) = self.jobs.iter().position(|e| {
            e.as_ref()
                .is_some_and(|e| e.client.as_ref() == Some(&client) && e.job.response().is_some())
        }) else {
            return Ok(false);
        };
        let entry = self.jobs[index].as_ref().ok_or(Fault::Stale)?;
        if Instant::now() >= entry.hard {
            let until = entry.job.deadline();
            self.jobs[index]
                .as_mut()
                .ok_or(Fault::Stale)?
                .job
                .expire(until);
            return Ok(true);
        }
        let view = entry.job.response().ok_or(Fault::NotReady)?;
        let sequence = self.next_output.checked_add(1).ok_or(Fault::Overflow)?;
        let token = view.output.clone();
        let origin = Origin {
            client: client.serial,
            job: entry.tag,
            sequence,
            rid: entry.rid,
        };
        let frame = OwnedFrame::copy_from(view.bytes.expose())?;
        let total = frame.len();
        let peer = self.peers[row].as_mut().ok_or(Fault::Stale)?;
        peer.io.reserve(frame.len(), Class::Ordinary)?;
        if let Err(rejected) = peer.io.enqueue_owned(frame, origin, Class::Ordinary) {
            return Err(rejected.reason.into());
        }
        peer.output = Some(OutputSend {
            origin,
            token: token.clone(),
            total,
            sent: 0,
        });
        self.next_output = sequence;
        self.entry_mut(origin.job)?.job.output_queued(&token)?;
        observe(Event::Queued {
            client,
            rid: origin.rid,
        });
        Ok(true)
    }
    fn write_peer(
        &mut self,
        cx: &mut Context<'_>,
        row: usize,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        let progress = match self.peers[row]
            .as_mut()
            .ok_or(Fault::Stale)?
            .io
            .poll_write(cx)
        {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => {
                self.close_peer(row, CloseCause::Io(e), observe);
                return Poll::Ready(Ok(Progress::Activity));
            }
            Poll::Ready(Ok(p)) => p,
        };
        let client = self.peers[row].as_ref().ok_or(Fault::Stale)?.client.clone();
        if progress.origin.client != client.serial {
            return Poll::Ready(Err(Fault::StaleGeneration.into()));
        }
        let outgoing = self.peers[row]
            .as_mut()
            .ok_or(Fault::Stale)?
            .output
            .as_mut()
            .ok_or(Fault::Conflict)?;
        if outgoing.origin != progress.origin {
            return Poll::Ready(Err(Fault::StaleGeneration.into()));
        }
        outgoing.sent = outgoing
            .sent
            .checked_add(progress.bytes)
            .filter(|n| *n <= outgoing.total)
            .ok_or(Fault::Overflow)?;
        if progress.complete != (outgoing.sent == outgoing.total) {
            return Poll::Ready(Err(Fault::Conflict.into()));
        }
        let token = outgoing.token.clone();
        let entry = self.entry_mut(progress.origin.job)?;
        entry.job.output_exposed(&token, progress.bytes)?;
        if progress.complete {
            entry.job.output_written(&token)?;
            entry.output_until = None;
            self.peers[row].as_mut().ok_or(Fault::Stale)?.output = None;
            self.report.written = self.report.written.saturating_add(1);
            observe(Event::Written {
                client,
                rid: progress.origin.rid,
            });
        }
        Poll::Ready(Ok(Progress::Activity))
    }
    fn read_peer(
        &mut self,
        cx: &mut Context<'_>,
        row: usize,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        if self.peers[row]
            .as_ref()
            .ok_or(Fault::Stale)?
            .io
            .frame()
            .is_some()
        {
            match self.process(row, observe) {
                Ok(()) => {}
                Err(Error::Protocol(Fault::Capacity | Fault::WouldBlock | Fault::TooLarge)) => {
                    self.close_peer(row, CloseCause::Capacity, observe)
                }
                Err(Error::Protocol(e)) => self.close_peer(row, CloseCause::Protocol(e), observe),
                Err(e) => return Poll::Ready(Err(e)),
            }
            return Poll::Ready(Ok(Progress::Activity));
        }
        match self.peers[row]
            .as_mut()
            .ok_or(Fault::Stale)?
            .io
            .poll_read(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => {
                self.close_peer(row, CloseCause::Io(e), observe);
                Poll::Ready(Ok(Progress::Activity))
            }
            Poll::Ready(Ok(ReadStep::Eof)) => {
                self.close_peer(row, CloseCause::Eof, observe);
                Poll::Ready(Ok(Progress::Activity))
            }
            Poll::Ready(Ok(ReadStep::Progress { .. })) => {
                let peer = self.peers[row].as_mut().ok_or(Fault::Stale)?;
                if peer.input_until.is_none() {
                    peer.input_until = Some(
                        Instant::now()
                            .checked_add(self.limits.input_lifetime)
                            .ok_or(Fault::Overflow)?,
                    );
                }
                Poll::Ready(Ok(Progress::Activity))
            }
        }
    }
    fn peer(
        &mut self,
        cx: &mut Context<'_>,
        row: usize,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        match self.queue_output(row, observe) {
            Ok(true) => return Poll::Ready(Ok(Progress::Activity)),
            Ok(false) => {}
            Err(Error::Protocol(Fault::Capacity | Fault::WouldBlock | Fault::TooLarge)) => {
                self.close_peer(row, CloseCause::Capacity, observe);
                return Poll::Ready(Ok(Progress::Activity));
            }
            Err(error) => return Poll::Ready(Err(error)),
        }
        let read_first = self.peers[row].as_ref().ok_or(Fault::Stale)?.read_first;
        for n in 0..2 {
            let read = (n == 0) == read_first;
            let result = if read {
                self.read_peer(cx, row, observe)
            } else {
                self.write_peer(cx, row, observe)
            };
            if result.is_ready() {
                if let Some(peer) = self.peers[row].as_mut() {
                    peer.read_first = !read;
                }
                return result;
            }
        }
        Poll::Pending
    }
    fn accept_peer(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        if self.shutdown.is_some() || !self.accept.ready() || self.peers.iter().all(Option::is_some)
        {
            return Poll::Pending;
        }
        for n in 0..listeners.len() {
            let row = (self.listener_cursor + n) % listeners.len();
            match listeners[row].poll_canonical_connection(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(e)) => {
                    observe(Event::Socket(self.accept.failed(e)));
                    self.listener_cursor = (row + 1) % listeners.len();
                    return Poll::Ready(Ok(Progress::Activity));
                }
                Poll::Ready(Ok(accepted)) => {
                    self.listener_cursor = (row + 1) % listeners.len();
                    self.admit(accepted, observe)?;
                    return Poll::Ready(Ok(Progress::Activity));
                }
            }
        }
        Poll::Pending
    }
}
