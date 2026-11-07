//! One caller-polled native operation table over original actual clients.
use crate::{
    Error, Event, Instances, Limits, Loss, Ports, Progress, Report,
    core::{self, AnswerId, Bounds, Core, JobId, Kind, ZoneId},
    identity,
    metrics::{Metrics, Tracker},
    names::Names,
    namestore,
    time::{Budget, Clock},
};
use gnunet_dnsstub_host::{DnsStub, RequestId};
use gnunet_gnsrecord::ZoneKey;
use gnunet_service_runtime::clock::ClockSubscription;
use gnunet_types::Error as Fault;
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
use zeroize::Zeroizing;
mod actions;
mod native;
mod response;
mod shutdown;
use response::{Records, Workspace};

struct Key {
    zone: ZoneId,
    secret: identity::SecretKey,
}
struct Candidate {
    canonical: String,
    secret: identity::SecretKey,
    ambiguous: bool,
}
struct Answer {
    id: AnswerId,
    records: Records,
}
struct Pending<'id> {
    job: JobId,
    kind: Kind,
    bounds: Bounds,
    budget: Budget,
    epoch: Option<u64>,
    wire_bytes: usize,
    written: bool,
    retiring: bool,
    expired: bool,
    started: std::time::Instant,
    exposure: crate::Exposure,
    native: Native<'id>,
}
enum Native<'id> {
    Create {
        operation: identity::Operation<'id>,
        zone: ZoneId,
    },
    Check {
        operation: namestore::Operation<'id>,
        label: Vec<u8>,
    },
    Delegate {
        operation: namestore::Operation<'id>,
    },
    Scan(Box<Scan<'id>>),
    Query(Box<Query>),
    Store {
        operation: namestore::Operation<'id>,
        answer: AnswerId,
    },
    Deferred,
    Settled,
}
struct Scan<'id> {
    iterator: namestore::ZoneIterator<'id>,
    next_pending: bool,
    closed: bool,
}
struct Query {
    request: Option<RequestId>,
    bytes: Zeroizing<Vec<u8>>,
    hostname: String,
    tcp_server: Option<SocketAddr>,
    tcp: Option<crate::tcp::Exchange>,
}
struct Incoming {
    bytes: Zeroizing<Vec<u8>>,
    request: Option<RequestId>,
    server: Option<SocketAddr>,
}
enum Notice {
    Datagram,
    Io {
        request: Option<RequestId>,
        error: io::Error,
    },
    Activity,
}
/// Original physical sources and every native-to-Core attribution row.
/// No tasks, hidden resolver or worker is created. The caller drives all polls.
pub struct Runtime<'id> {
    core: Core,
    instances: Instances<'id>,
    ports: Ports,
    clock: Clock,
    limits: Limits,
    servers: Vec<SocketAddr>,
    dns: DnsStub<64, 512, 16>,
    identity: Option<identity::Client<'id>>,
    namestore: Option<namestore::Client<'id>>,
    initial: Option<Budget>,
    names: Names,
    keys: Vec<Key>,
    ambiguous: Vec<String>,
    pending: Vec<Option<Pending<'id>>>,
    answers: Vec<Option<Answer>>,
    work: Workspace,
    incoming: Incoming,
    notice: Option<Notice>,
    subscription: Box<dyn ClockSubscription>,
    revision: u64,
    last: core::Times,
    wake: Pin<Box<Sleep>>,
    wake_at: Option<Instant>,
    waiting: Option<Waker>,
    sealed: bool,
    initialized: bool,
    closing: bool,
    identity_closed: bool,
    namestore_closed: bool,
    stopped_dns: bool,
    stalled: bool,
    class: usize,
    cursor: usize,
    yield_due: bool,
    report: Report,
    metrics: Tracker,
}
impl<'id> Runtime<'id> {
    /// Prepare fixed metadata/buffer pools. Native clients are lazy until input
    /// EOF, so lengthy legal stdin preparation cannot burn an initialization IO
    /// budget before its source is even polled. Constructor errors have no open
    /// MQ, DNS socket, task, secret inventory or worker to return/drain.
    pub fn new(
        core: Core,
        instances: Instances<'id>,
        ports: Ports,
        clock: Clock,
        limits: Limits,
        servers: &[SocketAddr],
    ) -> Result<Self, Error> {
        limits.validate()?;
        if servers.is_empty()
            || servers.len() > 16
            || servers
                .iter()
                .any(|server| server.port() == 0 || server.ip().is_unspecified())
            || !std::sync::Arc::ptr_eq(&ports.clock, &clock.source())
            || !std::sync::Arc::ptr_eq(&ports.clock, &ports.identity.clock())
            || !std::sync::Arc::ptr_eq(&ports.clock, &ports.namestore.clock())
        {
            return Err(Fault::InvalidInput.into());
        }
        let capacity = core.limits();
        if limits.identity.egos < capacity.zones
            || limits.namestore.records < capacity.records_per_set
        {
            return Err(Fault::Capacity.into());
        }
        let mut report = Report::default();
        report
            .remaining
            .try_reserve_exact(capacity.jobs)
            .map_err(|_| Fault::Capacity)?;
        let last = clock.sample()?;
        let sample = ports.clock.sample()?;
        let subscription = ports.clock.subscribe()?;
        let mut keys = Vec::new();
        keys.try_reserve_exact(capacity.zones)
            .map_err(|_| Fault::Capacity)?;
        let mut ambiguous = Vec::new();
        ambiguous
            .try_reserve_exact(capacity.zones)
            .map_err(|_| Fault::Capacity)?;
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(capacity.jobs)
            .map_err(|_| Fault::Capacity)?;
        pending.resize_with(capacity.jobs, || None);
        let mut answers = Vec::new();
        answers
            .try_reserve_exact(capacity.jobs)
            .map_err(|_| Fault::Capacity)?;
        answers.resize_with(capacity.jobs, || None);
        let mut server_list = Vec::new();
        server_list
            .try_reserve_exact(servers.len())
            .map_err(|_| Fault::Capacity)?;
        server_list.extend_from_slice(servers);
        let mut incoming = Zeroizing::new(Vec::new());
        incoming
            .try_reserve_exact(limits.response_bytes)
            .map_err(|_| Fault::Capacity)?;
        let work = Workspace::new(limits, capacity.records_per_set)?;
        let mut dns = DnsStub::start(limits.dns_requests, limits.response_bytes)?;
        for server in servers {
            dns.add_dns_sa(*server)?;
        }
        Ok(Self {
            core,
            instances,
            ports,
            clock,
            limits,
            servers: server_list,
            dns,
            identity: None,
            namestore: None,
            initial: None,
            names: Names::default(),
            keys,
            ambiguous,
            pending,
            answers,
            work,
            incoming: Incoming {
                bytes: incoming,
                request: None,
                server: None,
            },
            notice: None,
            subscription,
            revision: sample.revision,
            last,
            wake: Box::pin(tokio::time::sleep(Duration::ZERO)),
            wake_at: None,
            waiting: None,
            sealed: false,
            initialized: false,
            closing: false,
            identity_closed: false,
            namestore_closed: false,
            stopped_dns: false,
            stalled: false,
            class: 0,
            cursor: 0,
            yield_due: false,
            report,
            metrics: Tracker::new(),
        })
    }
    /// Admit only public validated input metadata. It creates no DNS/IPC work
    /// before finish_input. Invalid input is never relabeled into another ego.
    pub fn add_name(&mut self, raw: &[u8]) -> Result<core::NameId, Error> {
        if self.closing || self.sealed {
            return Err(Fault::Closed.into());
        }
        self.metrics.add(16, 1);
        let name = self.names.input(raw)?;
        let now = self.clock.sample()?;
        self.last = now;
        Ok(self.core.add_name(&name, now)?)
    }
    /// Actual stdin EOF permits activation. It does not stand in for inventory END.
    pub fn finish_input(&mut self) -> Result<(), Error> {
        if self.closing || self.sealed {
            return Err(Fault::Closed.into());
        }
        // This is the actual caller EOF fact only. Core input activation waits
        // for the original IDENTITY initial END and retained key inventory.
        self.sealed = true;
        if let Some(waker) = self.waiting.take() {
            waker.wake();
        }
        Ok(())
    }
    /// Actual diagnostic values; no counter failure changes business state.
    pub fn metrics(&self) -> Metrics {
        self.metrics.snapshot()
    }
    /// Current original-owner cleanup metadata; never grants source authority.
    pub fn report(&self) -> &Report {
        &self.report
    }
    /// Consume original observations. This does not grant Closed/quiescence;
    /// inspect core_quiescent and payloads_remaining after the real close loop.
    pub fn into_report(mut self) -> Report {
        self.begin_close();
        // Core distinguishes prior failure and real terminal service rejection
        // from known-unsent normal cancellation. Refresh both totals after the
        // original close drains, including real rejection/uncertainty seen there.
        self.report.name_failures = self.core.name_failures();
        self.report.core_quiescent = self.core.quiescent();
        self.report.payloads_remaining = self.answers.iter().filter(|slot| slot.is_some()).count();
        self.report.invariant_stalled = self.stalled;
        self.report.remaining.clear();
        for row in self.pending.iter().flatten() {
            self.report.remaining.push(crate::Remaining {
                job: row.job.diagnostic(),
                kind: row.kind,
                bounds: row.bounds,
                epoch: row.epoch,
                exposure: row.exposure,
                terminal_observed: matches!(row.native, Native::Settled),
            });
        }
        std::mem::take(&mut self.report)
    }
    fn free(&self) -> Result<usize, Error> {
        self.pending
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| Fault::Capacity.into())
    }
    fn key(&self, zone: &ZoneId) -> Result<&identity::SecretKey, Error> {
        self.keys
            .iter()
            .find(|key| &key.zone == zone)
            .map(|key| &key.secret)
            .ok_or_else(|| Fault::StaleGeneration.into())
    }
    fn release(&mut self, completion: core::Completion) -> Result<(), Error> {
        if let Some(answer) = completion.release {
            let slot = self
                .answers
                .iter_mut()
                .find(|slot| slot.as_ref().is_some_and(|value| value.id == answer))
                .ok_or(Fault::StaleGeneration)?;
            drop(slot.take());
        }
        Ok(())
    }
    fn resume_deferred(&mut self) -> Result<(), Error> {
        for slot in &mut self.pending {
            if let Some(row) = slot.as_ref()
                && matches!(row.native, Native::Deferred)
                && !row.bounds.expired(self.last)
            {
                self.core.resume(&row.job)?;
                drop(slot.take());
            }
        }
        Ok(())
    }
    fn note_io(
        &mut self,
        request: Option<RequestId>,
        error: io::Error,
        observe: &mut impl FnMut(Event<'_>),
    ) {
        let job = request.and_then(|request| {
            self.pending
                .iter()
                .flatten()
                .find_map(|row| match &row.native {
                    Native::Query(query) if query.request == Some(request) => {
                        Some(row.job.diagnostic())
                    }
                    _ => None,
                })
        });
        observe(Event::Io { job, cause: &error });
        if let Some(slot) = self
            .report
            .native_errors
            .iter_mut()
            .find(|slot| slot.is_none())
        {
            *slot = Some(error);
        } else {
            self.report.additional_native_errors =
                self.report.additional_native_errors.saturating_add(1);
        }
    }
}
impl Drop for Runtime<'_> {
    fn drop(&mut self) {
        // Emergency owner Drop really fences native sources, but does not poll
        // original completions or claim a successful pure retirement report.
        self.begin_close();
    }
}
