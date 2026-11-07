//! Actual official NAMESTORE IPC, original durable effects and bounded streams.
use crate::{backend, worker};
use gnunet_namestore::{
    Change, ChangeKind, Code, Core, Decision, Filter, Monitor, Query, Reply, StreamProgress,
    Transaction, Write, ZoneIterator,
};
use gnunet_service_runtime::{
    accepted::{AcceptState, AcceptedConnection},
    clock::ClockSubscription,
    framing::{Accounting, Budget, Class, Framed, Limits as FrameLimits, OwnedFrame, ReadStep},
    service::{Listener, PeerAddress, ShutdownMode},
};
use gnunet_types::Error as Fault;
use gnunet_wire::official::namestore::{CString, Records, Request, Response};
use std::{
    collections::VecDeque,
    future::{Future, poll_fn},
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};
use zeroize::Zeroizing;
mod snapshot;
mod streams;
mod types;
use streams::{Driver, Target};
pub use types::*;
#[derive(Clone, Copy)]
struct Origin {
    client: u64,
    write: u64,
}
enum Item {
    Business {
        request: u32,
        reply: Reply,
    },
    Lookup {
        request: u32,
        query: Query,
    },
    Reverse {
        request: u32,
        query: Query,
    },
    ReverseMissing {
        request: u32,
        zone: gnunet_namestore::SecretKey,
    },
}
impl Item {
    fn response(&self) -> Result<Response<'_>, Fault> {
        match self {
            Self::Business {
                request,
                reply: Reply::Generic { code },
            } => Ok(Response::Generic {
                rid: *request,
                code: code.value(),
            }),
            Self::Business {
                request,
                reply: Reply::Edit { code, query },
            } => Ok(Response::Edit {
                rid: *request,
                code: u16::try_from(code.value()).map_err(|_| Fault::Overflow)?,
                hint: query.hint().map(CString::new).transpose()?,
                records: query.records()?,
            }),
            Self::Lookup { request, query } => Ok(Response::Lookup {
                rid: *request,
                zone: query.zone().view()?,
                label: CString::new(query.label())?,
                found: i16::from(query.found()),
                reserved: 0,
                records: query.records()?,
            }),
            Self::Reverse { request, query } => Ok(Response::ZoneToName {
                rid: *request,
                code: Code::NONE.value(),
                zone: Some(query.zone().view()?),
                label: Some(CString::new(query.label())?),
                records: query.records()?,
            }),
            // A completed lookup without a match is a normal NO_RESULTS reply.
            // The official C API reads the private-key field before switching
            // on that code, so retain only this request's supplied authority.
            Self::ReverseMissing { request, zone } => Ok(Response::ZoneToName {
                rid: *request,
                code: Code::NO_RESULTS.value(),
                zone: Some(zone.view()?),
                label: None,
                records: Records::empty()?,
            }),
        }
    }
}
struct Flight {
    native: u64,
    stream: Option<(Target, Write)>,
}
struct Peer {
    client: Client,
    io: Framed<Origin>,
    output: VecDeque<Item>,
    flights: VecDeque<Flight>,
    streams: Vec<Option<Driver>>,
    next_stream: u64,
    stream_cursor: usize,
    next_write: u64,
    first: bool,
    first_until: Instant,
    input_until: Option<Instant>,
    output_until: Option<Instant>,
    read_first: bool,
}
impl Peer {
    fn stream_mut(&mut self, t: Target) -> Option<&mut Driver> {
        self.streams.iter_mut().flatten().find(|s| s.target() == t)
    }
}
struct Pending {
    transaction: Transaction,
    job: worker::Job,
    client: Client,
    request: u32,
    kind: ChangeKind,
    until: Instant,
}
struct Notify {
    client: Client,
    request: u32,
    reply: Reply,
    change: Change,
    cursor: usize,
    until: Instant,
    barrier: bool,
}
/// One actual caller-driven SERVICE. One explicit separately started shared
/// snapshot Worker is borrowed; construction starts no task/thread/Resolver.
pub struct Server<'worker> {
    core: Core,
    worker: &'worker mut worker::Worker,
    generation: u64,
    limits: Limits,
    ports: Ports,
    peers: Vec<Option<Peer>>,
    domain: Rc<Domain>,
    next_client: u64,
    pending: Option<Pending>,
    notify: Option<Notify>,
    accept: AcceptState,
    subscription: Box<dyn ClockSubscription>,
    revision: u64,
    timer: Pin<Box<Sleep>>,
    class: usize,
    cursor: usize,
    listener_cursor: usize,
    report: Report,
    shutdown: Option<ShutdownMode>,
    yield_due: bool,
}
impl Limits {
    fn framing(self) -> FrameLimits {
        FrameLimits {
            frame_bytes: self.frame_bytes,
            ordinary: Budget {
                frames: self.output_frames,
                bytes: self.output_bytes,
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.io_slice_bytes,
        }
    }
    fn validate(self) -> Result<(), Fault> {
        self.framing().validate()?;
        streams::validate_limits(self.streams)?;
        if self.clients == 0
            || self.clients > 1024
            || self.output_items == 0
            || self.output_items > 4096
            || self.iterators == 0
            || self.iterators > 4096
            || self.output_frames == 0
            || self.output_frames > 64
            || self.output_bytes < self.frame_bytes
            || self.snapshot_body_bytes < 12
            || self.snapshot_body_bytes > 64 * 1024 * 1024
        {
            return Err(Fault::Capacity);
        }
        self.clients
            .checked_mul(self.iterators.checked_add(1).ok_or(Fault::Overflow)?)
            .ok_or(Fault::Overflow)?;
        for d in [
            self.first_input,
            self.input_lifetime,
            self.output_lifetime,
            self.storage_lifetime,
        ] {
            if d.is_zero() || Instant::now().checked_add(d).is_none() {
                return Err(Fault::Deadline);
            }
        }
        Ok(())
    }
}
impl<'worker> Server<'worker> {
    /// Recover one exact qualified NAMESTORE owner. A fresh namespace consumes
    /// a real empty canonical image under this original lease before returning.
    /// No await/cancellation boundary splits fresh open from initialization;
    /// the foreground starts its worker and declares READY only afterward.
    /// Existing missing/empty canonical state is never silently reset.
    pub fn recover(
        store: &mut backend::Store,
        loaded: backend::Loaded,
        limits: gnunet_namestore::Limits,
        critical: fn(gnunet_namestore::RecordType) -> bool,
    ) -> Result<(Core, u64), Error> {
        let namespace = gnunet_snapshot_host::Namespace::Namestore;
        if loaded.namespace() != namespace || store.namespace() != namespace {
            return Err(Fault::PermissionDenied.into());
        }
        let generation = loaded.generation();
        if generation != store.generation() {
            return Err(Fault::Stale.into());
        }
        let created = loaded.created_directory();
        let body = loaded.into_body();
        if generation == 0 {
            if !created || !body.is_empty() {
                return Err(Fault::Storage.into());
            }
            // Empty authority is a real versioned GNMCORE1/count0 image, not
            // the absent-image sentinel. This is startup storage, not a client
            // mutation or monitor event, and contributes no business receipt.
            let core = Core::new(limits, Vec::new(), critical)?;
            let image = snapshot::encode(&core.snapshot()?, 12)?;
            let receipt = store.commit(0, image).map_err(Error::Storage)?;
            if receipt.namespace() != namespace
                || receipt.generation() != 1
                || store.generation() != receipt.generation()
            {
                return Err(Fault::OutcomeUnknown.into());
            }
            return Ok((core, receipt.generation()));
        }
        // Committed empty authority has the same valid 12-byte body as every
        // ordinary empty snapshot. A zero-length committed body is corruption.
        let rows = snapshot::decode(body, limits)?;
        Ok((Core::new(limits, rows, critical)?, generation))
    }
    /// Retain actual explicit inventory, worker and shared SERVICE ports. This
    /// allocates bounded metadata and one clock subscription; no MQ is opened.
    pub fn new(
        core: Core,
        worker: &'worker mut worker::Worker,
        generation: u64,
        limits: Limits,
        ports: Ports,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if worker.namespace() != gnunet_snapshot_host::Namespace::Namestore {
            return Err(Fault::PermissionDenied.into());
        }
        let sample = ports.clock.sample().map_err(Error::Clock)?;
        let subscription = ports.clock.subscribe().map_err(Error::Clock)?;
        let mut peers = Vec::new();
        peers
            .try_reserve_exact(limits.clients)
            .map_err(|_| Fault::Capacity)?;
        peers.resize_with(limits.clients, || None);
        Ok(Self {
            core,
            worker,
            generation,
            limits,
            ports,
            peers,
            domain: Rc::new(Domain { _private: 0 }),
            next_client: 0,
            pending: None,
            notify: None,
            accept: AcceptState::default(),
            subscription,
            revision: sample.revision,
            timer: Box::pin(tokio::time::sleep(std::time::Duration::ZERO)),
            class: 0,
            cursor: 0,
            listener_cursor: 0,
            report: Report::default(),
            shutdown: None,
            yield_due: false,
        })
    }
    /// Public counters only; private labels/keys/hints/records are never logged.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.report
    }
    /// Actual ACL/Unix-credential admission precedes private RX/TX allocation.
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
        let index = self
            .peers
            .iter()
            .position(Option::is_none)
            .ok_or(Fault::Capacity)?;
        let mut output = VecDeque::new();
        output
            .try_reserve_exact(self.limits.output_items)
            .map_err(|_| Fault::Capacity)?;
        let mut flights = VecDeque::new();
        flights
            .try_reserve_exact(self.limits.output_frames)
            .map_err(|_| Fault::Capacity)?;
        let mut streams = Vec::new();
        streams
            .try_reserve_exact(self.limits.iterators + 1)
            .map_err(|_| Fault::Capacity)?;
        streams.resize_with(self.limits.iterators + 1, || None);
        let serial = self.next_client.checked_add(1).ok_or(Fault::Overflow)?;
        let client = Client {
            domain: self.domain.clone(),
            serial,
        };
        let first_until = Instant::now()
            .checked_add(self.limits.first_input)
            .ok_or(Fault::Overflow)?;
        let io = Framed::new(connection, self.limits.framing())?;
        self.peers[index] = Some(Peer {
            client: client.clone(),
            io,
            output,
            flights,
            streams,
            next_stream: 0,
            stream_cursor: 0,
            next_write: 0,
            first: true,
            first_until,
            input_until: None,
            output_until: None,
            read_first: false,
        });
        self.next_client = serial;
        self.report.accepted = self.report.accepted.saturating_add(1);
        observe(Event::Accepted(client.clone()));
        Ok(Some(client))
    }
    fn close_index(&mut self, i: usize, cause: CloseCause, observe: &mut impl FnMut(Event)) {
        if let Some(mut p) = self.peers[i].take() {
            p.io.retire();
            for d in p.streams.iter_mut().flatten() {
                let request = d.request();
                let debt = d.lost();
                observe(Event::StreamLost {
                    client: p.client.clone(),
                    request,
                    debt,
                });
            }
            p.output.clear();
            p.flights.clear();
            self.accept.client_closed();
            self.report.closed = self.report.closed.saturating_add(1);
            observe(Event::Closed {
                client: p.client,
                cause,
            });
        }
    }
    /// Independently stop this original physical MQ. An admitted disk mutation
    /// remains bound to its original worker receipt after client loss.
    pub fn close(&mut self, client: &Client, observe: &mut impl FnMut(Event)) -> Result<(), Error> {
        let i = self
            .peers
            .iter()
            .position(|p| p.as_ref().is_some_and(|p| p.client == *client))
            .ok_or(Fault::Stale)?;
        self.close_index(i, CloseCause::Shutdown, observe);
        Ok(())
    }
    /// Stop actual original MQs without reading a clock. Disk admission closes,
    /// but already admitted original effects still require actual drain/join.
    pub fn close_all(&mut self, observe: &mut impl FnMut(Event)) {
        self.shutdown = Some(ShutdownMode::Immediate);
        self.worker.request_stop();
        for i in 0..self.peers.len() {
            self.close_index(i, CloseCause::Shutdown, observe);
        }
    }
    /// Begin finite outer shutdown. Existing original output/worker debts remain;
    /// the foreground owns its actual grace and independently forces close.
    pub fn request_shutdown(&mut self, mode: ShutdownMode) {
        if self.shutdown != Some(ShutdownMode::Immediate) {
            self.shutdown = Some(mode);
        }
    }
    fn deadline(&self, d: std::time::Duration) -> Result<Instant, Fault> {
        Instant::now().checked_add(d).ok_or(Fault::Overflow)
    }
    fn queue(
        &mut self,
        i: usize,
        item: Item,
        observe: &mut impl FnMut(Event),
    ) -> Result<bool, Error> {
        let p = self.peers[i].as_mut().ok_or(Fault::Stale)?;
        if p.output.len() >= self.limits.output_items {
            self.close_index(i, CloseCause::Capacity, observe);
            return Ok(false);
        }
        if p.output_until.is_none() {
            p.output_until = Some(
                Instant::now()
                    .checked_add(self.limits.output_lifetime)
                    .ok_or(Fault::Overflow)?,
            );
        }
        p.output.push_back(item);
        Ok(true)
    }
    fn business(
        &mut self,
        i: usize,
        request: u32,
        reply: Reply,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Error> {
        let code = reply.code();
        let client = self.peers[i].as_ref().map(|p| p.client.clone());
        if self.queue(i, Item::Business { request, reply }, observe)?
            && let Some(client) = client
        {
            observe(Event::Result {
                client,
                request,
                code,
            });
        }
        Ok(())
    }
    fn release(&mut self, i: usize) -> Result<(), Error> {
        let p = self.peers[i].as_mut().ok_or(Fault::Stale)?;
        if !p.io.release_frame() {
            return Err(Fault::Stale.into());
        }
        p.input_until = None;
        p.first = false;
        Ok(())
    }
    fn process(
        &mut self,
        i: usize,
        now: u64,
        observe: &mut impl FnMut(Event),
    ) -> Result<bool, Error> {
        let p = self.peers[i].as_ref().ok_or(Fault::Stale)?;
        let input = p.io.frame().ok_or(Fault::NotReady)?;
        let request = match Request::decode(input) {
            Ok(r) => r,
            Err(Fault::Unsupported) if self.ports.options.tolerant => {
                self.release(i)?;
                return Ok(true);
            }
            Err(e) => return Err(e.into()),
        };
        let owner_blocked = self.pending.as_ref().is_some_and(|x| x.client == p.client)
            || self.notify.as_ref().is_some_and(|x| x.client == p.client);
        if owner_blocked
            && !matches!(
                request,
                Request::MonitorNext { .. }
                    | Request::IterateNext { .. }
                    | Request::IterateStop { .. }
            )
        {
            return Ok(false);
        }
        match request {
            Request::Store {
                rid,
                zone,
                sets,
                single_tx,
                ..
            } => {
                if self.pending.is_some() || self.notify.is_some() || !self.worker.available() {
                    return Ok(false);
                }
                let d = self.core.store(zone, sets, single_tx == 1, now)?;
                self.mutation(i, rid, d, observe)?;
            }
            Request::Lookup {
                rid,
                zone,
                label,
                filter,
                ..
            } => {
                let q = self
                    .core
                    .lookup(zone, label.bytes(), Filter::from_bits(filter), now)?;
                self.queue(
                    i,
                    Item::Lookup {
                        request: rid,
                        query: q,
                    },
                    observe,
                )?;
            }
            Request::ZoneToName { rid, zone, target } => {
                let item = match self.core.zone_to_name(zone, target)? {
                    Some(query) => Item::Reverse {
                        request: rid,
                        query,
                    },
                    None => Item::ReverseMissing {
                        request: rid,
                        zone: gnunet_namestore::SecretKey::from_serialized(
                            zone.expose_serialized(),
                        )?,
                    },
                };
                self.queue(i, item, observe)?;
            }
            Request::EditBegin {
                rid,
                zone,
                label,
                hint,
                ..
            } => {
                if self.pending.is_some() || self.notify.is_some() || !self.worker.available() {
                    return Ok(false);
                }
                let d = self
                    .core
                    .edit_begin(zone, label.bytes(), hint.bytes(), now)?;
                self.mutation(i, rid, d, observe)?;
            }
            Request::EditCancel {
                rid,
                zone,
                label,
                hint,
                replacement,
            } => {
                if self.pending.is_some() || self.notify.is_some() || !self.worker.available() {
                    return Ok(false);
                }
                let d = self.core.edit_cancel(
                    zone,
                    label.bytes(),
                    hint.bytes(),
                    replacement.bytes(),
                )?;
                self.mutation(i, rid, d, observe)?;
            }
            Request::IterateStart { rid, zone, filter } => {
                let p = self.peers[i].as_ref().ok_or(Fault::Stale)?;
                if p.streams.iter().flatten().any(|s| s.request() == Some(rid)) {
                    return Err(Fault::Conflict.into());
                }
                let at = p.streams[..self.limits.iterators]
                    .iter()
                    .position(Option::is_none)
                    .ok_or(Fault::Capacity)?;
                let generation = p.next_stream.checked_add(1).ok_or(Fault::Overflow)?;
                let owner = ZoneIterator::new(
                    &self.core,
                    rid,
                    zone,
                    Filter::from_bits(filter),
                    self.limits.streams,
                )?;
                let p = self.peers[i].as_mut().ok_or(Fault::Stale)?;
                p.next_stream = generation;
                p.streams[at] = Some(Driver::Iterator {
                    request: rid,
                    generation,
                    owner,
                });
            }
            Request::IterateNext { rid, limit } => {
                let p = self.peers[i].as_mut().ok_or(Fault::Stale)?;
                let d = p
                    .streams
                    .iter_mut()
                    .flatten()
                    .find(|s| s.request() == Some(rid))
                    .ok_or(Fault::Stale)?;
                d.grant(limit)?;
            }
            Request::IterateStop { rid } => {
                let p = self.peers[i].as_mut().ok_or(Fault::Stale)?;
                let d = p
                    .streams
                    .iter_mut()
                    .flatten()
                    .find(|s| s.request() == Some(rid))
                    .ok_or(Fault::Stale)?;
                d.stop();
            }
            Request::MonitorStart {
                zone,
                iterate_first,
                filter,
            } => {
                let p = self.peers[i].as_ref().ok_or(Fault::Stale)?;
                let at = self.limits.iterators;
                if p.streams[at].is_some() {
                    return Err(Fault::Conflict.into());
                }
                let generation = p.next_stream.checked_add(1).ok_or(Fault::Overflow)?;
                let opened = self.core.snapshot()?.revision();
                let owner = Monitor::new(
                    &self.core,
                    zone,
                    iterate_first == 1,
                    Filter::from_bits(filter),
                    self.limits.streams,
                )?;
                let p = self.peers[i].as_mut().ok_or(Fault::Stale)?;
                p.next_stream = generation;
                p.streams[at] = Some(Driver::Monitor {
                    generation,
                    opened,
                    offered: opened,
                    owner,
                });
            }
            Request::MonitorNext { limit, .. } => {
                let p = self.peers[i].as_mut().ok_or(Fault::Stale)?;
                p.streams[self.limits.iterators]
                    .as_mut()
                    .ok_or(Fault::Stale)?
                    .grant(limit)?;
            }
        }
        if self.peers[i].is_some() {
            self.release(i)?;
        }
        Ok(true)
    }
    fn mutation(
        &mut self,
        i: usize,
        request: u32,
        decision: Decision,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Error> {
        let transaction = match decision {
            Decision::Immediate(reply) => return self.business(i, request, reply, observe),
            Decision::Prepared(t) => t,
        };
        let stage = self.core.staged().ok_or(Fault::Stale)?;
        let kind = stage.kind;
        let body = match snapshot::encode(stage.after, self.limits.snapshot_body_bytes) {
            Ok(b) => b,
            Err(e) => {
                if let Err(cleanup) = self.core.abort(&transaction, Code::UNKNOWN) {
                    observe(Event::CleanupFailed(cleanup));
                }
                return Err(e.into());
            }
        };
        let until = match self.deadline(self.limits.storage_lifetime) {
            Ok(u) => u,
            Err(e) => {
                let _abort = self.core.abort(&transaction, Code::UNKNOWN);
                return Err(e.into());
            }
        };
        let job = match self.worker.submit(self.generation, body) {
            Ok(j) => j,
            Err((e, _body)) => {
                if let Err(cleanup) = self.core.abort(&transaction, Code::UNKNOWN) {
                    observe(Event::CleanupFailed(cleanup));
                }
                return Err(e.into());
            }
        };
        let client = self.peers[i].as_ref().ok_or(Fault::Stale)?.client.clone();
        self.pending = Some(Pending {
            transaction,
            job: job.clone(),
            client: client.clone(),
            request,
            kind,
            until,
        });
        self.core
            .queued(&self.pending.as_ref().ok_or(Fault::Stale)?.transaction)?;
        self.report.submitted = self.report.submitted.saturating_add(1);
        observe(Event::StorageQueued { client, job, kind });
        Ok(())
    }
    fn completion(
        &mut self,
        c: worker::Completion,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Error> {
        let (job, result) = c.into_parts();
        let p = self.pending.take().ok_or(Fault::Stale)?;
        if job != p.job || job.namespace() != gnunet_snapshot_host::Namespace::Namestore {
            self.pending = Some(p);
            return Err(Fault::Stale.into());
        }
        match result {
            Ok(receipt) => {
                let expected = self.generation.checked_add(1).ok_or(Fault::Overflow)?;
                if receipt.generation() != expected
                    || receipt.namespace() != gnunet_snapshot_host::Namespace::Namestore
                {
                    if let Err(cleanup) = self.core.unknown(&p.transaction) {
                        observe(Event::CleanupFailed(cleanup));
                    }
                    return Err(Fault::OutcomeUnknown.into());
                }
                self.generation = expected;
                let committed = match self.core.commit(&p.transaction) {
                    Ok(c) => c,
                    Err(e) => {
                        if let Err(cleanup) = self.core.unknown(&p.transaction) {
                            observe(Event::CleanupFailed(cleanup));
                        }
                        return Err(e.into());
                    }
                };
                self.report.committed = self.report.committed.saturating_add(1);
                observe(Event::Committed {
                    job,
                    generation: expected,
                    kind: p.kind,
                });
                if self.shutdown == Some(ShutdownMode::Immediate) {
                    drop(committed);
                    return Ok(());
                }
                let until = self.deadline(self.limits.output_lifetime)?;
                let barrier =
                    committed.change.kind() == ChangeKind::Store && !committed.change.is_empty();
                self.notify = Some(Notify {
                    client: p.client,
                    request: p.request,
                    reply: committed.reply,
                    change: committed.change,
                    cursor: 0,
                    until,
                    barrier,
                });
                Ok(())
            }
            Err(failure) => {
                let settled = if failure.exposure == backend::Exposure::Unknown {
                    self.core.unknown(&p.transaction)
                } else {
                    self.core
                        .abort(&p.transaction, Code::BACKEND_FAILED)
                        .map(|_| ())
                };
                if let Err(e) = settled {
                    observe(Event::CleanupFailed(e));
                }
                observe(Event::StorageFailed(failure.clone()));
                Err(Error::Storage(failure))
            }
        }
    }
    fn notification(&mut self, observe: &mut impl FnMut(Event)) -> Result<bool, Error> {
        let Some(n) = self.notify.as_ref() else {
            return Ok(false);
        };
        let revision = n.change.after().revision();
        let expired = Instant::now() >= n.until;
        // Exactly one original-source offer per turn. A new monitor whose
        // initial snapshot already includes this commit is not an old target.
        let cursor = n.cursor;
        if cursor < self.peers.len() {
            if let Some(p) = self.peers[cursor].as_mut()
                && let Some(Driver::Monitor {
                    opened,
                    offered,
                    owner,
                    ..
                }) = p.streams[self.limits.iterators].as_mut()
                && *opened < revision
                && *offered < revision
            {
                match owner.offer(n.change.clone()) {
                    Ok(()) => *offered = revision,
                    Err((Fault::Capacity | Fault::WouldBlock, _original)) => {}
                    Err((e, _original)) => return Err(e.into()),
                }
            }
            self.notify.as_mut().ok_or(Fault::Stale)?.cursor += 1;
            return Ok(true);
        }
        let barrier = n.barrier;
        let mut lagging = false;
        for i in 0..self.peers.len() {
            let waits=self.peers[i].as_ref().is_some_and(|p|matches!(&p.streams[self.limits.iterators],Some(Driver::Monitor{opened,offered,owner,..})if *opened<revision&&(*offered<revision||barrier&&owner.queued_revision()<revision)));
            if waits {
                if expired {
                    self.close_index(i, CloseCause::Deadline, observe);
                } else {
                    lagging = true;
                }
            }
        }
        if lagging {
            return Ok(false);
        }
        let n = self.notify.take().ok_or(Fault::Stale)?;
        if let Some(i) = self
            .peers
            .iter()
            .position(|p| p.as_ref().is_some_and(|p| p.client == n.client))
        {
            self.business(i, n.request, n.reply, observe)?;
        }
        Ok(true)
    }
    fn prepare(
        &mut self,
        i: usize,
        now: u64,
        observe: &mut impl FnMut(Event),
    ) -> Result<bool, Error> {
        let p = self.peers[i].as_mut().ok_or(Fault::Stale)?;
        if let Some(item) = p.output.front() {
            let response = item.response()?;
            let size = response.encoded_len()?;
            if size > self.limits.frame_bytes {
                return Err(Fault::TooLarge.into());
            }
            if !p.io.capacity(size, Class::Ordinary) {
                return Ok(false);
            }
            p.io.reserve(size, Class::Ordinary)?;
            let mut bytes = Zeroizing::new(Vec::new());
            bytes.try_reserve_exact(size).map_err(|_| Fault::Capacity)?;
            bytes.resize(size, 0);
            response.encode(&mut bytes)?;
            let write = p.next_write.checked_add(1).ok_or(Fault::Overflow)?;
            p.io.enqueue_owned(
                OwnedFrame::new(core::mem::take(&mut *bytes)),
                Origin {
                    client: p.client.serial,
                    write,
                },
                Class::Ordinary,
            )
            .map_err(|r| r.reason)?;
            p.flights.push_back(Flight {
                native: write,
                stream: None,
            });
            p.next_write = write;
            drop(p.output.pop_front());
            observe(Event::Queued {
                client: p.client.clone(),
                write,
            });
            return Ok(true);
        }
        let length = p.streams.len();
        for n in 0..length {
            let at = (p.stream_cursor + n) % length;
            let Some(d) = p.streams[at].as_mut() else {
                continue;
            };
            match d.prepare(&self.core, now)? {
                StreamProgress::Prepared => {
                    let prepared = d.prepared().ok_or(Fault::Stale)?;
                    let w = prepared.write.clone();
                    let response = streams::response(prepared.item)?;
                    let size = response.encoded_len()?;
                    if size > self.limits.frame_bytes {
                        return Err(Fault::TooLarge.into());
                    }
                    if p.output_until.is_none() {
                        p.output_until = Some(
                            Instant::now()
                                .checked_add(self.limits.output_lifetime)
                                .ok_or(Fault::Overflow)?,
                        );
                    }
                    if !p.io.capacity(size, Class::Ordinary) {
                        return Ok(false);
                    }
                    p.io.reserve(size, Class::Ordinary)?;
                    d.can_queue(&w)?;
                    let mut bytes = Zeroizing::new(Vec::new());
                    bytes.try_reserve_exact(size).map_err(|_| Fault::Capacity)?;
                    bytes.resize(size, 0);
                    response.encode(&mut bytes)?;
                    let write = p.next_write.checked_add(1).ok_or(Fault::Overflow)?;
                    let target = d.target();
                    p.io.enqueue_owned(
                        OwnedFrame::new(core::mem::take(&mut *bytes)),
                        Origin {
                            client: p.client.serial,
                            write,
                        },
                        Class::Ordinary,
                    )
                    .map_err(|r| r.reason)?;
                    p.flights.push_back(Flight {
                        native: write,
                        stream: Some((target, w.clone())),
                    });
                    d.queued(&w)?;
                    p.next_write = write;
                    p.stream_cursor = (at + 1) % length;
                    observe(Event::Queued {
                        client: p.client.clone(),
                        write,
                    });
                    return Ok(true);
                }
                StreamProgress::Advanced => {
                    p.stream_cursor = (at + 1) % length;
                    return Ok(true);
                }
                StreamProgress::Stopped | StreamProgress::Finished => {
                    p.streams[at] = None;
                    p.stream_cursor = (at + 1) % length;
                    return Ok(true);
                }
                _ => {}
            }
        }
        Ok(false)
    }
    fn write_peer(
        &mut self,
        cx: &mut Context<'_>,
        i: usize,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        match self.peers[i]
            .as_mut()
            .ok_or(Fault::Stale)?
            .io
            .poll_write(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => {
                self.close_index(i, CloseCause::Io(e), observe);
                Poll::Ready(Ok(Progress::Activity))
            }
            Poll::Ready(Ok(actual)) => {
                let p = self.peers[i].as_mut().ok_or(Fault::Stale)?;
                if actual.origin.client != p.client.serial {
                    return Poll::Ready(Err(Fault::Stale.into()));
                }
                let front = p.flights.front().ok_or(Fault::Stale)?;
                if front.native != actual.origin.write {
                    return Poll::Ready(Err(Fault::Stale.into()));
                }
                let stream = front.stream.as_ref().map(|(t, w)| (*t, w.clone()));
                if let Some((target, w)) = stream {
                    let owner = p.stream_mut(target).ok_or(Fault::Stale)?;
                    owner.exposed(&w)?;
                    if actual.complete {
                        owner.written(&w)?;
                    }
                }
                if actual.complete {
                    drop(p.flights.pop_front());
                    self.report.written = self.report.written.saturating_add(1);
                    observe(Event::Written {
                        client: p.client.clone(),
                        write: actual.origin.write,
                    });
                }
                if p.output.is_empty()
                    && p.io.queued_frames() == 0
                    && !p.streams.iter().flatten().any(|d| d.prepared().is_some())
                {
                    p.output_until = None;
                }
                Poll::Ready(Ok(Progress::Activity))
            }
        }
    }
    fn read_peer(
        &mut self,
        cx: &mut Context<'_>,
        i: usize,
        now: u64,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        if self.shutdown.is_some() {
            return Poll::Pending;
        }
        if self.peers[i]
            .as_ref()
            .is_some_and(|p| p.io.frame().is_some())
        {
            return match self.process(i, now, observe) {
                Ok(true) => Poll::Ready(Ok(Progress::Activity)),
                Ok(false) | Err(Error::Protocol(Fault::Capacity | Fault::WouldBlock)) => {
                    Poll::Pending
                }
                Err(Error::Protocol(e)) => {
                    self.close_index(i, CloseCause::Protocol(e), observe);
                    Poll::Ready(Ok(Progress::Activity))
                }
                Err(e) => Poll::Ready(Err(e)),
            };
        }
        match self.peers[i].as_mut().ok_or(Fault::Stale)?.io.poll_read(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => {
                self.close_index(i, CloseCause::Io(e), observe);
                Poll::Ready(Ok(Progress::Activity))
            }
            Poll::Ready(Ok(ReadStep::Eof)) => {
                self.close_index(i, CloseCause::Eof, observe);
                Poll::Ready(Ok(Progress::Activity))
            }
            Poll::Ready(Ok(ReadStep::Progress { complete, .. })) => {
                let p = self.peers[i].as_mut().ok_or(Fault::Stale)?;
                if complete {
                    p.first = false;
                }
                if p.input_until.is_none() {
                    p.input_until = Some(
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
        i: usize,
        now: u64,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        let native = Instant::now();
        let p = self.peers[i].as_ref().ok_or(Fault::Stale)?;
        if p.first && native >= p.first_until
            || p.output_until.is_some_and(|d| native >= d)
            || p.input_until.is_some_and(|d| native >= d)
        {
            self.close_index(i, CloseCause::Deadline, observe);
            return Poll::Ready(Ok(Progress::Activity));
        }
        if self.shutdown.is_some()
            && p.output.is_empty()
            && p.io.queued_frames() == 0
            && !self.pending.as_ref().is_some_and(|x| x.client == p.client)
            && !self.notify.as_ref().is_some_and(|x| x.client == p.client)
        {
            self.close_index(i, CloseCause::Shutdown, observe);
            return Poll::Ready(Ok(Progress::Activity));
        }
        match self.prepare(i, now, observe) {
            Ok(true) => return Poll::Ready(Ok(Progress::Activity)),
            Ok(false) => {}
            Err(Error::Protocol(e)) => {
                self.close_index(i, CloseCause::Protocol(e), observe);
                return Poll::Ready(Ok(Progress::Activity));
            }
            Err(e) => return Poll::Ready(Err(e)),
        }
        let first = self.peers[i].as_ref().ok_or(Fault::Stale)?.read_first;
        for direction in 0..2 {
            let reading = (direction == 0) == first;
            let progress = if reading {
                self.read_peer(cx, i, now, observe)
            } else {
                self.write_peer(cx, i, observe)
            };
            if progress.is_ready() {
                if let Some(p) = self.peers[i].as_mut() {
                    p.read_first = !reading;
                }
                return progress;
            }
        }
        Poll::Pending
    }
    fn accept(
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
            let i = (self.listener_cursor + n) % listeners.len();
            match listeners[i].poll_canonical_connection(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(e)) => {
                    observe(Event::Socket(self.accept.failed(e)));
                    self.listener_cursor = (i + 1) % listeners.len();
                    return Poll::Ready(Ok(Progress::Activity));
                }
                Poll::Ready(Ok(a)) => {
                    self.listener_cursor = (i + 1) % listeners.len();
                    self.admit(a, observe)?;
                    return Poll::Ready(Ok(Progress::Activity));
                }
            }
        }
        Poll::Pending
    }
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        until: Option<Instant>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        match self.subscription.poll_changed(cx, self.revision) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(Error::Clock(e))),
            Poll::Ready(Ok(s)) => self.revision = s.revision,
            Poll::Pending => {}
        }
        let sample = self.ports.clock.sample().map_err(Error::Clock)?;
        self.revision = sample.revision;
        if self
            .pending
            .as_ref()
            .is_some_and(|p| Instant::now() >= p.until)
        {
            return Poll::Ready(Err(Fault::Deadline.into()));
        }
        if self.shutdown == Some(ShutdownMode::Immediate) {
            self.close_all(observe);
        }
        if self.shutdown.is_some()
            && self.peers.iter().all(Option::is_none)
            && self.pending.is_none()
        {
            drop(self.notify.take());
            return Poll::Ready(Ok(Progress::Stopped));
        }
        if until.is_some_and(|d| Instant::now() >= d) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        for n in 0..4 {
            let class = (self.class + n) % 4;
            let progress = match class {
                0 => match self.worker.poll(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Ok(Some(c))) => {
                        Poll::Ready(self.completion(c, observe).map(|()| Progress::Activity))
                    }
                    Poll::Ready(Ok(None)) if self.pending.is_some() => {
                        Poll::Ready(Err(Fault::OutcomeUnknown.into()))
                    }
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
                    _ => Poll::Pending,
                },
                1 => match self.notification(observe) {
                    Ok(true) => Poll::Ready(Ok(Progress::Activity)),
                    Ok(false) => Poll::Pending,
                    Err(e) => Poll::Ready(Err(e)),
                },
                2 => {
                    let mut progress = Poll::Pending;
                    for k in 0..self.peers.len() {
                        let i = (self.cursor + k) % self.peers.len();
                        if self.peers[i].is_some() {
                            let step = self.peer(cx, i, sample.now.as_micros(), observe);
                            if step.is_ready() {
                                self.cursor = (i + 1) % self.peers.len();
                                progress = step;
                                break;
                            }
                        }
                    }
                    progress
                }
                _ => self.accept(cx, listeners, observe),
            };
            if progress.is_ready() {
                // Retry a capacity-refused original offer only after a peer
                // actually advances/releases state. Watermark-only waits stay
                // asleep on real IO/timers instead of rescanning forever.
                if class == 2
                    && let Some(notify) = self.notify.as_mut()
                    && notify.cursor >= self.peers.len()
                {
                    let revision = notify.change.after().revision();
                    if self.peers.iter().flatten().any(|p| matches!(&p.streams[self.limits.iterators], Some(Driver::Monitor { opened, offered, .. }) if *opened < revision && *offered < revision)) {
                                notify.cursor = 0;
                            }
                }
                self.class = (class + 1) % 4;
                return progress;
            }
        }
        let mut target = until;
        for p in self.peers.iter().flatten() {
            for due in p
                .output_until
                .into_iter()
                .chain(p.first.then_some(p.first_until))
                .chain(p.input_until)
            {
                target = Some(target.map_or(due, |t| t.min(due)));
            }
        }
        for due in self
            .pending
            .as_ref()
            .map(|p| p.until)
            .into_iter()
            .chain(self.notify.as_ref().map(|n| n.until))
        {
            target = Some(target.map_or(due, |t| t.min(due)));
        }
        if let Some(target) = target {
            self.timer.as_mut().reset(target);
            if self.timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
        Poll::Pending
    }
    /// Drive one bounded fair native turn. Fatal clock/storage errors physically
    /// stop every original MQ before returning; actual disk work still drains.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        until: Option<Instant>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        if self.yield_due {
            self.yield_due = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let result = self.poll_inner(cx, listeners, until, observe);
        if matches!(&result, Poll::Ready(Err(_))) {
            self.close_all(observe);
        }
        if matches!(&result, Poll::Ready(Ok(Progress::Activity))) {
            self.yield_due = true;
        }
        result
    }
    /// Caller-driven wrapper preserving original RX/TX/stream/worker cursors on
    /// cancellation. No hidden scheduler task or per-client thread is started.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        until: Option<Instant>,
        mut observe: impl FnMut(Event),
    ) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll(cx, listeners, until, &mut observe)).await
    }
    /// Close actual MQs first with no clock, consume the actual original worker
    /// receipt, and join the sole worker. A disk fsync can block; a socket grace
    /// never fabricates cancellation or bounded completion of filesystem calls.
    pub async fn shutdown(&mut self, mut observe: impl FnMut(Event)) -> Shutdown {
        self.close_all(&mut observe);
        drop(self.notify.take());
        let mut first = None;
        loop {
            match poll_fn(|cx| self.worker.poll(cx)).await {
                Ok(Some(c)) => {
                    if let Err(e) = self.completion(c, &mut observe)
                        && first.is_none()
                    {
                        first = Some(e);
                    }
                }
                Ok(None) => {
                    if let Some(p) = self.pending.take() {
                        if let Err(e) = self.core.unknown(&p.transaction) {
                            observe(Event::CleanupFailed(e));
                        }
                        if first.is_none() {
                            first = Some(Fault::OutcomeUnknown.into());
                        }
                    }
                    break;
                }
                Err(e) => {
                    if let Some(p) = self.pending.take()
                        && let Err(c) = self.core.unknown(&p.transaction)
                    {
                        observe(Event::CleanupFailed(c));
                    }
                    if first.is_none() {
                        first = Some(e.into());
                    }
                }
            }
        }
        let worker = match poll_fn(|cx| self.worker.poll_join(cx)).await {
            Ok(w) => Some(w),
            Err(e) => {
                if first.is_none() {
                    first = Some(e.into());
                }
                None
            }
        };
        Shutdown {
            report: self.report,
            worker,
            failure: first,
        }
    }
}
impl Drop for Server<'_> {
    fn drop(&mut self) {
        self.close_all(&mut |_| {});
    }
}

#[cfg(test)]
mod response_tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Fallible response setup with exact wire result assertions"
    )]
    use super::{Code, Fault, Item, Records, Response};
    use gnunet_namestore::SecretKey;
    use gnunet_wire::official::identity::{KEY_LEN, KeyType};

    #[test]
    fn reverse_miss_is_normal_no_results_with_original_authority() -> Result<(), Fault> {
        for kind in [KeyType::Ecdsa, KeyType::Eddsa] {
            // Synthetic structural source bytes, never a credential or a
            // cryptographic validity claim. No key generation is involved.
            let mut material = [0x42; KEY_LEN];
            material[..4].copy_from_slice(&kind.value().to_be_bytes());
            let item = Item::ReverseMissing {
                request: 0xfedc_ba98,
                zone: SecretKey::from_serialized(&material)?,
            };
            let mut frame = [0; 64];
            let length = item.response()?.encode(&mut frame)?;
            let Response::ZoneToName {
                rid,
                code,
                zone: Some(zone),
                label,
                records,
            } = Response::decode(&frame[..length])?
            else {
                return Err(Fault::Malformed);
            };
            assert_eq!(rid, 0xfedc_ba98);
            assert_eq!(code, 5010);
            assert!(zone.expose_serialized().iter().eq(material.iter()));
            assert!(label.is_none());
            assert_eq!(records.count(), 0);
            assert!(records.bytes().is_empty());
        }
        Ok(())
    }

    #[test]
    fn reverse_failure_words_remain_raw_failures() -> Result<(), Fault> {
        // Only the completed no-match Item changes. Actual producer failures,
        // including a reference peer's 5002, stay distinct and unnormalized.
        for raw in [
            Code::ZONE_NOT_FOUND.value(),
            Code::UNKNOWN.value(),
            Code::BACKEND_FAILED.value(),
            u32::MAX,
        ] {
            let response = Response::ZoneToName {
                rid: 17,
                code: raw,
                zone: None,
                label: None,
                records: Records::empty()?,
            };
            let mut frame = [0; 64];
            let length = response.encode(&mut frame)?;
            let Response::ZoneToName { rid, code, .. } = Response::decode(&frame[..length])? else {
                return Err(Fault::Malformed);
            };
            assert_eq!(rid, 17);
            assert_eq!(code, raw);
            assert_ne!(code, Code::NO_RESULTS.value());
            assert_ne!(code, Code::NONE.value());
        }
        Ok(())
    }
}
