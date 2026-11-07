//! Actual source ownership, FIFO snapshots and original durable mutation receipts.
use crate::{backend, worker};
use gnunet_identity::{Change, ChangeKind, Code, Core, Decision, Mutation, Snapshot, Transaction};
use gnunet_service_runtime::{
    accepted::{AcceptState, AcceptedConnection},
    clock::ClockSubscription,
    framing::{Accounting, Budget, Class, Framed, Limits as FrameLimits, OwnedFrame, ReadStep},
    service::{Listener, PeerAddress, ShutdownMode},
};
use gnunet_types::Error as Fault;
use gnunet_wire::official::identity::{Request, Response};
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
mod types;
pub use types::*;
#[derive(Clone, Copy)]
struct Origin {
    client: u64,
    write: u64,
}
enum Item {
    Initial {
        snapshot: Snapshot,
        index: usize,
    },
    Update {
        snapshot: Snapshot,
        index: usize,
        deleted: bool,
    },
    Code(Code),
}
impl Item {
    fn revision(&self) -> Option<u64> {
        match self {
            Self::Initial { snapshot, .. } | Self::Update { snapshot, .. } => {
                Some(snapshot.revision())
            }
            Self::Code(_) => None,
        }
    }
    fn response(&self) -> Result<Response<'_>, Fault> {
        match self {
            Self::Code(code) => Ok(Response::ResultCode { code: code.value() }),
            Self::Initial { snapshot, index } if *index == snapshot.egos().len() => {
                Ok(Response::EndOfList)
            }
            Self::Initial { snapshot, index }
            | Self::Update {
                snapshot,
                index,
                deleted: false,
            } => {
                let ego = snapshot.egos().get(*index).ok_or(Fault::Stale)?;
                Ok(Response::Update {
                    name: Some(ego.name()),
                    key: ego.key().view()?,
                })
            }
            Self::Update {
                snapshot,
                index,
                deleted: true,
            } => {
                let ego = snapshot.egos().get(*index).ok_or(Fault::Stale)?;
                Ok(Response::Update {
                    name: None,
                    key: ego.key().view()?,
                })
            }
        }
    }
    fn advance(&mut self) -> bool {
        match self {
            Self::Initial { snapshot, index } if *index < snapshot.egos().len() => {
                *index += 1;
                false
            }
            _ => true,
        }
    }
}
struct Peer {
    client: Client,
    io: Framed<Origin>,
    output: VecDeque<Item>,
    monitor: bool,
    first: bool,
    first_until: Instant,
    output_until: Option<Instant>,
    next_write: u64,
    input_until: Option<Instant>,
    read_first: bool,
}
struct Pending {
    transaction: Transaction,
    job: worker::Job,
    client: Client,
    kind: ChangeKind,
    until: Instant,
}
/// Actual caller-driven native server. One separately started Worker and one
/// process clock are supplied explicitly. No hidden thread/task/Resolver exists.
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
    accept: AcceptState,
    subscription: Box<dyn ClockSubscription>,
    revision: u64,
    timer: Pin<Box<Sleep>>,
    class: usize,
    cursor: usize,
    listener_cursor: usize,
    revisions: Vec<u64>,
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
        if self.clients == 0
            || self.clients > 1024
            || self.output_items == 0
            || self.output_items > 4096
            || self.retained_versions < 2
            || self.retained_versions > 4096
            || self.snapshot_body_bytes < 12
            || self.snapshot_body_bytes > 64 * 1024 * 1024
        {
            return Err(Fault::Capacity);
        }
        self.clients
            .checked_mul(self.output_items)
            .and_then(|n| n.checked_add(1))
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
    /// Recover actual marked-store bytes into the pure canonical inventory.
    /// Failure publishes no service or successful initialization.
    pub fn recover(
        store: &mut backend::Store,
        loaded: backend::Loaded,
        limits: gnunet_identity::Limits,
    ) -> Result<(Core, u64), Error> {
        if loaded.namespace() != backend::Namespace::Identity
            || store.namespace() != backend::Namespace::Identity
            || store.generation() != loaded.generation()
        {
            return Err(Fault::Authentication.into());
        }
        let mut generation = loaded.generation();
        let created = loaded.created_directory();
        let body = loaded.into_body();
        if generation == 0 && !created {
            return Err(Fault::OutcomeUnknown.into());
        }
        if (generation == 0) != body.is_empty() {
            return Err(Fault::Storage.into());
        }
        let initial = snapshot::decode(body, limits)?;
        let core = Core::new(limits, initial)?;
        if generation == 0 {
            // No await/cancellation split after the actual new-root receipt.
            // Commit the legal empty business image under this same Store lease
            // before any worker or ready owner can expose an empty inventory.
            let image = snapshot::encode(&core.snapshot(), limits.snapshot_bytes)?;
            let committed = store.commit(0, image).map_err(Error::Storage)?;
            if committed.namespace() != backend::Namespace::Identity
                || committed.generation() != 1
                || store.generation() != 1
            {
                return Err(Fault::OutcomeUnknown.into());
            }
            generation = committed.generation();
        }
        Ok((core, generation))
    }
    /// Consume the actual pure inventory and borrow its separately started worker.
    /// Validation/allocation performs no socket operation or worker creation.
    pub fn new(
        core: Core,
        worker: &'worker mut worker::Worker,
        generation: u64,
        limits: Limits,
        ports: Ports,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if worker.namespace() != backend::Namespace::Identity {
            return Err(Fault::Authentication.into());
        }
        let sample = ports.clock.sample().map_err(Error::Clock)?;
        let subscription = ports.clock.subscribe().map_err(Error::Clock)?;
        let mut peers = Vec::new();
        peers
            .try_reserve_exact(limits.clients)
            .map_err(|_| Fault::Capacity)?;
        peers.resize_with(limits.clients, || None);
        let mut revisions = Vec::new();
        revisions
            .try_reserve_exact(limits.clients * limits.output_items + 1)
            .map_err(|_| Fault::Capacity)?;
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
            accept: AcceptState::default(),
            subscription,
            revision: sample.revision,
            timer: Box::pin(tokio::time::sleep(std::time::Duration::ZERO)),
            class: 0,
            cursor: 0,
            listener_cursor: 0,
            revisions,
            report: Report::default(),
            shutdown: None,
            yield_due: false,
        })
    }
    /// Public current source/mutation counters; no key/name/snapshot diagnostics.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.report
    }
    /// Canonical acceptance and access policy precede private frame allocation.
    pub fn admit(
        &mut self,
        accepted: AcceptedConnection,
        observe: &mut impl FnMut(Event),
    ) -> Result<Option<Client>, Error> {
        let (connection, address, diagnostics) = accepted.into_parts();
        for diagnostic in diagnostics {
            observe(Event::Socket(
                gnunet_service_runtime::accepted::SocketEvent::Diagnostic(diagnostic),
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
        let first_until = Instant::now()
            .checked_add(self.limits.first_input)
            .ok_or(Fault::Overflow)?;
        let serial = self.next_client.checked_add(1).ok_or(Fault::Overflow)?;
        let mut output = VecDeque::new();
        output
            .try_reserve_exact(self.limits.output_items)
            .map_err(|_| Fault::Capacity)?;
        let io = Framed::new(connection, self.limits.framing())?;
        let client = Client {
            domain: self.domain.clone(),
            serial,
        };
        self.next_client = serial;
        self.peers[index] = Some(Peer {
            client: client.clone(),
            io,
            output,
            monitor: false,
            first: true,
            first_until,
            output_until: None,
            next_write: 0,
            input_until: None,
            read_first: false,
        });
        self.report.accepted = self.report.accepted.saturating_add(1);
        observe(Event::Accepted(client.clone()));
        Ok(Some(client))
    }
    fn close_index(&mut self, index: usize, cause: CloseCause, observe: &mut impl FnMut(Event)) {
        if let Some(mut peer) = self.peers[index].take() {
            peer.io.retire(); // physical original socket fence first, no clock.
            peer.output.clear();
            self.accept.client_closed();
            self.report.closed = self.report.closed.saturating_add(1);
            observe(Event::Closed {
                client: peer.client,
                cause,
            });
        }
    }
    /// Physically retire this exact original source; an admitted mutation keeps
    /// its original worker/transaction through the actual persistence outcome.
    pub fn close(&mut self, client: &Client, observe: &mut impl FnMut(Event)) -> Result<(), Error> {
        let i = self
            .peers
            .iter()
            .position(|p| p.as_ref().is_some_and(|p| p.client == *client))
            .ok_or(Fault::Stale)?;
        self.close_index(i, CloseCause::Shutdown, observe);
        Ok(())
    }
    /// Independent actual source closure without consulting clock/Resolver ports.
    pub fn close_all(&mut self, observe: &mut impl FnMut(Event)) {
        self.shutdown = Some(ShutdownMode::Immediate);
        self.worker.request_stop();
        for i in 0..self.peers.len() {
            self.close_index(i, CloseCause::Shutdown, observe);
        }
    }
    /// Stop admission, preserving original FIFO/debt. Soft closes idle monitors
    /// and waits existing finite source/mutation output; outer owner sets grace.
    pub fn request_shutdown(&mut self, mode: ShutdownMode) {
        if self.shutdown != Some(ShutdownMode::Immediate) {
            self.shutdown = Some(mode);
        }
    }
    fn queue(&mut self, i: usize, item: Item, observe: &mut impl FnMut(Event)) -> bool {
        let Some(peer) = self.peers[i].as_mut() else {
            return false;
        };
        if peer.output.len() >= self.limits.output_items {
            self.close_index(i, CloseCause::Capacity, observe);
            return false;
        }
        if peer.output_until.is_none() {
            let Some(until) = Instant::now().checked_add(self.limits.output_lifetime) else {
                self.close_index(i, CloseCause::Deadline, observe);
                return false;
            };
            peer.output_until = Some(until);
        }
        peer.output.push_back(item);
        true
    }
    fn result(&mut self, i: usize, code: Code, observe: &mut impl FnMut(Event)) {
        let client = self.peers[i].as_ref().map(|p| p.client.clone());
        if self.queue(i, Item::Code(code), observe)
            && let Some(client) = client
        {
            observe(Event::Result { client, code });
        }
    }
    fn release(&mut self, i: usize) -> Result<(), Error> {
        if !self.peers[i]
            .as_mut()
            .ok_or(Fault::Stale)?
            .io
            .release_frame()
        {
            return Err(Fault::Stale.into());
        }
        self.peers[i].as_mut().ok_or(Fault::Stale)?.input_until = None;
        Ok(())
    }
    fn process(&mut self, i: usize, observe: &mut impl FnMut(Event)) -> Result<bool, Error> {
        let peer = self.peers[i].as_ref().ok_or(Fault::Stale)?;
        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.client == peer.client)
        {
            return Ok(false);
        }
        let input = peer.io.frame().ok_or(Fault::NotReady)?;
        let request = match Request::decode(input) {
            Ok(r) => r,
            Err(Fault::Unsupported) if self.ports.options.tolerant => {
                self.release(i)?;
                return Ok(true);
            }
            Err(e) => return Err(e.into()),
        };
        match request {
            Request::Start => {
                let current = self.core.snapshot();
                if let Some(peer) = self.peers[i].as_mut() {
                    peer.monitor = true;
                    peer.first = false;
                }
                self.queue(
                    i,
                    Item::Initial {
                        snapshot: current,
                        index: 0,
                    },
                    observe,
                );
            }
            Request::Lookup { name } | Request::LookupSuffix { name } => {
                let suffix = matches!(request, Request::LookupSuffix { .. });
                let found = self.core.lookup(name, suffix)?;
                if let Some(index) = found {
                    let current = self.core.snapshot();
                    self.queue(
                        i,
                        Item::Update {
                            snapshot: current,
                            index,
                            deleted: false,
                        },
                        observe,
                    );
                } else {
                    self.result(i, Code::NOT_FOUND, observe);
                }
            }
            Request::Create { name, key } => {
                if self.pending.is_some() {
                    return Ok(false);
                }
                let decision = self.core.begin(Mutation::Create { name, key })?;
                self.mutation(i, decision, observe)?;
            }
            Request::Rename { old, new } => {
                if self.pending.is_some() {
                    return Ok(false);
                }
                let decision = self.core.begin(Mutation::Rename { old, new })?;
                self.mutation(i, decision, observe)?;
            }
            Request::Delete { name } => {
                if self.pending.is_some() {
                    return Ok(false);
                }
                let decision = self.core.begin(Mutation::Delete { name })?;
                self.mutation(i, decision, observe)?;
            }
        }
        if let Some(peer) = self.peers[i].as_mut() {
            peer.first = false;
        }
        if self.peers[i].is_some() {
            self.release(i)?;
        }
        self.enforce_versions(observe);
        Ok(true)
    }
    fn mutation(
        &mut self,
        i: usize,
        decision: Decision,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Error> {
        let transaction = match decision {
            Decision::Immediate(code) => {
                self.result(i, code, observe);
                return Ok(());
            }
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
        let until = match Instant::now().checked_add(self.limits.storage_lifetime) {
            Some(u) => u,
            None => {
                let _abort = self.core.abort(&transaction, Code::UNKNOWN);
                return Err(Fault::Overflow.into());
            }
        };
        let job = match self.worker.submit(self.generation, body) {
            Ok(job) => job,
            Err((error, _body)) => {
                if let Err(cleanup) = self.core.abort(&transaction, Code::UNKNOWN) {
                    observe(Event::CleanupFailed(cleanup));
                }
                return Err(error.into());
            }
        };
        let client = self.peers[i].as_ref().ok_or(Fault::Stale)?.client.clone();
        self.pending = Some(Pending {
            transaction,
            job: job.clone(),
            client: client.clone(),
            kind,
            until,
        });
        self.core
            .queued(&self.pending.as_ref().ok_or(Fault::Stale)?.transaction)?;
        self.report.submitted = self.report.submitted.saturating_add(1);
        observe(Event::StorageQueued { client, job, kind });
        Ok(())
    }
    fn apply_change(
        &mut self,
        p: Pending,
        change: Change,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Error> {
        let owner = self
            .peers
            .iter()
            .position(|peer| peer.as_ref().is_some_and(|peer| peer.client == p.client));
        if matches!(change.kind, ChangeKind::Create)
            && let Some(i) = owner
        {
            self.result(i, Code::NONE, observe);
        }
        let (snapshot, index, deleted) = match change.kind {
            ChangeKind::Create | ChangeKind::Rename => {
                (change.after, change.after_index.ok_or(Fault::Stale)?, false)
            }
            ChangeKind::Delete => (
                change.before,
                change.before_index.ok_or(Fault::Stale)?,
                true,
            ),
        };
        for i in 0..self.peers.len() {
            if self.peers[i].as_ref().is_some_and(|peer| peer.monitor) {
                self.queue(
                    i,
                    Item::Update {
                        snapshot: snapshot.clone(),
                        index,
                        deleted,
                    },
                    observe,
                );
            }
        }
        if !matches!(p.kind, ChangeKind::Create)
            && let Some(i) = self
                .peers
                .iter()
                .position(|peer| peer.as_ref().is_some_and(|peer| peer.client == p.client))
        {
            self.result(i, Code::NONE, observe);
        }
        self.enforce_versions(observe);
        Ok(())
    }
    fn completion(
        &mut self,
        c: worker::Completion,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Error> {
        let (job, result) = c.into_parts();
        let p = self.pending.take().ok_or(Fault::Stale)?;
        if job != p.job {
            self.pending = Some(p);
            return Err(Fault::Stale.into());
        }
        match result {
            Ok(committed) => {
                let expected = self.generation.checked_add(1).ok_or(Fault::Overflow)?;
                if committed.generation() != expected {
                    self.pending = Some(p);
                    return Err(Fault::OutcomeUnknown.into());
                }
                self.generation = expected;
                let change = match self.core.commit(&p.transaction) {
                    Ok(change) => change,
                    Err(error) => {
                        if let Err(cleanup) = self.core.unknown(&p.transaction) {
                            observe(Event::CleanupFailed(cleanup));
                        }
                        return Err(error.into());
                    }
                };
                self.report.committed = self.report.committed.saturating_add(1);
                observe(Event::Committed {
                    job,
                    generation: expected,
                    kind: p.kind,
                });
                self.apply_change(p, change, observe)
            }
            Err(failure) => {
                let settled = if failure.exposure == backend::Exposure::Unknown {
                    self.core.unknown(&p.transaction)
                } else {
                    self.core.abort(&p.transaction, Code::UNKNOWN).map(|_| ())
                };
                if let Err(error) = settled {
                    observe(Event::CleanupFailed(error));
                }
                observe(Event::StorageFailed(failure.clone()));
                Err(Error::Storage(failure))
            }
        }
    }
    fn enforce_versions(&mut self, observe: &mut impl FnMut(Event)) {
        loop {
            self.revisions.clear();
            self.revisions.push(self.core.snapshot().revision());
            for peer in self.peers.iter().flatten() {
                for item in &peer.output {
                    if let Some(revision) = item.revision()
                        && !self.revisions.contains(&revision)
                    {
                        self.revisions.push(revision);
                    }
                }
            }
            if self.revisions.len() <= self.limits.retained_versions {
                return;
            }
            let oldest = self.revisions.iter().copied().min();
            let index = self.peers.iter().position(|peer| {
                peer.as_ref()
                    .is_some_and(|peer| peer.output.iter().any(|item| item.revision() == oldest))
            });
            let Some(i) = index else {
                return;
            };
            self.close_index(i, CloseCause::Capacity, observe);
        }
    }
    fn prepare(&mut self, i: usize, observe: &mut impl FnMut(Event)) -> Result<bool, Error> {
        let peer = self.peers[i].as_mut().ok_or(Fault::Stale)?;
        let Some(front) = peer.output.front() else {
            return Ok(false);
        };
        let response = front.response()?;
        let size = response.encoded_len()?;
        if !peer.io.capacity(size, Class::Ordinary) {
            return Ok(false);
        }
        peer.io.reserve(size, Class::Ordinary)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.try_reserve_exact(size).map_err(|_| Fault::Capacity)?;
        bytes.resize(size, 0);
        response.encode(&mut bytes)?;
        let write = peer.next_write.checked_add(1).ok_or(Fault::Overflow)?;
        let frame = OwnedFrame::new(core::mem::take(&mut *bytes));
        peer.io
            .enqueue_owned(
                frame,
                Origin {
                    client: peer.client.serial,
                    write,
                },
                Class::Ordinary,
            )
            .map_err(|e| e.reason)?;
        peer.next_write = write;
        if peer.output.front_mut().is_some_and(Item::advance) {
            drop(peer.output.pop_front());
        }
        observe(Event::Queued {
            client: peer.client.clone(),
            write,
        });
        Ok(true)
    }
    fn peer(
        &mut self,
        cx: &mut Context<'_>,
        i: usize,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        let now = Instant::now();
        let peer = self.peers[i].as_ref().ok_or(Fault::Stale)?;
        if peer.first && now >= peer.first_until
            || peer.output_until.is_some_and(|until| now >= until)
            || peer.input_until.is_some_and(|until| now >= until)
        {
            self.close_index(i, CloseCause::Deadline, observe);
            return Poll::Ready(Ok(Progress::Activity));
        }
        if self.shutdown.is_some()
            && peer.output.is_empty()
            && peer.io.queued_frames() == 0
            && !self
                .pending
                .as_ref()
                .is_some_and(|p| p.client == peer.client)
        {
            self.close_index(i, CloseCause::Shutdown, observe);
            return Poll::Ready(Ok(Progress::Activity));
        }
        if let Err(error) = self.prepare(i, observe) {
            let cause = match error {
                Error::Protocol(e) => CloseCause::Protocol(e),
                Error::Io(e) => CloseCause::Io(e),
                other => return Poll::Ready(Err(other)),
            };
            self.close_index(i, cause, observe);
            return Poll::Ready(Ok(Progress::Activity));
        }
        let read_first = self.peers[i].as_ref().ok_or(Fault::Stale)?.read_first;
        for direction in 0..2 {
            let reading = (direction == 0) == read_first;
            let step = if reading {
                self.read_peer(cx, i, observe)
            } else {
                self.write_peer(cx, i, observe)
            };
            if step.is_ready() {
                if let Some(peer) = self.peers[i].as_mut() {
                    peer.read_first = !reading;
                }
                return step;
            }
        }
        Poll::Pending
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
            Poll::Ready(Err(e)) => {
                self.close_index(i, CloseCause::Io(e), observe);
                Poll::Ready(Ok(Progress::Activity))
            }
            Poll::Ready(Ok(p)) => {
                let peer = self.peers[i].as_mut().ok_or(Fault::Stale)?;
                if p.origin.client != peer.client.serial {
                    return Poll::Ready(Err(Fault::Stale.into()));
                }
                if p.complete {
                    self.report.written = self.report.written.saturating_add(1);
                    observe(Event::Written {
                        client: peer.client.clone(),
                        write: p.origin.write,
                    });
                }
                if peer.output.is_empty() && peer.io.queued_frames() == 0 {
                    peer.output_until = None;
                }
                Poll::Ready(Ok(Progress::Activity))
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn read_peer(
        &mut self,
        cx: &mut Context<'_>,
        i: usize,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        if self.shutdown.is_some() {
            return Poll::Pending;
        }
        let ready = self.peers[i]
            .as_ref()
            .is_some_and(|p| p.io.frame().is_some());
        if ready {
            return match self.process(i, observe) {
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
                let peer = self.peers[i].as_mut().ok_or(Fault::Stale)?;
                if complete {
                    peer.first = false;
                }
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
            let result = listeners[i].poll_canonical_connection(cx);
            match result {
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
            return Poll::Ready(Ok(Progress::Stopped));
        }
        if until.is_some_and(|u| Instant::now() >= u) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        for n in 0..3 {
            let class = (self.class + n) % 3;
            let result = match class {
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
                1 => {
                    let mut result = Poll::Pending;
                    for n in 0..self.peers.len() {
                        let i = (self.cursor + n) % self.peers.len();
                        if self.peers[i].is_some() {
                            let p = self.peer(cx, i, observe);
                            if p.is_ready() {
                                self.cursor = (i + 1) % self.peers.len();
                                result = p;
                                break;
                            }
                        }
                    }
                    result
                }
                _ => self.accept(cx, listeners, observe),
            };
            if result.is_ready() {
                self.class = (class + 1) % 3;
                return result;
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
        if let Some(p) = &self.pending {
            target = Some(target.map_or(p.until, |t| t.min(p.until)));
        }
        if let Some(target) = target {
            self.timer.as_mut().reset(target);
            if self.timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
        Poll::Pending
    }
    /// One bounded cancellation-safe native turn. Clock/storage errors physically
    /// close every original MQ before returning the original error; no clock is
    /// needed by this independent close path.
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
    /// Wait only by polling this same original owner; dropping the future keeps
    /// all RX/TX/cursor/worker/transaction identities and original hard targets.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        until: Option<Instant>,
        mut observe: impl FnMut(Event),
    ) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll(cx, listeners, until, &mut observe)).await
    }
    /// Close actual MQs first, drain the actual original disk result and then
    /// join its sole worker. No secret-bearing response is queued after closure.
    pub async fn shutdown(&mut self, mut observe: impl FnMut(Event)) -> Shutdown {
        self.close_all(&mut observe);
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
                        if let Err(cleanup) = self.core.unknown(&p.transaction) {
                            observe(Event::CleanupFailed(cleanup));
                        }
                        if first.is_none() {
                            first = Some(Fault::OutcomeUnknown.into());
                        }
                    }
                    break;
                }
                Err(e) => {
                    if let Some(p) = self.pending.take()
                        && let Err(cleanup) = self.core.unknown(&p.transaction)
                    {
                        observe(Event::CleanupFailed(cleanup));
                    }
                    if first.is_none() {
                        first = Some(e.into());
                    }
                }
            }
        }
        let worker = match poll_fn(|cx| self.worker.poll_join(cx)).await {
            Ok(r) => Some(r),
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
