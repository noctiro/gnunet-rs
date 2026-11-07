//! Bounded accepted MQ owner and original verification/persistence composition.
use crate::{Inventory, inventory::Planned, verification};
use gnunet_revocation::{Certificate, RevocationConfig, ipc};
use gnunet_service_runtime::{
    accepted::{AcceptState, AcceptedConnection},
    clock::{ClockSubscription, Deadline},
    framing::{Accounting, Budget, Class, Framed, Limits as FrameLimits, ReadStep},
    service::{Listener, PeerAddress, ShutdownMode},
};
use gnunet_snapshot_host::{
    Namespace,
    backend::{Exposure, Loaded, Store},
    worker::{self, Worker as Storage},
};
use gnunet_types::Error as Fault;
use std::{
    collections::VecDeque,
    future::{Future, poll_fn},
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
mod network;
mod types;
pub use network::{Instances, NetworkEvent, Sources};
pub use types::*;
#[derive(Clone)]
enum Origin<'id> {
    App {
        client: Client,
        request: u64,
    },
    Core {
        epoch: gnunet_core_client_host::ConnectionEpoch<'id>,
        peer: [u8; 32],
    },
    Union {
        epoch: gnunet_setu_client_host::Epoch<'id>,
        operation: gnunet_setu_client_host::Operation<'id>,
        serial: u64,
    },
}
struct Candidate<'id> {
    certificate: Certificate,
    origin: Origin<'id>,
    until: u64,
    hard: Instant,
}
#[derive(Clone, Copy)]
struct Bound {
    until: u64,
    hard: Instant,
}
#[derive(Clone, Copy)]
struct Write {
    client: u64,
    request: u64,
    response: ipc::Response,
}
struct Peer {
    client: Client,
    io: Framed<Write>,
    next_request: u64,
    busy: Option<u64>,
    first: bool,
    first_bound: Bound,
    input: Option<Bound>,
    output: Option<Bound>,
}
struct Checking<'id> {
    job: verification::Job,
    retired: bool,
    candidate: Candidate<'id>,
}
struct Storing<'id> {
    job: worker::Job,
    origin: Origin<'id>,
    planned: Planned,
    expected: u64,
    bound: Bound,
}
/// Real accepted IPC service. Explicit recovery/start may create exactly one
/// verifier and one snapshot worker; poll creates no hidden task or Resolver.
pub struct Server<'id> {
    inventory: Inventory,
    policy: RevocationConfig,
    limits: Limits,
    ports: Ports,
    network: network::Network<'id>,
    storage: Storage,
    verifier: verification::Worker,
    checking: Option<Checking<'id>>,
    storing: Option<Storing<'id>>,
    peers: Vec<Option<Peer>>,
    candidates: VecDeque<Candidate<'id>>,
    domain: Rc<Domain>,
    next_client: u64,
    accept: AcceptState,
    subscription: Box<dyn ClockSubscription>,
    revision: u64,
    alarm: Option<Pin<Box<Deadline>>>,
    alarm_at: Option<u64>,
    native: Pin<Box<Sleep>>,
    tick: Instant,
    cursor: usize,
    turn: u8,
    accept_first: bool,
    network_first: bool,
    stopping: Option<ShutdownMode>,
    failure: Option<Error>,
    network_failure: Option<Error>,
    report: Report,
    yield_due: bool,
}
fn plus(at: Instant, d: Duration) -> Result<Instant, Error> {
    at.checked_add(d).ok_or_else(|| Fault::Overflow.into())
}
fn bound(now: u64, d: Duration) -> Result<Bound, Error> {
    Ok(Bound {
        until: now
            .checked_add(u64::try_from(d.as_micros()).map_err(|_| Fault::Overflow)?)
            .filter(|n| *n != u64::MAX)
            .ok_or(Fault::Overflow)?,
        hard: plus(Instant::now(), d)?,
    })
}
fn frame_limits(limits: Limits) -> FrameLimits {
    FrameLimits {
        frame_bytes: ipc::REVOKE_BYTES,
        ordinary: Budget {
            frames: 1,
            bytes: ipc::RESPONSE_BYTES,
        },
        reserved: Budget::default(),
        accounting: Accounting::Retained,
        io_slice_bytes: limits.io_slice_bytes,
    }
}
impl<'id> Server<'id> {
    /// Actual marked namespace recovery and explicit owned worker start. All
    /// inputs are caller-owned; old C/unmarked DB files are never opened here.
    /// Apply UID/GID before invoking. Construction grants no network readiness.
    pub fn recover(
        mut store: Store,
        loaded: Loaded,
        instances: Instances<'id>,
        sources: Sources,
        policy: RevocationConfig,
        limits: Limits,
        ports: Ports,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if policy.matching_bits >= 512
            || policy.epoch_duration == 0
            || store.namespace() != Namespace::Revocation
            || loaded.namespace() != Namespace::Revocation
            || store.generation() != loaded.generation()
        {
            return Err(Fault::Authentication.into());
        }
        let mut inventory = Inventory::recover(loaded, limits.certificates, limits.snapshot_bytes)?;
        // Commit even the initial empty inventory before publishing this owner.
        // An existing marked root without its canonical image must fail closed.
        if inventory.generation == 0 {
            let image = inventory.image(&[])?;
            let committed = store.commit(0, image).map_err(Error::Storage)?;
            if committed.namespace() != Namespace::Revocation || committed.generation() != 1 {
                return Err(Fault::OutcomeUnknown.into());
            }
            inventory.generation = committed.generation();
        }
        let order = sources.core_order;
        let network = network::Network::new(instances, sources, limits, order)?;
        if !std::sync::Arc::ptr_eq(&ports.clock, &network.clock()) {
            return Err(Fault::Conflict.into());
        }
        let subscription = ports.clock.subscribe().map_err(Error::Clock)?;
        let sample = ports.clock.sample().map_err(Error::Clock)?;
        let mut peers = Vec::new();
        peers
            .try_reserve_exact(limits.clients)
            .map_err(|_| Fault::Capacity)?;
        peers.resize_with(limits.clients, || None);
        let mut candidates = VecDeque::new();
        candidates
            .try_reserve_exact(limits.network_inputs)
            .map_err(|_| Fault::Capacity)?;
        let storage = Storage::start(store)?;
        let verifier = verification::Worker::start(ports.clock.clone(), policy)?;
        let tick = plus(Instant::now(), limits.tick)?;
        Ok(Self {
            inventory,
            policy,
            limits,
            ports,
            network,
            storage,
            verifier,
            checking: None,
            storing: None,
            peers,
            candidates,
            domain: Rc::new(Domain),
            next_client: 0,
            accept: AcceptState::default(),
            subscription,
            revision: sample.revision,
            alarm: None,
            alarm_at: None,
            native: Box::pin(tokio::time::sleep_until(tick)),
            tick,
            cursor: 0,
            turn: 0,
            accept_first: false,
            network_first: false,
            stopping: None,
            failure: None,
            network_failure: None,
            report: Report::default(),
            yield_due: false,
        })
    }
    /// Actual committed permanent inventory, not pending verification/admission.
    pub fn inventory(&self) -> &Inventory {
        &self.inventory
    }
    /// Original actual CORE/SETU callbacks for the official statistics owner.
    /// Snapshotting admits no work and confers no remote/durable receipt.
    pub fn metrics(&self) -> Metrics {
        self.network.metrics()
    }
    /// Actual original source/worker counters.
    pub const fn report(&self) -> Report {
        self.report
    }
    /// Actual AcceptedConnection goes through canonical TCP ACL/kernel UID policy
    /// before frame/pool admission. No source is retagged by descriptor reuse.
    pub fn admit(
        &mut self,
        accepted: AcceptedConnection,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<Option<Client>, Error> {
        let (connection, address, diagnostics) = accepted.into_parts();
        for diagnostic in diagnostics {
            observe(Event::Socket(
                gnunet_service_runtime::accepted::SocketEvent::Diagnostic(diagnostic),
            ))
        }
        let allowed = match address {
            PeerAddress::Tcp(p) => self.ports.options.access.allows(p.ip()),
            PeerAddress::Unix => match self.ports.unix.allows(&connection) {
                Ok(allowed) => allowed,
                Err(e) => {
                    drop(connection);
                    return Err(e.into());
                }
            },
        };
        if !allowed || self.stopping.is_some() {
            drop(connection);
            observe(Event::Rejected(address));
            return Ok(None);
        }
        let Some(index) = self.peers.iter().position(Option::is_none) else {
            drop(connection);
            observe(Event::Capacity);
            return Ok(None);
        };
        let now = match self.ports.clock.sample() {
            Ok(sample) => sample.now.as_micros(),
            Err(error) => {
                drop(connection);
                self.abort(CloseCause::Clock, observe);
                return Err(Error::Clock(error));
            }
        };
        let first_bound = bound(now, self.limits.first_input)?;
        let serial = self.next_client.checked_add(1).ok_or(Fault::Overflow)?;
        let io = Framed::new(connection, frame_limits(self.limits))?;
        let client = Client {
            domain: self.domain.clone(),
            serial,
        };
        self.next_client = serial;
        self.peers[index] = Some(Peer {
            client: client.clone(),
            io,
            next_request: 0,
            busy: None,
            first: true,
            first_bound,
            input: None,
            output: None,
        });
        self.report.accepted = self.report.accepted.saturating_add(1);
        observe(Event::Accepted(client.clone()));
        Ok(Some(client))
    }
    fn index(&self, client: &Client) -> Option<usize> {
        self.peers
            .iter()
            .position(|p| p.as_ref().is_some_and(|p| &p.client == client))
    }
    fn close_index(
        &mut self,
        index: usize,
        cause: CloseCause,
        observe: &mut impl FnMut(Event<'id>),
    ) {
        if let Some(mut peer) = self.peers[index].take() {
            peer.io.retire();
            self.accept.client_closed();
            if let Some(checking) = &mut self.checking
                && matches!(&checking.candidate.origin,Origin::App{client,..} if client==&peer.client)
            {
                checking.retired = true;
                let _canceled = self.verifier.cancel(&checking.job);
            }
            self.report.closed = self.report.closed.saturating_add(1);
            observe(Event::Closed(peer.client, cause));
        }
    }
    /// Close only this original accepted MQ, independent of all clock ports.
    pub fn close_client(
        &mut self,
        client: &Client,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        let index = self.index(client).ok_or(Fault::Stale)?;
        self.close_index(index, CloseCause::Shutdown, observe);
        Ok(())
    }
    fn queue_response(
        &mut self,
        client: &Client,
        request: u64,
        response: ipc::Response,
        now: Option<u64>,
    ) -> Result<(), Error> {
        let Some(index) = self.index(client) else {
            return Ok(());
        };
        let peer = self.peers[index].as_mut().ok_or(Fault::Stale)?;
        if peer.busy.is_some_and(|old| old != request) {
            return Err(Fault::Stale.into());
        }
        peer.io.reserve(ipc::RESPONSE_BYTES, Class::Ordinary)?;
        let mut frame = Vec::new();
        frame
            .try_reserve_exact(ipc::RESPONSE_BYTES)
            .map_err(|_| Fault::Capacity)?;
        frame.resize(ipc::RESPONSE_BYTES, 0);
        response.encode(&mut frame)?;
        let output = bound(now.ok_or(Fault::NotReady)?, self.limits.output_lifetime)?;
        peer.io
            .enqueue_owned(
                gnunet_service_runtime::framing::OwnedFrame::new(frame),
                Write {
                    client: client.serial,
                    request,
                    response,
                },
                Class::Ordinary,
            )
            .map_err(|r| Error::Fault(r.reason))?;
        peer.busy = None;
        peer.output = Some(output);
        Ok(())
    }
    fn reply_origin(
        &mut self,
        origin: &Origin<'id>,
        response: ipc::Response,
        now: Option<u64>,
    ) -> Result<(), Error> {
        if let Origin::App { client, request } = origin {
            self.queue_response(client, *request, response, now)?
        }
        Ok(())
    }
    fn invalid_origin(
        &mut self,
        origin: &Origin<'id>,
        cause: Fault,
        observe: &mut impl FnMut(Event<'id>),
    ) {
        if let Origin::App { client, .. } = origin
            && let Some(index) = self.index(client)
        {
            self.close_index(index, CloseCause::Protocol(cause), observe)
        }
    }
    fn admit_check(
        &mut self,
        candidate: Candidate<'id>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        if self.storing.is_some()
            || self.checking.is_some()
            || !self.verifier.available()
            || self.inventory.blocked
        {
            return Ok(false);
        }
        let job = self
            .verifier
            .submit(
                candidate.certificate.clone(),
                candidate.until,
                candidate.hard,
            )
            .map_err(|r| Error::Fault(r.reason))?;
        self.report.verification_jobs = self.report.verification_jobs.saturating_add(1);
        observe(Event::VerificationQueued(job.clone()));
        observe(Event::Input(match &candidate.origin {
            Origin::App { client, request } => InputSource::Application(client.clone(), *request),
            Origin::Core { epoch, peer } => InputSource::Core(*epoch, *peer),
            Origin::Union {
                epoch,
                operation,
                serial,
            } => InputSource::Union(*epoch, *operation, *serial),
        }));
        self.checking = Some(Checking {
            job,
            retired: false,
            candidate,
        });
        self.network_first = !self.network_first;
        Ok(true)
    }
    fn admit_network(
        &mut self,
        now: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        if self.checking.is_some()
            || self.storing.is_some()
            || self.inventory.blocked
            || self.stopping.is_some()
        {
            return Ok(false);
        }
        while let Some(candidate) = self.candidates.pop_front() {
            if Instant::now() >= candidate.hard || now >= candidate.until {
                continue;
            }
            if self
                .inventory
                .revoked(candidate.certificate.proof()?.public()?)
            {
                continue;
            }
            return self.admit_check(candidate, observe);
        }
        Ok(false)
    }
    fn complete_check(
        &mut self,
        completion: verification::Completion,
        now: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        let checking = self.checking.take().ok_or(Fault::Stale)?;
        let (job, outcome) = completion.into_parts();
        if job != checking.job {
            return Err(Fault::Stale.into());
        }
        if let Origin::App { client, .. } = &checking.candidate.origin
            && self.index(client).is_none()
        {
            return Ok(());
        }
        match outcome {
            verification::Outcome::Checked(checked) => {
                observe(Event::Checked(job));
                if self
                    .inventory
                    .revoked(checked.certificate().proof()?.public()?)
                {
                    return self.reply_origin(
                        &checking.candidate.origin,
                        ipc::Response::Revoke(0),
                        Some(now),
                    );
                }
                if Instant::now() >= checking.candidate.hard || now >= checking.candidate.until {
                    self.invalid_origin(&checking.candidate.origin, Fault::Deadline, observe);
                    return Ok(());
                }
                let planned = match self.inventory.plan(*checked, self.policy, now) {
                    Ok(plan) => plan,
                    Err(Fault::Capacity) => {
                        self.reply_origin(
                            &checking.candidate.origin,
                            ipc::Response::Revoke(1),
                            Some(now),
                        )?;
                        observe(Event::Capacity);
                        return Ok(());
                    }
                    Err(e) => {
                        self.invalid_origin(&checking.candidate.origin, e, observe);
                        return Ok(());
                    }
                };
                let image = self.inventory.image(&planned.records)?;
                let expected = self.inventory.generation;
                let job = self
                    .storage
                    .submit(expected, image)
                    .map_err(|(e, _)| Error::Fault(e))?;
                observe(Event::StoreQueued(job.clone()));
                self.storing = Some(Storing {
                    job,
                    origin: checking.candidate.origin,
                    planned,
                    expected,
                    bound: Bound {
                        until: checking.candidate.until,
                        hard: checking.candidate.hard,
                    },
                });
            }
            verification::Outcome::Clock(e) => return Err(Error::Clock(e)),
            verification::Outcome::Fault(e) => {
                self.invalid_origin(&checking.candidate.origin, e, observe)
            }
            verification::Outcome::Invalid => {
                self.invalid_origin(&checking.candidate.origin, Fault::Authentication, observe)
            }
            verification::Outcome::Deadline | verification::Outcome::Cancelled => {
                self.invalid_origin(&checking.candidate.origin, Fault::Deadline, observe)
            }
        }
        Ok(())
    }
    fn complete_store(
        &mut self,
        completion: worker::Completion,
        now: Option<u64>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        let pending = self.storing.take().ok_or(Fault::Stale)?;
        let (job, result) = completion.into_parts();
        if job != pending.job || job.namespace() != Namespace::Revocation {
            return Err(Fault::Stale.into());
        }
        match result {
            Ok(committed) => {
                let expected = pending.expected.checked_add(1).ok_or(Fault::Overflow)?;
                if committed.namespace() != Namespace::Revocation
                    || committed.generation() != expected
                {
                    return Err(Fault::OutcomeUnknown.into());
                }
                self.inventory.publish(pending.planned)?;
                self.inventory.generation = committed.generation();
                self.report.commits = self.report.commits.saturating_add(1);
                observe(Event::Committed(committed.generation()));
                self.reply_origin(&pending.origin, ipc::Response::Revoke(0), now)?;
            }
            Err(failure) => {
                self.inventory.blocked = true;
                self.stopping = Some(ShutdownMode::Soft);
                let unknown = failure.exposure == Exposure::Unknown;
                if unknown {
                    self.close_all_with(CloseCause::StorageUnknown, observe)
                } else {
                    self.reply_origin(&pending.origin, ipc::Response::Revoke(1), now)?;
                }
                if self.failure.is_none() {
                    self.failure = Some(Error::Storage(failure))
                }
                if let Err(e) = self.network.close(observe)
                    && self.network_failure.is_none()
                {
                    self.network_failure = Some(e)
                }
            }
        }
        Ok(())
    }
    fn service_input(
        &mut self,
        index: usize,
        now: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        let Some(peer) = &self.peers[index] else {
            return Ok(false);
        };
        if peer.busy.is_some() || peer.io.queued_frames() != 0 || self.stopping.is_some() {
            return Ok(false);
        }
        let Some(frame) = peer.io.frame() else {
            return Ok(false);
        };
        let request = match ipc::Request::decode(frame) {
            Ok(request) => request,
            Err(e) => {
                self.close_index(index, CloseCause::Protocol(e), observe);
                return Ok(true);
            }
        };
        let order = peer.next_request.checked_add(1).ok_or(Fault::Overflow)?;
        let client = peer.client.clone();
        let immediate = match request {
            ipc::Request::Query(public) => Some(ipc::Response::Query(u32::from(
                !self.inventory.revoked(public),
            ))),
            ipc::Request::Revoke(proof) if self.inventory.revoked(proof.public()?) => {
                Some(ipc::Response::Revoke(0))
            }
            _ => None,
        };
        if let Some(response) = immediate {
            self.peers[index]
                .as_ref()
                .ok_or(Fault::Stale)?
                .io
                .capacity(ipc::RESPONSE_BYTES, Class::Ordinary)
                .then_some(())
                .ok_or(Fault::Capacity)?;
            self.queue_response(&client, order, response, Some(now))?;
            let peer = self.peers[index].as_mut().ok_or(Fault::Stale)?;
            peer.next_request = order;
            peer.first = false;
            peer.input = None;
            peer.io.release_frame();
            return Ok(true);
        }
        if self.checking.is_some() || self.storing.is_some() || !self.verifier.available() {
            return Ok(false);
        }
        let ipc::Request::Revoke(proof) = request else {
            return Err(Fault::Malformed.into());
        };
        let certificate = Certificate::copy(proof);
        let target = peer.input.ok_or(Fault::Stale)?;
        let candidate = Candidate {
            certificate,
            origin: Origin::App {
                client: client.clone(),
                request: order,
            },
            until: target.until,
            hard: target.hard,
        };
        if self.admit_check(candidate, observe)? {
            let peer = self.peers[index].as_mut().ok_or(Fault::Stale)?;
            peer.next_request = order;
            peer.busy = Some(order);
            peer.input = None;
            peer.first = false;
            peer.io.release_frame();
            return Ok(true);
        }
        Ok(false)
    }
    fn peer_io(
        &mut self,
        index: usize,
        cx: &mut Context<'_>,
        now: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        let Some(peer) = &mut self.peers[index] else {
            return Ok(false);
        };
        if peer.io.queued_frames() != 0 {
            match peer.io.poll_write(cx) {
                Poll::Ready(Ok(write)) => {
                    if write.origin.client != peer.client.serial {
                        return Err(Fault::Stale.into());
                    }
                    if write.complete {
                        peer.output = None;
                        self.report.replies = self.report.replies.saturating_add(1);
                        observe(Event::Written(
                            peer.client.clone(),
                            write.origin.request,
                            write.origin.response,
                        ))
                    }
                    return Ok(true);
                }
                Poll::Ready(Err(e)) => {
                    self.close_index(index, CloseCause::Io(e), observe);
                    return Ok(true);
                }
                Poll::Pending => {}
            }
        }
        if peer.io.frame().is_none() && self.stopping.is_none() {
            match peer.io.poll_read(cx) {
                Poll::Ready(Ok(ReadStep::Eof)) => {
                    self.close_index(index, CloseCause::Eof, observe);
                    return Ok(true);
                }
                Poll::Ready(Err(e)) => {
                    self.close_index(index, CloseCause::Io(e), observe);
                    return Ok(true);
                }
                Poll::Ready(Ok(ReadStep::Progress { complete, .. })) => {
                    if peer.input.is_none() {
                        peer.input = Some(bound(now, self.limits.operation_lifetime)?)
                    }
                    if complete {
                        peer.first = false;
                    }
                    return Ok(true);
                }
                Poll::Pending => {}
            }
        }
        self.service_input(index, now, observe)
    }
    fn close_all_with(&mut self, cause: CloseCause, observe: &mut impl FnMut(Event<'id>)) {
        // Use only reproducible non-IO reasons here; each individual native IO
        // cause is retained by close_index rather than cloned or replaced.
        let kind = match cause {
            CloseCause::StorageUnknown => 0,
            CloseCause::Clock => 1,
            _ => 2,
        };
        for index in 0..self.peers.len() {
            self.close_index(
                index,
                match kind {
                    0 => CloseCause::StorageUnknown,
                    1 => CloseCause::Clock,
                    _ => CloseCause::Shutdown,
                },
                observe,
            )
        }
    }
    /// Physical application close independent of clock; admitted storage is still
    /// retained and later drained by shutdown, never secretly rolled back.
    pub fn close_all(&mut self, observe: &mut impl FnMut(Event<'id>)) {
        self.abort(CloseCause::Shutdown, observe)
    }
    fn abort(&mut self, cause: CloseCause, observe: &mut impl FnMut(Event<'id>)) {
        self.stopping = Some(ShutdownMode::Immediate);
        self.close_all_with(cause, observe);
        if let Err(e) = self.network.close(observe)
            && self.network_failure.is_none()
        {
            self.network_failure = Some(e)
        }
        self.candidates.clear();
        self.verifier.request_stop();
        self.storage.request_stop();
    }
    /// Stop acceptance. Soft mode drains original work/output under their fixed
    /// bounds; Immediate closes MQs and requests between-step verifier cancel.
    pub fn request_shutdown(&mut self, mode: ShutdownMode, observe: &mut impl FnMut(Event<'id>)) {
        self.stopping = Some(mode);
        if mode == ShutdownMode::Immediate {
            self.close_all(observe)
        }
    }
    fn native_expiry(
        &mut self,
        now: Option<u64>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        let at = Instant::now();
        for index in 0..self.peers.len() {
            let expired = self.peers[index].as_ref().is_some_and(|p| {
                p.first
                    && (at >= p.first_bound.hard
                        || now.is_some_and(|now| now >= p.first_bound.until))
                    || p.input
                        .is_some_and(|b| at >= b.hard || now.is_some_and(|now| now >= b.until))
                    || p.output
                        .is_some_and(|b| at >= b.hard || now.is_some_and(|now| now >= b.until))
            });
            if expired {
                self.close_index(index, CloseCause::Deadline, observe)
            }
        }
        let expired_check = self
            .checking
            .as_ref()
            .filter(|c| {
                !c.retired
                    && (at >= c.candidate.hard || now.is_some_and(|now| now >= c.candidate.until))
            })
            .map(|c| (c.job.clone(), c.candidate.origin.clone()));
        if let Some((job, origin)) = expired_check {
            if let Some(check) = &mut self.checking {
                check.retired = true;
            }
            let _cancel = self.verifier.cancel(&job);
            if let Origin::App { client, .. } = origin
                && let Some(index) = self.index(&client)
            {
                self.close_index(index, CloseCause::Deadline, observe)
            }
        }
        let expired_store = self
            .storing
            .as_ref()
            .filter(|s| at >= s.bound.hard || now.is_some_and(|now| now >= s.bound.until))
            .and_then(|s| match &s.origin {
                Origin::App { client, .. } => Some(client.clone()),
                _ => None,
            });
        if let Some(client) = expired_store
            && let Some(index) = self.index(&client)
        {
            self.close_index(index, CloseCause::Deadline, observe)
        }
        self.network.expire_native(observe)
    }
    fn target(&self) -> Option<u64> {
        self.peers
            .iter()
            .flatten()
            .flat_map(|p| {
                p.first
                    .then_some(p.first_bound.until)
                    .into_iter()
                    .chain(p.input.map(|b| b.until))
                    .chain(p.output.map(|b| b.until))
            })
            .chain(self.checking.as_ref().filter(|c|!c.retired).map(|c| c.candidate.until))
            .chain(self.storing.as_ref().filter(|s|matches!(&s.origin,Origin::App{client,..} if self.index(client).is_some())).map(|s|s.bound.until))
            .min()
    }
    fn native_target(&self) -> Instant {
        self.peers
            .iter()
            .flatten()
            .flat_map(|p| {
                p.first
                    .then_some(p.first_bound.hard)
                    .into_iter()
                    .chain(p.input.map(|b| b.hard))
                    .chain(p.output.map(|b| b.hard))
            })
            .chain(self.checking.as_ref().filter(|c|!c.retired).map(|c| c.candidate.hard))
            .chain(self.storing.as_ref().filter(|s|matches!(&s.origin,Origin::App{client,..} if self.index(client).is_some())).map(|s|s.bound.hard))
            .chain(self.network.next_native())
            .fold(self.tick, Instant::min)
    }
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        wait: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        self.native_expiry(None, observe)?;
        let at = wait.map_or(self.native_target(), |wait| wait.min(self.native_target()));
        self.native.as_mut().reset(at);
        if self.native.as_mut().poll(cx).is_ready() {
            self.tick = plus(Instant::now(), self.limits.tick)?;
            self.native_expiry(None, observe)?;
        }
        let subscription = self.subscription.poll_changed(cx, self.revision);
        if let Poll::Ready(Err(e)) = subscription {
            return Poll::Ready(Err(Error::Clock(e)));
        }
        let sample = self.ports.clock.sample().map_err(Error::Clock)?;
        self.revision = sample.revision;
        let now = sample.now.as_micros();
        self.native_expiry(Some(now), observe)?;
        if wait.is_some_and(|at| Instant::now() >= at) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        if let Poll::Ready(changed) = self.subscription.poll_changed(cx, sample.revision) {
            changed.map_err(Error::Clock)?;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if let Some(target) = self.target() {
            if self.alarm_at != Some(target) {
                self.alarm = Some(Box::pin(
                    Deadline::at(
                        self.ports.clock.clone(),
                        gnunet_types::AbsoluteTime::from_micros(target),
                    )
                    .map_err(Error::Clock)?,
                ));
                self.alarm_at = Some(target)
            }
            if let Some(alarm) = &mut self.alarm {
                match alarm.as_mut().poll(cx) {
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(Error::Clock(e))),
                    Poll::Ready(Ok(())) => {
                        self.alarm = None;
                        self.alarm_at = None;
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    Poll::Pending => {}
                }
            }
        }
        if wait.is_some_and(|at| Instant::now() >= at) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        if self.yield_due {
            self.yield_due = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        match self.storage.poll(cx) {
            Poll::Ready(Ok(Some(completion))) => {
                self.complete_store(completion, Some(now), observe)?;
                return Poll::Ready(Ok(Progress::Activity));
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(None)) if self.stopping.is_none() => {
                return Poll::Ready(Err(Fault::Closed.into()));
            }
            _ => {}
        }
        match self.verifier.poll(cx) {
            Poll::Ready(Ok(Some(completion))) => {
                self.complete_check(completion, now, observe)?;
                return Poll::Ready(Ok(Progress::Activity));
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(None)) if self.stopping.is_none() => {
                return Poll::Ready(Err(Fault::Closed.into()));
            }
            _ => {}
        }
        if self.stopping.is_some() {
            for index in 0..self.peers.len() {
                if self.peers[index]
                    .as_ref()
                    .is_some_and(|p| p.busy.is_none() && p.io.queued_frames() == 0)
                {
                    self.close_index(index, CloseCause::Shutdown, observe)
                }
            }
            if self.peers.iter().all(Option::is_none)
                && self.checking.is_none()
                && self.storing.is_none()
            {
                return Poll::Ready(Ok(Progress::Stopped));
            }
        }
        if self.stopping.is_none() && self.network_first && self.admit_network(now, observe)? {
            return Poll::Ready(Ok(Progress::Activity));
        }
        for offset in 0..3 {
            let direction = (self.turn + offset) % 3;
            let activity = match direction {
                0 => self.poll_network(cx, now, wait, observe)?,
                1 => self.poll_peers(cx, now, observe)?,
                _ => self.poll_accept(cx, listeners, observe)?,
            };
            if activity {
                self.turn = (direction + 1) % 3;
                return Poll::Ready(Ok(Progress::Activity));
            }
        }
        if self.stopping.is_none() && self.admit_network(now, observe)? {
            return Poll::Ready(Ok(Progress::Activity));
        }
        Poll::Pending
    }
    fn poll_network(
        &mut self,
        cx: &mut Context<'_>,
        now: u64,
        wait: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        if self.stopping.is_some() {
            return Ok(false);
        }
        if let Poll::Ready(result) = self.network.poll(cx, &self.inventory, now, wait, observe) {
            if let Some(mut candidate) = result? {
                let target = bound(now, self.limits.operation_lifetime)?;
                candidate.until = target.until;
                candidate.hard = target.hard;
                if self.candidates.len() < self.limits.network_inputs {
                    self.candidates.push_back(candidate)
                } else {
                    self.report.network_capacity_drops =
                        self.report.network_capacity_drops.saturating_add(1);
                    observe(Event::Capacity)
                }
            }
            return Ok(true);
        }
        Ok(false)
    }
    fn poll_peers(
        &mut self,
        cx: &mut Context<'_>,
        now: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        for offset in 0..self.peers.len() {
            let index = (self.cursor + offset) % self.peers.len();
            if self.peer_io(index, cx, now, observe)? {
                self.cursor = (index + 1) % self.peers.len();
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn poll_accept(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        if self.stopping.is_some() || !self.accept.ready() || self.peers.iter().all(Option::is_some)
        {
            return Ok(false);
        }
        for offset in 0..listeners.len() {
            let index = (usize::from(self.accept_first) + offset) % listeners.len();
            match listeners[index].poll_canonical_connection(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(e)) => {
                    observe(Event::Socket(self.accept.failed(e)));
                    return Ok(true);
                }
                Poll::Ready(Ok(accepted)) => {
                    self.admit(accepted, observe)?;
                    self.accept_first = !self.accept_first;
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    /// One bounded step. Any original error closes all actual MQ/provider owners
    /// before returning; storage jobs remain owned for actual shutdown receipts.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        wait: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        let result = self.poll_inner(cx, listeners, wait, observe);
        match &result {
            Poll::Ready(Err(Error::Clock(_))) => self.abort(CloseCause::Clock, observe),
            Poll::Ready(Err(_)) => self.close_all(observe),
            Poll::Ready(Ok(Progress::Activity)) => self.yield_due = true,
            _ => {}
        }
        result
    }
    /// Canceling this future preserves original RX/TX, work, source and deadlines.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        wait: Option<Instant>,
        mut observe: impl FnMut(Event<'id>),
    ) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll(cx, listeners, wait, &mut observe)).await
    }
    /// Physically stop all original sources, then consume actual verification and
    /// durable-store outcomes and join their exact original threads.
    pub async fn shutdown(&mut self, mut observe: impl FnMut(Event<'id>)) -> Shutdown {
        self.close_all(&mut observe);
        let verification = self.verifier.shutdown(|_| {}).await;
        self.checking = None;
        let mut completion = None;
        let storage = self.storage.shutdown(|c| completion = Some(c)).await;
        if let Some(completion) = completion
            && let Err(e) = self.complete_store(completion, None, &mut observe)
            && self.failure.is_none()
        {
            self.failure = Some(e)
        }
        if self.storing.is_some() {
            self.inventory.blocked = true;
            if self.failure.is_none() {
                self.failure = Some(Fault::OutcomeUnknown.into())
            }
        }
        let network = match self.network_failure.take() {
            Some(e) => Err(e),
            None => Ok(()),
        };
        Shutdown {
            report: self.report,
            failure: self.failure.take(),
            storage,
            verification,
            network,
        }
    }
}

impl Drop for Server<'_> {
    fn drop(&mut self) {
        for slot in &mut self.peers {
            if let Some(mut peer) = slot.take() {
                peer.io.retire();
            }
        }
        let _network = self.network.close(&mut |_| {});
        self.verifier.request_stop();
        self.storage.request_stop();
    }
}
