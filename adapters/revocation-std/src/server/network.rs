//! Actual shared CORE flooding and SETU reconciliation. Only durable inventory
//! creates new outgoing knowledge intents; no old IPC mutation is replayed.
use super::{Candidate, Error, Event, Limits, Metrics, Origin};
use crate::Inventory;
use gnunet_client_host::EndpointSource;
use gnunet_core_client_host as core;
use gnunet_revocation::{Certificate, ipc};
use gnunet_setu_client_host as setu;
use gnunet_types::Error as Fault;
use std::{
    cmp::Ordering,
    future::Future,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;
const TYPES: &[u16] = &[638];
const ELEMENT: u16 = 12;
#[derive(Clone, Copy)]
struct Send<'id> {
    id: core::SendId<'id>,
    epoch: core::ConnectionEpoch<'id>,
    peer: core::Peer<'id>,
    index: usize,
    hard: Instant,
    drain: Option<Instant>,
}
#[derive(Clone, Copy)]
struct Sync<'id> {
    id: setu::Operation<'id>,
    epoch: setu::Epoch<'id>,
    hard: Instant,
    drain: Option<Instant>,
}
struct Peer<'id> {
    id: [u8; 32],
    core: Option<core::Peer<'id>>,
    cursor: usize,
    send: Option<Send<'id>>,
    retry: Instant,
    sync_due: Option<Instant>,
    sync: [Option<Sync<'id>>; 2],
}
/// Actual network-source diagnostics; no variant asserts remote receipt.
#[derive(Debug)]
pub enum NetworkEvent<'id> {
    /// Actual CORE source attached/initialized.
    CoreReady(core::ConnectionEpoch<'id>, [u8; 32]),
    /// Actual original CORE physical loss.
    CoreLost(core::ConnectionEpoch<'id>, core::LossCause),
    /// Actual original local send result and exact exposure.
    FloodEnded(
        core::SendId<'id>,
        core::PayloadState<'id>,
        core::SendOutcome,
    ),
    /// Actual original CORE cancel receipt for an unwritten payload. Control
    /// bytes may already have reached CORE; this is no remote cancel ACK.
    FloodCanceled(
        core::ConnectionEpoch<'id>,
        core::Peer<'id>,
        core::SendId<'id>,
        core::SendOutcome,
    ),
    /// Actual SETU source loss.
    SetLost(Option<setu::Epoch<'id>>, setu::Cause),
    /// Original local union retirement, not a protocol DONE.
    UnionRetired(setu::Operation<'id>, setu::Reason, setu::Submission),
    /// Actual original protocol status.
    UnionStatus(setu::Operation<'id>, setu::ipc::Status),
    /// Actual full local SETU command write, never ACK.
    SetWritten(setu::Epoch<'id>, setu::WriteId<'id>, setu::Command),
    /// Unadmitted public packet was refused by bounded host capacity.
    Capacity,
    /// Actual original source failure/refusal.
    Port(gnunet_client_host::ConnectError),
    /// Independent cleanup failure after an earlier error was already retained.
    Cleanup(Error),
}
/// Explicit borrowed stable domains. Caller creates these outside Server.
pub struct Instances<'id> {
    /// Stable actual CORE client domain.
    pub core: &'id mut core::Instance,
    /// Stable SETU allocation domain for bounded replacement sets/listeners.
    pub setu: &'id setu::Instance,
}
/// Actual explicit CLIENT selections; constructor opens no hidden Resolver.
pub struct Sources {
    /// CORE source.
    pub core: EndpointSource,
    /// SETU source.
    pub setu: EndpointSource,
    /// Original CORE producer's native enum representation.
    pub core_order: core::ClassOrder,
}
pub(super) struct Network<'id> {
    core: core::Client<'id, 64, 64>,
    set: Option<setu::Client<'id>>,
    listener: Option<setu::Client<'id>>,
    set_domain: &'id setu::Instance,
    set_source: EndpointSource,
    clock: Arc<dyn gnunet_service_runtime::clock::RuntimeClock>,
    set_limits: setu::Limits,
    limits: Limits,
    order: core::ClassOrder,
    app: [u8; 64],
    local: Option<[u8; 32]>,
    peers: Vec<Peer<'id>>,
    set_epoch: Option<setu::Epoch<'id>>,
    listener_epoch: Option<setu::Epoch<'id>>,
    set_ready: bool,
    add_cursor: usize,
    add_pending: Option<(setu::Epoch<'id>, setu::WriteId<'id>, usize, Instant)>,
    inventory_len: usize,
    set_hard: Option<Instant>,
    listener_hard: Option<Instant>,
    listener_create: Option<Instant>,
    set_retry: Instant,
    listener_retry: Instant,
    turn: u8,
    input_serial: u64,
    closed: bool,
    metrics: Metrics,
}
fn later(at: Instant, duration: Duration) -> Result<Instant, Error> {
    at.checked_add(duration)
        .ok_or_else(|| Fault::Overflow.into())
}
fn until(now: u64, d: Duration) -> Result<u64, Error> {
    now.checked_add(u64::try_from(d.as_micros()).map_err(|_| Fault::Overflow)?)
        .filter(|n| *n != u64::MAX)
        .ok_or_else(|| Fault::Overflow.into())
}
impl<'id> Network<'id> {
    pub(super) fn new(
        instances: Instances<'id>,
        sources: Sources,
        limits: Limits,
        order: core::ClassOrder,
    ) -> Result<Self, Error> {
        let [source, set_source] = EndpointSource::snapshot_all([&sources.core, &sources.setu])?;
        let clock = source.clock();
        if !Arc::ptr_eq(&clock, &set_source.clock()) {
            return Err(Fault::Conflict.into());
        }
        let native = core::Limits {
            sends: limits.peers,
            source_bytes: limits
                .peers
                .checked_mul(ipc::REVOKE_BYTES)
                .ok_or(Fault::Overflow)?,
            frame_bytes: 65535,
            output: gnunet_service_runtime::framing::Budget {
                frames: limits.peers * 2 + 1,
                bytes: (limits.peers * 2 + 1) * 65535,
            },
            io_slice_bytes: limits.io_slice_bytes,
        };
        let core = core::Client::new(instances.core, source, order, 0, TYPES, native)?;
        let set_limits = setu::Limits {
            abi: limits.setu_abi,
            operations: limits.peers * 2,
            incoming: limits.peers,
            incoming_bytes: limits.peers * 65535,
            io_slice_bytes: limits.io_slice_bytes,
            retirement_grace_micros: u64::try_from(limits.retirement_grace.as_micros())
                .map_err(|_| Fault::Overflow)?,
            ..Default::default()
        };
        let mut peers = Vec::new();
        peers
            .try_reserve_exact(limits.peers)
            .map_err(|_| Fault::Capacity)?;
        let now = Instant::now();
        Ok(Self {
            core,
            set: None,
            listener: None,
            set_domain: instances.setu,
            set_source,
            clock,
            set_limits,
            limits,
            order,
            app: gnunet_crypto::hash512(b"revocation-set-union-application-id"),
            local: None,
            peers,
            set_epoch: None,
            listener_epoch: None,
            set_ready: false,
            add_cursor: 0,
            add_pending: None,
            inventory_len: 0,
            set_hard: None,
            listener_hard: None,
            listener_create: None,
            set_retry: now,
            listener_retry: now,
            turn: 0,
            input_serial: 0,
            closed: false,
            metrics: Metrics::default(),
        })
    }
    pub(super) fn clock(&self) -> Arc<dyn gnunet_service_runtime::clock::RuntimeClock> {
        self.clock.clone()
    }
    pub(super) const fn metrics(&self) -> Metrics {
        self.metrics
    }
    fn retire_core_peers(&mut self) {
        for peer in &mut self.peers {
            if peer.core.take().is_some() {
                self.metrics.add(1);
            }
            peer.sync_due = None;
        }
    }
    fn event(observe: &mut impl FnMut(Event<'id>), event: NetworkEvent<'id>) {
        observe(Event::Network(event))
    }
    fn peer_index(&mut self, id: [u8; 32]) -> Result<usize, Error> {
        if let Some(i) = self.peers.iter().position(|p| p.id == id) {
            return Ok(i);
        }
        if self.peers.len() == self.limits.peers {
            return Err(Fault::Capacity.into());
        }
        let at = Instant::now();
        self.peers.push(Peer {
            id,
            core: None,
            cursor: 0,
            send: None,
            retry: at,
            sync_due: None,
            sync: [None; 2],
        });
        Ok(self.peers.len() - 1)
    }
    fn initiate(&self, id: [u8; 32]) -> bool {
        let Some(local) = self.local else {
            return false;
        };
        let a = gnunet_crypto::hash512(&local);
        let b = gnunet_crypto::hash512(&id);
        for (a, b) in a.as_chunks::<4>().0.iter().zip(b.as_chunks::<4>().0).rev() {
            let a = match self.order {
                core::ClassOrder::Little => u32::from_le_bytes(*a),
                core::ClassOrder::Big => u32::from_be_bytes(*a),
            };
            let b = match self.order {
                core::ClassOrder::Little => u32::from_le_bytes(*b),
                core::ClassOrder::Big => u32::from_be_bytes(*b),
            };
            match a.cmp(&b) {
                Ordering::Greater => return true,
                Ordering::Less => return false,
                Ordering::Equal => {}
            }
        }
        false
    }
    fn stop_set(&mut self, observe: &mut impl FnMut(Event<'id>)) -> Result<(), Error> {
        if let Some(mut set) = self.set.take() {
            if let setu::Step::Lost(epoch, cause) = set.close() {
                Self::event(observe, NetworkEvent::SetLost(epoch, cause))
            }
            while let Some(event) = set.next_event() {
                if let setu::Step::LocalEnd(op, reason, submission) = event {
                    Self::event(observe, NetworkEvent::UnionRetired(op, reason, submission))
                }
            }
        }
        self.set_epoch = None;
        self.set_ready = false;
        self.add_cursor = 0;
        self.add_pending = None;
        self.set_hard = None;
        self.set_retry = later(Instant::now(), self.limits.retry)?;
        for peer in &mut self.peers {
            peer.sync = [None; 2];
            if peer.core.is_some() {
                peer.sync_due = Some(self.set_retry)
            }
        }
        Ok(())
    }
    fn stop_listener(&mut self, observe: &mut impl FnMut(Event<'id>)) -> Result<(), Error> {
        if let Some(mut listener) = self.listener.take() {
            if let setu::Step::Lost(epoch, cause) = listener.close() {
                Self::event(observe, NetworkEvent::SetLost(epoch, cause))
            }
            while let Some(event) = listener.next_event() {
                if let setu::Step::LocalEnd(op, reason, submission) = event {
                    Self::event(observe, NetworkEvent::UnionRetired(op, reason, submission))
                }
            }
        }
        self.listener_epoch = None;
        self.listener_hard = None;
        self.listener_create = None;
        self.listener_retry = later(Instant::now(), self.limits.retry)?;
        Ok(())
    }
    /// Native guards run before any canonical subscription wait. Late polling
    /// never moves a first cancellation beyond its original hard+grace.
    pub(super) fn expire_native(
        &mut self,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        if self.closed {
            return Ok(());
        }
        let now = Instant::now();
        let mut reset_core = false;
        let mut reset_set = self.set_hard.is_some_and(|h| now >= h && !self.set_ready)
            || self.add_pending.is_some_and(|(_, _, _, hard)| now >= hard);
        for peer in &mut self.peers {
            if let Some(send) = &mut peer.send {
                if send.drain.is_some_and(|h| now >= h) {
                    reset_core = true
                } else if now >= send.hard && send.drain.is_none() {
                    match self.core.cancel(send.id) {
                        Ok(Some(completion)) => {
                            Self::event(
                                observe,
                                NetworkEvent::FloodCanceled(
                                    send.epoch,
                                    send.peer,
                                    send.id,
                                    completion.outcome,
                                ),
                            );
                            peer.send = None;
                            peer.retry = later(now, self.limits.retry)?
                        }
                        Ok(None) => {
                            send.drain = Some(later(send.hard, self.limits.retirement_grace)?)
                        }
                        Err(e) => {
                            Self::event(observe, NetworkEvent::Port(e));
                            reset_core = true
                        }
                    }
                }
            }
            for sync in peer.sync.iter_mut().flatten() {
                if sync.drain.is_some_and(|h| now >= h) {
                    reset_set = true
                } else if now >= sync.hard && sync.drain.is_none() {
                    match self.set.as_mut().ok_or(Fault::Stale)?.cancel(sync.id) {
                        Ok(()) => {
                            sync.drain = Some(later(sync.hard, self.limits.retirement_grace)?)
                        }
                        Err(e) => {
                            Self::event(observe, NetworkEvent::Port(e));
                            reset_set = true
                        }
                    }
                }
            }
        }
        if reset_core {
            match self.core.reconnect() {
                Ok(core::Progress::Lost { epoch, cause }) => {
                    Self::event(observe, NetworkEvent::CoreLost(epoch, cause))
                }
                Ok(_) => {}
                Err(gnunet_client_host::ConnectError::Protocol(Fault::Conflict)) => {}
                Err(e) => {
                    Self::event(observe, NetworkEvent::Port(e));
                    let _closed = self.core.close()?;
                }
            }
            self.retire_core_peers();
        }
        if reset_set {
            self.stop_set(observe)?
        }
        if self.listener_hard.is_some_and(|h| now >= h)
            || self.listener_create.is_some_and(|h| now >= h)
        {
            self.stop_listener(observe)?
        }
        Ok(())
    }
    pub(super) fn next_native(&self) -> Option<Instant> {
        self.set_hard
            .filter(|_| !self.set_ready)
            .into_iter()
            .chain(self.listener_hard)
            .chain(self.listener_create)
            .chain(self.add_pending.map(|(_, _, _, hard)| hard))
            .chain(
                self.peers
                    .iter()
                    .filter_map(|p| p.send.map(|s| s.drain.unwrap_or(s.hard))),
            )
            .chain(
                self.peers
                    .iter()
                    .flat_map(|p| p.sync.iter().flatten().map(|s| s.drain.unwrap_or(s.hard))),
            )
            .min()
    }
    fn setup(&mut self, now: u64) -> Result<bool, Error> {
        if self.closed {
            return Ok(false);
        }
        let at = Instant::now();
        if self.set.is_none() && at >= self.set_retry {
            self.set = Some(setu::Client::new_set(
                self.set_domain,
                self.set_source.duplicate()?,
                self.set_limits,
                until(now, self.limits.operation_lifetime)?,
            )?);
            self.set_hard = Some(later(at, self.limits.operation_lifetime)?);
            return Ok(true);
        }
        if self.listener.is_none() && at >= self.listener_retry {
            self.listener = Some(setu::Client::new_listener(
                self.set_domain,
                self.set_source.duplicate()?,
                self.set_limits,
                self.app,
                until(now, self.limits.listener_lifetime)?,
            )?);
            self.listener_hard = Some(later(at, self.limits.listener_lifetime)?);
            self.listener_create = Some(later(at, self.limits.operation_lifetime)?);
            return Ok(true);
        }
        Ok(false)
    }
    fn schedule(&mut self, inventory: &Inventory, now: u64) -> Result<bool, Error> {
        if self.closed {
            return Ok(false);
        }
        if self.set_ready && self.add_pending.is_none() && self.add_cursor < inventory.len() {
            let fact = inventory.records.get(self.add_cursor).ok_or(Fault::Stale)?;
            let mut frame = [0u8; ipc::REVOKE_BYTES];
            ipc::Request::Revoke(fact.certificate().proof()?).encode(&mut frame)?;
            let set = self.set.as_mut().ok_or(Fault::Stale)?;
            match set.add(ELEMENT, &frame, until(now, self.limits.operation_lifetime)?) {
                Ok(write) => {
                    self.add_pending = Some((
                        self.set_epoch.ok_or(Fault::Stale)?,
                        write,
                        self.add_cursor,
                        later(Instant::now(), self.limits.operation_lifetime)?,
                    ));
                    return Ok(true);
                }
                Err(gnunet_client_host::ConnectError::Protocol(
                    Fault::Capacity | Fault::WouldBlock | Fault::NotReady,
                )) => {}
                Err(e) => return Err(e.into()),
            }
        }
        let at = Instant::now();
        for index in 0..self.peers.len() {
            let peer = &mut self.peers[index];
            if let Some(token) = peer.core
                && peer.send.is_none()
                && peer.cursor < inventory.len()
                && at >= peer.retry
            {
                let mut frame = [0u8; ipc::REVOKE_BYTES];
                ipc::Request::Revoke(inventory.records[peer.cursor].certificate().proof()?)
                    .encode(&mut frame)?;
                if self
                    .core
                    .request_available(token, frame.len(), frame.len())?
                {
                    let message = core::Message::copy_from(&frame)?;
                    let send = self
                        .core
                        .send(
                            token,
                            0,
                            until(now, self.limits.operation_lifetime)?,
                            message,
                        )
                        .map_err(|r| Error::Native(r.reason.into()))?;
                    peer.send = Some(Send {
                        id: send,
                        epoch: self.core.epoch().ok_or(Fault::Stale)?,
                        peer: token,
                        index: peer.cursor,
                        hard: later(at, self.limits.operation_lifetime)?,
                        drain: None,
                    });
                    return Ok(true);
                }
            }
            if self.set_ready
                && self.add_cursor == inventory.len()
                && self.add_pending.is_none()
                && peer.sync_due.is_some_and(|d| at >= d)
                && peer.sync.iter().all(Option::is_none)
            {
                let op = match self.set.as_mut().ok_or(Fault::Stale)?.evaluate(
                    peer.id,
                    self.app,
                    Default::default(),
                    None,
                    until(now, self.limits.operation_lifetime)?,
                ) {
                    Ok(op) => op,
                    Err(gnunet_client_host::ConnectError::Protocol(
                        Fault::Capacity | Fault::WouldBlock | Fault::NotReady,
                    )) => continue,
                    Err(e) => return Err(e.into()),
                };
                peer.sync[0] = Some(Sync {
                    id: op,
                    epoch: self.set_epoch.ok_or(Fault::Stale)?,
                    hard: later(at, self.limits.operation_lifetime)?,
                    drain: None,
                });
                peer.sync_due = None;
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn core_step(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Option<Candidate<'id>>, Error>> {
        let step = match self.core.poll(cx, wait) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(r) => r?,
        };
        match step {
            core::Progress::Inbound {
                epoch,
                event: core::Inbound::Ready { local, .. },
            } => {
                let id = local.identity().0;
                self.local = Some(id);
                Self::event(observe, NetworkEvent::CoreReady(epoch, id));
            }
            core::Progress::Inbound {
                event: core::Inbound::Connected(token),
                ..
            } => {
                let id = token.identity().0;
                if Some(id) != self.local {
                    let initiate = self.initiate(id);
                    let index = self.peer_index(id)?;
                    let peer = &mut self.peers[index];
                    if peer.send.is_some() && peer.core != Some(token) {
                        return Poll::Ready(Err(Fault::Stale.into()));
                    }
                    if peer.core != Some(token) {
                        if peer.core.is_none() {
                            self.metrics.add(0);
                        }
                        peer.cursor = 0;
                        peer.core = Some(token);
                        peer.retry = Instant::now();
                        if initiate {
                            peer.sync_due = Some(later(Instant::now(), Duration::from_secs(1))?)
                        }
                    }
                }
            }
            core::Progress::Inbound {
                event: core::Inbound::Disconnected(token),
                ..
            }
            | core::Progress::PeerLost { peer: token, .. } => {
                for peer in &mut self.peers {
                    if peer.core == Some(token) {
                        peer.core = None;
                        peer.sync_due = None;
                        self.metrics.add(1);
                    }
                }
            }
            core::Progress::Inbound {
                epoch,
                event:
                    core::Inbound::Traffic {
                        peer,
                        direction: core::Direction::Inbound,
                        traffic: core::OwnedTraffic::Full(message),
                        ..
                    },
            } => {
                let certificate = match ipc::Request::decode(message.as_ref()) {
                    Ok(ipc::Request::Revoke(proof)) => Certificate::copy(proof),
                    _ => return Poll::Ready(Ok(None)),
                };
                return Poll::Ready(Ok(Some(Candidate {
                    certificate,
                    origin: Origin::Core {
                        epoch,
                        peer: peer.0,
                    },
                    until: 0,
                    hard: Instant::now(),
                })));
            }
            core::Progress::Finished {
                epoch,
                peer: token,
                send,
                payload,
                completion,
            } => {
                Self::event(
                    observe,
                    NetworkEvent::FloodEnded(send, payload, completion.outcome),
                );
                if let Some(peer) = self.peers.iter_mut().find(|p| {
                    p.send
                        .is_some_and(|s| s.id == send && s.epoch == epoch && s.peer == token)
                }) {
                    let original = peer.send.take().ok_or(Fault::Stale)?;
                    if payload.complete() {
                        peer.cursor = original.index.checked_add(1).ok_or(Fault::Overflow)?
                    } else {
                        peer.retry = later(Instant::now(), self.limits.retry)?
                    }
                }
            }
            core::Progress::Lost { epoch, cause } => {
                Self::event(observe, NetworkEvent::CoreLost(epoch, cause));
                self.retire_core_peers();
            }
            core::Progress::Unavailable(e) => return Poll::Ready(Err(e.into())),
            core::Progress::ConnectRetry { error, .. } => {
                Self::event(observe, NetworkEvent::Port(error.into()))
            }
            core::Progress::Closed => return Poll::Ready(Err(Fault::Closed.into())),
            core::Progress::WaitDeadline => return Poll::Pending,
            _ => {}
        }
        Poll::Ready(Ok(None))
    }
    fn set_step(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Option<Candidate<'id>>, Error>> {
        let Some(set) = &mut self.set else {
            return Poll::Pending;
        };
        let step = {
            let future = set.drive(wait);
            let mut future = std::pin::pin!(future);
            future.as_mut().poll(cx)
        };
        let step = match step {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(r) => r?,
        };
        match step {
            setu::Step::Connected(epoch) => self.set_epoch = Some(epoch),
            setu::Step::Written(epoch, write, command) => {
                Self::event(observe, NetworkEvent::SetWritten(epoch, write, command));
                if command == setu::Command::Create {
                    self.set_ready = true;
                    self.set_hard = None
                }
                if let Some((old, id, index, _)) = self.add_pending
                    && old == epoch
                    && id == write
                    && command == setu::Command::Add
                {
                    self.add_cursor = index.checked_add(1).ok_or(Fault::Overflow)?;
                    self.add_pending = None;
                }
            }
            setu::Step::Result(record) => {
                let found = self.peers.iter().enumerate().find_map(|(i, p)| {
                    p.sync.iter().enumerate().find_map(|(j, s)| {
                        s.filter(|s| s.id == record.operation() && s.epoch == record.epoch())
                            .map(|s| (i, j, s))
                    })
                });
                let Some((i, j, original)) = found else {
                    return Poll::Ready(Ok(None));
                };
                let response = record.response()?;
                if let setu::ipc::Response::Result {
                    status, element, ..
                } = response
                {
                    Self::event(observe, NetworkEvent::UnionStatus(original.id, status));
                    match status {
                        setu::ipc::Status::AddLocal if original.drain.is_none() => {
                            if element.kind != ELEMENT {
                                self.metrics.add(2);
                            } else {
                                // C counts the actual supported element callback,
                                // independently of later proof verification/result.
                                self.metrics.add(3);
                            }
                            if element.kind == ELEMENT
                                && let Ok(ipc::Request::Revoke(proof)) =
                                    ipc::Request::decode(element.data)
                            {
                                self.input_serial =
                                    self.input_serial.checked_add(1).ok_or(Fault::Overflow)?;
                                return Poll::Ready(Ok(Some(Candidate {
                                    certificate: Certificate::copy(proof),
                                    origin: Origin::Union {
                                        epoch: original.epoch,
                                        operation: original.id,
                                        serial: self.input_serial,
                                    },
                                    until: 0,
                                    hard: Instant::now(),
                                })));
                            }
                        }
                        setu::ipc::Status::Done | setu::ipc::Status::Failure => {
                            self.metrics.add(if status == setu::ipc::Status::Done {
                                5
                            } else {
                                4
                            });
                            self.peers[i].sync[j] = None;
                            if self.peers[i].core.is_some() {
                                self.peers[i].sync_due = Some(later(
                                    Instant::now(),
                                    self.limits.reconciliation_interval,
                                )?)
                            }
                        }
                        _ => {}
                    }
                }
            }
            setu::Step::LocalEnd(op, reason, submission) => {
                Self::event(observe, NetworkEvent::UnionRetired(op, reason, submission));
                for peer in &mut self.peers {
                    for slot in &mut peer.sync {
                        if slot.is_some_and(|s| s.id == op) {
                            *slot = None;
                            peer.sync_due = peer.core.map(|_| Instant::now());
                        }
                    }
                }
            }
            setu::Step::Lost(epoch, cause) => {
                Self::event(observe, NetworkEvent::SetLost(epoch, cause));
                self.stop_set(observe)?;
            }
            setu::Step::Closed => {
                self.stop_set(observe)?;
            }
            setu::Step::Retry(e, _) => Self::event(observe, NetworkEvent::Port(e.into())),
            setu::Step::WaitDeadline | setu::Step::Capacity => return Poll::Pending,
            _ => {}
        }
        Poll::Ready(Ok(None))
    }
    fn listener_step(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
        now: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Option<Candidate<'id>>, Error>> {
        let Some(listener) = &mut self.listener else {
            return Poll::Pending;
        };
        let step = {
            let future = listener.drive(wait);
            let mut future = std::pin::pin!(future);
            future.as_mut().poll(cx)
        };
        let step = match step {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(r) => r?,
        };
        match step {
            setu::Step::Connected(epoch) => self.listener_epoch = Some(epoch),
            setu::Step::Written(epoch, write, command) => {
                if command == setu::Command::Listen {
                    self.listener_create = None
                }
                Self::event(observe, NetworkEvent::SetWritten(epoch, write, command))
            }
            setu::Step::Incoming(mut incoming) => {
                if self.listener_epoch != Some(incoming.epoch())
                    || !self.set_ready
                    || self.add_pending.is_some()
                    || self.add_cursor != self.inventory_len
                {
                    drop(incoming);
                    return Poll::Ready(Ok(None));
                }
                let id = match incoming.request()? {
                    setu::ipc::Response::Incoming {
                        peer,
                        context: None,
                        ..
                    } => peer,
                    _ => {
                        drop(incoming);
                        return Poll::Ready(Ok(None));
                    }
                };
                let index = match self.peer_index(id) {
                    Ok(i) => i,
                    Err(_) => {
                        drop(incoming);
                        Self::event(observe, NetworkEvent::Capacity);
                        return Poll::Ready(Ok(None));
                    }
                };
                let Some(slot) = self.peers[index].sync.iter().position(Option::is_none) else {
                    drop(incoming);
                    return Poll::Ready(Ok(None));
                };
                let operation = match self.set.as_mut().ok_or(Fault::Stale)?.accept(
                    &mut incoming,
                    Default::default(),
                    until(now, self.limits.operation_lifetime)?,
                ) {
                    Ok(op) => op,
                    Err(gnunet_client_host::ConnectError::Protocol(
                        Fault::Capacity
                        | Fault::WouldBlock
                        | Fault::NotReady
                        | Fault::Stale
                        | Fault::Deadline,
                    )) => {
                        drop(incoming);
                        Self::event(observe, NetworkEvent::Capacity);
                        return Poll::Ready(Ok(None));
                    }
                    Err(e) => return Poll::Ready(Err(e.into())),
                };
                self.peers[index].sync[slot] = Some(Sync {
                    id: operation,
                    epoch: self.set_epoch.ok_or(Fault::Stale)?,
                    hard: later(Instant::now(), self.limits.operation_lifetime)?,
                    drain: None,
                });
            }
            setu::Step::Lost(epoch, cause) => {
                Self::event(observe, NetworkEvent::SetLost(epoch, cause));
                self.stop_listener(observe)?;
            }
            setu::Step::Closed => self.stop_listener(observe)?,
            setu::Step::Retry(e, _) => Self::event(observe, NetworkEvent::Port(e.into())),
            setu::Step::WaitDeadline | setu::Step::Capacity => return Poll::Pending,
            _ => {}
        }
        Poll::Ready(Ok(None))
    }
    pub(super) fn poll(
        &mut self,
        cx: &mut Context<'_>,
        inventory: &Inventory,
        now: u64,
        wait: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Option<Candidate<'id>>, Error>> {
        if self.closed {
            return Poll::Pending;
        }
        self.inventory_len = inventory.len();
        if self.setup(now)? || self.schedule(inventory, now)? {
            return Poll::Ready(Ok(None));
        }
        self.peers
            .retain(|p| p.core.is_some() || p.send.is_some() || p.sync.iter().any(Option::is_some));
        for offset in 0..3 {
            let result = match (self.turn + offset) % 3 {
                0 => self.core_step(cx, wait, observe),
                1 => self.set_step(cx, wait, observe),
                _ => self.listener_step(cx, wait, now, observe),
            };
            if result.is_ready() {
                self.turn = (self.turn + offset + 1) % 3;
                return result;
            }
        }
        Poll::Pending
    }
    pub(super) fn close(&mut self, observe: &mut impl FnMut(Event<'id>)) -> Result<(), Error> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        // Always close each physical owner, independently of preceding errors or
        // clock state. No native socket close-errno receipt is available in Drop.
        let core = self.core.close();
        self.retire_core_peers();
        let set = self.stop_set(observe);
        let listener = self.stop_listener(observe);
        let mut first = match core {
            Ok(Some(core::Progress::Lost { epoch, cause })) => {
                Self::event(observe, NetworkEvent::CoreLost(epoch, cause));
                None
            }
            Ok(_) => None,
            Err(e) => Some(Error::Native(e)),
        };
        if first.is_none() {
            first = set.err()
        } else if let Err(e) = set {
            Self::event(observe, NetworkEvent::Cleanup(e))
        }
        if first.is_none() {
            first = listener.err()
        } else if let Err(e) = listener {
            Self::event(observe, NetworkEvent::Cleanup(e))
        }
        // The CORE port returns all original pure send/peer debts before Closed;
        // this drain performs no clock, native IO or fresh-source connection.
        let mut context = Context::from_waker(std::task::Waker::noop());
        for _ in 0..self.limits.peers.saturating_mul(4).saturating_add(4) {
            match self.core.poll(&mut context, None) {
                Poll::Ready(Ok(core::Progress::Finished {
                    send,
                    payload,
                    completion,
                    ..
                })) => Self::event(
                    observe,
                    NetworkEvent::FloodEnded(send, payload, completion.outcome),
                ),
                Poll::Ready(Ok(core::Progress::Lost { epoch, cause })) => {
                    Self::event(observe, NetworkEvent::CoreLost(epoch, cause))
                }
                Poll::Ready(Ok(core::Progress::Closed)) => break,
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => {
                    if first.is_none() {
                        first = Some(e.into())
                    }
                    break;
                }
                Poll::Pending => {
                    if first.is_none() {
                        first = Some(Fault::OutcomeUnknown.into())
                    }
                    break;
                }
            }
        }
        self.peers.clear();
        match first {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}
