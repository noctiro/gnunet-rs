//! One communicator process, with shared service MQs and generation-bound routes.
use crate::{
    Activity, Capacity, Clock, HostError, ServiceCause,
    history::{ReplayHistory, ReplayTask},
    link::Link,
    peer::Peer,
};
mod history;
use gnunet_crypto::{EddsaPublicKey, Entropy};
use gnunet_service_runtime::connection::Connection;
use gnunet_tcp_communicator_core::{
    services::{self, Peerstore, Transport},
    session::{Effect, Phase, REPLAY_CAPACITY, ReplayKind, ResultKind, Session, Ticket, Time},
};
use gnunet_types::{Error, Rejected};
use history::Claim;
use std::{
    collections::VecDeque,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use zeroize::Zeroize;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Key {
    index: usize,
    generation: u64,
}
/// Original finite preamble/connectback bounds. This is caller timing metadata,
/// not an authentication or native-write completion capability.
#[derive(Clone, Copy, Debug)]
pub struct HandshakeBounds {
    until: u64,
    hard: tokio::time::Instant,
}
impl HandshakeBounds {
    /// Preserve the exact original targets; no clock is sampled or deadline renewed.
    pub fn new(until: u64, hard: tokio::time::Instant) -> Result<Self, Error> {
        if until == u64::MAX {
            return Err(Error::InvalidInput);
        }
        Ok(Self { until, hard })
    }
    /// Original canonical proto target.
    pub fn until(self) -> u64 {
        self.until
    }
    /// Original fixed native proto target.
    pub fn hard(self) -> tokio::time::Instant {
        self.hard
    }
    /// Validate both original targets before a new session/native effect.
    pub fn check(self, now: u64) -> Result<(), Error> {
        if now >= self.until || tokio::time::Instant::now() >= self.hard {
            Err(Error::Deadline)
        } else {
            Ok(())
        }
    }
}
/// One concrete actually accepted connection's retained native admission facts.
pub struct NativeAdmission<'a> {
    /// Actual physical peer address bytes.
    pub address: &'a [u8],
    /// Existing classifier result for this physical socket.
    pub network: u32,
    /// Actual bytes consumed by the preamble reader, before this host owns it.
    pub prefix: &'a [u8],
    /// Exact original helper targets, never reminted at handoff.
    pub bounds: HandshakeBounds,
    /// Same actual canonical observation supplied to Session construction.
    pub now: u64,
}
/// Local session capability. Its process identity and generation never enter wire bytes.
#[derive(Clone, Debug)]
pub struct SessionId {
    owner: Arc<()>,
    key: Key,
}
impl SessionId {
    /// Compare actual Manager allocations, without minting another session.
    #[must_use]
    pub fn same_process(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.owner, &other.owner)
    }
}
impl PartialEq for SessionId {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.owner, &other.owner) && self.key == other.key
    }
}
impl Eq for SessionId {}
/// Original CREATE authority in one physical TRANSPORT connection epoch.
#[derive(Clone, Debug)]
pub struct CreateId {
    owner: Arc<()>,
    epoch: u64,
    serial: u64,
}
/// Caller-visible actual outbound request; no connect success is manufactured.
pub struct CreateRequest<'a> {
    /// Complete local authority to acknowledge this exact request.
    pub id: CreateId,
    /// Original official opaque request ID, not the local capability.
    pub wire_id: [u8; 4],
    /// Official expected remote identity.
    pub peer: EddsaPublicKey,
    /// Official communicator address, without the trailing NUL.
    pub address: &'a [u8],
}
/// Process resource bounds. These are local limits, not private protocol fields.
#[derive(Clone, Copy, Debug)]
pub struct ManagerCapacity {
    /// Maximum simultaneous physical peer owners.
    pub sessions: usize,
    /// Maximum waiting TRANSPORT sends per peer, in addition to its active send.
    pub pending_sends: usize,
    /// Maximum original outbound CREATE requests waiting for their actual result.
    pub commands: usize,
}
/// A real progress observation, optionally belonging to one original peer.
#[derive(Clone, Debug)]
pub struct Progress {
    /// Original peer authority, absent for shared service-only progress.
    pub session: Option<SessionId>,
    /// Actual activity; enqueue and native writes remain distinct from callbacks.
    pub activity: Activity,
}
/// Actual original task failure with its peer generation when applicable.
#[derive(Debug)]
pub struct OwnedFailure {
    /// Original physical session; shared service/clock causes have no peer owner.
    pub session: Option<SessionId>,
    /// Original cause, without reconnecting or retiring an unrelated peer.
    pub cause: HostError,
}
impl std::fmt::Display for OwnedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.session, self.cause)
    }
}
impl std::error::Error for OwnedFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
/// One retained caller-created actual native connect attempt.
pub type Connect<'a> =
    Pin<Box<dyn Future<Output = io::Result<Connection>> + std::marker::Send + 'a>>;
struct Prepared {
    index: usize,
    generation: u64,
    next_qid: u32,
    address: Vec<u8>,
    rx: Vec<u8>,
    sends: VecDeque<PendingSend>,
    prefix: usize,
    initial: Option<crate::peer::ProtoGuard>,
}
struct Slot<'a> {
    generation: u64,
    peer: Option<Peer<'a>>,
}
#[derive(Clone, Copy)]
struct Replay<'a> {
    rid: u32,
    epoch: u64,
    key: Key,
    ticket: Ticket<'a>,
    peer: EddsaPublicKey,
    kind: ReplayKind,
    ended: bool,
    canceled: bool,
    history: usize,
}
#[derive(Clone, Copy)]
struct Flow<'a> {
    id: [u8; 8],
    peer: EddsaPublicKey,
    epoch: u64,
    key: Key,
    ticket: Ticket<'a>,
}
#[derive(Clone, Copy)]
pub(crate) struct Send {
    qid: [u8; 4],
    mid: [u8; 8],
    peer: EddsaPublicKey,
    epoch: u64,
    // A retained original completion has two once-only local admissions:
    // ACK first, additive capacity second. Keeping the owner across them also
    // supports a one-frame IPC budget without replaying the first frame.
    result_queued: bool,
}
impl Send {
    fn complete(
        &mut self,
        transport: &mut Link,
        current_epoch: u64,
        credit: bool,
        queue: &services::Queue<'_>,
        scratch: &mut [u8],
    ) -> Result<bool, Error> {
        if !transport.online() || self.epoch != current_epoch {
            return Ok(true);
        }
        if !self.result_queued {
            let n = services::sent_result(self.qid, self.mid, self.peer, 1, scratch)?;
            transport.enqueue(&scratch[..n])?;
            self.result_queued = true;
            return Ok(false);
        }
        if credit {
            let n = queue.update(1, scratch)?;
            transport.enqueue(&scratch[..n])?;
        }
        Ok(true)
    }
}
pub(crate) struct PendingSend {
    send: Send,
    message: Vec<u8>,
}
impl Drop for PendingSend {
    fn drop(&mut self) {
        self.message.zeroize();
    }
}
struct Outbound {
    epoch: u64,
    serial: u64,
    wire_id: [u8; 4],
    peer: EddsaPublicKey,
    address: Vec<u8>,
    claimed: bool,
}
/// Process-level TCP communicator. A bounded caller-owned Session pool supplies
/// non-self-referential engine storage; each admitted peer owns only its own socket.
/// One PEERSTORE and one TRANSPORT connection serve every physical session.
/// This process exclusively owns writes to its official TCP monotime namespace:
/// each peer/kind scan and commit is serialized through its actual store result.
/// Caller-supplied engines use the same process PILS identity; callers bind
/// canonical listeners, supply persisted signature monotime, and retain reconnect
/// attempts. Every new scan/store must use the actual process ReplayHistory.
/// Local floor plus frontier durability precedes PS admission. Lost original
/// callbacks retire without replay; late remote REPLACE cannot lower local max.
/// No C service, native DNS shortcut or detached task is embedded.
pub struct Communicator<'a> {
    owner: Arc<()>,
    slots: Vec<Slot<'a>>,
    capacity: ManagerCapacity,
    queue_capacity: u64,
    callbacks: usize,
    generation: u64,
    peerstore: Link,
    transport: Link,
    peerstore_epoch: u64,
    transport_epoch: u64,
    queries: Vec<Option<Replay<'a>>>,
    histories: Vec<Option<Claim>>,
    retired_metrics: gnunet_tcp_communicator_core::metrics::Metrics,
    history_tainted: bool,
    stores: Vec<Option<Replay<'a>>>,
    flows: Vec<Option<Flow<'a>>>,
    rid: u32,
    fc: u64,
    qid: u32,
    command_serial: u64,
    commands: VecDeque<Outbound>,
    scratch: Vec<u8>,
    announce: bool,
    shutdown: bool,
    task_cursor: usize,
    timer: Pin<Box<tokio::time::Sleep>>,
    timer_key: Option<(u64, u64)>,
}
fn zeroes(n: usize) -> Result<Vec<u8>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    v.resize(n, 0);
    Ok(v)
}
fn empty_slots<T>(n: usize) -> Result<Vec<Option<T>>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    v.resize_with(n, || None);
    Ok(v)
}
impl<'a> Communicator<'a> {
    /// Adopt exactly one genuinely connected service pair and register once.
    pub fn new(
        services: [Connection; 2],
        ipc: Capacity,
        capacity: ManagerCapacity,
    ) -> Result<Self, HostError> {
        if capacity.sessions == 0
            || capacity.pending_sends == 0
            || capacity.commands == 0
            || ipc.callbacks == 0
        {
            return Err(Error::InvalidInput.into());
        }
        let queue_capacity = u64::try_from(capacity.pending_sends).map_err(|_| Error::Overflow)?;
        if queue_capacity == u64::MAX {
            return Err(Error::InvalidInput.into());
        }
        capacity
            .sessions
            .checked_mul(4)
            .and_then(|n| n.checked_add(4))
            .ok_or(Error::Overflow)?;
        let replay = capacity
            .sessions
            .checked_mul(REPLAY_CAPACITY)
            .ok_or(Error::Overflow)?;
        let callbacks = capacity
            .sessions
            .checked_mul(ipc.callbacks)
            .ok_or(Error::Overflow)?;
        let [ps, tr] = services;
        let peerstore = Link::new(ps, ipc.ipc_bytes, ipc.ipc_frames)?;
        let mut transport = Link::new(tr, ipc.ipc_bytes, ipc.ipc_frames)?;
        let mut scratch = zeroes(65535)?;
        let n = services::communicator_available(&mut scratch)?;
        transport.enqueue(&scratch[..n])?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity.sessions)
            .map_err(|_| Error::Capacity)?;
        slots.resize_with(capacity.sessions, || Slot {
            generation: 0,
            peer: None,
        });
        let mut commands = VecDeque::new();
        commands
            .try_reserve_exact(capacity.commands)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            owner: Arc::new(()),
            slots,
            capacity,
            queue_capacity,
            callbacks: ipc.callbacks,
            generation: 0,
            peerstore,
            transport,
            peerstore_epoch: 0,
            transport_epoch: 0,
            queries: empty_slots(replay)?,
            histories: empty_slots(replay)?,
            retired_metrics: Default::default(),
            history_tainted: false,
            stores: empty_slots(replay)?,
            flows: empty_slots(callbacks)?,
            rid: 0,
            fc: 0,
            qid: 0,
            command_serial: 0,
            commands,
            scratch,
            announce: false,
            shutdown: false,
            task_cursor: 0,
            timer: Box::pin(tokio::time::sleep_until(tokio::time::Instant::now())),
            timer_key: None,
        })
    }
    fn id(&self, key: Key) -> SessionId {
        SessionId {
            owner: self.owner.clone(),
            key,
        }
    }
    fn validate(&self, id: &SessionId) -> Result<Key, Error> {
        if !Arc::ptr_eq(&self.owner, &id.owner) {
            return Err(Error::Stale);
        }
        self.peer(id.key)?;
        Ok(id.key)
    }
    fn peer(&self, key: Key) -> Result<&Peer<'a>, Error> {
        let slot = self.slots.get(key.index).ok_or(Error::Stale)?;
        if slot.generation != key.generation {
            return Err(Error::Stale);
        }
        slot.peer.as_ref().ok_or(Error::Stale)
    }
    /// Inspect one original session without granting service callback authority.
    pub fn core(&self, id: &SessionId) -> Result<&Session<'a>, Error> {
        Ok(&self.peer(self.validate(id)?)?.core)
    }
    /// Current live owner count, including detached peers draining callbacks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.peer.is_some()).count()
    }
    /// Whether no physical peer owner is retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Adopt an actual socket and externally allocated engine; refusal returns both.
    pub fn admit(
        &mut self,
        core: Box<Session<'a>>,
        connection: Connection,
        address: &[u8],
        network: u32,
    ) -> Result<SessionId, Rejected<(Box<Session<'a>>, Connection)>> {
        let ready = match self.prepare(address) {
            Ok(p) => p,
            Err(reason) => {
                return Err(Rejected {
                    reason,
                    value: (core, connection),
                });
            }
        };
        Ok(self.install(core, Some(connection), None, ready, network))
    }
    /// Adopt the same actual socket with a retained prefix and original proto
    /// bound. Refusal returns the original engine/socket; no bytes are reread.
    pub fn admit_prefixed(
        &mut self,
        core: Box<Session<'a>>,
        connection: Connection,
        input: NativeAdmission<'_>,
    ) -> Result<SessionId, Rejected<(Box<Session<'a>>, Connection)>> {
        let prepared = (|| -> Result<Prepared, Error> {
            input.bounds.check(input.now)?;
            let mut ready = self.prepare(input.address)?;
            if input.prefix.len() > ready.rx.len() {
                return Err(Error::Capacity);
            }
            ready.rx[..input.prefix.len()].copy_from_slice(input.prefix);
            ready.prefix = input.prefix.len();
            ready.initial = Some(crate::peer::ProtoGuard::new(input.bounds));
            input.bounds.check(input.now)?;
            Ok(ready)
        })();
        match prepared {
            Ok(ready) => Ok(self.install(core, Some(connection), None, ready, input.network)),
            Err(reason) => Err(Rejected {
                reason,
                value: (core, connection),
            }),
        }
    }
    fn prepare(&self, address: &[u8]) -> Result<Prepared, Error> {
        if self.shutdown || address.contains(&0) || address.len() > 65470 {
            return Err(Error::InvalidInput);
        }
        let index = self
            .slots
            .iter()
            .position(|s| s.peer.is_none())
            .ok_or(Error::Capacity)?;
        let generation = self.generation.checked_add(1).ok_or(Error::Capacity)?;
        let next_qid = self.qid.checked_add(1).ok_or(Error::Capacity)?;
        let mut addr = Vec::new();
        addr.try_reserve_exact(address.len())
            .map_err(|_| Error::Capacity)?;
        addr.extend_from_slice(address);
        let mut sends = VecDeque::new();
        sends
            .try_reserve_exact(self.capacity.pending_sends)
            .map_err(|_| Error::Capacity)?;
        Ok(Prepared {
            index,
            generation,
            next_qid,
            address: addr,
            rx: zeroes(65571)?,
            sends,
            prefix: 0,
            initial: None,
        })
    }
    fn install(
        &mut self,
        core: Box<Session<'a>>,
        peer: Option<Connection>,
        connecting: Option<Connect<'a>>,
        ready: Prepared,
        network: u32,
    ) -> SessionId {
        let Prepared {
            index,
            generation,
            next_qid,
            address,
            rx,
            sends,
            prefix,
            initial,
        } = ready;
        let key = Key { index, generation };
        self.slots[index] = Slot {
            generation,
            peer: Some(Peer {
                core,
                peer,
                connecting,
                address,
                network,
                qid: self.qid,
                queue: false,
                reannounce: false,
                rx,
                rx_position: 0,
                rx_size: prefix,
                initial,
                pending_send: None,
                sends,
            }),
        };
        self.generation = generation;
        self.qid = next_qid;
        self.id(key)
    }
    /// Admit one retained real native connect future and its outbound core.
    /// The future is polled by this manager and survives canceled drive waits.
    /// Success means ownership of the attempt, not successful TCP/authentication.
    pub fn admit_connecting(
        &mut self,
        core: Box<Session<'a>>,
        connecting: Connect<'a>,
        address: &[u8],
        network: u32,
    ) -> Result<SessionId, Rejected<(Box<Session<'a>>, Connect<'a>)>> {
        let ready = match self.prepare(address) {
            Ok(p) => p,
            Err(reason) => {
                return Err(Rejected {
                    reason,
                    value: (core, connecting),
                });
            }
        };
        Ok(self.install(core, None, Some(connecting), ready, network))
    }
    /// Begin graceful close of exactly one original peer.
    pub fn finish(&mut self, id: &SessionId, time: Time) -> Result<(), HostError> {
        let key = self.validate(id)?;
        self.slots[key.index]
            .peer
            .as_mut()
            .ok_or(Error::Stale)?
            .core
            .finish(time)?;
        Ok(())
    }
    /// Record actual EOF/fatal loss of one original peer; cleanup is still driven.
    pub fn lost(&mut self, id: &SessionId) -> Result<(), Error> {
        let key = self.validate(id)?;
        self.slots[key.index]
            .peer
            .as_mut()
            .ok_or(Error::Stale)?
            .core
            .native_lost();
        Ok(())
    }
    /// Disallow new peers and start bounded graceful close of every original peer.
    pub fn begin_shutdown(&mut self, time: Time) -> Result<(), HostError> {
        self.shutdown = true;
        for p in self.slots.iter_mut().filter_map(|s| s.peer.as_mut()) {
            p.core.finish(time)?;
        }
        Ok(())
    }
    /// Physical peers, original callbacks and previously admitted service bytes drained.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.slots.iter().filter_map(|s| s.peer.as_ref()).all(|p| {
            p.core.phase() == Phase::Closed && p.sends.is_empty() && p.pending_send.is_none()
        }) && self.histories.iter().all(Option::is_none)
            && self.queries.iter().all(Option::is_none)
            && self.stores.iter().all(Option::is_none)
            && self.flows.iter().all(Option::is_none)
            && self.commands.is_empty()
            && self.peerstore.empty()
            && self.transport.empty()
    }
    /// Return the engine only after its peer/callback ownership has fully retired.
    /// The slot can then admit a new generation with a fresh, never-reused queue ID.
    pub fn retire(&mut self, id: &SessionId) -> Result<Box<Session<'a>>, Error> {
        let key = self.validate(id)?;
        if self.peer(key)?.core.phase() != Phase::Closed
            || self.histories.iter().flatten().any(|r| r.key == key)
            || self.queries.iter().flatten().any(|r| r.key == key)
            || self.stores.iter().flatten().any(|r| r.key == key)
            || self.flows.iter().flatten().any(|r| r.key == key)
        {
            return Err(Error::WouldBlock);
        }
        let p = self.slots[key.index].peer.take().ok_or(Error::Stale)?;
        self.retired_metrics.add_retired(p.core.metrics());
        Ok(p.core)
    }
    /// Cumulative actual Session counters plus only currently advertised queue gauge.
    #[must_use]
    pub fn metrics(&self) -> gnunet_tcp_communicator_core::metrics::Metrics {
        let mut metrics = self.retired_metrics;
        for peer in self.slots.iter().filter_map(|slot| slot.peer.as_ref()) {
            metrics.add_active(peer.core.metrics());
        }
        metrics
    }
    /// Whether a physical PS epoch counter exhausted or source invariants were
    /// lost. Ordinary late remote writes are protected by the durable local
    /// floor; they are not called quiescent merely because MQ was reconnected.
    #[must_use]
    pub fn peerstore_recovery_required(&self) -> bool {
        self.history_tainted
    }
    /// Drop only the failed PEERSTORE MQ and fail its original live callbacks once.
    pub fn peerstore_lost(&mut self, time: Time) -> Result<(), Error> {
        if !self.peerstore.online() {
            return Ok(());
        }
        self.peerstore.disconnect();
        // Retire each original protected local task before fallible callbacks.
        // Late remote writes remain possible; the real local floor is retained.
        for i in 0..self.stores.len() {
            if let Some(r) = self.stores[i]
                && let Some(claim) = self.histories.get_mut(r.history).and_then(Option::as_mut)
            {
                claim.retiring = true;
            }
        }
        let mut first = None;
        match self.peerstore_epoch.checked_add(1) {
            Some(epoch) => self.peerstore_epoch = epoch,
            None => {
                self.history_tainted = true;
                first = Some(Error::Capacity);
            }
        }
        for i in 0..self.queries.len() {
            if let Some(r) = self.queries[i].take() {
                let slot = &mut self.slots[r.key.index];
                if slot.generation == r.key.generation
                    && let Some(p) = slot.peer.as_mut()
                {
                    let result = if r.ended {
                        p.core.finish(time)
                    } else {
                        p.core.replay_failed(r.ticket, time)
                    };
                    if let Err(error) = result {
                        p.core.native_lost();
                        if first.is_none() {
                            first = Some(error);
                        }
                    }
                }
            }
        }
        for i in 0..self.stores.len() {
            if let Some(r) = self.stores[i].take() {
                let slot = &mut self.slots[r.key.index];
                if !r.canceled
                    && slot.generation == r.key.generation
                    && let Some(p) = slot.peer.as_mut()
                    && let Err(error) = p.core.replay_stored(r.ticket, false)
                {
                    p.core.native_lost();
                    if first.is_none() {
                        first = Some(error);
                    }
                }
            }
        }
        match first {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    /// Whether this same original manager currently owns a TRANSPORT MQ.
    /// This is physical attachment, not registration, queue or peer acceptance.
    #[must_use]
    pub fn transport_online(&self) -> bool {
        self.transport.online()
    }
    /// Original service-source generation. Loss advances it; attaching a new MQ
    /// never restores an old CREATE, SEND or receive-flow continuation.
    #[must_use]
    pub const fn transport_epoch(&self) -> u64 {
        self.transport_epoch
    }
    /// All current peer queue replay intents were locally admitted and every
    /// queued IPC byte was actually written on this MQ. No remote ACK is implied.
    /// This observes existing state and does not gate duplex read/write progress.
    #[must_use]
    pub fn transport_reannounced(&self) -> bool {
        self.transport.online()
            && !self.announce
            && self
                .slots
                .iter()
                .filter_map(|slot| slot.peer.as_ref())
                .all(|peer| !peer.reannounce)
            && self.transport.empty()
    }
    /// Fail original receive continuations once, retaining physical peers and queues.
    pub fn transport_lost(&mut self, time: Time) -> Result<(), Error> {
        if !self.transport.online() {
            return Ok(());
        }
        self.transport.disconnect();
        let mut first = match self.transport_epoch.checked_add(1) {
            Some(epoch) => {
                self.transport_epoch = epoch;
                None
            }
            None => Some(Error::Capacity),
        };
        self.commands.clear();
        self.announce = false;
        for p in self.slots.iter_mut().filter_map(|s| s.peer.as_mut()) {
            p.pending_send = None;
            p.sends.clear();
            p.reannounce = false;
        }
        for i in 0..self.flows.len() {
            if let Some(r) = self.flows[i].take() {
                let slot = &mut self.slots[r.key.index];
                if slot.generation == r.key.generation
                    && let Some(p) = slot.peer.as_mut()
                    && let Err(error) = p.core.completed(r.ticket, false, time.now)
                {
                    p.core.native_lost();
                    if first.is_none() {
                        first = Some(error);
                    }
                }
            }
        }
        match first {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    /// Install one actual replacement PEERSTORE connection without reviving old callbacks.
    pub fn attach_peerstore(&mut self, connection: Connection) -> Result<(), Rejected<Connection>> {
        if self.peerstore_epoch == u64::MAX {
            return Err(Rejected {
                reason: Error::Capacity,
                value: connection,
            });
        }
        self.peerstore.attach(connection)
    }
    /// Reconnect once; preserve queue identities and reannounce each surviving queue.
    pub fn attach_transport(&mut self, connection: Connection) -> Result<(), Rejected<Connection>> {
        if self.shutdown {
            return Err(Rejected {
                reason: Error::Closed,
                value: connection,
            });
        }
        if self.transport_epoch == u64::MAX {
            return Err(Rejected {
                reason: Error::Capacity,
                value: connection,
            });
        }
        self.transport.attach(connection)?;
        self.announce = true;
        for p in self.slots.iter_mut().filter_map(|s| s.peer.as_mut()) {
            // A terminal native session is not a queue on a replacement MQ.
            // The core still retires its original leases through QueueDelete.
            p.queue &= p.core.phase() == Phase::Established;
            p.reannounce = p.queue;
        }
        Ok(())
    }
    fn announce(&mut self) -> Result<(), HostError> {
        if self.announce {
            let n = services::communicator_available(&mut self.scratch)?;
            self.transport.enqueue(&self.scratch[..n])?;
            self.announce = false;
        }
        Ok(())
    }
    /// Publish this actual listener/NAT-owned address on the original MQ. Failed
    /// capacity retains the caller's original intent; registration stays FIFO first.
    pub fn advertise(&mut self, id: u32, address: &[u8], network: u32) -> Result<(), HostError> {
        if self.shutdown {
            return Err(Error::Closed.into());
        }
        if !self.transport.online() {
            return Err(Error::WouldBlock.into());
        }
        self.announce()?;
        let n = services::address_add_owned(id, address, network, u64::MAX, &mut self.scratch)?;
        self.transport.enqueue(&self.scratch[..n])?;
        Ok(())
    }
    /// Withdraw only this original listener address while draining its epoch.
    pub fn withdraw(&mut self, id: u32) -> Result<(), HostError> {
        if !self.transport.online() {
            return Err(Error::WouldBlock.into());
        }
        self.announce()?;
        let n = services::address_remove(id, &mut self.scratch)?;
        self.transport.enqueue(&self.scratch[..n])?;
        Ok(())
    }
    /// Inspect one bounded owned CREATE without borrowing the shared RX frame.
    pub fn command(&self) -> Option<CreateRequest<'_>> {
        self.commands.front().map(|r| CreateRequest {
            id: CreateId {
                owner: self.owner.clone(),
                epoch: r.epoch,
                serial: r.serial,
            },
            wire_id: r.wire_id,
            peer: r.peer,
            address: &r.address,
        })
    }
    /// Claim the original front request before a native side effect. Shutdown
    /// retains this caller-owned result instead of inventing a negative response.
    pub fn claim_create(&mut self, id: &CreateId) -> Result<(), HostError> {
        let request = self.commands.front_mut().ok_or(Error::Stale)?;
        if !Arc::ptr_eq(&id.owner, &self.owner)
            || id.epoch != self.transport_epoch
            || request.epoch != id.epoch
            || request.serial != id.serial
            || request.claimed
        {
            return Err(Error::Stale.into());
        }
        request.claimed = true;
        Ok(())
    }
    /// Acknowledge only this original admitted/failed native connection attempt.
    pub fn created(&mut self, id: &CreateId, accepted: bool) -> Result<(), HostError> {
        let r = self.commands.front().ok_or(Error::Stale)?;
        if !Arc::ptr_eq(&id.owner, &self.owner)
            || id.epoch != self.transport_epoch
            || r.epoch != id.epoch
            || r.serial != id.serial
        {
            return Err(Error::Stale.into());
        }
        let n = services::create_result(r.wire_id, accepted, &mut self.scratch)?;
        self.transport.enqueue(&self.scratch[..n])?;
        self.commands.pop_front();
        Ok(())
    }
    fn ps_reply(&mut self, time: Time) -> Result<bool, Error> {
        let Some(bytes) = self.peerstore.frame() else {
            return Ok(false);
        };
        match Peerstore::decode(bytes)? {
            Peerstore::End(rid, status) => {
                if let Some(i) = self.queries.iter().position(|r| {
                    r.is_some_and(|r| r.rid == rid && r.epoch == self.peerstore_epoch && !r.ended)
                }) {
                    let r = self.queries[i].ok_or(Error::Stale)?;
                    let slot = &mut self.slots[r.key.index];
                    if slot.generation != r.key.generation {
                        return Err(Error::Stale);
                    }
                    let p = slot.peer.as_mut().ok_or(Error::Stale)?;
                    if status < 0 {
                        p.core.replay_failed(r.ticket, time)?;
                        self.queries[i] = None;
                    } else {
                        p.core.replay_record(r.ticket, None, time)?;
                        if matches!(
                            p.core.phase(),
                            Phase::Finishing | Phase::Closing | Phase::Detached | Phase::Closed
                        ) {
                            self.queries[i] = None;
                        } else {
                            self.queries[i].as_mut().ok_or(Error::Stale)?.ended = true;
                        }
                    }
                }
            }
            Peerstore::Stored(rid, status) => {
                if let Some(i) = self.stores.iter().position(|r| {
                    r.is_some_and(|r| r.rid == rid && r.epoch == self.peerstore_epoch)
                }) {
                    let r = self.stores[i].take().ok_or(Error::Stale)?;
                    let slot = &mut self.slots[r.key.index];
                    if slot.generation != r.key.generation {
                        return Err(Error::Stale);
                    }
                    if !r.canceled {
                        slot.peer
                            .as_mut()
                            .ok_or(Error::Stale)?
                            .core
                            .replay_stored(r.ticket, status == 1)?;
                    }
                    for q in &mut self.queries {
                        if q.is_some_and(|q| q.ended && q.key == r.key && q.kind == r.kind) {
                            *q = None;
                        }
                    }
                }
            }
            Peerstore::Record(rid, peer, subsystem, key_name, value) => {
                if let Some(r) = self
                    .queries
                    .iter()
                    .flatten()
                    .find(|r| r.rid == rid && r.epoch == self.peerstore_epoch && !r.ended)
                {
                    if peer != r.peer
                        || subsystem != services::SUBSYSTEM
                        || key_name != r.kind.key()
                    {
                        return Err(Error::Malformed);
                    }
                    let slot = &mut self.slots[r.key.index];
                    if slot.generation != r.key.generation {
                        return Err(Error::Stale);
                    }
                    slot.peer.as_mut().ok_or(Error::Stale)?.core.replay_record(
                        r.ticket,
                        Some(value),
                        time,
                    )?;
                }
            }
            Peerstore::Unknown(_) => {}
        }
        self.peerstore.release();
        Ok(true)
    }
    fn reject_send(&mut self, send: Send) -> Result<(), Error> {
        let n = services::sent_result(send.qid, send.mid, send.peer, 0, &mut self.scratch)?;
        self.transport.enqueue(&self.scratch[..n])?;
        Ok(())
    }
    fn withdraw_queue(
        peer: &mut Peer<'_>,
        transport: &mut Link,
        scratch: &mut [u8],
    ) -> Result<bool, Error> {
        if !peer.queue {
            return Ok(false);
        }
        let target = peer.core.target().ok_or(Error::NotReady)?;
        let n = services::Queue::new(
            target,
            peer.qid,
            peer.network,
            peer.core.role(),
            &peer.address,
        )
        .teardown(scratch)?;
        // A bounded cleanup admission precedes local withdrawal. WouldBlock
        // leaves the original route and unsent owners intact for the next turn.
        transport.cleanup(&scratch[..n])?;
        peer.queue = false;
        peer.reannounce = false;
        peer.sends.clear();
        // The active BOX/ratchet and its original continuation still belong to
        // the core; closing a route cannot cancel/replay an admitted record.
        Ok(true)
    }
    fn tr_reply(&mut self, time: Time) -> Result<Option<Activity>, Error> {
        let Some(bytes) = self.transport.frame() else {
            return Ok(None);
        };
        match Transport::decode(bytes)? {
            Transport::Received(id, peer) => {
                let i = self
                    .flows
                    .iter()
                    .position(|r| {
                        r.is_some_and(|r| {
                            r.id == id && r.peer == peer && r.epoch == self.transport_epoch
                        })
                    })
                    .ok_or(Error::Malformed)?;
                let r = self.flows[i].take().ok_or(Error::Stale)?;
                let slot = &mut self.slots[r.key.index];
                if slot.generation != r.key.generation {
                    return Err(Error::Stale);
                }
                slot.peer
                    .as_mut()
                    .ok_or(Error::Stale)?
                    .core
                    .completed(r.ticket, true, time.now)?;
            }
            Transport::Send(qid, mid, peer, message) => {
                let send = Send {
                    qid: qid.to_be_bytes(),
                    mid,
                    peer,
                    epoch: self.transport_epoch,
                    result_queued: false,
                };
                let slot = self.slots.iter_mut().find_map(|s| {
                    s.peer
                        .as_mut()
                        .filter(|p| p.queue && p.qid == qid && p.core.target() == Some(peer))
                });
                if let Some(p) = slot {
                    if p.core.phase() != Phase::Established {
                        Self::withdraw_queue(p, &mut self.transport, &mut self.scratch)?;
                        self.reject_send(send)?;
                    } else if p.sends.len() == self.capacity.pending_sends {
                        // Keep the exact held SEND. Exhausting a local buffer is
                        // not a failed route: negative ACK would make TRANSPORT
                        // delete an otherwise live, authenticated TCP queue.
                        return Err(Error::WouldBlock);
                    } else {
                        let mut owned = Vec::new();
                        owned
                            .try_reserve_exact(message.len())
                            .map_err(|_| Error::Capacity)?;
                        owned.extend_from_slice(message);
                        p.sends.push_back(PendingSend {
                            send,
                            message: owned,
                        });
                    }
                } else {
                    self.reject_send(send)?;
                }
            }
            Transport::Create(wire_id, peer, address) => {
                if self.shutdown {
                    let n = services::create_result(wire_id, false, &mut self.scratch)?;
                    self.transport.enqueue(&self.scratch[..n])?;
                    self.transport.release();
                    return Ok(Some(Activity::Callback));
                }
                if self.commands.len() >= self.capacity.commands {
                    return Err(Error::WouldBlock);
                }
                let serial = self.command_serial.checked_add(1).ok_or(Error::Capacity)?;
                let mut owned = Vec::new();
                owned
                    .try_reserve_exact(address.len())
                    .map_err(|_| Error::Capacity)?;
                owned.extend_from_slice(address);
                self.commands.push_back(Outbound {
                    claimed: false,
                    epoch: self.transport_epoch,
                    serial,
                    wire_id,
                    peer,
                    address: owned,
                });
                self.command_serial = serial;
                self.transport.release();
                return Ok(Some(Activity::Registry));
            }
            Transport::Backchannel(..) | Transport::Burst(..) | Transport::Unknown(_) => {}
        }
        self.transport.release();
        Ok(Some(Activity::Callback))
    }
    fn admit_effect(
        &mut self,
        cx: &mut Context<'_>,
        ports: &mut impl ReplayHistory,
        index: usize,
        time: Time,
        entropy: &mut impl Entropy,
    ) -> Result<Option<Activity>, HostError> {
        if self.transport.online() && self.announce {
            let n = services::communicator_available(&mut self.scratch)?;
            self.transport.enqueue(&self.scratch[..n])?;
            self.announce = false;
            return Ok(Some(Activity::Admitted));
        }
        let slot = self.slots.get_mut(index).ok_or(Error::Stale)?;
        let key = Key {
            index,
            generation: slot.generation,
        };
        let Some(p) = slot.peer.as_mut() else {
            return Ok(None);
        };
        if p.core.phase() != Phase::Established
            && Self::withdraw_queue(p, &mut self.transport, &mut self.scratch)?
        {
            return Ok(Some(Activity::Admitted));
        }
        if self.transport.online() && p.reannounce {
            if let Some(peer) = p.core.target() {
                let n = services::Queue::new(peer, p.qid, p.network, p.core.role(), &p.address)
                    .setup(self.queue_capacity, &mut self.scratch)?;
                self.transport.enqueue(&self.scratch[..n])?;
            }
            p.reannounce = false;
            return Ok(Some(Activity::Admitted));
        }
        if p.pending_send.is_none()
            && let Some(s) = p.sends.front()
        {
            match p.core.send(&s.message) {
                Ok(()) => {
                    p.pending_send = Some(s.send);
                    p.sends.pop_front();
                    return Ok(Some(Activity::Prepared));
                }
                Err(Error::WouldBlock) => {}
                Err(Error::Closed | Error::NotReady) => {
                    p.core.finish(time)?;
                    Self::withdraw_queue(p, &mut self.transport, &mut self.scratch)?;
                    return Ok(Some(Activity::Admitted));
                }
                Err(e) => return Err(e.into()),
            }
        }
        let Some(t) = p.core.next_effect()? else {
            return Ok(None);
        };
        match p.core.effect(t)? {
            Effect::ReplayStart {
                kind,
                peer,
                received,
            } => {
                if self.history_tainted {
                    p.core.acknowledge(t, ResultKind::Failed, time, entropy)?;
                    return Err(Error::OutcomeUnknown.into());
                }
                if self
                    .queries
                    .iter()
                    .flatten()
                    .any(|r| r.peer == peer && r.kind == kind)
                {
                    p.core.defer_effect(t)?;
                    return Ok(None);
                }
                if p.core.phase() == Phase::Closing {
                    p.core.acknowledge(t, ResultKind::Failed, time, entropy)?;
                    return Ok(Some(Activity::Admitted));
                }
                let route = self
                    .queries
                    .iter()
                    .position(Option::is_none)
                    .ok_or(Error::Capacity)?;
                let id = self.rid.checked_add(1).ok_or(Error::Capacity)?;
                let history = self
                    .histories
                    .iter()
                    .position(Option::is_none)
                    .ok_or(Error::Capacity)?;
                let task = ReplayTask::new(
                    SessionId {
                        owner: self.owner.clone(),
                        key,
                    },
                    self.peerstore_epoch,
                    id,
                    peer,
                    kind,
                    received,
                );
                let local = match ports.local_floor(&task) {
                    Ok(value) => value,
                    Err(Error::WouldBlock) => {
                        p.core.defer_effect(t)?;
                        return Ok(None);
                    }
                    Err(error) => {
                        p.core.acknowledge(t, ResultKind::Failed, time, entropy)?;
                        return Err(error.into());
                    }
                };
                let n = services::replay_start(id, peer, kind, &mut self.scratch)?;
                self.peerstore.tagged(&self.scratch[..n], id)?;
                self.histories[history] = Some(Claim {
                    task,
                    key,
                    query: route,
                    store: None,
                    retiring: false,
                    requested: false,
                    retired: false,
                });
                self.rid = id;
                self.queries[route] = Some(Replay {
                    rid: id,
                    ticket: t,
                    key,
                    epoch: self.peerstore_epoch,
                    peer,
                    kind,
                    ended: false,
                    canceled: false,
                    history,
                });
                p.core.acknowledge(t, ResultKind::Success, time, entropy)?;
                if let Some(floor) = local {
                    p.core.replay_floor(t, floor, time)?;
                }
            }
            Effect::ReplayStore { kind, peer, value } => {
                if matches!(
                    p.core.phase(),
                    Phase::Finishing | Phase::Closing | Phase::Detached | Phase::Closed
                ) {
                    p.core.acknowledge(t, ResultKind::Failed, time, entropy)?;
                    return Ok(Some(Activity::Admitted));
                }
                let history = self
                    .queries
                    .iter()
                    .flatten()
                    .find(|row| {
                        row.key == key
                            && row.kind == kind
                            && row.epoch == self.peerstore_epoch
                            && row.ended
                    })
                    .ok_or(Error::Stale)?
                    .history;
                let original = &self.histories[history].as_ref().ok_or(Error::Stale)?.task;
                if original.peer() != peer || original.kind() != kind {
                    return Err(Error::Stale.into());
                }
                let stamp = u64::from_be_bytes(value);
                match ports.poll_store(cx, original, stamp) {
                    Poll::Pending => {
                        p.core.defer_effect(t)?;
                        return Ok(None);
                    }
                    Poll::Ready(Err(error)) => {
                        p.core.acknowledge(t, ResultKind::Failed, time, entropy)?;
                        self.histories[history]
                            .as_mut()
                            .ok_or(Error::Stale)?
                            .retiring = true;
                        return Err(error.into());
                    }
                    Poll::Ready(Ok(())) => {}
                }
                let route = self
                    .stores
                    .iter()
                    .position(Option::is_none)
                    .ok_or(Error::Capacity)?;
                let id = self.rid.checked_add(1).ok_or(Error::Capacity)?;
                let n = services::replay_store(id, peer, kind, value, &mut self.scratch)?;
                self.peerstore.tagged(&self.scratch[..n], id)?;
                ports.store_admitted(original, stamp);
                self.rid = id;
                self.stores[route] = Some(Replay {
                    rid: id,
                    ticket: t,
                    key,
                    epoch: self.peerstore_epoch,
                    peer,
                    kind,
                    ended: false,
                    canceled: false,
                    history,
                });
                self.histories[history].as_mut().ok_or(Error::Stale)?.store = Some(route);
                p.core.acknowledge(t, ResultKind::Success, time, entropy)?;
            }
            Effect::ReplayNext(_k, original) => {
                let q = self
                    .queries
                    .iter()
                    .flatten()
                    .find(|q| {
                        q.key == key && q.epoch == self.peerstore_epoch && q.ticket == original
                    })
                    .copied()
                    .ok_or(Error::Stale)?;
                let n = services::replay_next(q.rid, &mut self.scratch)?;
                self.peerstore.enqueue(&self.scratch[..n])?;
                p.core.acknowledge(t, ResultKind::Success, time, entropy)?;
            }
            Effect::ReplayCancel(_k, store, original) => {
                if store {
                    if let Some(index) = self.stores.iter().position(|s| {
                        s.is_some_and(|s| {
                            s.key == key && s.epoch == self.peerstore_epoch && s.ticket == original
                        })
                    }) {
                        let s = self.stores[index].as_mut().ok_or(Error::Stale)?;
                        if self.peerstore.online() {
                            s.canceled = true;
                        } else {
                            let rid = s.rid;
                            self.stores[index] = None;
                            self.peerstore.cancel_offline(rid);
                            for q in &mut self.queries {
                                if q.is_some_and(|q| q.ended && q.key == key) {
                                    *q = None;
                                }
                            }
                        }
                    }
                } else if let Some(index) = self.queries.iter().position(|q| {
                    q.is_some_and(|q| {
                        q.key == key && q.epoch == self.peerstore_epoch && q.ticket == original
                    })
                }) {
                    let q = self.queries[index].ok_or(Error::Stale)?;
                    if self.peerstore.online() && !q.ended {
                        let n = services::replay_stop(q.rid, &mut self.scratch)?;
                        self.peerstore.cleanup(&self.scratch[..n])?;
                    } else {
                        self.peerstore.cancel_offline(q.rid);
                    }
                    self.queries[index] = None;
                }
                p.core.acknowledge(t, ResultKind::Success, time, entropy)?;
            }
            Effect::QueueAdd(peer, role) => {
                let q = services::Queue::new(peer, p.qid, p.network, role, &p.address);
                let n = q.setup(self.queue_capacity, &mut self.scratch)?;
                if self.transport.online() {
                    self.transport.enqueue(&self.scratch[..n])?;
                }
                p.queue = true;
                p.core.acknowledge(t, ResultKind::Success, time, entropy)?;
            }
            Effect::QueueDelete => {
                Self::withdraw_queue(p, &mut self.transport, &mut self.scratch)?;
                p.pending_send = None;
                p.sends.clear();
                p.core.acknowledge(t, ResultKind::Success, time, entropy)?;
            }
            Effect::Receive {
                peer,
                message,
                completion,
            } => {
                if p.core.phase() == Phase::Closing {
                    p.core.acknowledge(t, ResultKind::Failed, time, entropy)?;
                    return Ok(Some(Activity::Admitted));
                }
                if !self.transport.online() {
                    p.core
                        .acknowledge(t, ResultKind::Unavailable, time, entropy)?;
                    return Ok(Some(Activity::Admitted));
                }
                if self.flows.iter().flatten().filter(|f| f.key == key).count() >= self.callbacks {
                    return Ok(None);
                }
                let Some(slot) = self.flows.iter().position(Option::is_none) else {
                    return Ok(None);
                };
                let next = self.fc.checked_add(1).ok_or(Error::Capacity)?;
                let id = self.fc.to_ne_bytes();
                let n = match services::incoming(peer, id, message, &mut self.scratch) {
                    Ok(n) => n,
                    Err(Error::Overflow) => {
                        // The official 88-byte IPC prefix can exceed the local
                        // frame limit even for a valid TCP BOX. Refuse only this
                        // original receive; other peers retain their live flows.
                        p.core.acknowledge(t, ResultKind::Failed, time, entropy)?;
                        return Ok(Some(Activity::Admitted));
                    }
                    Err(e) => return Err(e.into()),
                };
                self.transport.enqueue(&self.scratch[..n])?;
                self.flows[slot] = Some(Flow {
                    id,
                    peer,
                    ticket: completion,
                    key,
                    epoch: self.transport_epoch,
                });
                self.fc = next;
                p.core.acknowledge(t, ResultKind::Queued, time, entropy)?;
            }
            Effect::SendContinue => {
                if let Some(s) = &mut p.pending_send {
                    let q = services::Queue::new(
                        s.peer,
                        u32::from_be_bytes(s.qid),
                        p.network,
                        p.core.role(),
                        &p.address,
                    );
                    if !s.complete(
                        &mut self.transport,
                        self.transport_epoch,
                        p.queue && p.core.phase() == Phase::Established,
                        &q,
                        &mut self.scratch,
                    )? {
                        // Retain the same leased continuation until its
                        // capacity frame is separately admitted. One-slot
                        // MQ budgets therefore never duplicate the ACK.
                        return Ok(Some(Activity::Admitted));
                    }
                    p.pending_send = None;
                }
                p.core.acknowledge(t, ResultKind::Success, time, entropy)?;
            }
            Effect::Close => {
                p.peer = None;
                p.connecting = None;
                for q in &mut self.queries {
                    if q.is_some_and(|q| {
                        q.ended
                            && q.key == key
                            && !self
                                .stores
                                .iter()
                                .flatten()
                                .any(|s| s.key == key && s.kind == q.kind)
                    }) {
                        *q = None;
                    }
                }
                p.core.acknowledge(t, ResultKind::Success, time, entropy)?;
                return Ok(Some(Activity::Closed));
            }
        }
        Ok(Some(Activity::Admitted))
    }
    fn service_failure(&mut self, time: Time, ps: bool, cause: ServiceCause) -> HostError {
        HostError::service_failure(ps, cause, || {
            if ps {
                self.peerstore_lost(time)
            } else {
                self.transport_lost(time)
            }
        })
    }
    fn poll_service_tx(
        &mut self,
        cx: &mut Context<'_>,
        time: Time,
        ps: bool,
    ) -> Poll<Result<Activity, HostError>> {
        if !ps
            && self.shutdown
            && self.transport.online()
            && let Some(wire_id) = self
                .commands
                .front()
                .filter(|r| !r.claimed)
                .map(|r| r.wire_id)
        {
            let attempt = (|| -> Result<(), HostError> {
                let n = services::create_result(wire_id, false, &mut self.scratch)?;
                self.transport.enqueue(&self.scratch[..n])?;
                self.commands.pop_front();
                Ok(())
            })();
            match attempt {
                Ok(()) => return Poll::Ready(Ok(Activity::Admitted)),
                Err(HostError::Core(Error::WouldBlock)) => {}
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        if !ps && self.announce && self.transport.online() {
            let attempt = self.announce();
            match attempt {
                Ok(()) => return Poll::Ready(Ok(Activity::Admitted)),
                Err(HostError::Core(Error::WouldBlock)) => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        let result = if ps {
            self.peerstore.poll_tx(cx)
        } else {
            self.transport.poll_tx(cx)
        };
        match result {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(Activity::Io)),
            Poll::Ready(Err(error)) => {
                Poll::Ready(Err(self.service_failure(time, ps, ServiceCause::Io(error))))
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_service_rx(
        &mut self,
        cx: &mut Context<'_>,
        time: Time,
        ps: bool,
    ) -> Poll<Result<Activity, HostError>> {
        let callback = if ps {
            self.ps_reply(time).map(|v| v.then_some(Activity::Callback))
        } else {
            self.tr_reply(time)
        };
        match callback {
            Ok(Some(a)) => return Poll::Ready(Ok(a)),
            Ok(None) | Err(Error::WouldBlock) => {}
            Err(error) => {
                return Poll::Ready(Err(self.service_failure(
                    time,
                    ps,
                    ServiceCause::Protocol(error),
                )));
            }
        }
        let result = if ps {
            self.peerstore.poll_rx(cx)
        } else {
            self.transport.poll_rx(cx)
        };
        match result {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(Activity::Io)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.service_failure(time, ps, error))),
            Poll::Pending => Poll::Pending,
        }
    }
    /// Poll one bounded fair task. Shared TX/RX and every peer direction/effect
    /// have separate rotating positions; one permanently ready peer cannot starve another.
    pub fn poll_step(
        &mut self,
        cx: &mut Context<'_>,
        time: Time,
        ports: &mut impl ReplayHistory,
        entropy: &mut impl Entropy,
    ) -> Poll<Result<Progress, HostError>> {
        self.poll_step_owned(cx, time, ports, entropy)
            .map(|r| r.map_err(|original| original.cause))
    }
    /// Poll one original task and retain its session identity on actual failure.
    /// The original native cause and shared-service distinction stay unchanged.
    pub fn poll_step_owned(
        &mut self,
        cx: &mut Context<'_>,
        time: Time,
        ports: &mut impl ReplayHistory,
        entropy: &mut impl Entropy,
    ) -> Poll<Result<Progress, OwnedFailure>> {
        if let Some(failure) = self.poll_native_guard(cx) {
            return Poll::Ready(Err(failure));
        }
        self.step_after_native(cx, time, ports, entropy)
    }
    /// Check/register original native proto guards before sampling canonical
    /// time or doing IO. Expiry physically closes only that original peer.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<OwnedFailure> {
        for index in 0..self.slots.len() {
            if let Some(peer) = &mut self.slots[index].peer
                && let Some(cause) = peer.poll_native_guard(cx)
            {
                let id = self.id(Key {
                    index,
                    generation: self.slots[index].generation,
                });
                return Some(OwnedFailure {
                    session: Some(id),
                    cause,
                });
            }
        }
        None
    }
    fn step_after_native(
        &mut self,
        cx: &mut Context<'_>,
        time: Time,
        ports: &mut impl ReplayHistory,
        entropy: &mut impl Entropy,
    ) -> Poll<Result<Progress, OwnedFailure>> {
        for index in 0..self.slots.len() {
            if let Some(peer) = &mut self.slots[index].peer
                && let Some(cause) = peer.check_proto_time(time.now)
            {
                let id = self.id(Key {
                    index,
                    generation: self.slots[index].generation,
                });
                return Poll::Ready(Err(OwnedFailure {
                    session: Some(id),
                    cause,
                }));
            }
        }
        if let Poll::Ready(result) = self.poll_history(cx, ports) {
            return Poll::Ready(
                result
                    .map(|activity| Progress {
                        session: None,
                        activity,
                    })
                    .map_err(|cause| OwnedFailure {
                        session: None,
                        cause,
                    }),
            );
        }
        let count = 4 + self.slots.len() * 4;
        for offset in 0..count {
            let task = (self.task_cursor + offset) % count;
            let result = match task {
                0 => self.poll_service_tx(cx, time, true),
                1 => self.poll_service_rx(cx, time, true),
                2 => self.poll_service_tx(cx, time, false),
                3 => self.poll_service_rx(cx, time, false),
                _ => {
                    let index = (task - 4) / 4;
                    if let Some(peer) = &mut self.slots[index].peer
                        && let Some(cause) = peer.check_proto_time(time.now)
                    {
                        let session = Some(self.id(Key {
                            index,
                            generation: self.slots[index].generation,
                        }));
                        return Poll::Ready(Err(OwnedFailure { session, cause }));
                    }
                    match (task - 4) % 4 {
                        0 => match self.slots[index].peer.as_mut() {
                            Some(p) => p.poll_connect(cx),
                            None => Poll::Pending,
                        },
                        1 => match self.slots[index].peer.as_mut() {
                            Some(p) => p.poll_read(cx, time, entropy),
                            None => Poll::Pending,
                        },
                        2 => match self.slots[index].peer.as_mut() {
                            Some(p) => p.poll_write(cx, time, entropy),
                            None => Poll::Pending,
                        },
                        _ => match self.admit_effect(cx, ports, index, time, entropy) {
                            Ok(Some(a)) => Poll::Ready(Ok(a)),
                            Ok(None) | Err(HostError::Core(Error::WouldBlock)) => Poll::Pending,
                            Err(e) => Poll::Ready(Err(e)),
                        },
                    }
                }
            };
            if let Poll::Ready(result) = result {
                for slot in &mut self.slots {
                    if let Some(peer) = &mut slot.peer {
                        peer.settle_proto(time.now);
                    }
                }
                self.task_cursor = (task + 1) % count;
                let session = if task < 4 {
                    None
                } else {
                    let index = (task - 4) / 4;
                    Some(self.id(Key {
                        index,
                        generation: self.slots[index].generation,
                    }))
                };
                return Poll::Ready(match result {
                    Ok(activity) => Ok(Progress { session, activity }),
                    Err(cause) => Err(OwnedFailure { session, cause }),
                });
            }
        }
        Poll::Pending
    }
    /// Drive every peer with one logical-clock subscription and earliest retained
    /// native wait. Revisions rebase waits, never protocol deadlines or signed monotime.
    pub fn poll_drive(
        &mut self,
        cx: &mut Context<'_>,
        clock: &mut (impl Clock + ReplayHistory),
        entropy: &mut impl Entropy,
    ) -> Poll<Result<Progress, HostError>> {
        self.poll_drive_owned(cx, clock, entropy)
            .map(|r| r.map_err(|original| original.cause))
    }
    /// Drive with the same retained clock/deadline and original failure identity.
    pub fn poll_drive_owned(
        &mut self,
        cx: &mut Context<'_>,
        clock: &mut (impl Clock + ReplayHistory),
        entropy: &mut impl Entropy,
    ) -> Poll<Result<Progress, OwnedFailure>> {
        if let Some(failure) = self.poll_native_guard(cx) {
            return Poll::Ready(Err(failure));
        }
        if let Poll::Ready(result) = self.poll_history(cx, clock) {
            return Poll::Ready(
                result
                    .map(|activity| Progress {
                        session: None,
                        activity,
                    })
                    .map_err(|cause| OwnedFailure {
                        session: None,
                        cause,
                    }),
            );
        }
        let time = match clock.read() {
            Ok(t) => t,
            Err(e) => {
                return Poll::Ready(Err(OwnedFailure {
                    session: None,
                    cause: e.into(),
                }));
            }
        };
        if let Poll::Ready(result) = self.step_after_native(cx, time, clock, entropy) {
            return Poll::Ready(result);
        }
        if clock.poll_change(cx).is_ready() {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let deadline = self
            .slots
            .iter()
            .filter_map(|s| s.peer.as_ref())
            .filter_map(|p| p.core.deadline())
            .filter(|d| *d != u64::MAX)
            .min();
        let Some(deadline) = deadline else {
            self.timer_key = None;
            return Poll::Pending;
        };
        let key = (deadline, clock.revision());
        if self.timer_key != Some(key) || self.timer.is_elapsed() {
            let Some(until) = tokio::time::Instant::now().checked_add(
                std::time::Duration::from_micros(deadline.saturating_sub(time.now)),
            ) else {
                return Poll::Ready(Err(OwnedFailure {
                    session: None,
                    cause: Error::Overflow.into(),
                }));
            };
            self.timer.as_mut().reset(until);
            self.timer_key = Some(key);
        }
        if std::future::Future::poll(self.timer.as_mut(), cx).is_ready() {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
    /// Cancellation drops only the wait future; original sockets/frames stay owned.
    pub async fn drive(
        &mut self,
        clock: &mut (impl Clock + ReplayHistory),
        entropy: &mut impl Entropy,
    ) -> Result<Progress, HostError> {
        poll_fn(|cx| self.poll_drive(cx, clock, entropy)).await
    }
    /// Wait for one fair actual step at a caller-supplied logical time.
    pub async fn step(
        &mut self,
        time: Time,
        ports: &mut impl ReplayHistory,
        entropy: &mut impl Entropy,
    ) -> Result<Progress, HostError> {
        poll_fn(|cx| self.poll_step(cx, time, ports, entropy)).await
    }
}

#[cfg(test)]
mod completion_tests;
