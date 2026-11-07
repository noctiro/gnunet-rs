use crate::NativeConnect;
use gnunet_crypto::{EddsaPublicKey, Entropy};
use gnunet_service_runtime::connection::Connection;
use gnunet_tcp_communicator_core::{
    registry::{Instance, Pending, Registry, Slot},
    session::{Buffers, Effect, Identity, Phase, Policy, ResultKind, Scope, Session, Time},
};
use gnunet_tcp_communicator_host::{
    Capacity, Clock, Communicator, CreateId, CreateRequest, HandshakeBounds, HostError,
    ManagerCapacity, NativeAdmission, OwnedFailure, Progress, SessionId,
};
use gnunet_types::Error;
use std::{
    io,
    net::Ipv4Addr,
    task::{Context, Poll},
};
/// Native admission failure. The original failed native resource is closed
/// before its pure registry/constructor right is released.
#[derive(Debug)]
pub enum AdmissionError {
    /// Actual bounded/protocol/key/entropy refusal.
    Core(Error),
    /// Actual original native socket error.
    Native(io::Error),
}
impl From<Error> for AdmissionError {
    fn from(e: Error) -> Self {
        Self::Core(e)
    }
}
impl From<io::Error> for AdmissionError {
    fn from(e: io::Error) -> Self {
        Self::Native(e)
    }
}
impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for AdmissionError {}
/// Caller-owned backing is borrowed once, then returned from every closed
/// Session. Active capacity stays fixed; there is no total-generation budget.
pub struct Setup<'a> {
    /// Actual connected PEERSTORE and TRANSPORT MQs, in that order.
    pub services: [Connection; 2],
    /// Current verified local identity capability for this caller-owned epoch.
    pub identity: Identity<'a>,
    /// One original registry scope; old tokens prevent resetting this scope.
    pub scope: &'a mut Scope,
    /// Fixed parent plus physical-generation metadata; length is checked twice
    /// the physical Session limit. This does not allocate additional payloads.
    pub slots: &'a mut [Slot],
    /// Once-allocated unique backing for each active slot.
    pub buffers: Vec<Buffers<'a>>,
    /// Original official crypto/timer defaults or explicit caller policy.
    pub policy: Policy,
    /// Physical IPC bounds.
    pub ipc: Capacity,
    /// Fixed active session, callback and CREATE bounds.
    pub capacity: ManagerCapacity,
    /// Current explicit configuration choice.
    pub disable_v6: bool,
}
/// Unique original IPv4 port-zero request. Copies of its diagnostic registry
/// identity do not grant another NAT submission or Session constructor right.
#[derive(Debug)]
#[must_use]
pub struct Reversal<'pool> {
    id: Instance<'pool>,
    peer: EddsaPublicKey,
    remote: Ipv4Addr,
    first_session: u64,
}
impl<'pool> Reversal<'pool> {
    /// Exact original registry allocation.
    pub const fn id(&self) -> Instance<'pool> {
        self.id
    }
    /// Expected signer, not authenticated by the clear probe.
    pub const fn peer(&self) -> EddsaPublicKey {
        self.peer
    }
    /// Actual original IPv4 target, with the reversal port omitted.
    pub const fn remote(&self) -> Ipv4Addr {
        self.remote
    }
}
struct Active {
    id: SessionId,
    sequence: u64,
}
/// Actual manager progress or release of one original closed generation.
#[derive(Debug)]
pub enum PoolProgress {
    /// Original native/service/callback activity, preserving original session ID.
    Manager(Progress),
    /// Closed original physical generation returned its original backing.
    Retired(SessionId),
}
/// Bounded reusable TCP session owner. The manager drops native/service resources
/// before registry/backing ownership. This owner creates no service or key source.
pub struct Pool<'a> {
    manager: Communicator<'a>,
    registry: Registry<'a>,
    free: Vec<Buffers<'a>>,
    active: Vec<Active>,
    identity: Identity<'a>,
    policy: Policy,
    capacity: usize,
    yield_due: bool,
    epoch: Option<crate::epoch::Epoch>,
    touched: bool,
    retiring: bool,
    next_session: u64,
}
impl<'a> Pool<'a> {
    /// Consume genuinely connected service owners and one fixed caller backing
    /// set. Failed setup closes these newly transferred physical resources.
    pub fn new(setup: Setup<'a>) -> Result<Self, HostError> {
        let Setup {
            services,
            identity,
            scope,
            slots,
            buffers,
            policy,
            ipc,
            capacity,
            disable_v6,
        } = setup;
        let metadata = capacity.sessions.checked_mul(2).ok_or(Error::Capacity)?;
        if capacity.sessions == 0 || slots.len() != metadata || buffers.len() != capacity.sessions {
            return Err(Error::InvalidInput.into());
        }
        let mut active = Vec::new();
        active
            .try_reserve_exact(capacity.sessions)
            .map_err(|_| Error::Capacity)?;
        let manager = Communicator::new(services, ipc, capacity)?;
        Ok(Self {
            manager,
            registry: Registry::new(scope, slots, disable_v6),
            free: buffers,
            active,
            identity,
            policy,
            capacity: capacity.sessions,
            yield_due: false,
            epoch: None,
            touched: false,
            retiring: false,
            next_session: 0,
        })
    }
    /// Bind the unique original durable epoch before any native/backend work.
    /// Wrong identities or an already-used pool return the same original token.
    pub fn bind_epoch(
        &mut self,
        epoch: crate::epoch::Epoch,
    ) -> Result<(), gnunet_types::Rejected<crate::epoch::Epoch>> {
        let reason = if self.touched || self.epoch.is_some() {
            Some(Error::Conflict)
        } else {
            (self.identity.public() != epoch.peer).then_some(Error::Authentication)
        };
        if let Some(reason) = reason {
            return Err(gnunet_types::Rejected {
                reason,
                value: epoch,
            });
        }
        self.epoch = Some(epoch);
        Ok(())
    }
    /// Consume/close the original service sockets only after all actual peers,
    /// callbacks and pending bytes drained and no backend uncertainty remains.
    /// An error returns this same original pool; no clean proof is fabricated.
    #[expect(
        clippy::result_large_err,
        reason = "Rejection retains the unique original pooled sockets, callbacks and backing without a new fallible allocation after retirement"
    )]
    pub fn into_quiescent(self) -> Result<crate::epoch::Quiescent, gnunet_types::Rejected<Self>> {
        if !self.is_empty()
            || self.registry.occupied() != 0
            || !self.manager.is_quiescent()
            || self.manager.peerstore_recovery_required()
            || self.epoch.is_none()
        {
            return Err(gnunet_types::Rejected {
                reason: Error::WouldBlock,
                value: self,
            });
        }
        let mut original = self;
        let Some(epoch) = original.epoch.take() else {
            return Err(gnunet_types::Rejected {
                reason: Error::Conflict,
                value: original,
            });
        };
        drop(original);
        Ok(crate::epoch::Quiescent { epoch })
    }
    /// Actual original manager counters/gauge, with retired counters preserved.
    #[must_use]
    pub fn metrics(&self) -> gnunet_tcp_communicator_core::metrics::Metrics {
        self.manager.metrics()
    }
    /// Number of original live physical generations, never authenticated peers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.active.len()
    }
    /// Whether no original session generation remains.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.active.is_empty()
    }
    /// Available original backing sets, independent of queue or wire credit.
    #[must_use]
    pub fn available(&self) -> usize {
        self.free.len()
    }
    /// Inspect actual phase/crypto state for this original manager token.
    pub fn core(&self, id: &SessionId) -> Result<&Session<'a>, Error> {
        self.manager.core(id)
    }
    /// Actual physical TRANSPORT attachment of this original manager.
    #[must_use]
    pub fn transport_online(&self) -> bool {
        self.manager.transport_online()
    }
    /// Current original TRANSPORT callback-source generation.
    #[must_use]
    pub fn transport_epoch(&self) -> u64 {
        self.manager.transport_epoch()
    }
    /// Current peer queue announcements and already admitted IPC bytes were
    /// wholly written locally. This is neither validation nor a remote ACK.
    #[must_use]
    pub fn transport_reannounced(&self) -> bool {
        self.manager.transport_reannounced()
    }
    /// Attach one genuinely connected replacement MQ to the same manager,
    /// backing, registry, sessions and original durable epoch. A rejected native
    /// owner is returned, never silently replaced or dropped as a success.
    pub fn attach_transport(
        &mut self,
        connection: Connection,
    ) -> Result<(), gnunet_types::Rejected<Connection>> {
        if self.retiring || self.manager.peerstore_recovery_required() {
            return Err(gnunet_types::Rejected {
                reason: Error::Closed,
                value: connection,
            });
        }
        self.manager.attach_transport(connection)
    }
    /// Publish one original actual listening address over the real MQ.
    pub fn advertise(&mut self, id: u32, address: &[u8], network: u32) -> Result<(), HostError> {
        self.touched = true;
        self.manager.advertise(id, address, network)
    }
    /// Withdraw one original address while retaining any native partial frame.
    pub fn withdraw(&mut self, id: u32) -> Result<(), HostError> {
        self.touched = true;
        self.manager.withdraw(id)
    }
    /// Close only this original failed peer; other native sessions stay owned.
    pub fn lost(&mut self, id: &SessionId) -> Result<(), Error> {
        self.manager.lost(id)
    }
    /// Original official CREATE command. Caller must preserve its id/address
    /// while starting real native admission and returning the actual result.
    pub fn command(&self) -> Option<CreateRequest<'_>> {
        self.manager.command()
    }
    /// Preserve this original CREATE result across native admission and shutdown.
    pub fn claim_create(&mut self, id: &CreateId) -> Result<(), HostError> {
        self.touched = true;
        self.manager.claim_create(id)
    }
    /// Return the result only after the actual original native admission decision.
    /// WouldBlock retains the caller's same original result; no connect is replayed.
    pub fn created(&mut self, id: &CreateId, accepted: bool) -> Result<(), HostError> {
        self.touched = true;
        self.manager.created(id, accepted)
    }
    fn check_room(&self) -> Result<(), Error> {
        if self.retiring {
            return Err(Error::Closed);
        }
        if self.free.is_empty()
            || self.active.len() == self.capacity
            || self.next_session == u64::MAX
        {
            Err(Error::Capacity)
        } else {
            Ok(())
        }
    }
    fn unadmitted(
        &mut self,
        mut core: Box<Session<'a>>,
        time: Time,
        entropy: &mut impl Entropy,
    ) -> Result<(), Error> {
        // Caller already physically dropped the rejected original native owner.
        core.native_lost();
        while let Some(ticket) = core.next_effect()? {
            if !matches!(core.effect(ticket)?, Effect::Close) {
                return Err(Error::Conflict);
            }
            core.acknowledge(ticket, ResultKind::Success, time, entropy)?;
        }
        self.registry.retire(&core)?;
        self.free
            .push((*core).into_buffers().map_err(|r| r.reason)?);
        Ok(())
    }
    /// Reserve one original port-zero intent without opening a socket or
    /// fabricating a NAT result. Actual submission requires PublishedPool.
    pub fn plan_reversal(
        &mut self,
        peer: EddsaPublicKey,
        address: &[u8],
    ) -> Result<Reversal<'a>, Error> {
        self.touched = true;
        self.check_room()?;
        if self.registry.pending_reversals() >= self.capacity {
            return Err(Error::Capacity);
        }
        let numeric = gnunet_tcp_communicator_core::registry::Address::parse(address)?.socket();
        let std::net::SocketAddr::V4(remote) = numeric else {
            return Err(Error::InvalidInput);
        };
        if remote.port() != 0 {
            return Err(Error::InvalidInput);
        }
        let (id, pending) = self.registry.outbound(peer, address)?;
        if pending != Pending::Reversal {
            self.registry.failed(id)?;
            return Err(Error::Conflict);
        }
        Ok(Reversal {
            id,
            peer,
            remote: *remote.ip(),
            first_session: self.next_session,
        })
    }
    /// The only submission gate: this same original intent must still be Planned.
    /// A previously admitted Waiting request is never silently replayed.
    pub fn owns_reversal(&self, original: &Reversal<'a>) -> Result<(), Error> {
        self.registry.reversal_planned(original.id)?;
        if self.registry.target(original.id)? != Some(original.peer) {
            return Err(Error::Authentication);
        }
        let address = gnunet_tcp_communicator_core::registry::Address::parse(
            self.registry.address(original.id)?,
        )?;
        if address.socket().ip() != std::net::IpAddr::V4(original.remote)
            || address.socket().port() != 0
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    /// Record the real original Registration.reverse local-admission receipt.
    /// Its ten-second pending timer is independent of write/remote processing.
    pub fn reversal_admitted(
        &mut self,
        original: &mut Reversal<'a>,
        receipt: &crate::addresses::ReverseWrite<'_, 'a>,
    ) -> Result<(), Error> {
        self.owns_reversal(original)?;
        if receipt.parent() != original.id
            || receipt.peer() != original.peer
            || *receipt.remote().ip() != original.remote
        {
            return Err(Error::Authentication);
        }
        self.registry
            .reversal_admitted(original.id, receipt.admitted_at())?;
        // A Session that predates this actual NAT admission cannot stand in for
        // a new authentication event, even if the intent waited for NAT credit.
        original.first_session = self.next_session;
        Ok(())
    }
    /// Inspect the exact original pending generation, without granting submission.
    pub fn reversal_live(&self, original: &Reversal<'a>) -> bool {
        self.registry.reversal_current(original.id).is_ok()
    }
    /// Release only this planned/waiting metadata. Native cancellation, if any,
    /// is a separate original WriteId operation on PublishedPool.
    pub fn cancel_reversal(&mut self, original: &Reversal<'a>) -> Result<(), Error> {
        self.registry.cancel_reversal(original.id)
    }
    /// Match the actual Established same-IP Session after replay/challenge. Failed
    /// anonymous prototypes and reused parent slots cannot consume another row.
    pub fn reversal_authenticated(
        &mut self,
        original: &Reversal<'a>,
        id: &SessionId,
        now: u64,
    ) -> Result<(), Error> {
        let active = self
            .active
            .iter()
            .find(|active| &active.id == id)
            .ok_or(Error::Stale)?;
        if active.sequence <= original.first_session {
            return Err(Error::Stale);
        }
        self.registry
            .reversal_authenticated(original.id, self.manager.core(id)?, now)
    }
    /// Consume the pending IP/PID only after an actual current Session reached
    /// Established through its original replay/challenge checks. Other prototypes and other same-IP peers are skipped.
    pub fn complete_reversal(&mut self, original: &Reversal<'a>, now: u64) -> Result<bool, Error> {
        self.registry.reversal_current(original.id)?;
        for active in &self.active {
            let core = self.manager.core(&active.id)?;
            if active.sequence <= original.first_session
                || core.phase() != Phase::Established
                || core.authenticated_target() != Some(original.peer)
            {
                continue;
            }
            match self.registry.reversal_authenticated(original.id, core, now) {
                Ok(()) => return Ok(true),
                Err(Error::Authentication | Error::Stale | Error::NotReady) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(false)
    }
    fn admit_registered(
        &mut self,
        instance: Instance<'a>,
        connection: Connection,
        address: &[u8],
        ingress: (&[u8], Option<HandshakeBounds>),
        time: Time,
        entropy: &mut impl Entropy,
    ) -> Result<SessionId, AdmissionError> {
        let sequence = self.next_session.checked_add(1).ok_or(Error::Capacity)?;
        let (prefix, bounds) = ingress;
        let admission = self.registry.session(instance)?;
        let Some(buffers) = self.free.pop() else {
            drop(connection);
            self.registry.cancel(admission).map_err(|r| r.reason)?;
            return Err(Error::Capacity.into());
        };
        let mut core = match Session::managed(
            admission,
            self.identity,
            buffers,
            self.policy,
            time,
            entropy,
        ) {
            Ok(core) => Box::new(core),
            Err(rejected) => {
                drop(connection);
                let (admission, buffers) = rejected.value;
                self.registry.cancel(admission).map_err(|r| r.reason)?;
                self.free.push(buffers);
                return Err(rejected.reason.into());
            }
        };
        if let Some(bounds) = bounds
            && let Err(error) = core
                .limit_initial_deadline(bounds.until())
                .and_then(|()| bounds.check(time.now))
        {
            drop(connection);
            self.unadmitted(core, time, entropy)?;
            return Err(error.into());
        }
        let admitted = match bounds {
            Some(bounds) => self.manager.admit_prefixed(
                core,
                connection,
                NativeAdmission {
                    address,
                    network: network(address),
                    prefix,
                    bounds,
                    now: time.now,
                },
            ),
            None => self
                .manager
                .admit(core, connection, address, network(address)),
        };
        match admitted {
            Ok(id) => {
                self.next_session = sequence;
                self.active.push(Active {
                    id: id.clone(),
                    sequence,
                });
                Ok(id)
            }
            Err(rejected) => {
                let (core, connection) = rejected.value;
                drop(connection);
                self.unadmitted(core, time, entropy)?;
                Err(rejected.reason.into())
            }
        }
    }
    /// Adopt this actual accepted native connection using the original Session.
    pub fn accepted(
        &mut self,
        connection: Connection,
        address: &[u8],
        time: Time,
        entropy: &mut impl Entropy,
    ) -> Result<SessionId, AdmissionError> {
        self.touched = true;
        self.check_room()?;
        let instance = self.registry.accepted(address)?;
        self.admit_registered(instance, connection, address, (&[], None), time, entropy)
    }
    /// Continue an original accepted/connectback prototype, including its actual
    /// consumed prefix and the original native/logical targets. No bytes reread.
    pub fn accepted_prefixed(
        &mut self,
        connection: Connection,
        address: &[u8],
        prefix: &[u8],
        bounds: HandshakeBounds,
        time: Time,
        entropy: &mut impl Entropy,
    ) -> Result<SessionId, AdmissionError> {
        bounds.check(time.now)?;
        self.touched = true;
        self.check_room()?;
        let instance = self.registry.accepted(address)?;
        self.admit_registered(
            instance,
            connection,
            address,
            (prefix, Some(bounds)),
            time,
            entropy,
        )
    }
    /// Adopt a real clear probe socket as a separate outbound-role prototype.
    /// The claimed PID only selected this parent; its KX must verify that signer.
    pub fn reversal_probe(
        &mut self,
        original: &Reversal<'a>,
        connection: Connection,
        address: &[u8],
        bounds: HandshakeBounds,
        time: Time,
        entropy: &mut impl Entropy,
    ) -> Result<SessionId, AdmissionError> {
        bounds.check(time.now)?;
        self.touched = true;
        self.check_room()?;
        let child = self
            .registry
            .reversal_probe(original.id, address, time.now)?;
        self.admit_registered(
            child,
            connection,
            address,
            (&[], Some(bounds)),
            time,
            entropy,
        )
    }
    /// Check/register original prototype native deadlines before any outer clock
    /// sample. Deadline failure physically detaches only that original socket.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<OwnedFailure> {
        self.manager.poll_native_guard(cx)
    }
    /// Start an actual nonblocking numeric TCP connect before committing the pure
    /// registry's connected-admission fact. Port-zero requests use the separate
    /// plan_reversal / PublishedPool admission path, never a direct connect.
    pub fn outbound(
        &mut self,
        peer: EddsaPublicKey,
        address: &[u8],
        time: Time,
        entropy: &mut impl Entropy,
    ) -> Result<SessionId, AdmissionError> {
        self.touched = true;
        self.check_room()?;
        let sequence = self.next_session.checked_add(1).ok_or(Error::Capacity)?;
        let (instance, pending) = self.registry.outbound(peer, address)?;
        if pending != Pending::Connect {
            self.registry.failed(instance)?;
            return Err(Error::Unavailable.into());
        }
        let numeric = gnunet_tcp_communicator_core::registry::Address::parse(address)?.socket();
        let connecting = match NativeConnect::begin(numeric) {
            Ok(c) => c.into_future(),
            Err(error) => {
                self.registry.failed(instance)?;
                return Err(error.into());
            }
        };
        self.registry.connected(instance)?;
        let admission = self.registry.session(instance)?;
        let buffers = self.free.pop().ok_or(Error::Capacity)?;
        let core = match Session::managed(
            admission,
            self.identity,
            buffers,
            self.policy,
            time,
            entropy,
        ) {
            Ok(core) => Box::new(core),
            Err(rejected) => {
                drop(connecting);
                let (admission, buffers) = rejected.value;
                self.registry.cancel(admission).map_err(|r| r.reason)?;
                self.free.push(buffers);
                return Err(rejected.reason.into());
            }
        };
        match self
            .manager
            .admit_connecting(core, connecting, address, network(address))
        {
            Ok(id) => {
                self.next_session = sequence;
                self.active.push(Active {
                    id: id.clone(),
                    sequence,
                });
                Ok(id)
            }
            Err(rejected) => {
                let (core, connecting) = rejected.value;
                drop(connecting);
                self.unadmitted(core, time, entropy)?;
                Err(rejected.reason.into())
            }
        }
    }
    /// Retire this original identity epoch without creating FINISH/signatures.
    /// Original native/service callbacks still drain before any clean proof.
    pub fn retire_epoch(&mut self, time: Time) -> Result<(), HostError> {
        self.retiring = true;
        self.registry.cancel_reversals();
        for original in &self.active {
            self.manager.lost(&original.id)?;
        }
        self.manager.begin_shutdown(time)
    }
    /// Begin authenticated graceful close using the original manager and clock.
    pub fn begin_shutdown(&mut self, time: Time) -> Result<(), HostError> {
        self.retiring = true;
        self.registry.cancel_reversals();
        self.manager.begin_shutdown(time)
    }
    /// Whether original callback/native/service owners have actually drained.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.manager.is_quiescent()
    }
    /// Public backend ambiguity is not cleared by a replacement IPC connection.
    #[must_use]
    pub fn history_recovery_required(&self) -> bool {
        self.manager.peerstore_recovery_required()
    }
    /// Drive existing original connections and recycle only completely closed
    /// generations. Fresh single-poll futures preserve the same fairness state.
    fn recycle(&mut self) -> Result<Option<SessionId>, OwnedFailure> {
        for index in 0..self.active.len() {
            let id = &self.active[index].id;
            if self
                .manager
                .core(id)
                .is_ok_and(|c| c.phase() == Phase::Closed)
            {
                let core = match self.manager.retire(id) {
                    Ok(c) => c,
                    Err(Error::WouldBlock) => continue,
                    Err(e) => {
                        return Err(OwnedFailure {
                            session: Some(id.clone()),
                            cause: e.into(),
                        });
                    }
                };
                if let Err(error) = self.registry.retire(&core) {
                    return Err(OwnedFailure {
                        session: Some(id.clone()),
                        cause: error.into(),
                    });
                }
                let buffers = match (*core).into_buffers() {
                    Ok(b) => b,
                    Err(r) => {
                        return Err(OwnedFailure {
                            session: Some(id.clone()),
                            cause: r.reason.into(),
                        });
                    }
                };
                self.free.push(buffers);
                let old = self.active.remove(index).id;
                self.yield_due = true;
                return Ok(Some(old));
            }
        }
        Ok(None)
    }
    fn budget(&mut self, cx: &mut Context<'_>) -> bool {
        self.touched = true;
        if self.yield_due {
            self.yield_due = false;
            cx.waker().wake_by_ref();
            true
        } else {
            false
        }
    }
    fn progress(
        &mut self,
        result: Poll<Result<Progress, OwnedFailure>>,
    ) -> Poll<Result<PoolProgress, OwnedFailure>> {
        match result {
            Poll::Ready(Ok(progress)) => {
                if let Some(id) = &progress.session
                    && let Ok(core) = self.manager.core(id)
                    && core.authenticated_target().is_some()
                    && let Err(error) = self.registry.authenticated(core)
                {
                    return Poll::Ready(Err(OwnedFailure {
                        session: Some(id.clone()),
                        cause: error.into(),
                    }));
                }
                self.yield_due = true;
                Poll::Ready(Ok(PoolProgress::Manager(progress)))
            }
            Poll::Ready(Err(original)) => {
                self.yield_due = true;
                Poll::Ready(Err(original))
            }
            Poll::Pending => Poll::Pending,
        }
    }
    /// Drive existing original connections with the canonical time provider.
    pub fn poll_drive(
        &mut self,
        cx: &mut Context<'_>,
        clock: &mut (impl Clock + gnunet_tcp_communicator_host::history::ReplayHistory),
        entropy: &mut impl Entropy,
    ) -> Poll<Result<PoolProgress, OwnedFailure>> {
        if self.budget(cx) {
            return Poll::Pending;
        }
        if let Some(old) = self.recycle()? {
            return Poll::Ready(Ok(PoolProgress::Retired(old)));
        }
        let result = self.manager.poll_drive_owned(cx, clock, entropy);
        self.progress(result)
    }
    /// Drain only an already-force-retired epoch using its last actual sample.
    /// This does not sample/reforge time or permit fresh signatures/admissions.
    pub fn poll_retire(
        &mut self,
        cx: &mut Context<'_>,
        last: Time,
        history: &mut impl gnunet_tcp_communicator_host::history::ReplayHistory,
        entropy: &mut impl Entropy,
    ) -> Poll<Result<PoolProgress, OwnedFailure>> {
        if !self.retiring {
            return Poll::Ready(Err(OwnedFailure {
                session: None,
                cause: Error::Conflict.into(),
            }));
        }
        if self.budget(cx) {
            return Poll::Pending;
        }
        if let Some(old) = self.recycle()? {
            return Poll::Ready(Ok(PoolProgress::Retired(old)));
        }
        let result = self.manager.poll_step_owned(cx, last, history, entropy);
        self.progress(result)
    }
}

// Loopback is known from the original numeric peer. Other network scopes await
// a real classifier; do not label all actual Internet/LAN sockets as loopback.
fn network(address: &[u8]) -> u32 {
    gnunet_tcp_communicator_core::registry::Address::parse(address)
        .map_or(0, |a| u32::from(a.socket().ip().is_loopback()))
}
