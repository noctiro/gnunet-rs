//! Independent native TRANSPORT composition. Authority comes from the original
//! PILS MQ; discovery, local whole writes and PEERSTORE results grant no keys or
//! durable-publication authority. No communicator/helper process is hidden here.
use crate::{
    Failure, discovery,
    generation::{self, Reservations},
    hello::HelloSink,
    pils,
    publication::{self, HelloTask, Publications, SignTask, StoreTask},
    settings::Settings,
    time::{Bounds, Clock},
    validated::ValidatedStore,
    writer::Writer,
};
use gnunet_client_host::EndpointSource;
use gnunet_crypto::{EddsaPublicKey, Entropy};
use gnunet_nat_client_host as nat;
use gnunet_peerstore_client_host as ps;
use gnunet_pils::client::{self as pc, Identity, OperationId};
use gnunet_transport::{
    Engine, PeerId, Signer, Times,
    signing::{ValidationId, ValidationMode, ValidationRequest},
};
use gnunet_transport_host::{Server, Step as NativeStep};
use gnunet_types::Error as Fault;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
/// Caller-owned independent native allocation brands. No brand is leaked or
/// reconstructed from a wire request number.
pub struct Instances<'id> {
    /// Actual PILS operation and MQ identity allocation domain.
    pub pils: &'id mut pc::Instance,
    /// Independent validated-address STORE client allocation domain.
    pub validated: &'id mut ps::Instance,
    /// Independent own-address public STORE allocation domain.
    pub publications: &'id mut ps::Instance,
    /// Independent actual HELLO-add client allocation domain.
    pub hello: &'id mut ps::Instance,
    /// Independent general address iterator allocation domain.
    pub queries: &'id mut ps::Instance,
    /// Caller-bounded per-peer HELLO monitor allocation domains.
    pub monitors: &'id mut [ps::Instance],
    /// Actual zero-binding NAT registration allocation domain.
    pub nat: &'id nat::Instance,
}
/// One coherent caller-snapshotted configuration, sharing the actual process
/// Resolver and the exact RuntimeClock Arc.
pub struct Sources {
    /// Actual external PILS source sharing the canonical process clock.
    pub pils: EndpointSource,
    /// Actual external PEERSTORE source for separate original client owners.
    pub peerstore: EndpointSource,
    /// Actual external NAT source for zero-binding registration.
    pub nat: EndpointSource,
}
/// Actual observable bounded steps. None is a remote-delivery/fsync assertion.
pub enum Event<'id> {
    /// Verified original PILS identity; local admission becomes available.
    Ready(Identity<'id>),
    /// Actual PID change began physical old-Engine retirement on the same
    /// PILS source. Neither observation authorizes old callbacks as new work.
    EpochRetiring {
        /// Original old Engine identity observation.
        previous: Identity<'id>,
        /// Latest real ordered announcement that triggered this retirement.
        observed: Identity<'id>,
    },
    /// New Engine brand created after all old original debts settled.
    EpochStarted {
        /// Current real PILS observation used by the new Engine brand.
        identity: Identity<'id>,
        /// Checked local allocation sequence only; never a wire token.
        generation: u64,
    },
    /// Exact retired foreign-address effect and actual result/no-admission.
    ValidatedRetired(crate::validated::RetiredValidation<'id>),
    /// Actual old public stamp completion; it is never a new publication token.
    ReservationRetired(crate::epoch::ReservationOutcome<'id>),
    /// Original actual FLOW range outcome, retaining the genuine receipt.
    FlowRange(crate::sender::Outcome<'id>),
    /// Actual matching live DV reservation. Caller must still match its original
    /// independent Actor source/epoch and fixed scheduler request before use.
    DvRange {
        /// Original Engine-specific DV scope and admitted worker request.
        original: crate::sender::DvReservation<'id>,
        /// Exact matching durable interval for that original scope.
        actual: generation::CommittedRange,
    },
    /// Actual protocol/socket/timer step, including isolated input refusal.
    Transport(NativeStep),
    /// First unread original native retirement and bounded coalesced count.
    NativeRetired(gnunet_transport_host::NativeRetirement),
    /// Original external candidate-source facts, retaining their actual tokens.
    Discovery(discovery::Event<'id>),
    /// Original NAT REGISTER source facts. Written is only a local whole write.
    Nat(nat::Progress<'id>),
    /// Original purpose35 job failed without a synthetic signature.
    ValidationFailed {
        /// Original purpose35 Engine request, never a replacement request.
        original: ValidationId,
        /// Actual original provider refusal, expiry or source-loss outcome.
        reason: pils::Reason,
    },
    /// Actual failed own-address/FEED job; no missing signature is fabricated.
    PublicationFailed {
        /// Original own-publication or address-signing task.
        original: SignTask,
        /// Actual original provider refusal, expiry or source-loss outcome.
        reason: pils::Reason,
    },
    /// Original PILS job/source retirement, returned after physical close.
    PilsRetired(pils::Event<'id, SignTask>),
    /// Original publication STORE retirement, retaining actual exposure/code.
    PublicationRetired(crate::writer::Event<StoreTask>),
    /// Original HELLO helper completion/cancellation from explicit stop.
    HelloRetired(crate::hello::Finished<'id, HelloTask<'id>>),
    /// Exact local burst terminal fact; no remote reachability is inferred.
    Burst(gnunet_transport::burst::Outcome),
    /// Bounded native progress only.
    Activity,
}
/// Exact observed counter projection; absent C-internal events are not guessed.
#[derive(Clone, Copy, Default)]
pub struct Statistics {
    /// Actual failed foreign-address STORE operations, not local queue refusals.
    pub foreign_address_failures: u64,
}
/// Actual current local public source for deferred purpose35 work. This owns
/// no signing key; the same Owner's real PILS effect path supplies signatures.
pub struct TransportSigner(EddsaPublicKey);
impl Signer for TransportSigner {
    fn identity(&self) -> PeerId {
        PeerId(*self.0.as_bytes())
    }
    fn sign_validation(&mut self, _: &[u8; 48]) -> Result<[u8; 64], Fault> {
        Err(Fault::NotReady)
    }
    fn validation_mode(&self) -> ValidationMode {
        ValidationMode::Deferred
    }
}
/// Actual scheduled native work, preserving the Owner's one maintenance state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportWork {
    /// One fair native receive/write step.
    Step,
    /// Original due maintenance tick.
    Tick,
    /// Original deferred-work retry turn.
    Retry,
}
/// Explicit disjoint actual IO ports lent for one call. A DV observer can drive
/// the same real Server without reborrowing Owner/Scheduler or replaying a step.
pub struct TransportContext<'a, 'id, E: Entropy> {
    /// Original native Server and its actual held RX/TX/FC state.
    pub server: &'a mut Server,
    /// Actual fresh separate mono/absolute observations for this original turn.
    pub times: Times,
    /// Original Step/Tick/Retry choice, fixed by the same Owner state machine.
    pub work: TransportWork,
    /// Actual original public source; deferred signing stays with Owner/PILS.
    pub signer: &'a mut TransportSigner,
    /// Original process entropy port, without hidden opening or generation.
    pub entropy: &'a mut E,
    /// Real original validated-address provider/persistence barrier.
    pub store: &'a mut ValidatedStore<'id>,
}
impl<E: Entropy> TransportContext<'_, '_, E> {
    /// Standard non-DV path. Native and persistence semantics are identical to
    /// the observer path; this performs real work and never synthesizes Ready.
    pub fn poll_standard(self, cx: &mut Context<'_>) -> Poll<Result<NativeStep, Failure>> {
        let actual = match self.work {
            TransportWork::Step => self.server.poll_step_at(
                cx,
                None,
                self.times,
                self.signer,
                self.entropy,
                self.store,
            ),
            TransportWork::Tick => {
                self.server
                    .poll_tick_at(cx, self.times, self.entropy, self.store)
            }
            TransportWork::Retry => {
                self.server
                    .poll_retry_deferred_at(cx, self.times, self.entropy, self.store)
            }
        };
        actual.map(|result| result.map_err(|error| Box::new(error) as Failure))
    }
}
struct Validation<'id> {
    request: ValidationRequest,
    bounds: Bounds,
    operation: Option<OperationId<'id>>,
    signature: Option<[u8; 64]>,
    retiring: bool,
}
/// Caller-driven real owners. The storage worker is passed by its real owner;
/// canceling a poll never discards its original actual completion.
pub struct Owner<'id, E: Entropy> {
    pils: pils::Pils<'id, SignTask>,
    validated: ValidatedStore<'id>,
    writer: Writer<'id, StoreTask>,
    hello: HelloSink<'id, HelloTask<'id>>,
    discovery: discovery::Provider<'id>,
    nat: nat::Registration<'id>,
    server: Option<Server>,
    burst: crate::burst::Port,
    burst_policy: gnunet_transport::burst::Policy,
    retired_burst: Option<gnunet_transport::burst::Outcome>,
    publications: Option<Publications<'id>>,
    sender: crate::sender::Sender<'id>,
    dv_range: Option<crate::sender::DvReservation<'id>>,
    dv_scope: Option<crate::sender::DvScope<'id>>,
    sender_horizon: Duration,
    identity: Option<Identity<'id>>,
    validations: Vec<Validation<'id>>,
    clock: Clock,
    entropy: E,
    core_limits: gnunet_transport::Limits,
    native_limits: gnunet_transport_host::NativeLimits,
    clients: usize,
    pending_bytes: usize,
    tolerant: bool,
    publication_limits: publication::Limits,
    operation: Duration,
    tick: Duration,
    deferred: bool,
    retry_turn: bool,
    maintenance_retry: Option<bool>,
    next_tick: Instant,
    alarm: Option<Pin<Box<Sleep>>>,
    stopped: bool,
    rotating: bool,
    next_identity: Option<Identity<'id>>,
    reservation_drain: Option<crate::epoch::Drain<'id>>,
    recovery: Option<crate::epoch::Recovery>,
    recovery_window: Duration,
    recovery_quiet: Duration,
    engine_generation: u64,
    restart_native: bool,
}
impl<'id, E: Entropy> Owner<'id, E> {
    /// Reserve real native/core state only. This does not create a key, load a
    /// keyfile, start communicators or grant a default peer identity.
    pub fn new(
        instances: Instances<'id>,
        sources: Sources,
        mut clock: Clock,
        settings: &Settings,
        entropy: E,
    ) -> Result<Self, Failure> {
        if settings.discovery.signature_profile != settings.profile.hello()
            || settings.publication.signature_profile != settings.profile.hello()
        {
            return Err(Fault::Conflict.into());
        }
        for source in [&sources.pils, &sources.peerstore, &sources.nat] {
            if !Arc::ptr_eq(&source.clock(), &clock.source()) {
                return Err(Fault::InvalidInput.into());
            }
        }
        let now = clock.sample()?.absolute().as_micros();
        let nat_profile = nat::native_profile()?;
        let session = Bounds::after(now, settings.native.lifetime)?;
        let send = Bounds::after(now, settings.operation)?;
        let nat = nat::Registration::new(
            instances.nat,
            sources.nat,
            nat::RegistrationRequest {
                flags: 0,
                protocol: 0,
                section: b"transport",
                addresses: nat::ipc::Addresses::decode(&[], 0, nat_profile)?,
            },
            nat::Profiles::same(nat_profile),
            nat::Deadlines {
                send_until: send.expires,
                first_input_until: None,
                until: session.expires,
            },
            nat::Limits::default(),
        )?;
        let pils = pils::Pils::new(
            instances.pils,
            sources.pils,
            settings.profile,
            settings.publication.hello,
            settings.pils,
        )?;
        let validated = ValidatedStore::new(
            instances.validated,
            sources.peerstore.duplicate()?,
            clock.clone(),
            settings.validated,
        )?;
        let writer = Writer::new(
            instances.publications,
            sources.peerstore.duplicate()?,
            settings.peerstore,
            settings.native.lifetime,
            settings.validated.initial,
            settings.native.input,
        )?;
        let hello = HelloSink::new(
            instances.hello,
            sources.peerstore.duplicate()?,
            settings.peerstore,
            |_| {},
        )?;
        let discovery = discovery::Provider::new(
            instances.queries,
            instances.monitors,
            sources.peerstore,
            clock.clone(),
            settings.peerstore,
            settings.discovery,
        )?;
        let mut validations = Vec::new();
        validations
            .try_reserve_exact(settings.core.control_messages)
            .map_err(|_| Fault::Capacity)?;
        Ok(Self {
            pils,
            validated,
            writer,
            hello,
            discovery,
            nat,
            server: None,
            burst: crate::burst::Port::default(),
            burst_policy: settings.burst,
            retired_burst: None,
            publications: None,
            sender: crate::sender::Sender::new(settings.sender_monotime_horizon),
            dv_range: None,
            dv_scope: None,
            sender_horizon: settings.sender_monotime_horizon,
            identity: None,
            validations,
            clock,
            entropy,
            core_limits: settings.core,
            native_limits: settings.native,
            clients: settings.clients,
            pending_bytes: settings.pending_bytes,
            tolerant: settings.options.tolerant,
            publication_limits: settings.publication,
            operation: settings.operation,
            tick: settings.tick,
            deferred: false,
            retry_turn: false,
            maintenance_retry: None,
            next_tick: Instant::now(),
            alarm: None,
            stopped: false,
            rotating: false,
            next_identity: None,
            reservation_drain: None,
            recovery: None,
            recovery_window: settings.recovery.min(settings.operation),
            recovery_quiet: settings
                .tick
                .checked_mul(4)
                .ok_or(Fault::Overflow)?
                .min(Duration::from_millis(500)),
            engine_generation: 0,
            restart_native: false,
        })
    }
    /// Admission is possible only after a real original-source public identity.
    pub fn ready(&self) -> bool {
        !self.stopped
            && !self.rotating
            && self
                .server
                .as_ref()
                .is_some_and(|s| !s.persistence_pending())
    }
    /// Current active original PILS observation for DV range admission/use.
    /// A different Actor PILS source must be independently checked by its owner;
    /// equal peer bytes never equate their native epochs or operation ledgers.
    pub fn dv_identity(&self) -> Option<Identity<'id>> {
        if self.stopped || self.rotating || self.server.is_none() || !self.pils.reusable() {
            None
        } else {
            self.identity
                .filter(|identity| self.pils.identity() == Some(*identity))
        }
    }
    /// Actual same-scope public source for original deferred purpose35 effects.
    /// No private key or synthetic signature is returned by this projection.
    pub fn dv_signer(&self, scope: &crate::sender::DvScope<'id>) -> Result<TransportSigner, Fault> {
        if self.dv_scope().as_ref() != Some(scope) {
            return Err(Fault::Stale);
        }
        Ok(TransportSigner(
            self.dv_identity().ok_or(Fault::NotReady)?.peer(),
        ))
    }
    /// Negative lifecycle fact for independent clock-free worker cleanup.
    pub fn is_stopped(&self) -> bool {
        self.stopped
    }
    /// Original actual Engine allocation, including PID A→B→A separation on a
    /// healthy unchanged PILS MQ. A scheduler must match this exact scope on
    /// admission, receipt and every use of an installed interval.
    pub fn dv_scope(&self) -> Option<crate::sender::DvScope<'id>> {
        self.dv_identity()?;
        self.dv_scope.clone()
    }
    /// Current native input boundary of this same active Engine allocation.
    /// The bootstrap retains its actual client and original bounds while a
    /// partial/held input is completed or physically retired by normal polling.
    pub fn dv_source_attach_ready(
        &self,
        scope: &crate::sender::DvScope<'id>,
    ) -> Result<bool, Fault> {
        if self.dv_scope().as_ref() != Some(scope) {
            return Err(Fault::Stale);
        }
        Ok(self
            .server
            .as_ref()
            .ok_or(Fault::NotReady)?
            .dv_source_attach_ready())
    }
    /// Exact original process clock shared by the native CLIENT sources.
    /// Cloning this port neither resamples time nor creates a new epoch.
    pub fn dv_clock(&self) -> Arc<dyn gnunet_service_runtime::clock::RuntimeClock> {
        self.clock.source()
    }
    /// Exact immutable native zero of this Engine's monotonic coordinate.
    /// Mapping an original job target never uses a fresh now+remaining TTL.
    pub fn dv_native_epoch(&self) -> Result<Instant, Fault> {
        self.clock.native_bound(gnunet_types::MonoInstant(0))
    }
    /// Actual current two-clock sample for this exact active Engine allocation.
    /// A retired scope cannot obtain a fresh operation sample through this port.
    pub fn dv_times(&mut self, scope: &crate::sender::DvScope<'id>) -> Result<Times, Fault> {
        if self.dv_scope().as_ref() != Some(scope) {
            return Err(Fault::Stale);
        }
        self.clock.sample()
    }
    /// Borrow only the exact original Server, including during retirement so
    /// the external actor can settle original native/FC debt and worker cleanup.
    /// This access creates no fresh scope, authentication or readiness fact.
    pub fn dv_server(&mut self, scope: &crate::sender::DvScope<'id>) -> Result<&mut Server, Fault> {
        if self.dv_scope.as_ref() != Some(scope) {
            return Err(Fault::Stale);
        }
        self.server.as_mut().ok_or(Fault::NotReady)
    }
    /// Admit an original DV range under this actual current service identity.
    /// The scheduler keeps its original independent Actor/source/budget binding.
    /// Busy returns without changing any target or admitting another worker job.
    pub fn request_dv_range(
        &mut self,
        reservations: &mut Reservations,
        scope: &crate::sender::DvScope<'id>,
        bounds: Bounds,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<generation::Request, Failure> {
        if self.dv_scope().as_ref() != Some(scope) {
            return Err(Fault::Stale.into());
        }
        if self.dv_range.is_some() {
            return Err(Fault::WouldBlock.into());
        }
        if Instant::now() >= bounds.hard {
            return Err(Fault::Deadline.into());
        }
        let times = match self.clock.sample() {
            Ok(times) => times,
            Err(error) => {
                let cleanup = self.stop(observe);
                return Err(Box::new(crate::Failures {
                    original: Some(Box::new(error)),
                    cleanup,
                }));
            }
        };
        if !bounds.live(times.absolute().as_micros())
            || self
                .dv_identity()
                .is_none_or(|identity| identity.expiration() <= times.absolute())
        {
            return Err(Fault::Deadline.into());
        }
        let request = reservations.request_range(
            generation::Purpose::Dv,
            times.absolute().as_micros(),
            self.sender_horizon,
            bounds.expires,
            bounds.hard,
        )?;
        self.dv_range = Some(crate::sender::DvReservation::admitted(
            scope.clone(),
            request.clone(),
        ));
        Ok(request)
    }
    fn take_original_reservation(
        &mut self,
        stamp: Option<crate::epoch::RetiredStamp<'id>>,
    ) -> Result<Option<crate::epoch::RetiredReservation<'id>>, Fault> {
        let flow = self.sender.retire();
        let dv = self.dv_range.take();
        let count =
            usize::from(stamp.is_some()) + usize::from(flow.is_some()) + usize::from(dv.is_some());
        if count > 1 {
            return Err(Fault::Stale);
        }
        Ok(stamp
            .map(crate::epoch::RetiredReservation::Stamp)
            .or_else(|| flow.map(crate::epoch::RetiredReservation::Range))
            .or_else(|| {
                dv.map(|old| {
                    crate::epoch::RetiredReservation::Range(crate::epoch::RetiredRange::dv(old))
                })
            }))
    }
    /// Current actual resource/protocol facts, never a completion assertion.
    pub fn snapshot(&self) -> Option<gnunet_transport::Snapshot> {
        self.server.as_ref().map(|s| s.engine().snapshot())
    }
    /// Exact original counters, without claiming unexposed C internal events.
    pub fn statistics(&self) -> Statistics {
        Statistics {
            foreign_address_failures: self.validated.store_failures(),
        }
    }
    /// Adopt a canonical connection only after external ACL/credential checks.
    pub fn admit(
        &mut self,
        c: gnunet_service_runtime::connection::Connection,
    ) -> Result<gnunet_transport::ClientId, Fault> {
        if self.stopped {
            return Err(Fault::Closed);
        }
        let server = self.server.as_mut().ok_or(Fault::NotReady)?;
        if self.rotating || server.persistence_pending() {
            return Err(Fault::WouldBlock);
        }
        server.admit(c)
    }
    /// Whether all actual client outputs have drained for soft process shutdown.
    pub fn draining_complete(&self) -> bool {
        self.server.as_ref().is_none_or(Server::draining_complete)
    }
    fn identity(&mut self, identity: Identity<'id>) -> Result<bool, Failure> {
        if self.rotating {
            self.next_identity = Some(identity);
            return Ok(false);
        }
        if let Some(old) = self.identity {
            if old.epoch() != identity.epoch() {
                return Err("TRANSPORT original PILS source changed without retirement".into());
            }
            if old.peer() != identity.peer() {
                let server = self.server.as_mut().ok_or(Fault::NotReady)?;
                let recovery = crate::epoch::Recovery::capture(
                    server,
                    self.publication_limits.hello.maximum_address_bytes,
                    self.recovery_window,
                    self.recovery_quiet,
                )?;
                // All actual old IPC owners close before old pure capabilities
                // can be discarded or a replacement Engine can be allocated.
                if let Err(error) = server.shutdown() {
                    self.restart_native = true;
                    return Err(Box::new(error));
                }
                self.burst.after_physical_retirement();
                if let Some(request) = server.burst_request().cloned()
                    && request.selected.is_none()
                {
                    server.cancel_burst(&request.id, gnunet_transport::burst::End::SourceLost)?;
                }
                if let Some(outcome) = server.take_burst_outcome() {
                    self.retired_burst = Some(outcome);
                }
                self.rotating = true;
                // Public dv_scope() is already unavailable while rotating.
                // Keep the private old allocation for exact cleanup access.
                self.next_identity = Some(identity);
                self.recovery = Some(recovery);
                let stamp = self
                    .publications
                    .as_mut()
                    .ok_or(Fault::NotReady)?
                    .begin_epoch_retirement(&mut self.pils)?;
                let original = self.take_original_reservation(stamp)?;
                self.reservation_drain =
                    Some(crate::epoch::Drain::after_physical_retirement(original));
                self.pils.cancel_all()?;
                self.discovery.retire_all();
                for row in &mut self.validations {
                    row.retiring = true;
                    row.signature = None;
                }
                self.alarm = None;
                self.maintenance_retry = None;
                return Ok(false);
            }
            self.publications
                .as_mut()
                .ok_or(Fault::NotReady)?
                .identity(identity)?;
            self.identity = Some(identity);
            return Ok(false);
        }
        let mut engine = Engine::new(PeerId(*identity.peer().as_bytes()), self.core_limits)?;
        engine.configure_burst(self.burst_policy)?;
        engine.configure_monotime(gnunet_transport::monotime::Policy::checked(
            gnunet_wire::official::RelativeTime::from_micros(
                u64::try_from(self.operation.as_micros()).map_err(|_| Fault::Overflow)?,
            ),
        )?)?;
        self.server = Some(Server::new_with_native(
            engine,
            self.clients,
            self.pending_bytes,
            self.native_limits,
        )?);
        self.server
            .as_mut()
            .ok_or(Fault::NotReady)?
            .set_tolerant(self.tolerant);
        self.publications = Some(Publications::new(identity, self.publication_limits)?);
        self.identity = Some(identity);
        self.next_tick = Instant::now();
        self.engine_generation = self
            .engine_generation
            .checked_add(1)
            .ok_or(Fault::Overflow)?;
        self.dv_scope = Some(crate::sender::DvScope::allocated(
            identity,
            self.engine_generation,
        ));
        Ok(true)
    }
    fn finish_rotation(
        &mut self,
        utc: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Failure> {
        if !self.rotating {
            return Ok(false);
        }
        let mut i = 0;
        while i < self.validations.len() {
            if self.validations[i].operation.is_none() {
                let old = self.validations.swap_remove(i);
                observe(Event::ValidationFailed {
                    original: old.request.id().clone(),
                    reason: pils::Reason::Cancelled,
                });
            } else {
                i += 1;
            }
        }
        if self.pils.pending_jobs() != 0
            || self.server.as_ref().is_some_and(Server::dv_source_active)
            || !self.validations.is_empty()
            || !self.validated.idle()
            || self
                .publications
                .as_ref()
                .is_none_or(|p| !p.epoch_quiescent())
            || self
                .reservation_drain
                .as_ref()
                .is_none_or(|d| !d.finished())
        {
            return Ok(false);
        }
        if !self.pils.reusable() || !self.validated.reusable() || !self.writer.reusable() {
            self.restart_native = true;
            return Err(Fault::Unavailable.into());
        }
        let identity = self.pils.identity().ok_or(Fault::NotReady)?;
        let observed = self.next_identity.ok_or(Fault::NotReady)?;
        if identity != observed {
            return Err(Fault::Stale.into());
        }
        if identity.expiration().as_micros() <= utc {
            return Err(Fault::Deadline.into());
        }
        // The old actor released its barrier. Revoke cleanup access BEFORE
        // any fallible construction can install a different Server allocation.
        self.dv_scope = None;
        self.server = None;
        self.publications = None;
        self.identity = None;
        self.reservation_drain = None;
        self.rotating = false;
        self.next_identity = None;
        self.deferred = false;
        self.retry_turn = false;
        self.maintenance_retry = None;
        self.identity(identity)?;
        if let Some(recovery) = &mut self.recovery {
            recovery.start()?;
        }
        observe(Event::EpochStarted {
            identity,
            generation: self.engine_generation,
        });
        Ok(true)
    }
    /// True only when a native dependency actually ended/refused its original
    /// source. A factory may allocate a fresh owner after full original drain;
    /// it must never replay old Engine input, tasks or typed callbacks.
    pub fn native_restart_requested(&self) -> bool {
        self.restart_native
    }
    /// After physical full retirement, transfer any actual pending stamp to the
    /// caller's mandatory drain before these branded instances may be dropped.
    pub fn take_reservation_drain(&mut self) -> Result<Option<crate::epoch::Drain<'id>>, Fault> {
        if !self.stopped {
            return Err(Fault::NotReady);
        }
        Ok(self.reservation_drain.take().filter(|d| !d.finished()))
    }
    fn pils_event(
        &mut self,
        event: pils::Event<'id, SignTask>,
        times: Times,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Failure> {
        let utc = times.absolute().as_micros();
        match event {
            pils::Event::Identity { identity, .. } => {
                let previous = self.identity;
                let was_rotating = self.rotating;
                let first = self.identity(identity)?;
                if let Some(outcome) = self.retired_burst.take() {
                    observe(Event::Burst(outcome));
                }
                if !was_rotating && self.rotating {
                    observe(Event::EpochRetiring {
                        previous: previous.ok_or(Fault::Stale)?,
                        observed: identity,
                    });
                }
                if !self.rotating
                    && let (Some(server), Some(publications), Some(bytes)) = (
                        &self.server,
                        &mut self.publications,
                        self.pils.announcement(),
                    )
                {
                    publications.announcement(server, bytes, utc)?;
                }
                if first {
                    observe(Event::Ready(identity));
                }
            }
            pils::Event::Signature {
                origin: SignTask::Validation(id),
                peer,
                signature,
            } => {
                let row = self
                    .validations
                    .iter_mut()
                    .find(|v| v.request.id() == &id)
                    .ok_or(Fault::Stale)?;
                row.operation = None;
                if peer.as_bytes() != &row.request.signer().0 {
                    return Err(Fault::Authentication.into());
                }
                if !row.retiring {
                    row.signature = Some(*signature.as_bytes());
                }
            }
            pils::Event::Signature {
                origin,
                peer,
                signature,
            } => {
                self.publications
                    .as_mut()
                    .ok_or(Fault::NotReady)?
                    .signature(
                        origin,
                        peer,
                        signature,
                        self.server.as_ref().ok_or(Fault::NotReady)?,
                    )?;
            }
            pils::Event::FeedWritten(origin) => {
                self.publications
                    .as_mut()
                    .ok_or(Fault::NotReady)?
                    .feed_written(origin, self.server.as_mut().ok_or(Fault::NotReady)?)?;
            }
            pils::Event::Failed {
                origin: SignTask::Validation(id),
                reason,
            } => {
                if let Some(i) = self.validations.iter().position(|v| v.request.id() == &id) {
                    self.validations.swap_remove(i);
                }
                if let Some(server) = &mut self.server
                    && server.validation_live(&id)
                {
                    server.cancel_validation(&id)?;
                }
                observe(Event::ValidationFailed {
                    original: id,
                    reason,
                });
            }
            pils::Event::Failed { origin, reason } => {
                let original = origin.clone();
                self.publications
                    .as_mut()
                    .ok_or(Fault::NotReady)?
                    .signature_failed(origin, utc)?;
                // Failure is an observed original result, never retried as a
                // successful signature/ACK. Publication's pure retry policy
                // may create a distinct future original offer.
                observe(Event::PublicationFailed { original, reason });
            }
            pils::Event::SourceLost { cause, .. } => {
                self.restart_native = true;
                return Err(cause);
            }
            pils::Event::Connected(_) | pils::Event::Activity => observe(Event::Activity),
        }
        Ok(())
    }
    fn validation_step(&mut self, times: Times) -> Result<bool, Failure> {
        let utc = times.absolute().as_micros();
        let Some(server) = &mut self.server else {
            return Ok(false);
        };
        let mut changed = false;
        for row in &mut self.validations {
            let live = server.validation_live(row.request.id());
            if (!live || !row.bounds.live(utc)) && !row.retiring {
                row.retiring = true;
                row.signature = None;
                if live {
                    server.cancel_validation(row.request.id())?;
                }
                if let Some(op) = row.operation {
                    self.pils.cancel(op)?;
                }
                changed = true;
            }
            if !row.retiring
                && let Some(signature) = row.signature
            {
                match server.complete_validation_at(
                    row.request.id(),
                    row.request.signer(),
                    signature,
                    times,
                ) {
                    Ok(()) => {
                        row.signature = None;
                        row.retiring = true;
                        changed = true;
                    }
                    Err(Fault::Capacity | Fault::WouldBlock) => {}
                    Err(Fault::Stale | Fault::NotFound) => {
                        row.signature = None;
                        row.retiring = true;
                        changed = true;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
        self.validations
            .retain(|r| !r.retiring || r.operation.is_some());
        if self.validations.len() < self.core_limits.control_messages
            && let Some(request) = server.validation_request()
            && !self
                .validations
                .iter()
                .any(|v| v.request.id() == request.id())
        {
            self.validations.push(Validation {
                request: request.clone(),
                bounds: Bounds::after(utc, self.operation)?,
                operation: None,
                signature: None,
                retiring: false,
            });
            changed = true;
        }
        for row in &mut self.validations {
            if row.retiring || row.operation.is_some() || row.signature.is_some() {
                continue;
            }
            match self.pils.sign(
                SignTask::Validation(row.request.id().clone()),
                EddsaPublicKey::from_bytes(row.request.signer().0),
                row.request.region(),
                row.bounds,
            ) {
                Ok(op) => {
                    row.operation = Some(op);
                    server.claim_validation(row.request.id())?;
                    changed = true;
                    break;
                }
                Err(r)
                    if matches!(
                        r.reason,
                        Fault::NotReady | Fault::Capacity | Fault::WouldBlock
                    ) => {}
                Err(r) => return Err(r.reason.into()),
            }
        }
        Ok(changed)
    }
    fn transport_error(store: &mut ValidatedStore<'id>, error: Failure) -> Failure {
        match store.take_error() {
            Some(original) => Box::new(crate::Failures {
                original: Some(original),
                cleanup: vec![error],
            }),
            None => error,
        }
    }
    /// Drive every child/native guard before logical sampling. Each call does a
    /// finite round across sources; an unchanged Pending round never self-wakes.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        generation: &mut Reservations,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<(), Failure>> {
        self.poll_with_transport(cx, generation, observe, &mut |cx, context| {
            context.poll_standard(cx)
        })
    }
    /// Drive the same guards/providers/maintenance with an actual native IO
    /// observer. The production DV session consumes this port; callbacks may
    /// use only these disjoint ports and never reenter this Owner/Scheduler.
    pub fn poll_with_transport(
        &mut self,
        cx: &mut Context<'_>,
        generation: &mut Reservations,
        observe: &mut impl FnMut(Event<'id>),
        transport: &mut impl FnMut(
            &mut Context<'_>,
            TransportContext<'_, 'id, E>,
        ) -> Poll<Result<NativeStep, Failure>>,
    ) -> Poll<Result<(), Failure>> {
        match self.poll_inner(cx, generation, observe, transport) {
            Poll::Ready(Err(original)) => {
                let cleanup = self.stop(observe);
                Poll::Ready(Err(Box::new(crate::Failures {
                    original: Some(original),
                    cleanup,
                })))
            }
            result => result,
        }
    }
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        generation: &mut Reservations,
        observe: &mut impl FnMut(Event<'id>),
        transport: &mut impl FnMut(
            &mut Context<'_>,
            TransportContext<'_, 'id, E>,
        ) -> Poll<Result<NativeStep, Failure>>,
    ) -> Poll<Result<(), Failure>> {
        if self.stopped {
            return Poll::Ready(Err(Fault::Closed.into()));
        }
        self.pils.native_guard(cx)?;
        self.writer.native_guard(cx);
        if !self.pils.reusable() || !self.writer.reusable() {
            // Native guards may have queued multiple original completions
            // before SourceLost. Fence old Engine immediately; stop() drains
            // all those actual original outcomes and independent causes.
            self.restart_native = true;
            return Poll::Ready(Err(Fault::Unavailable.into()));
        }
        if let Err(e) = self.validated.native_guard(cx)
            && (!self.rotating || self.validated.idle())
        {
            self.restart_native = !self.validated.reusable();
            return Poll::Ready(Err(self
                .validated
                .take_error()
                .unwrap_or_else(|| Box::new(e))));
        }
        let mut changed = self.sender.native_guard(cx);
        if let Some(outcome) = self.retired_burst.take() {
            observe(Event::Burst(outcome));
            changed = true;
        }
        if let Some(server) = &mut self.server {
            changed |= self.burst.native_guard(server, &self.clock, cx)?;
        }
        if let Some(server) = &mut self.server {
            let result = server.poll_native_guard(cx);
            if let Some(original) = server.take_native_retirement() {
                observe(Event::NativeRetired(original));
            }
            changed |= result?.is_some();
            while let Some(original) = server.take_monitor_retirement() {
                observe(Event::Transport(NativeStep::MonitorRetired(original)));
                changed = true;
            }
        }
        // These children all own and register their original hard deadlines
        // before their own CLIENT logical waits. No hidden task drives them.
        match self
            .discovery
            .poll(cx, None, &mut |e| observe(Event::Discovery(e)))
        {
            Poll::Ready(Ok(_)) => changed = true,
            Poll::Ready(Err(e)) => {
                self.restart_native = true;
                return Poll::Ready(Err(Box::new(e)));
            }
            Poll::Pending => {}
        }
        match self.nat.poll(cx, None) {
            Poll::Ready(Ok(nat::Progress::Ended(end))) => {
                self.restart_native = matches!(
                    &end.source.cause,
                    nat::Cause::Deadline
                        | nat::Cause::WriteDeadline
                        | nat::Cause::FirstInputDeadline
                        | nat::Cause::Eof
                        | nat::Cause::Io(_)
                );
                observe(Event::Nat(nat::Progress::Ended(end)));
                return Poll::Ready(Err(
                    "TRANSPORT original zero-binding NAT source ended".into()
                ));
            }
            Poll::Ready(Ok(p)) => {
                if matches!(p, nat::Progress::Notification { .. }) {
                    // This source registered flags0/no callbacks. Keep the
                    // actual held frame in its original End rather than
                    // releasing it or inventing a callback under another owner.
                    observe(Event::Nat(p));
                    return Poll::Ready(Err(Fault::Malformed.into()));
                }
                observe(Event::Nat(p));
                changed = true;
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(Box::new(e))),
            Poll::Pending => {}
        }
        if self.rotating {
            match self.validated.poll_retired(cx) {
                Poll::Ready(Ok(Some(done))) => {
                    let failure = done
                        .failure
                        .as_ref()
                        .map(crate::epoch::SharedFailure::boxed);
                    observe(Event::ValidatedRetired(done));
                    changed = true;
                    if let Some(error) = failure {
                        self.restart_native = !self.validated.reusable();
                        return Poll::Ready(Err(error));
                    }
                }
                Poll::Ready(Ok(None)) | Poll::Pending => {}
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(self
                        .validated
                        .take_error()
                        .unwrap_or_else(|| Box::new(e))));
                }
            }
        } else {
            match self.validated.poll(cx) {
                Poll::Ready(Ok(())) => changed = true,
                Poll::Ready(Err(e)) => {
                    self.restart_native = !self.validated.reusable();
                    return Poll::Ready(Err(self
                        .validated
                        .take_error()
                        .unwrap_or_else(|| Box::new(e))));
                }
                Poll::Pending => {}
            }
        }
        match self.hello.poll(cx) {
            Poll::Ready(Ok(done)) => {
                if self.rotating {
                    self.publications
                        .as_mut()
                        .ok_or(Fault::NotReady)?
                        .retire_hello(&done.origin)?;
                    let error = match &done.result {
                        Ok(actual)
                            if matches!(
                                actual.outcome,
                                ps::hello::AddOutcome::StoreResult(_)
                                    | ps::hello::AddOutcome::ExistingNewer { .. }
                            ) =>
                        {
                            None
                        }
                        Ok(actual) => Some(format!(
                            "TRANSPORT old HELLO helper cannot prove source reuse after {:?}",
                            actual.outcome
                        )),
                        Err(error) => Some(format!(
                            "TRANSPORT old HELLO helper source cannot be reused: {error}"
                        )),
                    };
                    observe(Event::HelloRetired(done));
                    if let Some(error) = error {
                        self.restart_native = true;
                        return Poll::Ready(Err(error.into()));
                    }
                } else {
                    self.restart_native |= done.result.is_err();
                    self.publications
                        .as_mut()
                        .ok_or(Fault::NotReady)?
                        .hello_finished(done)?;
                }
                changed = true
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => {}
        }
        let times = self.clock.sample()?;
        let utc = times.absolute().as_micros();
        match self.pils.poll(cx) {
            Poll::Ready(Ok(e)) => {
                self.pils_event(e, times, observe)?;
                changed = true
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => {}
        }
        if !self.pils.reusable() || !self.writer.reusable() {
            self.restart_native = true;
            return Poll::Ready(Err(Fault::Unavailable.into()));
        }
        match self.writer.poll(cx) {
            Poll::Ready(Ok(crate::writer::Event::SourceLost(error))) => {
                self.restart_native = true;
                return Poll::Ready(Err(error));
            }
            Poll::Ready(Ok(event)) => {
                self.restart_native |= !self.writer.reusable();
                if let Some(publications) = &mut self.publications {
                    if self.rotating {
                        publications.retire_store(&event)?;
                        observe(Event::PublicationRetired(event));
                    } else {
                        publications.stored(event)?;
                    }
                }
                changed = true;
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => {}
        }
        if !self.pils.reusable() || !self.writer.reusable() {
            self.restart_native = true;
            return Poll::Ready(Err(Fault::Unavailable.into()));
        }
        if self.rotating {
            if let Some(drain) = &mut self.reservation_drain
                && !drain.finished()
            {
                match drain.poll(cx, generation) {
                    Poll::Pending => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(Box::new(e))),
                    Poll::Ready(Ok(outcome)) => {
                        let failure = match &outcome {
                            crate::epoch::ReservationOutcome::Failed { error, .. } => {
                                Some(error.boxed())
                            }
                            crate::epoch::ReservationOutcome::Mismatched { .. } => {
                                Some(Box::new(Fault::Stale) as Failure)
                            }
                            _ => None,
                        };
                        observe(Event::ReservationRetired(outcome));
                        changed = true;
                        if let Some(error) = failure {
                            return Poll::Ready(Err(error));
                        }
                    }
                }
            }
            changed |= self.finish_rotation(utc, observe)?;
            if self.rotating {
                return if changed {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                };
            }
        } else {
            match generation.poll(cx) {
                Poll::Ready(Ok(Some(receipt))) => {
                    match receipt {
                        generation::Completion::Stamp(receipt) => {
                            self.publications
                                .as_mut()
                                .ok_or(Fault::NotReady)?
                                .reservation(
                                    receipt,
                                    self.server.as_ref().ok_or(Fault::NotReady)?,
                                    utc,
                                )?;
                        }
                        generation::Completion::Range(actual) => match actual.purpose() {
                            generation::Purpose::Flow => {
                                let outcome = self.sender.complete(
                                    actual,
                                    self.server.as_mut().ok_or(Fault::NotReady)?,
                                    self.identity.ok_or(Fault::NotReady)?,
                                    times,
                                )?;
                                observe(Event::FlowRange(outcome));
                            }
                            generation::Purpose::Dv => {
                                let original = self.dv_range.take().ok_or(Fault::Stale)?;
                                if original.request() != actual.request() {
                                    return Poll::Ready(Err(Fault::Stale.into()));
                                }
                                let live = self.dv_scope().as_ref() == Some(original.scope())
                                    && self.dv_identity().is_some_and(|identity| {
                                        identity.expiration() > times.absolute()
                                    })
                                    && utc < actual.request().expires()
                                    && Instant::now() < actual.request().hard()
                                    && utc <= actual.span().last();
                                if live {
                                    observe(Event::DvRange { original, actual });
                                } else {
                                    observe(Event::ReservationRetired(
                                        crate::epoch::ReservationOutcome::RangeBurned {
                                            original: crate::epoch::RetiredRange::dv(original),
                                            actual,
                                        },
                                    ));
                                }
                            }
                        },
                    }
                    changed = true;
                }
                Poll::Ready(Ok(None)) | Poll::Pending => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(Box::new(e))),
            }
        }
        // Official PILS run() creates its initial identity and connect sends
        // the current signed HELLO immediately. Wait under Pils' original
        // initialization/native bounds; never reset its current address set
        // with an invented startup FEED. Real ADD/DEL publications remain below.
        if let (Some(server), Some(identity)) = (&mut self.server, self.identity) {
            let mut signer = TransportSigner(identity.peer());
            let result = transport(
                cx,
                TransportContext {
                    server,
                    times,
                    work: TransportWork::Step,
                    signer: &mut signer,
                    entropy: &mut self.entropy,
                    store: &mut self.validated,
                },
            );
            if let Some(original) = server.take_native_retirement() {
                observe(Event::NativeRetired(original));
            }
            match result {
                Poll::Ready(Ok(s)) => {
                    self.deferred |= matches!(s, NativeStep::WorkDeferred(_));
                    observe(Event::Transport(s));
                    changed = true
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(Self::transport_error(&mut self.validated, e)));
                }
                Poll::Pending => {}
            }
            if !server.persistence_pending() {
                let discovery = server.discover_at(
                    times,
                    &mut self.discovery,
                    std::num::NonZeroUsize::new(16).ok_or(Fault::InvalidInput)?,
                );
                let discovery = match discovery {
                    Ok(step) => Some(step),
                    Err(Fault::WouldBlock | Fault::Capacity | Fault::NotReady) => None,
                    Err(e) => return Poll::Ready(Err(Box::new(e))),
                };
                if discovery.is_some_and(|step| {
                    !matches!(step, gnunet_transport_host::discovery::DiscoveryStep::Idle)
                }) {
                    changed = true;
                }
            }
            let timer_due = Instant::now() >= self.next_tick;
            if timer_due && (!server.persistence_pending() || self.maintenance_retry.is_some()) {
                let retry = *self
                    .maintenance_retry
                    .get_or_insert(self.deferred && self.retry_turn);
                let result = transport(
                    cx,
                    TransportContext {
                        server,
                        times,
                        work: if retry {
                            TransportWork::Retry
                        } else {
                            TransportWork::Tick
                        },
                        signer: &mut signer,
                        entropy: &mut self.entropy,
                        store: &mut self.validated,
                    },
                );
                if let Some(original) = server.take_native_retirement() {
                    observe(Event::NativeRetired(original));
                }
                match result {
                    Poll::Ready(Ok(s)) => {
                        if retry {
                            self.deferred = matches!(s, NativeStep::WorkDeferred(_));
                        } else {
                            self.deferred |= matches!(s, NativeStep::WorkDeferred(_));
                        }
                        observe(Event::Transport(s));
                        self.retry_turn = !retry;
                        self.maintenance_retry = None;
                        self.next_tick = Instant::now()
                            .checked_add(self.tick)
                            .ok_or(Fault::Overflow)?;
                        self.alarm = None;
                        changed = true;
                    }
                    Poll::Ready(Err(e)) => {
                        return Poll::Ready(Err(Self::transport_error(&mut self.validated, e)));
                    }
                    Poll::Pending => {
                        self.alarm = None;
                    }
                }
            }
            let (progress, outcome) =
                self.sender
                    .advance(server, identity, &mut self.clock, generation, times)?;
            changed |= progress;
            changed |= self.sender.native_guard(cx);
            if let Some(outcome) = outcome {
                observe(Event::FlowRange(outcome));
            }
            let publication_ready = match &mut self.recovery {
                Some(recovery) => recovery.ready(server)?,
                None => true,
            };
            if publication_ready && self.recovery.is_some() {
                // Only real new ADD/DEL dirties the new book. Completing this
                // comparison barrier must not create an empty startup FEED.
                self.recovery = None;
            }
            if !server.persistence_pending()
                && publication_ready
                && let Some(publications) = &mut self.publications
            {
                changed |= publications.advance(
                    server,
                    &mut self.pils,
                    &mut self.writer,
                    generation,
                    &mut self.hello,
                    utc,
                )?;
            }
        }
        if self
            .server
            .as_ref()
            .is_some_and(|s| !s.persistence_pending())
        {
            changed |= self.validation_step(times)?;
        }
        if !self.rotating
            && let Some(server) = &mut self.server
        {
            let (progress, outcome) =
                self.burst
                    .advance(server, &mut self.discovery, &mut self.clock, times, cx)?;
            changed |= progress;
            if let Some(outcome) = outcome {
                observe(Event::Burst(outcome));
            }
        }
        if self.server.is_some()
            && self.maintenance_retry.is_none()
            && self
                .server
                .as_ref()
                .is_some_and(|s| !s.persistence_pending())
        {
            if self.alarm.is_none() {
                self.alarm = Some(Box::pin(tokio::time::sleep_until(self.next_tick)));
            }
            if let Some(alarm) = &mut self.alarm {
                let _ready = alarm.as_mut().poll(cx);
            }
        }
        if self
            .server
            .as_ref()
            .is_some_and(Server::persistence_pending)
        {
            self.alarm = None;
        }
        if changed {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
    /// Permanently retire every original physical native owner. Worker drain and
    /// join remain the caller's separate explicit lifecycle obligation.
    pub fn stop(&mut self, observe: &mut impl FnMut(Event<'id>)) -> Vec<Failure> {
        if self.stopped {
            return Vec::new();
        }
        self.stopped = true;
        // Keep only exact old-Server cleanup access. Public dv_scope() and
        // dv_times() remain unavailable after this terminal state.
        if let Some(p) = &mut self.publications {
            p.retire();
        }
        let mut errors = Vec::new();
        if let Some(server) = &mut self.server {
            if let Err(e) = server.shutdown() {
                errors.push(Box::new(e) as Failure)
            }
            if let Some(original) = server.take_native_retirement() {
                observe(Event::NativeRetired(original));
            }
            while let Some(original) = server.take_monitor_retirement() {
                observe(Event::Transport(NativeStep::MonitorRetired(original)));
            }
        }
        if self.reservation_drain.is_none()
            && let Some(publications) = &mut self.publications
        {
            let stamp = publications.take_retired_stamp();
            match stamp.and_then(|stamp| self.take_original_reservation(stamp)) {
                Ok(original) => {
                    self.reservation_drain =
                        Some(crate::epoch::Drain::after_physical_retirement(original))
                }
                Err(e) => errors.push(Box::new(e) as Failure),
            }
        }
        self.burst.after_physical_retirement();
        if let Some(server) = &mut self.server {
            if let Some(request) = server.burst_request().cloned()
                && request.selected.is_none()
                && let Err(error) =
                    server.cancel_burst(&request.id, gnunet_transport::burst::End::SourceLost)
            {
                errors.push(Box::new(error));
            }
            if let Some(outcome) = server.take_burst_outcome() {
                observe(Event::Burst(outcome));
            }
        }
        if let Some(outcome) = self.retired_burst.take() {
            observe(Event::Burst(outcome));
        }
        self.pils.close();
        self.writer.close();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        // Both providers are already physically stopped; polling here drains
        // their retained originals without a clock, socket IO or new admission.
        loop {
            match self.pils.poll(&mut cx) {
                Poll::Ready(Ok(pils::Event::SourceLost { cause, .. })) => {
                    if cause.downcast_ref::<Fault>() != Some(&Fault::Closed) {
                        errors.push(cause);
                    }
                }
                Poll::Ready(Ok(event)) => observe(Event::PilsRetired(event)),
                Poll::Ready(Err(error)) => {
                    errors.push(error);
                    break;
                }
                Poll::Pending => break,
            }
        }
        loop {
            match self.writer.poll(&mut cx) {
                Poll::Ready(Ok(crate::writer::Event::SourceLost(error))) => {
                    if error.downcast_ref::<Fault>() != Some(&Fault::Closed) {
                        errors.push(error);
                    }
                }
                Poll::Ready(Ok(event)) => observe(Event::PublicationRetired(event)),
                Poll::Ready(Err(error)) => {
                    errors.push(error);
                    break;
                }
                Poll::Pending => break,
            }
        }
        if let Some(end) = self.nat.close() {
            observe(Event::Nat(nat::Progress::Ended(end)));
        }
        self.discovery
            .close_all(&mut |e| observe(Event::Discovery(e)));
        let (retired, cleanup) = self.validated.retire_now();
        errors.extend(cleanup);
        if let Some(done) = retired {
            if let Some(error) = &done.failure {
                errors.push(error.boxed());
            }
            observe(Event::ValidatedRetired(done));
        }
        errors.extend(self.hello.close());
        if let Some(done) = self.hello.take_retired() {
            observe(Event::HelloRetired(done));
        }
        self.validations.clear();
        self.alarm = None;
        errors
    }
}
impl<E: Entropy> Drop for Owner<'_, E> {
    fn drop(&mut self) {
        let _cleanup = self.stop(&mut |_| {});
    }
}
