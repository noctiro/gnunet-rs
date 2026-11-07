use crate::own_publisher::Publisher;
use gnunet_client_host::EndpointSource;
use gnunet_crypto::Entropy;
use gnunet_pils::{ActiveIdentity, Profile, client as pc};
use gnunet_pils_host::client as pils;
use gnunet_service_runtime::{
    accepted::{AcceptState, SocketEvent},
    clock::{ClockSubscription, Deadline, RuntimeClock},
    service::{Listener, PeerAddress, ServiceOptions},
};
use gnunet_transport::{
    Engine, PeerId, Signer,
    signing::{ValidationMode, ValidationRequest},
};
use gnunet_transport_host::{
    Server,
    peerstore::{self, Journal},
};
use gnunet_types::Error as ProtocolError;
use std::{
    future::{Future, poll_fn},
    io,
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

/// Actual original runtime failure; no accepted IPC input is replayed on error.
#[derive(Debug)]
pub enum Error {
    /// Native or filesystem capability error.
    Io(io::Error),
    /// Explicit protocol, clock, resource or durable-store error.
    Protocol(ProtocolError),
    /// Actual native PILS client error.
    Pils(pils::Error),
    /// Original managed-store stage, classification and native OS cause.
    Store(peerstore::JournalFailure),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
impl From<ProtocolError> for Error {
    fn from(e: ProtocolError) -> Self {
        Self::Protocol(e)
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<pils::Error> for Error {
    fn from(e: pils::Error) -> Self {
        Self::Pils(e)
    }
}
/// Explicit caller authorization for optional local private-key access.
/// It is usable only after a current real PILS announcement derives a matched key.
pub struct LocalKeyCapability {
    /// Existing persisted raw32 IKM, never created by this runtime.
    pub ikm_file: PathBuf,
}
/// Explicit current native ports and owned backend for local-capability mode.
pub struct LocalPorts {
    /// Canonical PILS endpoint/retained native attempt source.
    pub pils: EndpointSource,
    /// Caller-authorized existing IKM access, gated by actual PILS matching.
    pub capability: LocalKeyCapability,
    /// Same actual clock source carried by the endpoint/Resolver context.
    pub clock: Arc<dyn RuntimeClock>,
    /// Original fenced native public-peerstore backend.
    pub journal: Journal,
}
/// Explicit ports for standard asynchronous PILS signing; no local key access.
pub struct ServicePorts {
    /// Original PILS endpoint/retained attempt source.
    pub pils: EndpointSource,
    /// Same canonical clock as the endpoint and process Resolver context.
    pub clock: Arc<dyn RuntimeClock>,
    /// Original fenced native public-peerstore backend.
    pub journal: Journal,
}
/// Separate service policies on one physical process resource owner.
#[derive(Default)]
pub struct Policies {
    /// Official TRANSPORT TCP access policy.
    pub transport: ServiceOptions,
    /// Official public PEERSTORE TCP access policy.
    pub peerstore: ServiceOptions,
}
/// Bounded runtime resource policy, independent of official wire fields.
#[derive(Clone, Copy)]
pub struct Limits {
    /// Node-wide PILS identity derivation and HELLO verification policy.
    pub pils_profile: Profile,
    /// Independent verification policy for remote HELLO discovery hints.
    pub discovery_hello_profile: gnunet_hello::SignatureProfile,
    /// Pure transport capacities.
    pub transport: gnunet_transport::Limits,
    /// Maximum native TRANSPORT IPC owners.
    pub transport_clients: usize,
    /// Maximum pending bytes per transport IPC owner.
    pub transport_pending_bytes: usize,
    /// Maximum public peerstore IPC owners.
    pub peerstore_clients: usize,
    /// Bounded actual PILS traffic and native IO slice.
    pub pils: pils::Limits,
    /// Maximum records visited by one original discovery-source step.
    pub discovery_quantum: NonZeroUsize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            pils_profile: Profile::Reference029,
            discovery_hello_profile: gnunet_hello::SignatureProfile::Gnunet029,
            transport: Default::default(),
            transport_clients: 32,
            transport_pending_bytes: 1024 * 1024,
            peerstore_clients: 32,
            pils: Default::default(),
            discovery_quantum: NonZeroUsize::MIN,
        }
    }
}
impl Limits {
    fn own_bounds(self) -> Result<gnunet_transport::own::PublicationBounds, ProtocolError> {
        gnunet_transport::own::PublicationBounds::checked(
            self.transport.control_messages,
            self.transport.control_bytes,
            self.pils.frame_bytes,
            usize::from(u16::MAX),
        )
    }
    fn managed_quota(
        self,
        bounds: gnunet_transport::own::PublicationBounds,
    ) -> Result<peerstore::ManagedQuota, ProtocolError> {
        let addresses = self
            .transport
            .control_messages
            .min(self.transport.control_bytes / 6);
        let own_prefix = 60usize
            + gnunet_transport::own_wire::SUBSYSTEM.len()
            + 1
            + gnunet_transport::own_wire::KEY.len()
            + 1
            + 4;
        let overhead = own_prefix
            .checked_add(gnunet_transport::own_wire::maximum_value_bytes(0)?)
            .ok_or(ProtocolError::Capacity)?;
        let own_bytes = if addresses == 0 {
            0
        } else {
            (self.transport.control_bytes / 2)
                .checked_add(
                    addresses
                        .checked_mul(overhead)
                        .ok_or(ProtocolError::Capacity)?,
                )
                .ok_or(ProtocolError::Capacity)?
        };
        Ok(peerstore::ManagedQuota {
            records: addresses.checked_add(1).ok_or(ProtocolError::Capacity)?,
            bytes: own_bytes
                .checked_add(bounds.hello_record_bytes)
                .and_then(|n| n.checked_add(4))
                .ok_or(ProtocolError::Capacity)?,
        })
    }
    fn publication_limits(self) -> Result<gnunet_pils::HelloLimits, ProtocolError> {
        if self.transport.control_messages == 0 || self.transport.control_bytes < 120 {
            return Err(ProtocolError::InvalidInput);
        }
        let address_bytes = gnunet_transport::addresses::maximum_serialized_bytes(
            self.transport.control_messages,
            self.transport.control_bytes,
        )?;
        let announcement_bytes = gnunet_wire::official::pils::PEER_UPDATE_PREFIX
            .checked_add(gnunet_hello::BLOCK_HEADER_LEN)
            .and_then(|n| n.checked_add(address_bytes))
            .ok_or(ProtocolError::Capacity)?;
        // A resulting actual service announcement is larger than its unsigned
        // FEED. Check that complete wrapper, not just the outgoing112B prefix.
        if announcement_bytes > self.pils.frame_bytes || announcement_bytes > u16::MAX as usize {
            return Err(ProtocolError::Capacity);
        }
        Ok(gnunet_pils::HelloLimits {
            maximum_input_bytes: 65535,
            // Preserve the existing external-observation window. Other actual
            // PILS clients need not share this local communicator quota.
            maximum_address_bytes: 4096.max(address_bytes),
            maximum_addresses: 64.max(self.transport.control_messages),
        })
    }
}
/// Original actual progress, never a remote delivery claim.
#[must_use = "progress may own an original native PILS event"]
#[expect(
    clippy::large_enum_variant,
    reason = "Original bounded PILS results/loss reports return without a fallible allocation after physical retirement or response consumption"
)]
pub enum Progress<'a> {
    /// New transport actor activated on a verified current local identity.
    Activated([u8; 32]),
    /// Original physical/identity actor was retired before replacement.
    Retired,
    /// Real IO, clock, protocol or storage progress.
    Activity,
    /// Original complete ADD refused local quota; no wire ACK is invented.
    AddressRejected(gnunet_transport::addresses::AddressRejection),
    /// Original owned native PILS event, including its actual loss cause/report.
    Pils(pils::Progress<'a>),
    /// Original own-publication cause. Known storage outcomes are consumed
    /// before this observation is returned; it does not authorize replay.
    OwnPublicationNotice(Error),
    /// Original clients are closed and the final empty set, when required,
    /// reached its original PILS MQ as a local full write. No remote ACK exists.
    Drained {
        /// A fresh empty publication was locally written on the original epoch.
        local_empty_written: bool,
    },
    /// Caller permanently closed the runtime.
    Closed,
}
/// Cumulative concrete runtime observations.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report {
    /// Verified transport actor activations.
    pub activations: u64,
    /// Retired transport actor epochs.
    pub retirements: u64,
    /// Actual PILS physical losses.
    pub pils_losses: u64,
    /// Local IKM/public-announcement mismatches; no key was used.
    pub local_key_mismatches: u64,
    /// Original purpose35 snapshots successfully signed and locally admitted.
    pub validation_signatures: u64,
    /// Accepted TRANSPORT client sockets.
    pub transport_connections: u64,
    /// Accepted public peerstore sockets.
    pub peerstore_connections: u64,
    /// Actual public peerstore requests handled.
    pub peerstore_requests: u64,
    /// Actual journal commits.
    pub durable_commits: u64,
    /// Unexpected admitted PILS service operations explicitly canceled on close.
    pub canceled_pils_operations: u64,
    /// Original purpose35 requests admitted by the actual PILS client.
    pub service_signature_requests: u64,
    /// Original service failures or refused/retired signature completions.
    pub service_signature_failures: u64,
    /// Original service operations retained, including verified unadmitted results.
    pub pending_service_signatures: usize,
    /// Actual unsigned aggregate operations admitted on their original PILS MQ.
    pub address_publication_requests: u64,
    /// Actual original local FEED full writes; no remote application ACK exists.
    pub address_publication_writes: u64,
    /// Fresh current-resource effects after an observed settled-state mismatch.
    /// Reference029 address claims are not cryptographically authenticated by HELLO.
    pub address_reconciliations: u64,
    /// Original FEED operation canceled/retired with its owning transport epoch.
    pub address_publication_retirements: u64,
    /// Original aggregate operation still owned by PILS/native cursors.
    pub pending_address_publications: usize,
    /// Explicit bounded drains completed; repeated terminal polls count once.
    pub graceful_drains: u64,
    /// Complete original ADD requests visibly refused without dropping any MQ.
    pub address_rejections: u64,
}
struct Actor<'a> {
    epoch: pc::Epoch<'a>,
    peer: [u8; 32],
    server: Server,
}
struct Random;
impl Entropy for Random {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), ProtocolError> {
        getrandom::fill(out).map_err(|_| ProtocolError::Entropy)
    }
}
struct Signing<'k, 'a> {
    identity: pc::Identity<'a>,
    key: &'k ActiveIdentity,
    count: &'k mut u64,
}
impl Signer for Signing<'_, '_> {
    fn identity(&self) -> PeerId {
        PeerId(*self.identity.peer().as_bytes())
    }
    fn sign_validation(&mut self, region: &[u8; 48]) -> Result<[u8; 64], ProtocolError> {
        if self.key.public_key() != self.identity.peer() {
            return Err(ProtocolError::Authentication);
        }
        let signature = *self.key.sign(region)?.as_bytes();
        *self.count = self.count.saturating_add(1);
        Ok(signature)
    }
}
struct ServiceSigning<'a>(pc::Identity<'a>);
impl Signer for ServiceSigning<'_> {
    fn identity(&self) -> PeerId {
        PeerId(*self.0.peer().as_bytes())
    }
    fn sign_validation(&mut self, _: &[u8; 48]) -> Result<[u8; 64], ProtocolError> {
        Err(ProtocolError::NotReady)
    }
    fn validation_mode(&self) -> ValidationMode {
        ValidationMode::Deferred
    }
}
struct PendingPublication<'a> {
    id: gnunet_transport::addresses::PublicationId,
    operation: pc::OperationId<'a>,
    identity: pc::Identity<'a>,
}
struct PendingSignature<'a> {
    request: ValidationRequest,
    operation: pc::OperationId<'a>,
    identity: pc::Identity<'a>,
    result: Option<(PeerId, [u8; 64])>,
}
struct Draining<'a> {
    identity: Option<pc::Identity<'a>>,
    deadline: Deadline,
    publication_required: bool,
    completed: bool,
}
/// Caller-driven native runtime. No service/backend/Resolver task is spawned.
/// Physical PILS epochs and actor identity are retained independently from keys.
pub struct Runtime<'a> {
    pils: pils::Client<'a>,
    capability: Option<LocalKeyCapability>,
    clock: Arc<dyn RuntimeClock>,
    subscription: Option<Box<dyn ClockSubscription>>,
    deadline: Option<Deadline>,
    actor: Option<Actor<'a>>,
    peerstore: peerstore::Server,
    journal: Journal,
    own: Option<Publisher<'a>>,
    own_bounds: gnunet_transport::own::PublicationBounds,
    deferred: Option<peerstore::JournalTransaction>,
    limits: Limits,
    tr_options: ServiceOptions,
    ps_options: ServiceOptions,
    accept_state: AcceptState,
    tr_cursor: usize,
    ps_cursor: usize,
    actor_cursor: usize,
    last_signed: u64,
    signed_end: u64,
    next_tick: u64,
    next_key_read: u64,
    yield_due: bool,
    closed: bool,
    draining: Option<Draining<'a>>,
    revision: u64,
    report: Report,
    pending_pils_notice: Option<pils::Progress<'a>>,
    pending_own_notice: Option<Error>,
    signatures: Vec<PendingSignature<'a>>,
    publication: Option<PendingPublication<'a>>,
    publication_scratch: Vec<u8>,
    publication_limits: gnunet_pils::HelloLimits,
    publication_owned: bool,
    reset_publication: bool,
    retire_pils_for_publication: bool,
}
impl<'a> Runtime<'a> {
    /// Construct the explicit verified-local-key mode around existing native ports.
    /// The supplied Journal owns its original kernel writer fence throughout.
    pub fn new_local(
        instance: &'a mut pc::Instance,
        ports: LocalPorts,
        limits: Limits,
        policies: Policies,
    ) -> Result<Self, Error> {
        let LocalPorts {
            pils: source,
            capability,
            clock,
            journal,
        } = ports;
        Self::new(
            instance,
            ServicePorts {
                pils: source,
                clock,
                journal,
            },
            Some(capability),
            limits,
            policies,
        )
    }
    /// Construct standard service-signing mode. Only the actual verified PILS
    /// announcement grants identity; no IKM file or local private key is read.
    pub fn new_service(
        instance: &'a mut pc::Instance,
        ports: ServicePorts,
        limits: Limits,
        policies: Policies,
    ) -> Result<Self, Error> {
        Self::new(instance, ports, None, limits, policies)
    }
    fn new(
        instance: &'a mut pc::Instance,
        ports: ServicePorts,
        capability: Option<LocalKeyCapability>,
        limits: Limits,
        policies: Policies,
    ) -> Result<Self, Error> {
        let ServicePorts {
            pils: source,
            clock,
            mut journal,
        } = ports;
        let Policies {
            transport: tr_options,
            peerstore: ps_options,
        } = policies;
        if !Arc::ptr_eq(&source.clock(), &clock) {
            return Err(ProtocolError::InvalidInput.into());
        }
        if journal.hello_profiles()
            != (peerstore::HelloProfiles {
                managed: limits.pils_profile.hello(),
                discovery: limits.discovery_hello_profile,
            })
        {
            return Err(ProtocolError::Conflict.into());
        }
        let publication_limits = limits.publication_limits()?;
        let own_bounds = limits.own_bounds()?;
        journal.reserve_managed(limits.managed_quota(own_bounds)?)?;
        let subscription = clock.subscribe()?;
        let pils = pils::Client::new(
            instance,
            source,
            limits.pils_profile,
            limits.pils,
            publication_limits,
        )?;
        let peerstore = peerstore::Server::new(limits.peerstore_clients)?;
        let mut signatures = Vec::new();
        signatures
            .try_reserve_exact(limits.transport.control_messages)
            .map_err(|_| ProtocolError::Capacity)?;
        let mut publication_scratch = Vec::new();
        publication_scratch
            .try_reserve_exact(publication_limits.maximum_address_bytes)
            .map_err(|_| ProtocolError::Capacity)?;
        publication_scratch.resize(publication_limits.maximum_address_bytes, 0);
        Ok(Self {
            pils,
            capability,
            clock,
            subscription: Some(subscription),
            deadline: None,
            actor: None,
            peerstore,
            journal,
            own: None,
            own_bounds,
            deferred: None,
            limits,
            tr_options,
            ps_options,
            accept_state: Default::default(),
            tr_cursor: 0,
            ps_cursor: 0,
            actor_cursor: 0,
            last_signed: 0,
            signed_end: 0,
            next_tick: 0,
            next_key_read: 0,
            yield_due: false,
            closed: false,
            draining: None,
            revision: 0,
            report: Default::default(),
            pending_pils_notice: None,
            pending_own_notice: None,
            signatures,
            publication: None,
            publication_scratch,
            publication_limits,
            publication_owned: false,
            reset_publication: false,
            retire_pils_for_publication: false,
        })
    }
    /// Snapshot actual observations without advancing any port.
    #[must_use]
    pub fn report(&self) -> Report {
        Report {
            peerstore_requests: self.peerstore.requests(),
            durable_commits: self.journal.commits(),
            pending_service_signatures: self.signatures.len(),
            pending_address_publications: usize::from(self.publication.is_some()),
            ..self.report
        }
    }
    /// Drain an original native PILS notice, also after a fatal permanent close.
    /// This grants no current key authority and performs no IO or subscription.
    pub fn take_pils_notice(&mut self) -> Option<pils::Progress<'a>> {
        self.pending_pils_notice.take()
    }
    /// Take the actual original own-publication refusal, including after close.
    pub fn take_own_notice(&mut self) -> Option<Error> {
        let cause = self
            .pending_own_notice
            .take()
            .or_else(|| self.own.as_mut().and_then(Publisher::take_error));
        let cause = cause.or_else(|| {
            self.deferred.as_mut().and_then(|original| {
                if matches!(
                    original.outcome(),
                    Some(gnunet_transport::own::CommitOutcome::Unknown(_)) | None
                ) {
                    None
                } else {
                    original.take_failure().map(Error::Store)
                }
            })
        });
        if self
            .own
            .as_ref()
            .is_some_and(|own| own.retired() && !own.has_error())
        {
            self.own = None;
        }
        cause
    }
    /// Original actual storage cause while an unknown transaction remains owned.
    pub fn storage_failure(&self) -> Option<&peerstore::JournalFailure> {
        self.deferred
            .as_ref()
            .and_then(peerstore::JournalTransaction::failure)
            .or_else(|| self.own.as_ref().and_then(Publisher::storage_failure))
    }
    /// Current actually verified transport identity, absent while unready/offline.
    #[must_use]
    pub fn identity(&self) -> Option<[u8; 32]> {
        self.actor.as_ref().map(|a| a.peer)
    }
    /// Exact latest verified PILS observation. This does not grant an active
    /// transport lease or authenticate the reference profile's address claims.
    pub fn announcement(&self) -> Option<&[u8]> {
        self.pils.announcement()
    }
    /// Stop service admission and drop original service clients before draining
    /// a fresh empty publication. Original partial PILS frames retain their FIFO
    /// cursors. The timeout uses the canonical clock; cancellation of a waiting
    /// drive future preserves this owner. A physical/key epoch change or refused
    /// clock fails the drain and never republishes using a later identity.
    ///
    /// Poll `drive` until `Progress::Drained`, then call `close`. The resulting
    /// local full write is not a PILS application ACK. `close` remains immediate
    /// permanent retirement and may explicitly abandon a pending drain.
    pub fn begin_shutdown(&mut self, timeout_micros: NonZeroU64) -> Result<(), Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        if self.draining.is_some() {
            return Ok(());
        }
        let now = self.clock.sample()?.now.as_micros();
        let end = now
            .checked_add(timeout_micros.get())
            .ok_or(ProtocolError::Overflow)?;
        // Deadline reserves MAX for FOREVER; a bounded shutdown cannot accept
        // that sentinel, even though checked_add itself did not overflow.
        if end == u64::MAX {
            return Err(ProtocolError::InvalidInput.into());
        }
        let identity = self.pils.identity();
        if self.actor.as_ref().is_some_and(|actor| {
            identity.is_none_or(|i| i.epoch() != actor.epoch || *i.peer().as_bytes() != actor.peer)
        }) || (self.publication_owned && self.actor.is_none())
        {
            return Err(ProtocolError::Stale.into());
        }
        let deadline = Deadline::at(
            self.clock.clone(),
            gnunet_types::AbsoluteTime::from_micros(end),
        )?;
        self.draining = Some(Draining {
            identity,
            deadline,
            publication_required: self.publication_owned,
            completed: false,
        });
        let stopped = (|| {
            if let Some(own) = &mut self.own {
                own.begin_retirement();
            }
            if let Some(actor) = &mut self.actor {
                actor.server.shutdown()?;
                if self.publication_owned {
                    // A new current-resource effect; an older partial original
                    // stays owned and completes before this FIFO successor.
                    actor.server.refresh_address_publication()?;
                }
            }
            self.peerstore.shutdown();
            self.cancel_signatures()
        })();
        if let Err(error) = stopped {
            let _closed = self.close();
            return Err(error);
        }
        Ok(())
    }
    fn drained(&mut self) -> Poll<Result<Progress<'a>, Error>> {
        let draining = self.draining.as_mut().ok_or(ProtocolError::NotReady)?;
        if !draining.completed {
            draining.completed = true;
            self.report.graceful_drains = self.report.graceful_drains.saturating_add(1);
        }
        let local_empty_written = draining.publication_required;
        self.ready(Progress::Drained {
            local_empty_written,
        })
    }
    fn retire(&mut self) -> Result<bool, Error> {
        if let Some(own) = &mut self.own {
            own.begin_retirement();
        }
        if let Some(mut old) = self.actor.take() {
            let clients = old.server.engine().snapshot().clients;
            self.report.retirements = self.report.retirements.saturating_add(1);
            let retired = old.server.shutdown();
            if clients > 0 {
                self.accept_state.client_closed();
            }
            let cancelled = self.cancel_signatures();
            if self.publication_owned {
                self.reset_publication = true;
            }
            let publication = self.retire_publication();
            retired?;
            cancelled?;
            publication?;
            return Ok(true);
        }
        Ok(false)
    }
    fn reconcile(&mut self, now: u64) -> Result<Option<Progress<'a>>, Error> {
        let current = self.pils.identity();
        if self.actor.as_ref().is_some_and(|a| {
            current.is_none_or(|i| i.epoch() != a.epoch || *i.peer().as_bytes() != a.peer)
        }) {
            self.retire()?;
            return Ok(Some(Progress::Retired));
        }
        if let Some(capability) = &self.capability
            && current.is_some()
            && self.pils.local_key_status() != pc::LocalKeyStatus::Matched
            && now >= self.next_key_read
        {
            let master = gnunet_pils_host::identity::load_existing(&capability.ikm_file)?;
            let status = self.pils.enable_local_key(master)?;
            self.next_key_read = now.saturating_add(1_000_000);
            if status == pc::LocalKeyStatus::Mismatch {
                self.report.local_key_mismatches =
                    self.report.local_key_mismatches.saturating_add(1);
            }
        }
        if self.actor.is_none()
            && self.own.is_none()
            && (self.capability.is_none()
                || self.pils.local_key_status() == pc::LocalKeyStatus::Matched)
            && let Some(identity) = self.pils.identity()
        {
            let peer = *identity.peer().as_bytes();
            let mut engine = Engine::new(PeerId(peer), self.limits.transport)?;
            if self.reset_publication {
                engine.refresh_address_publication()?;
                self.reset_publication = false;
            }
            let server = Server::new(
                engine,
                self.limits.transport_clients,
                self.limits.transport_pending_bytes,
            )?;
            self.own = Some(Publisher::new(
                identity,
                self.limits
                    .transport
                    .control_messages
                    .min(self.limits.transport.control_bytes / 6),
                self.own_bounds,
            )?);
            self.actor = Some(Actor {
                epoch: identity.epoch(),
                peer,
                server,
            });
            self.report.activations = self.report.activations.saturating_add(1);
            return Ok(Some(Progress::Activated(peer)));
        }
        Ok(None)
    }
    fn cancel_signatures(&mut self) -> Result<(), Error> {
        let mut first = None;
        for pending in self.signatures.drain(..) {
            if pending.result.is_some() {
                continue;
            }
            match self.pils.cancel(pending.operation) {
                Ok(()) => {
                    self.report.canceled_pils_operations =
                        self.report.canceled_pils_operations.saturating_add(1)
                }
                Err(pils::Error::Protocol(ProtocolError::Stale)) => {}
                Err(error) => {
                    first.get_or_insert(error);
                }
            }
        }
        first.map_or(Ok(()), |e| Err(e.into()))
    }
    fn record_signature_result(&mut self) -> Result<(), Error> {
        let Some(pils::Progress::Inbound(pc::Inbound::Complete(completion))) =
            self.pending_pils_notice.as_ref()
        else {
            return Ok(());
        };
        let Some(index) = self
            .signatures
            .iter()
            .position(|p| p.operation == completion.operation())
        else {
            return Ok(());
        };
        match completion {
            pc::Completion::Signature {
                peer, signature, ..
            } => {
                let original = &mut self.signatures[index];
                if *peer != original.identity.peer() {
                    return Err(ProtocolError::Authentication.into());
                }
                original.result = Some((PeerId(*peer.as_bytes()), *signature.as_bytes()));
            }
            pc::Completion::Failed { .. } => {
                let original = self.signatures.remove(index);
                if let Some(actor) = &mut self.actor
                    && actor.server.validation_live(original.request.id())
                {
                    actor.server.cancel_validation(original.request.id())?;
                }
                self.report.service_signature_failures =
                    self.report.service_signature_failures.saturating_add(1);
            }
            _ => return Err(ProtocolError::Authentication.into()),
        }
        Ok(())
    }
    fn drive_signatures(&mut self, now: u64) -> Result<bool, Error> {
        let Some(actor) = &mut self.actor else {
            return Ok(false);
        };
        if let Some(index) = self.signatures.iter().position(|p| {
            !actor.server.validation_live(p.request.id())
                || p.identity.epoch() != actor.epoch
                || *p.identity.peer().as_bytes() != actor.peer
        }) {
            let original = self.signatures.remove(index);
            if original.result.is_none() {
                match self.pils.cancel(original.operation) {
                    Ok(()) => {
                        self.report.canceled_pils_operations =
                            self.report.canceled_pils_operations.saturating_add(1)
                    }
                    Err(pils::Error::Protocol(ProtocolError::Stale)) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            return Ok(true);
        }
        if let Some(index) = self.signatures.iter().position(|p| p.result.is_some()) {
            let original = &self.signatures[index];
            let (peer, signature) = original.result.ok_or(ProtocolError::Stale)?;
            match actor
                .server
                .complete_validation(original.request.id(), peer, signature, now)
            {
                Ok(()) => {
                    self.signatures.remove(index);
                    self.report.validation_signatures =
                        self.report.validation_signatures.saturating_add(1);
                    return Ok(true);
                }
                Err(ProtocolError::Capacity | ProtocolError::WouldBlock) => return Ok(false),
                Err(ProtocolError::Stale) => {
                    let original = self.signatures.remove(index);
                    if actor.server.validation_live(original.request.id()) {
                        actor.server.cancel_validation(original.request.id())?;
                    }
                    self.report.service_signature_failures =
                        self.report.service_signature_failures.saturating_add(1);
                    return Ok(true);
                }
                Err(error) => return Err(error.into()),
            }
        }
        if self.capability.is_some()
            || self.signatures.len() == self.limits.transport.control_messages
        {
            return Ok(false);
        }
        let Some(request) = actor.server.validation_request().cloned() else {
            return Ok(false);
        };
        let identity = self.pils.identity().ok_or(ProtocolError::NotReady)?;
        if identity.epoch() != actor.epoch || request.signer().0 != *identity.peer().as_bytes() {
            return Err(ProtocolError::Authentication.into());
        }
        let operation = match self
            .pils
            .sign(request.region(), pc::KeyTarget::Exact(identity))
        {
            Ok(operation) => operation,
            Err(pils::Error::Protocol(ProtocolError::Capacity | ProtocolError::WouldBlock)) => {
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        };
        if let Err(error) = actor.server.claim_validation(request.id()) {
            let _cancelled = self.pils.cancel(operation);
            return Err(error.into());
        }
        self.signatures.push(PendingSignature {
            request,
            operation,
            identity,
            result: None,
        });
        self.report.service_signature_requests =
            self.report.service_signature_requests.saturating_add(1);
        Ok(true)
    }
    fn retire_publication(&mut self) -> Result<(), Error> {
        let Some(original) = self.publication.take() else {
            return Ok(());
        };
        // FEED has no expected-key field. An unfinished original body must not
        // advance after a different peer was observed on this same physical MQ.
        if self.pils.identity().is_some_and(|i| {
            i.epoch() == original.identity.epoch() && i.peer() != original.identity.peer()
        }) {
            self.retire_pils_for_publication = true;
        }
        match self.pils.cancel(original.operation) {
            Ok(()) => {}
            Err(pils::Error::Protocol(ProtocolError::Stale)) => {}
            Err(error) => return Err(error.into()),
        }
        self.report.address_publication_retirements = self
            .report
            .address_publication_retirements
            .saturating_add(1);
        Ok(())
    }
    fn record_publication_write(&mut self) -> Result<(), Error> {
        let Some(pils::Progress::Written(written)) = self.pending_pils_notice.as_ref() else {
            return Ok(());
        };
        if !self
            .publication
            .as_ref()
            .is_some_and(|p| p.operation == written.operation)
        {
            return Ok(());
        }
        let original = self.publication.take().ok_or(ProtocolError::Stale)?;
        if written.kind != pc::OperationKind::Feed {
            return Err(ProtocolError::Authentication.into());
        }
        if written.canceled {
            return Err(ProtocolError::Closed.into());
        }
        if let Some(actor) = &mut self.actor {
            if actor.epoch != original.identity.epoch()
                || actor.peer != *original.identity.peer().as_bytes()
            {
                return Err(ProtocolError::Stale.into());
            }
            actor.server.address_publication_written(&original.id)?;
            self.report.address_publication_writes =
                self.report.address_publication_writes.saturating_add(1);
        }
        Ok(())
    }
    fn reconcile_publication_observation(&mut self) -> Result<(), Error> {
        if !self.publication_owned
            || self.publication.is_some()
            || !matches!(
                &self.pending_pils_notice,
                Some(pils::Progress::Inbound(pc::Inbound::Identity { .. }))
            )
        {
            return Ok(());
        }
        let Some(actor) = &mut self.actor else {
            return Ok(());
        };
        if actor.server.address_publication()?.is_some() {
            return Ok(());
        }
        let bytes = self.pils.announcement().ok_or(ProtocolError::NotReady)?;
        let update = gnunet_wire::official::pils::PeerUpdate::decode(bytes)?;
        let hello = gnunet_hello::Hello::parse_block(
            update.block,
            &mut self.publication_scratch,
            self.publication_limits,
        )?;
        if *hello.peer().as_bytes() != actor.peer {
            return Err(ProtocolError::Authentication.into());
        }
        // FEED has no application ACK or expected-key field. A late prior
        // submission may be observed after reconnect; reconcile a fresh snapshot
        // of current resources instead of replaying the retired original body.
        if !actor.server.addresses_match(hello) {
            actor.server.refresh_address_publication()?;
            self.report.address_reconciliations =
                self.report.address_reconciliations.saturating_add(1);
        }
        Ok(())
    }
    fn drive_publication(&mut self) -> Result<bool, Error> {
        if self.publication.is_some() {
            return Ok(false);
        }
        let Some(actor) = &mut self.actor else {
            return Ok(false);
        };
        let Some(offered) = actor.server.address_publication()? else {
            return Ok(false);
        };
        let identity = self.pils.identity().ok_or(ProtocolError::NotReady)?;
        if identity.epoch() != actor.epoch || *identity.peer().as_bytes() != actor.peer {
            return Err(ProtocolError::Authentication.into());
        }
        let id = offered.id().clone();
        let mut builder =
            gnunet_hello::HelloBuilder::new(&mut self.publication_scratch, self.publication_limits);
        for uri in offered.uris() {
            builder.add_address(uri)?;
        }
        let operation = match self.pils.feed_addresses(&builder) {
            Ok(operation) => operation,
            Err(pils::Error::Protocol(ProtocolError::Capacity | ProtocolError::WouldBlock)) => {
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        };
        if let Err(error) = actor.server.claim_address_publication(&id) {
            let _original = self.pils.cancel(operation);
            return Err(error.into());
        }
        self.publication = Some(PendingPublication {
            id,
            operation,
            identity,
        });
        self.publication_owned = true;
        self.report.address_publication_requests =
            self.report.address_publication_requests.saturating_add(1);
        Ok(true)
    }
    fn record_own_completion(&mut self, now: u64) -> Result<(), Error> {
        if let Some(pils::Progress::Inbound(pc::Inbound::Complete(completion))) =
            &self.pending_pils_notice
            && let Some(own) = &mut self.own
        {
            own.observe(completion, &self.pils, now)?;
        }
        Ok(())
    }
    fn collect_own_notice(&mut self) {
        if self.pending_own_notice.is_none() {
            self.pending_own_notice = self.own.as_mut().and_then(Publisher::take_error);
        }
        if self
            .own
            .as_ref()
            .is_some_and(|own| own.retired() && !own.has_error())
        {
            self.own = None;
        }
    }
    fn drive_own(&mut self, now: u64, stamp: Option<u64>) -> Result<bool, Error> {
        let Some(own) = &mut self.own else {
            return Ok(false);
        };
        let server = self.actor.as_ref().map(|actor| &actor.server);
        let result = own.advance(server, &mut self.pils, &mut self.journal, now, stamp);
        self.collect_own_notice();
        let progressed = result?;
        if progressed {
            self.deadline = None;
        }
        Ok(progressed)
    }
    /// Whether the original managed transaction still quarantines fresh writes.
    pub fn own_storage_pending(&self) -> bool {
        self.own.as_ref().is_some_and(Publisher::storage_pending)
    }
    fn signed_time(&mut self, now: u64) -> Result<u64, Error> {
        let wanted = now.max(
            self.last_signed
                .checked_add(1)
                .ok_or(ProtocolError::Overflow)?,
        );
        if wanted >= self.signed_end {
            let (start, end) = self.journal.reserve_monotime(wanted, 1_000_000)?;
            self.last_signed = start;
            self.signed_end = end;
        } else {
            self.last_signed = wanted;
        }
        Ok(self.last_signed)
    }
    fn ready(&mut self, progress: Progress<'a>) -> Poll<Result<Progress<'a>, Error>> {
        self.yield_due = true;
        Poll::Ready(Ok(progress))
    }
    /// Drive one fair original operation. Dropped waiting futures retain cursors,
    /// clock/PILS attempts and fairness state; a new single-poll future can advance.
    pub async fn drive(
        &mut self,
        tr: &[Listener<'_>],
        ps: &[Listener<'_>],
        observe: &mut impl FnMut(SocketEvent),
    ) -> Result<Progress<'a>, Error> {
        poll_fn(|cx| match self.poll_step(cx, tr, ps, observe) {
            Poll::Ready(Err(error)) => {
                let _closed = self.close();
                Poll::Ready(Err(error))
            }
            other => other,
        })
        .await
    }
    fn poll_step(
        &mut self,
        cx: &mut Context<'_>,
        tr: &[Listener<'_>],
        ps: &[Listener<'_>],
        observe: &mut impl FnMut(SocketEvent),
    ) -> Poll<Result<Progress<'a>, Error>> {
        if self.closed {
            return Poll::Ready(Ok(Progress::Closed));
        }
        if self.yield_due {
            self.yield_due = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if let Some(draining) = &mut self.draining {
            if draining.completed || (!draining.publication_required && self.own.is_none()) {
                return self.drained();
            }
            match Pin::new(&mut draining.deadline).poll(cx) {
                Poll::Ready(Ok(())) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "original PILS publication drain deadline",
                    )
                    .into()));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                Poll::Pending => {}
            }
        }
        let mut sample = self.clock.sample()?;
        if let Some(original) = self.pending_pils_notice.take() {
            return self.ready(Progress::Pils(original));
        }
        if let Some(original) = self.take_own_notice() {
            return self.ready(Progress::OwnPublicationNotice(original));
        }
        if self.retire_pils_for_publication {
            // Original notice is handed out first. The physical owner is then
            // retired before any driver poll can advance its old partial FEED.
            let original = self.pils.reconnect()?;
            self.retire_pils_for_publication = false;
            return self.ready(Progress::Pils(original));
        }
        if sample.revision != self.revision {
            self.revision = sample.revision;
            self.deadline = None;
        }
        if let Some(subscription) = &mut self.subscription {
            match subscription.poll_changed(cx, self.revision) {
                Poll::Ready(Ok(changed)) => {
                    self.revision = changed.revision;
                    sample = changed;
                    self.deadline = None;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Pending => {}
            }
        }
        let mut activity = false;
        // Retire logical own operations before the native client can reconnect
        // or copy them onto a later MQ. Cursor drain remains with that client.
        if let Some(own) = &mut self.own {
            let result = own.preflight(
                self.actor.as_ref().map(|actor| &actor.server),
                &mut self.pils,
                sample.now.as_micros(),
            );
            self.collect_own_notice();
            activity |= result?;
        }
        let pils_progress = {
            let mut driving = std::pin::pin!(self.pils.drive(None));
            driving.as_mut().poll(cx)
        };
        match pils_progress {
            Poll::Ready(Ok(pils::Progress::Closed)) => {
                return Poll::Ready(Err(ProtocolError::Closed.into()));
            }
            Poll::Ready(Ok(original)) => {
                if matches!(&original, pils::Progress::Lost { .. }) {
                    self.report.pils_losses = self.report.pils_losses.saturating_add(1);
                }
                self.pending_pils_notice = Some(original);
                activity = true;
            }
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
            Poll::Pending => {}
        }
        if let Some(draining) = &self.draining {
            let same = match (draining.identity, self.pils.identity()) {
                (Some(original), Some(current)) => {
                    original.epoch() == current.epoch() && original.peer() == current.peer()
                }
                (None, None) => true,
                _ => false,
            };
            if !same {
                self.retire()?;
                return Poll::Ready(Err(ProtocolError::Stale.into()));
            }
        } else if let Some(progress) = self.reconcile(sample.now.as_micros())? {
            return self.ready(progress);
        }
        self.record_signature_result()?;
        self.record_publication_write()?;
        self.record_own_completion(sample.now.as_micros())?;
        if self.draining.is_some() {
            // No new service work, address ownership or signatures can enter.
            // Observe writes of original operations, then submit the fresh final
            // empty set. Reconciliation is disabled: FIFO submission is the
            // closing guarantee; a late old announcement is not an ACK failure.
            let own_progress = self.drive_own(sample.now.as_micros(), None)?;
            let required = self
                .draining
                .as_ref()
                .ok_or(ProtocolError::Stale)?
                .publication_required;
            let feed_done = !required
                || (self.publication.is_none()
                    && self
                        .actor
                        .as_ref()
                        .ok_or(ProtocolError::NotReady)?
                        .server
                        .address_publication()?
                        .is_none());
            if self.own.is_none() && feed_done {
                if let Some(original) = self.pending_pils_notice.take() {
                    return self.ready(Progress::Pils(original));
                }
                if let Some(original) = self.take_own_notice() {
                    return self.ready(Progress::OwnPublicationNotice(original));
                }
                return self.drained();
            }
            if (required && self.drive_publication()?) || activity || own_progress {
                return self.ready(Progress::Activity);
            }
            if self.deadline.is_none()
                && let Some(when) = self.own.as_ref().and_then(Publisher::next_deadline)
            {
                self.deadline = Some(Deadline::at(
                    self.clock.clone(),
                    gnunet_types::AbsoluteTime::from_micros(when),
                )?);
            }
            if let Some(deadline) = &mut self.deadline {
                match Pin::new(deadline).poll(cx) {
                    Poll::Ready(Ok(())) => {
                        self.deadline = None;
                        cx.waker().wake_by_ref();
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                    Poll::Pending => {}
                }
            }
            return Poll::Pending;
        }
        self.reconcile_publication_observation()?;
        let storage_blocked = self.own_storage_pending();
        let signed = if storage_blocked {
            None
        } else {
            Some(self.signed_time(sample.now.as_micros())?)
        };
        for _ in 0..9 {
            let actor = self.actor_cursor;
            self.actor_cursor = (actor + 1) % 9;
            match actor {
                0 => {
                    if let (Some(host), Some(identity), Some(signed)) =
                        (&mut self.actor, self.pils.identity(), signed)
                    {
                        let before = host.server.engine().snapshot().clients;
                        let step = if self.capability.is_none() {
                            host.server.poll_step(
                                cx,
                                None,
                                signed,
                                &mut ServiceSigning(identity),
                                &mut Random,
                                &mut self.journal,
                            )
                        } else if let Some(key) = self.pils.local_key() {
                            let mut signer = Signing {
                                identity,
                                key,
                                count: &mut self.report.validation_signatures,
                            };
                            host.server.poll_step(
                                cx,
                                None,
                                signed,
                                &mut signer,
                                &mut Random,
                                &mut self.journal,
                            )
                        } else {
                            return Poll::Ready(Err(ProtocolError::NotReady.into()));
                        };
                        match step {
                            Poll::Ready(Ok(step)) => {
                                if host.server.engine().snapshot().clients < before {
                                    self.accept_state.client_closed();
                                }
                                if let gnunet_transport_host::Step::AddressRejected(original) = step
                                {
                                    self.report.address_rejections =
                                        self.report.address_rejections.saturating_add(1);
                                    return self.ready(Progress::AddressRejected(original));
                                }
                                return self.ready(Progress::Activity);
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                            Poll::Pending => {}
                        }
                    }
                }
                1 => {
                    let before = self.peerstore.clients();
                    match self
                        .peerstore
                        .poll_step(cx, &mut self.journal, sample.now.as_micros())
                    {
                        Poll::Ready(Ok(())) => {
                            if self.peerstore.clients() < before {
                                self.accept_state.client_closed();
                            }
                            return self.ready(Progress::Activity);
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                        Poll::Pending => {}
                    }
                }
                2 => {
                    if self.actor.as_ref().is_some_and(|a| {
                        a.server.engine().snapshot().clients < self.limits.transport_clients
                    }) && self.accept_state.ready()
                        && let Some(connection) = accept(
                            cx,
                            tr,
                            &mut self.tr_cursor,
                            &self.tr_options,
                            &mut self.accept_state,
                            observe,
                        )
                    {
                        self.actor
                            .as_mut()
                            .ok_or(ProtocolError::NotReady)?
                            .server
                            .admit(connection)?;
                        self.report.transport_connections =
                            self.report.transport_connections.saturating_add(1);
                        return self.ready(Progress::Activity);
                    }
                }
                3 => {
                    if self.peerstore.clients() < self.limits.peerstore_clients
                        && self.accept_state.ready()
                        && let Some(connection) = accept(
                            cx,
                            ps,
                            &mut self.ps_cursor,
                            &self.ps_options,
                            &mut self.accept_state,
                            observe,
                        )
                    {
                        self.peerstore.admit(connection)?;
                        self.report.peerstore_connections =
                            self.report.peerstore_connections.saturating_add(1);
                        return self.ready(Progress::Activity);
                    }
                }
                5 => {
                    if let (Some(host), Some(signed)) = (&mut self.actor, signed) {
                        let step = host.server.discover(
                            signed,
                            sample.now.as_micros(),
                            &mut self.journal,
                            self.limits.discovery_quantum,
                        )?;
                        if step != gnunet_transport_host::discovery::DiscoveryStep::Idle {
                            return self.ready(Progress::Activity);
                        }
                    }
                }
                6 => {
                    if let Some(signed) = signed
                        && self.drive_signatures(signed)?
                    {
                        return self.ready(Progress::Activity);
                    }
                }
                7 => {
                    if self.drive_publication()? {
                        return self.ready(Progress::Activity);
                    }
                }

                8 => {
                    if self.drive_own(sample.now.as_micros(), signed)? {
                        return self.ready(Progress::Activity);
                    }
                }
                _ => {
                    if let Some(signed) = signed
                        && sample.now.as_micros() >= self.next_tick
                    {
                        self.next_tick = sample.now.as_micros().saturating_add(10_000);
                        self.deadline = None;
                        if let Some(host) = &mut self.actor {
                            host.server.tick(signed, &mut Random, &mut self.journal)?;
                        }
                        return self.ready(Progress::Activity);
                    }
                }
            }
        }
        if self.deadline.is_none() {
            let own = self.own.as_ref().and_then(Publisher::next_deadline);
            let when = if storage_blocked {
                own.ok_or(ProtocolError::OutcomeUnknown)?
            } else {
                own.map_or(self.next_tick, |own| own.min(self.next_tick))
            };
            self.deadline = Some(Deadline::at(
                self.clock.clone(),
                gnunet_types::AbsoluteTime::from_micros(when),
            )?);
        }
        if let Some(deadline) = &mut self.deadline {
            match Pin::new(deadline).poll(cx) {
                Poll::Ready(Ok(())) => {
                    self.deadline = None;
                    cx.waker().wake_by_ref();
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Pending => {}
            }
        }
        if activity {
            self.ready(Progress::Activity)
        } else {
            Poll::Pending
        }
    }
    /// Permanently close original physical owners. No recovery resubscribes a
    /// clock or replays accepted application/peerstore/signature side effects.
    pub fn close(&mut self) -> Result<(), Error> {
        if self.closed {
            return if self.own.as_ref().is_some_and(|own| !own.retired()) || self.deferred.is_some()
            {
                Err(ProtocolError::OutcomeUnknown.into())
            } else {
                Ok(())
            };
        }
        self.closed = true;
        let sampled = self.clock.sample();
        let retired = self.retire();
        self.peerstore.shutdown();
        let cancelled = self.pils.close();
        if self.deferred.is_none() {
            self.deferred = self.journal.take_deferred();
        }
        self.report.canceled_pils_operations = self
            .report
            .canceled_pils_operations
            .saturating_add(cancelled.iter().filter(|x| x.is_some()).count() as u64);
        self.deadline = None;
        self.draining = None;
        self.subscription = None;
        retired?;
        let now = sampled?.now.as_micros();
        if self.deferred.is_some() {
            return Err(ProtocolError::OutcomeUnknown.into());
        }
        let bound = self
            .limits
            .transport
            .control_messages
            .min(self.limits.transport.control_bytes / 6)
            .checked_add(16)
            .ok_or(ProtocolError::Capacity)?;
        for _ in 0..bound {
            if self.own.as_ref().is_none_or(Publisher::retired) {
                return Ok(());
            }
            if !self.drive_own(now, None)? {
                break;
            }
        }
        if self.own.as_ref().is_some_and(|own| !own.retired()) {
            Err(ProtocolError::OutcomeUnknown.into())
        } else {
            Ok(())
        }
    }
    /// Advance exact retained managed storage after a permanent close. This
    /// cannot reopen a native service or issue new signing work.
    pub fn recover_own_storage(&mut self) -> Result<bool, Error> {
        if !self.closed {
            return Err(ProtocolError::Conflict.into());
        }
        let now = self.clock.sample()?.now.as_micros();
        if self.deferred.is_none() {
            self.deferred = self.journal.take_deferred();
        }
        if let Some(original) = &mut self.deferred {
            let outcome = match original.outcome() {
                Some(gnunet_transport::own::CommitOutcome::Unknown(_)) => {
                    self.journal.recover(original)
                }
                Some(known) => known,
                None => return Err(ProtocolError::Conflict.into()),
            };
            if matches!(outcome, gnunet_transport::own::CommitOutcome::Unknown(_)) {
                return Ok(false);
            }
            if original.failure().is_some() {
                if self.pending_own_notice.is_some() {
                    return Ok(false);
                }
                self.pending_own_notice = original.take_failure().map(Error::Store);
            }
            self.deferred = None;
            return Ok(true);
        }
        self.drive_own(now, None)
    }
}
impl Drop for Runtime<'_> {
    fn drop(&mut self) {
        let _closed = self.close();
    }
}
fn accept(
    cx: &mut Context<'_>,
    listeners: &[Listener<'_>],
    cursor: &mut usize,
    options: &ServiceOptions,
    state: &mut AcceptState,
    observe: &mut impl FnMut(SocketEvent),
) -> Option<gnunet_service_runtime::connection::Connection> {
    for _ in 0..listeners.len() {
        let i = *cursor % listeners.len();
        *cursor = (*cursor + 1) % listeners.len();
        match listeners[i].poll_canonical_connection(cx) {
            Poll::Ready(Ok(accepted)) => {
                let allowed = match accepted.peer() {
                    PeerAddress::Unix => true,
                    PeerAddress::Tcp(a) => options.access.allows(a.ip()),
                };
                let (connection, _, diagnostics) = accepted.into_parts();
                for diagnostic in diagnostics {
                    observe(SocketEvent::Diagnostic(diagnostic));
                }
                if allowed {
                    return Some(connection);
                }
            }
            Poll::Ready(Err(e)) => {
                observe(state.failed(e));
                return None;
            }
            Poll::Pending => {}
        }
    }
    None
}
