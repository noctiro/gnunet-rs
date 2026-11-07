use crate::{
    clock::{DriverClock, Span},
    providers::Signer,
    types::*,
    *,
};
use domain::{Core, Mode, OperationPhase, Work};
use gnunet_types::Error as Fault;
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
static OWNERS: AtomicU64 = AtomicU64::new(0);
pub(crate) struct Control<'a> {
    pub operation: native::Operation<'a>,
    pub epoch: native::Epoch<'a>,
    pub span: Span,
    pub kind: native::Kind,
    pub queued: bool,
    pub exposure: Exposure,
}
/// One actual owned high-level client over one original low-level MQ at a time.
/// It retains dropped-wait progress, zeroizing keys/scratch and exact original
/// bindings. No socket actor, private-key file loader or protocol ACK is hidden.
/// N bounds caller-selected crypto scratch, not arbitrary native frame policy.
pub struct Api<'a, E: crypto::Entropy, const N: usize = 65524> {
    pub(crate) instance: &'a native::Instance,
    pub(crate) baseline: EndpointSource,
    pub(crate) native: native::Client<'a>,
    pub(crate) records: Option<crate::records::Records<'a>>,
    pub(crate) record_turn: bool,
    pub(crate) core: Core<'a>,
    pub(crate) clock: DriverClock,
    pub(crate) limits: Limits,
    pub(crate) profiles: Profiles,
    pub(crate) next_notification: u64,
    pub(crate) entropy: E,
    pub(crate) signers: Vec<Signer>,
    pub(crate) owner: u64,
    pub(crate) next_identity: u64,
    pub(crate) selected: Identity,
    pub(crate) changing: Option<Identity>,
    pub(crate) rooms: Vec<LiveRoom<'a>>,
    pub(crate) memberships: Vec<crate::recovery::Membership<'a>>,
    pub(crate) membership_cursor: usize,
    pub(crate) subscriptions: Vec<crate::subscriptions::SubscriptionIntent<'a>>,
    pub(crate) subscription_cursor: usize,
    pub(crate) subscription_scan_remaining: usize,
    pub(crate) restoring: bool,
    pub(crate) reconnect_delay: Duration,
    pub(crate) reconnect_not_before: Option<tokio::time::Instant>,
    pub(crate) leases: Vec<Lease<'a>>,
    pub(crate) control: Option<Control<'a>>,
    pub(crate) held_work: Vec<Work<'a>>,
    pub(crate) held_notification: Option<HeldNotification<'a>>,
    pub(crate) pending_loss: Option<Loss<'a>>,
    pub(crate) epoch: Option<native::Epoch<'a>>,
    pub(crate) ready: bool,
    pub(crate) running: bool,
    pub(crate) closed: bool,
    pub(crate) disconnecting: bool,
    pub(crate) fenced: bool,
    pub(crate) initial: Span,
    pub(crate) buffers: Vec<SensitiveBuffer<N>>,
    pub(crate) observations: Vec<domain::Event<'a>>,
    pub(crate) cleanup: Vec<(Room<'a>, domain::Error)>,
    pub(crate) retire_next: Option<Operation<'a>>,
    pub(crate) room_cursor: usize,
    pub(crate) decrypt_cursor: usize,
    pub(crate) decrypt_remaining: usize,
    pub(crate) next_job: u64,
    pub(crate) next_native: u64,
    pub(crate) reservations: usize,
    pub(crate) yield_due: bool,
    pub(crate) scan_remaining: usize,
    pub(crate) domain_blocked: bool,
    pub(crate) native_blocked: bool,
    pub(crate) record_blocked: bool,
}
impl<E: crypto::Entropy, const N: usize> fmt::Debug for Api<'_, E, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessengerApi([REDACTED])")
            .field("rooms", &self.rooms.len())
            .field("original_jobs", &self.leases.len())
            .field("ready", &self.ready)
            .finish_non_exhaustive()
    }
}
fn reserve<T>(count: usize) -> Result<Vec<T>, Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(count).map_err(|_| Fault::Capacity)?;
    Ok(out)
}
impl<'a, E: crypto::Entropy, const N: usize> Api<'a, E, N> {
    /// Own an explicitly supplied IDENTITY key and real entropy port. The key
    /// public component is actually derived in production; no private file is
    /// read, key generated or native connection opened by this constructor.
    /// The caller keeps the separate core instance alive for every returned
    /// room/job/loss capability. Its exclusive borrow cannot be reused while
    /// any original branded capability remains live.
    pub fn new(
        core_instance: &'a mut domain::Instance,
        instance: &'a native::Instance,
        endpoint: EndpointSource,
        identity: gnunet_identity::SecretKey,
        entropy: E,
        limits: Limits,
    ) -> Result<Self, Error> {
        let profiles = Profiles::same(limits.native.profile)?;
        Self::new_profiled(
            core_instance,
            instance,
            endpoint,
            identity,
            entropy,
            limits,
            profiles,
        )
    }
    /// Own actual native/client/crypto providers with independently explicit
    /// original-producer, plaintext, identifier and record layouts. Unknown
    /// layouts remain an original bounded notification need, never guessed.
    pub fn new_profiled(
        core_instance: &'a mut domain::Instance,
        instance: &'a native::Instance,
        endpoint: EndpointSource,
        identity: gnunet_identity::SecretKey,
        entropy: E,
        limits: Limits,
        profiles: Profiles,
    ) -> Result<Self, Error> {
        limits.validate::<N>()?;
        if Self::minimum_overhead(limits)?
            .checked_add(profiles.bytes()?)
            .ok_or(Fault::Overflow)?
            > limits.bytes
        {
            return Err(Fault::Capacity.into());
        }
        let baseline = endpoint.duplicate()?;
        let clock = DriverClock::new(endpoint.clock()).map_err(Error::Clock)?;
        let initial = Span::new(
            clock.sample().map_err(Error::Clock)?,
            limits.native.initial_lifetime,
        )?;
        let native = native::Client::new(instance, endpoint, limits.native)?;
        if !Arc::ptr_eq(&native.clock(), &clock.source) {
            return Err(Fault::Conflict.into());
        }
        let core = Core::new(
            core_instance,
            Mode::Client,
            limits.core,
            profiles.local_profile(),
        )?;
        let owner = OWNERS
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map(|n| n + 1)
            .map_err(|_| Fault::Overflow)?;
        let mut signers = reserve(limits.identities)?;
        let public = identity.public_key()?;
        signers.push(Signer {
            id: Identity {
                owner,
                generation: 1,
            },
            public,
            secret: identity,
        });
        let rooms = reserve(limits.core.rooms)?;
        let memberships = reserve(limits.operations)?;
        let leases = reserve(limits.operations)?;
        let count = limits
            .core
            .events
            .checked_add(limits.core.rooms.checked_mul(2).ok_or(Fault::Overflow)?)
            .ok_or(Fault::Overflow)?;
        if limits.core.events < limits.core.rooms.checked_mul(2).ok_or(Fault::Overflow)? {
            return Err(Fault::Capacity.into());
        }
        let observations = reserve(count)?;
        let cleanup = reserve(
            limits
                .core
                .rooms
                .checked_add(limits.operations)
                .ok_or(Fault::Overflow)?,
        )?;
        let held_work = reserve(limits.operations)?;
        let mut buffers = reserve(2)?;
        buffers.push(SensitiveBuffer::new());
        buffers.push(SensitiveBuffer::new());
        let mut api = Self {
            instance,
            baseline,
            native,
            records: None,
            record_turn: false,
            core,
            clock,
            limits,
            profiles,
            next_notification: 0,
            entropy,
            signers,
            owner,
            next_identity: 1,
            selected: Identity {
                owner,
                generation: 1,
            },
            changing: None,
            rooms,
            memberships,
            membership_cursor: 0,
            subscriptions: Vec::new(),
            subscription_cursor: 0,
            subscription_scan_remaining: 0,
            restoring: false,
            reconnect_delay: Duration::from_millis(100),
            reconnect_not_before: None,
            leases,
            control: None,
            held_work,
            held_notification: None,
            pending_loss: None,
            epoch: None,
            ready: false,
            running: true,
            closed: false,
            disconnecting: false,
            fenced: false,
            initial,
            buffers,
            observations,
            cleanup,
            retire_next: None,
            room_cursor: 0,
            decrypt_cursor: 0,
            decrypt_remaining: 0,
            next_job: 0,
            next_native: 0,
            reservations: 0,
            yield_due: false,
            scan_remaining: 0,
            domain_blocked: false,
            native_blocked: false,
            record_blocked: false,
        };
        if api.retained_overhead()? > api.limits.bytes {
            api.closed = true;
            return Err(Fault::Capacity.into());
        }
        Ok(api)
    }
    /// Official public anonymous identity, with an explicit real entropy port.
    /// This retains the same actual initialization/native bounds as new().
    pub fn anonymous(
        core_instance: &'a mut domain::Instance,
        instance: &'a native::Instance,
        endpoint: EndpointSource,
        entropy: E,
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::new(
            core_instance,
            instance,
            endpoint,
            gnunet_identity::SecretKey::anonymous(),
            entropy,
            limits,
        )
    }
    /// Original canonical source. Sharing it creates no clock listener or MQ.
    pub fn clock(&self) -> Arc<dyn gnunet_service_runtime::clock::RuntimeClock> {
        self.clock.source.clone()
    }
    /// Read-only actual state. Callers cannot forge native notifications, provider
    /// results, source attachments or crypto capabilities through this borrow.
    pub const fn state(&self) -> &Core<'a> {
        &self.core
    }
    /// Exact actually attached native epoch, including pre-CREATE attachment.
    pub const fn epoch(&self) -> Option<native::Epoch<'a>> {
        self.epoch
    }
    /// Actual local CREATE whole-write fact for the current original epoch.
    pub const fn ready(&self) -> bool {
        self.ready && !self.closed && !self.fenced && !self.disconnecting
    }
    /// Explicit real entropy owner, for original OS/provider error observation.
    pub const fn entropy(&self) -> &E {
        &self.entropy
    }
    /// First explicitly imported local signing identity.
    pub fn default_identity(&self) -> Result<Identity, Error> {
        self.signer(self.selected)?;
        Ok(self.selected)
    }
    /// Import an actual owned identity without replacing any active room's
    /// signer. A later real signed KEY transition must authorize each change.
    pub fn import_identity(
        &mut self,
        secret: gnunet_identity::SecretKey,
    ) -> Result<Identity, Error> {
        if self.signers.len() == self.limits.identities {
            return Err(Fault::Capacity.into());
        }
        let public = secret.public_key()?;
        if self.signers.iter().any(|s| s.public == public) {
            return Err(Fault::Conflict.into());
        }
        let generation = self.next_identity.checked_add(1).ok_or(Fault::Overflow)?;
        let id = Identity {
            owner: self.owner,
            generation,
        };
        self.signers.push(Signer { id, public, secret });
        self.next_identity = generation;
        Ok(id)
    }
    /// Borrow an imported identity's actual serialized public key.
    pub fn identity_public(&self, identity: Identity) -> Result<&PublicKey, Error> {
        Ok(&self.signers[self.signer(identity)?].public)
    }
    /// Erase a retired local signing owner only after every original live room,
    /// draft and record source stopped using it. History retains public session
    /// attribution and does not require the signing secret.
    pub fn retire_identity(&mut self, identity: Identity) -> Result<(), Error> {
        let index = self.signer(identity)?;
        let public = self.signers[index].public;
        if self.selected == identity
            || self.changing == Some(identity)
            || self.rooms.iter().any(|r| {
                (r.source.is_some() || self.memberships.iter().any(|m| m.room == r.room))
                    && (r.signer == identity || r.pending_identity == Some(identity))
            })
            || self
                .records
                .as_ref()
                .is_some_and(|r| r.uses_public(&public))
            || self
                .held_work
                .iter()
                .any(|w| matches!(w,Work::Sign{public:p,..} if p==&public))
        {
            return Err(Fault::NotReady.into());
        }
        for room in &self.rooms {
            for (binding, phase) in self.core.operations(room.room)? {
                if !matches!(
                    phase,
                    OperationPhase::Complete | OperationPhase::Failed | OperationPhase::Cancelled
                ) && binding
                    .member()
                    .is_some_and(|m| self.core.member_public(m).is_ok_and(|p| p == &public))
                {
                    return Err(Fault::NotReady.into());
                }
            }
        }
        self.signers.remove(index);
        Ok(())
    }
    pub(crate) fn signer(&self, id: Identity) -> Result<usize, Error> {
        if id.owner != self.owner {
            return Err(Fault::StaleGeneration.into());
        }
        self.signers
            .iter()
            .position(|s| s.id == id)
            .ok_or(Fault::StaleGeneration.into())
    }
    pub(crate) fn room_index(&self, room: Room<'a>) -> Result<usize, Error> {
        self.rooms
            .iter()
            .position(|r| r.room == room)
            .ok_or(Fault::StaleGeneration.into())
    }
    pub(crate) fn live_source(
        &self,
        room: Room<'a>,
    ) -> Result<(usize, Source<'a>, native::Epoch<'a>), Error> {
        if !self.ready() {
            return Err(Fault::NotReady.into());
        }
        let i = self.room_index(room)?;
        let r = &self.rooms[i];
        let source = r.source.ok_or(Fault::Closed)?;
        let epoch = r.epoch.ok_or(Fault::Closed)?;
        if Some(epoch) != self.epoch {
            return Err(Fault::StaleGeneration.into());
        }
        Ok((i, source, epoch))
    }
    pub(crate) fn sample(&mut self) -> Result<u64, Error> {
        match self.clock.sample() {
            Ok(now) => Ok(now),
            Err(error) => {
                self.capture_stop(StopCause::Clock(error), false, None);
                Err(Error::Clock(error))
            }
        }
    }
    /// Capture a finite immutable calling budget on this actual Api clock.
    /// The native target precedes the canonical read; waiting for capacity,
    /// recipient keys or epochs must reuse this exact returned value.
    pub fn deadline(&mut self, duration: Duration) -> Result<crate::Deadline, Error> {
        let hard = tokio::time::Instant::now()
            .checked_add(duration)
            .ok_or(Fault::Overflow)?;
        if !self.ready() || self.pending_loss.is_some() {
            return Err(Fault::NotReady.into());
        }
        let micros = u64::try_from(duration.as_micros()).map_err(|_| Fault::Overflow)?;
        if micros == 0 {
            return Err(Fault::InvalidInput.into());
        }
        let now = self.sample()?;
        let logical = now
            .checked_add(micros)
            .filter(|n| *n != u64::MAX)
            .ok_or(Fault::Overflow)?;
        let deadline = crate::Deadline {
            owner: self.owner,
            span: Span { logical, hard },
        };
        if deadline.expired(Some(now)) {
            return Err(Fault::Timeout.into());
        }
        Ok(deadline)
    }
    pub(crate) fn admission(&mut self, duration: Duration) -> Result<(u64, Span), Error> {
        let deadline = self.deadline(duration)?;
        self.admission_bounded(deadline)
    }
    pub(crate) fn admission_bounded(
        &mut self,
        deadline: crate::Deadline,
    ) -> Result<(u64, Span), Error> {
        if deadline.owner != self.owner {
            return Err(Fault::StaleGeneration.into());
        }
        if deadline.expired(None) {
            return Err(Fault::Timeout.into());
        }
        if !self.ready() || self.pending_loss.is_some() || self.domain_blocked {
            return Err(Fault::NotReady.into());
        }
        if self
            .leases
            .len()
            .checked_add(self.reservations)
            .ok_or(Fault::Overflow)?
            >= self.limits.operations
        {
            return Err(Fault::WouldBlock.into());
        }
        self.next_job.checked_add(1).ok_or(Fault::Overflow)?;
        let now = self.sample()?;
        if deadline.expired(Some(now)) {
            return Err(Fault::Timeout.into());
        }
        Ok((now, deadline.span))
    }
    pub(crate) fn record_job(
        &mut self,
        room: Room<'a>,
        source: Source<'a>,
        epoch: native::Epoch<'a>,
        operation: Operation<'a>,
        span: Span,
        intent: Intent,
    ) -> Result<(), Error> {
        if self.leases.iter().any(|l| l.operation == operation) {
            return Err(Fault::Replay.into());
        }
        if self.leases.len() == self.limits.operations {
            return Err(Fault::Capacity.into());
        }
        let serial = self.next_job.checked_add(1).ok_or(Fault::Overflow)?;
        self.leases.push(Lease {
            layout: None,
            operation,
            room,
            source,
            epoch,
            span,
            binding: None,
            native: None,
            native_serial: None,
            kind: None,
            queued: false,
            exposure: Exposure::NotSubmitted,
            intent,
            frame_len: 0,
            serial,
        });
        self.next_job = serial;
        self.wake_domain();
        Ok(())
    }
    /// Retire one consumed terminal original result. Native whole-writing alone
    /// does not make a SEND terminal: its actual echoed message is still needed.
    pub fn retire(&mut self, operation: Operation<'a>) -> Result<(), Error> {
        self.observe_memberships();
        self.observe_subscriptions(None)
            .map_err(|(_, error)| Error::Domain(error))?;
        let i = self
            .leases
            .iter()
            .position(|l| l.operation == operation)
            .ok_or(Fault::StaleGeneration)?;
        if self.rooms.iter().any(|r| {
            r.source.is_some()
                && (r.close_after == Some(operation)
                    || r.close_child == Some(operation)
                    || r.identity_operation == Some(operation))
        }) {
            return Err(Fault::NotReady.into());
        }
        self.core.retire_operation(operation)?;
        self.leases.remove(i);
        self.wake_domain();
        Ok(())
    }
    /// Restore retained logical room memberships on a new physical source.
    /// Every old frame/job remains retired; only fresh OPEN/ENTRY work is made
    /// after actual CREATE writing, under original pending or new effect bounds.
    pub fn reconnect(&mut self) -> Result<(), Error> {
        if self.closed
            || self.fenced
            || self.running
            || self.epoch.is_some()
            || self.pending_loss.is_some()
        {
            return Err(Fault::NotReady.into());
        }
        self.retire_stopped_operations()?;
        self.leases
            .try_reserve_exact(self.limits.operations)
            .map_err(|_| Fault::Capacity)?;
        let count = self
            .limits
            .core
            .events
            .checked_add(
                self.limits
                    .core
                    .rooms
                    .checked_mul(2)
                    .ok_or(Fault::Overflow)?,
            )
            .ok_or(Fault::Overflow)?;
        self.observations
            .try_reserve_exact(count)
            .map_err(|_| Fault::Capacity)?;
        self.cleanup
            .try_reserve_exact(
                self.limits
                    .core
                    .rooms
                    .checked_add(self.limits.operations)
                    .ok_or(Fault::Overflow)?,
            )
            .map_err(|_| Fault::Capacity)?;
        let initial = Span::new(
            self.clock.sample().map_err(Error::Clock)?,
            self.limits.native.initial_lifetime,
        )?;
        let native = native::Client::new(
            self.instance,
            self.baseline.duplicate()?,
            self.limits.native,
        )?;
        if !Arc::ptr_eq(&native.clock(), &self.clock.source) {
            return Err(Fault::Conflict.into());
        }
        self.native = native;
        self.initial = initial;
        self.ready = false;
        self.running = true;
        self.control = None;
        self.held_work.clear();
        self.held_notification = None;
        self.yield_due = false;
        self.scan_remaining = 0;
        self.domain_blocked = false;
        self.native_blocked = false;
        self.record_blocked = false;
        self.restoring = true;
        let delay = self
            .reconnect_delay
            .min(self.limits.native.initial_lifetime / 2);
        self.reconnect_not_before = Some(
            tokio::time::Instant::now()
                .checked_add(delay)
                .ok_or(Fault::Overflow)?,
        );
        self.reconnect_delay = self
            .reconnect_delay
            .saturating_mul(2)
            .min(Duration::from_secs(5));
        if self.records.is_some() {
            self.reconnect_records()?;
        }
        Ok(())
    }
    /// Prepare the actual official DESTROY after all room jobs settled. Only a
    /// whole local DESTROY write permits physical close; Loss::control retains
    /// that write fact. No service ACK or remote receipt is manufactured.
    pub fn disconnect(&mut self, timeout: Duration) -> Result<native::Operation<'a>, Error> {
        let deadline = self.deadline(timeout)?;
        self.disconnect_bounded(deadline)
    }
    /// Submit original DESTROY under the caller's unchanged finite close budget.
    pub fn disconnect_bounded(
        &mut self,
        deadline: crate::Deadline,
    ) -> Result<native::Operation<'a>, Error> {
        let (_, span) = self.admission_bounded(deadline)?;
        if self.control.is_some()
            || !self.held_work.is_empty()
            || self.rooms.iter().any(|r| {
                r.join.is_some() || r.pending_identity.is_some() || r.close_after.is_some()
            })
            || self.leases.iter().any(|l| {
                self.core.operation_phase(l.operation).is_ok_and(|p| {
                    !matches!(
                        p,
                        OperationPhase::Complete
                            | OperationPhase::Failed
                            | OperationPhase::Cancelled
                    )
                })
            })
        {
            return Err(Fault::WouldBlock.into());
        }
        let epoch = self.epoch.ok_or(Fault::NotReady)?;
        let operation =
            self.native
                .submit_bounded(wire::Request::Destroy, span.logical, span.hard)?;
        self.control = Some(Control {
            operation,
            epoch,
            span,
            kind: native::Kind::Destroy,
            queued: false,
            exposure: Exposure::Unsent,
        });
        self.disconnecting = true;
        self.memberships.clear();
        self.subscriptions.clear();
        self.restoring = false;
        Ok(operation)
    }
    /// Actually stop the physical MQ without sampling the canonical clock.
    /// Original native causes and partial prefixes remain visible independently.
    pub fn cancel(&mut self, operation: Operation<'a>) -> Result<Loss<'a>, Error> {
        if let Some(loss) = self.pending_loss.as_ref() {
            if !loss.jobs().any(|job| job.operation() == operation) {
                return Err(Fault::StaleGeneration.into());
            }
            self.memberships.clear();
            self.subscriptions.clear();
            self.restoring = false;
            return Ok(self.pending_loss.take().ok_or(Fault::Conflict)?);
        }
        if !self.leases.iter().any(|l| l.operation == operation) {
            return Err(Fault::StaleGeneration.into());
        }
        self.memberships.clear();
        self.subscriptions.clear();
        self.restoring = false;
        Ok(self.stop(StopCause::Cancelled(operation), true, None))
    }
    /// Permanent physical close needs no canonical time, timer or crypto port.
    /// A pending first loss is returned intact instead of a new Closed cause.
    pub fn close(&mut self) -> Loss<'a> {
        self.closed = true;
        self.memberships.clear();
        self.subscriptions.clear();
        self.restoring = false;
        if let Some(loss) = self.pending_loss.take() {
            self.native.close();
            return loss;
        }
        self.stop(StopCause::Closed, false, None)
    }
    pub(crate) fn wake_domain(&mut self) {
        self.scan_remaining = self.rooms.len();
        self.subscription_scan_remaining = self.subscriptions.len();
        self.domain_blocked = false;
    }
    fn minimum_overhead(limits: Limits) -> Result<usize, Error> {
        let observations = limits
            .core
            .events
            .checked_add(limits.core.rooms.checked_mul(2).ok_or(Fault::Overflow)?)
            .ok_or(Fault::Overflow)?;
        let cleanup = limits
            .core
            .rooms
            .checked_add(limits.operations)
            .ok_or(Fault::Overflow)?;
        let mut bytes = limits
            .native
            .frame_bytes
            .checked_add(N)
            .ok_or(Fault::Overflow)?;
        for (count, width) in [
            (limits.core.rooms, core::mem::size_of::<LiveRoom<'a>>()),
            (limits.operations, core::mem::size_of::<Lease<'a>>()),
            (
                limits.operations,
                core::mem::size_of::<crate::recovery::Membership<'a>>(),
            ),
            (limits.identities, core::mem::size_of::<Signer>()),
            (limits.operations, core::mem::size_of::<Work<'a>>()),
            (2, core::mem::size_of::<SensitiveBuffer<N>>()),
            (observations, core::mem::size_of::<domain::Event<'a>>()),
            (cleanup, core::mem::size_of::<(Room<'a>, domain::Error)>()),
        ] {
            bytes = bytes
                .checked_add(count.checked_mul(width).ok_or(Fault::Overflow)?)
                .ok_or(Fault::Overflow)?;
        }
        Ok(bytes)
    }
    /// Actual bounded overhead capacities, outside the independently bounded
    /// native/core allocations. Pending domain work remains charged by Core.
    pub fn retained_overhead(&self) -> Result<usize, Error> {
        let mut bytes = self
            .limits
            .native
            .frame_bytes
            .checked_add(N)
            .and_then(|n| self.profiles.bytes().ok().and_then(|p| n.checked_add(p)))
            .ok_or(Fault::Overflow)?;
        for (capacity, width) in [
            (self.rooms.capacity(), core::mem::size_of::<LiveRoom<'a>>()),
            (
                self.subscriptions.capacity(),
                core::mem::size_of::<crate::subscriptions::SubscriptionIntent<'a>>(),
            ),
            (self.leases.capacity(), core::mem::size_of::<Lease<'a>>()),
            (
                self.memberships.capacity(),
                core::mem::size_of::<crate::recovery::Membership<'a>>(),
            ),
            (self.signers.capacity(), core::mem::size_of::<Signer>()),
            (self.held_work.capacity(), core::mem::size_of::<Work<'a>>()),
            (
                self.buffers.capacity(),
                core::mem::size_of::<SensitiveBuffer<N>>(),
            ),
            (
                self.observations.capacity(),
                core::mem::size_of::<domain::Event<'a>>(),
            ),
            (
                self.cleanup.capacity(),
                core::mem::size_of::<(Room<'a>, domain::Error)>(),
            ),
        ] {
            bytes = bytes
                .checked_add(capacity.checked_mul(width).ok_or(Fault::Overflow)?)
                .ok_or(Fault::Overflow)?;
        }
        Ok(bytes)
    }
    pub(crate) fn capture_stop(
        &mut self,
        cause: StopCause<'a>,
        cancelled: bool,
        original: Option<native::Loss<'a>>,
    ) {
        if self.pending_loss.is_none() {
            let loss = self.stop(cause, cancelled, original);
            self.pending_loss = Some(loss);
        } else {
            self.native.close();
        }
    }
    pub(crate) fn stop(
        &mut self,
        cause: StopCause<'a>,
        cancelled: bool,
        original: Option<native::Loss<'a>>,
    ) -> Loss<'a> {
        // Physical stop is first and never depends on a usable canonical clock.
        let original = original.unwrap_or_else(|| self.native.close());
        let subscription_deadline = self.retry_subscription_deadline(cause);
        self.observe_memberships();
        if let Err((room, error)) = self.observe_subscriptions(None) {
            self.cleanup.push((room, error));
            self.fenced = true;
        }
        self.retire_subscription_attempts();
        for membership in &mut self.memberships {
            membership.operation = None;
            membership.restored = false;
        }
        self.reconnect_not_before = None;
        let records = self.records.as_mut().map(crate::records::Records::close);
        self.ready = false;
        self.running = false;
        self.epoch = None;
        let control = self.control.take().map(|c| ControlReport {
            operation: c.operation,
            epoch: c.epoch,
            kind: c.kind,
            exposure: c.exposure,
        });
        self.disconnecting = false;
        self.clock.clear_alarms();
        self.held_work.clear();
        let layout = self.held_notification.take().and_then(|held| held.need);
        self.reservations = 0;
        self.scan_remaining = 0;
        self.domain_blocked = false;
        self.native_blocked = false;
        self.record_blocked = false;
        self.changing = None;
        self.retire_next = None;
        while let Some(event) = self.core.pop_event() {
            self.observations.push(event);
        }
        for report in &original.reports {
            if let Some(l) = self
                .leases
                .iter_mut()
                .find(|l| l.native == Some(report.operation))
            {
                let exposure = match report.submission {
                    native::Submission::Unsent => Exposure::Unsent,
                    native::Submission::Partial { bytes, total } => {
                        Exposure::Partial { bytes, total }
                    }
                };
                if l.exposure != exposure
                    && !matches!(l.exposure, Exposure::NotSubmitted | Exposure::Unsent)
                {
                    self.cleanup
                        .push((l.room, domain::Error::Protocol(Fault::Conflict)));
                    self.fenced = true;
                } else {
                    l.exposure = exposure;
                }
            }
        }
        // The already-reserved report can hold the queued events plus each
        // room's stop events. Drain before/after each real source retirement so
        // a full ordinary event queue cannot prevent clock-free cleanup.
        while let Some(event) = self.core.pop_event() {
            self.observations.push(event);
        }
        for room in &mut self.rooms {
            if let Some(source) = room.source.take() {
                let result = if cancelled {
                    self.core.source_cancelled(source)
                } else {
                    self.core.source_stopped(source)
                };
                if let Err(error) = result {
                    self.cleanup.push((room.room, error));
                    self.fenced = true;
                }
            }
            room.epoch = None;
            room.join = None;
            room.close_after = None;
            room.close_child = None;
            room.closing_span = None;
            room.member = None;
            room.pending_identity = None;
            room.identity_operation = None;
            room.replacement_key = None;
            while let Some(event) = self.core.pop_event() {
                self.observations.push(event);
            }
        }
        while let Some(event) = self.core.pop_event() {
            self.observations.push(event);
        }
        Loss {
            layout,
            control,
            records,
            original,
            cause,
            subscription_deadline,
            jobs: core::mem::take(&mut self.leases),
            observations: core::mem::take(&mut self.observations),
            cleanup: core::mem::take(&mut self.cleanup),
            failure: None,
        }
    }
}
impl<E: crypto::Entropy, const N: usize> Drop for Api<'_, E, N> {
    fn drop(&mut self) {
        self.native.close();
        if let Some(r) = self.records.as_mut() {
            r.close();
        }
        self.held_work.clear();
        self.held_notification = None;
    }
}
