//! Caller-bounded ARM server transition candidate for official v0.29.1.
//!
//! Real processes/listeners belong to an external host. A returned spawn effect
//! is a request, never evidence of native admission or application readiness.
//! This initial candidate is not a full ARM server, configuration or CLI claim.
#![no_std]
#![forbid(unsafe_code)]

use gnunet_arm_core::wire::{ArmAbi, ResultCode, ServiceStatus, WireId};

/// Explicit resource, authority or sequencing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Caller storage cannot represent this operation atomically.
    Capacity,
    /// An operation is awaiting its actual native acknowledgment.
    Busy,
    /// Token is stale in this original owner.
    Stale,
    /// A generation or global envelope sequence cannot advance.
    Exhausted,
    /// Configuration bytes or selected request are malformed.
    Malformed,
    /// The owner already reached shutdown.
    Closed,
}
/// Caller-owned nonzero-sized identity for one safe owner construction.
/// Constructor borrows it mutably, then tokens retain a shared reference. A live
/// token therefore prevents resetting the same scope with a new owner in safe Rust.
#[derive(Debug)]
pub struct OwnerScope {
    _identity: u8,
}
impl Default for OwnerScope {
    fn default() -> Self {
        Self::new()
    }
}
impl OwnerScope {
    /// Fresh caller storage; no atomic/global identity or entropy is required.
    pub const fn new() -> Self {
        Self { _identity: 1 }
    }
}
#[derive(Clone, Copy, Debug)]
struct Scope<'a>(&'a OwnerScope);
impl PartialEq for Scope<'_> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.0, other.0)
    }
}
impl Eq for Scope<'_> {}
impl core::hash::Hash for Scope<'_> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        core::ptr::hash(self.0, state);
    }
}
/// Opaque identity of one original caller-owned scope, including an empty or
/// fully retired registry. Equality and hashing use reference identity. This
/// value retains the scope borrow and grants no client/native-effect authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct OwnerId<'scope>(Scope<'scope>);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClientKey {
    slot: usize,
    generation: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ChildKey {
    service: usize,
    generation: u64,
}
/// Connection identity; scope equality uses reference identity, never scope contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ClientId<'scope> {
    scope: Scope<'scope>,
    slot: usize,
    generation: u64,
}
impl ClientId<'_> {
    fn key(self) -> ClientKey {
        ClientKey {
            slot: self.slot,
            generation: self.generation,
        }
    }
}
/// Stable service index bound to the original caller scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ServiceId<'scope>(usize, Scope<'scope>);
/// A particular actual child lifetime, bound to its original owner scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ChildId<'scope> {
    scope: Scope<'scope>,
    service: usize,
    generation: u64,
}
impl ChildId<'_> {
    fn key(self) -> ChildKey {
        ChildKey {
            service: self.service,
            generation: self.generation,
        }
    }
}
/// Leased immutable output identity; reused backing cannot revive this capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct FrameTicket<'scope> {
    scope: Scope<'scope>,
    slot: usize,
    generation: u64,
}
/// One native attempt's lease; its epoch is distinct from child lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct NativeTicket<'scope> {
    scope: Scope<'scope>,
    service: usize,
    generation: u64,
    action: Action,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
enum Action {
    Spawn,
    Term,
    ShutdownTerm,
}
/// Immutable host-prepared service definition; provided in registry order.
#[derive(Clone, Copy, Debug)]
pub struct ServiceSpec<'a> {
    /// Original configured C-string byte spelling (no embedded NUL; empty is valid).
    pub name: &'a [u8],
    /// Configured BINARY bytes, as encoded in LIST.
    pub binary: &'a [u8],
    /// Already source-prepared command plan; native host interpretation remains explicit.
    pub command: &'a [u8],
    /// Initial IMMEDIATE_START decision from real configuration.
    pub immediate: bool,
    /// PIPECONTROL decision from real configuration.
    pub pipe_control: bool,
}
/// Native process request; no OS effect has happened yet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeEffect<'a, 'scope> {
    /// Disarm managed listener readiness before native fork-admission attempt.
    Spawn {
        /// Native operation epoch, distinct from the child's lifetime generation.
        ticket: NativeTicket<'scope>,
        /// Host key for the actual native child capability it creates.
        child: ChildId<'scope>,
        /// Immutable source registry entry.
        service: ServiceId<'scope>,
        /// Source-prepared opaque command recipe, not shell syntax.
        command: &'a [u8],
        /// Actual native signal pipe policy.
        pipe_control: bool,
    },
    /// Try one-byte signal pipe then TERM fallback according to native profile.
    Term {
        /// This signal attempt's epoch; old attempts cannot acknowledge a later one.
        ticket: NativeTicket<'scope>,
        /// Actual child owner that remains live until a wait result is reported.
        child: ChildId<'scope>,
    },
}
/// Actual native outcome, distinct from an unexecuted effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpawnOutcome {
    /// A real owned child was created at C's fork-admission boundary.
    Admitted,
    /// Precheck/descriptor/fork operation actually failed; no native child remains.
    Failed,
}
/// Actual child termination reported only after an owned-child wait succeeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Exit {
    /// Process exited with this code.
    Exited(u32),
    /// Process terminated due to this signal.
    Signaled(u32),
}
/// Native readiness ownership state, independent from a socket's binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ListenerAction {
    /// Create one read-readiness registration; never accept a queued connection.
    Arm,
    /// Cancel one existing read-readiness registration before child spawn.
    Disarm,
    /// Consume the parent-owned listener/socket guard during shutdown.
    Close,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ListenerState {
    Disarmed,
    Armed,
    Closed,
}
/// Caller-owned metadata for an actual bound parent listener.
#[derive(Debug)]
pub struct ListenerSlot {
    generation: u64,
    service: Option<usize>,
    epoch: u64,
    actual: ListenerState,
    desired: ListenerState,
    leased: Option<ListenerAction>,
    close_taken: bool,
    armed_epoch: u64,
}
impl Default for ListenerSlot {
    fn default() -> Self {
        Self::new()
    }
}
impl ListenerSlot {
    /// Empty storage. Register only after the host owns a real bound listener.
    pub const fn new() -> Self {
        Self {
            generation: 0,
            service: None,
            epoch: 0,
            actual: ListenerState::Closed,
            desired: ListenerState::Closed,
            leased: None,
            close_taken: false,
            armed_epoch: 0,
        }
    }
}
/// Original bound-listener lifetime, scoped and generation checked.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ListenerId<'scope> {
    scope: Scope<'scope>,
    slot: usize,
    generation: u64,
}
/// One listener operation lease, retained across host-future cancellation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ListenerTicket<'scope> {
    scope: Scope<'scope>,
    slot: usize,
    generation: u64,
    epoch: u64,
    action: ListenerAction,
}
/// A particular armed one-shot read registration, not just a socket identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ReadinessId<'scope> {
    scope: Scope<'scope>,
    slot: usize,
    generation: u64,
    epoch: u64,
}
/// Actual host listener operation request; taking it is not applying it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenerEffect<'scope> {
    /// Original bound listener.
    pub listener: ListenerId<'scope>,
    /// Immutable source registry entry.
    pub service: ServiceId<'scope>,
    /// Checked completion lease.
    pub ticket: ListenerTicket<'scope>,
    /// Native action requested.
    pub action: ListenerAction,
}
/// An actual registered global restart task, bound to this owner scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct TimerId<'scope> {
    scope: Scope<'scope>,
    epoch: u64,
}
/// Scheduler request; the source uses one global IDLE-priority task.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TimerAction {
    /// Register a wake hint and re-evaluate source UTC in the callback.
    Arm {
        /// Official absolute restart time, not an invented monotonic field.
        at_utc: u64,
    },
    /// Consume/cancel the previously registered task capability.
    Cancel,
}
/// A retained scheduler lease; cancellation uses its existing task identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct TimerTicket<'scope> {
    id: TimerId<'scope>,
    action: TimerAction,
}
/// A real scheduler effect request; no scheduling occurs merely by taking it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerEffect<'scope> {
    /// Task registration identity.
    pub id: TimerId<'scope>,
    /// Exact completion authority.
    pub ticket: TimerTicket<'scope>,
    /// Scheduler action requested.
    pub action: TimerAction,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TimerRegistration {
    epoch: u64,
    at_utc: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TimerPending {
    Arm(TimerRegistration),
    Cancel(TimerRegistration),
}
/// Public construction/lifecycle phase; no client admission before initial starts finish.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Register actual bound listeners/configuration before source startup.
    Configuring,
    /// Initial forced spawn attempts have not all completed.
    Starting,
    /// Official control/request and demand callbacks may run.
    Serving,
    /// Manual shutdown retains real native cleanup authority.
    Draining,
    /// Host explicitly completed the final generic runtime shutdown.
    Closed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Process {
    None,
    Starting(ChildKey),
    Running(ChildKey),
    Term(ChildKey),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Request {
    client: ClientKey,
    id: WireId,
    reserved: usize,
    frame_generation: u64,
}
/// Caller service metadata, initialized with [`ServiceSlot::new`].
#[derive(Debug)]
pub struct ServiceSlot {
    generation: u64,
    process: Process,
    force: bool,
    last_started: u64,
    restart_at: u64,
    killed_at: u64,
    backoff: u64,
    last_exit: u32,
    start_request: Option<Request>,
    stop_request: Option<Request>,
    native_leased: bool,
    native_epoch: u64,
    shutdown_term_taken: bool,
    registered: bool,
}
impl Default for ServiceSlot {
    fn default() -> Self {
        Self::new()
    }
}
impl ServiceSlot {
    /// Empty storage; owner resets it on successful complete construction.
    pub const fn new() -> Self {
        Self {
            generation: 0,
            process: Process::None,
            force: false,
            last_started: 0,
            restart_at: u64::MAX,
            killed_at: 0,
            backoff: 1000,
            last_exit: 0,
            start_request: None,
            stop_request: None,
            native_leased: false,
            native_epoch: 0,
            shutdown_term_taken: false,
            registered: true,
        }
    }
}
/// Caller client metadata; identities are generation checked.
#[derive(Debug)]
pub struct ClientSlot {
    generation: u64,
    connected: bool,
    monitor_order: u64,
    mq_length: usize,
    resource_close: bool,
    persist: bool,
}
impl Default for ClientSlot {
    fn default() -> Self {
        Self::new()
    }
}
impl ClientSlot {
    /// Empty client metadata.
    pub const fn new() -> Self {
        Self {
            generation: 0,
            connected: false,
            monitor_order: 0,
            mq_length: 0,
            resource_close: false,
            persist: false,
        }
    }
}
/// Exclusive caller byte buffer for one required or optional envelope.
#[derive(Debug)]
pub struct FrameSlot<'a> {
    buffer: &'a mut [u8],
    len: usize,
    client: Option<ClientKey>,
    reserved: bool,
    sequence: u64,
    generation: u64,
    leased: bool,
}
impl<'a> FrameSlot<'a> {
    /// Caller slices remain exclusively borrowed throughout the owner lifetime.
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            buffer,
            len: 0,
            client: None,
            reserved: false,
            sequence: 0,
            generation: 0,
            leased: false,
        }
    }
}
/// Borrowed frame view; copy to persistent host TX before releasing its ticket.
/// A view cannot escape an owner mutation.
///
/// ```compile_fail,E0499
/// use gnunet_arm_service_core::Owner;
/// fn invalid(owner: &mut Owner<'_, '_, '_, '_>) {
///     if let Some(frame) = owner.frame() {
///         owner.begin_shutdown(0);
///         core::hint::black_box(frame.bytes);
///     }
/// }
/// ```
///
/// Copying while borrowed and releasing the view before mutation is supported.
///
/// ```
/// use gnunet_arm_service_core::Owner;
/// fn valid(owner: &mut Owner<'_, '_, '_, '_>) {
///     let mut copy = [0; 64];
///     if let Some(frame) = owner.frame() {
///         let n = frame.bytes.len().min(copy.len());
///         copy[..n].copy_from_slice(&frame.bytes[..n]);
///         let ticket = frame.ticket;
///         let _result = owner.release_frame(ticket);
///         owner.begin_shutdown(0);
///     }
///     core::hint::black_box(copy);
/// }
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Frame<'a, 'scope> {
    /// Exact generation identity used on release.
    pub ticket: FrameTicket<'scope>,
    /// Original recipient; a recycled slot has a different identity.
    pub client: ClientId<'scope>,
    /// Official complete frame bytes.
    pub bytes: &'a [u8],
}
/// Final generic runtime shutdown lease, independent from output/operation limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShutdownTicket<'scope> {
    scope: Scope<'scope>,
}
/// Actual child-exit report, including visible resource degradation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub struct ReapReport {
    /// Number of monitor clients explicitly requiring resource closure.
    pub resource_closures: usize,
}
/// Caller-owned, allocation-free source transition owner.
#[derive(Debug)]
pub struct Owner<'scope, 'spec, 'slots, 'bytes> {
    scope: Scope<'scope>,
    specs: &'spec [ServiceSpec<'spec>],
    services: &'slots mut [ServiceSlot],
    listeners: &'slots mut [ListenerSlot],
    phase: Phase,
    startup_cursor: usize,
    clients: &'slots mut [ClientSlot],
    frames: &'slots mut [FrameSlot<'bytes>],
    abi: ArmAbi,
    sequence: u64,
    monitor_order: u64,
    shutdown: bool,
    restart_scan: bool,
    restart_wake: Option<u64>,
    timer_epoch: u64,
    timer_actual: Option<TimerRegistration>,
    timer_pending: Option<TimerPending>,
    timer_cancel_requested: bool,
    scan_cursor: usize,
    scan_lowest: u64,
    scan_active: bool,
    shutdown_requested: bool,
    shutdown_lease: bool,
}
impl<'scope, 'spec, 'slots, 'bytes> Owner<'scope, 'spec, 'slots, 'bytes> {
    /// Preflight complete registry and all caller storage before changing metadata.
    /// Registry order is passed explicitly after host configuration iteration/head insertion.
    pub fn new(
        scope: &'scope mut OwnerScope,
        specs: &'spec [ServiceSpec<'spec>],
        services: &'slots mut [ServiceSlot],
        clients: &'slots mut [ClientSlot],
        listeners: &'slots mut [ListenerSlot],
        frames: &'slots mut [FrameSlot<'bytes>],
        abi: ArmAbi,
    ) -> Result<Self, Error> {
        if specs.len() != services.len() {
            return Err(Error::Capacity);
        }
        let mut total = abi.list_bytes();
        for (i, spec) in specs.iter().enumerate() {
            if spec.name.contains(&0)
                || spec.binary.contains(&0)
                || spec.name.eq_ignore_ascii_case(b"arm")
                || specs[..i]
                    .iter()
                    .any(|old| old.name.eq_ignore_ascii_case(spec.name))
            {
                return Err(Error::Malformed);
            }
            total = total
                .checked_add(28)
                .and_then(|v| v.checked_add(spec.name.len()))
                .and_then(|v| v.checked_add(spec.binary.len()))
                .and_then(|v| v.checked_add(2))
                .ok_or(Error::Capacity)?;
        }
        if total > u16::MAX as usize {
            return Err(Error::Capacity);
        }
        for (state, spec) in services.iter_mut().zip(specs) {
            *state = ServiceSlot::new();
            state.force = spec.immediate;
        }
        for listener in listeners.iter_mut() {
            *listener = ListenerSlot::new();
        }
        for slot in clients.iter_mut() {
            *slot = ClientSlot::new();
        }
        for slot in frames.iter_mut() {
            slot.len = 0;
            slot.client = None;
            slot.reserved = false;
            slot.sequence = 0;
            slot.generation = 0;
            slot.leased = false;
        }
        Ok(Self {
            scope: Scope(scope),
            specs,
            services,
            listeners,
            phase: Phase::Configuring,
            startup_cursor: 0,
            clients,
            frames,
            abi,
            sequence: 0,
            monitor_order: 0,
            shutdown: false,
            restart_scan: false,
            restart_wake: None,
            timer_epoch: 0,
            timer_actual: None,
            timer_pending: None,
            timer_cancel_requested: false,
            scan_cursor: 0,
            scan_lowest: u64::MAX,
            scan_active: false,
            shutdown_requested: false,
            shutdown_lease: false,
        })
    }
    fn client_raw(&self, id: ClientId) -> Result<&ClientSlot, Error> {
        if id.scope != self.scope {
            return Err(Error::Stale);
        }
        self.clients
            .get(id.slot)
            .filter(|s| s.connected && s.generation == id.generation)
            .ok_or(Error::Stale)
    }
    fn client(&self, id: ClientId) -> Result<&ClientSlot, Error> {
        self.client_raw(id).and_then(|s| {
            if s.resource_close {
                Err(Error::Closed)
            } else {
                Ok(s)
            }
        })
    }
    fn revoke_key(&mut self, key: ClientKey) {
        for service in self.services.iter_mut() {
            if service.stop_request.is_some_and(|r| r.client == key) {
                service.stop_request = None;
            }
            if service.start_request.is_some_and(|r| r.client == key) {
                service.start_request = None;
            }
        }
        for i in 0..self.frames.len() {
            if self.frames[i].client == Some(key) {
                self.release_slot(i);
            }
        }
    }
    fn resource_close(&mut self, key: ClientKey) -> usize {
        let Some(slot) = self.clients.get_mut(key.slot) else {
            return 0;
        };
        if !slot.connected || slot.generation != key.generation || slot.resource_close {
            return 0;
        }
        slot.resource_close = true;
        slot.monitor_order = 0;
        self.revoke_key(key);
        1
    }
    fn publish_request(&mut self, request: Request, code: ResultCode) -> usize {
        let valid = self.frames.get(request.reserved).is_some_and(|frame| {
            frame.client == Some(request.client)
                && frame.reserved
                && frame.generation == request.frame_generation
        });
        if !valid {
            return 0;
        }
        if self.result_at(request.reserved, request.id, code).is_err() {
            self.resource_close(request.client)
        } else {
            0
        }
    }
    fn free_frame(&self, size: usize) -> Result<usize, Error> {
        self.frames
            .iter()
            .position(|s| s.client.is_none() && s.buffer.len() >= size && s.generation < u64::MAX)
            .ok_or(Error::Capacity)
    }
    fn reserve(&mut self, client: ClientId, size: usize) -> Result<usize, Error> {
        self.client(client)?;
        let slot = self.free_frame(size)?;
        self.sequence.checked_add(1).ok_or(Error::Exhausted)?;
        let s = &mut self.frames[slot];
        s.client = Some(client.key());
        s.reserved = true;
        s.generation += 1;
        s.len = 0;
        Ok(slot)
    }
    fn release_slot(&mut self, slot: usize) {
        let s = &mut self.frames[slot];
        s.buffer[..s.len].fill(0);
        s.len = 0;
        s.client = None;
        s.reserved = false;
        s.leased = false;
    }
    fn publish(&mut self, slot: usize, len: usize) -> Result<(), Error> {
        let next = self.sequence.checked_add(1).ok_or(Error::Exhausted)?;
        let s = &mut self.frames[slot];
        s.len = len;
        s.reserved = false;
        s.sequence = next;
        self.sequence = next;
        Ok(())
    }
    fn result_at(&mut self, slot: usize, id: WireId, code: ResultCode) -> Result<(), Error> {
        let n = gnunet_arm_core::wire::ResultReply {
            reserved: 0,
            id,
            result: code,
        }
        .encode(self.abi, self.frames[slot].buffer)
        .map_err(|_| Error::Capacity)?;
        self.publish(slot, n)
    }
    fn reply(&mut self, client: ClientId, id: WireId, code: ResultCode) -> Result<(), Error> {
        let slot = self.reserve(client, self.abi.result_bytes())?;
        self.result_at(slot, id, code)
    }
    fn check_idle_native(&self) -> Result<(), Error> {
        if self
            .services
            .iter()
            .any(|s| matches!(s.process, Process::Starting(_) | Process::Term(_)))
        {
            Err(Error::Busy)
        } else {
            Ok(())
        }
    }
    fn find(&self, name: &[u8]) -> Option<usize> {
        self.specs
            .iter()
            .zip(self.services.iter())
            .position(|(spec, state)| state.registered && spec.name.eq_ignore_ascii_case(name))
    }
    /// Allocate a new connection generation without callbacks. Manual shutdown
    /// keeps ARM control admission alive through Draining; final runtime cleanup
    /// closes it. Initial startup still refuses admission.
    pub fn connect(&mut self) -> Result<ClientId<'scope>, Error> {
        if !matches!(self.phase, Phase::Serving | Phase::Draining) {
            return Err(if self.phase == Phase::Closed {
                Error::Closed
            } else {
                Error::Busy
            });
        }
        let (slot, state) = self
            .clients
            .iter_mut()
            .enumerate()
            .find(|(_, s)| !s.connected && s.generation < u64::MAX)
            .ok_or(Error::Capacity)?;
        state.generation += 1;
        state.connected = true;
        state.monitor_order = 0;
        state.resource_close = false;
        state.persist = false;
        state.mq_length = 0;
        Ok(ClientId {
            scope: self.scope,
            slot,
            generation: state.generation,
        })
    }
    /// Revoke old requester, subscription and all queued/reserved output immediately.
    pub fn disconnect(&mut self, id: ClientId) -> Result<(), Error> {
        self.client_raw(id)?;
        self.clients[id.slot].connected = false;
        self.clients[id.slot].monitor_order = 0;
        for service in self.services.iter_mut() {
            if service.stop_request.is_some_and(|r| r.client == id.key()) {
                service.stop_request = None;
            }
            if service.start_request.is_some_and(|r| r.client == id.key()) {
                service.start_request = None;
            }
        }
        for i in 0..self.frames.len() {
            if self.frames[i].client == Some(id.key()) {
                self.release_slot(i);
            }
        }
        Ok(())
    }
    /// Host supplies actual current logical MQ length; no kernel-ACK inference.
    pub fn set_mq_length(&mut self, id: ClientId, value: usize) -> Result<(), Error> {
        self.client(id)?;
        self.clients[id.slot].mq_length = value;
        Ok(())
    }
    /// Subscribe once while sending a fresh direct initial-status envelope every time.
    pub fn monitor(&mut self, id: ClientId) -> Result<(), Error> {
        self.client(id)?;
        self.check_idle_native()?;
        let next = if self.clients[id.slot].monitor_order == 0 {
            Some(self.monitor_order.checked_add(1).ok_or(Error::Exhausted)?)
        } else {
            None
        };
        let slot = self.reserve(id, 12)?;
        let n = gnunet_arm_core::wire::Status {
            status: gnunet_arm_core::wire::MonitorStatus::MONITORING_STARTED,
            service: b"arm",
        }
        .encode(self.frames[slot].buffer)
        .map_err(|_| Error::Capacity)?;
        self.publish(slot, n)?;
        if let Some(next) = next {
            self.clients[id.slot].monitor_order = next;
            self.monitor_order = next;
        }
        Ok(())
    }
    // Notifications are optional only for MQ>1024. Actual caller-storage exhaustion
    // is explicit client resource closure, never silent optional-policy success.
    fn notify(&mut self, name: &[u8], code: u32) -> usize {
        let mut remaining = self.monitor_order;
        let mut failures = 0;
        loop {
            let candidate = self
                .clients
                .iter()
                .enumerate()
                .filter(|(_, c)| c.connected && c.monitor_order > 0 && c.monitor_order <= remaining)
                .max_by_key(|(_, c)| c.monitor_order)
                .map(|(i, c)| (i, c.generation, c.monitor_order));
            let Some((slot, generation, order)) = candidate else {
                break;
            };
            remaining = order - 1;
            if self.clients[slot].mq_length > 1024 {
                continue;
            }
            let client = ClientId {
                scope: self.scope,
                slot,
                generation,
            };
            let outcome = (|| {
                let frame = self.reserve(
                    client,
                    9usize.checked_add(name.len()).ok_or(Error::Capacity)?,
                )?;
                let n = gnunet_arm_core::wire::Status {
                    status: gnunet_arm_core::wire::MonitorStatus(code),
                    service: name,
                }
                .encode(self.frames[frame].buffer)
                .map_err(|_| Error::Capacity)?;
                self.publish(frame, n)
            })();
            if outcome.is_err() {
                failures += self.resource_close(client.key());
            }
            if remaining == 0 {
                break;
            }
        }
        failures
    }
    /// Encode an exact TEST reply after explicit framing admission.
    pub fn test(&mut self, client: ClientId) -> Result<(), Error> {
        self.client(client)?;
        self.check_idle_native()?;
        let slot = self.reserve(client, 4)?;
        self.frames[slot].buffer[..4].copy_from_slice(&[0, 4, 0, 15]);
        self.publish(slot, 4)
    }
    /// Build a complete immutable LIST envelope using caller scratch rows.
    /// Scratch is used only while encoding and never retained in the queued output.
    pub fn list(
        &mut self,
        client: ClientId,
        id: WireId,
        rows: &mut [gnunet_arm_core::wire::ServiceInfo<'spec>],
    ) -> Result<(), Error> {
        self.client(client)?;
        self.check_idle_native()?;
        let count = self.services.iter().filter(|s| s.registered).count();
        if rows.len() < count {
            return Err(Error::Capacity);
        }
        let mut size = self.abi.list_bytes();
        let mut row = 0;
        for i in 0..self.services.len() {
            if !self.services[i].registered {
                continue;
            }
            let info = self.info(ServiceId(i, self.scope))?;
            rows[row] = gnunet_arm_core::wire::ServiceInfo {
                name: self.specs[i].name,
                binary: self.specs[i].binary,
                status: info.status,
                last_exit_status: info.last_exit,
                restart_at: info.restart_at,
                last_started_at: info.last_started,
            };
            size = size
                .checked_add(28)
                .and_then(|v| v.checked_add(info.name.len()))
                .and_then(|v| v.checked_add(info.binary.len()))
                .and_then(|v| v.checked_add(2))
                .ok_or(Error::Capacity)?;
            row += 1;
        }
        let slot = self.reserve(client, size)?;
        let n = gnunet_arm_core::wire::encode_list(
            self.abi,
            id,
            &rows[..count],
            self.frames[slot].buffer,
        )
        .map_err(|_| Error::Capacity)?;
        self.publish(slot, n)
    }
    /// Queue self-stop status/result and request a later generic shutdown task.
    /// Queueing does not guarantee that RESULT_STOPPING physically writes before EOF.
    pub fn stop_arm(&mut self, client: ClientId, id: WireId, spelling: &[u8]) -> Result<(), Error> {
        self.client(client)?;
        self.check_idle_native()?;
        if !spelling.eq_ignore_ascii_case(b"arm") {
            return Err(Error::Malformed);
        }
        self.sequence
            .checked_add(u64::try_from(self.clients.len()).map_err(|_| Error::Exhausted)?)
            .and_then(|v| v.checked_add(1))
            .ok_or(Error::Exhausted)?;
        let slot = self.reserve(client, self.abi.result_bytes())?;
        let required = Request {
            client: client.key(),
            id,
            reserved: slot,
            frame_generation: self.frames[slot].generation,
        };
        self.notify(spelling, 3);
        // Notification resource closure can revoke/reuse this reserved slot.
        // Required output must still belong to its original recipient/lifetime.
        self.publish_request(required, ResultCode::STOPPING);
        self.clients[client.slot].persist = true;
        self.shutdown_requested = true;
        Ok(())
    }
    /// Take one scheduled self-stop trigger; the host preserves source scheduler order.
    pub fn take_shutdown_request(&mut self) -> bool {
        core::mem::take(&mut self.shutdown_requested)
    }
    /// Admit actual official wire input, using caller LIST scratch for that request.
    /// Unknown valid message types are ignored as MQ extensions; malformed frames fail.
    pub fn receive(
        &mut self,
        client: ClientId,
        bytes: &[u8],
        utc: u64,
        rows: &mut [gnunet_arm_core::wire::ServiceInfo<'spec>],
    ) -> Result<(), Error> {
        use gnunet_arm_core::wire::Request;
        self.client(client)?;
        match Request::decode(bytes) {
            Ok(Request::Start { id, service, .. }) => self.start(client, id, service),
            Ok(Request::Stop { id, service, .. }) => {
                if service.eq_ignore_ascii_case(b"arm") {
                    self.stop_arm(client, id, service)
                } else {
                    self.stop(client, id, service, utc)
                }
            }
            Ok(Request::List { id, .. }) => self.list(client, id, rows),
            Ok(Request::Monitor) => self.monitor(client),
            Ok(Request::Test) => self.test(client),
            Err(gnunet_types::Error::Unsupported) => Ok(()),
            Err(_) => Err(Error::Malformed),
        }
    }
    /// Explicit START with official shutdown/unknown/already-running precedence.
    pub fn start(&mut self, client: ClientId, id: WireId, name: &[u8]) -> Result<(), Error> {
        self.client(client)?;
        self.check_idle_native()?;
        if self.shutdown {
            return self.reply(client, id, ResultCode::IN_SHUTDOWN);
        }
        let Some(i) = self.find(name) else {
            return self.reply(client, id, ResultCode::IS_NOT_KNOWN);
        };
        if self.services[i].process != Process::None {
            self.reply(client, id, ResultCode::IS_STARTED_ALREADY)?;
            self.services[i].force = true;
            return Ok(());
        }
        if self.services[i].generation == u64::MAX || self.services[i].native_epoch == u64::MAX {
            return Err(Error::Exhausted);
        }
        let reserved = self.reserve(client, self.abi.result_bytes())?;
        let frame_generation = self.frames[reserved].generation;
        let s = &mut self.services[i];
        s.generation += 1;
        s.force = true;
        let child = ChildKey {
            service: i,
            generation: s.generation,
        };
        s.process = Process::Starting(child);
        s.start_request = Some(Request {
            client: client.key(),
            id,
            reserved,
            frame_generation,
        });
        s.native_leased = false;
        self.want_listeners(i, ListenerState::Disarmed);
        Ok(())
    }
    /// Start initial forced entries one at a time, preserving passed registry order.
    pub fn startup_next(&mut self) -> Result<bool, Error> {
        if self.shutdown {
            return Err(Error::Closed);
        }
        if self.phase == Phase::Serving {
            return Ok(false);
        }
        self.check_idle_native()?;
        self.phase = Phase::Starting;
        while self.startup_cursor < self.services.len() {
            let i = self.startup_cursor;
            if self.services[i].registered && self.services[i].force {
                self.begin_automatic_spawn(i)?;
                self.startup_cursor += 1;
                return Ok(true);
            }
            self.startup_cursor += 1;
        }
        // Official notifier creation is after every initial spawn attempt.
        self.phase = Phase::Serving;
        Ok(false)
    }
    fn begin_automatic_spawn(&mut self, i: usize) -> Result<(), Error> {
        let s = &mut self.services[i];
        if s.native_epoch == u64::MAX {
            return Err(Error::Exhausted);
        }
        s.generation = s.generation.checked_add(1).ok_or(Error::Exhausted)?;
        s.process = Process::Starting(ChildKey {
            service: i,
            generation: s.generation,
        });
        s.native_leased = false;
        self.want_listeners(i, ListenerState::Disarmed);
        Ok(())
    }
    /// Readiness means queued demand; the host must never accept the connection.
    /// This is an actual consumed one-shot event. Resource failure still records
    /// its consumption and requests sibling readiness cancellation; it never
    /// restores an already-consumed registration or creates a fake child.
    pub fn demand(&mut self, readiness: ReadinessId) -> Result<(), Error> {
        if self.shutdown {
            return Err(Error::Closed);
        }
        if self.phase != Phase::Serving {
            return Err(Error::Busy);
        }
        self.check_idle_native()?;
        if readiness.scope != self.scope {
            return Err(Error::Stale);
        }
        let slot = self.listeners.get(readiness.slot).ok_or(Error::Stale)?;
        if slot.generation != readiness.generation
            || slot.actual != ListenerState::Armed
            || slot.desired != ListenerState::Armed
            || slot.armed_epoch != readiness.epoch
            || slot.leased.is_some()
        {
            return Err(Error::Stale);
        }
        let i = slot.service.ok_or(Error::Stale)?;
        if self.services[i].process != Process::None {
            return Err(Error::Busy);
        }
        // Physical one-shot readiness was consumed by this event. Do not accept().
        self.listeners[readiness.slot].actual = ListenerState::Disarmed;
        self.want_listeners(i, ListenerState::Disarmed);
        self.begin_automatic_spawn(i)
    }
    /// Original owner identity, independent of service count or retirement.
    pub fn identity(&self) -> OwnerId<'scope> {
        OwnerId(self.scope)
    }
    /// Registry identity with checked bounds, useful while registering native listeners.
    pub fn service(&self, index: usize) -> Option<ServiceId<'scope>> {
        self.services
            .get(index)
            .filter(|s| s.registered)
            .map(|_| ServiceId(index, self.scope))
    }
    /// Whether an ID names a slot in this original owner, including a service
    /// already unregistered during shutdown. This proves scope membership only;
    /// it grants no active-service, child, frame or native-effect authority.
    pub fn owns_service(&self, id: ServiceId<'_>) -> bool {
        id.1 == self.scope && id.0 < self.services.len()
    }
    /// Lease the next native operation once. The host retains it across future cancellation.
    pub fn take_native(&mut self) -> Result<Option<NativeEffect<'spec, 'scope>>, Error> {
        if self.shutdown && (!self.listeners_closed() || !self.timer_drained()) {
            return Ok(None);
        }
        let Some(i) = self.services.iter().enumerate().position(|(i, s)| {
            !s.native_leased
                && matches!(s.process, Process::Starting(_) | Process::Term(_))
                && (!matches!(s.process, Process::Starting(_)) || self.listeners_disarmed(i))
        }) else {
            return Ok(None);
        };
        let s = &mut self.services[i];
        let (epoch, action) = if self.shutdown && matches!(s.process, Process::Term(_)) {
            if s.shutdown_term_taken {
                return Ok(None);
            }
            s.shutdown_term_taken = true;
            // The existing child lifetime grants one final shutdown signal. No
            // ordinary attempt counter/output sequence is minted for cleanup.
            (s.generation, Action::ShutdownTerm)
        } else {
            let epoch = s.native_epoch.checked_add(1).ok_or(Error::Exhausted)?;
            s.native_epoch = epoch;
            (
                epoch,
                if matches!(s.process, Process::Starting(_)) {
                    Action::Spawn
                } else {
                    Action::Term
                },
            )
        };
        s.native_leased = true;
        let ticket = NativeTicket {
            scope: self.scope,
            service: i,
            generation: epoch,
            action,
        };
        Ok(match s.process {
            Process::Starting(child) => Some(NativeEffect::Spawn {
                ticket,
                child: ChildId {
                    scope: self.scope,
                    service: child.service,
                    generation: child.generation,
                },
                service: ServiceId(i, self.scope),
                command: self.specs[i].command,
                pipe_control: self.specs[i].pipe_control,
            }),
            Process::Term(child) => Some(NativeEffect::Term {
                ticket,
                child: ChildId {
                    scope: self.scope,
                    service: child.service,
                    generation: child.generation,
                },
            }),
            _ => None,
        })
    }
    /// Apply actual fork-admission result; required reply storage was reserved beforehand.
    #[must_use = "resource-closed monitor clients require actual host closure"]
    pub fn spawned(
        &mut self,
        ticket: NativeTicket<'scope>,
        outcome: SpawnOutcome,
        utc: u64,
    ) -> Result<ReapReport, Error> {
        let s = self.services.get(ticket.service).ok_or(Error::Stale)?;
        let expected = ChildKey {
            service: ticket.service,
            generation: s.generation,
        };
        if ticket.scope != self.scope
            || ticket.action != Action::Spawn
            || ticket.generation != s.native_epoch
            || s.process != Process::Starting(expected)
            || !s.native_leased
        {
            return Err(Error::Stale);
        }
        let request = s.start_request;
        let i = ticket.service;
        let mut failures = if outcome == SpawnOutcome::Admitted {
            let s = &mut self.services[i];
            s.process = if self.shutdown {
                s.killed_at = utc;
                Process::Term(expected)
            } else {
                Process::Running(expected)
            };
            s.last_started = utc;
            if self.phase == Phase::Serving {
                self.notify(self.specs[i].name, 2)
            } else {
                0
            }
        } else {
            self.services[i].process = Process::None;
            if self.shutdown {
                self.services[i].registered = false;
            }
            0
        };
        self.services[i].native_leased = false;
        self.services[i].start_request = None;
        if let Some(r) = request {
            failures += self.publish_request(
                r,
                if outcome == SpawnOutcome::Admitted {
                    ResultCode::STARTING
                } else {
                    ResultCode::START_FAILED
                },
            );
        }
        Ok(ReapReport {
            resource_closures: failures,
        })
    }
    /// STOP ordinary service; self-stop is deliberately a separate lifecycle call.
    pub fn stop(
        &mut self,
        client: ClientId,
        id: WireId,
        name: &[u8],
        utc: u64,
    ) -> Result<(), Error> {
        self.client(client)?;
        self.check_idle_native()?;
        if name.eq_ignore_ascii_case(b"arm") {
            return Err(Error::Malformed);
        }
        let Some(i) = self.find(name) else {
            return self.reply(client, id, ResultCode::IS_NOT_KNOWN);
        };
        let code = if self.shutdown {
            Some(ResultCode::IN_SHUTDOWN)
        } else if self.services[i].stop_request.is_some() {
            Some(ResultCode::IS_STOPPING_ALREADY)
        } else if self.services[i].process == Process::None {
            Some(ResultCode::IS_STOPPED_ALREADY)
        } else {
            None
        };
        if let Some(code) = code {
            self.reply(client, id, code)?;
            self.services[i].force = false;
            return Ok(());
        }
        if self.services[i].native_epoch == u64::MAX {
            return Err(Error::Exhausted);
        }
        let reserved = self.reserve(client, self.abi.result_bytes())?;
        let frame_generation = self.frames[reserved].generation;
        let s = &mut self.services[i];
        s.force = false;
        s.killed_at = utc;
        s.stop_request = Some(Request {
            client: client.key(),
            id,
            reserved,
            frame_generation,
        });
        if let Process::Running(child) | Process::Term(child) = s.process {
            s.process = Process::Term(child);
        }
        s.native_leased = false;
        // Any resource failure remains explicit via resource_closures(), before native TERM.
        self.notify(name, 3);
        Ok(())
    }
    /// Acknowledge an actual TERM attempt, including failed syscall/pipe fallback.
    /// Failure does not fabricate completion or remove the real child.
    pub fn term_attempted(&mut self, ticket: NativeTicket) -> Result<(), Error> {
        if !self.native_current(ticket) {
            return Err(Error::Stale);
        }
        if !matches!(ticket.action, Action::Term | Action::ShutdownTerm) {
            return Err(Error::Stale);
        }
        let s = &mut self.services[ticket.service];
        if let Process::Term(child) = s.process {
            s.process = Process::Running(child);
            s.native_leased = false;
            Ok(())
        } else {
            Err(Error::Stale)
        }
    }
    /// Commit actual owned-child wait result; optional resource failures are explicit.
    pub fn reaped(
        &mut self,
        child: ChildId<'scope>,
        exit: Exit,
        utc: u64,
    ) -> Result<ReapReport, Error> {
        if child.scope != self.scope {
            return Err(Error::Stale);
        }
        let s = self.services.get(child.service).ok_or(Error::Stale)?;
        if !matches!(s.process,Process::Running(x)|Process::Term(x) if x==child.key()) {
            return Err(Error::Stale);
        }
        let i = child.service;
        self.services[i].process = Process::None;
        self.services[i].native_leased = false;
        let request = self.services[i].stop_request.take();
        let mut failures = self.notify(self.specs[i].name, 1);
        if let Some(r) = request {
            failures += self.publish_request(r, ResultCode::STOPPED);
        }
        let s = &mut self.services[i];
        if self.shutdown {
            s.registered = false;
            return Ok(ReapReport {
                resource_closures: failures,
            });
        }
        s.last_exit = match exit {
            Exit::Exited(x) | Exit::Signaled(x) => x,
        };
        if exit == Exit::Exited(0) {
            s.restart_at = 0;
            self.want_listeners(i, ListenerState::Armed);
        } else {
            let minutes = utc.saturating_sub(s.restart_at) / 60_000_000;
            s.backoff = if minutes > 31 {
                0
            } else {
                s.backoff >> minutes
            };
            s.restart_at = utc.saturating_add(s.backoff);
            s.backoff = s.backoff.max(1000).saturating_mul(2).min(900_000_000);
            // C cancels its old global task and installs a new immediate
            // IDLE callback, whose actual registration/firing is still owed.
            self.restart_scan = false;
            self.restart_wake = Some(utc);
            self.timer_cancel_requested = true;
            self.scan_active = false;
        }
        Ok(ReapReport {
            resource_closures: failures,
        })
    }
    /// Resume one source-order automatic restart scan and return the next UTC wake.
    pub fn restart(&mut self, utc: u64) -> Result<Option<u64>, Error> {
        self.check_idle_native()?;
        if self.shutdown {
            return Err(Error::Closed);
        }
        if self.timer_cancel_requested
            && (self.timer_actual.is_some() || self.timer_pending.is_some())
        {
            return Err(Error::Busy);
        }
        if !self.scan_active {
            if !self.restart_scan {
                return Ok(self.restart_wake);
            }
            self.restart_scan = false;
            self.restart_wake = None;
            self.scan_active = true;
            self.scan_cursor = 0;
            self.scan_lowest = u64::MAX;
        }
        while self.scan_cursor < self.services.len() {
            let i = self.scan_cursor;
            let s = &mut self.services[i];
            if !s.registered || s.process != Process::None {
                self.scan_cursor += 1;
                continue;
            }
            if s.restart_at <= utc {
                if s.force {
                    self.begin_automatic_spawn(i)?;
                    self.scan_cursor += 1;
                    return Ok(Some(utc));
                }
                self.want_listeners(i, ListenerState::Armed);
            } else {
                self.scan_lowest = self.scan_lowest.min(s.restart_at);
            }
            self.scan_cursor += 1;
        }
        self.scan_active = false;
        if self.scan_lowest != u64::MAX {
            self.restart_wake = Some(self.scan_lowest);
        }
        Ok(self.restart_wake)
    }
    /// Lease the global scheduler operation; ordinary Arm epochs never wrap.
    /// Cancel consumes an existing registration and is independent from epoch/output limits.
    pub fn take_timer(&mut self) -> Result<Option<TimerEffect<'scope>>, Error> {
        if self.timer_pending.is_some() {
            return Ok(None);
        }
        if let Some(actual) = self.timer_actual {
            if self.shutdown
                || self.timer_cancel_requested
                || self.restart_wake != Some(actual.at_utc)
            {
                self.timer_pending = Some(TimerPending::Cancel(actual));
                let id = TimerId {
                    scope: self.scope,
                    epoch: actual.epoch,
                };
                return Ok(Some(TimerEffect {
                    id,
                    ticket: TimerTicket {
                        id,
                        action: TimerAction::Cancel,
                    },
                    action: TimerAction::Cancel,
                }));
            }
            return Ok(None);
        }
        self.timer_cancel_requested = false;
        if self.shutdown {
            return Ok(None);
        }
        let Some(at_utc) = self.restart_wake else {
            return Ok(None);
        };
        let epoch = self.timer_epoch.checked_add(1).ok_or(Error::Exhausted)?;
        self.timer_epoch = epoch;
        let registration = TimerRegistration { epoch, at_utc };
        self.timer_pending = Some(TimerPending::Arm(registration));
        let id = TimerId {
            scope: self.scope,
            epoch,
        };
        let action = TimerAction::Arm { at_utc };
        Ok(Some(TimerEffect {
            id,
            ticket: TimerTicket { id, action },
            action,
        }))
    }
    /// Validate the retained scheduler operation before the host acts on its task capability.
    pub fn timer_current(&self, ticket: TimerTicket) -> bool {
        ticket.id.scope == self.scope
            && match (self.timer_pending, ticket.action) {
                (Some(TimerPending::Arm(reg)), TimerAction::Arm { at_utc }) => {
                    reg.epoch == ticket.id.epoch && reg.at_utc == at_utc
                }
                (Some(TimerPending::Cancel(reg)), TimerAction::Cancel) => {
                    reg.epoch == ticket.id.epoch
                }
                _ => false,
            }
    }
    /// Acknowledge actual scheduler registration or cancellation, not just its intent.
    pub fn timer_applied(&mut self, ticket: TimerTicket) -> Result<(), Error> {
        if !self.timer_current(ticket) {
            return Err(Error::Stale);
        }
        match self.timer_pending.take() {
            Some(TimerPending::Arm(reg)) => self.timer_actual = Some(reg),
            Some(TimerPending::Cancel(_)) => {
                self.timer_actual = None;
                self.timer_cancel_requested = false;
            }
            None => return Err(Error::Stale),
        }
        Ok(())
    }
    /// Abort registration only when the host confirms no actual task was installed.
    /// A cancellation lease cannot be abandoned while its real task remains live.
    pub fn timer_aborted(&mut self, ticket: TimerTicket) -> Result<(), Error> {
        if !self.timer_current(ticket) || ticket.action == TimerAction::Cancel {
            return Err(Error::Stale);
        }
        self.timer_pending = None;
        Ok(())
    }
    /// Record an actual registered task firing. Stale canceled/replaced IDs are refused.
    /// A backward UTC jump still runs the source scan and may schedule a later wake again.
    pub fn timer_fired(&mut self, id: TimerId) -> Result<(), Error> {
        if id.scope != self.scope {
            return Err(Error::Stale);
        }
        let actual = self
            .timer_actual
            .filter(|reg| reg.epoch == id.epoch)
            .ok_or(Error::Stale)?;
        self.timer_actual = None;
        let current = !self.shutdown
            && !matches!(self.timer_pending, Some(TimerPending::Cancel(_)))
            && !self.timer_cancel_requested
            && self.restart_wake == Some(actual.at_utc);
        if matches!(self.timer_pending,Some(TimerPending::Cancel(reg)) if reg==actual) {
            self.timer_pending = None;
        }
        if current {
            self.restart_scan = true;
            self.restart_wake = None;
        }
        if self.timer_pending.is_none() {
            self.timer_cancel_requested = false;
        }
        Ok(())
    }
    /// All actual or leased scheduler resources are gone; no implicit cancellation claim.
    pub fn timer_drained(&self) -> bool {
        self.timer_actual.is_none() && self.timer_pending.is_none()
    }
    /// Current lifecycle phase, before callbacks or scheduler work are admitted.
    pub const fn phase(&self) -> Phase {
        self.phase
    }
    fn want_listeners(&mut self, service: usize, state: ListenerState) {
        for listener in self
            .listeners
            .iter_mut()
            .filter(|l| l.service == Some(service))
        {
            listener.desired = state;
        }
    }
    fn listeners_disarmed(&self, service: usize) -> bool {
        self.listeners
            .iter()
            .filter(|l| l.service == Some(service))
            .all(|l| {
                l.actual == ListenerState::Disarmed
                    && l.desired == ListenerState::Disarmed
                    && l.leased.is_none()
            })
    }
    /// Every actual parent listener was closed and its leased action completed.
    pub fn listeners_closed(&self) -> bool {
        self.listeners.iter().all(|l| {
            l.service.is_none() || (l.actual == ListenerState::Closed && l.leased.is_none())
        })
    }
    /// Register an actual host-owned bound listener during configuration only.
    /// Binding/native failures must not call this method as if they succeeded.
    pub fn register_listener(&mut self, service: ServiceId) -> Result<ListenerId<'scope>, Error> {
        if service.1 != self.scope {
            return Err(Error::Stale);
        }
        if self.phase != Phase::Configuring {
            return Err(Error::Busy);
        }
        if !self.services.get(service.0).is_some_and(|s| s.registered) {
            return Err(Error::Stale);
        }
        let (slot, l) = self
            .listeners
            .iter_mut()
            .enumerate()
            .find(|(_, l)| l.service.is_none() && l.generation < u64::MAX)
            .ok_or(Error::Capacity)?;
        l.generation += 1;
        l.service = Some(service.0);
        l.epoch = 0;
        l.actual = ListenerState::Disarmed;
        l.desired = ListenerState::Armed;
        l.leased = None;
        l.close_taken = false;
        l.armed_epoch = 0;
        Ok(ListenerId {
            scope: self.scope,
            slot,
            generation: l.generation,
        })
    }
    /// Lease one real readiness/close operation once; hold it across driver cancellation.
    pub fn take_listener(&mut self) -> Result<Option<ListenerEffect<'scope>>, Error> {
        if self.shutdown && !self.timer_drained() {
            return Ok(None);
        }
        let Some((slot, l)) = self
            .listeners
            .iter_mut()
            .enumerate()
            .find(|(_, l)| l.service.is_some() && l.actual != l.desired && l.leased.is_none())
        else {
            return Ok(None);
        };
        let action = match l.desired {
            ListenerState::Armed => ListenerAction::Arm,
            ListenerState::Disarmed => ListenerAction::Disarm,
            ListenerState::Closed => ListenerAction::Close,
        };
        let epoch = if action == ListenerAction::Close {
            if l.close_taken {
                return Ok(None);
            }
            l.close_taken = true;
            l.generation
        } else {
            let next = l.epoch.checked_add(1).ok_or(Error::Exhausted)?;
            l.epoch = next;
            next
        };
        l.leased = Some(action);
        let listener = ListenerId {
            scope: self.scope,
            slot,
            generation: l.generation,
        };
        Ok(Some(ListenerEffect {
            listener,
            service: ServiceId(l.service.ok_or(Error::Stale)?, self.scope),
            ticket: ListenerTicket {
                scope: self.scope,
                slot,
                generation: l.generation,
                epoch,
                action,
            },
            action,
        }))
    }
    /// Check a retained operation immediately before actual host I/O.
    pub fn listener_current(&self, ticket: ListenerTicket) -> bool {
        ticket.scope == self.scope
            && self.listeners.get(ticket.slot).is_some_and(|l| {
                l.generation == ticket.generation
                    && l.leased == Some(ticket.action)
                    && if ticket.action == ListenerAction::Close {
                        l.close_taken && ticket.epoch == l.generation
                    } else {
                        ticket.epoch == l.epoch
                    }
            })
    }
    /// Acknowledge that the host actually applied the leased action.
    /// No output counter or ordinary operation generation is required for Close.
    pub fn listener_applied(&mut self, ticket: ListenerTicket) -> Result<(), Error> {
        if !self.listener_current(ticket) {
            return Err(Error::Stale);
        }
        let l = &mut self.listeners[ticket.slot];
        l.actual = match ticket.action {
            ListenerAction::Arm => {
                l.armed_epoch = ticket.epoch;
                ListenerState::Armed
            }
            ListenerAction::Disarm => ListenerState::Disarmed,
            ListenerAction::Close => ListenerState::Closed,
        };
        l.leased = None;
        Ok(())
    }
    /// Abort a lease only when the host confirms that no actual I/O happened.
    /// Close cannot be abandoned; it retains cleanup authority until actually consumed.
    pub fn listener_aborted(&mut self, ticket: ListenerTicket) -> Result<(), Error> {
        if !self.listener_current(ticket) || ticket.action == ListenerAction::Close {
            return Err(Error::Stale);
        }
        self.listeners[ticket.slot].leased = None;
        Ok(())
    }
    /// Current one-shot registration identity. Stale prior registrations cannot start a child.
    pub fn readiness(&self, id: ListenerId) -> Result<Option<ReadinessId<'scope>>, Error> {
        if id.scope != self.scope {
            return Err(Error::Stale);
        }
        let l = self
            .listeners
            .get(id.slot)
            .filter(|l| l.generation == id.generation && l.service.is_some())
            .ok_or(Error::Stale)?;
        Ok(if l.actual == ListenerState::Armed && l.leased.is_none() {
            Some(ReadinessId {
                scope: self.scope,
                slot: id.slot,
                generation: id.generation,
                epoch: l.armed_epoch,
            })
        } else {
            None
        })
    }
    /// Begin manual shutdown independently from output capacity; close-before-TERM host order.
    pub fn begin_shutdown(&mut self, utc: u64) {
        if self.shutdown {
            return;
        }
        self.shutdown = true;
        self.phase = Phase::Draining;
        for listener in self.listeners.iter_mut().filter(|l| l.service.is_some()) {
            listener.desired = ListenerState::Closed;
        }
        self.restart_scan = false;
        self.restart_wake = None;
        self.timer_cancel_requested = true;
        self.scan_active = false;
        for i in 0..self.services.len() {
            let s = &mut self.services[i];
            s.force = false;
            match s.process {
                Process::Running(child) | Process::Term(child) => {
                    s.process = Process::Term(child);
                    s.native_leased = false;
                    s.shutdown_term_taken = false;
                    s.killed_at = utc;
                }
                Process::None => s.registered = false,
                Process::Starting(_) if !s.native_leased => {
                    // No native effect was leased or admitted. Retire only this
                    // prepared plan; actual leased spawn is still acknowledged.
                    s.process = Process::None;
                    s.registered = false;
                    if let Some(request) = s.start_request.take() {
                        self.publish_request(request, ResultCode::START_FAILED);
                    }
                }
                Process::Starting(_) => {}
            }
        }
    }
    /// No actual child or pending spawn remains; host resources still need real cleanup.
    pub fn children_drained(&self) -> bool {
        self.shutdown && self.services.iter().all(|s| s.process == Process::None)
    }
    /// All real child/listener/timer capabilities were retired before generic shutdown.
    pub fn cleanup_ready(&self) -> bool {
        self.children_drained() && self.listeners_closed() && self.timer_drained()
    }
    /// Lease final notifier/service/SIGCHLD-read cancellation in source order.
    /// This is a host request, never an assertion that those resources closed themselves.
    pub fn take_runtime_shutdown(&mut self) -> Option<ShutdownTicket<'scope>> {
        if self.phase != Phase::Draining || !self.cleanup_ready() || self.shutdown_lease {
            return None;
        }
        self.shutdown_lease = true;
        Some(ShutdownTicket { scope: self.scope })
    }
    /// Confirm the host actually shut down its generic runtime resources.
    /// Queued undelivered outputs are revoked; no successful callback is fabricated.
    pub fn runtime_shutdown_applied(&mut self, ticket: ShutdownTicket) -> Result<(), Error> {
        if ticket.scope != self.scope
            || !self.shutdown_lease
            || self.phase != Phase::Draining
            || !self.cleanup_ready()
        {
            return Err(Error::Stale);
        }
        for i in 0..self.clients.len() {
            if self.clients[i].connected {
                let key = ClientKey {
                    slot: i,
                    generation: self.clients[i].generation,
                };
                self.clients[i].connected = false;
                self.clients[i].monitor_order = 0;
                self.revoke_key(key);
            }
        }
        self.shutdown_lease = false;
        self.phase = Phase::Closed;
        Ok(())
    }
    /// Generic service policy for the special self-stop requester.
    /// All other connections are monitor-kind and cannot delay manual shutdown.
    /// Cleanup can inspect this policy after a resource failure revokes message
    /// admission; the original connected generation is still required.
    pub fn client_persisted(&self, client: ClientId) -> Result<bool, Error> {
        Ok(self.client_raw(client)?.persist)
    }
    /// Validate a retained native lease immediately before executing its host effect.
    /// The host also requires its actual native child/listener capability to be live.
    pub fn native_current(&self, ticket: NativeTicket) -> bool {
        ticket.scope == self.scope
            && self.services.get(ticket.service).is_some_and(|s| {
                s.native_leased
                    && match ticket.action {
                        Action::Spawn => {
                            s.native_epoch == ticket.generation
                                && matches!(s.process, Process::Starting(_))
                        }
                        Action::Term => {
                            !self.shutdown
                                && s.native_epoch == ticket.generation
                                && matches!(s.process, Process::Term(_))
                        }
                        Action::ShutdownTerm => {
                            self.shutdown
                                && s.shutdown_term_taken
                                && s.generation == ticket.generation
                                && matches!(s.process, Process::Term(_))
                        }
                    }
            })
    }
    /// A resource-failed client must actually be closed and then disconnected.
    pub fn resource_closures(&self) -> impl Iterator<Item = ClientId<'scope>> + '_ {
        self.clients
            .iter()
            .enumerate()
            .filter(|(_, s)| s.connected && s.resource_close)
            .map(|(slot, s)| ClientId {
                scope: self.scope,
                slot,
                generation: s.generation,
            })
    }
    /// Lease the earliest queued complete envelope; bytes remain stable until release/EOF.
    pub fn frame(&mut self) -> Option<Frame<'_, 'scope>> {
        let slot = self
            .frames
            .iter()
            .enumerate()
            .filter(|(_, s)| {
                s.client.is_some()
                    && !s.reserved
                    && s.len > 0
                    && !s.leased
                    && !self.frames.iter().any(|earlier| {
                        earlier.client == s.client
                            && earlier.len > 0
                            && !earlier.reserved
                            && earlier.sequence < s.sequence
                    })
            })
            .min_by_key(|(_, s)| s.sequence)
            .map(|(i, _)| i)?;
        let s = &mut self.frames[slot];
        s.leased = true;
        Some(Frame {
            ticket: FrameTicket {
                scope: self.scope,
                slot,
                generation: s.generation,
            },
            client: {
                let key = s.client?;
                ClientId {
                    scope: self.scope,
                    slot: key.slot,
                    generation: key.generation,
                }
            },
            bytes: &s.buffer[..s.len],
        })
    }
    /// Complete actual host handoff/write according to its persistent TX ownership contract.
    pub fn release_frame(&mut self, ticket: FrameTicket) -> Result<(), Error> {
        if ticket.scope != self.scope {
            return Err(Error::Stale);
        }
        let s = self.frames.get(ticket.slot).ok_or(Error::Stale)?;
        if s.generation != ticket.generation || s.client.is_none() || !s.leased {
            return Err(Error::Stale);
        }
        self.release_slot(ticket.slot);
        Ok(())
    }
    /// Snapshot of actual source LIST status and clocks for typed serializer integration.
    pub fn info(&self, id: ServiceId) -> Result<ServiceInfo<'spec>, Error> {
        if id.1 != self.scope {
            return Err(Error::Stale);
        }
        let s = self
            .services
            .get(id.0)
            .filter(|s| s.registered)
            .ok_or(Error::Stale)?;
        let status = match s.process {
            Process::None if s.last_started == 0 => ServiceStatus::STOPPED,
            Process::None if s.last_exit == 0 => ServiceStatus::FINISHED,
            Process::None => ServiceStatus::FAILED,
            _ if s.stop_request.is_some() || self.shutdown => ServiceStatus::STOPPING,
            _ => ServiceStatus::STARTED,
        };
        Ok(ServiceInfo {
            name: self.specs[id.0].name,
            binary: self.specs[id.0].binary,
            status,
            last_exit: if status == ServiceStatus::FAILED {
                s.last_exit as u16
            } else {
                0
            },
            last_started: s.last_started,
            restart_at: s.restart_at,
            backoff: s.backoff,
            force_start: s.force,
            killed_at: s.killed_at,
        })
    }
}
/// Borrowed source state snapshot, not an asynchronously queued LIST envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceInfo<'a> {
    /// Original service name.
    pub name: &'a [u8],
    /// Configured binary bytes.
    pub binary: &'a [u8],
    /// Official LIST state.
    pub status: ServiceStatus,
    /// Source last exit field (only FAILED).
    pub last_exit: u16,
    /// Source last-start UTC.
    pub last_started: u64,
    /// Source restart UTC, including FOREVER.
    pub restart_at: u64,
    /// Current source relative backoff.
    pub backoff: u64,
    /// Explicit/immediate force policy.
    pub force_start: bool,
    /// Last actual signal-attempt UTC.
    pub killed_at: u64,
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod boundaries {
    //! Private arithmetic and authority boundaries; no host side effects.
    #![expect(
        clippy::expect_used,
        reason = "Finite private boundary setup requires successful ordinary construction"
    )]
    use super::*;
    static SPECS: [ServiceSpec<'static>; 1] = [ServiceSpec {
        name: b"s",
        binary: b"b",
        command: b"recipe",
        immediate: false,
        pipe_control: false,
    }];
    fn setup(test: impl FnOnce(&mut Owner<'_, '_, '_, '_>)) {
        let mut service = [ServiceSlot::new()];
        let mut client = [ClientSlot::new()];
        let mut a = [0xA5; 64];
        let mut b = [0xA5; 64];
        let mut frames = [FrameSlot::new(&mut a), FrameSlot::new(&mut b)];
        let mut listeners = [];
        let mut scope = OwnerScope::new();
        let mut o = Owner::new(
            &mut scope,
            &SPECS,
            &mut service,
            &mut client,
            &mut listeners,
            &mut frames,
            ArmAbi::U64Align8,
        )
        .expect("initial");
        assert_eq!(o.startup_next(), Ok(false));
        test(&mut o);
    }
    #[test]
    fn original_service_membership_survives_retirement_without_restoring_active_authority() {
        setup(|o| {
            let id = o.service(0).expect("registered original slot");
            let foreign = OwnerScope::new();
            assert!(o.owns_service(id));
            assert!(!o.owns_service(ServiceId(0, Scope(&foreign))));
            assert!(!o.owns_service(ServiceId(o.services.len(), o.scope)));
            o.begin_shutdown(1);
            assert!(o.service(0).is_none());
            assert!(matches!(o.info(id), Err(Error::Stale)));
            assert!(o.owns_service(id));
        });
    }
    #[test]
    fn empty_owner_identity_is_distinct_and_survives_registry_shutdown() {
        let mut first_scope = OwnerScope::new();
        let mut second_scope = OwnerScope::new();
        let mut first_services = [];
        let mut second_services = [];
        let mut first_clients = [];
        let mut second_clients = [];
        let mut first_listeners = [];
        let mut second_listeners = [];
        let mut first_frames = [];
        let mut second_frames = [];
        let mut first = Owner::new(
            &mut first_scope,
            &[],
            &mut first_services,
            &mut first_clients,
            &mut first_listeners,
            &mut first_frames,
            ArmAbi::U64Align8,
        )
        .expect("first empty owner");
        let second = Owner::new(
            &mut second_scope,
            &[],
            &mut second_services,
            &mut second_clients,
            &mut second_listeners,
            &mut second_frames,
            ArmAbi::U64Align8,
        )
        .expect("second empty owner");
        let original = first.identity();
        assert_ne!(original, second.identity());
        let identities = std::collections::HashSet::from([original, second.identity()]);
        assert_eq!(identities.len(), 2);
        first.begin_shutdown(1);
        assert_eq!(original, first.identity());
        assert!(first.service(0).is_none());
    }
    #[test]
    #[expect(
        clippy::panic,
        reason = "A different leased native effect is a concrete failure of this finite shutdown control"
    )]
    fn draining_keeps_new_control_test_and_in_shutdown_start_until_final_runtime_close() {
        setup(|o| {
            let original = o.connect().expect("initial requester");
            o.start(original, WireId(1), b"s").expect("initial start");
            let (ticket, child) = match o.take_native().expect("native epoch").expect("spawn") {
                NativeEffect::Spawn { ticket, child, .. } => (ticket, child),
                _ => panic!("expected spawn"),
            };
            let _report = o
                .spawned(ticket, SpawnOutcome::Admitted, 1)
                .expect("host admission");
            let frame = o.frame().expect("starting result");
            let ticket = frame.ticket;
            o.release_frame(ticket).expect("delivered starting");
            o.disconnect(original).expect("old requester closes");
            o.begin_shutdown(2);
            let term = match o.take_native().expect("term epoch").expect("actual term") {
                NativeEffect::Term { ticket, .. } => ticket,
                _ => panic!("expected term"),
            };
            o.term_attempted(term).expect("host attempted term");
            assert!(o.take_runtime_shutdown().is_none());
            let late = o.connect().expect("manual drain still accepts ARM control");
            o.test(late).expect("late TEST");
            let frame = o.frame().expect("TEST echo");
            assert_eq!(frame.bytes, &[0, 4, 0, 15]);
            let ticket = frame.ticket;
            o.release_frame(ticket).expect("TEST sent");
            o.start(late, WireId(2), b"missing")
                .expect("shutdown result");
            let frame = o.frame().expect("IN_SHUTDOWN frame");
            let result = gnunet_arm_core::wire::ResultReply::decode(ArmAbi::U64Align8, frame.bytes)
                .expect("result codec");
            assert_eq!(result.result, ResultCode::IN_SHUTDOWN);
            let ticket = frame.ticket;
            o.release_frame(ticket).expect("shutdown result sent");
            let _report = o
                .reaped(child, Exit::Exited(0), 3)
                .expect("host real exit report");
            let close = o.take_runtime_shutdown().expect("last child drained");
            o.runtime_shutdown_applied(close)
                .expect("actual final generic close");
            assert_eq!(o.connect(), Err(Error::Closed));
        });
    }
    #[test]
    fn child_generation_and_envelope_sequence_exhaustion_reject_before_reservation() {
        setup(|o| {
            let c = o.connect().expect("client");
            o.services[0].generation = u64::MAX;
            assert_eq!(o.start(c, WireId(1), b"s"), Err(Error::Exhausted));
            assert!(o.frames.iter().all(|f| f.client.is_none()));
            assert_eq!(o.services[0].process, Process::None);
            o.services[0].generation = 0;
            o.sequence = u64::MAX;
            assert_eq!(o.stop_arm(c, WireId(2), b"arm"), Err(Error::Exhausted));
            assert!(o.frames.iter().all(|f| f.client.is_none()));
            assert!(!o.take_shutdown_request());
        });
    }
    #[test]
    fn native_attempt_epoch_does_not_wrap_or_grant_duplicate_lease() {
        setup(|o| {
            let c = o.connect().expect("client");
            o.start(c, WireId(1), b"s").expect("request");
            o.services[0].native_epoch = u64::MAX;
            assert_eq!(o.take_native(), Err(Error::Exhausted));
            assert!(!o.services[0].native_leased);
            assert!(o.frame().is_none());
        });
    }
    #[test]
    fn frame65535_registry_is_allowed_65536_rejected_before_metadata_mutation() {
        for (name_len, success) in [(65480, true), (65481, false)] {
            let name = std::vec![b'x';name_len];
            let specs = [ServiceSpec {
                name: &name,
                binary: b"b",
                command: b"c",
                immediate: false,
                pipe_control: false,
            }];
            let mut service = [ServiceSlot::new()];
            service[0].killed_at = 991;
            let mut clients = [];
            let mut listeners = [];
            let mut frames = [];
            let mut scope = OwnerScope::new();
            let result = Owner::new(
                &mut scope,
                &specs,
                &mut service,
                &mut clients,
                &mut listeners,
                &mut frames,
                ArmAbi::U64Align8,
            );
            if success {
                assert!(result.is_ok());
            } else {
                assert!(matches!(result, Err(Error::Capacity)));
                assert_eq!(service[0].killed_at, 991);
            }
        }
    }
    #[test]
    fn future_and_forever_duration_zero_saturating_restart_preserves_sentinel() {
        setup(|o| {
            let c = o.connect().expect("client");
            o.start(c, WireId(1), b"s").expect("request");
            let child = ChildId {
                scope: o.scope,
                service: 0,
                generation: 1,
            };
            o.services[0].process = Process::Running(child.key());
            o.services[0].start_request = None;
            o.services[0].last_started = 1;
            o.services[0].restart_at = u64::MAX;
            o.services[0].backoff = 1000;
            assert_eq!(
                o.reaped(child, Exit::Signaled(9), u64::MAX - 100)
                    .expect("reap")
                    .resource_closures,
                0
            );
            assert_eq!(o.services[0].restart_at, u64::MAX);
            assert_eq!(o.services[0].backoff, 2000);
            let timer = o
                .take_timer()
                .expect("immediate IDLE epoch")
                .expect("immediate callback");
            o.timer_applied(timer.ticket).expect("actually registered");
            o.timer_fired(timer.id).expect("actually fired");
            assert_eq!(o.restart(u64::MAX - 99), Ok(None));
        });
    }
    #[test]
    fn actual_native_ack_and_final_term_ignore_output_and_attempt_counter_exhaustion() {
        setup(|o| {
            let c = o.connect().expect("client");
            o.start(c, WireId(1), b"s").expect("reserved request");
            let (ticket, child) = match o.take_native().expect("native epoch").expect("spawn") {
                NativeEffect::Spawn { ticket, child, .. } => (ticket, child),
                other => {
                    assert!(matches!(other, NativeEffect::Spawn { .. }));
                    return;
                }
            };
            o.sequence = u64::MAX;
            let report = o
                .spawned(ticket, SpawnOutcome::Admitted, 50)
                .expect("real child must be retained");
            assert_eq!(report.resource_closures, 1);
            assert_eq!(o.services[0].process, Process::Running(child.key()));
            assert!(o.frames.iter().all(|f| f.client.is_none()));
            assert!(matches!(o.client(c), Err(Error::Closed)));
            assert_eq!(o.client_persisted(c), Ok(false));
            o.services[0].native_epoch = u64::MAX;
            o.begin_shutdown(51);
            let final_ticket = match o
                .take_native()
                .expect("final TERM has no ordinary counter")
                .expect("TERM")
            {
                NativeEffect::Term { ticket, child: got } => {
                    assert_eq!(got, child);
                    ticket
                }
                other => {
                    assert!(matches!(other, NativeEffect::Term { .. }));
                    return;
                }
            };
            assert!(o.native_current(final_ticket));
            o.term_attempted(final_ticket)
                .expect("actual signal attempt");
            assert!(!o.children_drained());
            assert_eq!(
                o.reaped(child, Exit::Signaled(15), 52)
                    .expect("actual child reaped")
                    .resource_closures,
                0
            );
            assert!(o.children_drained());
            o.disconnect(c).expect("actual failed-client close");
        });
    }
    #[test]
    fn actual_reap_with_reserved_stop_reply_at_max_retires_child_and_client() {
        setup(|o| {
            let c = o.connect().expect("client");
            o.start(c, WireId(1), b"s").expect("request");
            let (ticket, child) = match o.take_native().expect("epoch").expect("spawn") {
                NativeEffect::Spawn { ticket, child, .. } => (ticket, child),
                other => {
                    assert!(matches!(other, NativeEffect::Spawn { .. }));
                    return;
                }
            };
            assert_eq!(
                o.spawned(ticket, SpawnOutcome::Admitted, 1)
                    .expect("admit")
                    .resource_closures,
                0
            );
            let frame = o.frame().expect("STARTING");
            let done = frame.ticket;
            o.release_frame(done).expect("written");
            o.stop(c, WireId(2), b"s", 2).expect("reserve completion");
            let ticket = match o.take_native().expect("epoch").expect("TERM") {
                NativeEffect::Term { ticket, .. } => ticket,
                other => {
                    assert!(matches!(other, NativeEffect::Term { .. }));
                    return;
                }
            };
            o.term_attempted(ticket).expect("actual attempt");
            o.sequence = u64::MAX;
            let report = o
                .reaped(child, Exit::Exited(0), 3)
                .expect("actual reap is not refused by output sequence");
            assert_eq!(report.resource_closures, 1);
            assert_eq!(o.services[0].process, Process::None);
            assert!(o.services[0].stop_request.is_none());
            assert!(o.frames.iter().all(|f| f.client.is_none()));
            o.begin_shutdown(4);
            assert!(o.children_drained());
        });
    }
    #[test]
    fn zero_client_storage_real_child_lifecycle_is_not_an_output_budget() {
        let specs = [ServiceSpec {
            immediate: true,
            ..SPECS[0]
        }];
        let mut services = [ServiceSlot::new()];
        let mut clients = [];
        let mut listeners = [];
        let mut frames = [];
        let mut scope = OwnerScope::new();
        let mut o = Owner::new(
            &mut scope,
            &specs,
            &mut services,
            &mut clients,
            &mut listeners,
            &mut frames,
            ArmAbi::U64Align8,
        )
        .expect("zero clients supported");
        assert_eq!(o.startup_next(), Ok(true));
        let (ticket, child) = match o.take_native().expect("epoch").expect("spawn") {
            NativeEffect::Spawn { ticket, child, .. } => (ticket, child),
            other => {
                assert!(matches!(other, NativeEffect::Spawn { .. }));
                return;
            }
        };
        o.sequence = u64::MAX;
        assert_eq!(
            o.spawned(ticket, SpawnOutcome::Admitted, 10)
                .expect("actual child retained")
                .resource_closures,
            0
        );
        o.services[0].native_epoch = u64::MAX;
        o.begin_shutdown(11);
        let ticket = match o
            .take_native()
            .expect("final TERM epoch independent")
            .expect("TERM")
        {
            NativeEffect::Term { ticket, .. } => ticket,
            other => {
                assert!(matches!(other, NativeEffect::Term { .. }));
                return;
            }
        };
        o.term_attempted(ticket).expect("actual TERM");
        assert_eq!(
            o.reaped(child, Exit::Exited(0), 12)
                .expect("actual wait")
                .resource_closures,
            0
        );
        assert!(o.children_drained());
    }
    #[test]
    fn startup_and_restart_cursor_never_skip_a_counter_exhausted_forced_service() {
        setup(|o| {
            o.phase = Phase::Configuring;
            o.startup_cursor = 0;
            o.services[0].force = true;
            o.services[0].generation = u64::MAX;
            assert_eq!(o.startup_next(), Err(Error::Exhausted));
            assert_eq!(o.startup_cursor, 0);
            assert_eq!(o.startup_next(), Err(Error::Exhausted));
            assert_eq!(o.startup_cursor, 0);
            assert_ne!(o.phase, Phase::Serving);
            o.phase = Phase::Serving;
            o.restart_scan = true;
            o.services[0].restart_at = 0;
            assert_eq!(o.restart(10), Err(Error::Exhausted));
            assert_eq!(o.scan_cursor, 0);
            assert_eq!(o.restart(10), Err(Error::Exhausted));
            assert_eq!(o.scan_cursor, 0);
            assert_eq!(o.services[0].process, Process::None);
            o.begin_shutdown(11);
            assert!(o.cleanup_ready());
        });
    }
    #[test]
    fn native_epoch_exhaustion_rejects_admission_before_reserving_or_starting() {
        setup(|o| {
            let c = o.connect().expect("client");
            o.services[0].native_epoch = u64::MAX;
            assert_eq!(o.start(c, WireId(1), b"s"), Err(Error::Exhausted));
            assert_eq!(o.services[0].process, Process::None);
            assert!(!o.services[0].force);
            assert!(o.frames.iter().all(|f| f.client.is_none()));
            o.phase = Phase::Configuring;
            o.startup_cursor = 0;
            o.services[0].force = true;
            assert_eq!(o.startup_next(), Err(Error::Exhausted));
            assert_eq!(o.startup_cursor, 0);
            o.begin_shutdown(2);
            assert!(o.cleanup_ready());
        });
    }
    #[test]
    fn listener_timer_native_and_output_max_cannot_block_actual_shutdown_cleanup() {
        let specs = [ServiceSpec {
            immediate: true,
            ..SPECS[0]
        }];
        let mut scope = OwnerScope::new();
        let mut services = [ServiceSlot::new()];
        let mut clients = [];
        let mut listeners = [ListenerSlot::new()];
        let mut frames = [];
        let mut o = Owner::new(
            &mut scope,
            &specs,
            &mut services,
            &mut clients,
            &mut listeners,
            &mut frames,
            ArmAbi::U64Align8,
        )
        .expect("owner");
        o.register_listener(o.service(0).expect("service"))
            .expect("actual bound listener");
        assert_eq!(o.startup_next(), Ok(true));
        let (ticket, child) = match o.take_native().expect("epoch").expect("spawn") {
            NativeEffect::Spawn { ticket, child, .. } => (ticket, child),
            other => {
                assert!(matches!(other, NativeEffect::Spawn { .. }));
                return;
            }
        };
        assert_eq!(
            o.spawned(ticket, SpawnOutcome::Admitted, 1)
                .expect("actual fork admitted")
                .resource_closures,
            0
        );
        assert_eq!(o.startup_next(), Ok(false));
        o.timer_epoch = u64::MAX - 1;
        o.restart_wake = Some(100);
        let timer = o.take_timer().expect("last timer epoch").expect("timer");
        o.timer_applied(timer.ticket).expect("actual task");
        o.listeners[0].epoch = u64::MAX;
        o.services[0].native_epoch = u64::MAX;
        o.sequence = u64::MAX;
        o.begin_shutdown(2);
        assert!(o.take_listener().expect("cancel task first").is_none());
        assert!(o.take_native().expect("cleanup order").is_none());
        let cancel = o
            .take_timer()
            .expect("cancel cannot mint a new epoch")
            .expect("cancel");
        assert_eq!(cancel.id, timer.id);
        o.timer_applied(cancel.ticket).expect("actually canceled");
        let close = o
            .take_listener()
            .expect("close existing listener, no new epoch")
            .expect("close");
        assert_eq!(close.action, ListenerAction::Close);
        assert!(o.take_native().expect("not closed until ack").is_none());
        o.listener_applied(close.ticket).expect("actually closed");
        let term = match o
            .take_native()
            .expect("final child capability independent")
            .expect("TERM")
        {
            NativeEffect::Term { ticket, .. } => ticket,
            other => {
                assert!(matches!(other, NativeEffect::Term { .. }));
                return;
            }
        };
        o.term_attempted(term).expect("actual TERM");
        assert!(!o.cleanup_ready());
        assert_eq!(
            o.reaped(child, Exit::Exited(0), 3)
                .expect("actually reaped")
                .resource_closures,
            0
        );
        assert!(o.cleanup_ready());
        let final_close = o
            .take_runtime_shutdown()
            .expect("final generic runtime effect");
        o.runtime_shutdown_applied(final_close)
            .expect("actually closed runtime");
        assert_eq!(o.phase, Phase::Closed);
    }
    #[test]
    fn exhausted_demand_records_consumed_registration_without_a_fake_starting_child() {
        for use_native_epoch in [false, true] {
            let mut scope = OwnerScope::new();
            let mut services = [ServiceSlot::new()];
            let mut clients = [];
            let mut listeners = [ListenerSlot::new(), ListenerSlot::new()];
            let mut frames = [];
            let mut o = Owner::new(
                &mut scope,
                &SPECS,
                &mut services,
                &mut clients,
                &mut listeners,
                &mut frames,
                ArmAbi::U64Align8,
            )
            .expect("owner");
            let service = o.service(0).expect("service");
            let first = o.register_listener(service).expect("actual bound first");
            o.register_listener(service).expect("actual bound sibling");
            assert_eq!(o.startup_next(), Ok(false));
            for _ in 0..2 {
                let arm = o.take_listener().expect("epoch").expect("arm");
                o.listener_applied(arm.ticket).expect("actual arm");
            }
            let event = o
                .readiness(first)
                .expect("listener")
                .expect("actual readiness registration");
            if use_native_epoch {
                o.services[0].native_epoch = u64::MAX;
            } else {
                o.services[0].generation = u64::MAX;
            }
            assert_eq!(o.demand(event), Err(Error::Exhausted));
            assert_eq!(o.services[0].process, Process::None);
            assert_eq!(o.readiness(first), Ok(None));
            assert_eq!(o.demand(event), Err(Error::Stale));
            let sibling = o
                .take_listener()
                .expect("epoch")
                .expect("cancel sibling readiness");
            assert_eq!(sibling.action, ListenerAction::Disarm);
            o.listener_applied(sibling.ticket)
                .expect("actually canceled");
            assert!(o.take_native().expect("no fake child grant").is_none());
            o.begin_shutdown(1);
            for _ in 0..2 {
                let close = o.take_listener().expect("cleanup lane").expect("close");
                o.listener_applied(close.ticket).expect("actually closed");
            }
            assert!(o.cleanup_ready());
        }
    }
    #[test]
    fn duplicate_monitor_needs_no_new_registration_epoch_when_counter_exhausted() {
        setup(|o| {
            let c = o.connect().expect("client");
            o.monitor(c).expect("initial registration");
            let frame = o.frame().expect("initial ack");
            let ticket = frame.ticket;
            o.release_frame(ticket).expect("actual host handoff");
            o.monitor_order = u64::MAX;
            o.clients[c.slot].monitor_order = u64::MAX;
            o.monitor(c)
                .expect("duplicate direct ack requires no new registration");
            assert_eq!(o.monitor_order, u64::MAX);
            let frame = o.frame().expect("actual duplicate ack");
            assert_eq!(
                frame.bytes,
                &[0, 12, 0, 11, 0, 0, 0, 0, b'a', b'r', b'm', 0]
            );
        });
    }
}
