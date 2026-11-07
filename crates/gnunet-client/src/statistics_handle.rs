//! Bounded long-lived owner of the eight official GNUnet STATISTICS operations.
//!
//! The queue follows v0.29.1 `statistics_api.c`. Connection epochs and operation
//! generations are local ownership metadata and are never put on the wire.
use crate::statistics::{self, Response, Selector, Set, Statistic, WatchValue};
use crate::statistics_owner::Brand;
pub use crate::statistics_owner::Instance;
use gnunet_types::{AbsoluteTime, Duration, Error, GenerationalId};
use gnunet_wire::official::{Frame, message_type};

/// Official `GNUNET_STATISTICS_VERSION` API constant. This is not a new wire field.
pub const VERSION: u32 = 0;

/// A GET owned by one handle instance; IDs from different owners are not interchangeable.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GetId<'owner>(GenerationalId, Brand<'owner>);
impl GetId<'_> {
    /// Local slot and generation, not a protocol request number.
    #[must_use]
    pub const fn resource_id(self) -> GenerationalId {
        self.0
    }
}
/// Stable logical subscription identity, separate from each connection's wire WID.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WatchId<'owner>(GenerationalId, Brand<'owner>);
impl WatchId<'_> {
    /// Local slot and generation, not a protocol watch number.
    #[must_use]
    pub const fn resource_id(self) -> GenerationalId {
        self.0
    }
}
/// One virtual service-connection/MQ lifetime. Initial socket retries retain this epoch.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectionEpoch<'owner>(u64, Brand<'owner>);
impl ConnectionEpoch<'_> {
    /// Local epoch value; never transmitted.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}
/// One admitted outgoing envelope in a connection epoch.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TransmitId<'owner>(u64, Brand<'owner>);
impl TransmitId<'_> {
    /// Local monotonic envelope number; never transmitted.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}
/// Local setter admission; none of these means remote execution or durable storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetterAdmission {
    /// A new action entered the pending queue.
    Queued,
    /// The first matching pending setter was updated in place.
    Coalesced,
    /// Calling update with zero performs no action, including no persistence change.
    Noop,
}
/// Why a frame was admitted to the host's bounded transmit queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundKind<'owner> {
    /// One original GET, retained until END or connection retirement.
    Get(GetId<'owner>),
    /// A setter without a per-operation protocol acknowledgement.
    Mutation {
        /// The official relative flag.
        relative: bool,
        /// The official persistence flag.
        persistent: bool,
    },
    /// One registration; a cancelled logical watch still consumes its connection WID.
    Watch {
        /// Fresh connection-local wire watch number.
        wire_id: u32,
        /// Live logical owner, or a cancelled-registration tombstone.
        logical: Option<WatchId<'owner>>,
    },
    /// The official processing barrier used during deferred destruction.
    Disconnect,
}
/// One encoded/admitted frame. The host must preserve these bytes until written
/// or retire this connection; it cannot re-encode them after later coalescing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Outbound<'owner> {
    /// Original virtual connection lifetime.
    pub epoch: ConnectionEpoch<'owner>,
    /// Original local envelope number.
    pub transmit: TransmitId<'owner>,
    /// Bytes encoded in the caller's scratch buffer.
    pub len: usize,
    /// Local ownership information for the encoded official frame.
    pub kind: OutboundKind<'owner>,
}
/// A checked incoming effect. GET rows borrow only frame bytes, not the handle,
/// so callbacks can admit commands before the next buffered row is processed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Inbound<'owner, 'a> {
    /// No row callback: END/confirmation was handled or a cancelled WID ignored.
    None,
    /// Row for exactly this current GET.
    GetValue {
        /// Original GET owner.
        get: GetId<'owner>,
        /// Borrowed official row bytes.
        statistic: Statistic<'a>,
    },
    /// Notification bound to a stable logical subscription.
    WatchValue {
        /// Original logical subscription owner.
        watch: WatchId<'owner>,
        /// Exact server fields; no wire-supplied selector exists here.
        notification: WatchValue,
    },
}
/// GET iterator result. Abort suppresses later rows but retains END continuation;
/// explicit get_cancel additionally suppresses that continuation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GetFlow {
    /// Accept later rows.
    Continue,
    /// Ignore later rows while draining the original END.
    AbortIteration,
}
/// An enabled GET continuation. Cancelled GETs do not create one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GetCompletion<'owner> {
    /// Original operation identity, including its slot generation.
    pub get: GetId<'owner>,
    /// Exact END is success; connection/protocol failure is an error.
    pub result: Result<(), Error>,
}
/// Final destruction result; processing confirmation never implies a disk sync.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestroyOutcome {
    /// Exact official DISCONNECT_CONFIRM was received in the expected state.
    ProcessingConfirmed,
    /// Immediate destruction discarded pending work, as the C API may do.
    Discarded,
    /// The original derived shutdown deadline elapsed.
    Deadline,
    /// The service connection failed before confirmation.
    ConnectionLost,
}
/// Honest local destruction accounting. Submitted setters are never silently retried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DestroyReport {
    /// Actual terminal event.
    pub outcome: DestroyOutcome,
    /// Pending setters discarded before host queue admission.
    pub queued_mutations_discarded: u64,
    /// Admitted setters with no processing confirmation, including older lost
    /// epochs that a later connection's barrier cannot acknowledge.
    pub unconfirmed_mutations: u64,
    /// Persistent subset of the unconfirmed setters.
    pub unconfirmed_persistent_mutations: u64,
}

#[derive(Clone, Copy)]
struct Names<const N: usize> {
    bytes: [u8; N],
    subsystem: usize,
    name: usize,
}
impl<const N: usize> Names<N> {
    fn new(selector: Selector<'_>) -> Result<Self, Error> {
        if selector.subsystem.contains(&0) || selector.name.contains(&0) {
            return Err(Error::InvalidInput);
        }
        let size = selector
            .subsystem
            .len()
            .checked_add(selector.name.len())
            .and_then(|n| n.checked_add(2))
            .ok_or(Error::Overflow)?;
        if size > N {
            return Err(Error::Capacity);
        }
        let mut bytes = [0; N];
        bytes[..selector.subsystem.len()].copy_from_slice(selector.subsystem);
        bytes[selector.subsystem.len() + 1..size - 1].copy_from_slice(selector.name);
        Ok(Self {
            bytes,
            subsystem: selector.subsystem.len(),
            name: selector.name.len(),
        })
    }
    fn selector(&self) -> Selector<'_> {
        Selector {
            subsystem: &self.bytes[..self.subsystem],
            name: &self.bytes[self.subsystem + 1..self.subsystem + 1 + self.name],
        }
    }
    fn byte_len(&self) -> usize {
        self.subsystem + self.name + 2
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum ActionKind<'owner> {
    Get,
    Set,
    Update,
    Watch(WatchId<'owner>),
}
#[derive(Clone, Copy)]
struct Action<'owner, const N: usize> {
    names: Names<N>,
    kind: ActionKind<'owner>,
    value: u64,
    persistent: bool,
    next: Option<usize>,
    queued: bool,
    aborted: bool,
    continuation: bool,
}
#[derive(Clone, Copy)]
struct Slot<'owner, const N: usize> {
    generation: u32,
    retired: bool,
    action: Option<Action<'owner, N>>,
}
impl<'owner, const N: usize> Slot<'owner, N> {
    const EMPTY: Self = Self {
        generation: 0,
        retired: false,
        action: None,
    };
}
#[derive(Clone, Copy)]
struct Watch<const N: usize> {
    names: Names<N>,
    order: u64,
}
#[derive(Clone, Copy)]
struct WatchSlot<const N: usize> {
    generation: u32,
    retired: bool,
    watch: Option<Watch<N>>,
}
impl<const N: usize> WatchSlot<N> {
    const EMPTY: Self = Self {
        generation: 0,
        retired: false,
        watch: None,
    };
}
#[derive(Clone, Copy)]
struct Transmit<'owner> {
    id: TransmitId<'owner>,
    started: bool,
    kind: OutboundKind<'owner>,
}
#[derive(Clone, Copy)]
enum DestroyState {
    Open,
    Draining {
        deadline: AbsoluteTime,
    },
    AwaitConfirm {
        deadline: AbsoluteTime,
    },
    Ready {
        deadline: AbsoluteTime,
        outcome: DestroyOutcome,
        cause: Error,
    },
    Closed,
}

/// Fixed-capacity implementation of the official long-lived statistics handle.
///
/// A bounds action slots, N bounds two owned selector strings including NULs,
/// W bounds live subscriptions, WW bounds all WIDs in one connection including
/// cancelled registrations, and T reserves non-droppable GET continuations.
/// The two-envelope host/MQ boundary distinguishes first send attempt from full
/// frame write and does not invent remote setter acknowledgements.
pub struct StatisticsHandle<
    'owner,
    const A: usize,
    const N: usize,
    const W: usize,
    const WW: usize,
    const T: usize,
> {
    instance: Brand<'owner>,
    subsystem: [u8; N],
    subsystem_len: usize,
    actions: [Slot<'owner, N>; A],
    head: Option<usize>,
    tail: Option<usize>,
    current: Option<usize>,
    watches: [WatchSlot<N>; W],
    watch_order: u64,
    wire: [Option<WatchId<'owner>>; WW],
    wire_issued: usize,
    connection: Option<ConnectionEpoch<'owner>>,
    next_epoch: u64,
    retry_at: Option<AbsoluteTime>,
    retry_pending: bool,
    backoff: Duration,
    ever_transport: bool,
    transmit: [Option<Transmit<'owner>>; 2],
    next_transmit: u64,
    completions: [Option<GetCompletion<'owner>>; T],
    completion_len: usize,
    get_reservations: usize,
    destroy: DestroyState,
    destroy_report: Option<DestroyReport>,
    unconfirmed: u64,
    unconfirmed_persistent: u64,
    current_unconfirmed: u64,
    current_unconfirmed_persistent: u64,
}

impl<'owner, const A: usize, const N: usize, const W: usize, const WW: usize, const T: usize>
    StatisticsHandle<'owner, A, N, W, WW, T>
{
    /// Create an enabled lazy owner or return None for official DISABLE=YES.
    /// Construction submits no connection or message.
    pub fn new(
        instance: &'owner mut Instance,
        subsystem: &[u8],
        enabled: bool,
    ) -> Result<Option<Self>, Error> {
        if !enabled {
            return Ok(None);
        }
        if subsystem.contains(&0) {
            return Err(Error::InvalidInput);
        }
        if subsystem.len() > N {
            return Err(Error::Capacity);
        }
        let mut own = [0; N];
        own[..subsystem.len()].copy_from_slice(subsystem);
        Ok(Some(Self {
            instance: Brand::new(instance),
            subsystem: own,
            subsystem_len: subsystem.len(),
            actions: [Slot::EMPTY; A],
            head: None,
            tail: None,
            current: None,
            watches: [WatchSlot::EMPTY; W],
            watch_order: 0,
            wire: [None; WW],
            wire_issued: 0,
            connection: None,
            next_epoch: 0,
            retry_at: None,
            retry_pending: false,
            backoff: Duration(1000),
            ever_transport: false,
            transmit: [None; 2],
            next_transmit: 0,
            completions: [None; T],
            completion_len: 0,
            get_reservations: 0,
            destroy: DestroyState::Open,
            destroy_report: None,
            unconfirmed: 0,
            unconfirmed_persistent: 0,
            current_unconfirmed: 0,
            current_unconfirmed_persistent: 0,
        }))
    }
    fn open(&self) -> Result<(), Error> {
        if matches!(self.destroy, DestroyState::Open) {
            Ok(())
        } else {
            Err(Error::Closed)
        }
    }
    fn check_epoch(&self, epoch: ConnectionEpoch<'owner>) -> Result<(), Error> {
        if self.connection == Some(epoch) {
            Ok(())
        } else {
            Err(Error::StaleGeneration)
        }
    }
    fn names(selector: Selector<'_>, fixed: usize) -> Result<Names<N>, Error> {
        let names = Names::new(selector)?;
        if names
            .byte_len()
            .checked_add(fixed)
            .is_none_or(|size| size > usize::from(u16::MAX))
        {
            return Err(Error::TooLarge);
        }
        Ok(names)
    }
    fn free_action_index(&self) -> Result<usize, Error> {
        let index = self
            .actions
            .iter()
            .position(|slot| !slot.retired && slot.action.is_none())
            .ok_or(Error::Capacity)?;
        u32::try_from(index).map_err(|_| Error::Overflow)?;
        Ok(index)
    }
    fn live_watch_id(&self, index: usize) -> WatchId<'owner> {
        WatchId(
            GenerationalId {
                index: index as u32,
                generation: self.watches[index].generation,
            },
            self.instance,
        )
    }
    fn watch_index(&self, id: WatchId<'owner>) -> Result<usize, Error> {
        if id.1 != self.instance {
            return Err(Error::Stale);
        }
        let index = usize::try_from(id.0.index).map_err(|_| Error::StaleGeneration)?;
        if self
            .watches
            .get(index)
            .is_some_and(|slot| slot.generation == id.0.generation && slot.watch.is_some())
        {
            Ok(index)
        } else {
            Err(Error::StaleGeneration)
        }
    }
    fn get_index(&self, id: GetId<'owner>) -> Result<usize, Error> {
        if id.1 != self.instance {
            return Err(Error::Stale);
        }
        let index = usize::try_from(id.0.index).map_err(|_| Error::StaleGeneration)?;
        if self.actions.get(index).is_some_and(|slot| {
            slot.generation == id.0.generation
                && slot
                    .action
                    .is_some_and(|action| action.kind == ActionKind::Get)
        }) {
            Ok(index)
        } else {
            Err(Error::StaleGeneration)
        }
    }
    fn missing_watch_actions(&self) -> usize {
        self.watches
            .iter()
            .enumerate()
            .filter(|(index, slot)| {
                slot.watch.is_some()
                    && !self.actions.iter().any(|action| {
                        action.action.is_some_and(|action| {
                            action.kind == ActionKind::Watch(self.live_watch_id(*index))
                        })
                    })
            })
            .count()
    }
    fn action_admission(&self) -> Result<(), Error> {
        let free = self
            .actions
            .iter()
            .filter(|slot| !slot.retired && slot.action.is_none())
            .count();
        if free <= self.missing_watch_actions() {
            Err(Error::Capacity)
        } else {
            Ok(())
        }
    }
    fn enqueue(&mut self, mut action: Action<'owner, N>) -> Result<usize, Error> {
        let index = self.free_action_index()?;
        if self.tail.is_some_and(|tail| {
            self.actions
                .get(tail)
                .and_then(|s| s.action.as_ref())
                .is_none()
        }) {
            return Err(Error::Stale);
        }
        action.next = None;
        action.queued = true;
        self.actions[index].action = Some(action);
        if let Some(tail) = self.tail {
            if let Some(prior) = self.actions[tail].action.as_mut() {
                prior.next = Some(index);
            }
        } else {
            self.head = Some(index);
        }
        self.tail = Some(index);
        Ok(index)
    }
    fn unlink(&mut self, index: usize) -> Result<Action<'owner, N>, Error> {
        let mut current = self.head;
        let mut previous: Option<usize> = None;
        for _ in 0..A {
            let Some(position) = current else {
                break;
            };
            let mut action = self.actions[position].action.ok_or(Error::Stale)?;
            if position == index {
                if let Some(previous) = previous {
                    if let Some(prior) = self.actions[previous].action.as_mut() {
                        prior.next = action.next;
                    }
                } else {
                    self.head = action.next;
                }
                if self.tail == Some(index) {
                    self.tail = previous;
                }
                action.queued = false;
                action.next = None;
                self.actions[index].action = Some(action);
                return Ok(action);
            }
            previous = Some(position);
            current = action.next;
        }
        Err(Error::Stale)
    }
    fn free_action(&mut self, index: usize) {
        self.actions[index].action = None;
        if let Some(generation) = self.actions[index].generation.checked_add(1) {
            self.actions[index].generation = generation;
        } else {
            self.actions[index].retired = true;
        }
    }
    fn finish_get(&mut self, index: usize, result: Option<Result<(), Error>>) -> Result<(), Error> {
        if result.is_some() && self.completion_len >= T {
            return Err(Error::Capacity);
        }
        let id = GetId(
            GenerationalId {
                index: u32::try_from(index).map_err(|_| Error::Overflow)?,
                generation: self.actions[index].generation,
            },
            self.instance,
        );
        if let Some(result) = result {
            self.completions[self.completion_len] = Some(GetCompletion { get: id, result });
            self.completion_len += 1;
        } else {
            self.get_reservations -= 1;
        }
        self.free_action(index);
        Ok(())
    }
    fn action(
        names: Names<N>,
        kind: ActionKind<'owner>,
        value: u64,
        persistent: bool,
    ) -> Action<'owner, N> {
        Action {
            names,
            kind,
            value,
            persistent,
            next: None,
            queued: true,
            aborted: false,
            continuation: true,
        }
    }
    fn add_setter(
        &mut self,
        name: &[u8],
        value: u64,
        persistent: bool,
        kind: ActionKind<'owner>,
    ) -> Result<SetterAdmission, Error> {
        self.open()?;
        let names = Self::names(
            Selector {
                subsystem: &self.subsystem[..self.subsystem_len],
                name,
            },
            16,
        )?;
        let mut current = self.head;
        for _ in 0..A {
            let Some(index) = current else {
                break;
            };
            let mut action = self.actions[index].action.ok_or(Error::Stale)?;
            current = action.next;
            if !matches!(action.kind, ActionKind::Set | ActionKind::Update)
                || action.names.selector() != names.selector()
            {
                continue;
            }
            if action.kind == ActionKind::Set && kind == ActionKind::Update {
                let delta = value as i64;
                action.value = if delta < 0 {
                    action.value.saturating_sub(delta.unsigned_abs())
                } else {
                    action.value.wrapping_add(value)
                };
            } else if kind == ActionKind::Set {
                action.kind = ActionKind::Set;
                action.value = value;
            } else {
                action.value = action.value.wrapping_add(value);
            }
            action.persistent = persistent;
            self.actions[index].action = Some(action);
            return Ok(SetterAdmission::Coalesced);
        }
        self.action_admission()?;
        self.enqueue(Self::action(names, kind, value, persistent))?;
        Ok(SetterAdmission::Queued)
    }
    /// Queue an absolute SET, coalescing the first same-name pending setter even
    /// across intervening GETs, as the official C handle does.
    pub fn set(
        &mut self,
        name: &[u8],
        value: u64,
        persistent: bool,
    ) -> Result<SetterAdmission, Error> {
        self.add_setter(name, value, persistent, ActionKind::Set)
    }
    /// Queue a signed update. A newly called zero update is a complete no-op;
    /// coalesced nonzero updates that sum to zero remain a real pending UPDATE.
    pub fn update(
        &mut self,
        name: &[u8],
        delta: i64,
        persistent: bool,
    ) -> Result<SetterAdmission, Error> {
        if delta == 0 {
            return Ok(SetterAdmission::Noop);
        }
        self.add_setter(name, delta as u64, persistent, ActionKind::Update)
    }
    /// Admit one GET and reserve its eventual continuation before any state changes.
    pub fn get(&mut self, selector: Selector<'_>) -> Result<GetId<'owner>, Error> {
        self.open()?;
        let names = Self::names(selector, 4)?;
        if self.get_reservations >= T {
            return Err(Error::Capacity);
        }
        self.action_admission()?;
        let index = self.enqueue(Self::action(names, ActionKind::Get, 0, false))?;
        self.get_reservations += 1;
        Ok(GetId(
            GenerationalId {
                index: index as u32,
                generation: self.actions[index].generation,
            },
            self.instance,
        ))
    }
    /// Suppress this same instance's GET callbacks. A current request remains a
    /// stream tombstone until its END; it does not close or reuse the connection.
    pub fn get_cancel(&mut self, id: GetId<'owner>) -> Result<(), Error> {
        if let Some(index) = self.completions[..self.completion_len]
            .iter()
            .position(|item| item.is_some_and(|item| item.get == id))
        {
            self.completions
                .copy_within(index + 1..self.completion_len, index);
            self.completion_len -= 1;
            self.completions[self.completion_len] = None;
            self.get_reservations -= 1;
            return Ok(());
        }
        let index = self.get_index(id)?;
        let mut action = self.actions[index].action.ok_or(Error::Stale)?;
        if action.queued {
            self.unlink(index)?;
            self.finish_get(index, None)?;
        } else if self.current == Some(index) {
            action.aborted = true;
            action.continuation = false;
            self.actions[index].action = Some(action);
        } else {
            return Err(Error::Stale);
        }
        Ok(())
    }
    /// Apply the current GET iterator's result. Continue never undoes a cancel
    /// that was admitted reentrantly from that callback.
    pub fn get_value_result(&mut self, id: GetId<'owner>, flow: GetFlow) -> Result<(), Error> {
        let index = self.get_index(id)?;
        if self.current != Some(index) {
            return Err(Error::Stale);
        }
        if flow == GetFlow::AbortIteration
            && let Some(action) = self.actions[index].action.as_mut()
        {
            action.aborted = true;
        }
        Ok(())
    }
    /// Register one literal selector and stable logical owner. Logical slots can
    /// be reused only with a fresh generation; connection WIDs are never reused.
    pub fn watch(&mut self, selector: Selector<'_>) -> Result<WatchId<'owner>, Error> {
        self.open()?;
        let names = Self::names(selector, 4)?;
        let index = self
            .watches
            .iter()
            .position(|slot| !slot.retired && slot.watch.is_none())
            .ok_or(Error::Capacity)?;
        u32::try_from(index).map_err(|_| Error::Overflow)?;
        let queued = self
            .actions
            .iter()
            .filter(|slot| {
                slot.action
                    .is_some_and(|a| matches!(a.kind, ActionKind::Watch(_)) && a.queued)
            })
            .count();
        let required = if self.connection.is_some() {
            self.wire_issued
                .checked_add(queued)
                .and_then(|n| n.checked_add(1))
        } else {
            self.watches
                .iter()
                .filter(|slot| slot.watch.is_some())
                .count()
                .checked_add(1)
        }
        .ok_or(Error::Overflow)?;
        if required > WW {
            return Err(Error::Capacity);
        }
        self.action_admission()?;
        let order = self.watch_order.checked_add(1).ok_or(Error::Overflow)?;
        let id = self.live_watch_id(index);
        self.enqueue(Self::action(names, ActionKind::Watch(id), 0, false))?;
        self.watches[index].watch = Some(Watch { names, order });
        self.watch_order = order;
        Ok(id)
    }
    /// Cancel this instance's logical subscription. Already queued registration
    /// copies are retained, so they still consume the original connection WID.
    pub fn watch_cancel(&mut self, id: WatchId<'owner>) -> Result<(), Error> {
        let index = self.watch_index(id)?;
        self.watches[index].watch = None;
        if let Some(generation) = self.watches[index].generation.checked_add(1) {
            self.watches[index].generation = generation;
        } else {
            self.watches[index].retired = true;
        }
        for binding in &mut self.wire {
            if *binding == Some(id) {
                *binding = None;
            }
        }
        Ok(())
    }
    /// Copy a live watch's original names into caller scratch. The result borrows
    /// only that scratch, permitting a mutable callback context on this handle.
    pub fn watch_selector<'a>(
        &self,
        id: WatchId<'owner>,
        output: &'a mut [u8],
    ) -> Result<Selector<'a>, Error> {
        let index = self.watch_index(id)?;
        let names = self.watches[index].watch.ok_or(Error::Stale)?.names;
        if output.len() < names.byte_len() {
            return Err(Error::Capacity);
        }
        output[..names.byte_len()].copy_from_slice(&names.bytes[..names.byte_len()]);
        Ok(Selector {
            subsystem: &output[..names.subsystem],
            name: &output[names.subsystem + 1..names.subsystem + 1 + names.name],
        })
    }
    /// Whether the next virtual MQ can be created now. After a connection error
    /// the persistent owner reconnects even when its action queue is currently empty.
    #[must_use]
    pub fn connection_needed(&self, now: AbsoluteTime) -> bool {
        matches!(self.destroy, DestroyState::Open)
            && !self.retry_pending
            && self.connection.is_none()
            && (self.ever_transport || self.head.is_some())
            && self
                .retry_at
                .is_none_or(|deadline| deadline.as_micros() != u64::MAX && now >= deadline)
    }
    /// Create a new virtual MQ lifetime. Drop stale queued WATCH copies and append
    /// live subscriptions in original registration order after pending GET/setters.
    /// Initial socket-connect retries must retain this epoch and admitted frames.
    pub fn begin_connection(
        &mut self,
        now: AbsoluteTime,
    ) -> Result<ConnectionEpoch<'owner>, Error> {
        if !self.connection_needed(now) {
            return Err(Error::NotReady);
        }
        let epoch = ConnectionEpoch(
            self.next_epoch.checked_add(1).ok_or(Error::Overflow)?,
            self.instance,
        );
        let live = self
            .watches
            .iter()
            .filter(|slot| slot.watch.is_some())
            .count();
        let usable = self
            .actions
            .iter()
            .filter(|slot| {
                !slot.retired
                    && (slot.action.is_none()
                        || slot.action.is_some_and(|action| {
                            action.queued
                                && matches!(action.kind, ActionKind::Watch(_))
                                && slot.generation < u32::MAX
                        }))
            })
            .count();
        if live > usable {
            return Err(Error::Capacity);
        }
        for index in 0..A {
            if self.actions[index]
                .action
                .is_some_and(|action| matches!(action.kind, ActionKind::Watch(_)) && action.queued)
            {
                self.unlink(index)?;
                self.free_action(index);
            }
        }
        let mut after = 0;
        for _ in 0..live {
            let next = self
                .watches
                .iter()
                .enumerate()
                .filter_map(|(index, slot)| slot.watch.map(|watch| (index, watch)))
                .filter(|(_, watch)| watch.order > after)
                .min_by_key(|(_, watch)| watch.order)
                .ok_or(Error::Stale)?;
            self.enqueue(Self::action(
                next.1.names,
                ActionKind::Watch(self.live_watch_id(next.0)),
                0,
                false,
            ))?;
            after = next.1.order;
        }
        self.wire.fill(None);
        self.wire_issued = 0;
        self.transmit.fill(None);
        self.connection = Some(epoch);
        self.next_epoch = epoch.0;
        self.retry_at = None;
        self.ever_transport = true;
        Ok(epoch)
    }
    /// Encode and admit one immutable outgoing envelope after the host preflights
    /// its own two-envelope queue. Capacity refusal preserves output/state. Once
    /// admitted, mutation actions are not replayed on connection loss.
    pub fn next_request(
        &mut self,
        epoch: ConnectionEpoch<'owner>,
        output: &mut [u8],
    ) -> Result<Option<Outbound<'owner>>, Error> {
        self.check_epoch(epoch)?;
        if self.is_closed()
            || self.current.is_some()
            || self.mq_nontransmitted_length() != 0
            || self.transmit_count() >= 2
        {
            return Ok(None);
        }
        let tx = TransmitId(
            self.next_transmit.checked_add(1).ok_or(Error::Overflow)?,
            self.instance,
        );
        let (len, kind, index) = if let Some(index) = self.head {
            let action = self.actions[index].action.ok_or(Error::Stale)?;
            let selector = action.names.selector();
            match action.kind {
                ActionKind::Get => (
                    selector.encode_get(output)?,
                    OutboundKind::Get(GetId(
                        GenerationalId {
                            index: index as u32,
                            generation: self.actions[index].generation,
                        },
                        self.instance,
                    )),
                    Some(index),
                ),
                ActionKind::Set | ActionKind::Update => {
                    self.unconfirmed.checked_add(1).ok_or(Error::Overflow)?;
                    if action.persistent {
                        self.unconfirmed_persistent
                            .checked_add(1)
                            .ok_or(Error::Overflow)?;
                    }
                    let relative = action.kind == ActionKind::Update;
                    let flags = if relative {
                        statistics::SET_RELATIVE
                    } else {
                        0
                    } | if action.persistent {
                        statistics::SET_PERSISTENT
                    } else {
                        0
                    };
                    (
                        Set {
                            selector,
                            flags,
                            value: action.value,
                        }
                        .encode(output)?,
                        OutboundKind::Mutation {
                            relative,
                            persistent: action.persistent,
                        },
                        Some(index),
                    )
                }
                ActionKind::Watch(id) => {
                    if self.wire_issued >= WW {
                        return Err(Error::Capacity);
                    }
                    let wire_id = u32::try_from(self.wire_issued).map_err(|_| Error::Overflow)?;
                    let logical = if self.watch_index(id).is_ok() {
                        Some(id)
                    } else {
                        None
                    };
                    (
                        selector.encode_watch(output)?,
                        OutboundKind::Watch { wire_id, logical },
                        Some(index),
                    )
                }
            }
        } else if matches!(self.destroy, DestroyState::Draining { .. }) {
            (
                statistics::encode_disconnect(output)?,
                OutboundKind::Disconnect,
                None,
            )
        } else {
            return Ok(None);
        };
        if let Some(index) = index {
            self.unlink(index)?;
            match kind {
                OutboundKind::Get(_) => self.current = Some(index),
                OutboundKind::Mutation { persistent, .. } => {
                    self.unconfirmed += 1;
                    self.unconfirmed_persistent += u64::from(persistent);
                    self.current_unconfirmed += 1;
                    self.current_unconfirmed_persistent += u64::from(persistent);
                    self.free_action(index);
                }
                OutboundKind::Watch { logical, .. } => {
                    self.wire[self.wire_issued] = logical;
                    self.wire_issued += 1;
                    self.free_action(index);
                }
                OutboundKind::Disconnect => {}
            }
        }
        if kind == OutboundKind::Disconnect
            && let DestroyState::Draining { deadline } = self.destroy
        {
            self.destroy = DestroyState::AwaitConfirm { deadline };
        }
        let slot = self
            .transmit
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(Error::Capacity)?;
        *slot = Some(Transmit {
            id: tx,
            started: false,
            kind,
        });
        self.next_transmit = tx.0;
        Ok(Some(Outbound {
            epoch,
            transmit: tx,
            len,
            kind,
        }))
    }
    /// Mark the front envelope irreversible after a partial/zero-progress first
    /// send attempt, like MQ_impl_send_in_flight. This is not remote execution.
    pub fn on_first_send_attempt(
        &mut self,
        epoch: ConnectionEpoch<'owner>,
        id: TransmitId<'owner>,
    ) -> Result<(), Error> {
        self.check_epoch(epoch)?;
        let front = self.transmit[0].as_mut().ok_or(Error::Stale)?;
        if front.id != id {
            return Err(Error::Conflict);
        }
        front.started = true;
        Ok(())
    }
    /// Finish the front frame. A full first write may call this directly without
    /// on_first_send_attempt, matching MQ_impl_send_continue. SET is still unacknowledged.
    pub fn on_frame_written(
        &mut self,
        epoch: ConnectionEpoch<'owner>,
        id: TransmitId<'owner>,
    ) -> Result<(), Error> {
        self.check_epoch(epoch)?;
        if !self.transmit[0].is_some_and(|front| front.id == id) {
            return Err(Error::Stale);
        }
        self.transmit[0] = self.transmit[1];
        self.transmit[1] = None;
        Ok(())
    }
    /// Decode one complete frame in its original epoch. Protocol failures retire
    /// that epoch and require the host to close its actual stream. Stale epochs
    /// are rejected without touching a replacement connection.
    pub fn receive<'a>(
        &mut self,
        epoch: ConnectionEpoch<'owner>,
        bytes: &'a [u8],
        now: AbsoluteTime,
    ) -> Result<Inbound<'owner, 'a>, Error> {
        self.receive_owned(epoch, bytes, now, false)
    }
    /// Receive with original retirement/callback authority but defer reading
    /// retry time until the host has returned the original GET continuation.
    pub fn receive_staged<'a>(
        &mut self,
        epoch: ConnectionEpoch<'owner>,
        bytes: &'a [u8],
        now: AbsoluteTime,
    ) -> Result<Inbound<'owner, 'a>, Error> {
        self.receive_owned(epoch, bytes, now, true)
    }
    fn receive_owned<'a>(
        &mut self,
        epoch: ConnectionEpoch<'owner>,
        bytes: &'a [u8],
        now: AbsoluteTime,
        staged: bool,
    ) -> Result<Inbound<'owner, 'a>, Error> {
        self.check_epoch(epoch)?;
        if matches!(self.destroy,DestroyState::Draining{deadline}|DestroyState::AwaitConfirm{deadline} if deadline.as_micros()!=u64::MAX && now>=deadline)
        {
            self.finish_destroy(DestroyOutcome::Deadline, Error::Deadline)?;
            return Err(Error::Deadline);
        }
        let result = self.receive_inner(bytes);
        if let Err(error) = result {
            self.prepare_connection_lost(epoch, error)?;
            if !staged && self.retry_pending {
                self.register_retry(now)?;
            }
        }
        result
    }
    fn receive_inner<'a>(&mut self, bytes: &'a [u8]) -> Result<Inbound<'owner, 'a>, Error> {
        let frame = Frame::decode(bytes)?;
        match frame.header().message_type() {
            message_type::STATISTICS_VALUE => {
                let Response::Value(statistic) = Response::decode(bytes)? else {
                    return Err(Error::Malformed);
                };
                let index = self.current.ok_or(Error::Malformed)?;
                let action = self.actions[index].action.ok_or(Error::Stale)?;
                if action.kind != ActionKind::Get {
                    return Err(Error::Malformed);
                }
                if action.aborted {
                    return Ok(Inbound::None);
                }
                Ok(Inbound::GetValue {
                    get: GetId(
                        GenerationalId {
                            index: index as u32,
                            generation: self.actions[index].generation,
                        },
                        self.instance,
                    ),
                    statistic,
                })
            }
            message_type::STATISTICS_END => {
                if Response::decode(bytes)? != Response::End {
                    return Err(Error::Malformed);
                }
                let index = self.current.ok_or(Error::Malformed)?;
                let action = self.actions[index].action.ok_or(Error::Stale)?;
                self.finish_get(
                    index,
                    if action.continuation {
                        Some(Ok(()))
                    } else {
                        None
                    },
                )?;
                self.current = None;
                self.backoff = Duration(1000);
                Ok(Inbound::None)
            }
            message_type::STATISTICS_WATCH_VALUE => {
                let notification = WatchValue::decode(bytes)?;
                let index = usize::try_from(notification.wid).map_err(|_| Error::Malformed)?;
                if index >= self.wire_issued {
                    return Err(Error::Malformed);
                }
                match self.wire[index] {
                    Some(watch) if self.watch_index(watch).is_ok() => Ok(Inbound::WatchValue {
                        watch,
                        notification,
                    }),
                    _ => Ok(Inbound::None),
                }
            }
            message_type::STATISTICS_DISCONNECT_CONFIRM => {
                statistics::confirm_disconnect(bytes)?;
                // A peer cannot acknowledge our processing barrier before its
                // complete frame was actually written. Normal C peers satisfy
                // this even when the host received readability immediately.
                if !matches!(self.destroy, DestroyState::AwaitConfirm { .. })
                    || self
                        .transmit
                        .iter()
                        .flatten()
                        .any(|tx| tx.kind == OutboundKind::Disconnect)
                {
                    return Err(Error::Malformed);
                }
                let DestroyState::AwaitConfirm { deadline } = self.destroy else {
                    return Err(Error::Malformed);
                };
                self.destroy = DestroyState::Ready {
                    deadline,
                    outcome: DestroyOutcome::ProcessingConfirmed,
                    cause: Error::Cancelled,
                };
                Ok(Inbound::None)
            }
            // GNUNET_MQ_inject_message ignores a well-framed message with no
            // registered handler. It must not retire the current GET/epoch.
            _ => Ok(Inbound::None),
        }
    }
    /// Report that the host could not create a virtual MQ at all, as when
    /// `GNUNET_CLIENT_connect` rejects the service configuration. Pending actions
    /// remain unsubmitted and coalescible; no epoch or watch WID is allocated.
    pub fn connection_unavailable(&mut self, now: AbsoluteTime) -> Result<(), Error> {
        self.prepare_connection_unavailable(now)?;
        self.register_retry(now)
    }
    /// Retain a failed MQ-creation effect before its source-time registration.
    /// The host must sample after that effect, then call register_retry once.
    pub fn prepare_connection_unavailable(&mut self, now: AbsoluteTime) -> Result<(), Error> {
        self.open()?;
        if !self.connection_needed(now) {
            return Err(Error::NotReady);
        }
        self.ever_transport = true;
        self.retry_at = None;
        self.retry_pending = true;
        Ok(())
    }
    /// Whether the original retired connection/configuration is waiting for
    /// callback return and its one source-time registration. No deadline exists
    /// yet, so admission must not fabricate or reuse an old retry timestamp.
    #[must_use]
    pub const fn retry_registration_pending(&self) -> bool {
        self.retry_pending
    }
    /// Register the original pending retry after synchronous GET continuation.
    /// Saturating absolute conversion preserves C's public FOREVER semantics.
    pub fn register_retry(&mut self, now: AbsoluteTime) -> Result<(), Error> {
        self.open()?;
        if !self.retry_pending {
            return Err(Error::NotReady);
        }
        self.retry_at = Some(AbsoluteTime::from_micros(
            now.as_micros().saturating_add(self.backoff.0),
        ));
        self.retry_pending = false;
        self.backoff = Duration(self.backoff.0.saturating_mul(2).min(900_000_000));
        Ok(())
    }
    /// Retire an established/fatally failed MQ, fail a non-aborted current GET,
    /// keep pending non-watch actions, and schedule the original retry backoff.
    /// Initial socket connect retries are transport-local and must not call this.
    pub fn connection_lost(
        &mut self,
        epoch: ConnectionEpoch<'owner>,
        cause: Error,
        now: AbsoluteTime,
    ) -> Result<(), Error> {
        self.prepare_connection_lost(epoch, cause)?;
        if self.retry_pending {
            self.register_retry(now)?;
        }
        Ok(())
    }
    /// Retire this exact MQ and queue its original GET continuation before
    /// reading a retry clock. Caller dispatches that continuation synchronously,
    /// then register_retry consumes the still-pending registration once.
    pub fn prepare_connection_lost(
        &mut self,
        epoch: ConnectionEpoch<'owner>,
        cause: Error,
    ) -> Result<(), Error> {
        self.check_epoch(epoch)?;
        if self.is_destroying() {
            return self.finish_destroy(DestroyOutcome::ConnectionLost, cause);
        }
        if let Some(index) = self.current {
            let action = self.actions[index].action.ok_or(Error::Stale)?;
            self.finish_get(
                index,
                if action.continuation && !action.aborted {
                    Some(Err(cause))
                } else {
                    None
                },
            )?;
            self.current = None;
        }
        self.connection = None;
        self.transmit.fill(None);
        self.wire.fill(None);
        self.wire_issued = 0;
        self.current_unconfirmed = 0;
        self.current_unconfirmed_persistent = 0;
        self.retry_at = None;
        self.retry_pending = true;
        Ok(())
    }
    fn queued_mutations(&self) -> u64 {
        self.actions
            .iter()
            .filter(|slot| {
                slot.action.is_some_and(|action| {
                    action.queued && matches!(action.kind, ActionKind::Set | ActionKind::Update)
                })
            })
            .count() as u64
    }
    fn finish_destroy(&mut self, outcome: DestroyOutcome, cause: Error) -> Result<(), Error> {
        let queued = self.queued_mutations();
        if let Some(index) = self.current {
            let action = self.actions[index].action.ok_or(Error::Stale)?;
            self.finish_get(
                index,
                if action.continuation && !action.aborted {
                    Some(Err(cause))
                } else {
                    None
                },
            )?;
            self.current = None;
        }
        for index in 0..A {
            if let Some(action) = self.actions[index].action {
                if action.kind == ActionKind::Get {
                    self.get_reservations -= 1;
                }
                self.free_action(index);
            }
        }
        for slot in &mut self.watches {
            if slot.watch.take().is_some() {
                if let Some(generation) = slot.generation.checked_add(1) {
                    slot.generation = generation;
                } else {
                    slot.retired = true;
                }
            }
        }
        let confirmed = outcome == DestroyOutcome::ProcessingConfirmed;
        self.destroy_report = Some(DestroyReport {
            outcome,
            queued_mutations_discarded: queued,
            unconfirmed_mutations: if confirmed {
                self.unconfirmed - self.current_unconfirmed
            } else {
                self.unconfirmed
            },
            unconfirmed_persistent_mutations: if confirmed {
                self.unconfirmed_persistent - self.current_unconfirmed_persistent
            } else {
                self.unconfirmed_persistent
            },
        });
        self.head = None;
        self.tail = None;
        self.connection = None;
        self.retry_at = None;
        self.transmit.fill(None);
        self.wire.fill(None);
        self.wire_issued = 0;
        self.retry_pending = false;
        self.destroy = DestroyState::Closed;
        Ok(())
    }
    /// Begin official destruction once. sync_first defers only when a virtual MQ
    /// has non-transmitted envelopes, following the pinned API's actual condition.
    /// It drops queued GET/WATCH actions, drains setters/current GET, then emits
    /// DISCONNECT. The fixed shutdown deadline is five times the current backoff.
    /// Immediate cleanup is reported Discarded, never fabricated confirmation.
    pub fn begin_destroy(&mut self, sync_first: bool, now: AbsoluteTime) -> Result<(), Error> {
        self.open()?;
        if !sync_first || self.connection.is_none() || self.mq_nontransmitted_length() == 0 {
            return self.finish_destroy(DestroyOutcome::Discarded, Error::Cancelled);
        }
        let timeout = Duration(self.backoff.0.checked_mul(5).ok_or(Error::Overflow)?);
        let deadline = AbsoluteTime::from_micros(now.as_micros().saturating_add(timeout.0));
        for index in 0..A {
            if self.actions[index].action.is_some_and(|action| {
                action.queued && matches!(action.kind, ActionKind::Get | ActionKind::Watch(_))
            }) {
                let action = self.unlink(index)?;
                if action.kind == ActionKind::Get {
                    self.finish_get(index, None)?;
                } else {
                    self.free_action(index);
                }
            }
        }
        if let Some(index) = self.current
            && let Some(action) = self.actions[index].action.as_mut()
        {
            action.aborted = true;
        }
        self.destroy = DestroyState::Draining { deadline };
        Ok(())
    }
    /// Enforce only the already-admitted destruction deadline. The C source's
    /// unused setter timeout field is not turned into invented expiry behavior.
    pub fn tick(&mut self, now: AbsoluteTime) -> Result<(), Error> {
        if self.ready_destroy_pending() {
            return self.finalize_ready_destroy();
        }
        if let DestroyState::Draining { deadline } | DestroyState::AwaitConfirm { deadline } =
            self.destroy
            && deadline.as_micros() != u64::MAX
            && now >= deadline
        {
            self.finish_destroy(DestroyOutcome::Deadline, Error::Deadline)?;
        }
        Ok(())
    }
    /// Original retry/shutdown wakeup, or no timer. Initial actions require an
    /// immediate virtual connection rather than an invented delayed deadline.
    #[must_use]
    pub fn next_wakeup(&self) -> Option<AbsoluteTime> {
        match self.destroy {
            DestroyState::Draining { deadline } | DestroyState::AwaitConfirm { deadline } => {
                Some(deadline)
            }
            DestroyState::Ready { .. } => Some(AbsoluteTime::from_micros(0)),
            DestroyState::Open => self.retry_at,
            DestroyState::Closed => None,
        }
    }
    /// Original admitted destruction deadline, including while its final
    /// add_now cleanup is ready. This is local scheduling data, never wire time.
    #[must_use]
    pub const fn destruction_deadline(&self) -> Option<AbsoluteTime> {
        match self.destroy {
            DestroyState::Draining { deadline }
            | DestroyState::AwaitConfirm { deadline }
            | DestroyState::Ready { deadline, .. } => Some(deadline),
            _ => None,
        }
    }
    /// Whether the final source add_now task has already entered its ready queue.
    #[must_use]
    pub const fn ready_destroy_pending(&self) -> bool {
        matches!(self.destroy, DestroyState::Ready { .. })
    }
    /// Run only that original ready finalizer without sampling a clock again.
    pub fn finalize_ready_destroy(&mut self) -> Result<(), Error> {
        let DestroyState::Ready {
            deadline: _,
            outcome,
            cause,
        } = self.destroy
        else {
            return Err(Error::NotReady);
        };
        self.finish_destroy(outcome, cause)
    }
    /// Consume one reserved GET continuation. Queued/explicitly cancelled GETs
    /// and interrupted aborted iterations do not manufacture callbacks.
    pub fn take_completion(&mut self) -> Option<GetCompletion<'owner>> {
        if self.completion_len == 0 {
            return None;
        }
        let completion = self.completions[0].take();
        self.completions.copy_within(1..self.completion_len, 0);
        self.completion_len -= 1;
        self.completions[self.completion_len] = None;
        self.get_reservations -= 1;
        completion
    }
    /// Consume the final destruction report once, after dispatching any already
    /// queued GET continuation. Processing confirmation is not disk durability.
    pub fn take_destroy_report(&mut self) -> Option<DestroyReport> {
        self.destroy_report.take()
    }
    /// Current virtual MQ lifetime; actual socket readiness is owned by the host.
    #[must_use]
    pub const fn connection_epoch(&self) -> Option<ConnectionEpoch<'owner>> {
        self.connection
    }
    /// Whether destruction permanently retired this owner.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        matches!(self.destroy, DestroyState::Closed)
    }
    /// Whether asynchronous destruction is draining or awaiting confirmation.
    #[must_use]
    pub fn is_destroying(&self) -> bool {
        matches!(
            self.destroy,
            DestroyState::Draining { .. }
                | DestroyState::AwaitConfirm { .. }
                | DestroyState::Ready { .. }
        )
    }
    /// Pending action count, excluding current GET and host-owned envelopes.
    #[must_use]
    pub fn pending_actions(&self) -> usize {
        self.actions
            .iter()
            .filter(|slot| slot.action.is_some_and(|action| action.queued))
            .count()
    }
    /// Current GET owner, including a cancelled stream tombstone until END.
    #[must_use]
    pub fn active_get(&self) -> Option<GetId<'owner>> {
        self.current.map(|index| {
            GetId(
                GenerationalId {
                    index: index as u32,
                    generation: self.actions[index].generation,
                },
                self.instance,
            )
        })
    }
    /// Number of currently live logical subscriptions, excluding cancelled WIDs.
    #[must_use]
    pub fn live_watches(&self) -> usize {
        self.watches
            .iter()
            .filter(|slot| slot.watch.is_some())
            .count()
    }
    /// Whether an operation still owns a queued/current GET or reserved terminal.
    /// A cancelled current GET remains an owner only for draining its END.
    #[must_use]
    pub fn owns_get(&self, id: GetId<'owner>) -> bool {
        self.get_index(id).is_ok()
            || self.completions[..self.completion_len]
                .iter()
                .any(|completion| completion.is_some_and(|c| c.get == id))
    }
    /// Whether a GET can still produce a row/continuation callback. Runtime maps
    /// can release explicitly cancelled or interrupted-aborted callback closures
    /// without waiting for a fabricated completion event.
    #[must_use]
    pub fn get_callbacks_enabled(&self, id: GetId<'owner>) -> bool {
        self.get_index(id)
            .ok()
            .and_then(|index| self.actions[index].action)
            .is_some_and(|action| action.continuation)
            || self.completions[..self.completion_len]
                .iter()
                .any(|completion| completion.is_some_and(|c| c.get == id))
    }
    /// Whether a logical subscription still owns callbacks in this handle.
    #[must_use]
    pub fn owns_watch(&self, id: WatchId<'owner>) -> bool {
        self.watch_index(id).is_ok()
    }
    /// MQ envelope count excluding the front envelope after its first send attempt.
    #[must_use]
    pub fn mq_nontransmitted_length(&self) -> usize {
        self.transmit
            .iter()
            .flatten()
            .filter(|tx| !tx.started)
            .count()
    }
    /// Number of host envelopes still owned, at most two.
    #[must_use]
    pub fn transmit_count(&self) -> usize {
        self.transmit.iter().flatten().count()
    }
    /// Reserved continuations waiting for application dispatch.
    #[must_use]
    pub const fn pending_completions(&self) -> usize {
        self.completion_len
    }
    /// No queued/current/transmit/continuation work. Live idle watches do not
    /// cause disconnection or make this queue non-idle.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.head.is_none()
            && self.current.is_none()
            && self.transmit_count() == 0
            && self.completion_len == 0
            && !self.is_destroying()
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Fallible boundary tests force identifier/resource exhaustion and compare original retry limits"
    )]
    extern crate std;
    use super::*;
    type H<'owner> = StatisticsHandle<'owner, 2, 8, 1, 2, 2>;
    fn owner<'owner>(
        instance: &'owner mut crate::statistics_handle::Instance,
    ) -> Result<H<'owner>, Error> {
        H::new(instance, b"s", true)?.ok_or(Error::Unavailable)
    }
    fn selector() -> Selector<'static> {
        Selector {
            subsystem: b"s",
            name: b"a",
        }
    }
    fn send<'owner>(
        h: &mut H<'owner>,
        e: ConnectionEpoch<'owner>,
    ) -> Result<Outbound<'owner>, Error> {
        let out = h.next_request(e, &mut [0; 32])?.ok_or(Error::NotReady)?;
        h.on_frame_written(e, out.transmit)?;
        Ok(out)
    }
    #[test]
    fn generation_exhaustion_retires_slots_without_aliasing() -> Result<(), Error> {
        let mut statistics_instance_2 = crate::statistics_handle::Instance::new();
        let mut h = owner(&mut statistics_instance_2)?;
        h.actions[0].generation = u32::MAX;
        let id = h.get(selector())?;
        let e = h.begin_connection(AbsoluteTime::from_micros(0))?;
        send(&mut h, e)?;
        h.receive(e, b"\0\x04\0\xab", AbsoluteTime::from_micros(1))?;
        h.take_completion();
        assert!(h.actions[0].retired);
        assert!(!h.owns_get(id));
        let replacement = h.get(selector())?;
        assert_ne!(id, replacement);
        assert_eq!(replacement.resource_id().index, 1);
        h.get_cancel(replacement)?;
        h.watches[0].generation = u32::MAX;
        let watch = h.watch(selector())?;
        h.watch_cancel(watch)?;
        assert!(h.watches[0].retired);
        assert_eq!(h.watch(selector()), Err(Error::Capacity));
        Ok(())
    }
    #[test]
    fn epoch_and_transmit_exhaustion_refuse_before_frame_or_queue_changes() -> Result<(), Error> {
        let mut statistics_instance_3 = crate::statistics_handle::Instance::new();
        let mut h = owner(&mut statistics_instance_3)?;
        h.set(b"a", 1, false)?;
        h.next_epoch = u64::MAX;
        assert_eq!(
            h.begin_connection(AbsoluteTime::from_micros(0)),
            Err(Error::Overflow)
        );
        assert_eq!(h.pending_actions(), 1);
        assert_eq!(h.connection, None);
        h.next_epoch = 0;
        let e = h.begin_connection(AbsoluteTime::from_micros(0))?;
        h.next_transmit = u64::MAX;
        let mut output = [0xa5; 32];
        assert_eq!(h.next_request(e, &mut output), Err(Error::Overflow));
        assert_eq!(output, [0xa5; 32]);
        assert_eq!(h.pending_actions(), 1);
        Ok(())
    }
    #[test]
    fn exponential_retry_caps_at_fifteen_minutes_and_only_end_resets_it() -> Result<(), Error> {
        let mut statistics_instance_4 = crate::statistics_handle::Instance::new();
        let mut h = owner(&mut statistics_instance_4)?;
        h.set(b"a", 1, false)?;
        let mut now = AbsoluteTime::from_micros(0);
        let mut expected = 1000u64;
        for _ in 0..30 {
            let e = h.begin_connection(now)?;
            h.connection_lost(e, Error::Io, now)?;
            let deadline = h.next_wakeup().ok_or(Error::NotReady)?;
            assert_eq!(deadline.as_micros() - now.as_micros(), expected);
            assert!(!h.connection_needed(AbsoluteTime::from_micros(deadline.as_micros() - 1)));
            expected = expected.saturating_mul(2).min(900_000_000);
            now = deadline;
        }
        assert_eq!(expected, 900_000_000);
        let e = h.begin_connection(now)?;
        send(&mut h, e)?;
        let get = h.get(selector())?;
        send(&mut h, e)?;
        h.receive(e, b"\0\x04\0\xab", now)?;
        assert_eq!(h.take_completion().map(|c| c.get), Some(get));
        h.connection_lost(e, Error::Io, now)?;
        assert_eq!(
            h.next_wakeup().map(|d| d.as_micros() - now.as_micros()),
            Some(1000)
        );
        Ok(())
    }
    fn check_maximum_public_frames() -> Result<(), Error> {
        type Large<'owner> = StatisticsHandle<'owner, 1, 65532, 1, 2, 1>;
        for kind in 0..3 {
            let mut statistics_instance_1 = crate::statistics_handle::Instance::new();
            let mut h =
                Large::new(&mut statistics_instance_1, b"", true)?.ok_or(Error::Unavailable)?;
            let fixed = if kind == 2 { 16 } else { 4 };
            let name = std::vec![b'a'; 65536 - fixed - 2];
            let oversized = Selector {
                subsystem: b"",
                name: &name,
            };
            let refusal = match kind {
                0 => h.get(oversized).map(|_| ()),
                1 => h.watch(oversized).map(|_| ()),
                _ => h.set(&name, u64::MAX, true).map(|_| ()),
            };
            assert_eq!(refusal, Err(Error::TooLarge));
            assert_eq!(h.pending_actions(), 0);
            assert_eq!(h.connection_epoch(), None);
            let valid = Selector {
                subsystem: b"",
                name: &name[..name.len() - 1],
            };
            match kind {
                0 => {
                    h.get(valid)?;
                }
                1 => {
                    h.watch(valid)?;
                }
                _ => {
                    h.set(valid.name, u64::MAX, true)?;
                }
            }
            let epoch = h.begin_connection(AbsoluteTime::from_micros(0))?;
            let mut output = std::vec![0xa5; usize::from(u16::MAX)];
            let request = h.next_request(epoch, &mut output)?.ok_or(Error::NotReady)?;
            assert_eq!(request.len, 65535);
            assert_eq!(&output[..2], &[0xff, 0xff]);
            assert_eq!(output[request.len - 1], 0);
            let expected_type = match kind {
                0 => 169_u16,
                1 => 172,
                _ => 168,
            };
            assert_eq!(&output[2..4], &expected_type.to_be_bytes());
        }
        Ok(())
    }
    #[test]
    fn all_public_requests_accept_65535_and_reject_65536_without_admission() -> Result<(), Error> {
        // This intentionally uses the full 64KiB inline-name profile, rather
        // than the small default test profile. Give its debug constructors an
        // explicit bounded stack without changing production allocation rules.
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(check_maximum_public_frames)
            .map_err(|_| Error::Io)?
            .join()
            .map_err(|_| Error::Io)?
    }
}
