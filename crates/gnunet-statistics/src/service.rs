use crate::protocol::{names_len, raw_uid};
use crate::storage::{Growth, Names, Table};
#[cfg(feature = "alloc")]
mod snapshot;
use crate::{Notification, Reply, Request, SET_PERSISTENT, SET_RELATIVE, Selector, Set, Statistic};
use gnunet_types::{Error, GenerationalId};
use gnunet_wire::official::{MessageHeader, message_type};
#[cfg(feature = "alloc")]
pub use snapshot::{PersistentSnapshot, SnapshotId};

/// A local service connection, protected against slot reuse after disconnection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientId(GenerationalId);

impl ClientId {
    /// Resource-table identity. This conveys no network authentication.
    #[must_use]
    pub const fn resource_id(self) -> GenerationalId {
        self.0
    }
}

struct Client {
    active: bool,
    retired: bool,
    generation: u32,
    next_wid: u64,
    #[cfg(feature = "alloc")]
    next_snapshot: u64,
    #[cfg(feature = "alloc")]
    snapshot: Option<snapshot::Active>,
}

impl Client {
    const EMPTY: Self = Self {
        active: false,
        retired: false,
        generation: 0,
        next_wid: 0,
        #[cfg(feature = "alloc")]
        next_snapshot: 0,
        #[cfg(feature = "alloc")]
        snapshot: None,
    };
}

struct Row<const N: usize> {
    names: Names<N>,
    subsystem_len: usize,
    name_len: usize,
    subsystem_order: u64,
    row_order: u64,
    uid: u32,
    value: u64,
    persistent: bool,
    set: bool,
    watch_head: Option<usize>,
}

impl<const N: usize> Row<N> {
    fn new(
        selector: Selector<'_>,
        order: u64,
        subsystem_order: u64,
        uid: u32,
        allocated: bool,
    ) -> Result<Self, Error> {
        let names = Names::new(selector.subsystem, selector.name, allocated)?;
        Ok(Self {
            names,
            subsystem_len: selector.subsystem.len(),
            name_len: selector.name.len(),
            subsystem_order,
            row_order: order,
            uid,
            value: 0,
            persistent: false,
            set: false,
            watch_head: None,
        })
    }
    fn selector(&self) -> Selector<'_> {
        Selector {
            subsystem: &self.names[..self.subsystem_len],
            name: &self.names[self.subsystem_len + 1..self.subsystem_len + 1 + self.name_len],
        }
    }
    fn statistic(&self) -> Statistic<'_> {
        Statistic {
            raw_uid: raw_uid(self.uid, self.persistent),
            value: self.value,
            selector: self.selector(),
        }
    }
    const fn order(&self) -> (u64, u64) {
        (self.subsystem_order, self.row_order)
    }
}

#[derive(Clone, Copy)]
struct Watch {
    client: ClientId,
    wid: u32,
    last_value: Option<u64>,
    next: Option<usize>,
}

/// Result of a committed official SET, including the C service's overflow warning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetOutcome {
    /// Stable service-lifetime UID, without the persistence marker.
    pub uid: u32,
    /// Stored value after the operation.
    pub value: u64,
    /// Whether a value has now been explicitly established.
    ///
    /// A newly created row with a nonpositive relative delta remains unset.
    pub is_set: bool,
    /// Current persistence flag; every SET replaces the previous flag.
    pub persistent: bool,
    /// Number of WATCH_VALUE effects atomically queued by this operation.
    pub notifications: usize,
    /// A positive relative delta wrapped through `u64::MAX`.
    ///
    /// Upstream logs a failed `GNUNET_break` but still stores the wrapped value.
    /// The caller can report that diagnostic without changing protocol behavior.
    pub positive_overflow: bool,
}

/// Explicit deployment admission limits. Fixed cores derive their own table bounds.
/// Byte accounting includes the core, actual allocated table capacities and names,
/// active GET metadata and caller-reported host buffers; allocator overhead and
/// temporary unpublished reservation candidates are outside retained state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceLimits {
    /// Maximum global rows; live rows are never silently evicted.
    pub max_rows: usize,
    /// Combined row names including both terminal NULs; SET/VALUE must fit BE16.
    pub max_name_bytes: usize,
    /// Maximum connection slots, including permanently retired generations.
    pub max_clients: usize,
    /// Maximum simultaneous subscriptions.
    pub max_watches: usize,
    /// Maximum queued, unmerged WATCH_VALUE effects.
    pub max_events: usize,
    /// Maximum actually retained accounted bytes, including host-reported buffers.
    pub max_retained_bytes: usize,
}
#[cfg(feature = "alloc")]
/// Same protocol engine with initially empty, fallibly grown owned tables.
pub type AllocatedStatistics = Statistics<0, 0, 0, 0, 0>;

/// One official STATISTICS state machine with fixed or allocated private backing.
///
/// [`Self::new`] and fixed SET/WATCH state use only compile-time tables, even
/// when the allocation feature is compiled. The existing borrowed GET iterator
/// stays allocation-free; explicit alloc-only snapshot methods own metadata.
/// The allocated alias instead grows empty tables under explicit runtime limits. Stored rows survive
/// client disconnection and their immutable names are never silently evicted.
///
/// Admission reserves all names, metadata and affected notification capacity
/// before committing arithmetic, persistence, UID/WID/order or WATCH last values.
/// Allocated name lookup uses a sorted row-index vector without another name copy;
/// existing updates use binary search, while new names may shift bounded indices.
/// The small fixed profile keeps its bounded linear lookup and borrowed iterator.
/// The normal allocated host captures/sorts GET metadata once, rather than using
/// the borrowed fixed iterator's repeated full-table scans for a large listing.
///
/// UID/WID, generations and ordering counters reject exhaustion without reuse.
/// Accounted bytes include actual owned capacities and caller-reported buffers,
/// but not allocator overhead, kernel storage or unpublished reservation peaks.
pub struct Statistics<
    const ROWS: usize,
    const NAME_BYTES: usize,
    const CLIENTS: usize,
    const WATCHES: usize,
    const EVENTS: usize,
> {
    rows: Table<Option<Row<NAME_BYTES>>, ROWS>,
    clients: Table<Client, CLIENTS>,
    watches: Table<Option<Watch>, WATCHES>,
    events: Table<Option<Notification>, EVENTS>,
    limits: ResourceLimits,
    allocated: bool,
    names_retained: usize,
    snapshots_retained: usize,
    #[cfg(feature = "alloc")]
    persistent_retained: core::cell::Cell<usize>,
    external_retained: usize,
    name_index: Table<usize, 0>,
    event_len: usize,
    event_head: usize,
    row_count: usize,
    client_count: usize,
    watch_count: usize,
    next_uid: u64,
    order: u64,
}

struct Admission<const R: usize, const N: usize, const C: usize, const W: usize, const E: usize> {
    rows: Growth<Option<Row<N>>>,
    name_index: Growth<usize>,
    clients: Growth<Client>,
    watches: Growth<Option<Watch>>,
    events: Growth<Option<Notification>>,
    needed: [usize; 4],
    names: usize,
}
impl<const R: usize, const N: usize, const C: usize, const W: usize, const E: usize>
    Statistics<R, N, C, W, E>
{
    /// Construct empty tables. Zero capacities are valid and reject admission.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rows: Table::fixed([const { None }; R]),
            clients: Table::fixed([const { Client::EMPTY }; C]),
            watches: Table::fixed([None; W]),
            events: Table::fixed([None; E]),
            limits: ResourceLimits {
                max_rows: R,
                max_name_bytes: N,
                max_clients: C,
                max_watches: W,
                max_events: E,
                max_retained_bytes: usize::MAX,
            },
            allocated: false,
            names_retained: 0,
            snapshots_retained: 0,
            #[cfg(feature = "alloc")]
            persistent_retained: core::cell::Cell::new(0),
            external_retained: 0,
            name_index: Table::fixed([]),
            event_len: 0,
            event_head: 0,
            row_count: 0,
            client_count: 0,
            watch_count: 0,
            next_uid: 0,
            order: 0,
        }
    }

    fn persistent_view_bytes(&self) -> usize {
        #[cfg(feature = "alloc")]
        {
            self.persistent_retained.get()
        }
        #[cfg(not(feature = "alloc"))]
        {
            0
        }
    }
    /// Actual accounted retained bytes, including backing capacity and host ownership.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        [
            core::mem::size_of::<Self>(),
            self.rows.retained_bytes()?,
            self.name_index.retained_bytes()?,
            self.clients.retained_bytes()?,
            self.watches.retained_bytes()?,
            self.events.retained_bytes()?,
            self.names_retained,
            self.snapshots_retained,
            self.persistent_view_bytes(),
            self.external_retained,
        ]
        .into_iter()
        .try_fold(0usize, |sum, n| sum.checked_add(n).ok_or(Error::Overflow))
    }
    /// Borrow the explicit profile without changing protocol state.
    #[must_use]
    pub const fn limits(&self) -> ResourceLimits {
        self.limits
    }
    /// Caller-reported actual host buffer capacities. A successful increase must
    /// immediately publish those already-reserved buffers; release after drop.
    /// The same original caller restores its baseline on shutdown/cancellation.
    pub fn set_external_retained_bytes(&mut self, bytes: usize) -> Result<(), Error> {
        let current = self.retained_bytes()?;
        let proposed = current
            .checked_sub(self.external_retained)
            .and_then(|n| n.checked_add(bytes))
            .ok_or(Error::Overflow)?;
        if bytes > self.external_retained && proposed > self.limits.max_retained_bytes {
            return Err(Error::Capacity);
        }
        self.external_retained = bytes;
        Ok(())
    }
    /// Current original caller's external memory accounting baseline.
    #[must_use]
    pub const fn external_retained_bytes(&self) -> usize {
        self.external_retained
    }
    fn reserve(&self, needed: [usize; 4], names: usize) -> Result<Admission<R, N, C, W, E>, Error> {
        match self.reserve_growth(needed, names, true) {
            Err(Error::Capacity) => self.reserve_growth(needed, names, false),
            result => result,
        }
    }
    fn reserve_growth(
        &self,
        needed: [usize; 4],
        names: usize,
        geometric: bool,
    ) -> Result<Admission<R, N, C, W, E>, Error> {
        if needed[0] > self.limits.max_rows
            || needed[1] > self.limits.max_clients
            || needed[2] > self.limits.max_watches
            || needed[3] > self.limits.max_events
        {
            return Err(Error::Capacity);
        }
        let rows = self
            .rows
            .prepare(needed[0], self.limits.max_rows, geometric)?;
        let name_index = self.name_index.prepare(
            if self.allocated { needed[0] } else { 0 },
            self.limits.max_rows,
            geometric,
        )?;
        let clients = self
            .clients
            .prepare(needed[1], self.limits.max_clients, geometric)?;
        let watches = self
            .watches
            .prepare(needed[2], self.limits.max_watches, geometric)?;
        let events = self
            .events
            .prepare(needed[3], self.limits.max_events, geometric)?;
        let extra = [
            rows.extra_bytes(self.rows.capacity())?,
            name_index.extra_bytes(self.name_index.capacity())?,
            clients.extra_bytes(self.clients.capacity())?,
            watches.extra_bytes(self.watches.capacity())?,
            events.extra_bytes(self.events.capacity())?,
            names,
        ]
        .into_iter()
        .try_fold(0usize, |s, n| s.checked_add(n).ok_or(Error::Overflow))?;
        if self
            .retained_bytes()?
            .checked_add(extra)
            .ok_or(Error::Overflow)?
            > self.limits.max_retained_bytes
        {
            return Err(Error::Capacity);
        }
        Ok(Admission {
            rows,
            name_index,
            clients,
            watches,
            events,
            needed,
            names,
        })
    }
    fn commit_reservation(&mut self, plan: Admission<R, N, C, W, E>) {
        self.rows.commit(plan.rows, plan.needed[0], || None);
        self.name_index.commit(
            plan.name_index,
            if self.allocated { plan.needed[0] } else { 0 },
            || 0,
        );
        self.clients
            .commit(plan.clients, plan.needed[1], || Client::EMPTY);
        self.watches.commit(plan.watches, plan.needed[2], || None);
        let slots = plan
            .events
            .capacity_after(self.events.capacity())
            .min(self.limits.max_events);
        if slots != self.events.len() && self.event_head != 0 {
            self.events.rotate_left(self.event_head);
            self.event_head = 0;
        }
        self.events.commit(plan.events, slots, || None);
        self.names_retained += plan.names;
    }
    /// Admit a local connection. The first watch on this connection has WID zero.
    pub fn connect(&mut self) -> Result<ClientId, Error> {
        let index = self
            .clients
            .iter()
            .position(|client| !client.active && !client.retired)
            .unwrap_or(self.clients.len());
        let needed = self
            .clients
            .len()
            .max(index.checked_add(1).ok_or(Error::Overflow)?);
        let plan = self.reserve(
            [
                self.rows.len(),
                needed,
                self.watches.len(),
                self.events.len(),
            ],
            0,
        )?;
        let wire_index = u32::try_from(index).map_err(|_| Error::Overflow)?;
        self.commit_reservation(plan);
        let client = &mut self.clients[index];
        client.active = true;
        client.next_wid = 0;
        self.client_count += 1;
        Ok(ClientId(GenerationalId {
            index: wire_index,
            generation: client.generation,
        }))
    }

    fn client_index(&self, id: ClientId) -> Result<usize, Error> {
        let index = usize::try_from(id.0.index).map_err(|_| Error::StaleGeneration)?;
        match self.clients.get(index) {
            Some(client) if client.active && client.generation == id.0.generation => Ok(index),
            _ => Err(Error::StaleGeneration),
        }
    }

    fn find_row(&self, selector: Selector<'_>) -> Option<usize> {
        if self.allocated {
            let target = (selector.subsystem, selector.name);
            return self
                .name_index
                .binary_search_by(|&index| {
                    self.rows[index]
                        .as_ref()
                        .map(|r| {
                            let s = r.selector();
                            (s.subsystem, s.name)
                        })
                        .cmp(&Some(target))
                })
                .ok()
                .map(|index| self.name_index[index]);
        }
        self.rows
            .iter()
            .position(|row| row.as_ref().is_some_and(|row| row.selector() == selector))
    }
    fn install_row(&mut self, index: usize, row: Row<N>) {
        if self.allocated {
            let names = row.selector();
            let target = (names.subsystem, names.name);
            let count = self.row_count;
            let at = self.name_index[..count].partition_point(|&i| {
                self.rows[i]
                    .as_ref()
                    .map(|r| {
                        let s = r.selector();
                        (s.subsystem, s.name)
                    })
                    .is_some_and(|s| s < target)
            });
            self.name_index.copy_within(at..count, at + 1);
            self.name_index[at] = index;
        }
        self.rows[index] = Some(row);
        self.next_uid += 1;
        self.row_count += 1;
    }

    fn check_row_names(&self, selector: Selector<'_>) -> Result<(), Error> {
        let storage = selector
            .subsystem
            .len()
            .checked_add(selector.name.len())
            .and_then(|len| len.checked_add(2))
            .ok_or(Error::Overflow)?;
        if storage > self.limits.max_name_bytes {
            return Err(Error::Capacity);
        }
        let bytes = names_len(selector)?;
        MessageHeader::new(
            message_type::STATISTICS_SET,
            12usize.checked_add(bytes).ok_or(Error::Overflow)?,
        )?;
        Ok(())
    }

    fn next_order(&self) -> Result<u64, Error> {
        self.order.checked_add(1).ok_or(Error::Overflow)
    }

    fn prepare_new_row(
        &self,
        selector: Selector<'_>,
        order: u64,
    ) -> Result<(usize, Row<N>), Error> {
        let index = self
            .rows
            .iter()
            .position(Option::is_none)
            .unwrap_or(self.rows.len());
        if index >= self.limits.max_rows {
            return Err(Error::Capacity);
        }
        // VALUE reserves the high UID bit for persistence. Refuse ambiguous UIDs.
        if self.next_uid >= u64::from(crate::PERSIST_BIT) {
            return Err(Error::Overflow);
        }
        let uid = u32::try_from(self.next_uid).map_err(|_| Error::Overflow)?;
        let subsystem_order = self
            .rows
            .iter()
            .flatten()
            .find(|row| row.selector().subsystem == selector.subsystem)
            .map_or(order, |row| row.subsystem_order);
        Ok((
            index,
            Row::new(selector, order, subsystem_order, uid, self.allocated)?,
        ))
    }

    /// Apply a SET from a live connection, atomically admitting required effects.
    ///
    /// Negative relative deltas saturate at zero; positive overflow wraps as in
    /// the C handler. Unknown flag bits have no effect. Persistence is replaced
    /// even when the value is unchanged, and that alone does not notify watches.
    pub fn set(&mut self, client: ClientId, request: Set<'_>) -> Result<SetOutcome, Error> {
        self.client_index(client)?;
        self.set_inner(request)
    }

    fn set_inner(&mut self, request: Set<'_>) -> Result<SetOutcome, Error> {
        self.check_row_names(request.selector)?;
        let order = self.next_order()?;
        let existing = self.find_row(request.selector);
        let (index, new) = match existing {
            Some(index) => (index, None),
            None => {
                let (index, row) = self.prepare_new_row(request.selector, order)?;
                (index, Some(row))
            }
        };
        let row = match &new {
            Some(row) => row,
            None => self.rows[index].as_ref().ok_or(Error::NotFound)?,
        };
        let relative = request.flags & SET_RELATIVE != 0;
        let delta = request.value as i64;
        let positive_overflow = existing.is_some()
            && relative
            && delta > 0
            && row.value.checked_add(request.value).is_none();
        let value = if !relative {
            request.value
        } else if delta < 0 {
            row.value.saturating_sub(delta.unsigned_abs())
        } else {
            row.value.wrapping_add(request.value)
        };
        let changed = if !relative {
            row.value != value
        } else if delta < 0 && row.value < delta.unsigned_abs() {
            row.value != 0
        } else {
            delta != 0
        };
        let notify = existing.is_some() && (changed || !row.set);
        let head = row.watch_head;
        let uid = row.uid;
        let notifications = if notify {
            self.notification_count(head, value)
        } else {
            0
        };
        self.check_event_capacity(notifications)?;
        let names = new.as_ref().map_or(0, |row| row.names.retained_bytes());
        let needed = [
            self.rows
                .len()
                .max(index.checked_add(1).ok_or(Error::Overflow)?),
            self.clients.len(),
            self.watches.len(),
            self.events.len().max(
                self.event_len
                    .checked_add(notifications)
                    .ok_or(Error::Overflow)?,
            ),
        ];
        let plan = self.reserve(needed, names)?;
        // No allocation, arithmetic admission or protocol fallibility after this point.
        self.commit_reservation(plan);
        if let Some(row) = new {
            self.install_row(index, row);
        }
        let is_set = existing.is_some() || !relative || delta > 0;
        let persistent = request.flags & SET_PERSISTENT != 0;
        if let Some(row) = self.rows[index].as_mut() {
            row.value = value;
            row.set = is_set;
            row.persistent = persistent;
            row.row_order = order;
        }
        self.order = order;
        if notify {
            self.notify(head, value, persistent);
        }
        Ok(SetOutcome {
            uid,
            value,
            is_set,
            persistent,
            notifications,
            positive_overflow,
        })
    }

    fn notification_count(&self, mut head: Option<usize>, value: u64) -> usize {
        let mut count = 0;
        while let Some(index) = head {
            let Some(watch) = self.watches[index] else {
                break;
            };
            count += usize::from(watch.last_value != Some(value));
            head = watch.next;
        }
        count
    }

    fn check_event_capacity(&self, count: usize) -> Result<(), Error> {
        if count > self.limits.max_events.saturating_sub(self.event_len) {
            Err(Error::Capacity)
        } else {
            Ok(())
        }
    }

    fn notify(&mut self, mut head: Option<usize>, value: u64, persistent: bool) {
        while let Some(index) = head {
            let Some(mut watch) = self.watches[index] else {
                break;
            };
            if watch.last_value != Some(value) {
                let tail = (self.event_head + self.event_len) % self.events.len();
                self.events[tail] = Some(Notification {
                    client: watch.client,
                    wid: watch.wid,
                    value,
                    persistent,
                });
                self.event_len += 1;
                watch.last_value = Some(value);
                self.watches[index] = Some(watch);
            }
            head = watch.next;
        }
    }

    /// Subscribe to an exact subsystem/name, creating an unset row if needed.
    ///
    /// A nonzero current value produces an initial notification. A zero value
    /// does not, even if previously SET. A watch-created row's first SET (including
    /// zero) notifies; later equal values are suppressed independently per watch.
    /// New subscriptions are notified before older subscriptions, as upstream.
    pub fn watch(&mut self, client: ClientId, selector: Selector<'_>) -> Result<u32, Error> {
        let client_index = self.client_index(client)?;
        self.check_row_names(selector)?;
        let slot = self
            .watches
            .iter()
            .position(Option::is_none)
            .unwrap_or(self.watches.len());
        if slot >= self.limits.max_watches {
            return Err(Error::Capacity);
        }
        let wid =
            u32::try_from(self.clients[client_index].next_wid).map_err(|_| Error::Overflow)?;
        let existing = self.find_row(selector);
        let (index, new) = match existing {
            Some(index) => (index, None),
            None => {
                let (i, row) = self.prepare_new_row(selector, self.next_order()?)?;
                (i, Some(row))
            }
        };
        let row = match &new {
            Some(row) => row,
            None => self.rows[index].as_ref().ok_or(Error::NotFound)?,
        };
        let value = row.value;
        let persistent = row.persistent;
        let head = row.watch_head;
        let notifications = if value != 0 {
            1 + self.notification_count(head, value)
        } else {
            0
        };
        self.check_event_capacity(notifications)?;
        let names = new.as_ref().map_or(0, |row| row.names.retained_bytes());
        let needed = [
            self.rows
                .len()
                .max(index.checked_add(1).ok_or(Error::Overflow)?),
            self.clients.len(),
            self.watches
                .len()
                .max(slot.checked_add(1).ok_or(Error::Overflow)?),
            self.events.len().max(
                self.event_len
                    .checked_add(notifications)
                    .ok_or(Error::Overflow)?,
            ),
        ];
        let plan = self.reserve(needed, names)?;
        self.commit_reservation(plan);
        if let Some(row) = new {
            self.order = row.row_order;
            self.install_row(index, row);
        }
        self.watches[slot] = Some(Watch {
            client,
            wid,
            last_value: None,
            next: head,
        });
        if let Some(row) = self.rows[index].as_mut() {
            row.watch_head = Some(slot);
        }
        self.clients[client_index].next_wid += 1;
        self.watch_count += 1;
        if value != 0 {
            self.notify(Some(slot), value, persistent);
        }
        Ok(wid)
    }

    /// Enumerate matching rows in official subsystem/row list order, then END.
    ///
    /// Empty subsystem and name are independent wildcards. Unset rows are
    /// included. The immutable borrow holds a consistent view until enumeration
    /// finishes; the transport must finish or drop it before admitting mutation.
    pub fn get<'a>(
        &'a self,
        client: ClientId,
        selector: Selector<'a>,
    ) -> Result<Get<'a, N>, Error> {
        self.client_index(client)?;
        MessageHeader::new(message_type::STATISTICS_GET, names_len(selector)?)?;
        Ok(Get {
            rows: &self.rows,
            selector,
            before: None,
            ended: false,
        })
    }

    /// Oldest unconsumed effect. Encode/send successfully before consuming it.
    #[must_use]
    pub fn notification(&self) -> Option<&Notification> {
        if self.event_len == 0 {
            return None;
        }
        self.events.get(self.event_head).and_then(Option::as_ref)
    }

    /// Consume exactly the oldest effect after host queue admission, in O(1).
    /// This is not a physical-write or service/durable acknowledgement.
    pub fn consume_notification(&mut self) -> Option<Notification> {
        if self.event_len == 0 {
            return None;
        }
        let value = self.events[self.event_head].take();
        self.event_len -= 1;
        self.event_head = if self.event_len == 0 {
            0
        } else {
            (self.event_head + 1) % self.events.len()
        };
        value
    }

    /// Release precisely this connection's watches and queued notifications.
    ///
    /// Stored values remain global, including rows first created by this client.
    /// The slot generation changes before reuse; stale handles cannot release a
    /// replacement connection's resources.
    pub fn disconnect(&mut self, client: ClientId) -> Result<(), Error> {
        let client_index = self.client_index(client)?;
        for row in self.rows.iter_mut().flatten() {
            let mut current = row.watch_head;
            let mut previous: Option<usize> = None;
            while let Some(index) = current {
                let Some(watch) = self.watches[index] else {
                    break;
                };
                if watch.client == client {
                    if let Some(previous) = previous {
                        if let Some(prior) = self.watches[previous].as_mut() {
                            prior.next = watch.next;
                        }
                    } else {
                        row.watch_head = watch.next;
                    }
                    self.watches[index] = None;
                    self.watch_count -= 1;
                } else {
                    previous = Some(index);
                }
                current = watch.next;
            }
        }
        if self.event_head != 0 {
            self.events.rotate_left(self.event_head);
            self.event_head = 0;
        }
        let mut kept = 0;
        for index in 0..self.event_len {
            if self.events[index].is_some_and(|event| event.client != client) {
                self.events[kept] = self.events[index];
                kept += 1;
            }
        }
        self.events[kept..self.event_len].fill(None);
        self.event_len = kept;
        let entry = &mut self.clients[client_index];
        #[cfg(feature = "alloc")]
        if let Some(snapshot) = entry.snapshot.take() {
            self.snapshots_retained -= snapshot.retained_bytes();
        }
        entry.active = false;
        if let Some(next) = entry.generation.checked_add(1) {
            entry.generation = next;
        } else {
            entry.retired = true;
        }
        self.client_count -= 1;
        Ok(())
    }

    /// Snapshot persistent rows as canonical absolute persistent SET messages.
    ///
    /// Concatenate each returned [`Set::encode`] frame directly. No private
    /// header, UID, watch state or connection metadata is written. This does not
    /// perform storage I/O, fsync, crash recovery or the C service's shutdown.
    #[must_use]
    pub fn persistent(&self) -> Persistent<'_, N> {
        Persistent {
            rows: &self.rows,
            before: None,
        }
    }

    /// Import one canonical persistent SET frame when no clients are connected.
    ///
    /// Only absolute SET with exactly SET_PERSISTENT is a canonical dump record.
    /// Each successful frame commits independently. The application bounds its
    /// input stream, handles truncated files and supplies any transactional policy.
    pub fn restore(&mut self, frame: &[u8]) -> Result<SetOutcome, Error> {
        if self.client_count != 0 {
            return Err(Error::Conflict);
        }
        let Request::Set(set) = Request::decode(frame)? else {
            return Err(Error::InvalidInput);
        };
        if set.flags != SET_PERSISTENT {
            return Err(Error::InvalidInput);
        }
        self.set_inner(set)
    }

    /// Replay one complete official SET from a database when no clients are connected.
    ///
    /// The reference file injector applies ordinary SET semantics, including
    /// relative deltas, replacement of persistence and unknown flag bits. This
    /// is intentionally broader than [`Self::restore`], which accepts only
    /// canonical records produced by [`Self::persistent`]. Framing and names
    /// are still checked, and foreign message types are rejected. Each admitted
    /// frame commits independently; a host wanting all-or-nothing loading must
    /// build a fresh candidate state and publish it only after the complete file
    /// has been validated. No file or durability operation happens here.
    pub fn replay(&mut self, frame: &[u8]) -> Result<SetOutcome, Error> {
        if self.client_count != 0 {
            return Err(Error::Conflict);
        }
        let Request::Set(set) = Request::decode(frame)? else {
            return Err(Error::InvalidInput);
        };
        self.set_inner(set)
    }

    /// Number of global statistic rows, including unset watch-created rows.
    #[must_use]
    pub const fn row_count(&self) -> usize {
        self.row_count
    }
    /// Number of live local connections.
    #[must_use]
    pub const fn client_count(&self) -> usize {
        self.client_count
    }
    /// Number of subscriptions owned by live connections.
    #[must_use]
    pub const fn watch_count(&self) -> usize {
        self.watch_count
    }
    /// Number of queued, unconsumed WATCH_VALUE effects.
    #[must_use]
    pub const fn notification_count_queued(&self) -> usize {
        self.event_len
    }
}

#[cfg(feature = "alloc")]
impl AllocatedStatistics {
    /// Construct empty fallible-growth tables; no maximum-sized arrays are allocated.
    pub fn with_limits(limits: ResourceLimits) -> Result<Self, Error> {
        if limits.max_rows == 0
            || !(2..=65519).contains(&limits.max_name_bytes)
            || limits.max_clients == 0
            || limits.max_clients > u32::MAX as usize
            || limits.max_watches == 0
            || limits.max_events == 0
        {
            return Err(Error::InvalidInput);
        }
        let mut state = Self::new();
        state.rows = Table::allocated();
        state.name_index = Table::allocated();
        state.clients = Table::allocated();
        state.watches = Table::allocated();
        state.events = Table::allocated();
        state.limits = limits;
        state.allocated = true;
        if state.retained_bytes()? > limits.max_retained_bytes {
            return Err(Error::Capacity);
        }
        Ok(state)
    }
}

impl<const R: usize, const N: usize, const C: usize, const W: usize, const E: usize> Default
    for Statistics<R, N, C, W, E>
{
    fn default() -> Self {
        Self::new()
    }
}

fn next_row<const N: usize>(
    rows: &[Option<Row<N>>],
    before: Option<(u64, u64)>,
    mut matches: impl FnMut(&Row<N>) -> bool,
) -> Option<&Row<N>> {
    rows.iter()
        .flatten()
        .filter(|row| before.is_none_or(|before| row.order() < before) && matches(row))
        .max_by_key(|row| row.order())
}

/// A borrowed official GET enumeration that ends with exactly one END effect.
pub struct Get<'a, const NAME_BYTES: usize> {
    rows: &'a [Option<Row<NAME_BYTES>>],
    selector: Selector<'a>,
    before: Option<(u64, u64)>,
    ended: bool,
}

impl<'a, const N: usize> Iterator for Get<'a, N> {
    type Item = Reply<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.ended {
            return None;
        }
        let row = next_row(self.rows, self.before, |row| {
            let selector = row.selector();
            (self.selector.subsystem.is_empty() || self.selector.subsystem == selector.subsystem)
                && (self.selector.name.is_empty() || self.selector.name == selector.name)
        });
        if let Some(row) = row {
            self.before = Some(row.order());
            Some(Reply::Value(row.statistic()))
        } else {
            self.ended = true;
            Some(Reply::End)
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.ended {
            (0, Some(0))
        } else {
            (1, Some(self.rows.len().saturating_add(1)))
        }
    }
}
impl<const N: usize> core::iter::FusedIterator for Get<'_, N> {}

/// Borrowed persistent rows in the same order as the C service's shutdown dump.
pub struct Persistent<'a, const NAME_BYTES: usize> {
    rows: &'a [Option<Row<NAME_BYTES>>],
    before: Option<(u64, u64)>,
}

impl<'a, const N: usize> Iterator for Persistent<'a, N> {
    type Item = Set<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let row = next_row(self.rows, self.before, |row| row.persistent)?;
        self.before = Some(row.order());
        Some(Set {
            selector: row.selector(),
            flags: SET_PERSISTENT,
            value: row.value,
        })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.rows.len()))
    }
}
impl<const N: usize> core::iter::FusedIterator for Persistent<'_, N> {}
