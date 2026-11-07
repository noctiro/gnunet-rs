//! Fixed caller-storage official PEERSTORE service state and explicit storage port.
#![no_std]
#![forbid(unsafe_code)]
use core::{cell::Cell, ptr};
use gnunet_types::Error;
pub use gnunet_wire::official::peerstore::{
    Envelope, Filter, Iteration, MAX_ROUND, Monitor, Record, Request, Response,
};
/// Stable one-service allocation domain. Tokens contain no wire authority.
#[derive(Debug, Default)]
pub struct Instance {
    next: Cell<u64>,
}
impl Instance {
    /// Fresh explicit service domain.
    #[must_use]
    pub const fn new() -> Self {
        Self { next: Cell::new(0) }
    }
}
/// Original actual accepted MQ allocation.
#[derive(Clone, Copy, Debug)]
pub struct Client<'id> {
    domain: &'id Instance,
    index: usize,
    generation: u64,
}
impl PartialEq for Client<'_> {
    fn eq(&self, o: &Self) -> bool {
        ptr::eq(self.domain, o.domain) && self.index == o.index && self.generation == o.generation
    }
}
impl Eq for Client<'_> {}
impl Client<'_> {
    /// Local diagnostic allocation; never a wire id.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.generation
    }
}
/// Original immutable output, inseparable from its accepted MQ allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Output<'id> {
    client: Client<'id>,
    slot: usize,
    serial: u64,
}
impl<'id> Output<'id> {
    /// Original actual accepted MQ.
    #[must_use]
    pub const fn client(self) -> Client<'id> {
        self.client
    }
}
/// Original STORE effect bound to retained immutable original record bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Store<'id> {
    client: Client<'id>,
    slot: usize,
    serial: u64,
    rid: u32,
}
impl<'id> Store<'id> {
    /// Original actual accepted MQ.
    #[must_use]
    pub const fn client(self) -> Client<'id> {
        self.client
    }
    /// Original official request id.
    #[must_use]
    pub const fn request_id(self) -> u32 {
        self.rid
    }
}
#[derive(Clone, Copy)]
struct StoreState {
    slot: usize,
    serial: u64,
    rid: u32,
}
/// Original immutable storage-scan cursor, tied to one operation allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scan<'id> {
    client: Client<'id>,
    slot: usize,
    serial: u64,
    after: u64,
}
impl<'id> Scan<'id> {
    /// Original actual accepted MQ.
    #[must_use]
    pub const fn client(self) -> Client<'id> {
        self.client
    }
    /// Original actual backend cursor.
    #[must_use]
    pub const fn after(self) -> u64 {
        self.after
    }
}
/// Explicit borrowed scan request; copying filters can fail before admission.
pub struct ScanRequest<'a, 'id> {
    /// Original operation/cursor token.
    pub scan: Scan<'id>,
    /// Original retained selector bytes.
    pub filter: Filter<'a>,
}
/// Original physical-loss metadata. A queued/written record is not app delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Loss<'id> {
    /// Original accepted source.
    pub client: Client<'id>,
    /// Original output still retained at stop.
    pub pending: Option<Output<'id>>,
    /// Actual MQ admission was reported.
    pub queued: bool,
    /// Actual positive native write was reported.
    pub exposed: bool,
    /// An actual STORE outcome remained unknown.
    pub unknown_store: Option<u32>,
    /// Original admitted storage effect still owned independently of this MQ.
    pub pending_store: Option<Store<'id>>,
}
/// One caller-owned actual client metadata row.
#[derive(Clone, Copy)]
pub struct ClientSlot {
    generation: u64,
    live: bool,
    pending: Option<usize>,
    fault: Option<Error>,
    unknown_store: Option<u32>,
    store: Option<StoreState>,
}
impl ClientSlot {
    /// Initially unused row.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            generation: 0,
            live: false,
            pending: None,
            fault: None,
            unknown_store: None,
            store: None,
        }
    }
}
impl Default for ClientSlot {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Clone, Copy)]
struct Operation {
    client: usize,
    generation: u64,
    rid: u32,
    monitor: bool,
    serial: u64,
    scanning: bool,
    peer: Option<[u8; 32]>,
    ss: Option<usize>,
    key: Option<usize>,
    seq: u64,
    credit: u64,
    initial: bool,
    sync: bool,
}
/// Caller-owned filter bytes and one iterator/monitor row; no per-record copy.
pub struct OperationSlot<'a> {
    bytes: &'a mut [u8],
    state: Option<Operation>,
}
impl<'a> OperationSlot<'a> {
    /// Empty row with explicit combined filter-byte capacity.
    #[must_use]
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, state: None }
    }
    fn filter(&self, state: Operation) -> Filter<'_> {
        let ss = state.ss.unwrap_or(0);
        Filter {
            peer: state.peer,
            subsystem: state.ss.map(|n| &self.bytes[..n]),
            key: state.key.map(|n| &self.bytes[ss..ss + n]),
        }
    }
}
#[derive(Clone, Copy)]
struct Message {
    client: usize,
    generation: u64,
    serial: u64,
    len: usize,
    queued: bool,
    exposed: bool,
    store: bool,
}
/// Shared caller-owned immutable response slab. At most one per actual MQ.
pub struct MessageSlot<'a> {
    bytes: &'a mut [u8],
    state: Option<Message>,
}
impl<'a> MessageSlot<'a> {
    /// Empty response slab. Service validates every slab's bound.
    #[must_use]
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, state: None }
    }
}
/// Explicit native-independent storage facts; serials are positive and never
/// reused within this storage namespace, including after durable restart.
#[derive(Clone, Copy, Debug)]
pub struct Row<'a> {
    /// Actual backend sequence, not an IPC RID.
    pub sequence: u64,
    /// Original retained opaque record.
    pub record: Record<'a>,
}
/// Actual storage boundary. Only Ok from store may mean committed. Every error
/// except OutcomeUnknown guarantees no mutation; OutcomeUnknown forbids success
/// and fresh storage work until the original backend resolves or stops.
pub trait Storage {
    /// Commit one MULTIPLE or REPLACE atomically, retaining monotonic sequence.
    fn store(&mut self, record: Record<'_>, replace: bool) -> Result<u64, Error>;
    /// First actual matching UID strictly after the original cursor. No expiry
    /// hiding is inferred: expiration is the explicit maintenance operation.
    fn next(&self, filter: Filter<'_>, after: u64) -> Result<Option<Row<'_>>, Error>;
    /// Atomically expire only records with expiry strictly below now.
    fn expire(&mut self, now: u64) -> Result<u64, Error>;
}
/// Complete frame bound and no hidden dynamic storage.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum encoded RECORD/STORE frame including header.
    pub record_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            record_bytes: 65535,
        }
    }
}
/// One actual original pending output view. Native copy is fallible before queued.
pub struct Prepared<'a, 'id> {
    /// Private original effect token.
    pub output: Output<'id>,
    /// Original immutable response bytes.
    pub bytes: &'a [u8],
}
/// Fixed service owner. Store/scan/expiry are explicit port calls; no scheduler,
/// thread, allocator, peer authentication or implied delivery is created here.
pub struct Service<'id, 'slots, 'bytes> {
    domain: &'id Instance,
    clients: &'slots mut [ClientSlot],
    operations: &'slots mut [OperationSlot<'bytes>],
    messages: &'slots mut [MessageSlot<'bytes>],
    limits: Limits,
    next_output: u64,
    op_cursor: usize,
}
impl<'id, 'slots, 'bytes> Service<'id, 'slots, 'bytes> {
    /// Borrow all finite metadata/filter/response storage. Baseline one shared
    /// slab per potential actual MQ guarantees another source's reply capacity.
    pub fn new(
        domain: &'id mut Instance,
        clients: &'slots mut [ClientSlot],
        operations: &'slots mut [OperationSlot<'bytes>],
        messages: &'slots mut [MessageSlot<'bytes>],
        limits: Limits,
    ) -> Result<Self, Error> {
        if clients.is_empty()
            || operations.is_empty()
            || messages.len() < clients.len()
            || !(60..=65535).contains(&limits.record_bytes)
            || clients.iter().any(|s| s.live)
            || operations.iter().any(|s| s.state.is_some())
            || messages
                .iter()
                .any(|s| s.state.is_some() || s.bytes.len() < limits.record_bytes)
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            domain,
            clients,
            operations,
            messages,
            limits,
            next_output: 0,
            op_cursor: 0,
        })
    }
    /// Fixed potential actual MQ count reserved by the caller.
    #[must_use]
    pub fn client_capacity(&self) -> usize {
        self.clients.len()
    }
    /// Complete immutable response slab/frame limit.
    #[must_use]
    pub const fn record_capacity(&self) -> usize {
        self.limits.record_bytes
    }
    fn serial(&self) -> Result<u64, Error> {
        let next = self
            .domain
            .next
            .get()
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        self.domain.next.set(next);
        Ok(next)
    }
    fn index(&self, c: Client<'id>) -> Result<usize, Error> {
        if !ptr::eq(c.domain, self.domain) {
            return Err(Error::StaleGeneration);
        }
        let s = self.clients.get(c.index).ok_or(Error::StaleGeneration)?;
        if !s.live || s.generation != c.generation {
            return Err(Error::StaleGeneration);
        }
        Ok(c.index)
    }
    fn client(&self, index: usize) -> Client<'id> {
        Client {
            domain: self.domain,
            index,
            generation: self.clients[index].generation,
        }
    }
    /// Admit only after an actual accepted MQ exists.
    pub fn attach(&mut self) -> Result<Client<'id>, Error> {
        let index = self
            .clients
            .iter()
            .position(|s| !s.live)
            .ok_or(Error::Capacity)?;
        let generation = self
            .domain
            .next
            .get()
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        self.domain.next.set(generation);
        self.clients[index] = ClientSlot {
            generation,
            live: true,
            pending: None,
            fault: None,
            unknown_store: None,
            store: None,
        };
        Ok(self.client(index))
    }
    fn enqueue(&mut self, index: usize, response: Response<'_>) -> Result<Output<'id>, Error> {
        if self.clients[index].pending.is_some() || self.clients[index].store.is_some() {
            return Err(Error::WouldBlock);
        }
        let len = response.encoded_len()?;
        if len > self.limits.record_bytes {
            return Err(Error::TooLarge);
        }
        let slot = self
            .messages
            .iter()
            .position(|m| m.state.is_none())
            .ok_or(Error::Capacity)?;
        let serial = self.next_output.checked_add(1).ok_or(Error::Overflow)?;
        response.encode(&mut self.messages[slot].bytes[..len])?;
        self.next_output = serial;
        self.messages[slot].state = Some(Message {
            client: index,
            generation: self.clients[index].generation,
            serial,
            len,
            queued: false,
            exposed: false,
            store: false,
        });
        self.clients[index].pending = Some(slot);
        Ok(Output {
            client: self.client(index),
            slot,
            serial,
        })
    }
    fn start(
        &mut self,
        index: usize,
        rid: u32,
        filter: Filter<'_>,
        monitor: bool,
        initial: bool,
    ) -> Result<(), Error> {
        if filter.subsystem.is_none() {
            return Err(Error::InvalidInput);
        }
        if self.operations.iter().filter_map(|s| s.state).any(|o| {
            o.client == index
                && o.generation == self.clients[index].generation
                && ((o.monitor && monitor) || (!o.monitor && !monitor && o.rid == rid))
        }) {
            return Err(Error::Conflict);
        }
        let ss = filter.subsystem.map(<[u8]>::len);
        let key = filter.key.map(<[u8]>::len);
        let length = ss
            .unwrap_or(0)
            .checked_add(key.unwrap_or(0))
            .ok_or(Error::Overflow)?;
        let slot = self
            .operations
            .iter()
            .position(|s| s.state.is_none() && s.bytes.len() >= length)
            .ok_or(Error::Capacity)?;
        let serial = self.serial()?;
        if let Some(b) = filter.subsystem {
            self.operations[slot].bytes[..b.len()].copy_from_slice(b)
        }
        if let Some(b) = filter.key {
            let at = ss.unwrap_or(0);
            self.operations[slot].bytes[at..at + b.len()].copy_from_slice(b)
        }
        self.operations[slot].state = Some(Operation {
            client: index,
            generation: self.clients[index].generation,
            rid,
            monitor,
            serial,
            scanning: false,
            peer: filter.peer,
            ss,
            key,
            seq: 0,
            credit: 1,
            initial,
            sync: monitor && !initial,
        });
        Ok(())
    }
    /// Accept one complete original official request. STORE success follows only
    /// actual committed storage, then preserves independent live-monitor credit.
    pub fn receive(
        &mut self,
        client: Client<'id>,
        request: Request<'_>,
        storage: &mut impl Storage,
    ) -> Result<(), Error> {
        if let Request::Store(e) = request {
            let effect = self.begin_store(client, e)?;
            let result = storage.store(e.record, e.options == 1);
            return self.complete_store(effect, e.record, result);
        }
        self.receive_control(client, request)
    }
    /// Accept a non-STORE control without accessing a storage implementation.
    /// Native storage submission/completion is a separate original effect port.
    pub fn receive_control(
        &mut self,
        client: Client<'id>,
        request: Request<'_>,
    ) -> Result<(), Error> {
        let index = self.index(client)?;
        if self.clients[index].fault.is_some() {
            return Err(Error::Cancelled);
        }
        request.encoded_len()?;
        match request {
            Request::Store(_) => return Err(Error::InvalidInput),
            Request::IterateStart(i) => self.start(index, i.rid, i.filter, false, true)?,
            Request::MonitorStart(m) => {
                self.start(index, m.rid, m.filter, true, m.iterate_first)?
            }
            Request::IterateStop { rid } => {
                if let Some(s) = self.operations.iter_mut().find(|s| {
                    s.state.is_some_and(|o| {
                        o.client == index
                            && o.generation == client.generation
                            && !o.monitor
                            && o.rid == rid
                    })
                }) {
                    s.state = None
                }
            }
            Request::IterateNext { rid, limit } => {
                if limit == 0 {
                    return Err(Error::InvalidInput);
                }
                let s = self
                    .operations
                    .iter_mut()
                    .find(|s| {
                        s.state.is_some_and(|o| {
                            o.client == index
                                && o.generation == client.generation
                                && !o.monitor
                                && o.rid == rid
                        })
                    })
                    .ok_or(Error::StaleGeneration)?;
                let o = s.state.as_mut().ok_or(Error::StaleGeneration)?;
                // An ordered NEXT replaces a finished round, never overwrites
                // still-unemitted credit from a pipelined overlapping round.
                if o.credit != 0 {
                    return Err(Error::WouldBlock);
                }
                o.credit = limit.min(MAX_ROUND);
            }
            Request::MonitorNext { limit } => {
                let s = self
                    .operations
                    .iter_mut()
                    .find(|s| {
                        s.state.is_some_and(|o| {
                            o.client == index && o.generation == client.generation && o.monitor
                        })
                    })
                    .ok_or(Error::StaleGeneration)?;
                let o = s.state.as_mut().ok_or(Error::StaleGeneration)?;
                let credit = o
                    .credit
                    .checked_add(limit.min(MAX_ROUND))
                    .ok_or(Error::Overflow)?;
                credit
                    .checked_add(if o.scanning { 1 } else { 0 })
                    .ok_or(Error::Overflow)?;
                o.credit = credit;
            }
        }
        Ok(())
    }
    fn notify(&mut self, record: Record<'_>) -> Result<(), Error> {
        for slot in 0..self.operations.len() {
            let Some(o) = self.operations[slot].state else {
                continue;
            };
            if !o.monitor || o.credit == 0 || !self.operations[slot].filter(o).matches(record) {
                continue;
            }
            // A no-iteration monitor has not entered its live phase until
            // its original SYNC is queued. If that barrier still needs this
            // source's bounded response slot, report the same explicit slow
            // monitor failure instead of mislabelling a live record as initial.
            if o.sync
                || self.clients[o.client].pending.is_some()
                || self.clients[o.client].store.is_some()
            {
                self.clients[o.client].fault = Some(Error::Capacity);
                continue;
            }
            match self.enqueue(
                o.client,
                Response::Record(Envelope {
                    rid: 0,
                    options: 0,
                    reserved: 0,
                    record,
                }),
            ) {
                Ok(_) => {
                    if let Some(o) = self.operations[slot].state.as_mut() {
                        o.credit -= 1
                    }
                }
                Err(Error::Capacity | Error::WouldBlock) => {
                    self.clients[o.client].fault = Some(Error::Capacity)
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    /// Retain the original STORE before actual backend admission. Rollback is
    /// permitted only if the actual external port refused it without admission.
    pub fn begin_store(
        &mut self,
        client: Client<'id>,
        e: Envelope<'_>,
    ) -> Result<Store<'id>, Error> {
        let i = self.index(client)?;
        if self.clients[i].fault.is_some() {
            return Err(Error::Cancelled);
        }
        if self.clients[i].pending.is_some() || self.clients[i].store.is_some() {
            return Err(Error::WouldBlock);
        }
        if e.record.subsystem.is_none() || e.record.key.is_none() {
            return Err(Error::Malformed);
        }
        let len = Request::Store(e).encoded_len()?;
        if len > self.limits.record_bytes {
            return Err(Error::TooLarge);
        }
        let effects = u64::try_from(self.operations.len())
            .map_err(|_| Error::Overflow)?
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        self.next_output
            .checked_add(effects)
            .ok_or(Error::Overflow)?;
        let slot = self
            .messages
            .iter()
            .position(|m| m.state.is_none())
            .ok_or(Error::Capacity)?;
        let serial = self.serial()?;
        Request::Store(e).encode(&mut self.messages[slot].bytes[..len])?;
        self.messages[slot].state = Some(Message {
            client: i,
            generation: client.generation,
            serial,
            len,
            queued: false,
            exposed: false,
            store: true,
        });
        self.clients[i].store = Some(StoreState {
            slot,
            serial,
            rid: e.rid,
        });
        Ok(Store {
            client,
            slot,
            serial,
            rid: e.rid,
        })
    }
    fn store_index(&self, effect: Store<'id>) -> Result<usize, Error> {
        let i = self.index(effect.client)?;
        let state = self.clients[i].store.ok_or(Error::StaleGeneration)?;
        if state.slot != effect.slot || state.serial != effect.serial || state.rid != effect.rid {
            return Err(Error::StaleGeneration);
        }
        let m = self
            .messages
            .get(effect.slot)
            .and_then(|m| m.state)
            .ok_or(Error::StaleGeneration)?;
        if !m.store || m.serial != effect.serial || m.generation != effect.client.generation {
            return Err(Error::StaleGeneration);
        }
        Ok(i)
    }
    /// Only the actual port's never-admitted refusal permits this rollback.
    pub fn store_unsubmitted(&mut self, effect: Store<'id>) -> Result<(), Error> {
        let i = self.store_index(effect)?;
        self.clients[i].store = None;
        self.messages[effect.slot].state = None;
        Ok(())
    }
    /// Apply the actual external storage outcome to the exact retained original
    /// record. A foreign result/record cannot change the current generation.
    pub fn complete_store(
        &mut self,
        effect: Store<'id>,
        record: Record<'_>,
        result: Result<u64, Error>,
    ) -> Result<(), Error> {
        let i = self.store_index(effect)?;
        let message = self.messages[effect.slot]
            .state
            .ok_or(Error::StaleGeneration)?;
        let Request::Store(original) =
            Request::decode(&self.messages[effect.slot].bytes[..message.len])?
        else {
            return Err(Error::StaleGeneration);
        };
        if original.record != record {
            return Err(Error::Conflict);
        }
        if result == Ok(0) {
            return Err(Error::Replay);
        }
        if result == Err(Error::OutcomeUnknown) {
            self.clients[i].unknown_store = Some(effect.rid);
            return Err(Error::OutcomeUnknown);
        }
        self.clients[i].store = None;
        self.messages[effect.slot].state = None;
        self.enqueue(
            i,
            Response::StoreResult {
                rid: effect.rid,
                result: if result.is_ok() { 1 } else { -1 },
            },
        )?;
        if result.is_ok() {
            self.notify(record)?
        }
        Ok(())
    }
    /// Actual committed STORE completed after its original MQ was retired. This
    /// trusted storage port notification cannot revive that source or emit its
    /// result; it only observes the committed record for other live monitors.
    pub fn committed_after_loss(&mut self, record: Record<'_>) -> Result<(), Error> {
        self.notify(record)
    }
    /// Produce at most one local monitor SYNC whose no-iteration start was
    /// actually accepted. Existing-record scans use the separate external port.
    pub fn progress(&mut self) -> Result<bool, Error> {
        for n in 0..self.operations.len() {
            let slot = (self.op_cursor + n) % self.operations.len();
            let Some(o) = self.operations[slot].state else {
                continue;
            };
            if !o.sync
                || self.clients[o.client].pending.is_some()
                || self.clients[o.client].store.is_some()
                || self.clients[o.client].fault.is_some()
            {
                continue;
            }
            self.enqueue(o.client, Response::MonitorSync)?;
            if let Some(op) = self.operations[slot].state.as_mut() {
                op.sync = false;
                op.initial = false
            }
            self.op_cursor = (slot + 1) % self.operations.len();
            return Ok(true);
        }
        Ok(false)
    }
    /// One actual eligible cursor. Native may copy and submit it to an explicit
    /// bounded worker, then report original admission through scan_started.
    pub fn scan_request(&mut self) -> Option<ScanRequest<'_, 'id>> {
        for n in 0..self.operations.len() {
            let slot = (self.op_cursor + n) % self.operations.len();
            let Some(o) = self.operations[slot].state else {
                continue;
            };
            if !o.initial
                || o.scanning
                || o.credit == 0
                || o.sync
                || self.clients[o.client].pending.is_some()
                || self.clients[o.client].store.is_some()
                || self.clients[o.client].fault.is_some()
            {
                continue;
            }
            self.op_cursor = (slot + 1) % self.operations.len();
            return Some(ScanRequest {
                scan: Scan {
                    client: self.client(o.client),
                    slot,
                    serial: o.serial,
                    after: o.seq,
                },
                filter: self.operations[slot].filter(o),
            });
        }
        None
    }
    fn scan_state(&self, scan: Scan<'id>) -> Result<Operation, Error> {
        let i = self.index(scan.client)?;
        let o = self
            .operations
            .get(scan.slot)
            .and_then(|s| s.state)
            .ok_or(Error::StaleGeneration)?;
        if o.client != i
            || o.generation != scan.client.generation
            || o.serial != scan.serial
            || o.seq != scan.after
        {
            return Err(Error::StaleGeneration);
        }
        Ok(o)
    }
    /// Reserve exactly one original record credit for an actual admitted scan;
    /// concurrent live notifications cannot spend that same reserved credit.
    pub fn scan_started(&mut self, scan: Scan<'id>) -> Result<(), Error> {
        let o = self.scan_state(scan)?;
        if o.scanning || o.credit == 0 {
            return Err(Error::WouldBlock);
        }
        if let Some(o) = self.operations[scan.slot].state.as_mut() {
            o.scanning = true;
            o.credit -= 1
        }
        Ok(())
    }
    /// Port refused this original scan without admission; refund its reservation.
    pub fn scan_unsubmitted(&mut self, scan: Scan<'id>) -> Result<(), Error> {
        let o = self.scan_state(scan)?;
        if !o.scanning {
            return Err(Error::InvalidInput);
        }
        let credit = o.credit.checked_add(1).ok_or(Error::Overflow)?;
        if let Some(o) = self.operations[scan.slot].state.as_mut() {
            o.scanning = false;
            o.credit = credit
        }
        Ok(())
    }
    /// Finish the exact actual scan, retaining a refused original result until
    /// output capacity exists. STOP/reuse makes this old receipt stale.
    pub fn complete_scan(
        &mut self,
        scan: Scan<'id>,
        result: Result<Option<Row<'_>>, Error>,
    ) -> Result<(), Error> {
        let o = self.scan_state(scan)?;
        if !o.scanning {
            return Err(Error::InvalidInput);
        }
        if self.clients[o.client].pending.is_some() || self.clients[o.client].store.is_some() {
            return Err(Error::WouldBlock);
        }
        let row = match result {
            Ok(row) => row,
            Err(Error::OutcomeUnknown) => return Err(Error::OutcomeUnknown),
            Err(reason) => {
                if o.monitor {
                    self.clients[o.client].fault = Some(reason);
                    self.operations[scan.slot].state = None;
                    return Ok(());
                }
                self.enqueue(
                    o.client,
                    Response::IterateEnd {
                        rid: o.rid,
                        result: -1,
                    },
                )?;
                self.operations[scan.slot].state = None;
                return Ok(());
            }
        };
        if let Some(row) = row {
            if !self.operations[scan.slot].filter(o).matches(row.record) {
                return Err(Error::Conflict);
            }
            if row.sequence <= scan.after {
                return Err(Error::Replay);
            }
            match self.enqueue(
                o.client,
                Response::Record(Envelope {
                    rid: if o.monitor { 0 } else { o.rid },
                    options: 0,
                    reserved: 0,
                    record: row.record,
                }),
            ) {
                Ok(_) => {
                    if let Some(op) = self.operations[scan.slot].state.as_mut() {
                        op.seq = row.sequence;
                        op.scanning = false
                    }
                }
                Err(reason @ (Error::TooLarge | Error::Capacity)) => {
                    self.clients[o.client].fault = Some(reason)
                }
                Err(e) => return Err(e),
            }
        } else {
            self.enqueue(
                o.client,
                if o.monitor {
                    Response::MonitorSync
                } else {
                    Response::IterateEnd {
                        rid: o.rid,
                        result: 1,
                    }
                },
            )?;
            if o.monitor {
                let credit = o.credit.checked_add(1).ok_or(Error::Overflow)?;
                if let Some(op) = self.operations[scan.slot].state.as_mut() {
                    op.scanning = false;
                    op.initial = false;
                    op.credit = credit
                }
            } else {
                self.operations[scan.slot].state = None
            }
        }
        Ok(())
    }
    /// Convenience synchronous port for pure/model/in-process storage. Native
    /// production uses the same original scan receipt with an explicit worker.
    pub fn pump(&mut self, storage: &impl Storage) -> Result<bool, Error> {
        if self.progress()? {
            return Ok(true);
        }
        let Some(request) = self.scan_request() else {
            return Ok(false);
        };
        let scan = request.scan;
        let result = storage.next(request.filter, scan.after);
        self.scan_started(scan)?;
        self.complete_scan(scan, result)?;
        Ok(true)
    }
    /// Actual monitor classification used by official soft shutdown: a monitor
    /// MQ does not extend the service's lifetime. No peer identity is implied.
    pub fn is_monitor(&self, client: Client<'id>) -> Result<bool, Error> {
        let i = self.index(client)?;
        Ok(self
            .operations
            .iter()
            .filter_map(|s| s.state)
            .any(|o| o.client == i && o.generation == client.generation && o.monitor))
    }
    /// Actual bounded maintenance, independent of any application MQ credit.
    pub fn expire(&mut self, storage: &mut impl Storage, now: u64) -> Result<u64, Error> {
        storage.expire(now)
    }
    /// A slow monitor's explicit finite-buffer refusal. Caller closes only this
    /// actual MQ after callbacks; no success/credit or silent loss is fabricated.
    pub fn fault(&self) -> Option<(Client<'id>, Error)> {
        self.clients.iter().enumerate().find_map(|(i, s)| {
            s.live
                .then_some(s.fault)
                .flatten()
                .map(|e| (self.client(i), e))
        })
    }
    /// View one original immutable output without claiming MQ admission.
    pub fn output(&self, client: Client<'id>) -> Result<Option<Prepared<'_, 'id>>, Error> {
        let i = self.index(client)?;
        let Some(slot) = self.clients[i].pending else {
            return Ok(None);
        };
        let m = self.messages[slot].state.ok_or(Error::StaleGeneration)?;
        Ok(Some(Prepared {
            output: Output {
                client,
                slot,
                serial: m.serial,
            },
            bytes: &self.messages[slot].bytes[..m.len],
        }))
    }
    fn message(&mut self, output: Output<'id>) -> Result<&mut Message, Error> {
        let i = self.index(output.client)?;
        if self.clients[i].pending != Some(output.slot) {
            return Err(Error::StaleGeneration);
        }
        let m = self
            .messages
            .get_mut(output.slot)
            .and_then(|s| s.state.as_mut())
            .ok_or(Error::StaleGeneration)?;
        if m.store
            || m.client != i
            || m.generation != output.client.generation
            || m.serial != output.serial
        {
            return Err(Error::StaleGeneration);
        }
        Ok(m)
    }
    /// Actual immutable frame was admitted by its original physical MQ.
    pub fn queued(&mut self, output: Output<'id>) -> Result<(), Error> {
        let m = self.message(output)?;
        if m.queued {
            return Err(Error::Conflict);
        }
        m.queued = true;
        Ok(())
    }
    /// Actual positive write on the original immutable frame.
    pub fn exposed(&mut self, output: Output<'id>) -> Result<(), Error> {
        let m = self.message(output)?;
        if !m.queued {
            return Err(Error::InvalidInput);
        }
        m.exposed = true;
        Ok(())
    }
    /// Full original frame actually wrote; release only this original slab.
    pub fn written(&mut self, output: Output<'id>) -> Result<(), Error> {
        let m = self.message(output)?;
        if !m.exposed {
            return Err(Error::InvalidInput);
        }
        self.clients[output.client.index].pending = None;
        self.messages[output.slot].state = None;
        Ok(())
    }
    /// Detach only after the original physical source stopped. Iterators/monitor
    /// are canceled; an already committed STORE is never rolled back/replayed.
    pub fn detach(&mut self, client: Client<'id>) -> Result<Loss<'id>, Error> {
        let i = self.index(client)?;
        let pending = self.clients[i].pending;
        let state = pending.and_then(|s| self.messages[s].state);
        let loss = Loss {
            client,
            pending: state.map(|m| Output {
                client,
                slot: pending.unwrap_or(0),
                serial: m.serial,
            }),
            queued: state.is_some_and(|m| m.queued),
            exposed: state.is_some_and(|m| m.exposed),
            unknown_store: self.clients[i].unknown_store,
            pending_store: self.clients[i].store.map(|m| Store {
                client,
                slot: m.slot,
                serial: m.serial,
                rid: m.rid,
            }),
        };
        if let Some(slot) = pending {
            self.messages[slot].state = None
        }
        if let Some(store) = self.clients[i].store.take() {
            self.messages[store.slot].state = None
        }
        for s in &mut *self.operations {
            if s.state
                .is_some_and(|o| o.client == i && o.generation == client.generation)
            {
                s.state = None
            }
        }
        self.clients[i].live = false;
        self.clients[i].pending = None;
        Ok(loss)
    }
}

#[cfg(test)]
mod tests;
