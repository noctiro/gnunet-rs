use crate::{
    AttemptId, Epoch, GetId, HelloId, Instance, MonitorId, OperationId, identity::Brand, ipc,
};
use alloc::vec::Vec;
use gnunet_crypto::hash512;
use gnunet_types::Error;
use gnunet_wire::official::{AbsoluteTime, Frame, message_type};
use zeroize::{Zeroize, Zeroizing};

/// Explicit resource policy; variable source allocations and physical output
/// frames have independent budgets.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Active and draining logical GETs.
    pub gets: usize,
    /// Active and draining monitor registrations.
    pub monitors: usize,
    /// Pending public HELLO observations.
    pub hellos: usize,
    /// Outstanding one-shot operations, including terminal notices not yet taken.
    pub operations: usize,
    /// Original physical attempts issued concurrently.
    pub attempts: usize,
    /// Original GET/known/one-shot allocation charges until final release.
    pub source_bytes: usize,
    /// Distinct remembered hashes per GET; zero disables automatic history.
    pub known_per_get: usize,
    /// Complete outgoing/input frame upper bound, from144 through65535.
    pub frame_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            gets: 32,
            monitors: 16,
            hellos: 16,
            operations: 32,
            attempts: 64,
            source_bytes: 1024 * 1024,
            known_per_get: 128,
            frame_bytes: 65535,
        }
    }
}
/// Original GET parameters. The client assigns opaque wire correlation bytes.
#[derive(Clone, Copy, Debug)]
pub struct Get<'b> {
    /// Exact requested key, including an all-zero key.
    pub key: &'b [u8; 64],
    /// Requested concrete type or ANY0.
    pub block_type: u32,
    /// Original public route options.
    pub options: u32,
    /// Requested replication before service policy.
    pub replication: u32,
    /// Original plugin-specific query bytes.
    pub extended_query: &'b [u8],
}
/// Owned public monitor selectors. Nonzero flag values retain their wire width.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Monitor {
    /// Concrete block type or ANY0.
    pub block_type: u32,
    /// GET selection flag.
    pub get: u16,
    /// RESULT selection flag.
    pub result: u16,
    /// PUT selection flag.
    pub put: u16,
    /// Optional exact key, distinct from Some(all-zero).
    pub key: Option<[u8; 64]>,
}
impl Monitor {
    fn wire(&self) -> ipc::Monitor<'_> {
        ipc::Monitor {
            block_type: self.block_type,
            get: self.get,
            get_response: self.result,
            put: self.put,
            key: self.key.as_ref(),
        }
    }
    fn matches(&self, kind: MonitorKind, block: u32, key: &[u8; 64]) -> bool {
        (self.block_type == 0 || self.block_type == block)
            && self.key.is_none_or(|k| k == *key)
            && match kind {
                MonitorKind::Get => self.get != 0,
                MonitorKind::Result => self.result != 0,
                MonitorKind::Put => self.put != 0,
            }
    }
}
/// Which public monitor payload was actually received.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MonitorKind {
    /// Official149.
    Get,
    /// Official150.
    Result,
    /// Official151.
    Put,
}
/// Exact purpose of an original immutable output. This enum alone is not an attempt capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action<'a> {
    /// Start/reconstruct this original logical GET on one physical epoch.
    Get(GetId<'a>),
    /// Stop this original logical GET.
    Stop(GetId<'a>),
    /// Original chunk of known hashes.
    Known {
        /// Original GET.
        get: GetId<'a>,
        /// Number of original hashes.
        count: usize,
    },
    /// Start/reconstruct this monitor registration.
    MonitorStart(MonitorId<'a>),
    /// Stop this monitor registration.
    MonitorStop(MonitorId<'a>),
    /// Request an observation, not an authenticated identity.
    Hello(HelloId<'a>),
    /// One original PUT, without a service acknowledgement.
    Put(OperationId<'a>),
    /// One original HELLO offer, without a service acknowledgement.
    Offer(OperationId<'a>),
}
/// Private original output capability; scalar fields cannot reconstruct one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Attempt<'a> {
    id: AttemptId<'a>,
    epoch: Epoch<'a>,
    action: Action<'a>,
}
impl<'a> Attempt<'a> {
    /// Original physical stream.
    #[must_use]
    pub const fn epoch(self) -> Epoch<'a> {
        self.epoch
    }
    /// Actual logical action.
    #[must_use]
    pub const fn action(self) -> Action<'a> {
        self.action
    }
    /// Diagnostic identity only.
    #[must_use]
    pub const fn id(self) -> AttemptId<'a> {
        self.id
    }
}
/// One original immutable wire frame. Dropping it does not undo its issue;
/// finish its FIFO write or retire that original physical MQ.
pub struct Outbound<'a> {
    attempt: Attempt<'a>,
    bytes: Zeroizing<Vec<u8>>,
}
impl<'a> Outbound<'a> {
    /// Original capability to settle only after an actual complete local write.
    #[must_use]
    pub const fn attempt(&self) -> Attempt<'a> {
        self.attempt
    }
    /// Exact official bytes with no private prefix.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Move the same buffer to native framing. The receiver owns erasure duty.
    #[must_use]
    pub fn into_parts(mut self) -> (Attempt<'a>, Vec<u8>) {
        (self.attempt, core::mem::take(&mut self.bytes))
    }
}
/// Terminal local one-shot outcome; none means service processing or delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Every original frame byte was written to its original local MQ.
    Written,
    /// Cancellation suppressed the operation callback, but its original frame finished writing.
    CanceledWritten,
    /// Physical loss made the local write uncertain; it is never replayed.
    Lost,
    /// A canceled original frame was retired with its physical MQ.
    CanceledLost,
}
/// Original terminal notice, retained until explicitly taken.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Completion<'a> {
    /// Original logical operation.
    pub operation: OperationId<'a>,
    /// Original physical MQ owner, including pending bytes not yet issued.
    pub epoch: Option<Epoch<'a>>,
    /// Local outcome only.
    pub outcome: Outcome,
}
/// What cancellation did to the original owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cancel {
    /// Never-issued bytes were removed without a native effect.
    BeforeIssue,
    /// Already-issued bytes must finish their original FIFO or lose that MQ.
    Draining,
}
/// A complete input that did not address a live logical recipient.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ignored {
    /// Unknown/canceled/old GET ID, key or type; it grants no query authority.
    Result,
    /// No current matching monitor.
    Monitor,
    /// No pending written HELLO observation on this physical epoch.
    Hello,
}
/// Provenance of a received public observation. Payload structure grants no
/// block/path/address authentication.
#[derive(Debug)]
pub enum Event<'a> {
    /// Actual original GET result, without BLOCK or path authenticity assertion.
    Result {
        /// Original logical GET.
        get: GetId<'a>,
        /// Whether this payload hash was already known.
        duplicate: bool,
        /// Whether bounded reconnect history retained its hash.
        remembered: bool,
    },
    /// Actual monitor frame delivered to these original local subscriptions.
    Monitor {
        /// Public kind.
        kind: MonitorKind,
        /// Current matching registrations.
        monitors: Vec<MonitorId<'a>>,
    },
    /// Actual public HELLO snapshot for these written observations.
    Hello {
        /// Original requests fulfilled by this current-MQ snapshot.
        requests: Vec<HelloId<'a>>,
    },
    /// Actual unrelated input was consumed without a fabricated callback.
    Ignored(Ignored),
}
/// Owned complete received observation; erased on drop. Borrowed decoding is
/// explicit and remains unverified protocol metadata.
pub struct Received<'a> {
    epoch: Epoch<'a>,
    event: Event<'a>,
    bytes: Zeroizing<Vec<u8>>,
}
impl<'a> Received<'a> {
    /// Actual original physical stream.
    #[must_use]
    pub const fn epoch(&self) -> Epoch<'a> {
        self.epoch
    }
    /// Original logical recipients and bounded-history outcome.
    #[must_use]
    pub const fn event(&self) -> &Event<'a> {
        &self.event
    }
    /// Original complete bytes, empty only for explicitly ignored input.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Decode a RESULT145 without adding authenticity.
    pub fn result(&self) -> Result<ipc::ResultMessage<'_>, Error> {
        ipc::ResultMessage::decode(&self.bytes)
    }
    /// Extract a structurally valid HELLO159 URL, including actual None absence.
    pub fn hello_url(&self) -> Result<Option<&[u8]>, Error> {
        match ipc::Request::decode(&self.bytes)? {
            ipc::Request::HelloUrl(url) => Ok(url),
            _ => Err(Error::Unsupported),
        }
    }
}
/// Current bounded usage; counts are diagnostics rather than capabilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// Retained logical GETs including STOP drain.
    pub gets: usize,
    /// Retained monitor registrations including STOP drain.
    pub monitors: usize,
    /// Retained public HELLO requests.
    pub hellos: usize,
    /// Original one-shots, including untaken terminal notices.
    pub operations: usize,
    /// Issued original physical frames not fully written yet.
    pub attempts: usize,
    /// Actual retained variable source allocation capacities.
    pub source_bytes: usize,
    /// Permanent close state.
    pub closed: bool,
}
struct Query<'a> {
    id: GetId<'a>,
    wire: ipc::RequestId,
    key: [u8; 64],
    kind: u32,
    source: Zeroizing<Vec<u8>>,
    known: Vec<[u8; 64]>,
    charge: usize,
    announced: Option<Epoch<'a>>,
    written: Option<Epoch<'a>>,
    next_known: usize,
    canceled: bool,
    stop_issued: bool,
}
struct Registration<'a> {
    id: MonitorId<'a>,
    spec: Monitor,
    announced: Option<Epoch<'a>>,
    written: Option<Epoch<'a>>,
    canceled: bool,
    stop_issued: bool,
}
struct Observation<'a> {
    id: HelloId<'a>,
    announced: Option<Epoch<'a>>,
    written: Option<Epoch<'a>>,
    canceled: bool,
}
#[derive(Clone, Copy)]
enum CommandKind {
    Put,
    Offer,
}
#[derive(Clone, Copy)]
enum CommandState<'a> {
    Pending,
    Issued(Epoch<'a>),
    Terminal(Option<Epoch<'a>>, Outcome),
}
struct Command<'a> {
    id: OperationId<'a>,
    kind: CommandKind,
    epoch: Epoch<'a>,
    source: Zeroizing<Vec<u8>>,
    charge: usize,
    state: CommandState<'a>,
    canceled: bool,
}
#[derive(Clone, Copy)]
enum Selected {
    Query(usize, u8),
    Monitor(usize, bool),
    Hello(usize),
    Command(usize),
}
/// Bounded pure logical DHT client. The native host must retire original IO
/// before `lost`/`close`; no socket, task, callback or hidden RNG exists here.
pub struct Client<'a> {
    brand: Brand<'a>,
    limits: Limits,
    serial: u64,
    wire_serial: u64,
    wire_exhausted: bool,
    epoch: Option<Epoch<'a>>,
    queries: Vec<Query<'a>>,
    monitors: Vec<Registration<'a>>,
    hellos: Vec<Observation<'a>>,
    commands: Vec<Command<'a>>,
    attempts: Vec<Attempt<'a>>,
    source_bytes: usize,
    domain: usize,
    cursors: [usize; 4],
    closed: bool,
}
impl<'a> Client<'a> {
    /// Reserve all bounded metadata, then accept caller requests without native IO.
    pub fn new(instance: &'a mut Instance, limits: Limits) -> Result<Self, Error> {
        if !(144..=65535).contains(&limits.frame_bytes) || limits.attempts == 0 {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            brand: Brand(instance),
            limits,
            serial: 0,
            wire_serial: 0,
            wire_exhausted: false,
            epoch: None,
            queries: reserved(limits.gets)?,
            monitors: reserved(limits.monitors)?,
            hellos: reserved(limits.hellos)?,
            commands: reserved(limits.operations)?,
            attempts: reserved(limits.attempts)?,
            source_bytes: 0,
            domain: 0,
            cursors: [0; 4],
            closed: false,
        })
    }
    fn open(&self) -> Result<(), Error> {
        if self.closed {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }
    fn next_serial(&self) -> Result<u64, Error> {
        self.serial.checked_add(1).ok_or(Error::Overflow)
    }
    fn check_brand(&self, brand: Brand<'a>) -> Result<(), Error> {
        if self.brand == brand {
            Ok(())
        } else {
            Err(Error::InvalidInput)
        }
    }
    fn check_epoch(&self, epoch: Epoch<'a>) -> Result<(), Error> {
        self.open()?;
        self.check_brand(epoch.brand)?;
        if self.epoch == Some(epoch) {
            Ok(())
        } else {
            Err(Error::Stale)
        }
    }
    fn charge(&self, n: usize) -> Result<(), Error> {
        if self.source_bytes.checked_add(n).ok_or(Error::Overflow)? > self.limits.source_bytes {
            Err(Error::Capacity)
        } else {
            Ok(())
        }
    }
    /// Adopt exactly one new physical MQ after old IO has really retired.
    pub fn connect(&mut self) -> Result<Epoch<'a>, Error> {
        self.open()?;
        if self.epoch.is_some() {
            return Err(Error::Conflict);
        }
        let serial = self.next_serial()?;
        let epoch = Epoch {
            brand: self.brand,
            serial,
        };
        self.serial = serial;
        self.epoch = Some(epoch);
        Ok(epoch)
    }
    /// Current physical stream, with no service/node identity assertion.
    #[must_use]
    pub const fn epoch(&self) -> Option<Epoch<'a>> {
        self.epoch
    }
    /// Whether another physical MQ can be attached.
    #[must_use]
    pub const fn connection_needed(&self) -> bool {
        !self.closed && self.epoch.is_none()
    }
    /// Admission assigns never-reused opaque correlation, starting with legal zero.
    pub fn get(&mut self, g: Get<'_>) -> Result<GetId<'a>, Error> {
        self.open()?;
        if self.queries.len() == self.limits.gets {
            return Err(Error::Capacity);
        }
        if self.wire_exhausted {
            return Err(Error::Overflow);
        }
        let serial = self.next_serial()?;
        let wire = ipc::RequestId(self.wire_serial.to_be_bytes());
        let message = ipc::Get {
            options: g.options,
            replication: g.replication,
            block_type: g.block_type,
            key: g.key,
            id: wire,
            extended_query: g.extended_query,
        };
        let n = message.encoded_len()?;
        if n > self.limits.frame_bytes {
            return Err(Error::TooLarge);
        }
        let mut source = Zeroizing::new(bytes(n)?);
        message.encode(&mut source)?;
        let known = reserved::<[u8; 64]>(self.limits.known_per_get)?;
        let charge = source
            .capacity()
            .checked_add(known.capacity().checked_mul(64).ok_or(Error::Overflow)?)
            .ok_or(Error::Overflow)?;
        self.charge(charge)?;
        let id = GetId {
            brand: self.brand,
            serial,
        };
        self.serial = serial;
        if self.wire_serial == u64::MAX {
            self.wire_exhausted = true
        } else {
            self.wire_serial += 1
        }
        self.source_bytes += charge;
        self.queries.push(Query {
            id,
            wire,
            key: *g.key,
            kind: g.block_type,
            source,
            known,
            charge,
            announced: None,
            written: None,
            next_known: 0,
            canceled: false,
            stop_issued: false,
        });
        Ok(id)
    }
    fn query_index(&self, id: GetId<'a>) -> Result<usize, Error> {
        self.open()?;
        self.check_brand(id.brand)?;
        self.queries
            .iter()
            .position(|q| q.id == id)
            .ok_or(Error::Stale)
    }
    /// Inspect only the original wire correlation data, never reconstruct authority.
    pub fn request_id(&self, id: GetId<'a>) -> Result<ipc::RequestId, Error> {
        Ok(self.queries[self.query_index(id)?].wire)
    }
    /// Atomically retain all distinct explicit known hashes or refuse capacity.
    pub fn known(&mut self, id: GetId<'a>, hashes: &[[u8; 64]]) -> Result<(), Error> {
        let i = self.query_index(id)?;
        let q = &mut self.queries[i];
        if q.canceled {
            return Err(Error::Stale);
        }
        let extra = hashes
            .iter()
            .enumerate()
            .filter(|(i, h)| !q.known.contains(h) && !hashes[..*i].contains(h))
            .count();
        if q.known.len().checked_add(extra).ok_or(Error::Overflow)? > self.limits.known_per_get {
            return Err(Error::Capacity);
        }
        for hash in hashes {
            if !q.known.contains(hash) {
                q.known.push(*hash)
            }
        }
        Ok(())
    }
    /// Stop the original query. Already issued bytes retain FIFO ownership.
    pub fn stop(&mut self, id: GetId<'a>) -> Result<Cancel, Error> {
        let i = self.query_index(id)?;
        if self.queries[i].canceled {
            return Ok(Cancel::Draining);
        }
        if self.queries[i].announced == self.epoch && self.epoch.is_some() {
            self.queries[i].canceled = true;
            Ok(Cancel::Draining)
        } else {
            let q = self.queries.remove(i);
            self.source_bytes -= q.charge;
            Ok(Cancel::BeforeIssue)
        }
    }
    /// Admit a public monitor; it is restored on replacement MQs.
    pub fn monitor(&mut self, spec: Monitor) -> Result<MonitorId<'a>, Error> {
        self.open()?;
        if self.monitors.len() == self.limits.monitors {
            return Err(Error::Capacity);
        }
        let serial = self.next_serial()?;
        let id = MonitorId {
            brand: self.brand,
            serial,
        };
        self.monitors.push(Registration {
            id,
            spec,
            announced: None,
            written: None,
            canceled: false,
            stop_issued: false,
        });
        self.serial = serial;
        Ok(id)
    }
    /// Remove this original monitor, preserving any already-issued partial START.
    pub fn stop_monitor(&mut self, id: MonitorId<'a>) -> Result<Cancel, Error> {
        self.open()?;
        self.check_brand(id.brand)?;
        let i = self
            .monitors
            .iter()
            .position(|m| m.id == id)
            .ok_or(Error::Stale)?;
        if self.monitors[i].canceled {
            return Ok(Cancel::Draining);
        }
        if self.monitors[i].announced == self.epoch && self.epoch.is_some() {
            self.monitors[i].canceled = true;
            Ok(Cancel::Draining)
        } else {
            self.monitors.remove(i);
            Ok(Cancel::BeforeIssue)
        }
    }
    /// Request a public HELLO snapshot. This idempotent observation intent can
    /// be reissued on a fresh MQ; it is not replay of its original physical bytes.
    pub fn hello(&mut self) -> Result<HelloId<'a>, Error> {
        self.open()?;
        if self.hellos.len() == self.limits.hellos {
            return Err(Error::Capacity);
        }
        let serial = self.next_serial()?;
        let id = HelloId {
            brand: self.brand,
            serial,
        };
        self.hellos.push(Observation {
            id,
            announced: None,
            written: None,
            canceled: false,
        });
        self.serial = serial;
        Ok(id)
    }
    /// Suppress this logical observation; an issued header still drains its MQ.
    pub fn cancel_hello(&mut self, id: HelloId<'a>) -> Result<Cancel, Error> {
        self.open()?;
        self.check_brand(id.brand)?;
        let i = self
            .hellos
            .iter()
            .position(|h| h.id == id)
            .ok_or(Error::Stale)?;
        if self.hellos[i].canceled {
            return Ok(Cancel::Draining);
        }
        if self.hellos[i].announced == self.epoch
            && self.hellos[i].written != self.epoch
            && self.epoch.is_some()
        {
            self.hellos[i].canceled = true;
            Ok(Cancel::Draining)
        } else {
            self.hellos.remove(i);
            Ok(Cancel::BeforeIssue)
        }
    }
    fn one_shot(
        &mut self,
        kind: CommandKind,
        source: Zeroizing<Vec<u8>>,
    ) -> Result<OperationId<'a>, Error> {
        self.open()?;
        if self.epoch.is_none() {
            return Err(Error::NotReady);
        }
        let epoch = self.epoch.ok_or(Error::NotReady)?;
        if self.commands.len() == self.limits.operations {
            return Err(Error::Capacity);
        }
        if source.len() > self.limits.frame_bytes {
            return Err(Error::TooLarge);
        }
        let charge = source.capacity();
        self.charge(charge)?;
        let serial = self.next_serial()?;
        let id = OperationId {
            brand: self.brand,
            serial,
        };
        self.serial = serial;
        self.source_bytes += charge;
        self.commands.push(Command {
            id,
            kind,
            epoch,
            source,
            charge,
            state: CommandState::Pending,
            canceled: false,
        });
        Ok(id)
    }
    /// Admit a nonempty original PUT only while an MQ exists. Completion means
    /// local full writing, never service acceptance, replication or durability.
    pub fn put(&mut self, p: ipc::Put<'_>) -> Result<OperationId<'a>, Error> {
        self.open()?;
        if self.epoch.is_none() {
            return Err(Error::NotReady);
        }
        if p.payload.is_empty() {
            return Err(Error::InvalidInput);
        }
        let n = p.encoded_len()?;
        if n > self.limits.frame_bytes {
            return Err(Error::TooLarge);
        }
        let mut source = Zeroizing::new(bytes(n)?);
        p.encode(&mut source)?;
        self.one_shot(CommandKind::Put, source)
    }
    /// Offer a parsed, unexpired, signature-checked official URL. The returned
    /// coverage is MetadataOnly for v0.29.1; no address authenticity is inferred.
    pub fn offer_hello(
        &mut self,
        url: &[u8],
        storage: &mut [u8],
        limits: gnunet_hello::Limits,
        now: AbsoluteTime,
    ) -> Result<(OperationId<'a>, gnunet_hello::SignatureCoverage), Error> {
        self.open()?;
        if self.epoch.is_none() {
            return Err(Error::NotReady);
        }
        let n = url.len().checked_add(5).ok_or(Error::Overflow)?;
        if n > self.limits.frame_bytes {
            return Err(Error::TooLarge);
        }
        let hello = gnunet_hello::Hello::parse_url(url, storage, limits)?;
        let checked = hello.verify_at(gnunet_hello::SignatureProfile::Gnunet029, now)?;
        let coverage = checked.coverage();
        let mut source = Zeroizing::new(bytes(n)?);
        ipc::encode_hello(Some(url), false, &mut source)?;
        Ok((self.one_shot(CommandKind::Offer, source)?, coverage))
    }
    /// Cancel an original one-shot notification. Issued immutable bytes must
    /// finish or lose that MQ; they are never silently swapped or replayed.
    pub fn cancel(&mut self, id: OperationId<'a>) -> Result<Cancel, Error> {
        self.open()?;
        self.check_brand(id.brand)?;
        let i = self
            .commands
            .iter()
            .position(|c| c.id == id)
            .ok_or(Error::Stale)?;
        match self.commands[i].state {
            CommandState::Pending => {
                let c = self.commands.remove(i);
                self.source_bytes -= c.charge;
                Ok(Cancel::BeforeIssue)
            }
            CommandState::Issued(_) => {
                self.commands[i].canceled = true;
                Ok(Cancel::Draining)
            }
            CommandState::Terminal(..) => Err(Error::Stale),
        }
    }
    /// Take one retained original terminal notice; metadata/source capacity is
    /// released only for this same logical operation.
    pub fn completion(&mut self) -> Option<Completion<'a>> {
        let i = self
            .commands
            .iter()
            .position(|c| matches!(c.state, CommandState::Terminal(..)))?;
        let c = self.commands.remove(i);
        self.source_bytes -= c.charge;
        let CommandState::Terminal(epoch, outcome) = c.state else {
            return None;
        };
        Some(Completion {
            operation: c.id,
            epoch,
            outcome,
        })
    }
    fn selected(&self) -> Option<(usize, Selected)> {
        let epoch = self.epoch?;
        if self.closed || self.attempts.len() == self.limits.attempts {
            return None;
        }
        for offset in 0..4 {
            let domain = (self.domain + offset) % 4;
            match domain {
                0 => {
                    for k in 0..self.queries.len() {
                        let i = (self.cursors[0] + k) % self.queries.len();
                        let q = &self.queries[i];
                        let mode = if q.canceled {
                            if q.announced == Some(epoch) && !q.stop_issued {
                                Some(1)
                            } else {
                                None
                            }
                        } else if q.announced != Some(epoch) {
                            Some(0)
                        } else if q.next_known < q.known.len() {
                            Some(2)
                        } else {
                            None
                        };
                        if let Some(mode) = mode {
                            return Some((domain, Selected::Query(i, mode)));
                        }
                    }
                }
                1 => {
                    for k in 0..self.monitors.len() {
                        let i = (self.cursors[1] + k) % self.monitors.len();
                        let m = &self.monitors[i];
                        if (m.canceled && m.announced == Some(epoch) && !m.stop_issued)
                            || (!m.canceled && m.announced != Some(epoch))
                        {
                            return Some((domain, Selected::Monitor(i, m.canceled)));
                        }
                    }
                }
                2 => {
                    for k in 0..self.hellos.len() {
                        let i = (self.cursors[2] + k) % self.hellos.len();
                        let h = &self.hellos[i];
                        if !h.canceled && h.announced != Some(epoch) {
                            return Some((domain, Selected::Hello(i)));
                        }
                    }
                }
                _ => {
                    for k in 0..self.commands.len() {
                        let i = (self.cursors[3] + k) % self.commands.len();
                        if matches!(self.commands[i].state, CommandState::Pending) {
                            return Some((domain, Selected::Command(i)));
                        }
                    }
                }
            }
        }
        None
    }
    fn selected_size(&self, selected: Selected) -> usize {
        match selected {
            Selected::Query(i, 0) => self.queries[i].source.len(),
            Selected::Query(i, 1) | Selected::Monitor(i, _) => {
                let _index = i;
                80
            }
            Selected::Query(i, _) => {
                80 + 64
                    * (self.queries[i].known.len() - self.queries[i].next_known)
                        .min((self.limits.frame_bytes - 80) / 64)
            }
            Selected::Hello(_) => 4,
            Selected::Command(i) => self.commands[i].source.len(),
        }
    }
    /// Extent of the next fair immutable frame, without leasing or mutating it.
    #[must_use]
    pub fn next_size(&self) -> Option<usize> {
        self.selected().map(|(_, s)| self.selected_size(s))
    }
    /// Lease one fair immutable original frame after the host reserves its
    /// corresponding physical framing budget. Dropping it requires MQ retirement.
    pub fn outbound(&mut self) -> Result<Option<Outbound<'a>>, Error> {
        self.open()?;
        let Some((domain, selected)) = self.selected() else {
            return Ok(None);
        };
        let epoch = self.epoch.ok_or(Error::NotReady)?;
        let serial = self.next_serial()?;
        let n = self.selected_size(selected);
        let mut data = if let Selected::Command(_) = selected {
            Vec::new()
        } else {
            bytes(n)?
        };
        let action = match selected {
            Selected::Query(i, 0) => {
                data.copy_from_slice(&self.queries[i].source);
                self.queries[i].announced = Some(epoch);
                Action::Get(self.queries[i].id)
            }
            Selected::Query(i, 1) => {
                let q = &self.queries[i];
                ipc::Stop {
                    id: q.wire,
                    key: &q.key,
                }
                .encode(&mut data)?;
                self.queries[i].stop_issued = true;
                Action::Stop(self.queries[i].id)
            }
            Selected::Query(i, _) => {
                let q = &self.queries[i];
                let from = q.next_known;
                let count = (q.known.len() - from).min((self.limits.frame_bytes - 80) / 64);
                ipc::Known {
                    key: &q.key,
                    id: q.wire,
                    hashes: ipc::Hashes::new(q.known[from..from + count].as_flattened())?,
                }
                .encode(&mut data)?;
                self.queries[i].next_known += count;
                Action::Known {
                    get: self.queries[i].id,
                    count,
                }
            }
            Selected::Monitor(i, stop) => {
                self.monitors[i].spec.wire().encode(stop, &mut data)?;
                if stop {
                    self.monitors[i].stop_issued = true;
                    Action::MonitorStop(self.monitors[i].id)
                } else {
                    self.monitors[i].announced = Some(epoch);
                    Action::MonitorStart(self.monitors[i].id)
                }
            }
            Selected::Hello(i) => {
                ipc::encode_hello(None, true, &mut data)?;
                self.hellos[i].announced = Some(epoch);
                Action::Hello(self.hellos[i].id)
            }
            Selected::Command(i) => {
                data = core::mem::take(&mut self.commands[i].source);
                self.commands[i].state = CommandState::Issued(epoch);
                match self.commands[i].kind {
                    CommandKind::Put => Action::Put(self.commands[i].id),
                    CommandKind::Offer => Action::Offer(self.commands[i].id),
                }
            }
        };
        let index = match selected {
            Selected::Query(i, _)
            | Selected::Monitor(i, _)
            | Selected::Hello(i)
            | Selected::Command(i) => i,
        };
        self.cursors[domain] = index + 1;
        self.domain = (domain + 1) % 4;
        self.serial = serial;
        let attempt = Attempt {
            id: AttemptId {
                brand: self.brand,
                serial,
            },
            epoch,
            action,
        };
        self.attempts.push(attempt);
        Ok(Some(Outbound {
            attempt,
            bytes: Zeroizing::new(data),
        }))
    }
    /// Settle exactly the first original FIFO frame after its last native byte.
    /// A foreign or early/out-of-order report leaves every attempt unchanged.
    pub fn written(&mut self, attempt: Attempt<'a>) -> Result<Action<'a>, Error> {
        self.check_epoch(attempt.epoch)?;
        if self.attempts.first() != Some(&attempt) {
            return Err(Error::Stale);
        }
        match attempt.action {
            Action::Get(id) => {
                let i = self.query_index(id)?;
                self.queries[i].written = Some(attempt.epoch)
            }
            Action::Stop(id) => {
                let i = self.query_index(id)?;
                let q = self.queries.remove(i);
                self.source_bytes -= q.charge
            }
            Action::Known { get, .. } => {
                self.query_index(get)?;
            }
            Action::MonitorStart(id) => {
                let m = self
                    .monitors
                    .iter_mut()
                    .find(|m| m.id == id)
                    .ok_or(Error::Stale)?;
                m.written = Some(attempt.epoch)
            }
            Action::MonitorStop(id) => {
                let i = self
                    .monitors
                    .iter()
                    .position(|m| m.id == id)
                    .ok_or(Error::Stale)?;
                self.monitors.remove(i);
            }
            Action::Hello(id) => {
                let i = self
                    .hellos
                    .iter()
                    .position(|h| h.id == id)
                    .ok_or(Error::Stale)?;
                if self.hellos[i].canceled {
                    self.hellos.remove(i);
                } else {
                    self.hellos[i].written = Some(attempt.epoch)
                }
            }
            Action::Put(id) | Action::Offer(id) => {
                let c = self
                    .commands
                    .iter_mut()
                    .find(|c| c.id == id)
                    .ok_or(Error::Stale)?;
                if !matches!(c.state,CommandState::Issued(e)if e==attempt.epoch) {
                    return Err(Error::Stale);
                }
                c.state = CommandState::Terminal(
                    Some(attempt.epoch),
                    if c.canceled {
                        Outcome::CanceledWritten
                    } else {
                        Outcome::Written
                    },
                )
            }
        };
        self.attempts.remove(0);
        Ok(attempt.action)
    }
    /// Interpret one complete actual input only for the current physical MQ.
    /// Copies and all recipient allocation precede changes to known/result state.
    pub fn receive(&mut self, epoch: Epoch<'a>, input: &[u8]) -> Result<Received<'a>, Error> {
        self.check_epoch(epoch)?;
        if input.len() > self.limits.frame_bytes {
            return Err(Error::TooLarge);
        }
        let frame = Frame::decode(input)?;
        let event = match frame.header().message_type() {
            message_type::DHT_CLIENT_RESULT => {
                let result = ipc::ResultMessage::decode(input)?;
                let Some(i) = self.queries.iter().position(|q| {
                    !q.canceled
                        && q.written == Some(epoch)
                        && q.wire == result.id
                        && q.key == *result.key
                        && (q.kind == 0 || q.kind == result.block_type)
                }) else {
                    return Ok(ignored(epoch, Ignored::Result));
                };
                let hash = hash512(result.payload);
                let q = &self.queries[i];
                let duplicate = q.known.contains(&hash);
                let remembered = duplicate || q.known.len() < self.limits.known_per_get;
                let owned = copy(input)?;
                let q = &mut self.queries[i];
                if !duplicate && remembered {
                    let previous = q.known.len();
                    q.known.push(hash);
                    if q.next_known == previous {
                        q.next_known += 1
                    }
                }
                return Ok(Received {
                    epoch,
                    event: Event::Result {
                        get: q.id,
                        duplicate,
                        remembered,
                    },
                    bytes: Zeroizing::new(owned),
                });
            }
            message_type::DHT_MONITOR_GET
            | message_type::DHT_MONITOR_GET_RESP
            | message_type::DHT_MONITOR_PUT => {
                let (kind, block, key) = match frame.header().message_type() {
                    message_type::DHT_MONITOR_GET => {
                        let m = ipc::MonitorGet::decode(input)?;
                        (MonitorKind::Get, m.block_type, *m.key)
                    }
                    message_type::DHT_MONITOR_GET_RESP => {
                        let m = ipc::MonitorResult::decode(input)?;
                        (MonitorKind::Result, m.block_type, *m.key)
                    }
                    _ => {
                        let m = ipc::MonitorPut::decode(input)?;
                        (MonitorKind::Put, m.block_type, *m.key)
                    }
                };
                let mut matches = reserved(self.monitors.len())?;
                for m in &self.monitors {
                    if !m.canceled && m.written == Some(epoch) && m.spec.matches(kind, block, &key)
                    {
                        matches.push(m.id)
                    }
                }
                if matches.is_empty() {
                    return Ok(ignored(epoch, Ignored::Monitor));
                }
                Event::Monitor {
                    kind,
                    monitors: matches,
                }
            }
            message_type::DHT_CLIENT_HELLO_URL => {
                let ipc::Request::HelloUrl(_) = ipc::Request::decode(input)? else {
                    return Err(Error::Malformed);
                };
                let mut requests = reserved(self.hellos.len())?;
                for h in &self.hellos {
                    if !h.canceled && h.written == Some(epoch) {
                        requests.push(h.id)
                    }
                }
                if requests.is_empty() {
                    return Ok(ignored(epoch, Ignored::Hello));
                }
                let owned = copy(input)?;
                self.hellos.retain(|h| !requests.contains(&h.id));
                return Ok(Received {
                    epoch,
                    event: Event::Hello { requests },
                    bytes: Zeroizing::new(owned),
                });
            }
            _ => return Err(Error::Unsupported),
        };
        Ok(Received {
            epoch,
            event,
            bytes: Zeroizing::new(copy(input)?),
        })
    }
    /// Retire one original physical MQ after the host has stopped all its IO.
    /// GET/filter/monitor/observation intent survives; one-shots never replay.
    pub fn lost(&mut self, epoch: Epoch<'a>) -> Result<(), Error> {
        self.check_epoch(epoch)?;
        self.epoch = None;
        self.attempts.clear();
        self.queries.retain(|q| !q.canceled);
        self.monitors.retain(|m| !m.canceled);
        self.hellos.retain(|h| !h.canceled);
        for q in &mut self.queries {
            q.announced = None;
            q.written = None;
            q.next_known = 0;
            q.stop_issued = false
        }
        for m in &mut self.monitors {
            m.announced = None;
            m.written = None;
            m.stop_issued = false
        }
        for h in &mut self.hellos {
            h.announced = None;
            h.written = None
        }
        for c in &mut self.commands {
            if !matches!(c.state, CommandState::Terminal(..)) {
                c.source.zeroize();
                c.state = CommandState::Terminal(
                    Some(epoch),
                    if c.canceled {
                        Outcome::CanceledLost
                    } else {
                        Outcome::Lost
                    },
                )
            }
        }
        self.recount();
        Ok(())
    }
    /// Permanently close after native retirement. Outstanding original one-shot
    /// notices remain drainable; no further epoch or operation can be created.
    pub fn close(&mut self) {
        self.closed = true;
        self.epoch = None;
        self.attempts.clear();
        self.queries.clear();
        self.monitors.clear();
        self.hellos.clear();
        for c in &mut self.commands {
            if !matches!(c.state, CommandState::Terminal(..)) {
                let epoch = Some(c.epoch);
                c.source.zeroize();
                c.state = CommandState::Terminal(
                    epoch,
                    if c.canceled {
                        Outcome::CanceledLost
                    } else {
                        Outcome::Lost
                    },
                )
            }
        }
        self.recount();
    }
    fn recount(&mut self) {
        self.source_bytes = self.queries.iter().map(|q| q.charge).sum::<usize>()
            + self.commands.iter().map(|c| c.charge).sum::<usize>();
    }
    /// Read bounded logical usage without reconstructing any capability.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            gets: self.queries.len(),
            monitors: self.monitors.len(),
            hellos: self.hellos.len(),
            operations: self.commands.len(),
            attempts: self.attempts.len(),
            source_bytes: self.source_bytes,
            closed: self.closed,
        }
    }
}
fn ignored<'a>(epoch: Epoch<'a>, reason: Ignored) -> Received<'a> {
    Received {
        epoch,
        event: Event::Ignored(reason),
        bytes: Zeroizing::new(Vec::new()),
    }
}
fn reserved<T>(n: usize) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    Ok(v)
}
fn bytes(n: usize) -> Result<Vec<u8>, Error> {
    let mut v = reserved(n)?;
    v.resize(n, 0);
    Ok(v)
}
fn copy(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut v = bytes(input.len())?;
    v.copy_from_slice(input);
    Ok(v)
}
