//! Fixed directories, shared actual-length payload accounting and original
//! effects. No hidden resolver, process, native source or output success exists.
use crate::*;
use alloc::vec::Vec;
use core::{cell::Cell, fmt, ptr};
use zeroize::Zeroizing;
/// Stable caller allocation domain, no hidden global IDs or Atomic64 target need.
pub struct Instance {
    next: Cell<u64>,
}
impl Instance {
    /// Empty allocation domain, no effect.
    pub const fn new() -> Self {
        Self { next: Cell::new(0) }
    }
    fn allocate(&self) -> Result<u64, Error> {
        let n = self.next.get().checked_add(1).ok_or(Error::Overflow)?;
        self.next.set(n);
        Ok(n)
    }
}
impl Default for Instance {
    fn default() -> Self {
        Self::new()
    }
}
impl PartialEq for Instance {
    fn eq(&self, b: &Self) -> bool {
        ptr::eq(self, b)
    }
}
impl Eq for Instance {}
#[derive(Clone, Copy, Eq, PartialEq)]
struct Scope<'a> {
    domain: &'a Instance,
    serial: u64,
}
impl fmt::Debug for Scope<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsInterceptionScope")
            .field("serial", &self.serial)
            .finish_non_exhaustive()
    }
}
/// Original accepted client MQ, not merely UID or a carried identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Client<'id> {
    scope: Scope<'id>,
    row: usize,
    serial: u64,
}
/// Original actual privileged-helper pipe/process source generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Source<'id> {
    scope: Scope<'id>,
    serial: u64,
}
/// Original intercepted request, independent from DNS-ID collisions and clients.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request<'id> {
    scope: Scope<'id>,
    row: usize,
    serial: u64,
}
/// Exact source-scoped actual resolver operation; no wire field is introduced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Resolve<'id> {
    request: Request<'id>,
    serial: u64,
}
impl<'id> Resolve<'id> {
    /// Original service request scope; no answer is implied.
    pub const fn request(self) -> Request<'id> {
        self.request
    }
}
/// Actual output destination, whose physical retirement is separately required.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Destination<'id> {
    /// Original local client MQ.
    Client(Client<'id>),
    /// Original helper IPC source.
    Helper(Source<'id>),
}
/// Immutable original output attempt. Private construction binds exact original
/// request/phase/client/source and serial; it contains no private wire RID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Effect<'id> {
    request: Request<'id>,
    serial: u64,
    destination: Destination<'id>,
}
impl<'id> Effect<'id> {
    /// Exact original request.
    pub const fn request(self) -> Request<'id> {
        self.request
    }
    /// Actual destination owner.
    pub const fn destination(self) -> Destination<'id> {
        self.destination
    }
}
/// Current protocol phase. Only actual client/resolver results advance it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Read-only query observers.
    RequestMonitor,
    /// Answer/query-rewrite providers.
    PreResolution,
    /// Actual original outbound DNSSTUB job outstanding or ready.
    Resolver,
    /// Response rewrite providers.
    PostResolution,
    /// Read-only final observers.
    ResponseMonitor,
    /// Actual helper output awaits local whole-write.
    Output,
    /// Original request is dropped/expired; external debts still need retirement.
    Dropped,
}
/// Explicit bounded directory and payload limits.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    ///1..64; eligible phase snapshot is one u64 bitmap.
    pub clients: usize,
    /// Fixed request rows, allocated once.
    pub requests: usize,
    /// Shared current payload capacities; no maximum buffer per client/request.
    pub bytes: usize,
    /// Maximum actual DNS payload,12..MAX_DNS_BYTES.
    pub payload_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            clients: 16,
            requests: 128,
            bytes: 4 * 1024 * 1024,
            payload_bytes: MAX_DNS_BYTES,
        }
    }
}
#[derive(Clone, Copy)]
struct App {
    serial: u64,
    flags: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Read-only original output lifecycle; none means remote DNS/application delivery.
pub enum OutputPhase {
    /// Exact bytes prepared but not admitted to native MQ.
    Prepared,
    /// Immutable bytes admitted to the original native queue.
    Queued,
    /// Actual positive original local-write prefix observed.
    Exposed,
    /// Original complete local-write observed; callback decision may still wait.
    Written,
}
#[derive(Clone, Copy)]
struct Output<'id> {
    effect: Effect<'id>,
    phase: OutputPhase,
}
struct Row<'id> {
    serial: u64,
    source: Source<'id>,
    id: [u8; 8],
    payload: Zeroizing<Vec<u8>>,
    from: Address,
    to: Address,
    source_port: u16,
    destination_port: u16,
    phase: Phase,
    eligible: u64,
    water: u64,
    current: Option<Client<'id>>,
    output: Option<Output<'id>>,
    resolver: Option<Resolve<'id>>,
    until: u64,
    expired: bool,
}
/// One next actual provider/output requirement, borrowed without admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Work<'id> {
    /// Encode and queue one original client callback.
    Client {
        /// Original intercepted request.
        request: Request<'id>,
        /// Exact accepted application MQ allocation.
        client: Client<'id>,
    },
    /// Submit a real resolver operation.
    Resolve(Request<'id>),
    /// Encode and queue one real helper reply.
    Helper {
        /// Original intercepted request.
        request: Request<'id>,
        /// Exact original helper process/pipe source.
        source: Source<'id>,
    },
    /// Actual original output source must retire before cleanup.
    Close(Destination<'id>),
    /// Cancel only the original actual resolver operation.
    Cancel(Resolve<'id>),
    /// No external debt remains; caller may retire original row.
    Retire(Request<'id>),
}
/// One pure bounded owner. It mints no accepted MQ, helper readiness, resolver
/// answer, remote delivery or filesystem success on construction.
pub struct Engine<'id> {
    scope: Scope<'id>,
    limits: Limits,
    apps: Vec<Option<App>>,
    rows: Vec<Option<Row<'id>>>,
    source: Option<Source<'id>>,
    used: usize,
    last_client: u64,
    closed: bool,
}
fn fixed<T>(n: usize) -> Result<Vec<Option<T>>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    v.resize_with(n, || None);
    Ok(v)
}
impl<'id> Engine<'id> {
    /// Allocate bounded directories; native ports remain explicitly external.
    pub fn new(instance: &'id Instance, limits: Limits) -> Result<Self, Error> {
        if !(1..=64).contains(&limits.clients)
            || limits.requests == 0
            || !(12..=MAX_DNS_BYTES).contains(&limits.payload_bytes)
            || limits.bytes < limits.payload_bytes
        {
            return Err(Error::InvalidInput);
        }
        let scope = Scope {
            domain: instance,
            serial: instance.allocate()?,
        };
        Ok(Self {
            scope,
            limits,
            apps: fixed(limits.clients)?,
            rows: fixed(limits.requests)?,
            source: None,
            used: 0,
            last_client: 0,
            closed: false,
        })
    }
    fn live(&self) -> Result<(), Error> {
        if self.closed {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }
    fn app(&self, c: Client<'id>) -> Result<App, Error> {
        self.live()?;
        if c.scope != self.scope {
            return Err(Error::StaleGeneration);
        }
        let app = self
            .apps
            .get(c.row)
            .and_then(Option::as_ref)
            .ok_or(Error::StaleGeneration)?;
        if app.serial != c.serial {
            return Err(Error::StaleGeneration);
        }
        Ok(*app)
    }
    fn row(&self, r: Request<'id>) -> Result<&Row<'id>, Error> {
        if r.scope != self.scope {
            return Err(Error::StaleGeneration);
        }
        let row = self
            .rows
            .get(r.row)
            .and_then(Option::as_ref)
            .ok_or(Error::StaleGeneration)?;
        if row.serial != r.serial {
            return Err(Error::StaleGeneration);
        }
        Ok(row)
    }
    fn row_mut(&mut self, r: Request<'id>) -> Result<&mut Row<'id>, Error> {
        self.row(r)?;
        self.rows[r.row].as_mut().ok_or(Error::StaleGeneration)
    }
    fn handle(&self, row: usize) -> Result<Request<'id>, Error> {
        Ok(Request {
            scope: self.scope,
            row,
            serial: self.rows[row]
                .as_ref()
                .ok_or(Error::StaleGeneration)?
                .serial,
        })
    }
    /// Mint only after actual original helper pipe/FD ownership was attached. This
    /// is source identity, not proof that routing/interception setup is finished.
    pub fn attach_source(&mut self) -> Result<Source<'id>, Error> {
        self.live()?;
        if self.source.is_some() {
            return Err(Error::Conflict);
        }
        let source = Source {
            scope: self.scope,
            serial: self.scope.domain.allocate()?,
        };
        self.source = Some(source);
        Ok(source)
    }
    /// Actual accepted MQ allocation; INIT flags initially zero as official.
    pub fn attach_client(&mut self) -> Result<Client<'id>, Error> {
        self.live()?;
        let row = self
            .apps
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let serial = self.scope.domain.allocate()?;
        self.apps[row] = Some(App { serial, flags: 0 });
        self.last_client = serial;
        Ok(Client {
            scope: self.scope,
            row,
            serial,
        })
    }
    /// Actual decoded original INIT, with raw future flag bits preserved.
    pub fn init(&mut self, client: Client<'id>, flags: u32) -> Result<(), Error> {
        self.app(client)?;
        self.apps[client.row]
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .flags = flags;
        Ok(())
    }
    fn mask(&self, phase: Phase) -> u64 {
        let flag = match phase {
            Phase::RequestMonitor => wire::REQUEST_MONITOR,
            Phase::PreResolution => wire::PRE_RESOLUTION,
            Phase::PostResolution => wire::POST_RESOLUTION,
            Phase::ResponseMonitor => wire::RESPONSE_MONITOR,
            _ => 0,
        };
        self.apps.iter().enumerate().fold(0, |bits, (i, a)| {
            if a.is_some_and(|a| a.flags & flag != 0) {
                bits | (1u64 << i)
            } else {
                bits
            }
        })
    }
    fn enter(&mut self, r: Request<'id>, phase: Phase) -> Result<(), Error> {
        let mask = self.mask(phase);
        let water = self.last_client;
        let row = self.row_mut(r)?;
        row.phase = phase;
        row.eligible = mask;
        row.water = water;
        row.current = None;
        row.output = None;
        Ok(())
    }
    /// Consume actual checksum-checked helper raw UDP/53 query. Duplicate DNS IDs
    /// from different OS sockets remain independent requests and original tuples.
    pub fn intercept(
        &mut self,
        source: Source<'id>,
        packet: &[u8],
        now: u64,
        until: u64,
    ) -> Result<Request<'id>, Error> {
        self.live()?;
        if self.source != Some(source) {
            return Err(Error::StaleGeneration);
        }
        if now >= until || until == u64::MAX {
            return Err(Error::Deadline);
        }
        let p = gnunet_vpn::packet::Packet::parse(packet)?;
        p.validate_checksums()?;
        if p.protocol() != gnunet_vpn::packet::UDP {
            return Err(Error::Unsupported);
        }
        let ports = p.ports()?;
        if ports.1 != 53 {
            return Err(Error::Unsupported);
        }
        let payload = p.segment().get(8..).ok_or(Error::Truncated)?;
        let header = gnunet_dns::Header::decode(payload)?;
        if header.flags.bits() & 0x8000 != 0 {
            return Err(Error::Malformed);
        }
        if payload.len() > self.limits.payload_bytes {
            return Err(Error::TooLarge);
        }
        let row = self
            .rows
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        if payload.len() > self.limits.bytes.saturating_sub(self.used) {
            return Err(Error::Capacity);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(payload.len())
            .map_err(|_| Error::Capacity)?;
        if bytes.capacity() > self.limits.bytes.saturating_sub(self.used) {
            return Err(Error::Capacity);
        }
        let serial = self.scope.domain.allocate()?;
        bytes.extend_from_slice(payload);
        let r = Request {
            scope: self.scope,
            row,
            serial,
        };
        let mask = self.mask(Phase::RequestMonitor);
        self.used += bytes.capacity();
        self.rows[row] = Some(Row {
            serial,
            source,
            id: serial.to_be_bytes(),
            payload: Zeroizing::new(bytes),
            from: p.source(),
            to: p.destination(),
            source_port: ports.0,
            destination_port: ports.1,
            phase: Phase::RequestMonitor,
            eligible: mask,
            water: self.last_client,
            current: None,
            output: None,
            resolver: None,
            until,
            expired: false,
        });
        Ok(r)
    }
    /// Original finite deadline metadata.
    pub fn deadline(&self, r: Request<'id>) -> Result<u64, Error> {
        Ok(self.row(r)?.until)
    }
    /// Exact current original DNS bytes for actual provider submission.
    pub fn payload(&self, r: Request<'id>) -> Result<&[u8], Error> {
        Ok(&self.row(r)?.payload)
    }
    /// Pure lookup of the next bounded requirement. Phase transitions use actual
    /// prior results; current phase's client bitmap freezes eligibility at entry.
    pub fn next_work(&mut self, r: Request<'id>) -> Result<Work<'id>, Error> {
        for _ in 0..6 {
            let row = self.row(r)?;
            if row.expired || row.phase == Phase::Dropped {
                if let Some(out) = row.output {
                    return Ok(Work::Close(out.effect.destination));
                }
                if let Some(job) = row.resolver {
                    return Ok(Work::Cancel(job));
                }
                return Ok(Work::Retire(r));
            }
            if row.output.is_some() {
                return Err(Error::WouldBlock);
            }
            if row.phase == Phase::Resolver {
                return if row.resolver.is_some() {
                    Err(Error::WouldBlock)
                } else {
                    Ok(Work::Resolve(r))
                };
            }
            if row.phase == Phase::Output {
                return Ok(Work::Helper {
                    request: r,
                    source: row.source,
                });
            }
            let eligible = row.eligible;
            let water = row.water;
            let next = self
                .apps
                .iter()
                .enumerate()
                .filter_map(|(i, a)| {
                    let a = a.as_ref()?;
                    (eligible & (1u64 << i) != 0 && a.serial <= water).then_some((i, *a))
                })
                .max_by_key(|(_, a)| a.serial);
            if let Some((index, app)) = next {
                let client = Client {
                    scope: self.scope,
                    row: index,
                    serial: app.serial,
                };
                self.row_mut(r)?.current = Some(client);
                return Ok(Work::Client { request: r, client });
            }
            let phase = match self.row(r)?.phase {
                Phase::RequestMonitor => Phase::PreResolution,
                Phase::PreResolution => Phase::Resolver,
                Phase::PostResolution => Phase::ResponseMonitor,
                Phase::ResponseMonitor => Phase::Output,
                _ => return Err(Error::Conflict),
            };
            self.enter(r, phase)?;
        }
        Err(Error::Conflict)
    }
    /// Encode one original callback, then reserve its immutable effect. Native
    /// allocation/queue failure must reject_prepared before it changes MQ ownership.
    pub fn prepare_client(
        &mut self,
        r: Request<'id>,
        client: Client<'id>,
        out: &mut [u8],
    ) -> Result<(Effect<'id>, usize), Error> {
        self.app(client)?;
        let row = self.row(r)?;
        if row.output.is_some() || row.current != Some(client) || row.expired {
            return Err(Error::NotReady);
        }
        let n = wire::Response {
            id: row.id,
            dns: &row.payload,
        }
        .encode(out)?;
        let effect = Effect {
            request: r,
            serial: self.scope.domain.allocate()?,
            destination: Destination::Client(client),
        };
        self.row_mut(r)?.output = Some(Output {
            effect,
            phase: OutputPhase::Prepared,
        });
        Ok((effect, n))
    }
    /// Build actual checksummed IP/UDP reply and official helper framing; native
    /// whole pipe write remains distinct from actual TUN whole packet submission.
    pub fn prepare_helper(
        &mut self,
        r: Request<'id>,
        out: &mut [u8],
    ) -> Result<(Effect<'id>, usize), Error> {
        let row = self.row(r)?;
        if row.phase != Phase::Output || row.output.is_some() || row.expired {
            return Err(Error::NotReady);
        }
        let size =
            8 + match row.from.family() {
                Family::V4 => 20,
                Family::V6 => 40,
            } + 8
                + row.payload.len();
        if out.len() < size {
            return Err(Error::Capacity);
        }
        gnunet_wire::official::MessageHeader::from_total_size(
            gnunet_wire::official::message_type::DNS_HELPER,
            size,
        )?
        .encode(out)?;
        out[4..6].fill(0);
        let protocol: u16 = if row.from.family() == Family::V4 {
            0x0800
        } else {
            0x86dd
        };
        out[6..8].copy_from_slice(&protocol.to_be_bytes());
        let mut udp = [0; 8];
        udp[..2].copy_from_slice(&row.destination_port.to_be_bytes());
        udp[2..4].copy_from_slice(&row.source_port.to_be_bytes());
        let n = gnunet_vpn::packet::build_parts(
            row.to,
            row.from,
            gnunet_vpn::packet::UDP,
            &udp,
            &row.payload,
            &mut out[8..],
        )? + 8;
        let effect = Effect {
            request: r,
            serial: self.scope.domain.allocate()?,
            destination: Destination::Helper(row.source),
        };
        self.row_mut(r)?.output = Some(Output {
            effect,
            phase: OutputPhase::Prepared,
        });
        Ok((effect, n))
    }
    fn output_mut(&mut self, e: Effect<'id>) -> Result<&mut Output<'id>, Error> {
        let o = self
            .row_mut(e.request)?
            .output
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        if o.effect != e {
            return Err(Error::StaleGeneration);
        }
        Ok(o)
    }
    /// Actual immutable frame entered that destination's queue.
    pub fn queued(&mut self, e: Effect<'id>) -> Result<(), Error> {
        let o = self.output_mut(e)?;
        if o.phase != OutputPhase::Prepared {
            return Err(Error::Conflict);
        }
        o.phase = OutputPhase::Queued;
        Ok(())
    }
    /// Actual positive original prefix, not an ACK or delivery.
    pub fn exposed(&mut self, e: Effect<'id>) -> Result<(), Error> {
        let o = self.output_mut(e)?;
        if !matches!(o.phase, OutputPhase::Queued | OutputPhase::Exposed) {
            return Err(Error::Conflict);
        }
        o.phase = OutputPhase::Exposed;
        Ok(())
    }
    /// Actual local complete write. Helper pipe write retires only that original
    /// service output, not remote receipt or an unprovided TUN_WRITE ACK.
    pub fn written(&mut self, e: Effect<'id>) -> Result<(), Error> {
        let o = self.output_mut(e)?;
        if !matches!(o.phase, OutputPhase::Queued | OutputPhase::Exposed) {
            return Err(Error::Conflict);
        }
        if matches!(e.destination, Destination::Helper(_)) {
            self.row_mut(e.request)?.output = None;
            self.row_mut(e.request)?.phase = Phase::Dropped;
        } else {
            o.phase = OutputPhase::Written;
        }
        Ok(())
    }
    /// Native never-admitted output allocation failed, with no exposed bytes.
    pub fn reject_prepared(&mut self, e: Effect<'id>) -> Result<(), Error> {
        if self.output_mut(e)?.phase != OutputPhase::Prepared {
            return Err(Error::Conflict);
        }
        self.row_mut(e.request)?.output = None;
        Ok(())
    }
    fn replace(&mut self, r: Request<'id>, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > self.limits.payload_bytes {
            return Err(Error::TooLarge);
        }
        gnunet_dns::Header::decode(bytes)?;
        let old = self.row(r)?.payload.capacity();
        if bytes.len() <= old {
            let row = self.row_mut(r)?;
            row.payload.fill(0);
            row.payload.resize(bytes.len(), 0);
            row.payload.copy_from_slice(bytes);
            return Ok(());
        }
        let remaining = self.limits.bytes.saturating_sub(self.used);
        if bytes.len() > remaining {
            return Err(Error::Capacity);
        }
        let mut next = Vec::new();
        next.try_reserve_exact(bytes.len())
            .map_err(|_| Error::Capacity)?;
        if next.capacity() > remaining {
            return Err(Error::Capacity);
        }
        next.extend_from_slice(bytes);
        self.used = self.used - old + next.capacity();
        self.row_mut(r)?.payload = Zeroizing::new(next);
        Ok(())
    }
    /// Actual original client REPLY. Unknown stale RID is ignored; wrong client or
    /// premature callback retirement is refused, never retagged onto another query.
    pub fn reply(
        &mut self,
        client: Client<'id>,
        id: [u8; 8],
        decision: Decision<'_>,
    ) -> Result<bool, Error> {
        self.app(client)?;
        let Some(index) = self
            .rows
            .iter()
            .position(|row| row.as_ref().is_some_and(|r| r.id == id))
        else {
            return Ok(false);
        };
        let r = self.handle(index)?;
        let row = self.row(r)?;
        if row.expired {
            return Ok(false);
        }
        let output = row.output.ok_or(Error::PermissionDenied)?;
        if row.current != Some(client)
            || output.effect.destination != Destination::Client(client)
            || output.phase != OutputPhase::Written
        {
            return Err(Error::PermissionDenied);
        }
        let phase = row.phase;
        if let Decision::Answer(bytes) = decision {
            if matches!(phase, Phase::RequestMonitor | Phase::ResponseMonitor) {
                return Err(Error::PermissionDenied);
            }
            self.replace(r, bytes)?;
        }
        let row = self.row_mut(r)?;
        row.eligible &= !(1u64 << client.row);
        row.current = None;
        row.output = None;
        match decision {
            Decision::Drop => row.phase = Phase::Dropped,
            Decision::Forward => {}
            Decision::Answer(_) => {
                if phase == Phase::PreResolution {
                    let answered =
                        gnunet_dns::Header::decode(&row.payload)?.flags.bits() & 0x8000 != 0;
                    if answered {
                        self.enter(r, Phase::PostResolution)?
                    } else {
                        self.enter(r, Phase::Resolver)?
                    }
                }
            }
        }
        Ok(true)
    }
    /// Original resolver operation is admitted only after actual native resolve()
    /// returned its real ID; native owner retains that exact mapping externally.
    pub fn resolving(&mut self, r: Request<'id>) -> Result<Resolve<'id>, Error> {
        let row = self.row(r)?;
        if row.phase != Phase::Resolver || row.resolver.is_some() || row.expired {
            return Err(Error::NotReady);
        }
        let job = Resolve {
            request: r,
            serial: self.scope.domain.allocate()?,
        };
        self.row_mut(r)?.resolver = Some(job);
        Ok(job)
    }
    /// Submit checked original actual resolver payload. No signature/DNSSEC or
    /// application-success assertion is made by matching DNS header/question data.
    pub fn resolved(&mut self, job: Resolve<'id>, bytes: &[u8]) -> Result<(), Error> {
        let row = self.row(job.request)?;
        if row.resolver != Some(job) || row.expired {
            return Err(Error::StaleGeneration);
        }
        if !questions_match(&row.payload, bytes)? {
            return Err(Error::Authentication);
        }
        self.replace(job.request, bytes)?;
        self.row_mut(job.request)?.resolver = None;
        self.enter(job.request, Phase::PostResolution)
    }
    /// Exact native cancellation/eviction/failure has retired callback authority.
    /// It is not cached socket close or remote request revocation evidence.
    pub fn resolve_stopped(&mut self, job: Resolve<'id>) -> Result<(), Error> {
        if self.row(job.request)?.resolver != Some(job) {
            return Err(Error::StaleGeneration);
        }
        let row = self.row_mut(job.request)?;
        row.resolver = None;
        row.phase = Phase::Dropped;
        Ok(())
    }
    /// Actual physical client owner stopped: clear only original callback effects
    /// and phase snapshots. Other clients and intercepted requests continue.
    pub fn client_lost(&mut self, client: Client<'id>) -> Result<(), Error> {
        self.app(client)?;
        self.apps[client.row] = None;
        for row in self.rows.iter_mut().flatten() {
            row.eligible &= !(1u64 << client.row);
            if row.current == Some(client) {
                row.current = None;
                row.output = None;
            }
        }
        Ok(())
    }
    /// Actual physical helper source closed. All its original outputs and resolver
    /// jobs remain explicitly canceled/retired; no payload is replayed to a new one.
    pub fn source_lost(&mut self, source: Source<'id>) -> Result<(), Error> {
        if self.source != Some(source) {
            return Err(Error::StaleGeneration);
        }
        self.source = None;
        for row in self.rows.iter_mut().flatten() {
            if row.source == source {
                row.phase = Phase::Dropped;
                if row
                    .output
                    .is_some_and(|out| out.effect.destination == Destination::Helper(source))
                {
                    row.output = None;
                }
                // A helper loss does not physically stop an application MQ.
                // Preserve that callback debt until its original MQ is retired.
                row.expired = true;
            }
        }
        Ok(())
    }
    /// Original native hard target expired or owner explicitly canceled. This
    /// leaves real external output/resolver debts until their actual retirement.
    pub fn abort(&mut self, request: Request<'id>) -> Result<(), Error> {
        let row = self.row_mut(request)?;
        row.expired = true;
        row.phase = Phase::Dropped;
        Ok(())
    }
    /// Logical expiry does not pretend to cancel a partial MQ or DNSSTUB job.
    pub fn expire(&mut self, now: u64) {
        for row in self.rows.iter_mut().flatten() {
            if now >= row.until {
                row.expired = true;
                row.phase = Phase::Dropped;
            }
        }
    }
    /// Original rows, for caller-driven fair bounded work scheduling.
    pub fn requests(&self) -> impl Iterator<Item = Request<'id>> + '_ {
        self.rows.iter().enumerate().filter_map(|(i, row)| {
            row.as_ref().map(|r| Request {
                scope: self.scope,
                row: i,
                serial: r.serial,
            })
        })
    }
    /// Release only an actual terminal row with all original external debts settled.
    pub fn retire(&mut self, r: Request<'id>) -> Result<(), Error> {
        let row = self.row(r)?;
        if row.phase != Phase::Dropped || row.output.is_some() || row.resolver.is_some() {
            return Err(Error::WouldBlock);
        }
        let row = self.rows[r.row].take().ok_or(Error::StaleGeneration)?;
        self.used = self
            .used
            .checked_sub(row.payload.capacity())
            .ok_or(Error::Conflict)?;
        Ok(())
    }
    /// Exact configured local-MQ ceiling, for native construction consistency.
    pub const fn client_capacity(&self) -> usize {
        self.limits.clients
    }
    /// Exact maximum DNS bytes accepted by this original owner.
    pub const fn payload_limit(&self) -> usize {
        self.limits.payload_bytes
    }
    /// Fixed table ceiling for fair O(capacity) native scheduling, no nth rescans.
    pub const fn request_capacity(&self) -> usize {
        self.limits.requests
    }
    /// One original table row, checked only as read-only scheduling metadata.
    pub fn request_at(&self, index: usize) -> Option<Request<'id>> {
        self.rows.get(index)?.as_ref().map(|row| Request {
            scope: self.scope,
            row: index,
            serial: row.serial,
        })
    }
    /// All original callbacks on this still-current client, before its actual
    /// physical source loss is applied. Read-only facts grant no new authority.
    pub fn client_outputs(
        &self,
        client: Client<'id>,
    ) -> Result<impl Iterator<Item = (Effect<'id>, OutputPhase)> + '_, Error> {
        self.app(client)?;
        Ok(self.rows.iter().flatten().filter_map(move |r| {
            r.output
                .filter(|o| o.effect.destination == Destination::Client(client))
                .map(|o| (o.effect, o.phase))
        }))
    }
    /// Actual outstanding original callback metadata for this live MQ. INIT or a
    /// different RID cannot reset the oldest callback's native hard deadline.
    pub fn pending_client(&self, client: Client<'id>) -> Result<bool, Error> {
        self.app(client)?;
        Ok(self.rows.iter().flatten().any(|r| {
            r.output
                .is_some_and(|o| o.effect.destination == Destination::Client(client))
        }))
    }
    /// Actual retained payload allocation, independent of configured directory caps.
    pub const fn payload_bytes(&self) -> usize {
        self.used
    }
}
/// Bounded shared DNSPARSER question comparison. A source-matching DNSSTUB
/// datagram is still unverified; match original transaction/opcode/questions.
fn questions_match(query: &[u8], answer: &[u8]) -> Result<bool, Error> {
    let a = gnunet_dns::Header::decode(query)?;
    let b = gnunet_dns::Header::decode(answer)?;
    if a.id != b.id
        || b.flags.bits() & 0x8000 == 0
        || (a.flags.bits() & 0x7800) != (b.flags.bits() & 0x7800)
    {
        return Ok(false);
    }
    if b.counts.queries == 0 && b.flags.bits() & 15 != 0 {
        return Ok(true);
    }
    let maximum_queries = query.len().saturating_sub(12) / 5;
    if a.counts.queries != b.counts.queries || usize::from(a.counts.queries) > maximum_queries {
        return Ok(false);
    }
    let limits = gnunet_dns::Limits {
        maximum_queries,
        ..gnunet_dns::Limits::DNS
    };
    let mut qa = gnunet_dns::Reader::at(query, 12, query.len(), limits)?;
    let mut qb = gnunet_dns::Reader::at(answer, 12, answer.len(), limits)?;
    for _ in 0..a.counts.queries {
        let mut left = [0; 255];
        let mut right = [0; 255];
        let a = qa.query(&mut gnunet_dns::Arena::new(&mut left))?;
        let b = qb.query(&mut gnunet_dns::Arena::new(&mut right))?;
        if a.kind != b.kind
            || a.class != b.class
            || !a.name.wire().eq_ignore_ascii_case(b.name.wire())
        {
            return Ok(false);
        }
    }
    Ok(true)
}
