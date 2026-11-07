//! Bounded original DNS, VPN lease, exit, channel and retry state.
//! Caller ports must bind every completion to the original opaque token. No
//! state transition treats a queued effect, local write or DHT result as a reply.
use crate::{
    Error,
    exit::Advertisement,
    packet::{self, Address, AddressRecord, Families, Replacement},
};
use alloc::vec::Vec;
use core::{cell::Cell, fmt};
/// Caller-owned domain; counters never wrap and no entropy is required for IDs.
#[derive(Default)]
pub struct Instance {
    next: Cell<u64>,
}
impl Instance {
    /// New explicit state domain.
    pub const fn new() -> Self {
        Self { next: Cell::new(0) }
    }
}
#[derive(Clone, Copy)]
struct Brand<'a> {
    owner: &'a Instance,
    allocation: u64,
    serial: u64,
}
impl PartialEq for Brand<'_> {
    fn eq(&self, o: &Self) -> bool {
        core::ptr::eq(self.owner, o.owner)
            && self.allocation == o.allocation
            && self.serial == o.serial
    }
}
impl Eq for Brand<'_> {}
impl fmt::Debug for Brand<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Original")
            .field(&self.allocation)
            .field(&self.serial)
            .finish()
    }
}
macro_rules! token {
    ($n:ident,$d:literal) => {
        #[doc=$d]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $n<'a>(Brand<'a>);
    };
}
token!(
    Source,
    "One actually attached original DNS interception MQ and stage."
);
token!(Request, "One original intercepted DNS callback.");
token!(Job, "One original VPN allocation operation.");
token!(
    Tunnel,
    "One original CADET channel attempt, never a peer-only identity."
);
token!(Attempt, "One original DNS send on one exact channel.");
token!(Discovery, "One caller-owned live DHT GET operation.");
/// Official interception stage, each on its own original DNS MQ.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    /// DNS-over-CADET before external resolution.
    Pre,
    /// IP replacement after DNS resolution.
    Post,
}
/// Explicit finite budgets. Caller owns the independent native deadline too.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Concurrent intercepted requests, across both sources.
    pub requests: usize,
    /// Maximum original DNS payload.
    pub packet_bytes: usize,
    /// All retained request payload/response capacity.
    pub payload_bytes: usize,
    /// Maximum records in a packet, also plan slots.
    pub records: usize,
    /// Maximum questions in a packet.
    pub questions: usize,
    /// Bounded advertised candidate peers.
    pub exits: usize,
    /// Concurrent channel attempts, at most four.
    pub tunnels: usize,
    /// Attempts per original DNS request.
    pub attempts: u32,
    /// Per original DNS/VPN operation microseconds.
    pub timeout: u64,
    /// Bounded retry delay after a failed original channel.
    pub retry: u64,
    /// Bounded parser work for one packet.
    pub parse_work: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            requests: 256,
            packet_bytes: 8192,
            payload_bytes: 4 * 1024 * 1024,
            records: 512,
            questions: 16,
            exits: 128,
            tunnels: 4,
            attempts: 4,
            timeout: 60_000_000,
            retry: 1_000_000,
            parse_work: 1024 * 1024,
        }
    }
}
impl Limits {
    fn validate(self) -> Result<(), Error> {
        if self.requests == 0
            || self.requests > 65536
            || !(12..=65519).contains(&self.packet_bytes)
            || self.payload_bytes < self.packet_bytes
            || self.records == 0
            || self.records > 65535
            || self.questions > 65535
            || self.exits == 0
            || self.tunnels == 0
            || self.tunnels > 4
            || self.tunnels > self.exits
            || self.attempts == 0
            || self.timeout == 0
            || self.timeout == u64::MAX
            || self.retry == 0
            || self.parse_work == 0
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
    fn dns(self) -> gnunet_dns::Limits {
        gnunet_dns::Limits {
            maximum_packet_bytes: self.packet_bytes,
            maximum_queries: self.questions,
            maximum_records: self.records,
            maximum_compression_hops: 33,
            maximum_work: self.parse_work,
            maximum_text_input_bytes: self.packet_bytes,
        }
    }
}
struct SourceRow<'a> {
    source: Source<'a>,
    stage: Stage,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase<'a> {
    AllocReady,
    AllocPending(Job<'a>),
    PreReady,
    SendReady(Attempt<'a>, Tunnel<'a>, u16),
    SendQueued(Attempt<'a>, Tunnel<'a>, u16),
    Waiting(Attempt<'a>, Tunnel<'a>, u16),
    ReplyReady,
    ReplyQueued,
    DropReady,
    DropQueued,
    ForwardReady,
    ForwardQueued,
}
struct Row<'a> {
    request: Request<'a>,
    source: Source<'a>,
    id: [u8; 8],
    packet: Vec<u8>,
    output: Vec<u8>,
    plan: Vec<AddressRecord>,
    replacements: Vec<Replacement>,
    until: u64,
    phase: Phase<'a>,
    attempts: u32,
}
struct Exit<'a> {
    ad: Advertisement,
    tunnel: Option<Tunnel<'a>>,
    until: u64,
    ready: bool,
    opening: bool,
    next_id: u32,
    transmitted: u32,
    answered: u32,
    failed: u32,
    retry: u64,
    closing: bool,
}
/// One borrowed original work item; actual states/data are already retained.
/// Completion methods require its unforgeable original token.
pub enum Work<'a, 'b> {
    /// Real VPN allocation needed; original complete request remains owned.
    Allocate {
        /// Exact original job.
        job: Job<'a>,
        /// Original DNS request.
        request: Request<'a>,
        /// Original record destination.
        destination: Address,
        /// Original lease expiry.
        lease_until: u64,
        /// Original finite operation deadline.
        expires: u64,
    },
    /// Real CADET open needed for this authenticated live advertisement.
    Open {
        /// Exact channel attempt.
        tunnel: Tunnel<'a>,
        /// Signed peer identity.
        peer: [u8; 32],
        /// Signed absolute ad expiry.
        expires: u64,
    },
    /// Send exact application-frame bytes on the specified original channel.
    Send {
        /// Original request attempt.
        attempt: Attempt<'a>,
        /// Exact retained original callback, never inferred from equal deadlines.
        request: Request<'a>,
        /// Exact original tunnel.
        tunnel: Tunnel<'a>,
        /// Official complete application message.
        message: &'b [u8],
        /// Original request deadline.
        expires: u64,
    },
    /// Close a failed/expired original channel, never another peer generation.
    Close {
        /// Original tunnel to physically destroy.
        tunnel: Tunnel<'a>,
    },
    /// Resolve original callback; queueing is not completion or remote success.
    Reply {
        /// Original callback.
        request: Request<'a>,
        /// Exact original DNS source.
        source: Source<'a>,
        /// Exact opaque service request identifier.
        id: [u8; 8],
        /// Official DNS decision.
        decision: gnunet_wire::official::dns::Decision<'b>,
        /// Original deadline.
        expires: u64,
    },
}
/// Full bounded pure business owner. External tables may hold original port
/// receipts but cannot manufacture these private tokens or verified adverts.
pub struct Core<'a> {
    owner: &'a Instance,
    allocation: u64,
    next: u64,
    limits: Limits,
    families: Families,
    sources: Vec<SourceRow<'a>>,
    rows: Vec<Row<'a>>,
    exits: Vec<Exit<'a>>,
    discovery: Option<(Discovery<'a>, u64)>,
    scratch_a: Vec<u8>,
    scratch_b: Vec<u8>,
    record_scratch: Vec<AddressRecord>,
    bytes: usize,
    cursor: usize,
}
fn vector<T>(n: usize) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    Ok(v)
}
fn copy(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut v = vector(input.len())?;
    v.extend_from_slice(input);
    Ok(v)
}
impl<'a> Core<'a> {
    /// Reserve finite metadata and shared reusable parser workspace only.
    pub fn new(owner: &'a Instance, limits: Limits, families: Families) -> Result<Self, Error> {
        limits.validate()?;
        let allocation = owner.next.get().checked_add(1).ok_or(Error::Overflow)?;
        owner.next.set(allocation);
        let scratch = limits
            .packet_bytes
            .checked_add(1024)
            .ok_or(Error::Overflow)?;
        let mut scratch_a = vector(scratch)?;
        scratch_a.resize(scratch, 0);
        let mut scratch_b = vector(scratch)?;
        scratch_b.resize(scratch, 0);
        let mut record_scratch = vector(limits.records)?;
        record_scratch.resize(limits.records, AddressRecord::EMPTY);
        Ok(Self {
            owner,
            allocation,
            next: 0,
            limits,
            families,
            sources: vector(2)?,
            rows: vector(limits.requests)?,
            exits: vector(limits.exits)?,
            discovery: None,
            scratch_a,
            scratch_b,
            record_scratch,
            bytes: 0,
            cursor: 0,
        })
    }
    fn brand(&mut self) -> Result<Brand<'a>, Error> {
        self.next = self.next.checked_add(1).ok_or(Error::Overflow)?;
        Ok(Brand {
            owner: self.owner,
            allocation: self.allocation,
            serial: self.next,
        })
    }
    fn row(&self, request: Request<'a>) -> Result<usize, Error> {
        self.rows
            .iter()
            .position(|r| r.request == request)
            .ok_or(Error::Stale)
    }
    fn tunnel(&self, tunnel: Tunnel<'a>) -> Result<usize, Error> {
        self.exits
            .iter()
            .position(|e| e.tunnel == Some(tunnel))
            .ok_or(Error::Stale)
    }
    fn charge(&self, n: usize) -> Result<usize, Error> {
        self.bytes
            .checked_add(n)
            .filter(|n| *n <= self.limits.payload_bytes)
            .ok_or(Error::Capacity)
    }
    /// Bind only after the caller observes a real native DNS attachment. Each
    /// stage has one current source; other sources cannot finish its requests.
    pub fn attached(&mut self, stage: Stage) -> Result<Source<'a>, Error> {
        if self.sources.iter().any(|s| s.stage == stage) {
            return Err(Error::Conflict);
        }
        let source = Source(self.brand()?);
        self.sources.push(SourceRow { source, stage });
        Ok(source)
    }
    /// Physical source loss retires its requests without reassigning old opaque
    /// callbacks to a later reconnect. VPN cancellation remains caller-owned.
    pub fn source_stopped(&mut self, source: Source<'a>) -> Result<(), Error> {
        let index = self
            .sources
            .iter()
            .position(|s| s.source == source)
            .ok_or(Error::Stale)?;
        self.sources.remove(index);
        let mut i = 0;
        while i < self.rows.len() {
            if self.rows[i].source == source {
                self.remove(i)?;
            } else {
                i += 1
            }
        }
        Ok(())
    }
    fn remove(&mut self, index: usize) -> Result<(), Error> {
        let r = self.rows.remove(index);
        self.bytes = self
            .bytes
            .checked_sub(r.packet.capacity() + r.output.capacity())
            .ok_or(Error::Conflict)?;
        Ok(())
    }
    /// Admit a validated original DNS packet. `expires` is copied from the
    /// original native callback and may shorten, never extend, its lifetime.
    /// Standalone callers must mint finite targets once and retain an independent
    /// original native hard bound. A later logical rollback never remints them;
    /// `limits.timeout` is admission policy for that caller, not a fresh TTL here.
    pub fn admit(
        &mut self,
        source: Source<'a>,
        id: [u8; 8],
        dns: &[u8],
        expires: u64,
        now: u64,
    ) -> Result<Request<'a>, Error> {
        let stage = self
            .sources
            .iter()
            .find(|s| s.source == source)
            .map(|s| s.stage)
            .ok_or(Error::Stale)?;
        if self.rows.len() >= self.limits.requests {
            return Err(Error::Capacity);
        }
        if self.rows.iter().any(|r| r.source == source && r.id == id) {
            return Err(Error::Replay);
        }
        if expires <= now || expires == u64::MAX {
            return Err(Error::Deadline);
        }
        packet::validate(dns, &mut self.scratch_a, self.limits.dns())?;
        let mut plan = Vec::new();
        let mut replacements = Vec::new();
        let phase = if stage == Stage::Post {
            let n = packet::scan(
                dns,
                self.families,
                &mut self.record_scratch,
                &mut self.scratch_a,
                self.limits.dns(),
            )?;
            plan = vector(n)?;
            plan.extend_from_slice(&self.record_scratch[..n]);
            replacements = vector(n)?;
            if n == 0 {
                Phase::ForwardReady
            } else {
                Phase::AllocReady
            }
        } else {
            if gnunet_dns::Header::decode(dns)?.flags.query_or_response() {
                return Err(Error::Malformed);
            }
            Phase::PreReady
        };
        replacements.clear();
        let packet = copy(dns)?;
        let bytes = self.charge(packet.capacity())?;
        let request = Request(self.brand()?);
        self.rows.push(Row {
            request,
            source,
            id,
            packet,
            output: Vec::new(),
            plan,
            replacements,
            until: expires,
            phase,
            attempts: 0,
        });
        self.bytes = bytes;
        Ok(request)
    }
    /// Begin one real caller-owned DHT GET, tied to its original finite deadline.
    /// Root's production DHT adapter must use type10, replication1, options1,
    /// key=exit::discovery_key(), empty xquery. This creates no DHT client itself.
    pub fn begin_discovery(&mut self, expires: u64, now: u64) -> Result<Discovery<'a>, Error> {
        if self.discovery.is_some() {
            return Err(Error::Conflict);
        }
        if expires <= now || expires == u64::MAX {
            return Err(Error::Deadline);
        }
        let d = Discovery(self.brand()?);
        self.discovery = Some((d, expires));
        Ok(d)
    }
    /// Retire only the original DHT GET. Already authenticated still-live
    /// advertisements retain their original absolute/native lease ownership.
    pub fn discovery_stopped(&mut self, d: Discovery<'a>) -> Result<(), Error> {
        if self.discovery.map(|x| x.0) != Some(d) {
            return Err(Error::Stale);
        }
        self.discovery = None;
        Ok(())
    }
    /// Accept only real raw results from the original DHT query, verify the
    /// signature/purpose/size and expiration using existing Rust crypto.
    pub fn advertisement(
        &mut self,
        d: Discovery<'a>,
        query: &[u8; 64],
        block_type: u32,
        bytes: &[u8],
        now: u64,
    ) -> Result<(), Error> {
        let (current, until) = self.discovery.ok_or(Error::Stale)?;
        if d != current || now >= until {
            return Err(Error::Stale);
        }
        if block_type != 10 || *query != crate::exit::discovery_key() {
            return Err(Error::Authentication);
        }
        let ad = Advertisement::verify(bytes, now)?;
        if let Some(e) = self.exits.iter_mut().find(|e| e.ad.peer() == ad.peer()) {
            if ad.expires() > e.ad.expires() {
                e.ad = ad;
                e.until = ad.expires();
            }
            return Ok(());
        }
        if self.exits.len() >= self.limits.exits {
            return Err(Error::Capacity);
        }
        self.exits.push(Exit {
            ad,
            tunnel: None,
            until: ad.expires(),
            ready: false,
            opening: false,
            next_id: 0,
            transmitted: 0,
            answered: 0,
            failed: 0,
            retry: now,
            closing: false,
        });
        Ok(())
    }
    /// Withdraw one exact peer's local advertisement capability after an actual
    /// independent native lease expiry or invalid peer response. This does not
    /// forge logical time, a DHT revocation or a remote channel-close receipt.
    /// Already absent candidates are harmless; live channels become close work.
    pub fn withdraw_exit(&mut self, peer: [u8; 32]) -> Result<(), Error> {
        if let Some(exit) = self.exits.iter_mut().find(|e| e.ad.peer() == peer) {
            exit.until = 0;
            exit.ready = false;
            exit.closing = exit.tunnel.is_some();
        }
        Ok(())
    }
    /// Report real open admission, or a refused/failed original attempt. A local
    /// open/write grants no send credit; channel_credit is a separate event.
    pub fn opened(&mut self, tunnel: Tunnel<'a>) -> Result<(), Error> {
        let i = self.tunnel(tunnel)?;
        if !self.exits[i].opening {
            return Err(Error::Replay);
        }
        self.exits[i].opening = false;
        Ok(())
    }
    /// Update availability only from actual CADET channel credit on this token.
    pub fn channel_credit(
        &mut self,
        tunnel: Tunnel<'a>,
        available: u32,
        now: u64,
    ) -> Result<(), Error> {
        let i = self.tunnel(tunnel)?;
        if self.exits[i].closing || now >= self.exits[i].until {
            return Err(Error::Stale);
        }
        self.exits[i].ready = available > 0;
        Ok(())
    }
    /// Actual channel destruction/loss clears the original channel mapping and
    /// allows bounded explicit retries without resetting any request deadline.
    pub fn tunnel_stopped(&mut self, tunnel: Tunnel<'a>, now: u64) -> Result<(), Error> {
        let i = self.tunnel(tunnel)?;
        self.exits[i].tunnel = None;
        // Reset IDs only after the caller has actually retired this exact old
        // channel. A new Tunnel token/native generation may then start at zero.
        self.exits[i].next_id = 0;
        self.exits[i].transmitted = 0;
        self.exits[i].answered = 0;
        self.exits[i].failed = 0;

        self.exits[i].ready = false;
        self.exits[i].opening = false;
        self.exits[i].closing = false;
        self.exits[i].retry = now.checked_add(self.limits.retry).ok_or(Error::Overflow)?;
        for r in &mut self.rows {
            if matches!(r.phase,Phase::SendReady(_,t,_)|Phase::SendQueued(_,t,_)|Phase::Waiting(_,t,_) if t==tunnel)
            {
                self.bytes = self
                    .bytes
                    .checked_sub(r.output.capacity())
                    .ok_or(Error::Conflict)?;
                r.output = Vec::new();
                r.phase = if r.attempts >= self.limits.attempts {
                    Phase::DropReady
                } else {
                    Phase::PreReady
                };
            }
        }
        Ok(())
    }
    /// Retire an original callback locally. The caller still owes physical DNS
    /// drop/write or whole-source closure and original VPN callback cancellation.
    pub fn cancel(&mut self, request: Request<'a>) -> Result<(), Error> {
        let i = self.row(request)?;
        self.rows[i].phase = Phase::DropReady;
        Ok(())
    }
    /// Actual same-family VPN allocation completes exactly one original job.
    /// None/failed allocation yields a drop, never an invented address result.
    pub fn allocation(
        &mut self,
        job: Job<'a>,
        allocated: Option<Replacement>,
        now: u64,
    ) -> Result<(), Error> {
        let i = self
            .rows
            .iter()
            .position(|r| r.phase == Phase::AllocPending(job))
            .ok_or(Error::Stale)?;
        if now >= self.rows[i].until {
            return Err(Error::Deadline);
        }
        let Some(value) = allocated else {
            self.rows[i].phase = Phase::DropReady;
            return Ok(());
        };
        let original = self.rows[i]
            .plan
            .get(self.rows[i].replacements.len())
            .ok_or(Error::Conflict)?;
        if value.address.kind() != original.address().kind()
            || value.lease_until != self.rows[i].until
            || value.lease_until <= now
        {
            return Err(Error::Authentication);
        }
        let last = self.rows[i].replacements.len() + 1 == self.rows[i].plan.len();
        let mut output = if last {
            let n = self.rows[i].packet.len();
            self.charge(n)?;
            let mut out = vector(n)?;
            out.resize(n, 0);
            out
        } else {
            Vec::new()
        };
        self.charge(output.capacity())?;
        self.rows[i].replacements.push(value);
        if !last {
            self.rows[i].phase = Phase::AllocReady;
            return Ok(());
        }
        let row = &self.rows[i];
        match packet::rewrite(
            &row.packet,
            &row.plan,
            &row.replacements,
            now,
            packet::RewriteBuffers {
                output: &mut output,
                original: &mut self.scratch_a,
                transformed: &mut self.scratch_b,
            },
            self.limits.dns(),
        ) {
            Ok(_) => {
                self.bytes = self.charge(output.capacity())?;
                self.rows[i].output = output;
                self.rows[i].phase = Phase::ReplyReady;
            }
            Err(_) => self.rows[i].phase = Phase::DropReady,
        }
        Ok(())
    }
    /// Real local send admission retains original attempt identity and cannot be
    /// mistaken for Written or an actual DNS reply.
    pub fn send_queued(&mut self, attempt: Attempt<'a>) -> Result<(), Error> {
        let r = self
            .rows
            .iter_mut()
            .find(|r| matches!(r.phase,Phase::SendReady(a,_,_) if a==attempt))
            .ok_or(Error::Stale)?;
        let Phase::SendReady(a, t, id) = r.phase else {
            return Err(Error::Conflict);
        };
        r.phase = Phase::SendQueued(a, t, id);
        Ok(())
    }
    /// Whole local write of this exact application transmit. Remote response is
    /// still required; the original channel and request lifetime remain fixed.
    pub fn send_written(&mut self, attempt: Attempt<'a>) -> Result<(), Error> {
        let r = self
            .rows
            .iter_mut()
            .find(|r| matches!(r.phase,Phase::SendQueued(a,_,_) if a==attempt))
            .ok_or(Error::Stale)?;
        let Phase::SendQueued(a, t, id) = r.phase else {
            return Err(Error::Conflict);
        };
        r.phase = Phase::Waiting(a, t, id);
        let exit = self
            .exits
            .iter_mut()
            .find(|e| e.tunnel == Some(t))
            .ok_or(Error::Stale)?;
        exit.transmitted = exit.transmitted.saturating_add(1);
        Ok(())
    }
    /// Consume one actual reply only from its exact current channel and unique
    /// per-channel DNS ID, with the original question/opcode structurally bound.
    pub fn response(
        &mut self,
        tunnel: Tunnel<'a>,
        application: &[u8],
        now: u64,
    ) -> Result<bool, Error> {
        let dns = crate::exit::decode_response(application)?;
        let h = gnunet_dns::Header::decode(dns)?;
        let wire_id = u16::from_be_bytes(h.id);
        let Some(i) = self
            .rows
            .iter()
            .position(|r| matches!(r.phase,Phase::Waiting(_,t,id) if t==tunnel&&id==wire_id))
        else {
            return Ok(false);
        };
        if now >= self.rows[i].until {
            return Ok(false);
        }
        let e = self.tunnel(tunnel)?;
        if now >= self.exits[e].until || self.exits[e].closing {
            return Ok(false);
        }
        packet::validate(dns, &mut self.scratch_a, self.limits.dns())?;
        if !packet::same_questions(
            &self.rows[i].packet,
            dns,
            &mut self.scratch_a,
            &mut self.scratch_b,
            self.limits.dns(),
        )? {
            return Err(Error::Authentication);
        }
        let old = self.rows[i].output.capacity();
        let new = dns.len();
        self.bytes
            .checked_sub(old)
            .and_then(|v| v.checked_add(new))
            .filter(|v| *v <= self.limits.payload_bytes)
            .ok_or(Error::Capacity)?;
        self.charge(new)?;
        let mut output = copy(dns)?;
        self.charge(output.capacity())?;
        output[..2].copy_from_slice(&self.rows[i].packet[..2]);
        self.bytes = self
            .bytes
            .checked_sub(old)
            .and_then(|v| v.checked_add(output.capacity()))
            .filter(|v| *v <= self.limits.payload_bytes)
            .ok_or(Error::Capacity)?;
        self.rows[i].output = output;
        self.rows[i].phase = Phase::ReplyReady;
        self.exits[e].answered = self.exits[e].answered.saturating_add(1);
        Ok(true)
    }
    /// Mark a real original DNS reply queue admission. It cannot free the
    /// callback or reassign it; only the matching actual whole write can do so.
    pub fn reply_queued(&mut self, request: Request<'a>) -> Result<(), Error> {
        let i = self.row(request)?;
        self.rows[i].phase = match self.rows[i].phase {
            Phase::ReplyReady => Phase::ReplyQueued,
            Phase::DropReady => Phase::DropQueued,
            Phase::ForwardReady => Phase::ForwardQueued,
            _ => return Err(Error::Replay),
        };
        Ok(())
    }
    /// Matching original DNS response whole-write retires retained payloads.
    pub fn reply_written(&mut self, source: Source<'a>, request: Request<'a>) -> Result<(), Error> {
        let i = self.row(request)?;
        if self.rows[i].source != source
            || !matches!(
                self.rows[i].phase,
                Phase::ReplyQueued | Phase::DropQueued | Phase::ForwardQueued
            )
        {
            return Err(Error::Stale);
        }
        self.remove(i)
    }
    /// Existing original logical targets only. A normal clock rollback does not
    /// extend them or revive any removed state. Native hard bounds are external.
    pub fn expire(&mut self, now: u64) -> Result<(), Error> {
        for r in &mut self.rows {
            if now >= r.until
                && !matches!(
                    r.phase,
                    Phase::ReplyQueued | Phase::ForwardQueued | Phase::DropQueued
                )
            {
                if let Phase::Waiting(_, tunnel, _) = r.phase
                    && let Some(exit) = self.exits.iter_mut().find(|e| e.tunnel == Some(tunnel))
                {
                    exit.failed = exit.failed.saturating_add(1);
                }
                r.phase = Phase::DropReady;
            }
        }
        for e in &mut self.exits {
            let finished =
                (u64::from(e.answered) + u64::from(e.failed)).min(u64::from(e.transmitted));
            let poor = finished > 20 && u64::from(e.failed) * 100 > finished * 25;
            let ids_exhausted = e.next_id > u32::from(u16::MAX);
            if ids_exhausted {
                e.ready = false;
            }
            let drained=ids_exhausted&&!self.rows.iter().any(|r|matches!(r.phase,Phase::SendReady(_,t,_)|Phase::SendQueued(_,t,_)|Phase::Waiting(_,t,_) if Some(t)==e.tunnel));
            if now >= e.until || poor || drained {
                e.ready = false;
                if e.tunnel.is_some() {
                    e.closing = true;
                }
            }
        }
        self.exits.retain(|e| e.until > now || e.tunnel.is_some());
        Ok(())
    }
    /// Earliest retained absolute original target.
    pub fn next_deadline(&self) -> Option<u64> {
        self.rows
            .iter()
            .map(|r| r.until)
            .chain(self.exits.iter().map(|e| e.until))
            .chain(self.discovery.map(|(_, n)| n))
            .min()
    }
    /// Actual bounded live request count.
    pub fn pending(&self) -> usize {
        self.rows.len()
    }
    /// Select and advance real retained work. Send retries retain the complete
    /// original callback lifetime and choose a fresh unique channel-local ID.
    pub fn next_work(&mut self, now: u64) -> Result<Option<Work<'a, '_>>, Error> {
        self.expire(now)?;
        if let Some(e) = self.exits.iter().find(|e| e.closing && e.tunnel.is_some()) {
            return Ok(Some(Work::Close {
                tunnel: e.tunnel.ok_or(Error::Conflict)?,
            }));
        }
        let live = self.exits.iter().filter(|e| e.tunnel.is_some()).count();
        if live < self.limits.tunnels
            && let Some(i) = self
                .exits
                .iter()
                .position(|e| e.tunnel.is_none() && e.until > now && e.retry <= now)
        {
            let tunnel = Tunnel(self.brand()?);
            self.exits[i].tunnel = Some(tunnel);
            self.exits[i].opening = true;
            return Ok(Some(Work::Open {
                tunnel,
                peer: self.exits[i].ad.peer(),
                expires: self.exits[i].until,
            }));
        }
        if let Some(i) = self.rows.iter().position(|r| r.phase == Phase::AllocReady) {
            let job = Job(self.brand()?);
            let r = &mut self.rows[i];
            let destination = r
                .plan
                .get(r.replacements.len())
                .ok_or(Error::Conflict)?
                .address();
            r.phase = Phase::AllocPending(job);
            return Ok(Some(Work::Allocate {
                job,
                request: r.request,
                destination,
                lease_until: r.until,
                expires: r.until,
            }));
        }
        if let Some(i) = self.rows.iter().position(|r| r.phase == Phase::PreReady) {
            if self.rows[i].attempts >= self.limits.attempts {
                self.rows[i].phase = Phase::DropReady;
            } else {
                let mut chosen = None;
                let mut best = 0u64;
                for offset in 0..self.exits.len() {
                    let e = (self.cursor + offset) % self.exits.len();
                    let row = &self.exits[e];
                    if !row.ready
                        || row.closing
                        || row.opening
                        || row.until <= now
                        || row.tunnel.is_none()
                    {
                        continue;
                    }
                    if row.next_id > u32::from(u16::MAX) {
                        continue;
                    }
                    let finished = (u64::from(row.answered) + u64::from(row.failed))
                        .min(u64::from(row.transmitted));
                    if finished > 20 && u64::from(row.failed) * 100 > finished * 25 {
                        continue;
                    }
                    let weight = 1
                        + (10_000 * u64::from(row.answered))
                            .checked_div(finished)
                            .unwrap_or(0);
                    if weight > best {
                        chosen = Some(e);
                        best = weight;
                    }
                }
                if let Some(e) = chosen {
                    let tunnel = self.exits[e].tunnel.ok_or(Error::Conflict)?;
                    let id = u16::try_from(self.exits[e].next_id).map_err(|_| Error::Capacity)?;
                    let n = self.rows[i]
                        .packet
                        .len()
                        .checked_add(4)
                        .ok_or(Error::Overflow)?;
                    self.charge(n)?;
                    let mut output = vector(n)?;
                    output.resize(n, 0);
                    crate::exit::encode_query(&self.rows[i].packet, &mut output)?;
                    output[4..6].copy_from_slice(&id.to_be_bytes());
                    let attempt = Attempt(self.brand()?);
                    self.bytes = self.charge(output.capacity())?;
                    self.rows[i].output = output;
                    self.rows[i].phase = Phase::SendReady(attempt, tunnel, id);
                    self.rows[i].attempts += 1;
                    self.exits[e].next_id = u32::from(id) + 1;
                    self.exits[e].ready = false;
                    self.cursor = (e + 1) % self.exits.len();
                }
            }
        }
        let dns_limits = self.limits.dns();
        for r in &mut self.rows {
            match r.phase {
                Phase::SendReady(attempt, tunnel, _) => {
                    return Ok(Some(Work::Send {
                        attempt,
                        request: r.request,
                        tunnel,
                        message: &r.output,
                        expires: r.until,
                    }));
                }
                Phase::ReplyReady => {
                    if !r.plan.is_empty()
                        && packet::rewrite_uncached(
                            &r.packet,
                            &r.plan,
                            &r.replacements,
                            now,
                            packet::RewriteBuffers {
                                output: &mut r.output,
                                original: &mut self.scratch_a,
                                transformed: &mut self.scratch_b,
                            },
                            dns_limits,
                        )
                        .is_err()
                    {
                        r.phase = Phase::DropReady;
                        return Ok(Some(Work::Reply {
                            request: r.request,
                            source: r.source,
                            id: r.id,
                            decision: gnunet_wire::official::dns::Decision::Drop,
                            expires: r.until,
                        }));
                    }
                    return Ok(Some(Work::Reply {
                        request: r.request,
                        source: r.source,
                        id: r.id,
                        decision: gnunet_wire::official::dns::Decision::Answer(&r.output),
                        expires: r.until,
                    }));
                }
                Phase::DropReady => {
                    return Ok(Some(Work::Reply {
                        request: r.request,
                        source: r.source,
                        id: r.id,
                        decision: gnunet_wire::official::dns::Decision::Drop,
                        expires: r.until,
                    }));
                }
                Phase::ForwardReady => {
                    return Ok(Some(Work::Reply {
                        request: r.request,
                        source: r.source,
                        id: r.id,
                        decision: gnunet_wire::official::dns::Decision::Forward,
                        expires: r.until,
                    }));
                }
                _ => {}
            }
        }
        Ok(None)
    }
}
