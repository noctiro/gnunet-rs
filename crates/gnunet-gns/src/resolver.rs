use crate::records::{bytes, cstring, filled, join, rewrite, text};
use crate::{Error, Record, RecordData, RecordFlags, RecordType, ZoneKey, validate_name};
use alloc::{string::String, vec::Vec};
use core::net::IpAddr;
use gnunet_dns::{Idna, Name};
use gnunet_gnscrypto::{Block, Label};

/// Stable exclusively borrowed identity storage; not a transport or wire ID.
#[derive(Debug)]
pub struct Instance {
    identity: u8,
}
impl Instance {
    /// New non-zero-sized owner identity.
    pub const fn new() -> Self {
        Self { identity: 1 }
    }
}
impl Default for Instance {
    fn default() -> Self {
        Self::new()
    }
}
macro_rules! token {
    ($name:ident,$doc:literal) => {
        #[doc=$doc]
        #[derive(Clone, Copy, Debug)]
        pub struct $name<'a> {
            owner: &'a Instance,
            serial: u64,
        }
        impl PartialEq for $name<'_> {
            fn eq(&self, other: &Self) -> bool {
                core::ptr::eq(self.owner, other.owner) && self.serial == other.serial
            }
        }
        impl Eq for $name<'_> {}
    };
}
token!(
    QueryId,
    "Original logical lookup identity; never a wire correlation value."
);
token!(
    EffectId,
    "Original dependency attempt, tied to its resolver instance."
);
/// Where authenticated zone records may be obtained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Policy {
    /// Local authenticated cache first, remote storage on miss/invalid data.
    CacheThenRemote,
    /// Every authority, including DNS-server GNS children, stays cache-only.
    LocalOnly,
    /// Initial authority cache-only; subsequent authority lookups may be remote.
    LocalMaster,
}
impl Policy {
    /// Interpret the pinned GNS IPC enum without mistaking it for combinable
    /// bit flags. The client codec may preserve unknown bits; domain policy
    /// rejects an option value it cannot enforce.
    pub fn from_local_options(value: u16) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::CacheThenRemote),
            1 => Ok(Self::LocalOnly),
            2 => Ok(Self::LocalMaster),
            _ => Err(Error::Unsupported),
        }
    }
}
/// Finite admission, storage, recursion and externally visible dependency limits.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Simultaneously admitted queries, including untaken completions.
    pub queries: usize,
    /// Bytes of one logical GNS name or label; not a DNS protocol limit.
    pub name_bytes: usize,
    /// Applicable records accepted from one block or dependency.
    pub records: usize,
    /// Total payload bytes in one result set.
    pub record_bytes: usize,
    /// Maximum configurable suffix mappings admitted by lookup_name.
    pub mappings: usize,
    /// Maximum nested GNS nameserver frames per original query.
    pub frames: usize,
    /// Maximum GNS2DNS servers and resolved addresses per server.
    pub servers: usize,
    /// Global effect/candidate work units per query, including invalid remote
    /// blocks and children; a stream of bad signatures cannot run unbounded.
    pub steps: u32,
    /// Enable DNS/OS resolution; direct requested GNS2DNS data still works.
    pub dns: bool,
    /// Enable namecache reads and validated remote-block cache writes.
    pub cache: bool,
    /// Match GNUnet C's DNS address-following treatment of stored CNAME.
    pub follow_cname: bool,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            queries: 32,
            name_bytes: 4096,
            records: 2048,
            record_bytes: 64512,
            mappings: 64,
            frames: 16,
            servers: 32,
            steps: 256,
            dns: true,
            cache: true,
            follow_cname: true,
        }
    }
}
/// Explicit-zone lookup intent. Raw original name is copied on admission.
#[derive(Clone, Copy, Debug)]
pub struct Lookup<'a> {
    /// Initial authoritative zone.
    pub zone: ZoneKey,
    /// Relative name; empty means apex.
    pub name: &'a str,
    /// Full32-bit requested type; zero requests any type.
    pub record_type: RecordType,
    /// Cache/remote policy propagated to nested GNS dependencies.
    pub policy: Policy,
    /// Global work ceiling, further restricted by Resolver limits.
    pub recursion_limit: u16,
}
/// Semantic terminal failure; never an invented successful record set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failure {
    /// No usable records or no applicable continuation.
    NotFound,
    /// Authoritative zone is revoked, including cache hits.
    Revoked,
    /// Unknown critical record type.
    Critical(RecordType),
    /// Malformed or mutually exclusive authoritative records.
    Records,
    /// Delegation or redirection illegally stored at apex.
    Apex,
    /// DNS transition disabled by configuration.
    DnsDisabled,
    /// Recursion or aggregate work budget exhausted.
    Recursion,
    /// Original logical query explicitly canceled.
    Cancelled,
    /// Dependency, validation or resource failure.
    Fault(Error),
}
/// Original immutable dependency action. Re-reading it does not generate a new
/// attempt. Only the matching receipt method can retire this effect.
#[derive(Debug)]
pub struct Effect<'a> {
    /// Exact original attempt ID to return in the receipt.
    pub id: EffectId<'a>,
    /// Original logical owner of this work (also for nested server lookups).
    pub query: QueryId<'a>,
    /// Typed dependency request.
    pub kind: EffectKind,
}
/// Dependencies are data ports, not an implicit native networking runtime.
#[derive(Debug)]
pub enum EffectKind {
    /// Check the local revocation list for this exact authoritative zone.
    Revocation {
        /// Original zone.
        zone: ZoneKey,
    },
    /// Find a cached encrypted block; bytes are always reauthenticated here.
    Cache {
        /// Original zone.
        zone: ZoneKey,
        /// NFC label.
        label: String,
        /// Derived SHA512 storage key.
        key: [u8; 64],
    },
    /// Stream candidate encrypted remote blocks until valid data or exhausted.
    Remote {
        /// Original zone.
        zone: ZoneKey,
        /// NFC label.
        label: String,
        /// Derived SHA512 storage key.
        key: [u8; 64],
    },
    /// Optional store of a block already authenticated for this zone and label.
    CachePut {
        /// Derived lookup key.
        key: [u8; 64],
        /// Exact original validated block.
        block: Vec<u8>,
    },
    /// Resolve a DNS nameserver hostname through ordinary DNS, with no GNS
    /// fallback. Receipt is a bounded set of IPv4/IPv6 addresses.
    Nameserver {
        /// IDNA ASCII hostname.
        name: String,
        /// Work available to the recursive dependency.
        remaining_steps: u32,
    },
    /// Perform recursive DNS against this server (port53), using supplied
    /// security records. MUST follow DNS recursion, never return to GNS.
    Dns {
        /// IDNA ASCII question.
        name: String,
        /// Original IDNA ASCII DNS namespace from the authenticated GNS2DNS
        /// record, before unresolved labels were prepended. It binds referral
        /// and security-anchor scope; the full question cannot reconstruct it.
        authority: String,
        /// Original desired record type.
        record_type: RecordType,
        /// One server; all candidates are tried on failure.
        server: IpAddr,
        /// DNSSEC/trust records from the authenticated GNS set.
        security: Vec<Record>,
        /// Shared remaining work allowance.
        remaining_steps: u32,
    },
    /// Default-system resolution after absolute REDIRECT/CNAME. If it calls
    /// GNS again, it MUST propagate this finite allowance and account spent work.
    System {
        /// Effective target: REDIRECT prepends remaining labels; CNAME replaces them.
        name: String,
        /// Original desired type.
        record_type: RecordType,
        /// Shared remaining work allowance.
        remaining_steps: u32,
    },
    /// Resolve symbolic protocol/service using configured GANA/OS registry;
    /// None means use the literal prefix as SBOX, never guess a numeric value.
    Service {
        /// Original service component without underscore.
        service: String,
        /// Original protocol component without underscore.
        protocol: String,
    },
}
/// Official near-expiry cache refresh threshold, in absolute-time microseconds.
pub const CACHE_REFRESH_THRESHOLD: u64 = 300_000_000;
/// An independently owned optional refresh of one authenticated cache binding.
/// It contains no caller QueryId/EffectId or authority to complete that query.
pub struct CacheRefresh {
    zone: ZoneKey,
    label: String,
    key: [u8; 64],
    expiration: u64,
    created_at: u64,
    remaining: u32,
}
impl core::fmt::Debug for CacheRefresh {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CacheRefresh([QUERY REDACTED])")
    }
}
impl CacheRefresh {
    /// Original public DHT query key, for explicit deduplication and dispatch.
    pub const fn key(&self) -> &[u8; 64] {
        &self.key
    }
    /// Expiration of the original authenticated cache entry.
    pub const fn expiration(&self) -> u64 {
        self.expiration
    }
    /// Canonical receipt time of this new optional intent. A delayed/dropped
    /// waiter cannot obtain another complete refresh budget when it resumes.
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }
    /// Remaining independent candidate-validation work; no foreground recursion
    /// allowance is extended or consumed by this owner.
    pub const fn remaining(&self) -> u32 {
        self.remaining
    }
    /// Derive the real standard remote effect without a foreground identity.
    pub fn effect(&self) -> Result<EffectKind, Error> {
        Ok(EffectKind::Remote {
            zone: self.zone,
            label: text(&self.label)?,
            key: self.key,
        })
    }
    /// Accept only a strictly fresher, currently valid block for the exact
    /// original zone/normalized label. Signature, decryption and full record
    /// framing are checked before a caller may submit its original bytes to cache.
    /// None is not an improvement; Some carries the authenticated expiration
    /// for a cheap recheck immediately before actual cache admission.
    pub fn candidate(
        &mut self,
        input: &[u8],
        now: u64,
        limits: Limits,
    ) -> Result<Option<u64>, Error> {
        self.remaining = self.remaining.checked_sub(1).ok_or(Error::Capacity)?;
        if input.len() > 64512 + 128 {
            return Err(Error::TooLarge);
        }
        if limits.name_bytes == 0
            || limits.name_bytes > 64512
            || self.label.len() > limits.name_bytes
            || limits.record_bytes > 64512
            || limits.records == 0
            || limits.records > gnunet_gnscrypto::MAX_RECORDS
        {
            return Err(Error::InvalidInput);
        }
        let raw = Block::decode(input)?;
        let expiration = raw.expiration()?;
        if expiration <= self.expiration || expiration <= now {
            return Ok(None);
        }
        let mut chars = filled(
            limits.name_bytes.checked_mul(4).ok_or(Error::Overflow)?,
            '\0',
        )?;
        let mut name = filled(limits.name_bytes, 0_u8)?;
        let label = Label::normalize(&self.label, &mut chars, &mut name)?;
        let verified = raw.verify_for(self.zone, label)?;
        if verified.block().query()? != self.key {
            return Err(Error::Authentication);
        }
        let mut plain = filled(limits.record_bytes, 0_u8)?;
        let opened = verified.open_at(now, &mut plain)?;
        let mut count = 0_usize;
        let mut bytes = 0_usize;
        for record in opened.iter() {
            let record = record?;
            count = count.checked_add(1).ok_or(Error::Overflow)?;
            bytes = bytes
                .checked_add(record.data.len())
                .ok_or(Error::Overflow)?;
            if count > limits.records || bytes > limits.record_bytes {
                return Err(Error::Capacity);
            }
        }
        Ok(Some(expiration))
    }
}
struct Frame {
    zone: ZoneKey,
    label: String,
    remaining: String,
    desired: RecordType,
    local: bool,
    bridge: Option<Bridge>,
    pending: Vec<Record>,
}
struct Bridge {
    name: String,
    authority: String,
    targets: Vec<String>,
    next: usize,
    addresses: Vec<IpAddr>,
    address: usize,
    security: Vec<Record>,
}
struct Entry<'a> {
    id: QueryId<'a>,
    policy: Policy,
    remaining: u32,
    authorities: u32,
    frames: Vec<Frame>,
    effect: Option<Effect<'a>>,
    result: Option<Result<Vec<Record>, Failure>>,
}
/// Bounded multi-query pure resolver. No wall clock, socket, C ABI, global task
/// queue or user callback is hidden inside this owner. Trusted UTC is explicit
/// on data receipts; transport loss/deadline must produce `failed` receipts.
///
/// The original instance cannot be reused while an old query token survives:
///
/// ```compile_fail,E0499
/// use gnunet_gns::{Instance,Resolver,Limits,Lookup,Policy,RecordType,ZoneKey};
/// use gnunet_gnsrecord::ZoneKeyType;
/// let mut instance=Instance::new();
/// let mut first=Resolver::new(&mut instance,Limits::default()).unwrap();
/// let old=first.lookup(Lookup { zone:ZoneKey::new(ZoneKeyType::Edkey,[7;32]),name:"host",record_type:RecordType::A,policy:Policy::LocalOnly,recursion_limit:1 }).unwrap();
/// drop(first);
/// let second=Resolver::new(&mut instance,Limits::default()).unwrap();
/// let _ = second.effect(old);
/// ```
///
/// Effect receipts cannot outlive the storage that brands their owner:
///
/// ```compile_fail,E0597
/// use gnunet_gns::{Instance,Resolver,Limits,Lookup,Policy,RecordType,ZoneKey};
/// use gnunet_gnsrecord::ZoneKeyType;
/// let receipt;
/// { let mut instance=Instance::new();
/// let mut resolver=Resolver::new(&mut instance,Limits::default()).unwrap();
/// let query=resolver.lookup(Lookup {zone:ZoneKey::new(ZoneKeyType::Edkey,[7;32]),name:"host",record_type:RecordType::A,policy:Policy::LocalOnly,recursion_limit:1}).unwrap();
/// receipt=resolver.effect(query).unwrap().unwrap().id; }
/// let _ = receipt;
/// ```
pub struct Resolver<'a> {
    owner: &'a Instance,
    limits: Limits,
    queries: Vec<Entry<'a>>,
    serial: u64,
    attempt: u64,
    closed: bool,
    refresh_enabled: bool,
    refresh: Option<CacheRefresh>,
}

impl<'a> Resolver<'a> {
    /// Reserve the complete query table; all counters fail closed on exhaustion.
    pub fn new(owner: &'a mut Instance, limits: Limits) -> Result<Self, Error> {
        if owner.identity != 1
            || limits.queries == 0
            || limits.name_bytes == 0
            || limits.name_bytes > 64512
            || limits.records == 0
            || limits.records > gnunet_gnscrypto::MAX_RECORDS
            || limits.record_bytes > 64512
            || limits.frames == 0
            || limits.servers == 0
            || limits.steps == 0
        {
            return Err(Error::InvalidInput);
        }
        let mut queries = Vec::new();
        queries
            .try_reserve_exact(limits.queries)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            owner,
            limits,
            queries,
            serial: 0,
            attempt: 0,
            closed: false,
            refresh_enabled: false,
            refresh: None,
        })
    }
    /// Enable optional independently owned refresh hints. Disabled by default
    /// for a pure caller without an explicit background owner. Disabling drops
    /// only an unadmitted hint, never an original native operation.
    pub fn enable_cache_refresh(&mut self, enabled: bool) {
        self.refresh_enabled = enabled;
        if !enabled {
            self.refresh = None;
        }
    }
    /// Take the sole optional pending hint. Capacity/allocation refusal while
    /// creating it never changes an already-authenticated foreground answer.
    pub fn take_cache_refresh(&mut self) -> Option<CacheRefresh> {
        self.refresh.take()
    }
    fn refresh_hint(&self, index: usize, expiration: u64, now: u64) -> Option<CacheRefresh> {
        if !self.refresh_enabled
            || self.refresh.is_some()
            || expiration <= now
            || expiration - now >= CACHE_REFRESH_THRESHOLD
        {
            return None;
        }
        let entry = &self.queries[index];
        let frame = entry.frames.last()?;
        if !Self::remote_allowed(entry, frame) {
            return None;
        }
        let EffectKind::Cache { zone, label, key } = &entry.effect.as_ref()?.kind else {
            return None;
        };
        Some(CacheRefresh {
            zone: *zone,
            label: text(label).ok()?,
            key: *key,
            expiration,
            created_at: now,
            remaining: self.limits.steps,
        })
    }
    /// Admit original intent and emit its first zone revocation check.
    pub fn lookup(&mut self, request: Lookup<'_>) -> Result<QueryId<'a>, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if self.queries.len() == self.limits.queries {
            return Err(Error::WouldBlock);
        }
        validate_name(request.name)?;
        if request.name.len() > self.limits.name_bytes {
            return Err(Error::TooLarge);
        }
        let serial = self.serial.checked_add(1).ok_or(Error::Overflow)?;
        let id = QueryId {
            owner: self.owner,
            serial,
        };
        let mut entry = Entry {
            id,
            policy: request.policy,
            remaining: self.limits.steps,
            authorities: u32::from(request.recursion_limit) + 1,
            frames: Vec::new(),
            effect: None,
            result: None,
        };
        entry
            .frames
            .try_reserve_exact(self.limits.frames)
            .map_err(|_| Error::Capacity)?;
        let frame = self.frame(request.zone, request.name, request.record_type, true)?;
        entry.frames.push(frame);
        self.start(&mut entry)?;
        self.serial = serial;
        self.queries.push(entry);
        Ok(id)
    }
    /// Normalize a configured GNS name and suffix mappings to NFC, select its
    /// authoritative Start Zone, then admit one ordinary explicit-zone lookup.
    /// Failure to select GNS is an error, never permission to leak the name to DNS.
    pub fn lookup_name(
        &mut self,
        name: &str,
        mappings: &[crate::Mapping<'_>],
        record_type: RecordType,
        policy: Policy,
        recursion_limit: u16,
    ) -> Result<QueryId<'a>, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if self.queries.len() == self.limits.queries {
            return Err(Error::WouldBlock);
        }
        if mappings.len() > self.limits.mappings {
            return Err(Error::Capacity);
        }
        let normalize = |input: &str| -> Result<String, Error> {
            if input.len() > self.limits.name_bytes {
                return Err(Error::TooLarge);
            }
            let mut scalars = filled(self.limits.name_bytes * 4, '\0')?;
            let mut out = filled(self.limits.name_bytes, 0_u8)?;
            text(Label::normalize(input, &mut scalars, &mut out)?.as_str())
        };
        let name = normalize(name)?;
        let mut suffixes = Vec::new();
        suffixes
            .try_reserve_exact(mappings.len())
            .map_err(|_| Error::Capacity)?;
        for mapping in mappings {
            suffixes.push(normalize(mapping.suffix)?);
        }
        let mut normalized = Vec::new();
        normalized
            .try_reserve_exact(mappings.len())
            .map_err(|_| Error::Capacity)?;
        for (mapping, suffix) in mappings.iter().zip(&suffixes) {
            normalized.push(crate::Mapping {
                suffix,
                zone: mapping.zone,
            });
        }
        let selected = crate::select_start_zone(&name, &normalized)?;
        self.lookup(Lookup {
            zone: selected.zone,
            name: selected.name,
            record_type,
            policy,
            recursion_limit,
        })
    }
    /// Borrow the current original dependency intent without leasing new work.
    pub fn effect(&self, query: QueryId<'_>) -> Result<Option<&Effect<'a>>, Error> {
        Ok(self.queries[self.index(query)?].effect.as_ref())
    }
    /// Take a completed owned result and retire its logical query exactly once.
    pub fn take_result(
        &mut self,
        query: QueryId<'_>,
    ) -> Result<Option<Result<Vec<Record>, Failure>>, Error> {
        let i = self.index(query)?;
        if self.queries[i].result.is_none() {
            return Ok(None);
        }
        Ok(self.queries.swap_remove(i).result)
    }
    /// Cancel all current/nested effects. Later receipts are stale immediately.
    pub fn cancel(&mut self, query: QueryId<'_>) -> Result<(), Error> {
        let i = self.index(query)?;
        let e = &mut self.queries[i];
        if e.result.is_some() {
            return Err(Error::Stale);
        }
        e.effect = None;
        e.frames.clear();
        e.result = Some(Err(Failure::Cancelled));
        Ok(())
    }
    /// Permanently close, suppressing all effects and producing canceled results.
    pub fn close(&mut self) {
        self.closed = true;
        self.enable_cache_refresh(false);
        for e in &mut self.queries {
            if e.result.is_none() {
                e.effect = None;
                e.frames.clear();
                e.result = Some(Err(Failure::Cancelled));
            }
        }
    }
    fn index(&self, q: QueryId<'_>) -> Result<usize, Error> {
        if !core::ptr::eq(q.owner, self.owner) {
            return Err(Error::Stale);
        }
        self.queries
            .iter()
            .position(|e| e.id == q)
            .ok_or(Error::Stale)
    }
    fn effect_index(
        &self,
        id: EffectId<'_>,
        expected: fn(&EffectKind) -> bool,
    ) -> Result<usize, Error> {
        if !core::ptr::eq(id.owner, self.owner) {
            return Err(Error::Stale);
        }
        let i = self
            .queries
            .iter()
            .position(|e| e.effect.as_ref().is_some_and(|x| x.id == id))
            .ok_or(Error::Stale)?;
        if !expected(&self.queries[i].effect.as_ref().ok_or(Error::Stale)?.kind) {
            return Err(Error::InvalidInput);
        }
        Ok(i)
    }
    fn run(
        &mut self,
        i: usize,
        f: impl FnOnce(&mut Self, &mut Entry<'a>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut e = self.queries.swap_remove(i);
        let result = f(self, &mut e);
        if let Err(error) = result {
            e.effect = None;
            e.frames.clear();
            e.result = Some(Err(Failure::Fault(error)));
        }
        self.queries.push(e);
        result
    }
    fn issue(&mut self, e: &mut Entry<'a>, kind: EffectKind) -> Result<(), Error> {
        if e.remaining == 0 {
            e.effect = None;
            e.frames.clear();
            e.result = Some(Err(Failure::Recursion));
            return Ok(());
        }
        let serial = self.attempt.checked_add(1).ok_or(Error::Overflow)?;
        self.attempt = serial;
        e.remaining -= 1;
        e.effect = Some(Effect {
            id: EffectId {
                owner: self.owner,
                serial,
            },
            query: e.id,
            kind,
        });
        Ok(())
    }
    fn frame(
        &self,
        zone: ZoneKey,
        name: &str,
        desired: RecordType,
        local: bool,
    ) -> Result<Frame, Error> {
        validate_name(name)?;
        if name.len() > self.limits.name_bytes {
            return Err(Error::TooLarge);
        }
        let (remaining, label) = match name.rsplit_once('.') {
            Some((_, last)) if last.starts_with('_') => (name, "@"),
            Some((rest, last)) => (rest, last),
            None if name.starts_with('_') => (name, "@"),
            None => ("", if name.is_empty() { "@" } else { name }),
        };
        let mut scalars = Vec::new();
        scalars
            .try_reserve_exact(
                self.limits
                    .name_bytes
                    .checked_mul(4)
                    .ok_or(Error::Overflow)?,
            )
            .map_err(|_| Error::Capacity)?;
        scalars.resize(self.limits.name_bytes * 4, '\0');
        let mut out = filled(self.limits.name_bytes, 0_u8)?;
        let normalized = Label::normalize(label, &mut scalars, &mut out)?;
        Ok(Frame {
            zone,
            label: text(normalized.as_str())?,
            remaining: text(remaining)?,
            desired,
            local,
            bridge: None,
            pending: Vec::new(),
        })
    }
    fn start(&mut self, e: &mut Entry<'a>) -> Result<(), Error> {
        if e.authorities == 0 {
            e.effect = None;
            e.frames.clear();
            e.result = Some(Err(Failure::Recursion));
            return Ok(());
        }
        e.authorities -= 1;
        let zone = e.frames.last().ok_or(Error::NotReady)?.zone;
        self.issue(e, EffectKind::Revocation { zone })
    }
    fn label<'b>(
        &self,
        f: &Frame,
        work: &mut [char],
        out: &'b mut [u8],
    ) -> Result<Label<'b>, Error> {
        Label::normalize(&f.label, work, out)
    }
    fn query_key(&self, f: &Frame) -> Result<[u8; 64], Error> {
        let mut chars = filled(self.limits.name_bytes * 4, '\0')?;
        let mut out = filled(self.limits.name_bytes, 0_u8)?;
        gnunet_gnscrypto::query(f.zone, self.label(f, &mut chars, &mut out)?)
    }
    fn remote_allowed(e: &Entry<'_>, f: &Frame) -> bool {
        match e.policy {
            Policy::CacheThenRemote => true,
            Policy::LocalOnly => false,
            Policy::LocalMaster => !f.local,
        }
    }
    fn storage(&mut self, e: &mut Entry<'a>, cache: bool) -> Result<(), Error> {
        let f = e.frames.last().ok_or(Error::NotReady)?;
        if !cache && !Self::remote_allowed(e, f) {
            return self.complete(e, Err(Failure::NotFound));
        }
        let zone = f.zone;
        let label = text(&f.label)?;
        let key = self.query_key(f)?;
        self.issue(
            e,
            if cache {
                EffectKind::Cache { zone, label, key }
            } else {
                EffectKind::Remote { zone, label, key }
            },
        )
    }
    /// Complete original revocation check. Errors must use `failed`, not `true`.
    pub fn revoked(&mut self, id: EffectId<'_>, revoked: bool) -> Result<(), Error> {
        let i = self.effect_index(id, |k| matches!(k, EffectKind::Revocation { .. }))?;
        self.run(i, |s, e| {
            e.effect = None;
            if revoked {
                s.complete(e, Err(Failure::Revoked))
            } else {
                s.storage(e, s.limits.cache)
            }
        })
    }
    /// Cached candidate. Invalid cache bytes become a miss, respecting policy;
    /// plaintext is never accepted here as a substitute for an encrypted block.
    pub fn cached(
        &mut self,
        id: EffectId<'_>,
        block: Option<&[u8]>,
        now: u64,
    ) -> Result<(), Error> {
        let i = self.effect_index(id, |k| matches!(k, EffectKind::Cache { .. }))?;
        let records = match block.map(|b| self.open_with_expiration(&self.queries[i], b, now)) {
            Some(Ok(records)) => Some(records),
            Some(Err(Error::Capacity | Error::TooLarge | Error::Overflow)) => {
                return Err(Error::Capacity);
            }
            _ => None,
        };
        let refresh = records
            .as_ref()
            .and_then(|(_, expiration)| self.refresh_hint(i, *expiration, now));
        self.run(i, |s, e| {
            e.effect = None;
            match records {
                Some((records, _)) => s.process(e, records),
                None => s.storage(e, false),
            }
        })?;
        if let Some(refresh) = refresh {
            self.refresh = Some(refresh);
        }
        Ok(())
    }
    /// Candidate from the current original remote GET. Invalid candidates are
    /// ignored without consuming the effect; `failed` exhausts that GET.
    pub fn remote_block(&mut self, id: EffectId<'_>, block: &[u8], now: u64) -> Result<(), Error> {
        let i = self.effect_index(id, |k| matches!(k, EffectKind::Remote { .. }))?;
        if self.queries[i].remaining == 0 {
            let entry = &mut self.queries[i];
            entry.effect = None;
            entry.frames.clear();
            entry.result = Some(Err(Failure::Recursion));
            return Err(Error::Capacity);
        }
        self.queries[i].remaining -= 1;
        let records = match self.open(&self.queries[i], block, now) {
            Ok(records) => records,
            Err(error) => {
                if self.queries[i].remaining == 0 {
                    let entry = &mut self.queries[i];
                    entry.effect = None;
                    entry.frames.clear();
                    entry.result = Some(Err(Failure::Recursion));
                }
                return Err(error);
            }
        };
        let saved = if self.limits.cache {
            Some(bytes(block)?)
        } else {
            None
        };
        self.run(i, |s, e| {
            e.effect = None;
            if let Some(block) = saved.filter(|_| e.remaining > 0) {
                let key = s.query_key(e.frames.last().ok_or(Error::NotReady)?)?;
                drop(records);
                s.issue(e, EffectKind::CachePut { key, block })
            } else {
                s.process(e, records)
            }
        })
    }
    fn open(&self, e: &Entry<'_>, input: &[u8], now: u64) -> Result<Vec<Record>, Error> {
        self.open_with_expiration(e, input, now)
            .map(|(records, _)| records)
    }
    fn open_with_expiration(
        &self,
        e: &Entry<'_>,
        input: &[u8],
        now: u64,
    ) -> Result<(Vec<Record>, u64), Error> {
        if input.len() > 64512 + 128 {
            return Err(Error::TooLarge);
        }
        let f = e.frames.last().ok_or(Error::NotReady)?;
        let mut scalars = filled(self.limits.name_bytes * 4, '\0')?;
        let mut name = filled(self.limits.name_bytes, 0_u8)?;
        let label = self.label(f, &mut scalars, &mut name)?;
        let block = Block::decode(input)?.verify_for(f.zone, label)?;
        let mut plain = filled(self.limits.record_bytes, 0_u8)?;
        let opened = block.open_at(now, &mut plain)?;
        let mut result = Vec::new();
        result
            .try_reserve_exact(self.limits.records)
            .map_err(|_| Error::Capacity)?;
        let mut total = 0_usize;
        for rd in opened.iter() {
            let rd = rd?;
            if result.len() == self.limits.records {
                return Err(Error::Capacity);
            }
            total = total.checked_add(rd.data.len()).ok_or(Error::Overflow)?;
            if total > self.limits.record_bytes {
                return Err(Error::Capacity);
            }
            result.push(Record::copy(rd, crate::Origin::Gns(f.zone))?);
        }
        let expiration = block.block().expiration()?;
        Ok((result, expiration))
    }
    /// Finish optional validated cache insertion; a store failure is nonfatal.
    pub fn cache_stored(&mut self, id: EffectId<'_>, now: u64) -> Result<(), Error> {
        let i = self.effect_index(id, |k| matches!(k, EffectKind::CachePut { .. }))?;
        let block = match &self.queries[i].effect.as_ref().ok_or(Error::Stale)?.kind {
            EffectKind::CachePut { block, .. } => block,
            _ => return Err(Error::InvalidInput),
        };
        // Re-open the original authenticated block at commit time. In
        // particular, shadow activation cannot use an earlier cache-store time.
        let records = self.open(&self.queries[i], block, now);
        self.run(i, |s, e| {
            e.effect = None;
            e.frames.last_mut().ok_or(Error::NotReady)?.pending.clear();
            match records {
                Ok(records) => s.process(e, records),
                Err(Error::Timeout) => s.complete(e, Err(Failure::NotFound)),
                Err(error) => Err(error),
            }
        })
    }
    /// Symbolic protocol/service receipt for BOX selection. None retains the
    /// literal SBOX prefix; zero-valued protocol/service is not a BOX match.
    pub fn service(&mut self, id: EffectId<'_>, selector: Option<(u16, u16)>) -> Result<(), Error> {
        let i = self.effect_index(id, |k| matches!(k, EffectKind::Service { .. }))?;
        self.run(i, |s, e| {
            e.effect = None;
            let records = core::mem::take(&mut e.frames.last_mut().ok_or(Error::NotReady)?.pending);
            s.boxes(e, records, selector)
        })
    }
    /// DNS-only nameserver address receipt. Every configured server is tried
    /// serially until an actual successful recursive DNS result is received.
    pub fn addresses(
        &mut self,
        id: EffectId<'_>,
        addresses: &[IpAddr],
        spent: u32,
    ) -> Result<(), Error> {
        let i = self.effect_index(id, |k| matches!(k, EffectKind::Nameserver { .. }))?;
        if addresses.len() > self.limits.servers {
            return Err(Error::Capacity);
        }
        self.run(i, |s, e| {
            s.charge(e, spent)?;
            e.effect = None;
            let b = e
                .frames
                .last_mut()
                .and_then(|f| f.bridge.as_mut())
                .ok_or(Error::NotReady)?;
            b.addresses.clear();
            b.addresses
                .try_reserve_exact(addresses.len())
                .map_err(|_| Error::Capacity)?;
            b.addresses.extend_from_slice(addresses);
            b.address = 0;
            s.bridge(e)
        })
    }
    fn charge(&self, e: &mut Entry<'_>, spent: u32) -> Result<(), Error> {
        e.remaining = e.remaining.checked_sub(spent).ok_or(Error::TooLarge)?;
        Ok(())
    }
    /// Actual DNS/system result receipt. DNS results may contain only DNS type
    /// numbers and cannot trigger GNS delegation; supplied spent work is charged
    /// to the same original query budget. Empty means try the next DNS server.
    pub fn resolved(
        &mut self,
        id: EffectId<'_>,
        records: &[RecordData<'_>],
        spent: u32,
        now: u64,
    ) -> Result<(), Error> {
        let i = self.effect_index(id, |k| {
            matches!(k, EffectKind::Dns { .. } | EffectKind::System { .. })
        })?;
        let origin = match &self.queries[i].effect.as_ref().ok_or(Error::Stale)?.kind {
            EffectKind::Dns { server, .. } => crate::Origin::Dns(*server),
            _ => crate::Origin::System,
        };
        let dns = matches!(
            self.queries[i].effect.as_ref().ok_or(Error::Stale)?.kind,
            EffectKind::Dns { .. }
        );
        if records.len() > self.limits.records {
            return Err(Error::Capacity);
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(records.len() + 1)
            .map_err(|_| Error::Capacity)?;
        let mut total = 0_usize;
        for rd in records {
            if dns && rd.record_type.value() > 65535 {
                return Err(Error::Malformed);
            }
            rd.validate_fixed_size()?;
            total = total.checked_add(rd.data.len()).ok_or(Error::Overflow)?;
            if total > self.limits.record_bytes {
                return Err(Error::Capacity);
            }
            if !rd.has_relative_expiration() && rd.expiration_time < now {
                continue;
            }
            owned.push(Record::copy(*rd, origin)?);
        }
        self.run(i, |s, e| {
            s.charge(e, spent)?;
            e.effect = None;
            if owned.is_empty() {
                if dns {
                    return s.bridge(e);
                }
                return s.complete(e, Err(Failure::NotFound));
            }
            if dns {
                let b = e
                    .frames
                    .last()
                    .and_then(|f| f.bridge.as_ref())
                    .ok_or(Error::NotReady)?;
                let leho = Record {
                    origin,
                    expiration_time: 3_600_000_000,
                    record_type: RecordType::LEHO,
                    flags: RecordFlags::SUPPLEMENTAL.union(RecordFlags::RELATIVE_EXPIRATION),
                    data: bytes(b.name.as_bytes())?,
                };
                if owned.len() == s.limits.records
                    || total.checked_add(leho.data.len()).ok_or(Error::Overflow)?
                        > s.limits.record_bytes
                {
                    return Err(Error::Capacity);
                }
                owned.push(leho);
            }
            s.complete(e, Ok(owned))
        })
    }
    /// Exhaust/fail an original effect. Cache failures fall back by policy;
    /// DNS/server failures try remaining candidates; other dependency failures
    /// are explicit terminal failures. CachePut failure still releases records.
    pub fn failed(&mut self, id: EffectId<'_>, error: Error, now: u64) -> Result<(), Error> {
        self.failed_counted(id, error, 0, now)
    }
    /// Fail the original effect while charging actual recursive work already
    /// performed by its dependency. Failed DNS/TCP/referral attempts do not
    /// restore the original query's budget before trying another candidate.
    pub fn failed_counted(
        &mut self,
        id: EffectId<'_>,
        error: Error,
        spent: u32,
        now: u64,
    ) -> Result<(), Error> {
        let i = self.effect_index(id, |_| true)?;
        self.run(i, |s, e| {
            s.charge(e, spent)?;
            let kind = e.effect.take().ok_or(Error::Stale)?.kind;
            match kind {
                EffectKind::Cache { .. } => s.storage(e, false),
                EffectKind::CachePut { block, .. } => {
                    e.frames.last_mut().ok_or(Error::NotReady)?.pending.clear();
                    match s.open(e, &block, now) {
                        Ok(records) => s.process(e, records),
                        Err(Error::Timeout) => s.complete(e, Err(Failure::NotFound)),
                        Err(error) => Err(error),
                    }
                }
                EffectKind::Dns { .. } | EffectKind::Nameserver { .. } => s.bridge(e),
                _ => s.complete(
                    e,
                    Err(if error == Error::NotFound {
                        Failure::NotFound
                    } else {
                        Failure::Fault(error)
                    }),
                ),
            }
        })
    }
    fn complete(
        &mut self,
        e: &mut Entry<'a>,
        outcome: Result<Vec<Record>, Failure>,
    ) -> Result<(), Error> {
        e.effect = None;
        if e.frames.len() == 1 {
            e.frames.clear();
            e.result = Some(outcome);
            return Ok(());
        }
        let _frame = e.frames.pop().ok_or(Error::NotReady)?;
        let b = e
            .frames
            .last_mut()
            .and_then(|f| f.bridge.as_mut())
            .ok_or(Error::NotReady)?;
        b.addresses.clear();
        b.address = 0;
        if let Ok(records) = outcome {
            for r in records {
                let ip = match r.record_type.value() {
                    1 => Some(IpAddr::from(
                        <[u8; 4]>::try_from(r.data.as_slice()).map_err(|_| Error::Malformed)?,
                    )),
                    28 => Some(IpAddr::from(
                        <[u8; 16]>::try_from(r.data.as_slice()).map_err(|_| Error::Malformed)?,
                    )),
                    _ => None,
                };
                if let Some(ip) = ip {
                    if b.addresses.len() == self.limits.servers {
                        return Err(Error::Capacity);
                    }
                    b.addresses.try_reserve(1).map_err(|_| Error::Capacity)?;
                    b.addresses.push(ip);
                }
            }
        }
        self.bridge(e)
    }
    fn transition(&mut self, e: &mut Entry<'a>, zone: ZoneKey, name: &str) -> Result<(), Error> {
        let desired = e.frames.last().ok_or(Error::NotReady)?.desired;
        let frame = self.frame(zone, name, desired, false)?;
        let current = e.frames.last_mut().ok_or(Error::NotReady)?;
        *current = frame;
        self.start(e)
    }
    fn process(&mut self, e: &mut Entry<'a>, records: Vec<Record>) -> Result<(), Error> {
        if records.is_empty() {
            return self.complete(e, Err(Failure::NotFound));
        }
        for r in &records {
            r.as_data().validate_fixed_size()?;
            if r.flags.contains(RecordFlags::CRITICAL) && !supported(r.record_type) {
                return self.complete(e, Err(Failure::Critical(r.record_type)));
            }
        }
        let f = e.frames.last().ok_or(Error::NotReady)?;
        let mut primary = Vec::new();
        primary
            .try_reserve_exact(records.len())
            .map_err(|_| Error::Capacity)?;
        primary.extend(
            records
                .iter()
                .filter(|r| !r.flags.contains(RecordFlags::SUPPLEMENTAL)),
        );
        let desired = f.desired;
        let empty = f.remaining.is_empty();
        let apex = f.label == "@";
        let zone = f.zone;
        let delegations = primary
            .iter()
            .filter(|r| r.record_type.is_zone_delegation())
            .count();
        if delegations > 0 {
            if apex {
                return self.complete(e, Err(Failure::Apex));
            }
            if primary.len() != 1 {
                return self.complete(e, Err(Failure::Records));
            }
            let r = primary[0];
            let target = ZoneKey::from_record(&r.as_data())?;
            if empty && desired == r.record_type {
                return self.finish_records(e, records);
            }
            let name = text(&f.remaining)?;
            return self.transition(e, target, &name);
        }
        if let Some(r) = primary
            .iter()
            .find(|r| r.record_type == RecordType::REDIRECT)
        {
            if apex {
                return self.complete(e, Err(Failure::Apex));
            }
            if primary.len() != 1 {
                return self.complete(e, Err(Failure::Records));
            }
            if empty && desired == RecordType::REDIRECT {
                return self.finish_records(e, records);
            }
            let target = cstring(&r.data)?;
            let combined = join(&f.remaining, target, self.limits.name_bytes)?;
            if let Some(relative) = combined.strip_suffix(".+") {
                let relative = text(relative)?;
                return self.transition(e, zone, &relative);
            }
            if combined == "+" {
                return self.transition(e, zone, "");
            }
            let (rest, last) = combined.rsplit_once('.').unwrap_or(("", &combined));
            if let Ok(target) = ZoneKey::from_ztld(last) {
                let rest = text(rest)?;
                return self.transition(e, target, &rest);
            }
            if !self.limits.dns {
                return self.complete(e, Err(Failure::DnsDisabled));
            }
            let name = dns_ascii(&combined)?;
            return self.issue(
                e,
                EffectKind::System {
                    name,
                    record_type: desired,
                    remaining_steps: e.remaining,
                },
            );
        }
        let gns2dns = primary
            .iter()
            .filter(|r| r.record_type == RecordType::GNS2DNS)
            .count();
        if gns2dns > 0 {
            if empty && desired == RecordType::GNS2DNS {
                return self.finish_records(e, records);
            }
            if apex {
                return self.complete(e, Err(Failure::Apex));
            }
            if !self.limits.dns {
                return self.complete(e, Err(Failure::DnsDisabled));
            }
            return self.start_bridge(e, records);
        }
        if self.limits.follow_cname
            && primary.len() == 1
            && primary[0].record_type == RecordType::CNAME
            && desired != RecordType::CNAME
        {
            if !self.limits.dns {
                return self.complete(e, Err(Failure::DnsDisabled));
            }
            let name = Name::from_wire(&primary[0].data)?;
            let mut dotted = [0; 255];
            let n = name.write_dotted(&mut dotted)?;
            let name = core::str::from_utf8(&dotted[..n]).map_err(|_| Error::Malformed)?;
            // Pinned C CNAME convenience replaces the unresolved name.
            // REDIRECT uses its distinct RFC remainder-prepending rule above.
            let target = text(name)?;
            return self.issue(
                e,
                EffectKind::System {
                    name: dns_ascii(&target)?,
                    record_type: desired,
                    remaining_steps: e.remaining,
                },
            );
        }
        if !empty {
            if let Some((service, protocol)) = box_prefix(&f.remaining) {
                let numeric = match (protocol, service.parse::<u16>()) {
                    ("tcp", Ok(p)) => Some((6, p)),
                    ("udp", Ok(p)) => Some((17, p)),
                    ("sctp", Ok(p)) => Some((132, p)),
                    _ => None,
                };
                if numeric.is_some() {
                    return self.boxes(e, records, numeric);
                }
                let kind = EffectKind::Service {
                    service: text(service)?,
                    protocol: text(protocol)?,
                };
                e.frames.last_mut().ok_or(Error::NotReady)?.pending = records;
                return self.issue(e, kind);
            }
            if f.remaining
                .rsplit('.')
                .next()
                .is_some_and(|s| s.starts_with('_'))
            {
                return self.boxes(e, records, None);
            }
            return self.complete(e, Err(Failure::NotFound));
        }
        // Ordinary final records preserve complete type sets and supplemental
        // information. NICK gating is applied by finish_records, not traversal.
        self.finish_records(e, records)
    }
    fn finish_records(&mut self, e: &mut Entry<'a>, mut records: Vec<Record>) -> Result<(), Error> {
        let f = e.frames.last().ok_or(Error::NotReady)?;
        if records.iter().any(|r| {
            r.record_type == RecordType::NICK && r.flags.contains(RecordFlags::SUPPLEMENTAL)
        }) && !records.iter().any(|r| {
            !r.flags.contains(RecordFlags::SUPPLEMENTAL)
                && (f.desired.value() == 0 || r.record_type == f.desired)
        }) {
            return self.complete(e, Err(Failure::NotFound));
        }
        let mut total = 0_usize;
        for r in &mut records {
            rewrite(r, f.zone, self.limits.name_bytes)?;
            r.as_data().validate_fixed_size()?;
            total = total.checked_add(r.data.len()).ok_or(Error::Overflow)?;
            if total > self.limits.record_bytes {
                return Err(Error::Capacity);
            }
        }
        self.complete(e, Ok(records))
    }
    fn boxes(
        &mut self,
        e: &mut Entry<'a>,
        records: Vec<Record>,
        selector: Option<(u16, u16)>,
    ) -> Result<(), Error> {
        let f = e.frames.last().ok_or(Error::NotReady)?;
        let prefix = &f.remaining;
        let mut result = Vec::new();
        result
            .try_reserve_exact(records.len())
            .map_err(|_| Error::Capacity)?;
        for mut r in records {
            let payload = if r.record_type == RecordType::BOX {
                if let Some((proto, service)) = selector {
                    if proto == 0 || service == 0 {
                        continue;
                    }
                    if r.data.len() < 8 {
                        return Err(Error::Malformed);
                    }
                    if r.data[..2] != proto.to_be_bytes() || r.data[2..4] != service.to_be_bytes() {
                        continue;
                    }
                    8
                } else {
                    continue;
                }
            } else if r.record_type == RecordType::SBOX {
                if r.data.len() < 5 {
                    return Err(Error::Malformed);
                }
                let n = r.data[4..]
                    .iter()
                    .position(|&b| b == 0)
                    .ok_or(Error::Malformed)?;
                if &r.data[4..4 + n] != prefix.as_bytes() {
                    continue;
                }
                4 + n + 1
            } else {
                continue;
            };
            let at = if r.record_type == RecordType::BOX {
                4
            } else {
                0
            };
            r.record_type = RecordType::new(u32::from_be_bytes(
                r.data[at..at + 4]
                    .try_into()
                    .map_err(|_| Error::Malformed)?,
            ));
            r.data = bytes(&r.data[payload..])?;
            r.as_data().validate_fixed_size()?;
            if r.flags.contains(RecordFlags::CRITICAL) && !supported(r.record_type) {
                return self.complete(e, Err(Failure::Critical(r.record_type)));
            }
            result.push(r);
        }
        if result.is_empty() {
            return self.complete(e, Err(Failure::NotFound));
        }
        self.finish_records(e, result)
    }
    fn start_bridge(&mut self, e: &mut Entry<'a>, records: Vec<Record>) -> Result<(), Error> {
        let f = e.frames.last().ok_or(Error::NotReady)?;
        let mut namespace = None;
        let mut targets = Vec::new();
        let mut security = Vec::new();
        targets
            .try_reserve_exact(self.limits.servers)
            .map_err(|_| Error::Capacity)?;
        security
            .try_reserve_exact(records.len())
            .map_err(|_| Error::Capacity)?;
        for r in records {
            if r.record_type == RecordType::GNS2DNS && !r.flags.contains(RecordFlags::SUPPLEMENTAL)
            {
                let split = r
                    .data
                    .iter()
                    .position(|&b| b == 0)
                    .ok_or(Error::Malformed)?;
                let n = core::str::from_utf8(&r.data[..split]).map_err(|_| Error::Malformed)?;
                let target = cstring(&r.data[split + 1..])?;
                if namespace
                    .as_ref()
                    .is_some_and(|old: &String| !old.eq_ignore_ascii_case(n))
                {
                    return self.complete(e, Err(Failure::Records));
                }
                if namespace.is_none() {
                    namespace = Some(text(n)?);
                }
                if targets.len() == self.limits.servers {
                    return Err(Error::Capacity);
                }
                targets.push(text(target)?);
            } else if r.flags.contains(RecordFlags::SUPPLEMENTAL) {
                continue;
            } else if gnunet_gnsrecord::is_gns2dns_security_type(r.record_type) {
                security.push(r);
            } else {
                return self.complete(e, Err(Failure::Records));
            }
        }
        let namespace = namespace.ok_or(Error::Malformed)?;
        let authority = if namespace.is_empty() {
            text(".")?
        } else {
            dns_ascii(&namespace)?
        };
        let name = dns_ascii(&join(&f.remaining, &namespace, self.limits.name_bytes)?)?;
        e.frames.last_mut().ok_or(Error::NotReady)?.bridge = Some(Bridge {
            name,
            authority,
            targets,
            next: 0,
            addresses: Vec::new(),
            address: 0,
            security,
        });
        self.bridge(e)
    }
    fn bridge(&mut self, e: &mut Entry<'a>) -> Result<(), Error> {
        loop {
            let f = e.frames.last_mut().ok_or(Error::NotReady)?;
            let zone = f.zone;
            let desired = f.desired;
            let b = f.bridge.as_mut().ok_or(Error::NotReady)?;
            if let Some(&server) = b.addresses.get(b.address) {
                b.address += 1;
                let mut security = Vec::new();
                security
                    .try_reserve_exact(b.security.len())
                    .map_err(|_| Error::Capacity)?;
                for r in &b.security {
                    security.push(Record::copy(r.as_data(), r.origin)?);
                }
                let kind = EffectKind::Dns {
                    authority: text(&b.authority)?,
                    name: text(&b.name)?,
                    record_type: desired,
                    server,
                    security,
                    remaining_steps: e.remaining,
                };
                return self.issue(e, kind);
            }
            b.addresses.clear();
            b.address = 0;
            let Some(target) = b.targets.get(b.next) else {
                return self.complete(e, Err(Failure::NotFound));
            };
            b.next += 1;
            let target = text(target)?;
            if let Ok(ip) = target.parse::<IpAddr>() {
                b.addresses.try_reserve(1).map_err(|_| Error::Capacity)?;
                b.addresses.push(ip);
                continue;
            }
            let (rest, last) = target.rsplit_once('.').unwrap_or(("", &target));
            let gns = if last == "+" {
                Some((zone, rest))
            } else {
                ZoneKey::from_ztld(last).ok().map(|z| (z, rest))
            };
            if let Some((zone, name)) = gns {
                if e.frames.len() == self.limits.frames {
                    return self.complete(e, Err(Failure::Recursion));
                }
                let child = self.frame(zone, name, RecordType::new(0), false)?;
                e.frames.push(child);
                return self.start(e);
            }
            return self.issue(
                e,
                EffectKind::Nameserver {
                    name: dns_ascii(&target)?,
                    remaining_steps: e.remaining,
                },
            );
        }
    }
}
fn box_prefix(input: &str) -> Option<(&str, &str)> {
    let (service, protocol) = input.split_once('.')?;
    if protocol.contains('.') {
        return None;
    }
    Some((service.strip_prefix('_')?, protocol.strip_prefix('_')?))
}
fn supported(kind: RecordType) -> bool {
    matches!(
        kind.value(),
        1 | 2
            | 5
            | 6
            | 12
            | 15
            | 16
            | 28
            | 33
            | 37
            | 39
            | 43
            | 44
            | 46
            | 47
            | 48
            | 50
            | 51
            | 52
            | 53
            | 59
            | 60
            | 61
            | 63
            | 64
            | 65
            | 99
            | 108
            | 109
            | 249
            | 250
            | 255
            | 256
            | 257
            | 65536..=65545 | 65547..=65561 | 65563 | 65564 | 4294901760
    )
}
fn dns_ascii(input: &str) -> Result<String, Error> {
    let mut workspace = gnunet_idna::Workspace::new();
    let backend = gnunet_idna::Backend::new(
        &mut workspace,
        gnunet_idna::Limits::GNUNET,
        gnunet_idna::NativeProfile::Libunistring1_5Unicode18_0,
    );
    let mut out = [0; 255];
    let n = backend.to_ascii(input.as_bytes(), &mut out)?;
    let result = core::str::from_utf8(&out[..n]).map_err(|_| Error::Malformed)?;
    let mut arena_bytes = [0; 255];
    let mut arena = gnunet_dns::Arena::new(&mut arena_bytes);
    let _name = Name::from_dotted(result.as_bytes(), &mut arena)?;
    text(result)
}

#[cfg(test)]
mod counter_tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Exercise actual checked counter exhaustion"
    )]
    use super::*;
    fn request() -> Lookup<'static> {
        Lookup {
            zone: gnunet_gnscrypto::ZoneSecret::Edkey(gnunet_crypto::gns::EdkeySecret::from_seed(
                [7; 32],
            ))
            .public_key(),
            name: "host",
            record_type: RecordType::A,
            policy: Policy::LocalOnly,
            recursion_limit: 5,
        }
    }
    #[test]
    fn query_and_effect_counter_exhaustion_never_wraps_or_reuses() -> Result<(), Error> {
        let mut i = Instance::new();
        let mut r = Resolver::new(&mut i, Limits::default())?;
        r.serial = u64::MAX;
        assert_eq!(r.lookup(request()), Err(Error::Overflow));
        assert!(r.queries.is_empty());
        r.serial = 0;
        r.attempt = u64::MAX;
        assert_eq!(r.lookup(request()), Err(Error::Overflow));
        assert!(r.queries.is_empty());
        r.attempt = u64::MAX - 1;
        let q = r.lookup(request())?;
        let first = r.effect(q)?.ok_or(Error::NotReady)?.id;
        assert_eq!(first.serial, u64::MAX);
        assert_eq!(r.revoked(first, false), Err(Error::Overflow));
        assert_eq!(
            r.take_result(q)?,
            Some(Err(Failure::Fault(Error::Overflow)))
        );
        assert_eq!(r.revoked(first, false), Err(Error::Stale));
        Ok(())
    }
}
