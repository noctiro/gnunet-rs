//! Fixed original-query and dependency ownership for authenticated GNS resolution.

mod dns;
mod records;

pub use dns::validate_dns_reply;

use crate::{
    DnsPolicy, Error, Failure, Lookup, Origin, Policy, RecordType, ZoneKey, names, validate_name,
};
use core::{net::IpAddr, ptr};
use gnunet_gnscrypto::{Block, Label};
use gnunet_gnsrecord::{RecordData, RecordSet, ZoneKeyType};
use zeroize::Zeroize;

/// Largest explicit starting name in the pinned GNS IPC profile.
pub const MAX_NAME_BYTES: usize = 252;
/// Fixed GNS work allowance, including invalid original DHT candidates.
const WORK_LIMIT: u16 = 256;
const BRIDGE_SLOTS: usize = 8;
/// Default bytes reserved per bridge for validated DNS server targets.
pub const DNS_TARGET_BYTES: usize = 1024;
/// Default number of resolved addresses reserved per selected DNS server.
pub const DNS_ADDRESSES: usize = 4;

#[derive(Debug)]
struct Identity {
    _identity: u8,
}

/// Exclusive caller storage for the bounded resolver and its original tokens.
/// Place this storage in a reusable arena when task stacks are constrained.
/// `B` bounds suspended DNS bridges shared by the query slots. Each bridge
/// consumes one arena slot; nesting also uses the original lookup budget.
/// `C` is the byte capacity for server targets in each bridge.
/// `A` bounds distinct, current addresses for a selected server.
pub struct Instance<
    const Q: usize = 4,
    const B: usize = BRIDGE_SLOTS,
    const C: usize = DNS_TARGET_BYTES,
    const A: usize = DNS_ADDRESSES,
> {
    identity: Identity,
    queries: [Option<Entry<A>>; Q],
    bridges: [Option<Bridged<C, A>>; B],
}

impl<const Q: usize, const B: usize, const C: usize, const A: usize> Instance<Q, B, C, A> {
    /// Establish an empty resolver scope and caller-owned query slots.
    pub const fn new() -> Self {
        Self {
            identity: Identity { _identity: 1 },
            queries: [const { None }; Q],
            bridges: [const { None }; B],
        }
    }
}

impl<const Q: usize, const B: usize, const C: usize, const A: usize> Default
    for Instance<Q, B, C, A>
{
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug)]
struct Token<'scope> {
    scope: &'scope Identity,
    serial: u64,
}

impl PartialEq for Token<'_> {
    fn eq(&self, other: &Self) -> bool {
        ptr::eq(self.scope, other.scope) && self.serial == other.serial
    }
}

impl Eq for Token<'_> {}

/// One original lookup in this resolver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryId<'scope>(Token<'scope>);

/// One original dependency attempt in this resolver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectId<'scope>(Token<'scope>);

/// Current original dependency. Inspecting it creates no new attempt.
#[derive(Clone, Copy, Debug)]
pub struct Effect<'scope, 'view> {
    /// Original receipt authority.
    pub id: EffectId<'scope>,
    /// Original logical query.
    pub query: QueryId<'scope>,
    /// Exact dependency parameters.
    pub kind: EffectKind<'view>,
    /// Latest qualified UTC microsecond for this exact delegated attempt.
    pub valid_through: Option<u64>,
}

/// Actual dependencies required before exposing authenticated records.
#[derive(Clone, Copy, Debug)]
pub enum EffectKind<'view> {
    /// Check the local revocation authority for this exact zone.
    Revocation {
        /// Original authority to check.
        zone: ZoneKey,
    },
    /// Read one original local NAMECACHE key.
    Cache {
        /// Exact current zone.
        zone: ZoneKey,
        /// Normalized label.
        label: &'view str,
        /// Original derived query hash.
        key: [u8; 64],
    },
    /// Stream original encrypted candidate blocks through DHT.
    Remote {
        /// Exact current zone.
        zone: ZoneKey,
        /// Normalized label.
        label: &'view str,
        /// Original derived query hash.
        key: [u8; 64],
    },
    /// Resolve one authenticated DNS server hostname through ordinary DNS.
    Nameserver {
        /// Exact IDNA ASCII hostname.
        name: &'view str,
        /// Original remaining recursive work allowance.
        remaining_steps: u16,
    },
    /// Resolve the exact delegated DNS question without returning to GNS.
    Dns {
        /// IDNA ASCII question, including the unresolved GNS prefix.
        name: &'view str,
        /// Exact IDNA ASCII delegated namespace for DNS referral and trust.
        authority: &'view str,
        /// Original desired type.
        record_type: RecordType,
        /// Original delegated server, its current address and authenticated scope.
        server: DnsServer<'view>,
        /// Complete authenticated DNS security records. A provider unable to
        /// enforce these records must fail the attempt.
        security: RecordSet<'view>,
        /// Original remaining recursive work allowance.
        remaining_steps: u16,
    },
    /// Resolve an absolute REDIRECT or CNAME through the configured system DNS
    /// lane. The lane must not call back into GNS.
    System {
        /// Exact effective IDNA ASCII target.
        name: &'view str,
        /// Original desired record type, or ANY for an explicit GNS DNS server.
        record_type: RecordType,
        /// Original remaining recursive work allowance.
        remaining_steps: u16,
    },
}

/// Original server form in the authenticated GNS2DNS record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsServerIdentity<'view> {
    /// The original IDNA ASCII DNS hostname, before address resolution.
    Hostname(&'view str),
    /// The selected address is the literal written in the original record.
    LiteralIp,
    /// The original record uses a GNS name which resolved to this address.
    GnsResolved,
}

/// One resolved nameserver address and its last usable UTC microsecond.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsAddress {
    /// Original IPv4 or IPv6 address.
    pub address: IpAddr,
    /// Absolute validity bound from the source RRset and aliases.
    /// `u64::MAX` leaves validity bounded by the current GNS operation.
    pub valid_through: u64,
}

/// One selected server scoped to the authority of its enclosing DNS effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnsServer<'view> {
    address: IpAddr,
    identity: DnsServerIdentity<'view>,
    valid_through: u64,
}

impl<'view> DnsServer<'view> {
    /// Current address of this exact original server.
    #[must_use]
    pub const fn address(self) -> IpAddr {
        self.address
    }

    /// Original server form, with a DNS hostname only where it was supplied.
    #[must_use]
    pub const fn identity(self) -> DnsServerIdentity<'view> {
        self.identity
    }

    /// Last valid original UTC microsecond under the GNS and address bounds.
    #[must_use]
    pub const fn valid_through(self) -> u64 {
        self.valid_through
    }
}

/// Metadata for a complete reply body rendered into this query's caller buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Answer {
    /// Exact canonical serialized body bytes, excluding the GNS IPC header.
    pub bytes: usize,
    /// Number of applicable records in the body.
    pub records: u32,
    /// Source of this terminal record set, which may differ from the starting zone.
    pub origin: Origin,
}

struct Name {
    bytes: [u8; MAX_NAME_BYTES],
    len: usize,
}

impl Name {
    const EMPTY: Self = Self {
        bytes: [0; MAX_NAME_BYTES],
        len: 0,
    };

    fn new(value: &str) -> Result<Self, Error> {
        Self::joined("", value)
    }

    fn joined(left: &str, right: &str) -> Result<Self, Error> {
        let separator = usize::from(!left.is_empty() && !right.is_empty());
        let split = left.len().checked_add(separator).ok_or(Error::Overflow)?;
        let len = split.checked_add(right.len()).ok_or(Error::Overflow)?;
        if len > MAX_NAME_BYTES {
            return Err(Error::TooLarge);
        }
        let mut bytes = [0; MAX_NAME_BYTES];
        bytes[..left.len()].copy_from_slice(left.as_bytes());
        if separator != 0 {
            bytes[left.len()] = b'.';
        }
        bytes[split..len].copy_from_slice(right.as_bytes());
        Ok(Self { bytes, len })
    }

    fn as_str(&self) -> Result<&str, Error> {
        core::str::from_utf8(&self.bytes[..self.len]).map_err(|_| Error::InvalidInput)
    }
}

struct Authority {
    zone: ZoneKey,
    label: Name,
    remaining: Name,
    initial: bool,
}

impl Authority {
    fn new(zone: ZoneKey, name: &str, initial: bool) -> Result<Self, Error> {
        validate_name(name)?;
        if name.len() > MAX_NAME_BYTES {
            return Err(Error::TooLarge);
        }
        let (remaining, label) = names::split_authority(name);
        let mut canonical = Name::EMPTY;
        let mut scalars = ['\0'; MAX_NAME_BYTES * 4];
        canonical.len = Label::normalize(label, &mut scalars, &mut canonical.bytes)?
            .as_str()
            .len();
        Ok(Self {
            zone,
            label: canonical,
            remaining: Name::new(remaining)?,
            initial,
        })
    }

    fn with_label<T>(&self, call: impl FnOnce(Label<'_>) -> Result<T, Error>) -> Result<T, Error> {
        let mut scalars = ['\0'; MAX_NAME_BYTES * 4];
        let mut bytes = [0; MAX_NAME_BYTES];
        call(Label::normalize(
            self.label.as_str()?,
            &mut scalars,
            &mut bytes,
        )?)
    }
}

#[derive(Clone, Copy)]
enum Dependency {
    Revocation,
    Cache([u8; 64]),
    Remote([u8; 64]),
    Dns(dns::Attempt),
}

#[derive(Clone, Copy)]
enum State {
    Waiting {
        attempt: u64,
        dependency: Dependency,
    },
    Done(Result<Answer, Failure>),
}

struct Entry<const A: usize> {
    serial: u64,
    authority: Authority,
    desired: RecordType,
    policy: Policy,
    transitions: u16,
    work: u16,
    state: State,
    bridge: Option<BridgeSlot>,
    system: Option<SystemResolution>,
    addresses: dns::Addresses<A>,
    observed_utc: u64,
}

#[derive(Clone, Copy)]
struct BridgeSlot(usize);

struct Bridged<const C: usize, const A: usize> {
    parent: Option<BridgeSlot>,
    authority_until: u64,
    source_zone: ZoneKey,
    targets: dns::Bridge<C, A>,
    exhausted: Failure,
}

impl<const C: usize, const A: usize> Bridged<C, A> {
    fn active_until(&self) -> u64 {
        self.authority_until.min(self.targets.selected_until())
    }
}

struct SystemResolution {
    name: dns::Name,
    valid_through: u64,
}

struct Candidate<const C: usize, const A: usize> {
    step: Result<records::Step<C, A>, Failure>,
    valid_through: u64,
}

impl<const A: usize> Entry<A> {
    fn addressing(&self) -> bool {
        self.bridge.is_some()
    }

    fn desired(&self) -> RecordType {
        if self.addressing() {
            RecordType::ANY
        } else {
            self.desired
        }
    }
}

/// One allocation-free resolver with finite original query and candidate slots.
/// The embedding owns actual dependencies, one reusable plaintext scratch and
/// the output storage for each original query until its reply is admitted.
pub struct Resolver<
    'scope,
    const Q: usize,
    const B: usize = BRIDGE_SLOTS,
    const C: usize = DNS_TARGET_BYTES,
    const A: usize = DNS_ADDRESSES,
> {
    scope: &'scope Identity,
    next: u64,
    queries: &'scope mut [Option<Entry<A>>; Q],
    bridges: &'scope mut [Option<Bridged<C, A>>; B],
    dns_policy: DnsPolicy,
    box_registry: Option<&'scope dyn crate::BoxRegistry>,
}

impl<'scope, const Q: usize, const B: usize, const C: usize, const A: usize>
    Resolver<'scope, Q, B, C, A>
{
    /// Take the original scope. The compile-time width bounds all active and
    /// completed operations held by this resolver. Allow external DNS effects.
    pub fn new(scope: &'scope mut Instance<Q, B, C, A>) -> Self {
        Self::with_dns_policy(scope, DnsPolicy::Allow)
    }

    /// Take the scope with an explicit DNS policy for all admitted queries.
    pub fn with_dns_policy(scope: &'scope mut Instance<Q, B, C, A>, dns_policy: DnsPolicy) -> Self {
        scope.queries.fill_with(|| None);
        scope.bridges.fill_with(|| None);
        Self {
            scope: &scope.identity,
            next: 0,
            queries: &mut scope.queries,
            bridges: &mut scope.bridges,
            dns_policy,
            box_registry: None,
        }
    }

    /// Configure additional numeric BOX service mappings from the host.
    #[must_use]
    pub fn with_box_registry(mut self, registry: &'scope dyn crate::BoxRegistry) -> Self {
        self.box_registry = Some(registry);
        self
    }

    /// Admit one explicit-zone lookup and request its first revocation check.
    pub fn lookup(&mut self, request: Lookup<'_>) -> Result<QueryId<'scope>, Error> {
        let index = self
            .queries
            .iter()
            .position(Option::is_none)
            .ok_or(Error::WouldBlock)?;
        let authority = Authority::new(request.zone, request.name, true)?;
        let serial = self.fresh()?;
        let attempt = self.fresh()?;
        self.queries[index] = Some(Entry {
            serial,
            authority,
            desired: request.record_type,
            policy: request.policy,
            transitions: request.recursion_limit,
            work: WORK_LIMIT - 1,
            state: State::Waiting {
                attempt,
                dependency: Dependency::Revocation,
            },
            bridge: None,
            system: None,
            addresses: dns::Addresses::EMPTY,
            observed_utc: 0,
        });
        Ok(QueryId(self.token(serial)))
    }

    /// Inspect the exact dependency still owned by this query.
    pub fn effect(&self, query: QueryId<'_>) -> Result<Option<Effect<'scope, '_>>, Error> {
        let entry = self.entry(self.query_index(query)?)?;
        let State::Waiting {
            attempt,
            dependency,
        } = entry.state
        else {
            return Ok(None);
        };
        let zone = entry.authority.zone;
        let kind = match dependency {
            Dependency::Revocation => EffectKind::Revocation { zone },
            Dependency::Cache(key) => EffectKind::Cache {
                zone,
                label: entry.authority.label.as_str()?,
                key,
            },
            Dependency::Remote(key) => EffectKind::Remote {
                zone,
                label: entry.authority.label.as_str()?,
                key,
            },
            Dependency::Dns(dns_attempt) => self.dns_effect(entry, dns_attempt)?,
        };
        Ok(Some(Effect {
            id: EffectId(self.token(attempt)),
            query: QueryId(self.token(entry.serial)),
            kind,
            valid_through: self.delegation_deadline(entry)?,
        }))
    }

    /// Read terminal metadata. The caller retains the exact successful output
    /// written by its original receipt until the physical reply settles.
    pub fn outcome(&self, query: QueryId<'_>) -> Result<Option<Result<Answer, Failure>>, Error> {
        Ok(match self.entry(self.query_index(query)?)?.state {
            State::Waiting { .. } => None,
            State::Done(result) => Some(result),
        })
    }

    /// Retire the original active or terminal operation and release its slot.
    pub fn cancel(&mut self, query: QueryId<'_>) -> Result<(), Error> {
        let index = self.query_index(query)?;
        self.release_bridges(index)?;
        self.queries[index] = None;
        Ok(())
    }

    /// Retire an attempt whose original delegation no longer qualifies.
    /// When expiry is due, retire its exact native lease and charge the
    /// reported work before issuing a replacement.
    pub fn expire_at(
        &mut self,
        query: QueryId<'_>,
        now: u64,
        retire: impl FnOnce() -> Result<u16, Error>,
    ) -> Result<bool, Error> {
        self.expire_index(self.query_index(query)?, now, retire)
    }

    /// Settle the original revocation observation. Failed native queries must
    /// be reported using [Self::failed].
    pub fn revoked(&mut self, id: EffectId<'_>, revoked: bool) -> Result<(), Error> {
        let (index, dependency) = self.attempt_index(id)?;
        if !matches!(dependency, Dependency::Revocation) {
            return Err(Error::InvalidInput);
        }
        if revoked {
            return self.authority_failure(index, Failure::Revoked);
        }
        let frame = &self.entry(index)?.authority;
        let key = match frame.with_label(|label| gnunet_gnscrypto::query(frame.zone, label)) {
            Ok(key) => key,
            Err(error) => return self.finish(index, Err(Failure::Fault(error))),
        };
        self.issue(index, Dependency::Cache(key))
    }

    /// Process an exact NAMECACHE observation. Invalid cache input is a miss
    /// under the original local/remote policy. No plaintext substitute is accepted.
    pub fn cached(
        &mut self,
        id: EffectId<'_>,
        block: Option<&[u8]>,
        now: u64,
        plaintext: &mut [u8],
        output: &mut [u8],
    ) -> Result<(), Error> {
        check_time(now)?;
        let (index, dependency) = self.attempt_index(id)?;
        let Dependency::Cache(key) = dependency else {
            return Err(Error::InvalidInput);
        };
        if self.expire_index(index, now, || Ok(0))? {
            return Ok(());
        }
        let now = self.entry(index)?.observed_utc;
        if let Some(block) = block {
            match self.candidate(index, block, now, plaintext, output) {
                Ok(candidate) => return self.apply(index, candidate, now, output),
                Err(Error::Capacity) => return Err(Error::Capacity),
                Err(_) => (),
            }
        }
        self.remote(index, key)
    }

    /// Process one complete original encrypted DHT candidate. True permits
    /// opaque caching of these exact bytes because authenticity, expiry,
    /// decryption and applicable record framing were verified. A rejected candidate returns false
    /// and keeps its original GET while work remains.
    pub fn remote_block(
        &mut self,
        id: EffectId<'_>,
        block: &[u8],
        now: u64,
        plaintext: &mut [u8],
        output: &mut [u8],
    ) -> Result<bool, Error> {
        check_time(now)?;
        let (index, dependency) = self.attempt_index(id)?;
        if !matches!(dependency, Dependency::Remote(_)) {
            return Err(Error::InvalidInput);
        }
        if self.expire_index(index, now, || Ok(0))? {
            return Ok(false);
        }
        let now = self.entry(index)?.observed_utc;
        let entry = self.entry_mut(index)?;
        if entry.work == 0 {
            self.finish(index, Err(Failure::Recursion))?;
            return Ok(false);
        }
        entry.work -= 1;
        match self.candidate(index, block, now, plaintext, output) {
            Ok(candidate) => {
                self.apply(index, candidate, now, output)?;
                Ok(true)
            }
            Err(Error::Capacity) => Err(Error::Capacity),
            Err(_) => {
                if self.entry(index)?.work == 0 {
                    self.finish(index, Err(Failure::Recursion))?;
                }
                Ok(false)
            }
        }
    }

    /// Retire the exact original failed dependency. Cache failure may start
    /// a remote attempt, but failure cannot bypass revocation.
    pub fn failed(&mut self, id: EffectId<'_>, error: Error) -> Result<(), Error> {
        self.failed_counted(id, error, 0)
    }

    /// Retire an exact dependency and account work that could not produce a
    /// usable result. A subsequent server uses only the remaining allowance.
    pub fn failed_counted(
        &mut self,
        id: EffectId<'_>,
        error: Error,
        spent: u16,
    ) -> Result<(), Error> {
        let (index, dependency) = self.attempt_index(id)?;
        if !self.charge(index, spent)? {
            return Ok(());
        }
        let failure = if error == Error::NotFound {
            Failure::NotFound
        } else {
            Failure::Fault(error)
        };
        if error == Error::OutcomeUnknown {
            return self.finish(index, Err(failure));
        }
        match dependency {
            Dependency::Cache(key) => self.remote(index, key),
            Dependency::Dns(
                attempt @ (dns::Attempt::Server(_, Some(_)) | dns::Attempt::System(Some(_))),
            ) => self.collect_addresses(index, attempt, dns::Addresses::EMPTY),
            Dependency::Dns(dns::Attempt::Nameserver(_) | dns::Attempt::Server(_, None)) => {
                self.advance_bridge(index)
            }
            _ => self.authority_failure(index, failure),
        }
    }

    /// Supply the exact address set observed for one original DNS hostname.
    /// An empty set advances to the next authenticated server target.
    /// A set exceeding the address budget advances with a capacity failure.
    pub fn nameserver(
        &mut self,
        id: EffectId<'_>,
        addresses: &[DnsAddress],
        spent: u16,
    ) -> Result<(), Error> {
        let (index, dependency) = self.attempt_index(id)?;
        if !matches!(dependency, Dependency::Dns(dns::Attempt::Nameserver(_))) {
            return Err(Error::InvalidInput);
        }
        let now = self.entry(index)?.observed_utc;
        if !self.charge(index, spent)? {
            return Ok(());
        }
        let Some(addresses) =
            self.checked_addresses(index, dns::Addresses::supplied(addresses, now))?
        else {
            return Ok(());
        };
        self.supply_addresses(index, addresses)
    }

    /// Supply the actual original DNS/system answer in canonical uncompressed
    /// RDATA, after source binding, recursion and DNS security checks. Native
    /// replies cannot return any GNS type or initiate GNS fallback.
    pub fn resolved(
        &mut self,
        id: EffectId<'_>,
        records: &[RecordData<'_>],
        spent: u16,
        now: u64,
        output: &mut [u8],
    ) -> Result<(), Error> {
        check_time(now)?;
        let (index, dependency) = self.attempt_index(id)?;
        let Dependency::Dns(attempt @ (dns::Attempt::Server(..) | dns::Attempt::System(_))) =
            dependency
        else {
            return Err(Error::InvalidInput);
        };
        if self.expire_index(index, now, || Ok(spent))? {
            return Ok(());
        }
        let entry = self.entry(index)?;
        let now = entry.observed_utc;
        let valid_through = self.delegation_deadline(entry)?.unwrap_or(u64::MAX);
        validate_dns_reply(records)?;
        if self.entry(index)?.work < spent {
            return self.finish(index, Err(Failure::Recursion));
        }
        if let dns::Attempt::Server(_, Some(family)) | dns::Attempt::System(Some(family)) = attempt
        {
            let addresses = dns::Addresses::records(
                records.iter().copied().map(Ok),
                now,
                Some(family),
                valid_through,
            );
            let _charged = self.charge(index, spent)?;
            let Some(addresses) = self.checked_addresses(index, addresses)? else {
                return Ok(());
            };
            return self.collect_addresses(index, attempt, addresses);
        }
        let (hostname, origin) = match attempt {
            dns::Attempt::Server(server, _) => (
                Some(self.bridge(index)?.targets.question_name()?),
                Origin::Dns(server.resolved.address),
            ),
            dns::Attempt::System(_) => (None, Origin::System),
            dns::Attempt::Nameserver(_) => return Err(Error::Conflict),
        };
        let result = dns::answer(records, hostname, now, valid_through, origin, output)?;
        let _charged = self.charge(index, spent)?;
        if let Some(answer) = result {
            return self.finish(index, Ok(answer));
        }
        match attempt {
            dns::Attempt::Server(..) => self.advance_bridge(index),
            _ => self.finish(index, Err(Failure::NotFound)),
        }
    }

    fn candidate(
        &self,
        index: usize,
        input: &[u8],
        now: u64,
        plaintext: &mut [u8],
        output: &mut [u8],
    ) -> Result<Candidate<C, A>, Error> {
        let entry = self.entry(index)?;
        let block = Block::decode(input)?;
        let frame = &entry.authority;
        let checked = frame.with_label(|label| block.verify_for(frame.zone, label))?;
        let valid_through = checked.block().expiration()?;
        let tag = if block.kind() == ZoneKeyType::Edkey {
            16
        } else {
            0
        };
        let width = block
            .ciphertext()
            .len()
            .checked_sub(tag)
            .ok_or(Error::Truncated)?;
        let plaintext = plaintext.get_mut(..width).ok_or(Error::Capacity)?;
        let result = checked.open_at(now, plaintext).and_then(|records| {
            records::process(
                frame,
                entry.desired(),
                records,
                output,
                self.box_registry,
                self.dns_policy,
            )
        });
        plaintext.zeroize();
        result.map(|step| Candidate {
            step,
            valid_through,
        })
    }

    fn apply(
        &mut self,
        index: usize,
        candidate: Candidate<C, A>,
        now: u64,
        output: &[u8],
    ) -> Result<(), Error> {
        match candidate.step {
            Ok(records::Step::Answer(answer)) if self.entry(index)?.addressing() => {
                let bytes = output.get(..answer.bytes).ok_or(Error::Conflict)?;
                let count = usize::try_from(answer.records).map_err(|_| Error::Capacity)?;
                let records = RecordSet::parse(bytes, count, count)?;
                let addresses =
                    dns::Addresses::records(records.iter(), now, None, candidate.valid_through);
                let Some(addresses) = self.checked_addresses(index, addresses)? else {
                    return Ok(());
                };
                self.supply_addresses(index, addresses)
            }
            Ok(records::Step::Answer(answer)) => self.finish(index, Ok(answer)),
            Err(failure) => self.authority_failure(index, failure),
            Ok(records::Step::Follow(zone, name)) => self.transition(index, zone, &name),
            Ok(records::Step::Dns(targets)) => {
                self.start_bridge(index, targets, candidate.valid_through)
            }
            Ok(records::Step::System(name)) => {
                let entry = self.entry_mut(index)?;
                let family = entry.addressing().then_some(dns::Family::V4);
                entry.system = Some(SystemResolution {
                    name,
                    valid_through: candidate.valid_through,
                });
                self.issue(index, Dependency::Dns(dns::Attempt::System(family)))
            }
        }
    }

    fn dns_effect<'view>(
        &'view self,
        entry: &'view Entry<A>,
        attempt: dns::Attempt,
    ) -> Result<EffectKind<'view>, Error> {
        let remaining_steps = entry.work;
        Ok(match attempt {
            dns::Attempt::Nameserver(index) => EffectKind::Nameserver {
                name: self
                    .bridge_at(entry.bridge.ok_or(Error::Conflict)?)?
                    .targets
                    .hostname(index)?,
                remaining_steps,
            },
            dns::Attempt::Server(server, family) => {
                let bridge = self.bridge_at(entry.bridge.ok_or(Error::Conflict)?)?;
                let target = &bridge.targets;
                EffectKind::Dns {
                    name: target.question_name()?,
                    authority: target.authority()?,
                    record_type: family.map_or(entry.desired, dns::Family::kind),
                    server: target.server(server, bridge.authority_until)?,
                    security: target.security()?,
                    remaining_steps,
                }
            }
            dns::Attempt::System(family) => EffectKind::System {
                name: entry
                    .system
                    .as_ref()
                    .ok_or(Error::Conflict)?
                    .name
                    .as_str()?,
                record_type: family.map_or(entry.desired, dns::Family::kind),
                remaining_steps,
            },
        })
    }

    fn bridge(&self, index: usize) -> Result<&Bridged<C, A>, Error> {
        self.bridge_at(self.entry(index)?.bridge.ok_or(Error::Conflict)?)
    }

    fn bridge_mut(&mut self, index: usize) -> Result<&mut Bridged<C, A>, Error> {
        let slot = self.entry(index)?.bridge.ok_or(Error::Conflict)?;
        self.bridges
            .get_mut(slot.0)
            .and_then(Option::as_mut)
            .ok_or(Error::Conflict)
    }

    fn bridge_at(&self, slot: BridgeSlot) -> Result<&Bridged<C, A>, Error> {
        self.bridges
            .get(slot.0)
            .and_then(Option::as_ref)
            .ok_or(Error::Conflict)
    }

    fn release_bridge(&mut self, index: usize) -> Result<(), Error> {
        let original = self.entry(index)?.bridge.ok_or(Error::Conflict)?;
        let parent = self.bridge_at(original)?.parent;
        self.bridges[original.0] = None;
        self.entry_mut(index)?.bridge = parent;
        Ok(())
    }

    fn release_bridges(&mut self, index: usize) -> Result<(), Error> {
        while self.entry(index)?.addressing() {
            self.release_bridge(index)?;
        }
        Ok(())
    }

    fn start_bridge(
        &mut self,
        index: usize,
        targets: dns::Bridge<C, A>,
        block_until: u64,
    ) -> Result<(), Error> {
        let entry = self.entry(index)?;
        let parent_slot = entry.bridge;
        let source_zone = entry.authority.zone;
        let parent_until = match parent_slot {
            Some(slot) => self.bridge_at(slot)?.active_until(),
            None => u64::MAX,
        };
        let Some(available) = self.bridges.iter().position(Option::is_none) else {
            return self.authority_failure(index, Failure::Fault(Error::Capacity));
        };
        let slot = BridgeSlot(available);
        self.bridges[slot.0] = Some(Bridged {
            parent: parent_slot,
            authority_until: targets.security_until.min(block_until).min(parent_until),
            source_zone,
            targets,
            exhausted: Failure::NotFound,
        });
        self.entry_mut(index)?.bridge = Some(slot);
        self.advance_bridge(index)
    }

    fn delegation_deadline(&self, entry: &Entry<A>) -> Result<Option<u64>, Error> {
        let mut until = match entry.bridge {
            Some(slot) => self.bridge_at(slot)?.active_until(),
            None => u64::MAX,
        };
        if let State::Waiting {
            dependency: Dependency::Dns(attempt),
            ..
        } = entry.state
        {
            match attempt {
                dns::Attempt::Server(server, _) => until = until.min(server.resolved.valid_through),
                dns::Attempt::System(_) => {
                    until = until.min(entry.system.as_ref().ok_or(Error::Conflict)?.valid_through);
                }
                dns::Attempt::Nameserver(_) => (),
            }
        }
        Ok((until != u64::MAX).then_some(until))
    }

    fn expire_index(
        &mut self,
        index: usize,
        now: u64,
        retire: impl FnOnce() -> Result<u16, Error>,
    ) -> Result<bool, Error> {
        check_time(now)?;
        let entry = self.entry_mut(index)?;
        entry.observed_utc = entry.observed_utc.max(now);
        let now = entry.observed_utc;
        if self
            .delegation_deadline(self.entry(index)?)?
            .is_none_or(|until| until >= now)
        {
            return Ok(false);
        }
        if !self.charge(index, retire()?)? {
            return Ok(true);
        }
        let failure = Failure::Fault(Error::Deadline);
        while let Some(slot) = self.entry(index)?.bridge {
            let bridge = self.bridge_at(slot)?;
            if bridge.authority_until >= now {
                self.bridge_mut(index)?.exhausted = failure;
                self.advance_bridge(index)?;
                return Ok(true);
            }
            if bridge.parent.is_none() {
                break;
            }
            self.release_bridge(index)?;
        }
        self.finish(index, Err(failure))?;
        Ok(true)
    }

    fn collect_addresses(
        &mut self,
        index: usize,
        attempt: dns::Attempt,
        addresses: dns::Addresses<A>,
    ) -> Result<(), Error> {
        let entry = self.entry_mut(index)?;
        if let Err(error) = entry.addresses.merge(addresses, entry.observed_utc) {
            return self.authority_failure(index, Failure::Fault(error));
        }
        let next = match attempt {
            dns::Attempt::Server(server, Some(dns::Family::V4)) => {
                Some(dns::Attempt::Server(server, Some(dns::Family::V6)))
            }
            dns::Attempt::System(Some(dns::Family::V4)) => {
                Some(dns::Attempt::System(Some(dns::Family::V6)))
            }
            _ => None,
        };
        if let Some(next) = next {
            return self.issue(index, Dependency::Dns(next));
        }
        let entry = self.entry_mut(index)?;
        let addresses = core::mem::replace(&mut entry.addresses, dns::Addresses::EMPTY);
        if addresses.live(entry.observed_utc) {
            if matches!(attempt, dns::Attempt::Server(..)) {
                self.release_bridge(index)?;
            }
            self.supply_addresses(index, addresses)
        } else {
            self.advance_bridge(index)
        }
    }

    fn checked_addresses(
        &mut self,
        index: usize,
        addresses: Result<dns::Addresses<A>, Error>,
    ) -> Result<Option<dns::Addresses<A>>, Error> {
        match addresses {
            Ok(addresses) => Ok(Some(addresses)),
            Err(Error::Capacity) => {
                self.authority_failure(index, Failure::Fault(Error::Capacity))?;
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn supply_addresses(
        &mut self,
        index: usize,
        addresses: dns::Addresses<A>,
    ) -> Result<(), Error> {
        self.bridge_mut(index)?.targets.supply(addresses);
        self.advance_bridge(index)
    }

    fn advance_bridge(&mut self, index: usize) -> Result<(), Error> {
        let entry = self.entry_mut(index)?;
        entry.system = None;
        entry.addresses = dns::Addresses::EMPTY;
        let now = entry.observed_utc;
        loop {
            let bridge = self.bridge_mut(index)?;
            let child = bridge.parent.is_some();
            let failure = bridge.exhausted;
            match bridge.targets.next(bridge.source_zone, now)? {
                Some(dns::Step::Native(dns::Attempt::Server(server, _))) if child => {
                    return self.issue(
                        index,
                        Dependency::Dns(dns::Attempt::Server(server, Some(dns::Family::V4))),
                    );
                }
                Some(dns::Step::Native(attempt)) => {
                    return self.issue(index, Dependency::Dns(attempt));
                }
                Some(dns::Step::Gns(zone, name)) => {
                    let Ok(authority) = name
                        .as_str()
                        .and_then(|name| Authority::new(zone, name, false))
                    else {
                        continue;
                    };
                    return self.enter_authority(index, authority);
                }
                None if child => {
                    self.release_bridge(index)?;
                    if failure != Failure::NotFound {
                        self.bridge_mut(index)?.exhausted = failure;
                    }
                }
                None => return self.finish(index, Err(failure)),
            }
        }
    }

    fn enter_authority(&mut self, index: usize, authority: Authority) -> Result<(), Error> {
        let entry = self.entry_mut(index)?;
        if entry.transitions == 0 {
            return self.finish(index, Err(Failure::Recursion));
        }
        entry.transitions -= 1;
        entry.authority = authority;
        self.issue(index, Dependency::Revocation)
    }

    fn transition(&mut self, index: usize, zone: ZoneKey, name: &Name) -> Result<(), Error> {
        if self.entry(index)?.transitions == 0 {
            return self.finish(index, Err(Failure::Recursion));
        }
        let frame = match Authority::new(zone, name.as_str()?, false) {
            Ok(frame) => frame,
            Err(error) => return self.authority_failure(index, Failure::Fault(error)),
        };
        self.enter_authority(index, frame)
    }

    fn authority_failure(&mut self, index: usize, failure: Failure) -> Result<(), Error> {
        if self.entry(index)?.addressing() {
            if failure == Failure::Fault(Error::Capacity) {
                self.bridge_mut(index)?.exhausted = failure;
            }
            self.advance_bridge(index)
        } else {
            self.finish(index, Err(failure))
        }
    }

    fn charge(&mut self, index: usize, spent: u16) -> Result<bool, Error> {
        let entry = self.entry_mut(index)?;
        if let Some(left) = entry.work.checked_sub(spent) {
            entry.work = left;
            Ok(true)
        } else {
            self.finish(index, Err(Failure::Recursion))?;
            Ok(false)
        }
    }

    fn remote(&mut self, index: usize, key: [u8; 64]) -> Result<(), Error> {
        let entry = self.entry(index)?;
        let allowed = match entry.policy {
            Policy::CacheThenRemote => true,
            Policy::LocalOnly => false,
            Policy::LocalMaster => !entry.authority.initial,
        };
        if allowed {
            self.issue(index, Dependency::Remote(key))
        } else {
            self.authority_failure(index, Failure::NotFound)
        }
    }

    fn issue(&mut self, index: usize, dependency: Dependency) -> Result<(), Error> {
        if self.entry(index)?.work == 0 {
            return self.finish(index, Err(Failure::Recursion));
        }
        let attempt = match self.fresh() {
            Ok(attempt) => attempt,
            Err(error) => return self.finish(index, Err(Failure::Fault(error))),
        };
        let entry = self.entry_mut(index)?;
        entry.work -= 1;
        entry.state = State::Waiting {
            attempt,
            dependency,
        };
        Ok(())
    }

    fn finish(&mut self, index: usize, result: Result<Answer, Failure>) -> Result<(), Error> {
        self.release_bridges(index)?;
        let entry = self.entry_mut(index)?;
        entry.system = None;
        entry.addresses = dns::Addresses::EMPTY;
        entry.state = State::Done(result);
        Ok(())
    }

    fn fresh(&mut self) -> Result<u64, Error> {
        self.next = self.next.checked_add(1).ok_or(Error::Overflow)?;
        Ok(self.next)
    }

    fn token(&self, serial: u64) -> Token<'scope> {
        Token {
            scope: self.scope,
            serial,
        }
    }

    fn entry(&self, index: usize) -> Result<&Entry<A>, Error> {
        self.queries
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(Error::Stale)
    }

    fn entry_mut(&mut self, index: usize) -> Result<&mut Entry<A>, Error> {
        self.queries
            .get_mut(index)
            .and_then(Option::as_mut)
            .ok_or(Error::Stale)
    }

    fn query_index(&self, query: QueryId<'_>) -> Result<usize, Error> {
        if !ptr::eq(query.0.scope, self.scope) {
            return Err(Error::Stale);
        }
        self.queries
            .iter()
            .position(|entry| {
                entry
                    .as_ref()
                    .is_some_and(|entry| entry.serial == query.0.serial)
            })
            .ok_or(Error::Stale)
    }

    fn attempt_index(&self, id: EffectId<'_>) -> Result<(usize, Dependency), Error> {
        if !ptr::eq(id.0.scope, self.scope) {
            return Err(Error::Stale);
        }
        self.queries
            .iter()
            .enumerate()
            .find_map(|(index, slot)| match slot.as_ref()?.state {
                State::Waiting {
                    attempt,
                    dependency,
                } if attempt == id.0.serial => Some((index, dependency)),
                _ => None,
            })
            .ok_or(Error::Stale)
    }
}

impl<const Q: usize, const B: usize, const C: usize, const A: usize> Drop
    for Resolver<'_, Q, B, C, A>
{
    fn drop(&mut self) {
        self.queries.fill_with(|| None);
        self.bridges.fill_with(|| None);
    }
}

fn pad_records(
    count: u32,
    len: usize,
    delegation: bool,
    origin: Origin,
    output: &mut [u8],
) -> Result<Answer, Error> {
    let end = if delegation {
        len
    } else {
        len.checked_next_power_of_two().ok_or(Error::Overflow)?
    };
    if end > usize::from(u16::MAX) - 12 {
        return Err(Error::TooLarge);
    }
    output.get_mut(len..end).ok_or(Error::Capacity)?.fill(0);
    Ok(Answer {
        bytes: end,
        records: count,
        origin,
    })
}

fn check_time(now: u64) -> Result<(), Error> {
    if now == u64::MAX {
        Err(Error::TimeUncertain)
    } else {
        Ok(())
    }
}
