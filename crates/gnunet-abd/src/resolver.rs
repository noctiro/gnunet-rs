use crate::resource::{self, bytes, reserve, sum};
use crate::{Credential, Principal, Time};
use alloc::vec::Vec;
use core::{cell::Cell, fmt};
use gnunet_types::Error;
use gnunet_wire::official::abd::{self, Chain, Policy, RecordLayout};

const NONE: usize = usize::MAX;
const ATTRIBUTE: u32 = 65_549;
const DELEGATE: u32 = 65_548;

/// Non-cloneable serial authority, borrowed by all its original queries.
pub struct Instance {
    next: Cell<Option<u64>>,
}
impl Instance {
    /// New unused authority; serial exhaustion never wraps or reuses IDs.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next: Cell::new(Some(1)),
        }
    }
    fn allocate(&self) -> Result<u64, Error> {
        let id = self.next.get().ok_or(Error::Overflow)?;
        self.next.set(id.checked_add(1));
        Ok(id)
    }
}
impl Default for Instance {
    fn default() -> Self {
        Self::new()
    }
}

/// Original instance/query/lookup identity, distinct from native/wire IDs.
#[derive(Clone, Copy)]
pub struct LookupId<'i> {
    instance: &'i Instance,
    query: u64,
    serial: u64,
}
impl PartialEq for LookupId<'_> {
    fn eq(&self, rhs: &Self) -> bool {
        core::ptr::eq(self.instance, rhs.instance)
            && self.query == rhs.query
            && self.serial == rhs.serial
    }
}
impl Eq for LookupId<'_> {}
impl fmt::Debug for LookupId<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LookupId")
            .field(&self.query)
            .field(&self.serial)
            .finish()
    }
}

/// Explicit finite resource and record-layout profile for one original query.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum distinct public principals, including issuer and requested subject.
    pub principals: usize,
    /// Maximum distinct authority/role nodes, without eviction or aliasing.
    pub roles: usize,
    /// Maximum conjunctive alternative rules, including signed delegates.
    pub rules: usize,
    /// Maximum terms in one conjunction.
    pub terms: usize,
    /// Maximum linked-role components in one term.
    pub depth: usize,
    /// Maximum derived membership facts.
    pub facts: usize,
    /// Maximum retained original supporting-fact references across all facts.
    pub supports: usize,
    /// Maximum original native GNS lookup owners, including completed ones.
    pub lookups: usize,
    /// Maximum canonical credentials retained, including discovered signed DEL.
    pub credentials: usize,
    /// Maximum role byte extent before and after Unicode lowercase/NFD.
    pub name_bytes: usize,
    /// Actual retained allocation capacities, including proof and dense index.
    pub retained_bytes: usize,
    /// Actual target C layout of the unpacked ATTR header.
    pub record_layout: RecordLayout,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            principals: 128,
            roles: 256,
            rules: 512,
            terms: 16,
            depth: 16,
            facts: 4096,
            supports: 32768,
            lookups: 512,
            credentials: 128,
            name_bytes: 253,
            retained_bytes: 4 * 1024 * 1024,
            record_layout: RecordLayout::native(),
        }
    }
}
impl Limits {
    /// Reject impossible/overflowing configured bounds before allocating or I/O.
    pub fn validate(self) -> Result<(), Error> {
        self.record_layout.validate()?;
        if self.principals < 2
            || self.roles == 0
            || self.rules == 0
            || self.terms == 0
            || self.depth == 0
            || self.facts == 0
            || self.lookups == 0
            || self.credentials == 0
            || self.name_bytes == 0
            || self.name_bytes > 65530
            || self.retained_bytes == 0
        {
            return Err(Error::InvalidInput);
        }
        self.principals
            .checked_mul(self.roles)
            .ok_or(Error::Overflow)?;
        self.principals
            .checked_mul(self.depth)
            .ok_or(Error::Overflow)?;
        self.terms.checked_mul(self.depth).ok_or(Error::Overflow)?;
        Ok(())
    }
}

/// A real result record from the exact originally admitted GNS lookup. The host
/// must supply only records authenticated by that lookup's GNS resolver; this
/// public value does not authenticate arbitrary bytes by its own construction.
#[derive(Clone, Copy, Debug)]
pub struct Record<'a> {
    /// Original GNS type, either ATTR or DEL for this query's corresponding lookup.
    pub record_type: u32,
    /// Exact original binary record.
    pub data: &'a [u8],
    /// Conservative absolute validity deadline of the original GNS result.
    pub expiration_us: u64,
}

/// Native work requiring the original explicit GNS/clock/source owners.
#[derive(Clone, Copy, Debug)]
pub enum Action<'a> {
    /// Start one keyed GNS lookup. It is not a completed or written lookup.
    Lookup {
        /// Original zone public authority, including key type.
        zone: Principal,
        /// Actual relative attribute, or @ for forward DEL lookup.
        attribute: &'a [u8],
        /// Actual record type65549 or65548.
        record_type: u32,
    },
    /// Physically retire the original source after local cancel/result/failure.
    Cancel {
        /// Exact source token previously supplied to admit; never a replacement.
        source: u64,
    },
}
/// One retained original effect. Re-observing it does not create new authority.
#[derive(Clone, Copy, Debug)]
pub struct Effect<'a, 'i> {
    /// Stable original instance/query/lookup identity.
    pub id: LookupId<'i>,
    /// Original work or physical retirement.
    pub action: Action<'a>,
}

/// Business terminal. Physical admitted lookup debts remain until explicitly
/// retired; callers must use is_quiescent instead of treating outcome as cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// A concrete acyclic proof for the requested subject was derived.
    Authorized {
        /// Earliest original signed/GNS validity deadline along that exact proof.
        valid_until_us: u64,
    },
    /// Complete finite fixed point after all actual lookup results, with no proof.
    Denied,
    /// Real clock, source, authentication or resource failure; not a denial proof.
    Failed(Error),
    /// Original caller cancellation, without a synthetic wire cancel/ACK.
    Cancelled,
}

#[derive(Clone, Copy)]
enum Phase {
    Queued,
    Running(u64),
    Cancel(u64),
    Done,
}
#[derive(Clone, Copy)]
enum Target {
    Policy(usize),
    Delegates(usize),
}
struct Lookup<'i> {
    id: LookupId<'i>,
    target: Target,
    phase: Phase,
}
struct Node {
    principal: usize,
    attribute: Vec<u8>,
}
struct Atom {
    principal: usize,
    path: Vec<u8>,
    segments: Vec<(usize, usize)>,
}
impl Atom {
    fn retained(&self) -> Result<usize, Error> {
        sum(&[bytes(&self.path)?, bytes(&self.segments)?])
    }
}
#[derive(Clone, Copy)]
enum Origin {
    Policy,
    Credential(usize),
}
struct Rule {
    head: usize,
    terms: Vec<Atom>,
    expiration: u64,
    origin: Origin,
}
impl Rule {
    fn retained(&self) -> Result<usize, Error> {
        self.terms
            .iter()
            .try_fold(bytes(&self.terms)?, |n, a| sum(&[n, a.retained()?]))
    }
}
struct StoredCredential {
    value: Credential,
    input: bool,
}
struct Fact {
    rule: usize,
    expiration: u64,
    start: usize,
    len: usize,
}
#[derive(Clone, Copy)]
struct Trace {
    parent: usize,
    fact: usize,
}
const NO_TRACE: Trace = Trace {
    parent: NONE,
    fact: NONE,
};

struct Graph<'i> {
    instance: &'i Instance,
    query: u64,
    limits: Limits,
    budget: usize,
    principals: Vec<Principal>,
    nodes: Vec<Node>,
    index: Vec<usize>,
    facts: Vec<Fact>,
    supports: Vec<usize>,
    lookups: Vec<Lookup<'i>>,
    current: Vec<u8>,
    next: Vec<u8>,
    trace: Vec<Trace>,
    scratch: Vec<usize>,
}
impl<'i> Graph<'i> {
    fn retained(&self) -> Result<usize, Error> {
        let n = sum(&[
            bytes(&self.principals)?,
            bytes(&self.nodes)?,
            bytes(&self.index)?,
            bytes(&self.facts)?,
            bytes(&self.supports)?,
            bytes(&self.lookups)?,
            bytes(&self.current)?,
            bytes(&self.next)?,
            bytes(&self.trace)?,
            bytes(&self.scratch)?,
        ])?;
        self.nodes
            .iter()
            .try_fold(n, |n, r| sum(&[n, bytes(&r.attribute)?]))
    }
    fn available(&self) -> Result<usize, Error> {
        self.budget
            .checked_sub(self.retained()?)
            .ok_or(Error::Capacity)
    }
    fn intern(&mut self, p: Principal) -> Result<usize, Error> {
        if let Some(n) = self.principals.iter().position(|v| *v == p) {
            return Ok(n);
        }
        let available = self.available()?;
        let needed = self
            .principals
            .len()
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        reserve(
            &mut self.principals,
            needed,
            self.limits.principals,
            available,
        )?;
        let index = self.principals.len();
        self.principals.push(p);
        Ok(index)
    }
    fn find_node(&self, principal: usize, attr: &[u8]) -> Option<usize> {
        self.nodes
            .iter()
            .position(|n| n.principal == principal && n.attribute == attr)
    }
    fn node(&mut self, principal: usize, attr: &[u8], backward: bool) -> Result<usize, Error> {
        if let Some(n) = self.find_node(principal, attr) {
            return Ok(n);
        }
        if self.nodes.len() >= self.limits.roles {
            return Err(Error::Capacity);
        }
        let name = resource::copy(attr, self.available()?)?;
        let staged = bytes(&name)?;
        let available = self
            .available()?
            .checked_sub(staged)
            .ok_or(Error::Capacity)?;
        let next = self.nodes.len().checked_add(1).ok_or(Error::Overflow)?;
        reserve(&mut self.nodes, next, self.limits.roles, available)?;
        let available = self
            .available()?
            .checked_sub(staged)
            .ok_or(Error::Capacity)?;
        let cells = next
            .checked_mul(self.limits.principals)
            .ok_or(Error::Overflow)?;
        reserve(
            &mut self.index,
            cells,
            self.limits
                .roles
                .checked_mul(self.limits.principals)
                .ok_or(Error::Overflow)?,
            available,
        )?;
        let n = self.nodes.len();
        if backward {
            self.queue(Target::Policy(n), staged)?;
        }
        self.nodes.push(Node {
            principal,
            attribute: name,
        });
        self.index.resize(cells, NONE);
        Ok(n)
    }
    fn queue(&mut self, target: Target, staged: usize) -> Result<(), Error> {
        let available = self
            .available()?
            .checked_sub(staged)
            .ok_or(Error::Capacity)?;
        let n = self.lookups.len().checked_add(1).ok_or(Error::Overflow)?;
        reserve(&mut self.lookups, n, self.limits.lookups, available)?;
        let serial = self.instance.allocate()?;
        self.lookups.push(Lookup {
            id: LookupId {
                instance: self.instance,
                query: self.query,
                serial,
            },
            target,
            phase: Phase::Queued,
        });
        Ok(())
    }
    fn forward(&mut self, principal: usize) -> Result<(), Error> {
        if !self
            .lookups
            .iter()
            .any(|r| matches!(r.target,Target::Delegates(p) if p == principal))
        {
            self.queue(Target::Delegates(principal), 0)?;
        }
        Ok(())
    }
    fn fact(&self, node: usize, member: usize) -> Option<usize> {
        let n = self
            .index
            .get(node * self.limits.principals + member)
            .copied()?;
        if n == NONE { None } else { Some(n) }
    }
    // Set-based relational composition deduplicates each intermediate principal
    // per path component. There is no recursive path/diamond expansion.
    fn atom(
        &mut self,
        atom: &Atom,
        member: usize,
        time: Time,
        backward: bool,
        uncertain: &mut bool,
    ) -> Result<bool, Error> {
        if atom.segments.is_empty() {
            return Ok(atom.principal == member);
        }
        self.current.fill(0);
        self.current[atom.principal] = 1;
        let peers = self.principals.len();
        for (depth, (start, end)) in atom.segments.iter().copied().enumerate() {
            self.next.fill(0);
            self.trace[depth * self.limits.principals..(depth + 1) * self.limits.principals]
                .fill(NO_TRACE);
            for source in 0..peers {
                if self.current[source] == 0 {
                    continue;
                }
                let node = self.node(source, &atom.path[start..end], backward)?;
                for target in 0..peers {
                    if self.next[target] != 0 {
                        continue;
                    }
                    if let Some(id) = self.fact(node, target) {
                        match time.valid_until(self.facts[id].expiration) {
                            Ok(()) => {
                                self.next[target] = 1;
                                self.trace[depth * self.limits.principals + target] = Trace {
                                    parent: source,
                                    fact: id,
                                };
                            }
                            Err(Error::TimeUncertain) => *uncertain = true,
                            Err(Error::Timeout) => {}
                            Err(e) => return Err(e),
                        }
                    }
                }
            }
            core::mem::swap(&mut self.current, &mut self.next);
        }
        if self.current[member] == 0 {
            return Ok(false);
        }
        let mut target = member;
        for depth in (0..atom.segments.len()).rev() {
            let trace = self.trace[depth * self.limits.principals + target];
            if trace.fact == NONE {
                return Err(Error::Conflict);
            }
            if !self.scratch.contains(&trace.fact) {
                if self.scratch.len() == self.scratch.capacity() {
                    return Err(Error::Capacity);
                }
                self.scratch.push(trace.fact);
            }
            target = trace.parent;
        }
        Ok(true)
    }
    fn add_fact(
        &mut self,
        node: usize,
        member: usize,
        rule: usize,
        expiration: u64,
    ) -> Result<usize, Error> {
        let available = self.available()?;
        let next = self.facts.len().checked_add(1).ok_or(Error::Overflow)?;
        reserve(&mut self.facts, next, self.limits.facts, available)?;
        let available = self.available()?;
        let support_end = self
            .supports
            .len()
            .checked_add(self.scratch.len())
            .ok_or(Error::Overflow)?;
        reserve(
            &mut self.supports,
            support_end,
            self.limits.supports,
            available,
        )?;
        let expiration = self
            .scratch
            .iter()
            .fold(expiration, |e, i| e.min(self.facts[*i].expiration));
        let start = self.supports.len();
        self.supports.extend_from_slice(&self.scratch);
        let id = self.facts.len();
        self.facts.push(Fact {
            rule,
            expiration,
            start,
            len: self.scratch.len(),
        });
        self.index[node * self.limits.principals + member] = id;
        Ok(id)
    }
}

/// One original collect/verify resolution. Rows and fact indices never move or
/// get evicted during its life; old native callbacks cannot bind a new lookup.
pub struct Query<'i> {
    graph: Graph<'i>,
    rules: Vec<Rule>,
    credentials: Vec<StoredCredential>,
    selected: Vec<usize>,
    goal: usize,
    subject: usize,
    resolution: u16,
    deadline: u64,
    outcome: Option<Outcome>,
    rule_cursor: usize,
    member_cursor: usize,
    dirty: bool,
    uncertain: bool,
}
impl<'i> Query<'i> {
    /// Admit a query for one exact subject/anchor. The initial attribute is the
    /// literal anchor label, as in the public C API; linked bodies split on dots.
    /// No native lookup, signature, private key or clock is created implicitly.
    #[expect(
        clippy::too_many_arguments,
        reason = "query authority, exact subject/role, direction, resource and original clock bounds are explicit"
    )]
    pub fn new(
        instance: &'i Instance,
        issuer: Principal,
        attribute: &[u8],
        subject: Principal,
        resolution: u16,
        limits: Limits,
        deadline_us: u64,
        time: Time,
    ) -> Result<Self, Error> {
        limits.validate()?;
        time.validate()?;
        if resolution == 0 || resolution & !abd::BOTH != 0 {
            return Err(Error::InvalidInput);
        }
        if time.monotonic_us >= deadline_us {
            return Err(Error::Deadline);
        }
        let mut graph = Graph {
            instance,
            query: instance.allocate()?,
            limits,
            budget: limits.retained_bytes,
            principals: Vec::new(),
            nodes: Vec::new(),
            index: Vec::new(),
            facts: Vec::new(),
            supports: Vec::new(),
            lookups: Vec::new(),
            current: Vec::new(),
            next: Vec::new(),
            trace: Vec::new(),
            scratch: Vec::new(),
        };
        graph.current = resource::filled(limits.principals, 0u8, graph.available()?)?;
        graph.next = resource::filled(limits.principals, 0u8, graph.available()?)?;
        graph.trace = resource::filled(
            limits
                .principals
                .checked_mul(limits.depth)
                .ok_or(Error::Overflow)?,
            NO_TRACE,
            graph.available()?,
        )?;
        let available = graph.available()?;
        let max = limits
            .terms
            .checked_mul(limits.depth)
            .ok_or(Error::Overflow)?;
        reserve(&mut graph.scratch, max, max, available)?;
        let issuer = graph.intern(issuer)?;
        let subject = graph.intern(subject)?;
        let attr = resource::normalize(attribute, limits.name_bytes, graph.available()?)?;
        graph.budget = limits
            .retained_bytes
            .checked_sub(bytes(&attr)?)
            .ok_or(Error::Capacity)?;
        let goal = graph.node(issuer, &attr, resolution & abd::BACKWARD != 0)?;
        graph.budget = limits.retained_bytes;
        Ok(Self {
            graph,
            rules: Vec::new(),
            credentials: Vec::new(),
            selected: Vec::new(),
            goal,
            subject,
            resolution,
            deadline: deadline_us,
            outcome: None,
            rule_cursor: 0,
            member_cursor: 0,
            dirty: true,
            uncertain: false,
        })
    }
    fn outer_bytes(&self) -> Result<usize, Error> {
        let n = sum(&[
            bytes(&self.rules)?,
            bytes(&self.credentials)?,
            bytes(&self.selected)?,
        ])?;
        let n = self
            .rules
            .iter()
            .try_fold(n, |n, r| sum(&[n, r.retained()?]))?;
        self.credentials
            .iter()
            .try_fold(n, |n, c| sum(&[n, c.value.retained_bytes()]))
    }
    /// Actual retained capacities, excluding caller/native source allocations.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        sum(&[self.outer_bytes()?, self.graph.retained()?])
    }
    fn available(&self, staged: usize) -> Result<usize, Error> {
        self.graph
            .limits
            .retained_bytes
            .checked_sub(sum(&[self.retained_bytes()?, staged])?)
            .ok_or(Error::Capacity)
    }
    fn graph_budget(&mut self, staged: usize) -> Result<(), Error> {
        self.graph.budget = self
            .graph
            .limits
            .retained_bytes
            .checked_sub(sum(&[self.outer_bytes()?, staged])?)
            .ok_or(Error::Capacity)?;
        Ok(())
    }
    fn check(&self, time: Time) -> Result<(), Error> {
        time.validate()?;
        if self.outcome.is_some() {
            return Err(Error::Closed);
        }
        if time.monotonic_us >= self.deadline {
            return Err(Error::Deadline);
        }
        Ok(())
    }
    fn atom(
        &mut self,
        subject: Principal,
        path: Option<&[u8]>,
        staged: usize,
    ) -> Result<Atom, Error> {
        self.graph_budget(staged)?;
        let principal = self.graph.intern(subject)?;
        let mut atom = Atom {
            principal,
            path: Vec::new(),
            segments: Vec::new(),
        };
        if let Some(input) = path {
            atom.path =
                resource::normalize(input, self.graph.limits.name_bytes, self.available(staged)?)?;
            let mut start = 0usize;
            for end in 0..=atom.path.len() {
                if end != atom.path.len() && atom.path[end] != b'.' {
                    continue;
                }
                if end == start {
                    return Err(Error::Malformed);
                }
                let available = self.available(sum(&[staged, atom.retained()?])?)?;
                let n = atom.segments.len().checked_add(1).ok_or(Error::Overflow)?;
                reserve(&mut atom.segments, n, self.graph.limits.depth, available)?;
                atom.segments.push((start, end));
                start = end + 1;
            }
        }
        Ok(atom)
    }
    fn add_rule(&mut self, rule: Rule) -> Result<(), Error> {
        let available = self.available(rule.retained()?)?;
        let n = self.rules.len().checked_add(1).ok_or(Error::Overflow)?;
        reserve(&mut self.rules, n, self.graph.limits.rules, available)?;
        self.rules.push(rule);
        self.dirty = true;
        Ok(())
    }
    /// Add an already cryptographically authenticated credential owner. Input
    /// credentials are the only leaves returned by proof_credentials; discovered
    /// signed forward DELs instead appear as original chain edges.
    pub fn add_credential(&mut self, value: Credential, time: Time) -> Result<(), Error> {
        self.credential(value, true, time, u64::MAX)
    }
    fn credential(
        &mut self,
        value: Credential,
        input: bool,
        time: Time,
        gns_expiration: u64,
    ) -> Result<(), Error> {
        self.check(time)?;
        let fields = value.view()?.delegate();
        time.valid_until(fields.expiration_us)?;
        let issuer = Principal::from_key(fields.issuer);
        let subject = Principal::from_key(fields.subject);
        let attr = resource::normalize(
            fields.issuer_attribute,
            self.graph.limits.name_bytes,
            self.available(value.retained_bytes())?,
        )?;
        let staged = sum(&[value.retained_bytes(), bytes(&attr)?])?;
        self.graph_budget(staged)?;
        let issuer = self.graph.intern(issuer)?;
        let head = self
            .graph
            .node(issuer, &attr, self.resolution & abd::BACKWARD != 0)?;
        drop(attr);
        let staged = value.retained_bytes();
        let atom = self.atom(subject, fields.subject_attribute, staged)?;
        let mut terms = Vec::new();
        let available = self.available(sum(&[staged, atom.retained()?])?)?;
        reserve(&mut terms, 1, 1, available)?;
        terms.push(atom);
        let rule_bytes = terms
            .iter()
            .try_fold(bytes(&terms)?, |n, a| sum(&[n, a.retained()?]))?;
        let available = self.available(sum(&[value.retained_bytes(), rule_bytes])?)?;
        let n = self
            .credentials
            .len()
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        reserve(
            &mut self.credentials,
            n,
            self.graph.limits.credentials,
            available,
        )?;
        let available = self.available(sum(&[value.retained_bytes(), rule_bytes])?)?;
        let nr = self.rules.len().checked_add(1).ok_or(Error::Overflow)?;
        reserve(&mut self.rules, nr, self.graph.limits.rules, available)?;
        let expiration = fields.expiration_us.min(gns_expiration);
        let index = self.credentials.len();
        self.credentials.push(StoredCredential { value, input });
        self.rules.push(Rule {
            head,
            terms,
            expiration,
            origin: Origin::Credential(index),
        });
        self.dirty = true;
        Ok(())
    }
    /// Feed one already cryptographically verified DEL from the exact original
    /// forward GNS lookup. This shares the same rule-publication algorithm as
    /// record, without rechecking its expensive signature. The native adapter
    /// can therefore diagnose/skip independent malformed or invalidly signed
    /// DEL records as the official consumer does, while source/resource/clock
    /// failures remain distinct and cannot become an empty successful lookup.
    /// Construction of Credential alone grants no GNS source provenance.
    pub fn verified_delegate(
        &mut self,
        id: LookupId<'_>,
        source: u64,
        value: Credential,
        expiration_us: u64,
        time: Time,
    ) -> Result<(), Error> {
        self.check(time)?;
        let index = self.running(id, source)?;
        if !matches!(self.graph.lookups[index].target, Target::Delegates(_)) {
            return Err(Error::InvalidInput);
        }
        time.valid_until(expiration_us)?;
        self.credential(value, false, time, expiration_us)
    }
    /// Observe the next retained queued lookup or required physical cancellation.
    /// Repeated observations retain the same ID and do not resubmit it.
    #[must_use]
    pub fn effect(&self) -> Option<Effect<'_, 'i>> {
        self.graph.lookups.iter().find_map(|r| {
            let action = match r.phase {
                Phase::Queued => match r.target {
                    Target::Policy(node) => {
                        let n = &self.graph.nodes[node];
                        Action::Lookup {
                            zone: self.graph.principals[n.principal],
                            attribute: &n.attribute,
                            record_type: ATTRIBUTE,
                        }
                    }
                    Target::Delegates(p) => Action::Lookup {
                        zone: self.graph.principals[p],
                        attribute: b"@",
                        record_type: DELEGATE,
                    },
                },
                Phase::Cancel(source) => Action::Cancel { source },
                Phase::Running(_) | Phase::Done => return None,
            };
            Some(Effect { id: r.id, action })
        })
    }
    fn lookup(&self, id: LookupId<'_>) -> Result<usize, Error> {
        self.graph
            .lookups
            .iter()
            .position(|r| r.id == id)
            .ok_or(Error::StaleGeneration)
    }
    /// Bind successful native lookup admission to its exact nonzero source token.
    /// This is not a whole write, remote response or GNS authenticity claim.
    pub fn admit(&mut self, id: LookupId<'_>, source: u64) -> Result<(), Error> {
        if source == 0 {
            return Err(Error::InvalidInput);
        }
        let i = self.lookup(id)?;
        if !matches!(self.graph.lookups[i].phase, Phase::Queued) || self.outcome.is_some() {
            return Err(Error::Conflict);
        }
        self.graph.lookups[i].phase = Phase::Running(source);
        Ok(())
    }
    /// A queued native admission failed before creating an active source.
    pub fn reject(&mut self, id: LookupId<'_>, cause: Error) -> Result<(), Error> {
        let i = self.lookup(id)?;
        if !matches!(self.graph.lookups[i].phase, Phase::Queued) {
            return Err(Error::Conflict);
        }
        self.graph.lookups[i].phase = Phase::Done;
        self.fail(cause);
        Ok(())
    }
    fn running(&self, id: LookupId<'_>, source: u64) -> Result<usize, Error> {
        let i = self.lookup(id)?;
        if !matches!(self.graph.lookups[i].phase,Phase::Running(s) if s==source) {
            return Err(Error::StaleGeneration);
        }
        Ok(i)
    }
    /// Feed a record from the exact admitted original GNS result. A malformed,
    /// expired, invalidly signed or over-budget record fails this original query
    /// and requests cancellation of all remaining admitted sources. Valid rules
    /// are published only after their entire conjunction has been staged.
    pub fn record(
        &mut self,
        id: LookupId<'_>,
        source: u64,
        record: Record<'_>,
        time: Time,
    ) -> Result<(), Error> {
        let result = self.record_inner(id, source, record, time);
        if let Err(e) = result
            && e != Error::StaleGeneration
            && e != Error::Closed
        {
            self.fail(e);
        }
        result
    }
    fn record_inner(
        &mut self,
        id: LookupId<'_>,
        source: u64,
        record: Record<'_>,
        time: Time,
    ) -> Result<(), Error> {
        self.check(time)?;
        let i = self.running(id, source)?;
        match self.graph.lookups[i].target {
            Target::Delegates(_) => {
                if record.record_type != DELEGATE {
                    return Ok(());
                }
                time.valid_until(record.expiration_us)?;
                let value = Credential::verify_record(
                    record.data,
                    time,
                    self.graph.limits.name_bytes,
                    self.available(0)?,
                )?;
                self.credential(value, false, time, record.expiration_us)
            }
            Target::Policy(head) => {
                if record.record_type != ATTRIBUTE {
                    return Ok(());
                }
                time.valid_until(record.expiration_us)?;
                let policy = Policy::decode(record.data, self.graph.limits.record_layout)?;
                if policy.count() == 0 {
                    return Err(Error::Malformed);
                }
                if usize::try_from(policy.count()).map_err(|_| Error::TooLarge)?
                    > self.graph.limits.terms
                {
                    return Err(Error::Capacity);
                }
                let mut terms = Vec::new();
                for term in policy.iter() {
                    let staged = terms
                        .iter()
                        .try_fold(bytes(&terms)?, |n, a: &Atom| sum(&[n, a.retained()?]))?;
                    let atom =
                        self.atom(Principal::from_key(term.subject), term.attribute, staged)?;
                    let available = self.available(sum(&[staged, atom.retained()?])?)?;
                    let n = terms.len().checked_add(1).ok_or(Error::Overflow)?;
                    reserve(&mut terms, n, self.graph.limits.terms, available)?;
                    terms.push(atom);
                }
                self.add_rule(Rule {
                    head,
                    terms,
                    expiration: record.expiration_us,
                    origin: Origin::Policy,
                })
            }
        }
    }
    /// The exact original native source completed and has actually been retired.
    /// Callback completion alone must not be used if its SDK still owns a source.
    pub fn finish_lookup(&mut self, id: LookupId<'_>, source: u64) -> Result<(), Error> {
        let i = self.lookup(id)?;
        if !matches!(self.graph.lookups[i].phase,Phase::Running(s)|Phase::Cancel(s) if s==source) {
            return Err(Error::StaleGeneration);
        }
        self.graph.lookups[i].phase = Phase::Done;
        self.dirty = true;
        Ok(())
    }
    /// An actual admitted source failed after physical retirement. Raw native
    /// errno/source chains must additionally be retained by its caller owner.
    pub fn source_lost(
        &mut self,
        id: LookupId<'_>,
        source: u64,
        cause: Error,
    ) -> Result<(), Error> {
        self.finish_lookup(id, source)?;
        self.fail(cause);
        Ok(())
    }
    fn terminal(&mut self, outcome: Outcome) {
        if self.outcome.is_none() {
            self.outcome = Some(outcome);
        }
        for r in &mut self.graph.lookups {
            r.phase = match r.phase {
                Phase::Queued => Phase::Done,
                Phase::Running(s) => Phase::Cancel(s),
                other => other,
            };
        }
    }
    /// Preserve the first real business failure and retire every original source.
    pub fn fail(&mut self, cause: Error) {
        self.terminal(Outcome::Failed(cause));
    }
    /// Cancel without sampling a replacement clock or creating wire messages.
    pub fn cancel(&mut self) {
        self.terminal(Outcome::Cancelled);
    }
    fn proof(&mut self, goal: usize) -> Result<(), Error> {
        let mut pending = Vec::new();
        let mut visited = Vec::new();
        let mut selected = Vec::new();
        let available = self.available(0)?;
        reserve(&mut pending, 1, self.graph.limits.facts, available)?;
        pending.push(goal);
        while let Some(id) = pending.pop() {
            if visited.contains(&id) {
                continue;
            }
            let staged = sum(&[bytes(&pending)?, bytes(&visited)?, bytes(&selected)?])?;
            let available = self.available(staged)?;
            let next = visited.len().checked_add(1).ok_or(Error::Overflow)?;
            reserve(&mut visited, next, self.graph.limits.facts, available)?;
            visited.push(id);
            let fact = &self.graph.facts[id];
            let rule = fact.rule;
            let start = fact.start;
            let len = fact.len;
            if !selected.contains(&rule) {
                let staged = sum(&[bytes(&pending)?, bytes(&visited)?, bytes(&selected)?])?;
                let available = self.available(staged)?;
                let n = selected.len().checked_add(1).ok_or(Error::Overflow)?;
                reserve(&mut selected, n, self.graph.limits.rules, available)?;
                selected.push(rule);
            }
            for offset in start..start + len {
                let support = self.graph.supports[offset];
                // Every witness was derived before this fact. Reject corruption
                // instead of permitting a recursive/self-supporting proof.
                if support >= id {
                    return Err(Error::Conflict);
                }
                if !visited.contains(&support) && !pending.contains(&support) {
                    let staged = sum(&[bytes(&pending)?, bytes(&visited)?, bytes(&selected)?])?;
                    let available = self.available(staged)?;
                    let n = pending.len().checked_add(1).ok_or(Error::Overflow)?;
                    reserve(&mut pending, n, self.graph.limits.facts, available)?;
                    pending.push(support);
                }
            }
        }
        self.selected = selected;
        Ok(())
    }
    /// Perform at most work rule/subject evaluations. Linked evaluation is
    /// polynomial and independently bounded by depth/principals/roles. No crypto
    /// job, I/O, hidden task or unbounded recursion runs inside this advancement.
    pub fn advance(&mut self, time: Time, work: usize) -> Result<bool, Error> {
        if self.outcome.is_some() {
            return Ok(false);
        }
        if let Err(e) = self.check(time) {
            self.fail(e);
            return Err(e);
        }
        let result = self.advance_inner(time, work);
        if let Err(e) = result {
            self.fail(e);
        }
        result
    }
    fn advance_inner(&mut self, time: Time, work: usize) -> Result<bool, Error> {
        let mut progressed = false;
        for _ in 0..work {
            if let Some(goal) = self.graph.fact(self.goal, self.subject) {
                match time.valid_until(self.graph.facts[goal].expiration) {
                    Ok(()) => {
                        self.proof(goal)?;
                        self.terminal(Outcome::Authorized {
                            valid_until_us: self.graph.facts[goal].expiration,
                        });
                        return Ok(true);
                    }
                    Err(Error::TimeUncertain) => self.uncertain = true,
                    Err(Error::Timeout) => {}
                    Err(e) => return Err(e),
                }
            }
            if self.rule_cursor >= self.rules.len() {
                if self.dirty {
                    self.dirty = false;
                    self.rule_cursor = 0;
                    self.member_cursor = 0;
                    if !self.rules.is_empty() {
                        continue;
                    }
                }
                if self
                    .graph
                    .lookups
                    .iter()
                    .all(|r| matches!(r.phase, Phase::Done))
                {
                    self.terminal(if self.uncertain {
                        Outcome::Failed(Error::TimeUncertain)
                    } else {
                        Outcome::Denied
                    });
                    return Ok(true);
                }
                return Ok(progressed);
            }
            let r = self.rule_cursor;
            let member = self.member_cursor;
            self.member_cursor += 1;
            if self.member_cursor >= self.graph.principals.len() {
                self.member_cursor = 0;
                self.rule_cursor += 1;
            }
            progressed = true;
            let head = self.rules[r].head;
            if let Some(existing) = self.graph.fact(head, member) {
                match time.valid_until(self.graph.facts[existing].expiration) {
                    Ok(()) => continue,
                    Err(Error::TimeUncertain) => self.uncertain = true,
                    Err(Error::Timeout) => {}
                    Err(e) => return Err(e),
                }
            }
            match time.valid_until(self.rules[r].expiration) {
                Ok(()) => {}
                Err(Error::TimeUncertain) => {
                    self.uncertain = true;
                    continue;
                }
                Err(Error::Timeout) => continue,
                Err(e) => return Err(e),
            }
            self.graph_budget(0)?;
            self.graph.scratch.clear();
            let lookups = self.graph.lookups.len();
            let nodes = self.graph.nodes.len();
            let mut matches = true;
            for atom in &self.rules[r].terms {
                if !self.graph.atom(
                    atom,
                    member,
                    time,
                    self.resolution & abd::BACKWARD != 0,
                    &mut self.uncertain,
                )? {
                    matches = false;
                    break;
                }
            }
            if self.graph.lookups.len() != lookups || self.graph.nodes.len() != nodes {
                self.dirty = true;
            }
            if !matches {
                continue;
            }
            self.graph
                .add_fact(head, member, r, self.rules[r].expiration)?;
            self.dirty = true;
            if self.resolution & abd::FORWARD != 0 {
                let principal = self.graph.nodes[head].principal;
                self.graph.forward(principal)?;
            }
        }
        Ok(progressed)
    }
    /// Recheck the selected proof's actual expiry before admitting any terminal
    /// response; callers must not cache an earlier Authorized across clock change.
    pub fn outcome(&self, time: Time) -> Result<Option<Outcome>, Error> {
        time.validate()?;
        if let Some(Outcome::Authorized { valid_until_us }) = self.outcome {
            time.valid_until(valid_until_us)?;
        }
        Ok(self.outcome)
    }
    /// True only after a terminal and actual retirement of every admitted source.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.outcome.is_some()
            && self
                .graph
                .lookups
                .iter()
                .all(|r| matches!(r.phase, Phase::Done))
    }
    /// Number of actual native source debts still requiring original retirement.
    #[must_use]
    pub fn pending_sources(&self) -> usize {
        self.graph
            .lookups
            .iter()
            .filter(|r| matches!(r.phase, Phase::Running(_) | Phase::Cancel(_)))
            .count()
    }
    /// Borrow only used input leaf credentials, in stable original proof order.
    pub fn proof_credentials(&self) -> impl Iterator<Item = &Credential> {
        self.selected
            .iter()
            .filter_map(|i| match self.rules[*i].origin {
                Origin::Credential(c) if self.credentials[c].input => {
                    Some(&self.credentials[c].value)
                }
                _ => None,
            })
    }
    /// Iterate actual used GNS policy/signed-delegate edges. Input leaf delegates
    /// are separate and no synthetic credential is invented for a direct GNS proof.
    #[must_use]
    pub fn proof_edges(&self) -> Edges<'_, 'i> {
        Edges {
            query: self,
            selected: 0,
            term: 0,
        }
    }
}

/// Borrowed no-allocation traversal of used chain edges from the concrete proof.
pub struct Edges<'q, 'i> {
    query: &'q Query<'i>,
    selected: usize,
    term: usize,
}
impl<'q> Iterator for Edges<'q, '_> {
    type Item = Result<Chain<'q>, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let rule = self
                .query
                .rules
                .get(*self.query.selected.get(self.selected)?)?;
            match rule.origin {
                Origin::Credential(c) => {
                    self.selected += 1;
                    self.term = 0;
                    if self.query.credentials[c].input {
                        continue;
                    }
                    return Some(self.query.credentials[c].value.view().map(|d| {
                        let d = d.delegate();
                        Chain {
                            issuer: d.issuer,
                            subject: d.subject,
                            issuer_attribute: d.issuer_attribute,
                            subject_attribute: d.subject_attribute,
                        }
                    }));
                }
                Origin::Policy => {
                    let Some(atom) = rule.terms.get(self.term) else {
                        self.selected += 1;
                        self.term = 0;
                        continue;
                    };
                    self.term += 1;
                    let node = &self.query.graph.nodes[rule.head];
                    return Some((|| {
                        Ok(Chain {
                            issuer: self.query.graph.principals[node.principal].view()?,
                            subject: self.query.graph.principals[atom.principal].view()?,
                            issuer_attribute: &node.attribute,
                            subject_attribute: if atom.path.is_empty() {
                                None
                            } else {
                                Some(&atom.path)
                            },
                        })
                    })());
                }
            }
        }
    }
}
