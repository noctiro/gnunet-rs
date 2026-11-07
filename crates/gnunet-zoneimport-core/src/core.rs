use crate::types::Brand;
use crate::{
    Action, ActionKind, AnswerId, Bounds, Completion, Creation, Error, JobId, Kind, Limits,
    Metrics, MonoInstant, Mutation, NameFailures, NameId, Outcome, Policy, ReadEnd, ReadFailure,
    Retirement, State, Times, Wakeup, ZoneId, conversion::Summary,
};
use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use gnunet_gnsrecord::{RecordData, RecordFlags, ZoneKey};
use gnunet_wire::official::AbsoluteTime;

#[derive(Clone, Copy)]
enum ZonePhase {
    Ready,
    Create,
    Creating(u64),
    Check,
    Checking(u64),
    Delegate(Bounds),
    Delegating(u64),
    Failed,
    Unknown,
}
#[derive(Clone, Copy)]
enum Cache {
    Unused,
    Running(u64),
    Done(ReadEnd),
}
struct Zone {
    name: Arc<str>,
    parent: Option<usize>,
    key: Option<ZoneKey>,
    phase: ZonePhase,
    cache: Cache,
    used: bool,
    anchor: bool,
    created: bool,
    observed: bool,
    stored: bool,
    // Only a real terminal CREATE/parent-STORE rejection, never local cancel.
    service_rejected: bool,
}
#[derive(Clone, Copy)]
enum When {
    Absolute(AbsoluteTime),
    Mono(MonoInstant),
}
#[derive(Clone, Copy)]
enum Phase {
    Preparing,
    Waiting(When),
    Query(u64),
    Store {
        job: u64,
        answer: u64,
        refresh: AbsoluteTime,
        count: usize,
    },
    Failed,
    Unknown,
}
struct Name {
    name: Arc<str>,
    split: usize,
    zone: Option<usize>,
    phase: Phase,
    attempts: u32,
    cached: Option<AbsoluteTime>,
    cache_nonempty: bool,
    // Latched once before stop can turn healthy pending work into Failed.
    failed_before_stop: bool,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum JobState {
    Ready,
    Deferred,
    Active,
    Retire,
    RetireDeferred,
    Retiring,
}
#[derive(Clone, Copy)]
enum Work {
    Create(usize),
    Check(usize),
    Delegate(usize),
    Scan(usize),
    Query(usize),
    Store(usize),
}
impl Work {
    fn kind(self) -> Kind {
        match self {
            Self::Create(_) => Kind::CreateZone,
            Self::Check(_) => Kind::CheckDelegation,
            Self::Delegate(_) => Kind::Delegate,
            Self::Scan(_) => Kind::ScanCache,
            Self::Query(_) => Kind::Query,
            Self::Store(_) => Kind::Store,
        }
    }
}
#[derive(Clone, Copy)]
struct Job {
    serial: u64,
    work: Work,
    bounds: Bounds,
    state: JobState,
    admitted: bool,
}

/// Actual state of the original startup cache attempt, separate from its data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheState {
    /// No iterator has been admitted or prepared for this zone.
    Unused,
    /// The original attempt is prepared, active or still retiring.
    Pending,
    /// The original iterator returned its actual complete END.
    Complete,
    /// The original attempt settled without END. Already observed sets remain
    /// usable; unobserved names query DNS under the explicit degraded policy.
    Incomplete,
}
/// Public observations for one control zone. A key alone proves no parent link.
#[derive(Clone, Copy, Debug)]
pub struct ZoneFacts {
    /// Actual inventory/CREATE public key has been supplied by the host.
    pub has_key: bool,
    /// Actual CREATE succeeded in this instance.
    pub created: bool,
    /// This existing inventory zone is a nearest independent namespace anchor.
    pub anchor: bool,
    /// Actual current parent-label lookup contained this public delegation.
    pub parent_observed: bool,
    /// Actual original parent STORE returned code0 in this instance.
    pub parent_stored: bool,
    /// Original cache-attempt completeness; failure is never promoted to END.
    pub cache: CacheState,
}
/// Bounded business owner. Hosts retain native jobs, secret keys and answer bytes.
/// Every callback below must refer to the original actually settled port job;
/// these methods cannot themselves prove a network, storage or crypto result.
pub struct Core {
    brand: Arc<Brand>,
    limits: Limits,
    policy: Policy,
    names: Vec<Name>,
    zones: Vec<Zone>,
    names_by_name: BTreeMap<Arc<str>, usize>,
    zones_by_name: BTreeMap<Arc<str>, usize>,
    jobs: Vec<Option<Job>>,
    bytes: usize,
    serial: u64,
    inventory: bool,
    input: bool,
    bootstrapped: bool,
    stopping: bool,
    last: Option<Times>,
    next_dispatch: MonoInstant,
    cursor: usize,
    metrics: Metrics,
}
impl Core {
    /// Reserve small initial name/zone pools and the fixed bounded job pool.
    /// Name/zone rows grow fallibly within their configured hard limits.
    /// No source, key, query or worker is created.
    pub fn new(limits: Limits, policy: Policy) -> Result<Self, Error> {
        limits.validate()?;
        policy.validate()?;
        let mut names = Vec::new();
        names
            .try_reserve_exact(limits.names.min(1024))
            .map_err(|_| Error::Capacity)?;
        let mut zones = Vec::new();
        zones
            .try_reserve_exact(limits.zones.min(64))
            .map_err(|_| Error::Capacity)?;
        let mut jobs = Vec::new();
        jobs.try_reserve_exact(limits.jobs)
            .map_err(|_| Error::Capacity)?;
        jobs.resize_with(limits.jobs, || None);
        Ok(Self {
            brand: Arc::new(Brand),
            limits,
            policy,
            names,
            zones,
            names_by_name: BTreeMap::new(),
            zones_by_name: BTreeMap::new(),
            jobs,
            bytes: 0,
            serial: 0,
            inventory: false,
            input: false,
            bootstrapped: false,
            stopping: false,
            last: None,
            next_dispatch: MonoInstant::from_micros(0),
            cursor: 0,
            metrics: Metrics::default(),
        })
    }
    fn name_id(&self, index: usize) -> NameId {
        NameId {
            brand: self.brand.clone(),
            serial: index as u64 + 1,
        }
    }
    fn zone_id(&self, index: usize) -> ZoneId {
        ZoneId {
            brand: self.brand.clone(),
            serial: index as u64 + 1,
        }
    }
    fn job_id(&self, serial: u64) -> JobId {
        JobId {
            brand: self.brand.clone(),
            serial,
        }
    }
    fn answer_id(&self, serial: u64) -> AnswerId {
        AnswerId {
            brand: self.brand.clone(),
            serial,
        }
    }
    fn name_index(&self, id: &NameId) -> Result<usize, Error> {
        if !Arc::ptr_eq(&self.brand, &id.brand) {
            return Err(Error::StaleGeneration);
        }
        usize::try_from(id.serial)
            .ok()
            .and_then(|n| n.checked_sub(1))
            .filter(|n| *n < self.names.len())
            .ok_or(Error::StaleGeneration)
    }
    fn zone_index(&self, id: &ZoneId) -> Result<usize, Error> {
        if !Arc::ptr_eq(&self.brand, &id.brand) {
            return Err(Error::StaleGeneration);
        }
        usize::try_from(id.serial)
            .ok()
            .and_then(|n| n.checked_sub(1))
            .filter(|n| *n < self.zones.len())
            .ok_or(Error::StaleGeneration)
    }
    fn job_index(&self, id: &JobId) -> Result<usize, Error> {
        if !Arc::ptr_eq(&self.brand, &id.brand) {
            return Err(Error::StaleGeneration);
        }
        self.jobs
            .iter()
            .position(|job| job.is_some_and(|job| job.serial == id.serial))
            .ok_or(Error::StaleGeneration)
    }
    fn now(&self) -> Result<Times, Error> {
        self.last.ok_or(Error::NotReady)
    }
    fn sample(&mut self, now: Times) -> Result<(), Error> {
        if self.last.is_some_and(|last| now.mono < last.mono)
            || now.absolute.as_micros() == u64::MAX
        {
            self.stop();
            return Err(Error::InvalidInput);
        }
        self.last = Some(now);
        Ok(())
    }
    fn copy_name(&self, value: &str) -> Result<Arc<str>, Error> {
        let end = self.bytes.checked_add(value.len()).ok_or(Error::Overflow)?;
        if end > self.limits.name_bytes {
            return Err(Error::Capacity);
        }
        let mut copy = String::new();
        copy.try_reserve_exact(value.len())
            .map_err(|_| Error::Capacity)?;
        copy.push_str(value);
        // Arc and BTreeMap use alloc's global OOM boundary. All recoverable
        // quota/reservation failures precede row/index/byte-count commits.
        Ok(Arc::from(copy))
    }
    fn reserve_row<T>(rows: &mut Vec<T>, limit: usize) -> Result<(), Error> {
        if rows.len() >= limit {
            return Err(Error::Capacity);
        }
        if rows.len() == rows.capacity() {
            let target = rows.capacity().saturating_mul(2).max(1).min(limit);
            rows.try_reserve_exact(target - rows.len())
                .map_err(|_| Error::Capacity)?;
        }
        Ok(())
    }
    fn canonical(input: &str) -> Result<String, Error> {
        let input = input.strip_suffix('.').unwrap_or(input);
        if input.is_empty()
            || input.len() > 253
            || !input.is_ascii()
            || input
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
            || input
                .split('.')
                .any(|label| label.is_empty() || label.len() > 63)
        {
            return Err(Error::InvalidInput);
        }
        let mut value = String::new();
        value
            .try_reserve_exact(input.len())
            .map_err(|_| Error::Capacity)?;
        for c in input.bytes() {
            value.push(char::from(c.to_ascii_lowercase()));
        }
        Ok(value)
    }
    /// Record an actual initial EGO inventory item. Duplicate conflicting keys fail.
    /// The host retains the corresponding original secret-key ownership separately.
    pub fn seed_zone(&mut self, name: &str, key: ZoneKey) -> Result<ZoneId, Error> {
        if self.inventory || self.stopping {
            return Err(Error::Closed);
        }
        let name = Self::canonical(name)?;
        if let Some(index) = self.zones_by_name.get(name.as_str()).copied() {
            return if self.zones[index].key == Some(key) {
                Ok(self.zone_id(index))
            } else {
                Err(Error::Conflict)
            };
        }
        Self::reserve_row(&mut self.zones, self.limits.zones)?;
        let name = self.copy_name(&name)?;
        let index = self.zones.len();
        let _previous = self.zones_by_name.insert(name.clone(), index);
        self.bytes += name.len();
        self.zones.push(Zone {
            name,
            parent: None,
            key: Some(key),
            phase: ZonePhase::Ready,
            cache: Cache::Unused,
            used: false,
            anchor: false,
            created: false,
            observed: false,
            stored: false,
            service_rejected: false,
        });
        self.metrics.zones = self.zones.len() as u64;
        Ok(self.zone_id(index))
    }
    /// Only the actual initial inventory END permits this transition.
    pub fn finish_inventory(&mut self, now: Times) -> Result<(), Error> {
        self.sample(now)?;
        if self.inventory || self.stopping {
            return Err(Error::Conflict);
        }
        self.inventory = true;
        Ok(())
    }
    /// Add one IDNA-validated ASCII FQDN, deduplicated by DNS ASCII case.
    /// The first label is stored under its suffix control zone, as in the public tool.
    pub fn add_name(&mut self, name: &str, now: Times) -> Result<NameId, Error> {
        self.sample(now)?;
        if self.input || self.stopping {
            return Err(Error::Closed);
        }
        let name = Self::canonical(name)?;
        let split = name.find('.').ok_or(Error::InvalidInput)?;
        if let Some(index) = self.names_by_name.get(name.as_str()).copied() {
            return Ok(self.name_id(index));
        }
        Self::reserve_row(&mut self.names, self.limits.names)?;
        let name = self.copy_name(&name)?;
        let index = self.names.len();
        let _previous = self.names_by_name.insert(name.clone(), index);
        self.bytes += name.len();
        self.names.push(Name {
            name,
            split,
            zone: None,
            phase: Phase::Preparing,
            attempts: 0,
            cached: None,
            cache_nonempty: false,
            failed_before_stop: false,
        });
        self.metrics.names = self.names.len() as u64;
        Ok(self.name_id(index))
    }
    fn ensure_zone(&mut self, name: &str) -> Result<Option<usize>, Error> {
        let mut suffixes = Vec::new();
        suffixes
            .try_reserve_exact(128)
            .map_err(|_| Error::Capacity)?;
        let mut tail = name;
        loop {
            suffixes.push(tail);
            let Some(at) = tail.find('.') else {
                break;
            };
            tail = &tail[at + 1..];
        }
        let Some((anchor_at, mut parent)) = suffixes.iter().enumerate().find_map(|(at, suffix)| {
            self.zones_by_name
                .get(*suffix)
                .copied()
                .filter(|index| self.zones[*index].key.is_some())
                .map(|index| (at, index))
        }) else {
            return Ok(None);
        };
        self.zones[parent].anchor = true;
        for suffix in suffixes[..anchor_at].iter().rev() {
            if let Some(index) = self.zones_by_name.get(*suffix).copied() {
                if self.zones[index].parent.is_none() {
                    self.zones[index].parent = Some(parent);
                    self.zones[index].anchor = false;
                    self.zones[index].phase = if self.zones[index].key.is_some() {
                        ZonePhase::Check
                    } else {
                        ZonePhase::Create
                    };
                } else if self.zones[index].parent != Some(parent) {
                    return Err(Error::Conflict);
                }
                parent = index;
            } else {
                Self::reserve_row(&mut self.zones, self.limits.zones)?;
                let name = self.copy_name(suffix)?;
                let index = self.zones.len();
                let _previous = self.zones_by_name.insert(name.clone(), index);
                self.bytes += name.len();
                self.zones.push(Zone {
                    name,
                    parent: Some(parent),
                    key: None,
                    phase: ZonePhase::Create,
                    cache: Cache::Unused,
                    used: false,
                    anchor: false,
                    created: false,
                    observed: false,
                    stored: false,
                    service_rejected: false,
                });
                parent = index;
            }
        }
        self.metrics.zones = self.zones.len() as u64;
        Ok(Some(parent))
    }
    /// Seal actual stdin EOF after initial inventory. An unanchored missing suffix
    /// is failed, never given a fabricated root key or an orphan CREATE action.
    pub fn finish_input(&mut self, now: Times) -> Result<(), Error> {
        self.sample(now)?;
        if !self.inventory {
            return Err(Error::NotReady);
        }
        if self.input || self.stopping {
            return Err(Error::Closed);
        }
        for index in 0..self.names.len() {
            let name = self.names[index].name.clone();
            let split = self.names[index].split;
            if let Some(zone) = self.ensure_zone(&name[split + 1..])? {
                self.names[index].zone = Some(zone);
                self.zones[zone].used = true;
            } else {
                self.names[index].phase = Phase::Failed;
            }
        }
        self.input = true;
        Ok(())
    }
    fn spawn(&mut self, work: Work, bounds: Bounds) -> Result<Option<u64>, Error> {
        let Some(index) = self.jobs.iter().position(Option::is_none) else {
            return Ok(None);
        };
        let serial = self.serial.checked_add(1).ok_or(Error::Overflow)?;
        self.serial = serial;
        let state = if self.stopping || self.last.is_some_and(|now| bounds.expired(now)) {
            JobState::Retire
        } else {
            JobState::Ready
        };
        self.jobs[index] = Some(Job {
            serial,
            work,
            bounds,
            state,
            admitted: false,
        });
        Ok(Some(serial))
    }
    fn free_job(&self) -> bool {
        self.jobs.iter().any(Option::is_none)
    }
    fn preparation(&mut self, now: Times) -> Result<(), Error> {
        if !self.inventory || !self.input || self.stopping {
            return Ok(());
        }
        for index in 0..self.zones.len() {
            if !self.free_job() {
                break;
            }
            let parent = self.zones[index].parent;
            let ready =
                parent.is_none_or(|parent| matches!(self.zones[parent].phase, ZonePhase::Ready));
            if !ready {
                if parent.is_some_and(|parent| {
                    matches!(
                        self.zones[parent].phase,
                        ZonePhase::Failed | ZonePhase::Unknown
                    )
                }) {
                    self.zones[index].phase = if parent.is_some_and(|parent| {
                        matches!(self.zones[parent].phase, ZonePhase::Unknown)
                    }) {
                        ZonePhase::Unknown
                    } else {
                        ZonePhase::Failed
                    };
                }
                continue;
            }
            match self.zones[index].phase {
                ZonePhase::Create => {
                    if let Some(job) = self.spawn(
                        Work::Create(index),
                        Bounds::new(now, self.policy.operation)?,
                    )? {
                        self.zones[index].phase = ZonePhase::Creating(job);
                    }
                }
                ZonePhase::Check => {
                    if let Some(job) =
                        self.spawn(Work::Check(index), Bounds::new(now, self.policy.operation)?)?
                    {
                        self.zones[index].phase = ZonePhase::Checking(job);
                    }
                }
                ZonePhase::Delegate(bounds) => {
                    if let Some(job) = self.spawn(Work::Delegate(index), bounds)? {
                        self.zones[index].phase = ZonePhase::Delegating(job);
                    }
                }
                _ => {}
            }
        }
        if self.zones.iter().any(|zone| {
            matches!(
                zone.phase,
                ZonePhase::Create
                    | ZonePhase::Creating(_)
                    | ZonePhase::Check
                    | ZonePhase::Checking(_)
                    | ZonePhase::Delegate(_)
                    | ZonePhase::Delegating(_)
            )
        }) {
            return Ok(());
        }
        for index in 0..self.zones.len() {
            if !self.free_job() {
                break;
            }
            if self.zones[index].used
                && matches!(self.zones[index].phase, ZonePhase::Ready)
                && matches!(self.zones[index].cache, Cache::Unused)
                && let Some(job) =
                    self.spawn(Work::Scan(index), Bounds::new(now, self.policy.operation)?)?
            {
                self.zones[index].cache = Cache::Running(job);
            }
        }
        if self.zones.iter().any(|zone| {
            zone.used
                && matches!(zone.phase, ZonePhase::Ready)
                && !matches!(zone.cache, Cache::Done(_))
        }) {
            return Ok(());
        }
        if !self.bootstrapped {
            self.bootstrapped = true;
            for name in &mut self.names {
                if !matches!(name.phase, Phase::Preparing) {
                    continue;
                }
                name.phase = match name.zone.map(|index| self.zones[index].phase) {
                    Some(ZonePhase::Ready) => Phase::Waiting(When::Absolute(
                        name.cached.unwrap_or(AbsoluteTime::from_micros(0)),
                    )),
                    Some(ZonePhase::Unknown) => Phase::Unknown,
                    _ => Phase::Failed,
                };
                if name.cache_nonempty {
                    self.metrics.cache_hits = self.metrics.cache_hits.saturating_add(1);
                }
            }
        }
        Ok(())
    }
    /// Advance only original timers. Expiry requests retirement; it never settles a port.
    pub fn tick(&mut self, now: Times) -> Result<(), Error> {
        self.sample(now)?;
        for row in self.jobs.iter_mut().flatten() {
            if matches!(
                row.state,
                JobState::Ready | JobState::Deferred | JobState::Active
            ) && row.bounds.expired(now)
            {
                row.state = JobState::Retire;
            }
        }
        Ok(())
    }
    fn action(&self, job: Job) -> Result<Action<'_>, Error> {
        let kind = if job.state == JobState::Retire {
            ActionKind::Retire {
                kind: job.work.kind(),
                admitted: job.admitted,
            }
        } else {
            match job.work {
                Work::Create(index) => ActionKind::CreateZone {
                    zone: self.zone_id(index),
                    name: &self.zones[index].name,
                },
                Work::Check(index) => {
                    let child = &self.zones[index];
                    let parent = child.parent.ok_or(Error::Conflict)?;
                    let split = child.name.find('.').ok_or(Error::Conflict)?;
                    ActionKind::CheckDelegation {
                        parent: self.zone_id(parent),
                        child: self.zone_id(index),
                        label: &child.name[..split],
                    }
                }
                Work::Delegate(index) => {
                    let child = &self.zones[index];
                    let parent = child.parent.ok_or(Error::Conflict)?;
                    let split = child.name.find('.').ok_or(Error::Conflict)?;
                    let key = child.key.as_ref().ok_or(Error::NotReady)?;
                    ActionKind::Delegate {
                        parent: self.zone_id(parent),
                        child: self.zone_id(index),
                        label: &child.name[..split],
                        record: RecordData {
                            expiration_time: self.policy.delegation_expiration.as_micros(),
                            record_type: key.kind().record_type(),
                            flags: RecordFlags::RELATIVE_EXPIRATION,
                            data: key.key(),
                        },
                    }
                }
                Work::Scan(index) => ActionKind::ScanCache {
                    zone: self.zone_id(index),
                },
                Work::Query(index) => ActionKind::Query {
                    name: self.name_id(index),
                    hostname: &self.names[index].name,
                },
                Work::Store(index) => {
                    let name = &self.names[index];
                    let Phase::Store { answer, .. } = name.phase else {
                        return Err(Error::Conflict);
                    };
                    ActionKind::Store {
                        name: self.name_id(index),
                        answer: self.answer_id(answer),
                        zone: self.zone_id(name.zone.ok_or(Error::NotReady)?),
                        label: &name.name[..name.split],
                    }
                }
            }
        };
        Ok(Action {
            job: self.job_id(job.serial),
            bounds: job.bounds,
            kind,
        })
    }
    fn choose_retirement(&mut self) -> Option<Job> {
        for offset in 0..self.jobs.len() {
            let index = (self.cursor + offset) % self.jobs.len();
            if let Some(job) = self.jobs[index]
                && job.state == JobState::Retire
            {
                self.cursor = (index + 1) % self.jobs.len();
                return Some(job);
            }
        }
        None
    }
    /// Clock-free cleanup work after stop or a clock-port failure.
    pub fn next_retirement(&mut self) -> Result<Option<Action<'_>>, Error> {
        self.choose_retirement()
            .map(|job| self.action(job))
            .transpose()
    }
    /// Pull bounded original work. The host must retain/copy the payload before
    /// awaiting, and call admitted only after its real native admission succeeds.
    pub fn next_action(&mut self, now: Times) -> Result<Option<Action<'_>>, Error> {
        self.tick(now)?;
        if let Some(job) = self.choose_retirement() {
            return Ok(Some(self.action(job)?));
        }
        self.preparation(now)?;
        if self.bootstrapped && !self.stopping {
            for index in 0..self.names.len() {
                if !self.free_job() {
                    break;
                }
                let due = match self.names[index].phase {
                    Phase::Waiting(When::Absolute(at)) => {
                        at.as_micros() <= now.absolute.as_micros()
                    }
                    Phase::Waiting(When::Mono(at)) => at <= now.mono,
                    _ => false,
                };
                if due {
                    if self.names[index].attempts >= self.policy.max_attempts {
                        self.names[index].phase = Phase::Failed;
                        continue;
                    }
                    if let Some(job) =
                        self.spawn(Work::Query(index), Bounds::new(now, self.policy.operation)?)?
                    {
                        self.names[index].attempts += 1;
                        self.names[index].phase = Phase::Query(job);
                    }
                }
            }
        }
        if let Some(job) = self.choose_retirement() {
            return Ok(Some(self.action(job)?));
        }
        for offset in 0..self.jobs.len() {
            let index = (self.cursor + offset) % self.jobs.len();
            if let Some(job) = self.jobs[index]
                && job.state == JobState::Ready
                && (!matches!(job.work, Work::Query(_)) || now.mono >= self.next_dispatch)
            {
                self.cursor = (index + 1) % self.jobs.len();
                return Ok(Some(self.action(job)?));
            }
        }
        Ok(None)
    }
    /// Register a real native admission without requiring a new clock sample.
    /// Even admission crossing a stop/budget check remains tracked for retirement.
    pub fn admitted(&mut self, id: &JobId) -> Result<(), Error> {
        let index = self.job_index(id)?;
        let now = self.now()?;
        let row = self.jobs[index].as_mut().ok_or(Error::StaleGeneration)?;
        if row.admitted {
            return Err(Error::Conflict);
        }
        row.admitted = true;
        if matches!(row.state, JobState::Ready | JobState::Deferred) {
            row.state = JobState::Active;
        } else {
            row.state = JobState::Retire;
        }
        if matches!(row.work, Work::Query(_)) {
            self.metrics.dns_admitted = self.metrics.dns_admitted.saturating_add(1);
            self.next_dispatch = MonoInstant::from_micros(
                now.mono
                    .as_micros()
                    .checked_add(self.policy.dispatch_interval.as_micros())
                    .ok_or(Error::Overflow)?,
            );
        }
        Ok(())
    }
    /// Suppress repeated capacity-blocked peeks without changing any original bound.
    pub fn defer(&mut self, id: &JobId) -> Result<(), Error> {
        let index = self.job_index(id)?;
        let row = self.jobs[index].as_mut().ok_or(Error::StaleGeneration)?;
        row.state = match row.state {
            JobState::Ready => JobState::Deferred,
            JobState::Retire => JobState::RetireDeferred,
            _ => return Err(Error::Conflict),
        };
        Ok(())
    }
    /// Re-enable one original deferred action after actual host capacity progress.
    pub fn resume(&mut self, id: &JobId) -> Result<(), Error> {
        let index = self.job_index(id)?;
        let row = self.jobs[index].as_mut().ok_or(Error::StaleGeneration)?;
        row.state = match row.state {
            JobState::Deferred => JobState::Ready,
            JobState::RetireDeferred => JobState::Retire,
            _ => return Err(Error::Conflict),
        };
        Ok(())
    }
    /// Record that the actual original native cancellation/drain has begun.
    pub fn retirement_started(&mut self, id: &JobId) -> Result<(), Error> {
        let index = self.job_index(id)?;
        let row = self.jobs[index].as_mut().ok_or(Error::StaleGeneration)?;
        if !matches!(row.state, JobState::Retire | JobState::RetireDeferred) {
            return Err(Error::Conflict);
        }
        row.state = JobState::Retiring;
        Ok(())
    }
    fn result_job(&mut self, id: &JobId, kind: Kind) -> Result<Job, Error> {
        let index = self.job_index(id)?;
        let row = self.jobs[index].ok_or(Error::StaleGeneration)?;
        if !row.admitted || row.work.kind() != kind {
            return Err(Error::Conflict);
        }
        let coherent = match row.work {
            Work::Create(index) => {
                matches!(self.zones[index].phase, ZonePhase::Creating(serial) if serial == row.serial)
            }
            Work::Check(index) => {
                matches!(self.zones[index].phase, ZonePhase::Checking(serial) if serial == row.serial)
            }
            Work::Delegate(index) => {
                matches!(self.zones[index].phase, ZonePhase::Delegating(serial) if serial == row.serial)
            }
            Work::Scan(index) => {
                matches!(self.zones[index].cache, Cache::Running(serial) if serial == row.serial)
            }
            Work::Query(index) => {
                matches!(self.names[index].phase, Phase::Query(serial) if serial == row.serial)
            }
            Work::Store(index) => {
                matches!(self.names[index].phase, Phase::Store {job: serial, ..} if serial == row.serial)
            }
        };
        if !coherent {
            return Err(Error::Conflict);
        }
        self.jobs[index] = None;
        Ok(row)
    }
    fn completion(&self, outcome: Outcome, release: Option<u64>) -> Completion {
        Completion {
            release: release.map(|serial| self.answer_id(serial)),
            outcome,
        }
    }
    /// Consume the same original actually settled CREATE result. Unknown never retries.
    pub fn created(&mut self, id: &JobId, result: Creation) -> Result<Completion, Error> {
        let job = self.result_job(id, Kind::CreateZone)?;
        let Work::Create(index) = job.work else {
            return Err(Error::Conflict);
        };
        let outcome = match result {
            Creation::Created(key) => {
                self.zones[index].key = Some(key);
                self.zones[index].created = true;
                self.zones[index].phase = ZonePhase::Check;
                Outcome::Applied
            }
            Creation::Rejected(_) => {
                self.zones[index].service_rejected = true;
                self.zones[index].phase = ZonePhase::Failed;
                Outcome::Failed
            }
            Creation::Unsent => {
                self.zones[index].phase = ZonePhase::Failed;
                Outcome::Failed
            }
            Creation::Unknown => {
                self.zones[index].phase = ZonePhase::Unknown;
                self.metrics.unknown_mutations = self.metrics.unknown_mutations.saturating_add(1);
                Outcome::Unknown
            }
        };
        Ok(self.completion(outcome, None))
    }
    /// Consume a whole actual parent-label LOOKUP. An already live matching
    /// delegation needs no write. For this instance's actually created child,
    /// other observed sets proceed to ordinary replacement under original bounds.
    /// Lookup-to-store is explicitly not a CAS transaction.
    pub fn delegation_observed(
        &mut self,
        id: &JobId,
        records: &[RecordData<'_>],
        now: Times,
    ) -> Result<Completion, Error> {
        self.sample(now)?;
        let job = self.result_job(id, Kind::CheckDelegation)?;
        let Work::Check(index) = job.work else {
            return Err(Error::Conflict);
        };
        if self.stopping || job.bounds.expired(now) {
            self.zones[index].phase = ZonePhase::Failed;
            return Ok(self.completion(
                if self.stopping {
                    Outcome::Closed
                } else {
                    Outcome::Failed
                },
                None,
            ));
        }
        if records.is_empty() {
            let outcome = if self.zones[index].created {
                self.zones[index].phase = ZonePhase::Delegate(job.bounds);
                Outcome::Retrying
            } else {
                self.zones[index].phase = ZonePhase::Failed;
                Outcome::Failed
            };
            return Ok(self.completion(outcome, None));
        }
        let eligible = records.len() == 1
            && records[0].flags.unknown_bits() == 0
            && !records[0].flags.contains(RecordFlags::PRIVATE)
            && !records[0].flags.contains(RecordFlags::MAINTENANCE)
            && !records[0].flags.contains(RecordFlags::SHADOW)
            && ZoneKey::from_record(&records[0]).ok() == self.zones[index].key;
        let matches =
            eligible && Self::expiry(&records[0], now).as_micros() > now.absolute.as_micros();
        if matches {
            self.zones[index].observed = true;
            self.zones[index].phase = ZonePhase::Ready;
        } else if self.zones[index].created {
            self.zones[index].phase = ZonePhase::Delegate(job.bounds);
            return Ok(self.completion(Outcome::Retrying, None));
        } else {
            self.zones[index].phase = ZonePhase::Failed;
        }
        Ok(self.completion(
            if matches {
                Outcome::Applied
            } else {
                Outcome::Failed
            },
            None,
        ))
    }
    /// Consume failure of this actually admitted original parent-label lookup
    /// only after its native owner is truly settled/closed. The host retains its
    /// real cause independently; a read error supplies no observed-empty data.
    /// Unadmitted constructor refusals use reject instead. This is clock-free,
    /// preserves the actual child CREATE fact and never records parent_stored.
    pub fn delegation_failed(&mut self, id: &JobId) -> Result<Completion, Error> {
        let job = self.result_job(id, Kind::CheckDelegation)?;
        let Work::Check(index) = job.work else {
            return Err(Error::Conflict);
        };
        self.zones[index].phase = ZonePhase::Failed;
        Ok(self.completion(
            if self.stopping {
                Outcome::Closed
            } else {
                Outcome::Failed
            },
            None,
        ))
    }
    /// Consume only an actual original parent-delegation STORE result.
    pub fn delegated(&mut self, id: &JobId, result: Mutation) -> Result<Completion, Error> {
        let job = self.result_job(id, Kind::Delegate)?;
        let Work::Delegate(index) = job.work else {
            return Err(Error::Conflict);
        };
        let outcome = match result {
            Mutation::KnownCode(0) => {
                self.zones[index].stored = true;
                self.zones[index].phase = ZonePhase::Ready;
                Outcome::Applied
            }
            Mutation::KnownCode(_) => {
                self.zones[index].service_rejected = true;
                self.zones[index].phase = ZonePhase::Failed;
                Outcome::Failed
            }
            Mutation::Unsent => {
                self.zones[index].phase = ZonePhase::Failed;
                Outcome::Failed
            }
            Mutation::Unknown => {
                self.zones[index].phase = ZonePhase::Unknown;
                self.metrics.unknown_mutations = self.metrics.unknown_mutations.saturating_add(1);
                Outcome::Unknown
            }
        };
        Ok(self.completion(outcome, None))
    }
    fn expiry(record: &RecordData<'_>, now: Times) -> AbsoluteTime {
        if !record.flags.contains(RecordFlags::RELATIVE_EXPIRATION) {
            return AbsoluteTime::from_micros(record.expiration_time);
        }
        if record.expiration_time == u64::MAX {
            return AbsoluteTime::from_micros(u64::MAX);
        }
        // Cache record data uses GNUnet's saturating lifetime arithmetic. This
        // does not alter the separately finite Bounds of the original iterator.
        AbsoluteTime::from_micros(
            now.absolute
                .as_micros()
                .saturating_add(record.expiration_time),
        )
    }
    fn cached_name(&self, zone: usize, label: &str) -> Option<usize> {
        // The original names have one ASCII first label and at most253 bytes.
        // Invalid/unrelated iterator labels remain a non-match, never an error.
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return None;
        }
        let suffix = &self.zones[zone].name;
        let length = label.len().checked_add(1)?.checked_add(suffix.len())?;
        if length > 253 {
            return None;
        }
        let mut fqdn = [0; 253];
        for (target, byte) in fqdn[..label.len()].iter_mut().zip(label.bytes()) {
            *target = byte.to_ascii_lowercase();
        }
        fqdn[label.len()] = b'.';
        fqdn[label.len() + 1..length].copy_from_slice(suffix.as_bytes());
        let key = core::str::from_utf8(&fqdn[..length]).ok()?;
        self.names_by_name
            .get(key)
            .copied()
            .filter(|index| self.names[*index].zone == Some(zone))
    }
    /// Observe one complete actual iterator set, not an initial-cache END. The
    /// host converts its returned Unicode label to the original ASCII DNS label.
    pub fn cache_record(
        &mut self,
        id: &JobId,
        label: &str,
        records: &[RecordData<'_>],
        now: Times,
    ) -> Result<bool, Error> {
        self.sample(now)?;
        if records.len() > self.limits.records_per_set {
            return Err(Error::Capacity);
        }
        let index = self.job_index(id)?;
        let job = self.jobs[index].ok_or(Error::StaleGeneration)?;
        let Work::Scan(zone) = job.work else {
            return Err(Error::Conflict);
        };
        if !job.admitted
            || !matches!(self.zones[zone].cache, Cache::Running(serial) if serial == job.serial)
        {
            return Err(Error::Conflict);
        }
        if job.bounds.expired(now) || self.stopping {
            self.jobs[index]
                .as_mut()
                .ok_or(Error::StaleGeneration)?
                .state = JobState::Retire;
            return Err(Error::Deadline);
        }
        let Some(name) = self.cached_name(zone, label) else {
            return Ok(false);
        };
        let mut expiry = AbsoluteTime::from_micros(u64::MAX);
        for record in records {
            let at = Self::expiry(record, now);
            if at.as_micros() < expiry.as_micros() {
                expiry = at;
            }
        }
        if records.is_empty() {
            expiry = AbsoluteTime::from_micros(0);
        }
        let name = &mut self.names[name];
        name.cached = Some(match name.cached {
            Some(old) if old.as_micros() < expiry.as_micros() => old,
            _ => expiry,
        });
        name.cache_nonempty |= !records.is_empty();
        Ok(true)
    }
    /// The host reports actual END or a separately retired failure. Both settle
    /// the original attempt; only END yields CacheState::Complete. Incomplete
    /// attempts retain actual observed sets and unseen names query fresh DNS.
    pub fn cache_end(&mut self, id: &JobId, result: ReadEnd) -> Result<Completion, Error> {
        let job = self.result_job(id, Kind::ScanCache)?;
        let Work::Scan(index) = job.work else {
            return Err(Error::Conflict);
        };
        self.zones[index].cache = Cache::Done(result);
        Ok(self.completion(
            if result == ReadEnd::Complete {
                Outcome::Applied
            } else {
                Outcome::Failed
            },
            None,
        ))
    }
    fn retry(&self) -> Result<When, Error> {
        let now = self.now()?;
        Ok(When::Mono(MonoInstant::from_micros(
            now.mono
                .as_micros()
                .checked_add(self.policy.retry.as_micros())
                .ok_or(Error::Overflow)?,
        )))
    }
    fn query_failed(&mut self, index: usize) -> Completion {
        self.metrics.dns_failures = self.metrics.dns_failures.saturating_add(1);
        if self.stopping {
            self.names[index].phase = Phase::Failed;
            return self.completion(Outcome::Closed, None);
        }
        let exhausted = self.names[index].attempts >= self.policy.max_attempts;
        let outcome = if exhausted {
            self.names[index].phase = Phase::Failed;
            Outcome::Failed
        } else {
            self.retry_name(index)
        };
        self.completion(outcome, None)
    }
    fn retry_name(&mut self, index: usize) -> Outcome {
        if self.stopping {
            self.names[index].phase = Phase::Failed;
            return Outcome::Closed;
        }
        match self.retry() {
            Ok(when) => {
                self.names[index].phase = Phase::Waiting(when);
                Outcome::Retrying
            }
            Err(_) => {
                self.names[index].phase = Phase::Failed;
                Outcome::Failed
            }
        }
    }
    /// Final failure of this original DNS attempt. TC fallback is not a failure
    /// or a new attempt and must keep the same native/core job and fixed bounds.
    pub fn dns_failed(&mut self, id: &JobId, _reason: ReadFailure) -> Result<Completion, Error> {
        let job = self.result_job(id, Kind::Query)?;
        let Work::Query(index) = job.work else {
            return Err(Error::Conflict);
        };
        Ok(self.query_failed(index))
    }
    /// Retain only metadata for a full matched converted NOERROR response. The
    /// host retains actual bytes under the returned answer until release is returned.
    /// Store inherits this query's original bounds, including TCP fallback time.
    pub fn dns_result(&mut self, id: &JobId, summary: Summary) -> Result<AnswerId, Error> {
        let job = self.result_job(id, Kind::Query)?;
        let Work::Query(index) = job.work else {
            return Err(Error::Conflict);
        };
        if summary.records > self.limits.records_per_set
            || summary.empty != (summary.records == 0)
            || summary.empty != summary.earliest_expiry.is_none()
            || summary
                .earliest_expiry
                .is_some_and(|expiry| expiry != summary.refresh)
        {
            self.query_failed(index);
            return Err(Error::InvalidInput);
        }
        let answer = job.serial;
        let serial = match self.spawn(Work::Store(index), job.bounds) {
            Ok(Some(serial)) => serial,
            Ok(None) => {
                self.query_failed(index);
                return Err(Error::Capacity);
            }
            Err(error) => {
                self.names[index].phase = Phase::Failed;
                return Err(error);
            }
        };
        self.names[index].attempts = 0;
        self.names[index].phase = Phase::Store {
            job: serial,
            answer,
            refresh: summary.refresh,
            count: summary.records,
        };
        Ok(self.answer_id(answer))
    }
    /// Actual original NAMESTORE result. Local whole write/admission is not success.
    pub fn stored(&mut self, id: &JobId, result: Mutation) -> Result<Completion, Error> {
        let job = self.result_job(id, Kind::Store)?;
        let Work::Store(index) = job.work else {
            return Err(Error::Conflict);
        };
        let Phase::Store {
            answer,
            refresh,
            count,
            job: serial,
        } = self.names[index].phase
        else {
            return Err(Error::Conflict);
        };
        if serial != job.serial {
            return Err(Error::Conflict);
        }
        let outcome = match result {
            Mutation::KnownCode(0) => {
                self.metrics.stored_sets = self.metrics.stored_sets.saturating_add(1);
                self.metrics.stored_records =
                    self.metrics.stored_records.saturating_add(count as u64);
                self.names[index].phase = Phase::Waiting(When::Absolute(refresh));
                Outcome::Applied
            }
            Mutation::KnownCode(_) | Mutation::Unsent => self.retry_name(index),
            Mutation::Unknown => {
                self.names[index].phase = Phase::Unknown;
                self.metrics.unknown_mutations = self.metrics.unknown_mutations.saturating_add(1);
                Outcome::Unknown
            }
        };
        Ok(self.completion(
            if self.stopping {
                Outcome::Closed
            } else {
                outcome
            },
            Some(answer),
        ))
    }
    fn retired_job(&mut self, job: Job, result: Retirement) -> Result<Completion, Error> {
        match job.work {
            Work::Create(index) | Work::Check(index) | Work::Delegate(index) => {
                let unknown = result == Retirement::Unknown && !matches!(job.work, Work::Check(_));
                self.zones[index].phase = if unknown {
                    ZonePhase::Unknown
                } else {
                    ZonePhase::Failed
                };
                if unknown {
                    self.metrics.unknown_mutations =
                        self.metrics.unknown_mutations.saturating_add(1);
                }
                Ok(self.completion(
                    if self.stopping {
                        Outcome::Closed
                    } else if unknown {
                        Outcome::Unknown
                    } else {
                        Outcome::Failed
                    },
                    None,
                ))
            }
            Work::Scan(index) => {
                self.zones[index].cache = Cache::Done(ReadEnd::Failed);
                Ok(self.completion(
                    if self.stopping {
                        Outcome::Closed
                    } else {
                        Outcome::Failed
                    },
                    None,
                ))
            }
            Work::Query(index) => Ok(self.query_failed(index)),
            Work::Store(index) => {
                let Phase::Store { answer, .. } = self.names[index].phase else {
                    return Err(Error::Conflict);
                };
                let unknown = result == Retirement::Unknown;
                let outcome = if unknown {
                    self.names[index].phase = Phase::Unknown;
                    Outcome::Unknown
                } else {
                    self.retry_name(index)
                };
                if unknown {
                    self.metrics.unknown_mutations =
                        self.metrics.unknown_mutations.saturating_add(1);
                }
                Ok(self.completion(
                    if self.stopping {
                        Outcome::Closed
                    } else if unknown {
                        Outcome::Unknown
                    } else {
                        outcome
                    },
                    Some(answer),
                ))
            }
        }
    }
    /// A pre-admission construction refusal is known unsent. Capacity-only cases
    /// should defer/resume instead. No actually admitted native job may use this path.
    pub fn reject(&mut self, id: &JobId) -> Result<Completion, Error> {
        let index = self.job_index(id)?;
        let job = self.jobs[index].ok_or(Error::StaleGeneration)?;
        if job.admitted {
            return Err(Error::Conflict);
        }
        self.jobs[index] = None;
        self.retired_job(job, Retirement::Unsent)
    }
    /// Complete original physical retirement, clock-free. This consumes the job
    /// only after the host's actual operation/partial/tombstone ownership is settled.
    pub fn retired(&mut self, id: &JobId, result: Retirement) -> Result<Completion, Error> {
        let index = self.job_index(id)?;
        let job = self.jobs[index].ok_or(Error::StaleGeneration)?;
        if !matches!(
            job.state,
            JobState::Retire | JobState::RetireDeferred | JobState::Retiring
        ) {
            return Err(Error::Conflict);
        }
        self.jobs[index] = None;
        self.retired_job(job, result)
    }
    /// Permanently stop new business while preserving every original native debt.
    pub fn stop(&mut self) {
        if self.stopping {
            return;
        }
        // Preserve known business failure once, before normal cancellation can
        // make healthy pending names/ancestors Failed. Later actual terminal
        // service rejections remain separately recorded on their original zone.
        for index in 0..self.names.len() {
            let (failed, _) = self.name_failure(&self.names[index]);
            self.names[index].failed_before_stop = failed;
        }
        self.stopping = true;
        for row in self.jobs.iter_mut().flatten() {
            if row.state != JobState::Retiring {
                row.state = JobState::Retire;
            }
        }
    }
    /// Local tracked jobs only; the host still owns its real source/worker proof.
    #[must_use]
    pub fn quiescent(&self) -> bool {
        self.jobs.iter().all(Option::is_none)
    }
    /// Number of original jobs including deferred and retiring native debt.
    #[must_use]
    pub fn pending_jobs(&self) -> usize {
        self.jobs.iter().flatten().count()
    }
    /// Exact retained canonical FQDN.
    pub fn name(&self, id: &NameId) -> Result<&str, Error> {
        Ok(&self.names[self.name_index(id)?].name)
    }
    /// Exact canonical control-zone name, for host key-table observation only.
    pub fn zone_name(&self, id: &ZoneId) -> Result<&str, Error> {
        Ok(&self.zones[self.zone_index(id)?].name)
    }
    /// Independent actual key/parent-link facts.
    pub fn zone_facts(&self, id: &ZoneId) -> Result<ZoneFacts, Error> {
        let zone = &self.zones[self.zone_index(id)?];
        Ok(ZoneFacts {
            has_key: zone.key.is_some(),
            created: zone.created,
            anchor: zone.anchor,
            parent_observed: zone.observed,
            parent_stored: zone.stored,
            cache: match zone.cache {
                Cache::Unused => CacheState::Unused,
                Cache::Running(_) => CacheState::Pending,
                Cache::Done(ReadEnd::Complete) => CacheState::Complete,
                Cache::Done(ReadEnd::Failed) => CacheState::Incomplete,
            },
        })
    }
    /// Current business name state, not a source readiness or authentication proof.
    pub fn name_state(&self, id: &NameId) -> Result<State, Error> {
        let phase = self.names[self.name_index(id)?].phase;
        Ok(if self.stopping {
            State::Stopped
        } else {
            match phase {
                Phase::Preparing => State::Preparing,
                Phase::Waiting(_) => State::Waiting,
                Phase::Query(_) | Phase::Store { .. } => State::Pending,
                Phase::Failed => State::Failed,
                Phase::Unknown => State::Uncertain,
            }
        })
    }
    fn name_failure(&self, name: &Name) -> (bool, bool) {
        let mut failed = if self.stopping {
            name.failed_before_stop
        } else {
            matches!(name.phase, Phase::Failed)
        };
        let mut uncertain = matches!(name.phase, Phase::Unknown);
        if self.stopping || matches!(name.phase, Phase::Preparing) {
            let mut next = name.zone;
            while let Some(index) = next {
                let zone = &self.zones[index];
                failed |= if self.stopping {
                    zone.service_rejected
                } else {
                    matches!(zone.phase, ZonePhase::Failed)
                };
                uncertain |= matches!(zone.phase, ZonePhase::Unknown);
                next = zone.parent;
            }
        }
        (failed, uncertain)
    }
    /// Count actual failed/uncertain input names without allocation. stop latches
    /// prior failures once; later real terminal CREATE/parent-STORE rejections
    /// still count through their original zone. Known-unsent normal cancellation
    /// never creates a business failure, while actual uncertainty stays visible.
    #[must_use]
    pub fn name_failures(&self) -> NameFailures {
        let mut counts = NameFailures::default();
        for name in &self.names {
            let (failed, uncertain) = self.name_failure(name);
            if uncertain {
                counts.uncertain += 1;
            } else if failed {
                counts.failed += 1;
            }
        }
        counts
    }
    /// Actual cumulative callback/admission facts; no socket counts are inferred.
    #[must_use]
    pub const fn metrics(&self) -> Metrics {
        self.metrics
    }
    /// Original fixed pool limits used to size the host's matching native rows.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }
    /// Original fixed scheduling/conversion policy, never refreshed by a poll.
    #[must_use]
    pub const fn policy(&self) -> Policy {
        self.policy
    }
    /// Earliest original timer work in separate coordinates. Retiring jobs use
    /// their host's actual cleanup wakeups, never an endlessly expired core timer.
    #[must_use]
    pub fn next_wakeup(&self) -> Wakeup {
        let mut result = Wakeup::default();
        let mono = |result: &mut Wakeup, at: MonoInstant| {
            if result.mono.is_none_or(|old| at < old) {
                result.mono = Some(at);
            }
        };
        let absolute = |result: &mut Wakeup, at: AbsoluteTime| {
            if at.as_micros() == u64::MAX {
                return;
            }
            if result
                .absolute
                .is_none_or(|old| at.as_micros() < old.as_micros())
            {
                result.absolute = Some(at);
            }
        };
        for job in self.jobs.iter().flatten() {
            match job.state {
                JobState::Ready | JobState::Deferred | JobState::Active => {
                    mono(&mut result, job.bounds.until);
                    absolute(&mut result, job.bounds.expires);
                    if job.state == JobState::Ready
                        && let Some(now) = self.last
                    {
                        mono(
                            &mut result,
                            if matches!(job.work, Work::Query(_)) && self.next_dispatch > now.mono {
                                self.next_dispatch
                            } else {
                                now.mono
                            },
                        );
                    }
                }
                JobState::Retire => {
                    if let Some(now) = self.last {
                        mono(&mut result, now.mono);
                    }
                }
                _ => {}
            }
        }
        if !self.stopping && self.bootstrapped && self.free_job() {
            for name in &self.names {
                if let Phase::Waiting(when) = name.phase {
                    match when {
                        When::Absolute(at) => absolute(&mut result, at),
                        When::Mono(at) => mono(&mut result, at),
                    }
                }
            }
        }
        result
    }
}
