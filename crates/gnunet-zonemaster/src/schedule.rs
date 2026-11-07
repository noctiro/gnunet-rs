//! Actual bounded publication, source/revision, refresh and completion state.
//! Tokens are private process metadata, never private network messages.
use crate::material::{Destinations, LocalCache, Origin, Prepared, PublicPublication, Sealed};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use gnunet_identity::SecretKey;
use gnunet_types::Error;
use zeroize::Zeroizing;
static NEXT: AtomicU64 = AtomicU64::new(0);
macro_rules! token {
    ($n:ident,$d:literal) => {
        #[doc=$d]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $n {
            owner: u64,
            serial: u64,
        }
    };
}
token!(
    Source,
    "One original actual NAMESTORE iterator or monitor source."
);
token!(
    Job,
    "One original label/revision worker and native publication job."
);
/// Distinct actual inventory and monitor authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Fresh complete inventory; retained start fence prevents old
    /// snapshot rows from overwriting a later monitor event.
    Inventory,
    /// Actual live monitor record stream.
    Monitor,
}
#[derive(Clone, Copy)]
enum Life {
    Live,
    Complete,
    Lost,
}
struct SourceRow {
    source: Source,
    kind: Kind,
    life: Life,
    fence: u64,
    started: u64,
    seen: u64,
    minimum: Option<u64>,
}
struct Identity {
    key: SecretKey,
    label: Zeroizing<Vec<u8>>,
}
impl Identity {
    fn matches(&self, key: &SecretKey, label: &[u8]) -> bool {
        self.key.constant_time_eq(key) && self.label.as_slice() == label
    }
}
struct Version {
    identity: Identity,
    revision: u64,
    monitor: u64,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum SealState {
    Queued,
    Running,
    Ready,
    Failed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Actual original native obligation, independent of local work preparation.
pub enum NativeState {
    /// A real original operation has not been admitted.
    Needed,
    /// Actual original native admission, still no result.
    Pending,
    /// Public: actual local PUT write boundary, not remote storage. Cache:
    /// successful original CACHE reply, never mere queue/whole-write progress.
    Submitted,
    /// Actual original response failed or local source was lost.
    Failed,
    /// Not required (no public records or namecache disabled).
    Omitted,
}
struct Row {
    job: Job,
    source: Source,
    revision: u64,
    version: usize,
    until: u64,
    prepared: Option<Prepared>,
    sealed: Option<Sealed>,
    seal: SealState,
    public: NativeState,
    cache: NativeState,
    superseded: bool,
    cancelled_native: bool,
    charged: usize,
    origin: Origin,
    cancel_issued: bool,
}
/// Explicit finite memory/credit/refesh policy.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Whole in-flight prepare/worker/put/cache jobs.
    pub jobs: usize,
    /// Sensitive keyed label revisions retained for live rounds/jobs.
    pub labels: usize,
    /// Aggregate retained plaintext/ciphertext capacity.
    pub bytes: usize,
    /// Default official full-zone publication window (4h).
    pub window: u64,
    /// Smallest real wake, avoiding relative-TTL0 busy loops.
    pub minimum_delay: u64,
    /// Actual finite job lifetime, separate from record expiry.
    pub job_timeout: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            jobs: 5000,
            labels: 10000,
            bytes: 256 * 1024 * 1024,
            window: 14_400_000_000,
            minimum_delay: 1000,
            job_timeout: 60_000_000,
        }
    }
}
/// One exact authoritative event and original finite job target. The host
/// retains its independent native hard bound; retry/rollback cannot remint it.
pub struct Submission<'a> {
    /// Actual original stream.
    pub source: Source,
    /// Exact original authority, opaque and zeroizing.
    pub key: &'a SecretKey,
    /// Canonical original label.
    pub label: &'a [u8],
    /// Actual selected worker material; None for deletion/empty or for a
    /// public-only update containing no retained public records.
    pub prepared: Option<Prepared>,
    /// Original finite operation target.
    pub expires: u64,
}
/// The immutable original worker input, moved exactly once to a real provider.
pub struct Sealing {
    /// Exact original binding.
    pub job: Job,
    /// Original finite operation target, never a renewed TTL.
    pub expires: u64,
    /// Opaque zeroizing material. No ordinary Clone/Debug.
    pub input: Prepared,
}
/// One native submission requiring its real result from the same original owner.
pub enum Work<'a> {
    /// Actual original worker/native debt has ended; free this bounded job.
    Finish {
        /// Original finished job.
        job: Job,
    },

    /// Only a public-filtered signed product can reach DHT.
    Public {
        /// Exact original job.
        job: Job,
        /// Already-sealed public material, with query and expiry.
        block: &'a PublicPublication,
        /// Original finite work deadline.
        expires: u64,
    },
    /// Complete private/public ciphertext goes only to NAMECACHE.
    Cache {
        /// Exact original job.
        job: Job,
        /// Explicit local-only material.
        block: &'a LocalCache,
        /// Original finite work deadline.
        expires: u64,
    },
    /// Real old publication/cache interest must be retired by its
    /// original host owners. This is no rollback/revocation acknowledgement.
    Cancel {
        /// Exact stale/deleted/expired original job.
        job: Job,
    },
}
/// True source/revision transitions, bounded jobs and periodic refresh state.
/// Native hard times remain caller-owned; independent expiration can call cancel
/// without inventing logical time. Public/native receipts cannot be fabricated.
pub struct Core {
    owner: u64,
    next: u64,
    revision: u64,
    limits: Limits,
    sources: Vec<SourceRow>,
    versions: Vec<Version>,
    rows: Vec<Row>,
    bytes: usize,
    cache_enabled: bool,
    next_inventory: u64,
    minimum_relative: Option<u64>,
    previous_count: u64,
    monitor_minimum: Option<u64>,
}
fn reserve<T>(n: usize) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    Ok(v)
}
impl Core {
    /// Reserve fixed metadata only. No runtime/worker/key/crypto source exists.
    pub fn new(limits: Limits, cache_enabled: bool, now: u64) -> Result<Self, Error> {
        if limits.jobs == 0
            || limits.labels <= limits.jobs
            || limits.window == 0
            || limits.minimum_delay == 0
            || limits.job_timeout == 0
            || limits.job_timeout == u64::MAX
            || limits.bytes == 0
        {
            return Err(Error::InvalidInput);
        }
        let owner = NEXT
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
            .map_err(|_| Error::Overflow)?
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        Ok(Self {
            owner,
            next: 0,
            revision: 0,
            limits,
            sources: reserve(4)?,
            versions: reserve(limits.labels)?,
            rows: reserve(limits.jobs)?,
            bytes: 0,
            cache_enabled,
            next_inventory: now,
            minimum_relative: None,
            previous_count: 0,
            monitor_minimum: None,
        })
    }
    fn serial(&mut self) -> Result<u64, Error> {
        self.next = self.next.checked_add(1).ok_or(Error::Overflow)?;
        Ok(self.next)
    }
    fn source(&self, source: Source) -> Result<usize, Error> {
        if source.owner != self.owner {
            return Err(Error::Stale);
        }
        self.sources
            .iter()
            .position(|r| r.source == source)
            .ok_or(Error::Stale)
    }
    fn row(&self, job: Job) -> Result<usize, Error> {
        if job.owner != self.owner {
            return Err(Error::Stale);
        }
        self.rows
            .iter()
            .position(|r| r.job == job)
            .ok_or(Error::Stale)
    }
    /// Bind a real newly admitted original stream. Never rebind a lost cursor.
    pub fn source_started(&mut self, kind: Kind, now: u64) -> Result<Source, Error> {
        if self
            .sources
            .iter()
            .any(|s| s.kind == kind && matches!(s.life, Life::Live))
        {
            return Err(Error::Conflict);
        }
        if self.sources.len() >= 4 {
            return Err(Error::Capacity);
        }
        let source = Source {
            owner: self.owner,
            serial: self.serial()?,
        };
        if kind == Kind::Inventory {
            self.monitor_minimum = None;
        }
        self.sources.push(SourceRow {
            source,
            kind,
            life: Life::Live,
            fence: self.revision,
            started: now,
            seen: 0,
            minimum: None,
        });
        Ok(source)
    }
    /// A real original source was physically lost/stopped. This requires no
    /// fabricated clock sample; legitimate actual END uses source_finished.
    pub fn source_lost(&mut self, source: Source) -> Result<(), Error> {
        let i = self.source(source)?;
        self.sources[i].life = Life::Lost;
        for row in &mut self.rows {
            if row.source == source {
                row.superseded = true;
            }
        }
        self.collect_sources();
        self.collect_versions();
        Ok(())
    }
    /// Actual iterator END retains its legitimate in-flight snapshot jobs. Lost
    /// sources cancel their old jobs; no fresh source can complete old tokens.
    pub fn source_finished(
        &mut self,
        source: Source,
        complete: bool,
        now: u64,
    ) -> Result<(), Error> {
        let i = self.source(source)?;
        self.sources[i].life = if complete { Life::Complete } else { Life::Lost };
        if !complete {
            for row in &mut self.rows {
                if row.source == source {
                    row.superseded = true;
                }
            }
        } else if self.sources[i].kind == Kind::Inventory {
            let minimum = match (self.sources[i].minimum, self.monitor_minimum) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            let period = minimum
                .map_or(self.limits.window, |v| (v / 4).min(self.limits.window))
                .max(self.limits.minimum_delay);
            self.minimum_relative = minimum;
            self.previous_count = self.sources[i].seen;
            self.next_inventory = self.sources[i]
                .started
                .saturating_add(period)
                .max(now.saturating_add(self.limits.minimum_delay));
        }
        self.collect_sources();
        self.collect_versions();
        Ok(())
    }
    fn collect_sources(&mut self) {
        self.sources.retain(|s| {
            matches!(s.life, Life::Live) || self.rows.iter().any(|r| r.source == s.source)
        });
    }
    /// Admit one original source update. No selected worker material still
    /// advances its revision and supersedes old jobs, including a private-only
    /// update with local caching disabled. It claims no DHT delete or output
    /// success. Opaque key equality is constant-time and never hashed/logged.
    pub fn submit(&mut self, input: Submission<'_>, now: u64) -> Result<Option<Job>, Error> {
        let Submission {
            source,
            key,
            label,
            prepared,
            expires: until,
        } = input;
        if until <= now || until == u64::MAX {
            return Err(Error::Deadline);
        }
        if prepared
            .as_ref()
            .is_some_and(|p| !p.matches_identity(key, label))
        {
            return Err(Error::Authentication);
        }
        if prepared.as_ref().is_some_and(|p| {
            (p.destinations() == Destinations::PublicAndLocal) != self.cache_enabled
        }) {
            return Err(Error::InvalidInput);
        }
        let s = self.source(source)?;
        if !matches!(self.sources[s].life, Life::Live) {
            return Err(Error::Stale);
        }
        if prepared.is_some() && self.rows.len() >= self.limits.jobs {
            return Err(Error::Capacity);
        }
        let existing = self
            .versions
            .iter()
            .position(|v| v.identity.matches(key, label));
        if self.sources[s].kind == Kind::Monitor && self.inventory_live() {
            let fence = self
                .sources
                .iter()
                .filter(|r| r.kind == Kind::Inventory && matches!(r.life, Life::Live))
                .map(|r| r.fence)
                .min()
                .ok_or(Error::Conflict)?;
            let already = existing.is_some_and(|i| self.versions[i].monitor > fence);
            let retained = self.versions.iter().filter(|v| v.monitor > fence).count();
            if !already && retained >= self.limits.labels.saturating_sub(self.limits.jobs) {
                return Err(Error::Capacity);
            }
        }

        if self.sources[s].kind == Kind::Inventory
            && let Some(i) = existing
            && self.versions[i].monitor > self.sources[s].fence
        {
            if let Some(input) = prepared.as_ref() {
                self.sources[s].seen = self.sources[s].seen.saturating_add(1);
                if let Some(v) = input.minimum_relative() {
                    self.sources[s].minimum =
                        Some(self.sources[s].minimum.map_or(v, |old| old.min(v)));
                }
            }
            return Ok(None);
        }
        let n = prepared
            .as_ref()
            .map(Prepared::worker_reservation)
            .transpose()?
            .unwrap_or(0);
        let bytes = self
            .bytes
            .checked_add(n)
            .filter(|n| *n <= self.limits.bytes)
            .ok_or(Error::Capacity)?;
        let new_identity = if existing.is_none() {
            if self.versions.len() >= self.limits.labels {
                return Err(Error::Capacity);
            }
            let mut copy = reserve(label.len())?;
            copy.extend_from_slice(label);
            Some(Identity {
                key: key.try_clone_secret(),
                label: Zeroizing::new(copy),
            })
        } else {
            None
        };
        let revision = self.revision.checked_add(1).ok_or(Error::Overflow)?;
        let job = if prepared.is_some() {
            Some(Job {
                owner: self.owner,
                serial: self.serial()?,
            })
        } else {
            None
        };
        let version = if let Some(i) = existing {
            i
        } else {
            self.versions.push(Version {
                identity: new_identity.ok_or(Error::Conflict)?,
                revision,
                monitor: 0,
            });
            self.versions.len() - 1
        };
        self.revision = revision;
        self.versions[version].revision = revision;
        if self.sources[s].kind == Kind::Monitor {
            self.versions[version].monitor = revision;
        }
        for row in &mut self.rows {
            if row.version == version {
                row.superseded = true;
            }
        }
        if let Some(input) = prepared {
            let origin = input.origin();
            let minimum = input.minimum_relative();
            self.sources[s].seen = self.sources[s].seen.saturating_add(1);
            if let Some(v) = minimum {
                if self.sources[s].kind == Kind::Monitor {
                    self.monitor_minimum = Some(self.monitor_minimum.map_or(v, |old| old.min(v)));
                }

                self.sources[s].minimum = Some(self.sources[s].minimum.map_or(v, |old| old.min(v)));
                self.minimum_relative = Some(self.minimum_relative.map_or(v, |old| old.min(v)));
                self.next_inventory = self
                    .next_inventory
                    .min(now.saturating_add((v / 4).max(self.limits.minimum_delay)));
            }
            self.rows.push(Row {
                job: job.ok_or(Error::Conflict)?,
                source,
                revision,
                version,
                until,
                prepared: Some(input),
                sealed: None,
                seal: SealState::Queued,
                public: NativeState::Needed,
                cache: if self.cache_enabled {
                    NativeState::Needed
                } else {
                    NativeState::Omitted
                },
                superseded: false,
                cancelled_native: false,
                charged: n,
                origin,
                cancel_issued: false,
            });
            self.bytes = bytes;
        }
        // No-output updates have no job whose later retirement could collect
        // metadata. Keep live monitor/inventory fences and actual rows, while
        // allowing ordinary private-only inventory to stream beyond this bound.
        if job.is_none() {
            let _removed = self.collect_version(version);
        }
        Ok(job)
    }
    /// Caller backpressure can retain the original raw NAMESTORE reply instead
    /// of granting more NEXT credit. This reports actual free bounded slots.
    pub fn capacity(&self) -> usize {
        self.limits.jobs.saturating_sub(self.rows.len())
    }
    /// A saturated monitor fence needs the real host to halt credit or retire
    /// and restart the original inventory; no old iterator row is silently
    /// promoted to newer monitor authority. Job slots remain reserved separately.
    pub fn fence_pressure(&self) -> bool {
        self.sources
            .iter()
            .filter(|s| s.kind == Kind::Inventory && matches!(s.life, Life::Live))
            .any(|s| {
                self.versions.iter().filter(|v| v.monitor > s.fence).count()
                    >= self.limits.labels.saturating_sub(self.limits.jobs)
            })
    }
    /// Actual current relative/4 window with finite resource minimum.
    pub fn publication_window(&self) -> u64 {
        self.minimum_relative
            .map_or(self.limits.window, |n| (n / 4).min(self.limits.window))
            .max(self.limits.minimum_delay)
    }
    /// Actual currently retained jobs, not remote records in a DHT.
    pub fn pending(&self) -> usize {
        self.rows.len()
    }
    /// Actual last complete inventory set count, not a remote-storage proof.
    pub const fn last_inventory_count(&self) -> u64 {
        self.previous_count
    }
    /// Actual minimum relative lifetime observed in the current schedule.
    pub const fn minimum_relative(&self) -> Option<u64> {
        self.minimum_relative
    }
    /// Erase all retained secret/material/metadata only after the enclosing host
    /// has physically stopped every original native owner and joined its CPU
    /// workers. This reports no database/DHT rollback or remote receipt.
    pub fn retire_all_after_native_stop(&mut self) {
        self.rows.clear();
        self.versions.clear();
        self.sources.clear();
        self.bytes = 0;
    }
    /// Bounded per-record publication pacing for full-inventory work. Monitor
    /// changes are urgent and need not wait behind that background pace.
    pub fn publication_delay(&self) -> u64 {
        if self.previous_count == 0 {
            return self.limits.minimum_delay;
        }
        let window = self
            .minimum_relative
            .map_or(self.limits.window, |n| (n / 4).min(self.limits.window));
        (window / self.previous_count)
            .min(900_000_000)
            .max(self.limits.minimum_delay)
    }
    /// Exact earliest original job target; native hard times are external.
    pub fn next_deadline(&self) -> Option<u64> {
        self.rows.iter().map(|r| r.until).min()
    }
    /// Earliest real full-inventory start, shortened by relative lifetime/4.
    pub const fn inventory_at(&self) -> u64 {
        self.next_inventory
    }
    /// Actual active full iterator, excluding completed/lost original sources.
    pub fn inventory_live(&self) -> bool {
        self.sources
            .iter()
            .any(|s| s.kind == Kind::Inventory && matches!(s.life, Life::Live))
    }
    /// Total retained material capacity charged to original jobs.
    pub const fn retained_bytes(&self) -> usize {
        self.bytes
    }
    /// Pull one original worker input. Queue refusal must call return_sealing
    /// with the same unmodified value; queueing is not successful encryption.
    pub fn take_sealing(&mut self, now: u64) -> Result<Option<Sealing>, Error> {
        self.expire(now);
        if let Some(row) = self
            .rows
            .iter_mut()
            .find(|r| !r.superseded && r.seal == SealState::Queued)
        {
            row.seal = SealState::Running;
            return Ok(Some(Sealing {
                job: row.job,
                expires: row.until,
                input: row.prepared.take().ok_or(Error::Conflict)?,
            }));
        }
        Ok(None)
    }
    /// Restore an actually refused, unexecuted worker input to its original job.
    pub fn return_sealing(&mut self, sealing: Sealing) -> Result<(), Error> {
        let i = self.row(sealing.job)?;
        let row = &mut self.rows[i];
        if row.seal != SealState::Running
            || row.until != sealing.expires
            || row.origin != sealing.input.origin()
        {
            return Err(Error::Stale);
        }
        row.prepared = Some(sealing.input);
        row.seal = SealState::Queued;
        Ok(())
    }
    /// Apply an actual worker result only to this original source/revision/job.
    /// Late/superseded results are discarded and cannot submit native effects.
    pub fn sealed(
        &mut self,
        job: Job,
        result: Result<Sealed, Error>,
        now: u64,
    ) -> Result<bool, Error> {
        let i = self.row(job)?;
        if self.rows[i].seal != SealState::Running {
            return Err(Error::Replay);
        }
        if self.rows[i].superseded
            || self.rows[i].until <= now
            || self.versions[self.rows[i].version].revision != self.rows[i].revision
        {
            self.rows[i].seal = SealState::Failed;
            return Ok(false);
        }
        match result {
            Err(_) => {
                self.rows[i].seal = SealState::Failed;
                self.rows[i].public = NativeState::Failed;
                self.rows[i].cache = NativeState::Failed;
                Ok(false)
            }
            Ok(sealed) => {
                if sealed.origin() != self.rows[i].origin {
                    return Err(Error::Authentication);
                }
                if (sealed.destinations() == Destinations::PublicAndLocal) != self.cache_enabled {
                    return Err(Error::InvalidInput);
                }
                let n = sealed.retained_bytes();
                let bytes = self
                    .bytes
                    .checked_sub(self.rows[i].charged)
                    .and_then(|v| v.checked_add(n))
                    .filter(|v| *v <= self.limits.bytes)
                    .ok_or(Error::Capacity);
                let bytes = match bytes {
                    Ok(n) => n,
                    Err(error) => {
                        self.rows[i].seal = SealState::Failed;
                        return Err(error);
                    }
                };
                self.bytes = bytes;
                self.rows[i].charged = n;
                self.rows[i].public = if sealed.public.is_some() {
                    NativeState::Needed
                } else {
                    NativeState::Omitted
                };
                self.rows[i].sealed = Some(sealed);
                self.rows[i].seal = SealState::Ready;
                Ok(true)
            }
        }
    }
    /// Actual provider returned/dropped an already cancelled original task.
    /// This is not a successful crypto or future publication receipt.
    pub fn worker_discarded(&mut self, job: Job) -> Result<(), Error> {
        let i = self.row(job)?;
        if !self.rows[i].superseded || self.rows[i].seal != SealState::Running {
            return Err(Error::Stale);
        }
        self.rows[i].seal = SealState::Failed;
        Ok(())
    }
    /// Original job is cancelled/superseded/failed; no new source can revive it.
    pub fn cancelled(&self, job: Job) -> Result<bool, Error> {
        let i = self.row(job)?;
        Ok(self.rows[i].superseded || self.rows[i].seal == SealState::Failed)
    }
    /// Host really initiated original worker/native cancellation. This records
    /// intent only; pending native suffixes and CPU tasks remain owned.
    pub fn cancellation_started(&mut self, job: Job) -> Result<(), Error> {
        let i = self.row(job)?;
        if !self.cancelled(job)? {
            return Err(Error::Conflict);
        }
        self.rows[i].cancel_issued = true;
        Ok(())
    }
    /// Independent actual native hard expiry/caller cancellation, without fake now.
    pub fn cancel(&mut self, job: Job) -> Result<(), Error> {
        let i = self.row(job)?;
        self.rows[i].superseded = true;
        Ok(())
    }
    /// Absolute logical expiry never remints/extends an original native bound.
    pub fn expire(&mut self, now: u64) {
        for r in &mut self.rows {
            if r.until <= now {
                r.superseded = true;
            }
        }
    }
    /// Select real native work from retained checked products. Caller must not
    /// grant public authority to the local-cache variant.
    pub fn next_work(&mut self, now: u64) -> Result<Option<Work<'_>>, Error> {
        self.next_work_ready(now, true, true)
    }
    /// Select only lanes that can presently accept original work. A saturated
    /// public provider cannot hide local-cache work or retirement. When a job
    /// has a distinct full PRIVATE set and local caching is enabled, its public
    /// lane depends on the successful original CACHE result for that same job.
    pub fn next_work_ready(
        &mut self,
        now: u64,
        public_ready: bool,
        cache_ready: bool,
    ) -> Result<Option<Work<'_>>, Error> {
        self.expire(now);
        for row in &mut self.rows {
            if let Some(sealed) = &row.sealed {
                if row.public == NativeState::Needed
                    && sealed.public.as_ref().is_some_and(|b| b.expires() <= now)
                {
                    row.public = NativeState::Failed;
                }
                if row.cache == NativeState::Needed
                    && sealed
                        .local
                        .as_ref()
                        .is_some_and(|block| block.expires() <= now)
                {
                    row.cache = NativeState::Failed;
                }
                if self.cache_enabled
                    && sealed.requires_private_cache()
                    && row.cache == NativeState::Failed
                    && row.public == NativeState::Needed
                {
                    // No successful CACHE result covers the full local version.
                    // Publishing its public projection could replace valid private data
                    // from the previous local version. Retire without a PUT.
                    row.public = NativeState::Failed;
                }
            }
            if row.superseded || row.seal == SealState::Failed {
                if !row.cancel_issued {
                    return Ok(Some(Work::Cancel { job: row.job }));
                }
                if row.cancelled_native && row.seal != SealState::Running {
                    return Ok(Some(Work::Finish { job: row.job }));
                }
                continue;
            }
            if row.seal == SealState::Ready
                && [row.public, row.cache].iter().all(|s| {
                    matches!(
                        s,
                        NativeState::Submitted | NativeState::Failed | NativeState::Omitted
                    )
                })
            {
                return Ok(Some(Work::Finish { job: row.job }));
            }
            if row.seal == SealState::Ready {
                let sealed = row.sealed.as_ref().ok_or(Error::Conflict)?;
                if public_ready
                    && row.public == NativeState::Needed
                    && (!self.cache_enabled
                        || !sealed.requires_private_cache()
                        || row.cache == NativeState::Submitted)
                    && let Some(block) = &sealed.public
                {
                    return Ok(Some(Work::Public {
                        job: row.job,
                        block,
                        expires: row.until,
                    }));
                }
                if cache_ready && row.cache == NativeState::Needed {
                    return Ok(Some(Work::Cache {
                        job: row.job,
                        block: sealed.local.as_ref().ok_or(Error::Conflict)?,
                        expires: row.until,
                    }));
                }
            }
        }
        Ok(None)
    }
    /// Original native admission failed/refused and any ambiguous provider debt
    /// was actually physically retired. This never fabricates queue admission.
    pub fn native_refused(&mut self, job: Job, public: bool) -> Result<(), Error> {
        let i = self.row(job)?;
        let state = if public {
            &mut self.rows[i].public
        } else {
            &mut self.rows[i].cache
        };
        if *state != NativeState::Needed {
            return Err(Error::Stale);
        }
        *state = NativeState::Failed;
        Ok(())
    }
    /// Actual original native admission, not fabricated completion.
    pub fn native_queued(&mut self, job: Job, public: bool) -> Result<(), Error> {
        let i = self.row(job)?;
        if public
            && self.cache_enabled
            && self.rows[i]
                .sealed
                .as_ref()
                .is_some_and(Sealed::requires_private_cache)
            && self.rows[i].cache != NativeState::Submitted
        {
            return Err(Error::NotReady);
        }
        let state = if public {
            &mut self.rows[i].public
        } else {
            &mut self.rows[i].cache
        };
        if *state != NativeState::Needed {
            return Err(Error::Replay);
        }
        *state = NativeState::Pending;
        Ok(())
    }
    /// Actual result of the original native PUT/cache operation. Submitted only
    /// means a real public PUT local-write boundary or a successful original
    /// CACHE result, respectively. Queue/write progress cannot complete CACHE.
    /// Neither lane proves remote durable storage.
    pub fn native_done(&mut self, job: Job, public: bool, success: bool) -> Result<(), Error> {
        let i = self.row(job)?;
        let state = if public {
            &mut self.rows[i].public
        } else {
            &mut self.rows[i].cache
        };
        if *state != NativeState::Pending {
            return Err(Error::Stale);
        }
        *state = if success {
            NativeState::Submitted
        } else {
            NativeState::Failed
        };
        Ok(())
    }
    /// Acknowledge real original native retirement only after the host has
    /// physically canceled/closed those exact operations. No remote rollback is
    /// asserted. A running worker remains owned until its actual result/join.
    pub fn cancelled_native(&mut self, job: Job) -> Result<(), Error> {
        let i = self.row(job)?;
        let row = &mut self.rows[i];
        if !row.superseded && row.seal != SealState::Failed {
            return Err(Error::Conflict);
        }
        row.cancelled_native = true;
        row.public = NativeState::Failed;
        row.cache = NativeState::Failed;
        if row.seal == SealState::Queued {
            row.prepared = None;
            row.seal = SealState::Failed;
        }
        Ok(())
    }
    /// Retire only after the host physically canceled/closed all original native
    /// debt and a running worker actually returned or was actually joined. No
    /// deleted/source-lost worker can be silently reused for a newer label job.
    pub fn retired(&mut self, job: Job) -> Result<(), Error> {
        let i = self.row(job)?;
        if self.rows[i].seal == SealState::Running
            || self.rows[i].public == NativeState::Pending
            || self.rows[i].cache == NativeState::Pending
        {
            return Err(Error::WouldBlock);
        }
        let row = self.rows.remove(i);
        self.bytes = self.bytes.checked_sub(row.charged).ok_or(Error::Conflict)?;
        self.collect_sources();
        self.collect_versions();
        Ok(())
    }
    /// True only once both real native interests completed/failed/omitted.
    pub fn finished(&self, job: Job) -> Result<bool, Error> {
        let i = self.row(job)?;
        let row = &self.rows[i];
        Ok(row.seal != SealState::Running
            && [row.public, row.cache].iter().all(|s| {
                matches!(
                    s,
                    NativeState::Submitted | NativeState::Failed | NativeState::Omitted
                )
            }))
    }
    /// Collect one exact candidate without sweeping unrelated active versions.
    /// Returns true only when that index was removed and later rows shifted.
    fn collect_version(&mut self, index: usize) -> bool {
        let needed_fence = self.sources.iter().any(|s| {
            s.kind == Kind::Inventory
                && matches!(s.life, Life::Live)
                && self.versions[index].monitor > s.fence
        });
        if needed_fence || self.rows.iter().any(|r| r.version == index) {
            return false;
        }
        self.versions.remove(index);
        for row in &mut self.rows {
            if row.version > index {
                row.version -= 1;
            }
        }
        true
    }
    fn collect_versions(&mut self) {
        let mut i = 0;
        while i < self.versions.len() {
            if !self.collect_version(i) {
                i += 1;
            }
        }
    }
}
