//! Actual monitor -> prepared tasks -> original DATASTORE/FS results -> catalog.
use super::{
    Error, Event, Limits, Options, Stop,
    catalog::{Catalog, Phase, Reply, TaskRef},
    scan::{Entry, Snapshot},
    worker::{Group, Load, Prepare, Worker},
};
use crate::{
    Buffers,
    publication::{self, Control as PublishControl, Disposition, Phase as PublishPhase},
};
use gnunet_client_host::EndpointSource;
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_types::AbsoluteTime;

use std::{
    future::{Future, poll_fn},
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
/// Original typed publication failure, retained independently of catalog errors.
#[derive(Debug)]
pub struct PublicationFailure {
    /// Original immutable local group id.
    pub version: u64,
    /// Original zero-based task in that group, never a wire RID.
    pub task: usize,
    /// Actual native reply/uncertainty plus independent retirement/state errors.
    pub failure: Box<publication::Failure>,
}
/// Actual source observations, not network availability/replication receipts.
#[derive(Debug, Default)]
pub struct RunReport {
    /// Complete successful scans only.
    pub scans: u64,
    /// Immutable groups actually prepared and recorded.
    pub prepared: u64,
    /// Groups with complete actual Task results and a successful catalog commit.
    pub published: u64,
    /// Original versions fenced against automatic replay.
    pub blocked: u64,
    /// Actual failed file/preparation/publication attempts observed.
    pub failures: u64,
    /// One extra original failure when the bounded table itself caused termination.
    pub overflow: Option<PublicationFailure>,
    /// Actual caller/source-lifetime stop was observed.
    pub stopped: bool,
    /// Latest typed failure per version, bounded explicitly by Limits.failures.
    pub publication_failures: Vec<PublicationFailure>,
}
/// Original foreground failure plus independent cleanup and typed native facts.
#[derive(Debug)]
pub struct RunFailure {
    /// First unhandled core/clock/filesystem/source error.
    pub cause: Option<Error>,
    /// Independent file/source error if canonical-clock failure occurred first.
    pub secondary: Option<Error>,
    /// Original worker/cleanup error independent of that cause.
    pub cleanup: Option<Error>,
    /// An original native failure retained even if the diagnostic table was full.
    pub publication: Option<PublicationFailure>,
    /// Actual accumulated source facts.
    pub report: RunReport,
}
impl std::fmt::Display for RunFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "auto-share stopped: cause={:?}; secondary={:?}; cleanup={:?}; native={:?}; scans={} prepared={} published={} blocked={}",
            self.cause,
            self.secondary,
            self.cleanup,
            self.publication,
            self.report.scans,
            self.report.prepared,
            self.report.published,
            self.report.blocked
        )
    }
}
impl std::error::Error for RunFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause
            .as_ref()
            .map(|e| e as &dyn std::error::Error)
            .or_else(|| self.secondary.as_ref().map(|e| e as &dyn std::error::Error))
            .or_else(|| self.cleanup.as_ref().map(|e| e as &dyn std::error::Error))
    }
}
struct Lease {
    native: Pin<Box<Sleep>>,
    logical: Deadline,
    ended: bool,
    error: Option<Error>,
    hard: Instant,
    until: u64,
}
impl Lease {
    fn new(clock: Arc<dyn RuntimeClock>, life: Duration) -> Result<Self, Error> {
        let hard = Instant::now()
            .checked_add(life)
            .ok_or(Error::Binding("auto-share native lifetime overflow"))?;
        let until = clock
            .sample()?
            .now
            .as_micros()
            .checked_add(
                u64::try_from(life.as_micros()).map_err(|_| Error::Binding("lifetime overflow"))?,
            )
            .ok_or(Error::Binding("auto-share absolute lifetime overflow"))?;
        let logical = Deadline::at(clock, AbsoluteTime::from_micros(until))?;
        Ok(Self {
            native: Box::pin(tokio::time::sleep_until(hard)),
            logical,
            ended: false,
            error: None,
            hard,
            until,
        })
    }
    fn poll(&mut self, cx: &mut Context<'_>, stop: &Stop) {
        stop.register(cx);
        if self.ended {
            return;
        }
        if self.native.as_mut().poll(cx).is_ready() {
            self.ended = true;
            stop.request();
            return;
        }
        match Pin::new(&mut self.logical).poll(cx) {
            Poll::Ready(result) => {
                self.ended = true;
                stop.request();
                if let Err(e) = result {
                    self.error = Some(e.into())
                }
            }
            Poll::Pending => {}
        }
    }
    async fn during<F: Future>(&mut self, stop: &Stop, future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        poll_fn(|cx| {
            self.poll(cx, stop);
            future.as_mut().poll(cx)
        })
        .await
    }
}
struct FailureAt<'a> {
    id: u64,
    index: usize,
    name: &'a [u8],
}
struct Stable {
    entry: Entry,
    since: Instant,
    retry: Instant,
}
/// One actual automatic-share allocation. Caller owns its actual configured FS /
/// DATASTORE selectors and drives the same shared Resolver concurrently with run.
/// Source/operation futures must be retained through stopping; canceling run does
/// not authorize starting a replacement on this owner or replaying an Unknown.
pub struct Owner {
    catalog: Catalog,
    worker: Worker,
    fs: EndpointSource,
    datastore: EndpointSource,
    clock: Arc<dyn RuntimeClock>,
    options: Options,
    limits: Limits,
    metadata: crate::extraction::MetadataSettings,
    stop: Stop,
    stable: Vec<Stable>,
    running: bool,
}
impl Owner {
    /// Open only a newly created or recognized marked Rust state below the selected
    /// directory, never the C .auto-share file. This performs synchronous owned-state
    /// setup but creates no native service client. Call after process privileges.
    pub fn open(
        directory: &Path,
        fs: EndpointSource,
        datastore: EndpointSource,
        options: Options,
        limits: Limits,
        stop: Stop,
    ) -> Result<Self, Error> {
        Self::open_with_metadata(
            directory,
            fs,
            datastore,
            options,
            limits,
            stop,
            crate::extraction::MetadataSettings::default(),
        )
    }
    /// Same original coordinator with a pure owned metadata configuration. No
    /// native provider exists until actual preparation inside the file worker.
    pub fn open_with_metadata(
        directory: &Path,
        fs: EndpointSource,
        datastore: EndpointSource,
        options: Options,
        limits: Limits,
        stop: Stop,
        metadata: crate::extraction::MetadataSettings,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if options
            .content_lifetime
            .is_some_and(|d| d.is_zero() || d.as_micros() >= u64::MAX as u128)
        {
            return Err(Error::Binding("invalid automatic content lifetime"));
        }
        let clock = datastore.clock();
        if !Arc::ptr_eq(&clock, &fs.clock()) {
            return Err(Error::Binding(
                "auto-share ports do not share the same actual clock",
            ));
        }
        let [fs, datastore] = EndpointSource::snapshot_all([&fs, &datastore])?;
        let mut stable = Vec::new();
        stable
            .try_reserve_exact(limits.entries)
            .map_err(|_| Error::Binding("auto-share observation capacity"))?;
        let catalog = Catalog::open(directory, limits)?;
        let worker = Worker::new(stop.clone())?;
        Ok(Self {
            catalog,
            worker,
            fs,
            datastore,
            clock,
            options,
            limits,
            metadata,
            stop,
            stable,
            running: false,
        })
    }
    /// Same original stop capability; it starts no task and resets no deadline.
    pub fn stop(&self) -> Stop {
        self.stop.clone()
    }
    /// All native publication work has settled before the explicit file worker join.
    /// The worker is not force-cancelable inside a synchronous OS filesystem call.
    pub async fn run(
        &mut self,
        mut observe: impl FnMut(Event<'_>),
    ) -> Result<RunReport, Box<RunFailure>> {
        let mut report = RunReport::default();
        if self.running {
            return Err(Box::new(RunFailure {
                cause: Some(Error::Binding("original auto-share run was not settled")),
                secondary: None,
                cleanup: None,
                publication: None,
                report,
            }));
        }
        self.running = true;
        if report
            .publication_failures
            .try_reserve_exact(self.limits.failures)
            .is_err()
        {
            let cleanup = self.worker.shutdown().await.err();
            return Err(Box::new(RunFailure {
                cause: Some(Error::Binding("typed failure table allocation")),
                secondary: None,
                cleanup,
                publication: None,
                report,
            }));
        }
        let mut lease = match Lease::new(Arc::clone(&self.clock), self.limits.lifetime) {
            Ok(v) => v,
            Err(e) => {
                let cleanup = self.worker.shutdown().await.err();
                return Err(Box::new(RunFailure {
                    cause: Some(e),
                    secondary: None,
                    cleanup,
                    publication: None,
                    report,
                }));
            }
        };
        let outcome = self.execute(&mut lease, &mut report, &mut observe).await;
        self.stop.request();
        let cleanup = self.worker.shutdown().await.err();
        let lease_error = lease.error.take();
        match (outcome, lease_error, cleanup) {
            (Ok(()), None, None) => {
                report.stopped = true;
                Ok(report)
            }
            (result, lease_error, cleanup) => {
                let (cause, secondary) = if let Some(first) = lease_error {
                    (Some(first), result.err())
                } else {
                    (result.err(), None)
                };
                let publication = report.overflow.take();
                Err(Box::new(RunFailure {
                    cause,
                    secondary,
                    cleanup,
                    publication,
                    report,
                }))
            }
        }
    }
    async fn execute(
        &mut self,
        lease: &mut Lease,
        report: &mut RunReport,
        observe: &mut impl FnMut(Event<'_>),
    ) -> Result<(), Error> {
        // A durable Preparing record precedes any native authorization. After restart
        // it is abandoned, never relabeled published or reused as a fresh path/version.
        let mut abandoned = Vec::new();
        abandoned
            .try_reserve_exact(self.catalog.versions.len())
            .map_err(|_| Error::Binding("restart id table allocation"))?;
        abandoned.extend(
            self.catalog
                .versions
                .iter()
                .filter(|v| v.phase == Phase::Preparing)
                .map(|v| v.id),
        );
        for id in abandoned {
            self.catalog.phase(id, Phase::Superseded, Vec::new())?;
        }
        let mut settled = Vec::new();
        settled
            .try_reserve_exact(self.catalog.versions.len())
            .map_err(|_| Error::Binding("restart settled table allocation"))?;
        settled.extend(
            self.catalog
                .versions
                .iter()
                .filter(|v| matches!(v.phase, Phase::Complete | Phase::Superseded))
                .map(|v| v.id),
        );
        for id in settled {
            if self.stop.requested() {
                return Ok(());
            }
            let path = self.catalog.path(id);
            match std::fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if self.catalog.version(id)?.phase == Phase::Complete {
                        self.catalog.phase(id, Phase::Blocked, Vec::new())?;
                    } else {
                        self.catalog.account(id, 0)?;
                    }
                }
                Err(error) => return Err(error.into()),
                Ok(_) => {
                    if self.catalog.version(id)?.phase == Phase::Complete {
                        let name = self.catalog.version(id)?.name.clone();
                        let Some(group) = self
                            .load_or_fence(lease, id, &name, report, observe)
                            .await?
                        else {
                            continue;
                        };
                        if group.tasks.iter().any(|t| {
                            let s = t.task.status();
                            s.phase != PublishPhase::Complete || uncertain(s)
                        }) {
                            self.catalog.phase(id, Phase::Blocked, Vec::new())?;
                            report.blocked = report.blocked.saturating_add(1);
                            observe(Event::Blocked {
                                version: id,
                                path: &name,
                                reason: "complete catalog lost original completed task states",
                            });
                            continue;
                        }
                    }
                    let sizing = self.worker.size(path, self.limits);
                    match lease.during(&self.stop, sizing).await {
                        Ok(bytes) => self.catalog.account(id, bytes)?,
                        Err(Error::Scan(super::ScanError::Stopped)) if self.stop.requested() => {
                            return Ok(());
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
        }
        loop {
            if self.stop.requested() {
                return Ok(());
            }
            let began = Instant::now();
            let scan = self.worker.scan(
                self.catalog.root().to_path_buf(),
                self.catalog.root_id,
                self.limits.scan,
            );
            let snapshot = lease.during(&self.stop, scan).await;
            let stopped = self.stop.requested();
            let snapshot = match snapshot {
                Ok(_) if stopped => return Ok(()),
                Err(error) if stopped && pure_worker_stop(&error) => return Ok(()),
                Err(error) if stopped => return Err(error),
                result => result,
            };
            let snapshot = match snapshot {
                Ok(s) => s,
                Err(error) => {
                    report.failures = report.failures.saturating_add(1);
                    observe(Event::Failed {
                        version: None,
                        path: &[],
                        error: &error,
                    });
                    self.wait(lease, self.limits.retry).await;
                    continue;
                }
            };
            report.scans = report.scans.saturating_add(1);
            observe(Event::Scanned {
                entries: snapshot.entries.len(),
                objects: snapshot.objects,
                bytes: snapshot.bytes,
            });
            self.update(snapshot, observe)?;
            let now = Instant::now();
            let mut work = Vec::new();
            work.try_reserve_exact(self.stable.len())
                .map_err(|_| Error::Binding("ready scan allocation"))?;
            for row in &self.stable {
                if now.duration_since(row.since) >= self.limits.stability && now >= row.retry {
                    work.push(row.entry.clone())
                }
            }
            for entry in work {
                if self.stop.requested() {
                    return Ok(());
                }
                self.process(lease, &entry, report, observe).await?;
                if let Some(row) = self.stable.iter_mut().find(|r| r.entry.name == entry.name) {
                    row.retry = Instant::now()
                        .checked_add(self.limits.retry)
                        .ok_or(Error::Binding("retry overflow"))?
                }
            }
            let unsettled = self
                .stable
                .iter()
                .any(|r| Instant::now().duration_since(r.since) < self.limits.stability);
            let delay = if unsettled {
                self.limits.stability
            } else {
                began
                    .elapsed()
                    .saturating_mul(100)
                    .clamp(self.limits.minimum_scan, self.limits.maximum_scan)
            };
            self.wait(lease, delay).await;
        }
    }
    fn update(
        &mut self,
        snapshot: Snapshot,
        observe: &mut impl FnMut(Event<'_>),
    ) -> Result<(), Error> {
        if snapshot.entries.len() > self.limits.entries {
            return Err(Error::Binding("auto-share top-level entry bound"));
        }
        for old in &self.stable {
            if !snapshot.entries.iter().any(|e| e.name == old.entry.name) {
                observe(Event::Removed {
                    path: &old.entry.name,
                })
            }
        }
        let mut next = Vec::new();
        next.try_reserve_exact(snapshot.entries.len())
            .map_err(|_| Error::Binding("observation table allocation"))?;
        for entry in snapshot.entries {
            let old = self.stable.iter().find(|r| r.entry == entry);
            next.push(Stable {
                entry,
                since: old.map_or_else(Instant::now, |r| r.since),
                retry: old.map_or_else(Instant::now, |r| r.retry),
            });
        }
        self.stable = next;
        Ok(())
    }
    async fn wait(&mut self, lease: &mut Lease, duration: Duration) {
        let at = Instant::now()
            .checked_add(duration)
            .unwrap_or(lease.hard)
            .min(lease.hard);
        let mut sleep = std::pin::pin!(tokio::time::sleep_until(at));
        poll_fn(|cx| {
            lease.poll(cx, &self.stop);
            if self.stop.requested() {
                Poll::Ready(())
            } else {
                sleep.as_mut().poll(cx)
            }
        })
        .await
    }
    async fn process(
        &mut self,
        lease: &mut Lease,
        entry: &Entry,
        report: &mut RunReport,
        observe: &mut impl FnMut(Event<'_>),
    ) -> Result<(), Error> {
        if Instant::now() >= lease.hard {
            self.stop.request();
            return Ok(());
        }
        if self.clock.sample()?.now.as_micros() >= lease.until {
            self.stop.request();
            return Ok(());
        }
        let previous = self.catalog.last(&entry.name);
        if let Some(v) = previous {
            if v.phase == Phase::Blocked {
                report.blocked = report.blocked.saturating_add(1);
                observe(Event::Blocked {
                    version: v.id,
                    path: &entry.name,
                    reason: "original uncertain/refused version is fenced",
                });
                return Ok(());
            }
            if v.phase == Phase::Complete && v.fingerprint == entry.fingerprint {
                return Ok(());
            }
        }
        let reuse = previous
            .filter(|v| v.phase == Phase::Ready && v.fingerprint == entry.fingerprint)
            .map(|v| v.id);
        if let Some(v) =
            previous.filter(|v| v.phase == Phase::Ready && v.fingerprint != entry.fingerprint)
        {
            // Every original task must prove no unresolved mutation before a changed
            // source may supersede it. Opening/checking does not issue a native request.
            let id = v.id;
            let Some(original) = self
                .load_or_fence(lease, id, &entry.name, report, observe)
                .await?
            else {
                return Ok(());
            };
            if original.tasks.iter().any(|t| uncertain(t.task.status())) {
                self.catalog.phase(id, Phase::Blocked, Vec::new())?;
                observe(Event::Blocked {
                    version: id,
                    path: &entry.name,
                    reason: "changed input cannot bypass original unknown intent",
                });
                return Ok(());
            }
            self.catalog.phase(id, Phase::Superseded, Vec::new())?;
        }
        let (id, mut group) = if let Some(id) = reuse {
            let Some(group) = self
                .load_or_fence(lease, id, &entry.name, report, observe)
                .await?
            else {
                return Ok(());
            };
            (id, group)
        } else {
            let id = self.catalog.reserve(entry)?;
            let sample = self.clock.sample()?.now;
            let expiration = super::expiration(sample.as_micros(), self.options.content_lifetime)?;
            let blocks = crate::network::BlockOptions {
                expiration: AbsoluteTime::from_micros(expiration),
                anonymity: self.options.anonymity,
                priority: self.options.priority,
                replication: self.options.replication,
            };
            let mut policy = self.limits.preparation;
            policy.indexed = true;
            policy.metadata.extract =
                !self.options.disable_extractor && self.metadata.automatic_keywords_enabled();
            policy.metadata.creation_time = (!self.options.disable_creation_time)
                .then_some(AbsoluteTime::from_micros(sample.as_micros()));
            let prepared = self.worker.prepare(Prepare {
                root: self.catalog.root().to_path_buf(),
                root_id: self.catalog.root_id,
                entry: entry.clone(),
                group: self.catalog.path(id),
                blocks,
                policy,
                metadata: self.metadata.clone(),
                limits: self.limits,
            });
            let result = lease.during(&self.stop, prepared).await;
            let stopped = self.stop.requested();
            let result = match result {
                Ok(_) if stopped => return Ok(()),
                Err(error) if stopped && pure_worker_stop(&error) => return Ok(()),
                Err(error) if stopped => return Err(error),
                result => result,
            };
            let group = match result {
                Ok(g) => g,
                Err(error) => {
                    report.failures = report.failures.saturating_add(1);
                    observe(Event::Failed {
                        version: Some(id),
                        path: &entry.name,
                        error: &error,
                    });
                    if let Err(cleanup) = self.catalog.phase(id, Phase::Superseded, Vec::new()) {
                        return Err(Error::WithCleanup {
                            original: Box::new(error),
                            cleanup: Box::new(cleanup),
                        });
                    }
                    if !self.stop.requested() {
                        let sizing = self.worker.size(self.catalog.path(id), self.limits);
                        match lease.during(&self.stop, sizing).await {
                            Ok(bytes) => {
                                if let Err(cleanup) = self.catalog.account(id, bytes) {
                                    return Err(Error::WithCleanup {
                                        original: Box::new(error),
                                        cleanup: Box::new(cleanup),
                                    });
                                }
                            }
                            Err(Error::Scan(super::ScanError::Stopped))
                                if self.stop.requested() => {}
                            Err(cleanup) => {
                                return Err(Error::WithCleanup {
                                    original: Box::new(error),
                                    cleanup: Box::new(cleanup),
                                });
                            }
                        }
                    }
                    return Ok(());
                }
            };
            let mut tasks = Vec::new();
            tasks
                .try_reserve_exact(group.tasks.len())
                .map_err(|_| Error::Binding("task binding allocation"))?;
            for t in &group.tasks {
                tasks.push(TaskRef {
                    name: t.name.clone(),
                    id: *t.task.task_id(),
                    uri: t.uri.clone(),
                    target: t.target.clone(),
                })
            }
            self.catalog.prepared(
                id,
                tasks,
                group.metadata.clone(),
                group.uri.clone(),
                group.bytes,
            )?;
            report.prepared = report.prepared.saturating_add(1);
            observe(Event::Prepared {
                version: id,
                path: &entry.name,
                tasks: group.tasks.len(),
            });
            (id, group)
        };
        if Instant::now() >= lease.hard {
            self.stop.request();
            return Ok(());
        }
        let sample = self.clock.sample()?.now;
        if sample.as_micros() >= lease.until {
            self.stop.request();
            return Ok(());
        }
        let expires = sample
            .as_micros()
            .checked_add(
                u64::try_from(self.limits.operation.as_micros())
                    .map_err(|_| Error::Binding("operation bound overflow"))?,
            )
            .ok_or(Error::Binding("operation target overflow"))?
            .min(lease.until);
        let hard = Instant::now()
            .checked_add(self.limits.operation)
            .ok_or(Error::Binding("native operation overflow"))?
            .min(lease.hard);
        let mut alarm = std::pin::pin!(tokio::time::sleep_until(hard));
        let mut expired = false;
        let mut buffers = Buffers::new();
        for (index, task) in group.tasks.iter_mut().enumerate() {
            if self.stop.requested() || expired || Instant::now() >= hard {
                return Ok(());
            }
            let status = task.task.status();
            if uncertain(status) {
                self.catalog.phase(id, Phase::Blocked, Vec::new())?;
                report.blocked = report.blocked.saturating_add(1);
                observe(Event::Blocked {
                    version: id,
                    path: &entry.name,
                    reason: "recovered original task is uncertain",
                });
                return Ok(());
            }
            // The official auto-share retry policy explicitly authorizes real negative
            // refusals only, using the SAME task and original retained reply history.
            if status.indexes.pending.is_some() {
                task.task
                    .retry_index_refused()
                    .map_err(|_| Error::Binding("cannot retry original index refusal"))?
            }
            if status.requires_explicit_retry {
                task.task
                    .retry_refused()
                    .map_err(|_| Error::Binding("cannot retry original negative PUT reply"))?
            }
            let fs = self.fs.duplicate()?;
            let datastore = self.datastore.duplicate()?;
            let stopping = self.stop.clone();
            let mut timed_out = false;
            let answer = {
                let mut running = std::pin::pin!(task.task.run_indexed(
                    fs,
                    datastore,
                    &mut buffers,
                    AbsoluteTime::from_micros(expires),
                    |progress| {
                        observe(Event::Publication {
                            version: id,
                            task: index,
                            progress: &progress,
                        });
                        if stopping.requested() || Instant::now() >= hard {
                            PublishControl::Pause
                        } else {
                            PublishControl::Continue
                        }
                    }
                ));
                poll_fn(|cx| {
                    if alarm.as_mut().poll(cx).is_ready() {
                        timed_out = true
                    }
                    lease.poll(cx, &self.stop);
                    running.as_mut().poll(cx)
                })
                .await
            };
            expired |= timed_out;
            match answer {
                Ok(mut outcome) => {
                    if let Some(cleanup) = outcome.cleanup.take() {
                        let failure = publication_failure_cleanup(outcome, cleanup);
                        self.fail(
                            FailureAt {
                                id,
                                index,
                                name: &entry.name,
                            },
                            &mut task.task,
                            failure,
                            report,
                            observe,
                        )?;
                        return Ok(());
                    }
                    if outcome.reason != publication::StopReason::Complete
                        || outcome.completed.is_none()
                    {
                        return Ok(());
                    }
                }
                Err(failure) => {
                    self.fail(
                        FailureAt {
                            id,
                            index,
                            name: &entry.name,
                        },
                        &mut task.task,
                        failure,
                        report,
                        observe,
                    )?;
                    return Ok(());
                }
            }
        }
        // Metadata and Tasks are actual prepared artifacts; release their memory only
        // after all original native owners settled, then account actual owned files.
        drop(group);
        self.catalog.phase(id, Phase::Complete, Vec::new())?;
        let v = self.catalog.version(id)?;
        report.published = report.published.saturating_add(1);
        observe(Event::Published {
            version: id,
            path: &entry.name,
            uri: &v.uri,
        });
        if !self.stop.requested() {
            let size = self.worker.size(self.catalog.path(id), self.limits);
            let answer = lease.during(&self.stop, size).await;
            match answer {
                Ok(bytes) => self.catalog.account(id, bytes)?,
                Err(Error::Scan(super::ScanError::Stopped)) if self.stop.requested() => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    async fn load_or_fence(
        &mut self,
        lease: &mut Lease,
        id: u64,
        name: &[u8],
        report: &mut RunReport,
        observe: &mut impl FnMut(Event<'_>),
    ) -> Result<Option<Group>, Error> {
        self.catalog.check_root()?;
        let version = self.catalog.version(id)?;
        let request = Load {
            path: self.catalog.path(id),
            tasks: version.tasks.clone(),
            metadata: version.metadata.clone(),
            uri: version.uri.clone(),
            bytes: version.charged,
            limits: self.limits,
        };
        match lease.during(&self.stop, self.worker.load(request)).await {
            Ok(group) => Ok(Some(group)),
            Err(Error::Scan(super::ScanError::Stopped)) if self.stop.requested() => Ok(None),
            Err(original) => {
                report.failures = report.failures.saturating_add(1);
                observe(Event::Failed {
                    version: Some(id),
                    path: name,
                    error: &original,
                });
                if let Err(cleanup) = self.catalog.phase(id, Phase::Blocked, Vec::new()) {
                    return Err(Error::WithCleanup {
                        original: Box::new(original),
                        cleanup: Box::new(cleanup),
                    });
                }
                report.blocked = report.blocked.saturating_add(1);
                observe(Event::Blocked {
                    version: id,
                    path: name,
                    reason: "original task restore failed; no new version can bypass it",
                });
                Ok(None)
            }
        }
    }
    fn fail(
        &mut self,
        at: FailureAt<'_>,
        task: &mut publication::Task,
        failure: Box<publication::Failure>,
        report: &mut RunReport,
        observe: &mut impl FnMut(Event<'_>),
    ) -> Result<(), Error> {
        let FailureAt { id, index, name } = at;
        report.failures = report.failures.saturating_add(1);
        observe(Event::Failed {
            version: Some(id),
            path: name,
            error: failure.as_ref(),
        });
        // Take ownership of the actual private native result BEFORE any fallible local
        // allocation/catalog write. A bookkeeping failure cannot discard that result.
        let item = PublicationFailure {
            version: id,
            task: index,
            failure,
        };
        let slot = if let Some(slot) = report
            .publication_failures
            .iter()
            .position(|f| f.version == id)
        {
            report.publication_failures[slot] = item;
            slot
        } else {
            if report.publication_failures.len() == self.limits.failures {
                report.overflow = Some(item);
                return Err(Error::Binding("typed publication failure retention bound"));
            }
            report.publication_failures.push(item);
            report.publication_failures.len() - 1
        };
        let original = &report.publication_failures[slot].failure;
        let mut replies = Vec::new();
        replies
            .try_reserve_exact(2)
            .map_err(|_| Error::Binding("original reply allocation"))?;
        if let Some(native) = &original.native
            && let Some(bytes) = native.response_bytes()
        {
            replies.push(reply(index, false, native.attempt(), bytes)?);
        }
        if let Some(native) = &original.index
            && let Some(bytes) = native.response_bytes()
        {
            replies.push(reply(index, true, native.attempt(), bytes)?);
        }
        let blocked = uncertain(task.status());
        self.catalog.phase(
            id,
            if blocked {
                Phase::Blocked
            } else {
                Phase::Ready
            },
            replies,
        )?;
        if blocked {
            report.blocked = report.blocked.saturating_add(1);
            observe(Event::Blocked {
                version: id,
                path: name,
                reason: "original native uncertainty retained; automatic replay forbidden",
            })
        }
        Ok(())
    }
}
// Only cancellation shells produced by this local file/preparation worker may
// settle a caller stop normally. Never reinterpret IO/WAL/Unknown or any
// independent native/cleanup/state failure as cancellation based on its text.
fn pure_worker_stop(error: &Error) -> bool {
    use publication::auto_prepare::Failure as Preparation;
    match error {
        Error::Scan(super::ScanError::Stopped) => true,
        Error::Preparation(Preparation::Plan(error)) => pure_plan_stop(error),
        Error::Preparation(Preparation::Publication(failure)) => {
            let progress = &failure.progress;
            failure.native.is_none()
                && failure.index.is_none()
                && failure.graph.is_none()
                && failure.cleanup.is_none()
                && failure.state_failure.is_none()
                && failure.requested_stop.is_none()
                && progress.historical == publication::Counts::default()
                && progress.recorded == publication::Counts::default()
                && progress.new_accepted == publication::Counts::default()
                && progress.indexes == publication::IndexProgress::default()
                && progress.graph == publication::GraphProgress::default()
                && progress.pending.is_none()
                && progress.state_records == 0
                && progress.total_puts == 0
                && !progress.payloads_verified
                && progress.verification == crate::Progress::default()
                && matches!(failure.cause.as_ref(), Some(publication::Cause::Plan(error)) if pure_plan_stop(error))
        }
        _ => false,
    }
}
fn pure_plan_stop(error: &publication::plan::Error) -> bool {
    match error {
        publication::plan::Error::Host(crate::Error::Cancelled) => true,
        publication::plan::Error::Extraction(error) => pure_extraction_stop(error),
        _ => false,
    }
}
fn pure_extraction_stop(error: &crate::extraction::Error) -> bool {
    match error {
        crate::extraction::Error::Cancelled => true,
        crate::extraction::Error::Extractor(failure)
            if failure.cleanup.is_none() && failure.restore.is_none() =>
        {
            matches!(&failure.cause, gnunet_extractor_host::Cause::Caller(original) if pure_extraction_stop(original))
        }
        _ => false,
    }
}
fn uncertain(status: publication::Status) -> bool {
    status.fenced
        || status.uncertain
        || matches!(
            status.phase,
            PublishPhase::Uncertain | PublishPhase::CancelRequested | PublishPhase::Cancelled
        )
        || status
            .pending
            .is_some_and(|p| !matches!(p.disposition, Disposition::Refused { .. }))
        || status.indexes.pending.is_some_and(|p| {
            !matches!(p.disposition, publication::IndexDisposition::Refused { .. })
        })
}
fn reply(
    task: usize,
    index: bool,
    attempt: publication::Attempt,
    bytes: &[u8],
) -> Result<Reply, Error> {
    let mut saved = Vec::new();
    saved
        .try_reserve_exact(bytes.len())
        .map_err(|_| Error::Binding("original reply allocation"))?;
    saved.extend_from_slice(bytes);
    Ok(Reply {
        task,
        index,
        attempt: attempt.index,
        request: attempt.request_hash,
        bytes: saved,
    })
}
fn publication_failure_cleanup(
    outcome: publication::Outcome,
    cleanup: gnunet_client_host::ConnectError,
) -> Box<publication::Failure> {
    Box::new(publication::Failure {
        cause: None,
        native: outcome.last_native,
        index: outcome.last_index,
        graph: outcome.last_graph,
        cleanup: Some(cleanup),
        state_failure: None,
        progress: outcome.progress,
        requested_stop: None,
    })
}
