//! Actual dedicated marked public DV watermark ledger on the shared fenced
//! snapshot backend and one explicit bounded worker. No private keys/nonces, C store,
//! T1 generation source, crypto provider or hidden retry is used here.
#![cfg(unix)]
#![forbid(unsafe_code)]
/// Actual BOX durable-fact and live-replay gate with original bounded loans.
pub mod box_admission;
mod format;
use gnunet_snapshot_host::{
    Namespace,
    backend::{self, Exposure, Store},
    worker::{Completion, Job, Stopped, Worker},
};
use gnunet_transport::{
    PeerId,
    dv::routes::{Routes, SourceId, SourceWork},
};
use gnunet_transport_dv_crypto::Token;
use gnunet_types::Error as Protocol;
use std::{
    fmt, io,
    path::Path,
    sync::Arc,
    task::{Context, Poll},
};
/// Independent qualified public DV snapshot namespace, distinct from T1 stamps.
pub const NAMESPACE: Namespace = Namespace::TransportDv;
/// Official subsystem (the dedicated Rust disk layout is independent).
pub const SUBSYSTEM: &[u8] = b"transport";
/// Official forever peer watermark families, deliberately never conflated.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum Kind {
    /// DV learning initiator's source-monotonic value.
    Learn = 1,
    /// Box/backchannel authenticated sender's source-monotonic value.
    Box = 2,
}
impl Kind {
    /// Exact active official PEERSTORE key name.
    pub const fn key(self) -> &'static [u8] {
        match self {
            Self::Learn => b"transport-dv-learn-monotonic-time",
            Self::Box => b"transport-backchannel-monotonic-time",
        }
    }
}
/// Typed original pure operation owner; not reconstructed from numeric IDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Owner<'id> {
    /// Original LEARN SourceWork owner.
    Learn(SourceId<'id>),
    /// Original actual BOX crypto/replay task owner.
    Box(Token<'id>),
}
impl Owner<'_> {
    fn kind(self) -> Kind {
        match self {
            Self::Learn(_) => Kind::Learn,
            Self::Box(_) => Kind::Box,
        }
    }
}
/// Immutable public request. Original owner/kind/peer/value are preserved across
/// actual worker admission, cancellation, completion and source retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request<'id> {
    owner: Owner<'id>,
    peer: PeerId,
    stamp: Option<u64>,
}
impl<'id> Request<'id> {
    /// Original actual caller task/source owner.
    pub const fn owner(self) -> Owner<'id> {
        self.owner
    }
    /// Exact separate official watermark family.
    pub fn kind(self) -> Kind {
        self.owner.kind()
    }
    /// Exact remote initiator/sender whose public value is requested.
    pub const fn peer(self) -> PeerId {
        self.peer
    }
    /// None is a load; Some is the exact original store value (zero stays valid).
    pub const fn stamp(self) -> Option<u64> {
        self.stamp
    }
    /// Load for an actual original authenticated BOX task. Caller obtains the
    /// peer from its private authentic Opened/Admitted, never an outer claim.
    pub const fn box_load(owner: Token<'id>, peer: PeerId) -> Self {
        Self {
            owner: Owner::Box(owner),
            peer,
            stamp: None,
        }
    }
    /// Store actual authenticated BOX sender watermark; nonce history is absent.
    pub const fn box_store(owner: Token<'id>, peer: PeerId, stamp: u64) -> Self {
        Self {
            owner: Owner::Box(owner),
            peer,
            stamp: Some(stamp),
        }
    }
}
impl<'id> From<SourceWork<'id>> for Request<'id> {
    fn from(work: SourceWork<'id>) -> Self {
        match work {
            SourceWork::Load { source, peer } => Self {
                owner: Owner::Learn(source),
                peer,
                stamp: None,
            },
            SourceWork::Store {
                source,
                peer,
                stamp,
            } => Self {
                owner: Owner::Learn(source),
                peer,
                stamp: Some(stamp),
            },
        }
    }
}
/// Bounded aggregate forever-record quota. No TTL/LRU deletion can revive a peer.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum distinct (Kind,public peer) records across both families.
    pub records: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self { records: 8192 }
    }
}
/// Actual original error, with publication uncertainty and backend cleanup kept.
#[derive(Debug)]
pub enum Cause {
    /// Exact protocol/quota/source/worker classification.
    Protocol(Protocol),
    /// Actual original OS operation error.
    Io(io::Error),
    /// Shared actual disk cause, exposure and independent cleanup.
    Snapshot(Arc<backend::Failure>),
}
/// Original failure is never replaced by a later worker/cleanup failure.
#[derive(Debug)]
pub struct Fault {
    /// Actual stage of failure.
    pub stage: &'static str,
    /// Whether an admitted physical publication may have occurred.
    pub uncertain: bool,
    /// Original exact cause, never a fabricated errno/ACK.
    pub cause: Cause,
}
impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DV store {} uncertain={}: {:?}",
            self.stage, self.uncertain, self.cause
        )
    }
}
impl std::error::Error for Fault {}
/// Shared first-cause error owner, safe to retain with original operation receipts.
pub type Error = Arc<Fault>;
fn fault(stage: &'static str, reason: Protocol) -> Error {
    Arc::new(Fault {
        stage,
        uncertain: reason == Protocol::OutcomeUnknown,
        cause: Cause::Protocol(reason),
    })
}
fn os(stage: &'static str, error: io::Error) -> Error {
    Arc::new(Fault {
        stage,
        uncertain: false,
        cause: Cause::Io(error),
    })
}
fn disk(error: Arc<backend::Failure>) -> Error {
    Arc::new(Fault {
        stage: error.stage,
        uncertain: error.exposure == Exposure::Unknown,
        cause: Cause::Snapshot(error),
    })
}
#[derive(Clone, Copy)]
struct Record {
    kind: Kind,
    peer: PeerId,
    stamp: u64,
}
fn key(record: &Record) -> (Kind, [u8; 32]) {
    (record.kind, record.peer.0)
}
/// Actual original provider operation token; constructor/domain stay private.
#[derive(Clone, Debug)]
pub struct Operation<'id> {
    domain: Arc<()>,
    serial: u64,
    request: Request<'id>,
}
impl PartialEq for Operation<'_> {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.domain, &other.domain)
            && self.serial == other.serial
            && self.request == other.request
    }
}
impl Eq for Operation<'_> {}
impl<'id> Operation<'id> {
    /// Exact original immutable request, not a replacement intent.
    pub const fn request(&self) -> Request<'id> {
        self.request
    }
    /// Diagnostic serial only; it cannot reconstruct authority.
    pub const fn value(&self) -> u64 {
        self.serial
    }
}
/// Private actual whole-snapshot durable knowledge, from Loaded or Committed.
/// Snapshot job may predate this read/known-store request; it is not relabeled as
/// that request's worker job. No arbitrary success constructor is exposed.
#[derive(Clone, Debug)]
pub struct Evidence {
    namespace: Namespace,
    generation: u64,
    job: Option<Job>,
}
impl Evidence {
    /// Original actual namespace; always the dedicated TransportDv namespace.
    pub const fn namespace(&self) -> Namespace {
        self.namespace
    }
    /// Actual loaded or definitely committed whole-image generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Actual most recent whole-snapshot commit job, None for actual recovery.
    pub fn snapshot_job(&self) -> Option<&Job> {
        self.job.as_ref()
    }
}
/// Original actual load result (absence is None, never a fabricated zero).
#[derive(Clone, Debug)]
pub struct Loaded<'id> {
    operation: Operation<'id>,
    value: Option<u64>,
    evidence: Evidence,
}
impl<'id> Loaded<'id> {
    /// Original load owner and peer/family.
    pub fn operation(&self) -> &Operation<'id> {
        &self.operation
    }
    /// Actual recovered/committed public value, or actual absence.
    pub const fn value(&self) -> Option<u64> {
        self.value
    }
    /// Actual qualified durable snapshot knowledge behind this load.
    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }
    /// Apply only to the exact original pure LEARN SourceWork source. A stale
    /// pure owner refuses; BOX cannot be silently applied as a LEARN watermark.
    pub fn apply_learn(&self, routes: &mut Routes<'id, '_>) -> Result<(), Protocol> {
        match self.operation.request.owner {
            Owner::Learn(source) => {
                if routes.source_peer(source)? != self.operation.request.peer {
                    return Err(Protocol::StaleGeneration);
                }
                routes.source_loaded(source, self.value)
            }
            Owner::Box(_) => Err(Protocol::InvalidInput),
        }
    }
}
/// Actual successful store/fact receipt. Local queue admission is not this type.
#[derive(Clone, Debug)]
pub struct Persisted<'id> {
    operation: Operation<'id>,
    job: Option<Job>,
    stamp: u64,
    evidence: Evidence,
    canceled: bool,
}
impl<'id> Persisted<'id> {
    /// Original exact owner/peer/value.
    pub fn operation(&self) -> &Operation<'id> {
        &self.operation
    }
    /// Actual original admitted worker job for a new commit; None means the
    /// equal value was already proven durable, with evidence() identifying it.
    pub fn job(&self) -> Option<&Job> {
        self.job.as_ref()
    }
    /// Exact requested public value actually durable.
    pub const fn stamp(&self) -> u64 {
        self.stamp
    }
    /// Actual namespace/generation snapshot receipt, not queued publication.
    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }
    /// Cancellation suppressed caller success while actual worker debt drained.
    pub const fn canceled(&self) -> bool {
        self.canceled
    }
    /// Apply only a noncanceled actual receipt to the original pure LEARN source.
    pub fn apply_learn(&self, routes: &mut Routes<'id, '_>) -> Result<(), Protocol> {
        if self.canceled {
            return Err(Protocol::Closed);
        }
        match self.operation.request.owner {
            Owner::Learn(source) => {
                if routes.source_peer(source)? != self.operation.request.peer {
                    return Err(Protocol::StaleGeneration);
                }
                routes.source_committed(source, self.stamp)
            }
            Owner::Box(_) => Err(Protocol::InvalidInput),
        }
    }
}
/// Actual store admission or previously durable equal-value knowledge.
#[derive(Debug)]
pub enum Admission<'id> {
    /// One actual bounded worker command, no persistence ACK.
    Queued {
        /// Original provider operation.
        operation: Operation<'id>,
        /// Actual original worker queue job.
        job: Job,
    },
    /// Equal requested value already had actual durable evidence.
    Known(Persisted<'id>),
}
/// Outcome of one actual original command or worker source termination.
#[derive(Debug)]
pub enum Event<'id> {
    /// Actual exact Namespace/generation/Job commit, even if canceled.
    Committed(Persisted<'id>),
    /// Actual failure/unknown for the original job; no replay.
    Failed {
        /// Original immutable operation, when an admitted job existed.
        operation: Option<Operation<'id>>,
        /// Actual original admitted job, if present.
        job: Option<Job>,
        /// Original cancellation disposition.
        canceled: bool,
        /// Exact original cause and publication uncertainty.
        error: Error,
    },
    /// Actual completion channel ended; not a guessed join/close.
    Ended,
}
/// Actual original cancellation retains physical debt until the real result.
#[derive(Debug)]
pub struct Canceled<'id> {
    operation: Operation<'id>,
    job: Job,
}
impl<'id> Canceled<'id> {
    /// Exact original canceled owner.
    pub fn operation(&self) -> &Operation<'id> {
        &self.operation
    }
    /// Still-owned actual worker debt, never a fake unsent/revoked receipt.
    pub fn job(&self) -> &Job {
        &self.job
    }
}
struct Pending<'id> {
    operation: Operation<'id>,
    job: Job,
    expected: u64,
    record: Record,
    index: usize,
    insert: bool,
    canceled: bool,
}
/// Explicit actual worker shutdown report. OS fsync/rename can block; neither
/// callback cancellation nor a socket deadline falsely proves it was interrupted.
#[derive(Debug)]
pub struct Shutdown {
    /// Independent actual join namespace/generation validation, if it failed.
    pub validation: Option<Error>,
    /// Actual original join report, or exact join/source error.
    pub worker: Result<Stopped, Protocol>,
    /// First provider/storage cause, retained independently.
    pub original: Option<Error>,
}
/// One qualified independent DV ledger and one explicit shared disk worker.
/// No original Request/opaque pure token crosses the worker; only one zeroizing
/// serialized PUBLIC metadata body does. Drop synchronously joins before scope
/// guard descriptors drop; explicit shutdown exposes the actual final report.
#[must_use = "explicitly stop/drain/join the actual worker to retain original results and cleanup errors"]
pub struct Provider<'id> {
    worker: Option<Worker>,
    records: Vec<Record>,
    limit: usize,
    evidence: Evidence,
    domain: Arc<()>,
    next: u64,
    pending: Option<Pending<'id>>,
    first: Option<Error>,
    stopping: bool,
    ended: bool,
}
impl<'id> Provider<'id> {
    /// Actually qualify a caller-owned new/recovered dedicated DV root, load its
    /// public image under the dedicated TransportDv namespace, then start exactly one
    /// bounded worker. Parent must exist. No T1 root/image is adopted or imported.
    pub fn open(directory: impl AsRef<Path>, limits: Limits) -> Result<Self, Error> {
        let bytes = format::limit(limits.records)?;
        let directory = directory.as_ref();
        if !directory.is_absolute() {
            return Err(fault("absolute-dv-directory", Protocol::InvalidInput));
        }
        let (mut store, loaded) =
            Store::open(NAMESPACE, directory, backend::Limits { body_bytes: bytes })
                .map_err(|e| disk(Arc::new(e)))?;
        if loaded.namespace() != NAMESPACE {
            return Err(fault("loaded-namespace", Protocol::Stale));
        }
        let mut generation = loaded.generation();
        let created = loaded.created_directory();
        let body = loaded.into_body();
        if generation == 0 && !created {
            return Err(fault("marked-root-missing-canonical", Protocol::Malformed));
        }
        let records = format::decode(&body, generation, limits.records)?;
        if generation == 0 {
            let committed = store.commit(0, format::empty_image()?).map_err(disk)?;
            if committed.namespace() != NAMESPACE || committed.generation() != 1 {
                return Err(fault("genesis-commit-binding", Protocol::Stale));
            }
            generation = committed.generation();
        }
        let worker = Worker::start(store).map_err(|e| os("worker-start", e))?;
        if worker.namespace() != NAMESPACE {
            return Err(fault("worker-namespace", Protocol::Stale));
        }
        Ok(Self {
            worker: Some(worker),
            records,
            limit: limits.records,
            evidence: Evidence {
                namespace: NAMESPACE,
                generation,
                job: None,
            },
            domain: Arc::new(()),
            next: 0,
            pending: None,
            first: None,
            stopping: false,
            ended: false,
        })
    }
    fn available(&self) -> Result<(), Error> {
        if let Some(e) = &self.first {
            return Err(e.clone());
        }
        if self.stopping || self.ended {
            return Err(fault("admission-closed", Protocol::Closed));
        }
        if self.pending.is_some() {
            return Err(fault("original-job-pending", Protocol::WouldBlock));
        }
        Ok(())
    }
    fn operation(&mut self, request: Request<'id>) -> Result<Operation<'id>, Error> {
        let serial = self
            .next
            .checked_add(1)
            .ok_or_else(|| fault("operation", Protocol::Overflow))?;
        self.next = serial;
        Ok(Operation {
            domain: self.domain.clone(),
            serial,
            request,
        })
    }
    fn index(&self, request: Request<'_>) -> Result<usize, usize> {
        self.records
            .binary_search_by_key(&(request.kind(), request.peer.0), key)
    }
    fn block(&mut self, error: Error) {
        if self.first.is_none() {
            self.first = Some(error)
        }
        self.stopping = true;
        if let Some(worker) = &mut self.worker {
            worker.request_stop()
        }
    }
    /// Return a load only from the actual qualified Loaded/Committed snapshot.
    /// It has no invented worker job: current shared worker writes only. Pending
    /// or unknown stores block loads so unobserved newer durable state cannot be
    /// silently represented by an older cache snapshot.
    pub fn load(&mut self, request: Request<'id>) -> Result<Loaded<'id>, Error> {
        self.available()?;
        if request.stamp.is_some() {
            return Err(fault("load-kind", Protocol::InvalidInput));
        }
        let value = self.index(request).ok().map(|i| self.records[i].stamp);
        let operation = self.operation(request)?;
        Ok(Loaded {
            operation,
            value,
            evidence: self.evidence.clone(),
        })
    }
    /// Store a monotonic public value. One new body/job max; lower values reject,
    /// full capacity refuses NEW keys without deleting any forever watermark.
    /// Equal known durable values return Known with explicit prior evidence.
    pub fn store(&mut self, request: Request<'id>) -> Result<Admission<'id>, Error> {
        self.available()?;
        let stamp = request
            .stamp
            .ok_or_else(|| fault("store-kind", Protocol::InvalidInput))?;
        let (index, insert) = match self.index(request) {
            Ok(i) => {
                if stamp < self.records[i].stamp {
                    return Err(fault("watermark-regression", Protocol::StaleGeneration));
                }
                if stamp == self.records[i].stamp {
                    let operation = self.operation(request)?;
                    return Ok(Admission::Known(Persisted {
                        operation,
                        job: None,
                        stamp,
                        evidence: self.evidence.clone(),
                        canceled: false,
                    }));
                }
                (i, false)
            }
            Err(i) => {
                if self.records.len() == self.limit {
                    return Err(fault("record-capacity", Protocol::Capacity));
                }
                (i, true)
            }
        };
        let next = self
            .evidence
            .generation
            .checked_add(1)
            .ok_or_else(|| fault("generation", Protocol::Overflow))?;
        let record = Record {
            kind: request.kind(),
            peer: request.peer,
            stamp,
        };
        let body = format::encode(&self.records, record, index, insert)?;
        let operation = self.operation(request)?;
        let expected = self.evidence.generation;
        let worker = self
            .worker
            .as_mut()
            .ok_or_else(|| fault("worker-closed", Protocol::Closed))?;
        let job = match worker.submit(expected, body) {
            Ok(job) => job,
            Err((reason, _body)) => {
                let error = fault("worker-admission", reason);
                if reason != Protocol::WouldBlock {
                    self.block(error.clone())
                }
                return Err(error);
            }
        };
        if job.namespace() != NAMESPACE {
            let error = Arc::new(Fault {
                stage: "job-namespace",
                uncertain: true,
                cause: Cause::Protocol(Protocol::OutcomeUnknown),
            });
            self.pending = Some(Pending {
                operation: operation.clone(),
                job: job.clone(),
                expected,
                record,
                index,
                insert,
                canceled: false,
            });
            self.block(error);
            return Ok(Admission::Queued { operation, job });
        }
        let _checked_generation = next;
        self.pending = Some(Pending {
            operation: operation.clone(),
            job: job.clone(),
            expected,
            record,
            index,
            insert,
            canceled: false,
        });
        Ok(Admission::Queued { operation, job })
    }
    /// Callback cancellation never revokes an admitted filesystem mutation.
    /// The original job stays pending and no replacement can reset its debt.
    pub fn cancel(&mut self, operation: &Operation<'id>) -> Result<Canceled<'id>, Error> {
        let pending = self
            .pending
            .as_mut()
            .filter(|p| p.operation == *operation)
            .ok_or_else(|| fault("cancel-original", Protocol::Stale))?;
        pending.canceled = true;
        Ok(Canceled {
            operation: pending.operation.clone(),
            job: pending.job.clone(),
        })
    }
    fn failed(&mut self, error: Error) -> Event<'id> {
        let pending = self.pending.take();
        self.block(error.clone());
        match pending {
            Some(p) => Event::Failed {
                operation: Some(p.operation),
                job: Some(p.job),
                canceled: p.canceled,
                error,
            },
            None => Event::Failed {
                operation: None,
                job: None,
                canceled: false,
                error,
            },
        }
    }
    fn completion(&mut self, completion: Completion) -> Event<'id> {
        let Some(pending) = self.pending.as_ref() else {
            return self.failed(fault(
                "completion-without-original",
                Protocol::OutcomeUnknown,
            ));
        };
        if completion.job() != &pending.job || completion.job().namespace() != NAMESPACE {
            return self.failed(Arc::new(Fault {
                stage: "completion-original",
                uncertain: true,
                cause: Cause::Protocol(Protocol::OutcomeUnknown),
            }));
        }
        let (_job, result) = completion.into_parts();
        let committed = match result {
            Ok(c) => c,
            Err(e) => return self.failed(disk(e)),
        };
        if committed.namespace() != NAMESPACE
            || pending.expected.checked_add(1) != Some(committed.generation())
        {
            return self.failed(Arc::new(Fault {
                stage: "commit-generation",
                uncertain: true,
                cause: Cause::Protocol(Protocol::OutcomeUnknown),
            }));
        }
        let Some(pending) = self.pending.take() else {
            return self.failed(Arc::new(Fault {
                stage: "lost-original-after-commit",
                uncertain: true,
                cause: Cause::Protocol(Protocol::OutcomeUnknown),
            }));
        };
        if pending.insert {
            self.records.insert(pending.index, pending.record)
        } else {
            self.records[pending.index] = pending.record
        }
        self.evidence = Evidence {
            namespace: committed.namespace(),
            generation: committed.generation(),
            job: Some(pending.job.clone()),
        };
        Event::Committed(Persisted {
            operation: pending.operation,
            job: Some(pending.job),
            stamp: pending.record.stamp,
            evidence: self.evidence.clone(),
            canceled: pending.canceled,
        })
    }
    /// Poll actual original worker result. Canceled waiting futures leave this
    /// state/channel/job cursor intact. No clock/sample can mask a native cause.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Event<'id>>, Error>> {
        if self.ended {
            return Poll::Ready(Ok(None));
        }
        let Some(worker) = self.worker.as_mut() else {
            return Poll::Ready(Err(fault("worker-gone", Protocol::Closed)));
        };
        match worker.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(Some(c))) => Poll::Ready(Ok(Some(self.completion(c)))),
            Poll::Ready(Ok(None)) => {
                self.ended = true;
                if self.pending.is_some() {
                    let error = Arc::new(Fault {
                        stage: "worker-ended-with-original",
                        uncertain: true,
                        cause: Cause::Protocol(Protocol::OutcomeUnknown),
                    });
                    Poll::Ready(Ok(Some(self.failed(error))))
                } else {
                    Poll::Ready(Ok(Some(Event::Ended)))
                }
            }
            Poll::Ready(Err(e)) => {
                let error = Arc::new(Fault {
                    stage: "worker-original-result",
                    uncertain: self.pending.is_some(),
                    cause: Cause::Protocol(e),
                });
                Poll::Ready(Ok(Some(self.failed(error))))
            }
        }
    }
    /// Refuse new intent; retain/drain original admitted job and actual outcome.
    pub fn request_stop(&mut self) {
        self.stopping = true;
        if let Some(worker) = &mut self.worker {
            worker.request_stop()
        }
    }
    /// Actual bounded debt drain + original worker join. Filesystem calls may
    /// block in the kernel; this reports no invented forced deadline/rollback.
    pub async fn shutdown(&mut self, mut observe: impl FnMut(Event<'id>)) -> Shutdown {
        self.request_stop();
        while !self.ended {
            match std::future::poll_fn(|cx| self.poll(cx)).await {
                Ok(Some(e)) => observe(e),
                Ok(None) => {}
                Err(error) => {
                    self.block(error);
                    self.ended = true;
                }
            }
        }
        let worker = match self.worker.as_mut() {
            Some(w) => std::future::poll_fn(|cx| w.poll_join(cx)).await,
            None => Err(Protocol::Closed),
        };
        let validation = worker.as_ref().ok().and_then(|stopped| {
            (stopped.namespace != NAMESPACE
                || (self.first.is_none() && stopped.generation != self.evidence.generation))
                .then(|| {
                    Arc::new(Fault {
                        stage: "joined-worker-provenance",
                        uncertain: true,
                        cause: Cause::Protocol(Protocol::OutcomeUnknown),
                    })
                })
        });
        Shutdown {
            worker,
            validation,
            original: self.first.clone(),
        }
    }
    /// Drain/join and consume this owner, releasing the original fenced Store
    /// after the worker exits. The ordinary File-drop close API has
    /// no independent close errno, and no such success receipt is fabricated.
    pub async fn close(mut self, observe: impl FnMut(Event<'id>)) -> Shutdown {
        self.shutdown(observe).await
    }
    /// Actual original outstanding queue debt, including cancellation or an
    /// admission-time source failure. Never reconstruct an operation from IDs.
    pub fn pending(&self) -> Option<(&Operation<'id>, &Job)> {
        self.pending.as_ref().map(|p| (&p.operation, &p.job))
    }
    /// First actual original failure, independent of shutdown/join errors.
    pub fn failure(&self) -> Option<&Error> {
        self.first.as_ref()
    }
}
impl Drop for Provider<'_> {
    fn drop(&mut self) {
        self.request_stop();
        drop(self.worker.take()); // Shared Worker drains/joins before its fenced Store is released.
    }
}
