//! One caller-driven REGEX server, actual PILS signer and original DHT provider.
//! No provider is replaced, no source task is detached, and no wire ACK exists.
use crate::{Event as HostEvent, Report, Server};
use crate::{
    dht::{self, Provider},
    pils,
};
use gnunet_crypto::EddsaPublicKey;
use gnunet_regex_service::{ClientId, Error as CoreError, JobId, Work};
use gnunet_service_runtime::service::Listener;
use gnunet_types::Error as Fault;
use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
/// Actual native/core/provider errors retain their original source chains.
pub type Failure = Box<dyn Error>;
/// Actual original PILS refusal retained in its typed form.
#[derive(Debug)]
pub struct SigningRefusal(
    /// The original independently verified PILS failure classification.
    pub gnunet_pils::client::Failure,
);
impl fmt::Display for SigningRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "original PILS signature refused: {:?}", self.0)
    }
}
impl Error for SigningRefusal {}
/// Independent bounded coordinator metadata and native signature lifetime.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum live original normal operations; match the pure Core's jobs bound.
    pub operations: usize,
    /// Fixed actual PILS signing lifetime; never extended by polling/reconnect.
    pub signature_lifetime: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            operations: 1024,
            signature_lifetime: Duration::from_secs(300),
        }
    }
}
/// Committed observations, distinct from remote replication or search DONE.
#[must_use = "original backend failures and transport observations must be retained"]
#[expect(
    clippy::large_enum_variant,
    reason = "Return the bounded original PILS loss/completion owner without allocating after native response consumption or retirement"
)]
pub enum Progress<'a> {
    /// Actual local work was admitted to an original provider.
    Submitted,
    /// An actual native or host step occurred.
    Activity,
    /// Actual independent DHT source failure; original readonly jobs survive.
    DhtSourceFailure(Failure),
    /// Actual local original PUT whole-write, separate from remote storage.
    Publication {
        /// Original publication job.
        job: JobId,
        /// Core retirement had already been requested, not logical PUT success.
        retiring: bool,
    },
    /// Actual peer update consumed by the one distributed core.
    Identity(EddsaPublicKey),
    /// Exact original PILS transport observation.
    Pils(gnunet_pils_host::client::Progress<'a, 1>),
    /// The original operation failed after actual local quiescence; only its
    /// original IPC client is requested to close by the pure core.
    BackendFailure {
        /// Original job.
        job: JobId,
        /// Actual independent cause.
        error: Failure,
    },
    /// A real untrusted provider record was refused; the original multi-reply
    /// query remains live unless its explicit finite resource bound closed it.
    Rejected {
        /// Original query.
        job: JobId,
        /// Actual validation/resource cause.
        error: CoreError,
    },
    /// Native observation budget elapsed; no operation is canceled.
    WaitDeadline,
    /// All original host/core/provider/signing owners are actually drained.
    /// Earlier independently returned failures still determine overall success.
    Closed,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Source {
    Pils,
    Dht,
}
struct Operation {
    job: JobId,
    client: ClientId,
    source: Source,
    started: Instant,
    retire: Option<JobId>,
    quiescent: bool,
    released: bool,
}
// One bounded acknowledgment stage. The pure mutation has already committed;
// a later consume refusal must retain its original operation without replay.
enum DhtCommit {
    Reply {
        job: JobId,
        rejected: Option<CoreError>,
    },
    Terminal {
        job: JobId,
        failed: bool,
        retiring: bool,
    },
}
impl DhtCommit {
    fn job(&self) -> &JobId {
        match self {
            Self::Reply { job, .. } | Self::Terminal { job, .. } => job,
        }
    }
}
#[derive(Debug)]
struct Independent {
    first: Failure,
    others: [Option<Failure>; 2],
}
impl fmt::Display for Independent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}; independent guard failures: {:?}",
            self.first, self.others
        )
    }
}
impl Error for Independent {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.first.as_ref())
    }
}
fn guards(errors: [Option<Failure>; 3]) -> Result<(), Failure> {
    let mut live = errors.into_iter().flatten();
    let Some(first) = live.next() else {
        return Ok(());
    };
    let others = [live.next(), live.next()];
    if others.iter().all(Option::is_none) {
        Err(first)
    } else {
        Err(Box::new(Independent { first, others }))
    }
}
/// Fixed cleanup observations from one actual shutdown request. The driver
/// itself retains every original owner if any physical/backend debt remains.
pub struct Shutdown {
    /// Actual local host report when available.
    pub host: Option<Report>,
    /// Independent host, PILS-metadata and original DHT errors.
    pub failures: [Option<Failure>; 3],
    /// Actual state now, never inferred from merely requesting cancellation.
    pub drained: bool,
}
/// Construction refused while preserving every actual original native owner.
/// The caller must close and drive these same parts before releasing their
/// source/storage. No failed allocation can silently discard an active provider.
#[must_use = "original host/signer/provider owners require explicit cleanup"]
pub struct ConstructionFailure<'a, D: Provider> {
    /// The exact original host and pure core.
    pub server: Server,
    /// The exact original PILS client and retained signing work.
    pub signer: pils::Signer<'a, JobId>,
    /// The actual caller-created DHT provider, including any native debt.
    pub dht: D,
    /// Original constructor validation/allocation cause.
    pub error: Failure,
}
/// One movable original owner; all native effects use the Core's opaque jobs.
pub struct Driver<'a, D: Provider> {
    server: Server,
    signer: pils::Signer<'a, JobId>,
    dht: D,
    operations: Vec<Operation>,
    limits: Limits,
    closing: bool,
    failed: bool,
    signer_stopped: bool,
    signature_timer: Option<Pin<Box<Sleep>>>,
    cursor: usize,
    turns: u8,
    observation: Option<Progress<'a>>,
    dht_commit: Option<DhtCommit>,
}
impl<'a, D: Provider> Driver<'a, D> {
    /// Join the actual host and sources. Three original clock Arcs must be the
    /// same authority; this does not create a Resolver, source or native task.
    #[expect(
        clippy::result_large_err,
        reason = "Return actual original native owners after refusal without another allocation that could fail or hide unjoined provider debt"
    )]
    pub fn try_new(
        server: Server,
        signer: pils::Signer<'a, JobId>,
        dht: D,
        limits: Limits,
    ) -> Result<Self, ConstructionFailure<'a, D>> {
        let prepare = (|| -> Result<Vec<Operation>, Failure> {
            if limits.operations == 0
                || limits.operations > 65536
                || limits.signature_lifetime.is_zero()
                || limits.signature_lifetime == Duration::MAX
                || Instant::now()
                    .checked_add(limits.signature_lifetime)
                    .is_none()
                || server.core().pending_jobs() != 0
                || signer.busy()
            {
                return Err(Fault::InvalidInput.into());
            }
            let clock = server.clock();
            if !Arc::ptr_eq(&clock, &signer.clock()) || !Arc::ptr_eq(&clock, &dht.clock()) {
                return Err(Fault::InvalidInput.into());
            }
            let mut operations = Vec::new();
            operations
                .try_reserve_exact(limits.operations)
                .map_err(|error| Box::new(error) as Failure)?;
            Ok(operations)
        })();
        let operations = match prepare {
            Ok(operations) => operations,
            Err(error) => {
                return Err(ConstructionFailure {
                    server,
                    signer,
                    dht,
                    error,
                });
            }
        };
        Ok(Self {
            server,
            signer,
            dht,
            operations,
            limits,
            closing: false,
            failed: false,
            signer_stopped: false,
            signature_timer: None,
            cursor: 0,
            turns: 0,
            observation: None,
            dht_commit: None,
        })
    }
    /// Latest current public identity observation on the actual original PILS
    /// client. This does not sample time or certify remote reachability.
    #[must_use]
    pub fn peer(&self) -> Option<EddsaPublicKey> {
        self.signer.peer()
    }
    /// Inspect this same original DHT provider for factory-specific readiness.
    /// No replacement source, mutable Core access or success proof is created.
    #[must_use]
    pub fn provider(&self) -> &D {
        &self.dht
    }
    /// Readonly cumulative observations from this actual Core allocation.
    /// Sampling these counters performs no native or STATISTICS mutation.
    #[must_use]
    pub fn metrics(&self) -> gnunet_regex_service::Metrics {
        self.server.core().metrics()
    }
    /// Actual local server view, with the same one distributed Core.
    #[must_use]
    pub fn server(&self) -> &Server {
        &self.server
    }
    /// Take an actual transport observation retained independently if a later
    /// clock/core error prevented delivering it in the same poll.
    pub fn take_observation(&mut self) -> Option<Progress<'a>> {
        self.observation.take()
    }
    /// Overall actual local owner quiescence, not remote storage or delivery.
    #[must_use]
    pub fn is_drained(&self) -> bool {
        self.closing
            && self.signer_stopped
            && self.dht.is_closed()
            && self.operations.is_empty()
            && self.dht_commit.is_none()
            && self.server.is_drained()
    }
    fn index(&self, job: &JobId) -> Result<usize, Failure> {
        self.operations
            .iter()
            .position(|operation| operation.job == *job)
            .ok_or_else(|| Fault::Stale.into())
    }
    fn finish_retirements(&mut self) -> Result<bool, Failure> {
        let mut changed = false;
        let mut index = 0;
        while index < self.operations.len() {
            if let Some(retire) = self.operations[index].retire.clone() {
                let stopped = self.operations[index].quiescent
                    || (self.operations[index].source == Source::Dht
                        && self.dht.quiescent(&self.operations[index].job)?);
                if stopped {
                    self.operations[index].quiescent = true;
                    if self.operations[index].source == Source::Dht
                        && !self.operations[index].released
                    {
                        if !self.dht.release(&self.operations[index].job)? {
                            index += 1;
                            continue;
                        }
                        self.operations[index].released = true;
                    }
                    self.server.core_mut().retired(&retire)?;
                    self.operations.swap_remove(index);
                    changed = true;
                    continue;
                }
            }
            index += 1;
        }
        Ok(changed)
    }
    fn dispatch(&mut self) -> Result<Option<Progress<'a>>, Failure> {
        let sign_ready =
            !self.signer_stopped && !self.signer.busy() && self.signer.peer().is_some();
        let Some(work) = self.server.core_mut().next_work_with_sign(sign_ready)? else {
            return Ok(None);
        };
        let started = Instant::now();
        let (job, client, source, get, result) = match work {
            Work::Retire { job, target, .. } => {
                // A completed target may already be absent from the native table;
                // removing it required a real terminal/quiescence observation.
                let Some(index) = self.operations.iter().position(|entry| entry.job == target)
                else {
                    self.server.core_mut().retired(&job)?;
                    return Ok(Some(Progress::Activity));
                };
                if self.operations[index].retire.is_some() {
                    return Err(Fault::Stale.into());
                }
                self.operations[index].retire = Some(job);
                match self.operations[index].source {
                    Source::Pils => {
                        if !self.operations[index].quiescent {
                            self.signer.cancel(&target)?;
                        }
                    }
                    Source::Dht => {
                        if !self.dht.quiescent(&target)? {
                            self.dht.retire(&target)?;
                        }
                    }
                }
                self.finish_retirements()?;
                return Ok(Some(Progress::Activity));
            }
            Work::Sign {
                job,
                client,
                peer,
                material,
            } => {
                if self.operations.len() == self.limits.operations {
                    self.server.core_mut().backend_failed(&job)?;
                    return Ok(Some(Progress::BackendFailure {
                        job,
                        error: Fault::Capacity.into(),
                    }));
                }
                let result = self
                    .signer
                    .submit(job.clone(), EddsaPublicKey::from_bytes(peer), material)
                    .map_err(|(_, error)| Box::new(error) as Failure);
                (job, client, Source::Pils, false, result)
            }
            Work::Put {
                job,
                client,
                key,
                kind,
                options,
                replication,
                expires,
                block,
            } => {
                if self.operations.len() == self.limits.operations {
                    self.server.core_mut().backend_failed(&job)?;
                    return Ok(Some(Progress::BackendFailure {
                        job,
                        error: Fault::Capacity.into(),
                    }));
                }
                let result = self.dht.put(
                    job.clone(),
                    dht::Put {
                        key,
                        kind,
                        options,
                        replication,
                        expires,
                        block,
                    },
                );
                (job, client, Source::Dht, false, result)
            }
            Work::Get {
                job,
                client,
                key,
                kind,
                options,
                replication,
                xquery,
            } => {
                if self.operations.len() == self.limits.operations {
                    self.server.core_mut().backend_failed(&job)?;
                    return Ok(Some(Progress::BackendFailure {
                        job,
                        error: Fault::Capacity.into(),
                    }));
                }
                let result = self.dht.get(
                    job.clone(),
                    dht::Get {
                        key,
                        kind,
                        options,
                        replication,
                        xquery,
                    },
                );
                (job, client, Source::Dht, true, result)
            }
        };
        // The table was reserved in new. Retain original ownership even if a
        // provider error does not establish whether admission happened.
        self.operations.push(Operation {
            job: job.clone(),
            client,
            source,
            started,
            retire: None,
            quiescent: false,
            released: false,
        });
        match result {
            Ok(()) => {
                if get {
                    self.server.core_mut().get_started(&job)?;
                } else if source == Source::Dht {
                    let _diagnostic_counted = self.server.core_mut().put_admitted(&job);
                }
                Ok(Some(Progress::Submitted))
            }
            Err(error) => {
                let quiescent = if source == Source::Pils {
                    true
                } else {
                    match self.dht.quiescent(&job) {
                        Ok(actual) => actual,
                        Err(cleanup) => {
                            return Err(Box::new(Independent {
                                first: error,
                                others: [Some(cleanup), None],
                            }));
                        }
                    }
                };
                if !quiescent {
                    return Err(error);
                }
                let index = self.index(&job)?;
                self.operations[index].quiescent = true;
                if source == Source::Dht {
                    match self.dht.release(&job) {
                        Ok(true) => self.operations[index].released = true,
                        Ok(false) => return Err(error),
                        Err(cleanup) => {
                            return Err(Box::new(Independent {
                                first: error,
                                others: [Some(cleanup), None],
                            }));
                        }
                    }
                }
                if let Err(cleanup) = self.server.core_mut().backend_failed(&job) {
                    return Err(Box::new(Independent {
                        first: error,
                        others: [Some(Box::new(cleanup)), None],
                    }));
                }
                self.operations.swap_remove(index);
                Ok(Some(Progress::BackendFailure { job, error }))
            }
        }
    }
    fn signature_guard(&mut self, cx: &mut Context<'_>) -> Result<(), Failure> {
        let mut earliest = None;
        for operation in self
            .operations
            .iter()
            .filter(|operation| operation.source == Source::Pils && !operation.quiescent)
        {
            let at = operation
                .started
                .checked_add(self.limits.signature_lifetime)
                .ok_or(Fault::Overflow)?;
            earliest = Some(earliest.map_or(at, |old: Instant| old.min(at)));
        }
        if let Some(at) = earliest {
            let timer = self
                .signature_timer
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(at)));
            if timer.deadline() != at {
                timer.as_mut().reset(at);
            }
            let _registered = timer.as_mut().poll(cx);
        } else {
            self.signature_timer = None;
        }
        if self.operations.iter().any(|operation| {
            operation.source == Source::Pils
                && !operation.quiescent
                && operation.started.elapsed() >= self.limits.signature_lifetime
        }) {
            let _original = self.signer.close();
            self.signer_stopped = true;
            for operation in &mut self.operations {
                if operation.source == Source::Pils {
                    operation.quiescent = true;
                }
            }
            return Err(Fault::Deadline.into());
        }
        Ok(())
    }
    fn pils_event(&mut self, event: pils::Event<'a, JobId>) -> Result<Progress<'a>, Failure> {
        match event {
            pils::Event::Identity { peer, .. } => {
                let times = self.server.sample_times()?;
                self.server
                    .core_mut()
                    .set_identity(Some(*peer.as_bytes()), times)?;
                Ok(Progress::Identity(peer))
            }
            pils::Event::Complete { job, result } => {
                let index = self.index(&job)?;
                if self.operations[index].source != Source::Pils {
                    return Err(Fault::Stale.into());
                }
                self.operations[index].quiescent = true;
                if let Some(retire) = &self.operations[index].retire {
                    self.server.core_mut().retired(retire)?;
                    self.operations.swap_remove(index);
                    return Ok(Progress::Activity);
                }
                match result {
                    Ok(signed) => {
                        let times = self.server.sample_times()?;
                        let applied = self.server.core_mut().complete_signature(
                            &job,
                            *signed.peer.as_bytes(),
                            *signed.signature.as_bytes(),
                            times,
                        );
                        if let Err(original) = applied {
                            // Actual original signer has retired, even if core
                            // allocation/validation refused the next publication.
                            self.server.core_mut().backend_failed(&job)?;
                            self.operations.swap_remove(index);
                            return Ok(Progress::BackendFailure {
                                job,
                                error: Box::new(original),
                            });
                        }
                        self.operations.swap_remove(index);
                        Ok(Progress::Activity)
                    }
                    Err(reason) => {
                        self.server.core_mut().backend_failed(&job)?;
                        self.operations.swap_remove(index);
                        Ok(Progress::BackendFailure {
                            job,
                            error: Box::new(SigningRefusal(reason)),
                        })
                    }
                }
            }
            pils::Event::Retired(job) => {
                let index = self.index(&job)?;
                self.operations[index].quiescent = true;
                self.finish_retirements()?;
                Ok(Progress::Activity)
            }
            pils::Event::ResultHeld => Ok(Progress::Activity),
            pils::Event::Transport(gnunet_pils_host::client::Progress::Unavailable(error)) => {
                Err(Box::new(error))
            }
            pils::Event::Transport(progress) => {
                if matches!(
                    &progress,
                    gnunet_pils_host::client::Progress::Connected(_)
                        | gnunet_pils_host::client::Progress::Lost { .. }
                        | gnunet_pils_host::client::Progress::Closed
                ) {
                    self.observation = Some(Progress::Pils(progress));
                    let times = self.server.sample_times()?;
                    self.server.core_mut().set_identity(None, times)?;
                    Ok(self.observation.take().ok_or(Fault::NotReady)?)
                } else {
                    Ok(Progress::Pils(progress))
                }
            }
        }
    }
    fn acknowledge_dht(&mut self) -> Result<Progress<'a>, Failure> {
        let committed = self.dht_commit.as_ref().ok_or(CoreError::Order)?;
        let index = self.index(committed.job())?;
        if self.operations[index].source != Source::Dht {
            return Err(Fault::Stale.into());
        }
        // On Err the Provider retains the exact event. Keep this phase and the
        // original operation; the already successful Core mutation is not run again.
        let original = self.dht.consume()?;
        let committed = self.dht_commit.take().ok_or(CoreError::Order)?;
        match committed {
            DhtCommit::Reply { job, rejected } => {
                if original.is_some() {
                    return Err(CoreError::Order.into());
                }
                Ok(match rejected {
                    Some(error) => Progress::Rejected { job, error },
                    None => Progress::Activity,
                })
            }
            DhtCommit::Terminal {
                job,
                failed,
                retiring,
            } => {
                let progress = if failed {
                    Progress::BackendFailure {
                        job,
                        error: original.ok_or(CoreError::Order)?,
                    }
                } else {
                    if original.is_some() {
                        return Err(CoreError::Order.into());
                    }
                    Progress::Publication { job, retiring }
                };
                self.operations.swap_remove(index);
                Ok(progress)
            }
        }
    }
    fn dht_poll(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(HostEvent),
    ) -> Poll<Result<Progress<'a>, Failure>> {
        let event = match self.dht.poll_next(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(event)) => event,
        };
        if matches!(&event, dht::Event::SourceFailure { .. }) {
            let error = self.dht.consume()?.ok_or(CoreError::Order)?;
            return Poll::Ready(Ok(Progress::DhtSourceFailure(error)));
        }
        let (job, terminal, failed, validation) = match event {
            dht::Event::SourceFailure { .. } => return Poll::Ready(Err(CoreError::Order.into())),
            dht::Event::Rejected { job, error } => (job, false, false, Some(Err(error))),
            dht::Event::PutComplete(job) => (job, true, false, None),
            dht::Event::Failed { job, .. } => (job, true, true, None),
            dht::Event::Reply { job, reply } => {
                let times = match self.server.sample_times() {
                    Ok(now) => now,
                    Err(error) => return Poll::Ready(Err(Box::new(error))),
                };
                let validation = self.server.core_mut().receive(&job, reply, times);
                (job, false, false, Some(validation))
            }
        };
        let result = (|| {
            let index = self.index(&job)?;
            if self.operations[index].source != Source::Dht {
                return Err(Fault::Stale.into());
            }
            let publication_retiring = self.operations[index].retire.is_some();
            if terminal {
                if !self.dht.quiescent(&job)? {
                    return Err(CoreError::Order.into());
                }
                self.operations[index].quiescent = true;
                if let Some(retire) = &self.operations[index].retire {
                    self.server.core_mut().retired(retire)?;
                } else if failed {
                    self.server.core_mut().backend_failed(&job)?;
                } else {
                    self.server.core_mut().put_complete(&job)?;
                }
            }
            if let Some(Err(error)) = validation {
                if self.operations[index].retire.is_none() && error == CoreError::Capacity {
                    let client = self.operations[index].client.clone();
                    self.server.close_client(&client, observe)?;
                }
                self.dht_commit = Some(DhtCommit::Reply {
                    job,
                    rejected: Some(error),
                });
                return self.acknowledge_dht();
            }
            self.dht_commit = Some(if terminal {
                DhtCommit::Terminal {
                    job,
                    failed,
                    retiring: publication_retiring,
                }
            } else {
                DhtCommit::Reply {
                    job,
                    rejected: None,
                }
            });
            self.acknowledge_dht()
        })();
        Poll::Ready(result)
    }
    /// Poll original native bounds before canonical waits, then rotate actual
    /// host/PILS/DHT progress. Errors retain this driver's original owners.
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        wait: Option<Instant>,
        mut observe: impl FnMut(HostEvent),
    ) -> Poll<Result<Progress<'a>, Failure>> {
        if let Some(event) = self.observation.take() {
            return Poll::Ready(Ok(event));
        }
        let host_guard = self.server.poll_native_guard(cx, &mut observe);
        let dht_guard = if self.dht.is_closed() {
            Ok(false)
        } else {
            self.dht.poll_native_guard(cx)
        };
        let signature_guard = self.signature_guard(cx);
        let changed = host_guard.as_ref().is_ok_and(|p| *p) || dht_guard.as_ref().is_ok_and(|p| *p);
        guards([
            host_guard.err().map(|e| Box::new(e) as Failure),
            dht_guard.err(),
            signature_guard.err(),
        ])?;
        // A committed original receipt needs no new canonical clock sample.
        // Native guards still run first; consume acknowledgment precedes Core
        // dispatch, retirement and any outer observation deadline.
        if self.dht_commit.is_some() {
            return Poll::Ready(self.acknowledge_dht());
        }
        let retired = self.finish_retirements()?;
        let reaped = self.server.reap(&mut observe)?;
        if self.is_drained() {
            return Poll::Ready(Ok(Progress::Closed));
        }
        if wait.is_some_and(|at| Instant::now() >= at) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        if let Some(progress) = self.dispatch()? {
            return Poll::Ready(Ok(progress));
        }
        for offset in 0..3 {
            let selected = (self.cursor + offset) % 3;
            let event = match selected {
                0 if !self.server.is_drained() => self
                    .server
                    .poll(cx, listeners, wait, &mut observe)
                    .map(|r| {
                        r.map(|progress| match progress {
                            crate::Progress::WaitDeadline => Progress::WaitDeadline,
                            _ => Progress::Activity,
                        })
                        .map_err(|e| Box::new(e) as Failure)
                    }),
                1 if !self.signer_stopped => match self.signer.poll(cx, wait) {
                    Poll::Ready(Ok(event)) => Poll::Ready(self.pils_event(event)),
                    Poll::Ready(Err(error)) => Poll::Ready(Err(Box::new(error) as Failure)),
                    Poll::Pending => Poll::Pending,
                },
                2 if !self.dht.is_closed() => self.dht_poll(cx, &mut observe),
                _ => Poll::Pending,
            };
            if event.is_ready() {
                self.cursor = (selected + 1) % 3;
                return event;
            }
        }
        if changed || retired || reaped {
            Poll::Ready(Ok(Progress::Activity))
        } else {
            Poll::Pending
        }
    }
    /// Poll the actual owner. A fatal error latches before returning: only
    /// stop/drain may follow, so an uncertain event-consume failure cannot replay
    /// a committed core mutation or resubmit the original publication.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        wait: Option<Instant>,
        observe: impl FnMut(HostEvent),
    ) -> Poll<Result<Progress<'a>, Failure>> {
        if self.failed && !self.closing {
            return Poll::Ready(Err(Fault::Closed.into()));
        }
        let result = self.poll_inner(cx, listeners, wait, observe);
        if matches!(&result, Poll::Ready(Err(_))) {
            self.failed = true;
        }
        result
    }
    /// Wait on this same polled owner. Every64 turns yield before new effects so
    /// zero-delay announcements cannot monopolize a current-thread scheduler.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        wait: Option<Instant>,
        mut observe: impl FnMut(HostEvent),
    ) -> Result<Progress<'a>, Failure> {
        self.turns = self.turns.wrapping_add(1);
        if self.turns.is_multiple_of(64) {
            tokio::task::yield_now().await;
        }
        poll_fn(|cx| self.poll(cx, listeners, wait, &mut observe)).await
    }
    /// Stop real IPC sources, original PILS cursors and the original DHT source
    /// independently. No canonical time sample is needed. Continue driving this
    /// same owner until Closed; a request alone never releases backend debts.
    pub fn stop(&mut self, mut observe: impl FnMut(HostEvent)) -> Shutdown {
        self.closing = true;
        let host = self.server.close_all(&mut observe);
        let _original = self.signer.close();
        self.signer_stopped = true;
        self.signature_timer = None;
        for operation in &mut self.operations {
            if operation.source == Source::Pils {
                operation.quiescent = true;
            }
        }
        let dht = self.dht.close();
        let failures = [None, None, dht.err()];
        let (host, host_error) = match host {
            Ok(report) => (Some(report), None),
            Err(error) => (None, Some(Box::new(error) as Failure)),
        };
        let mut failures = failures;
        failures[0] = host_error;
        Shutdown {
            host,
            failures,
            drained: self.is_drained(),
        }
    }
}
impl<D: Provider> Drop for Driver<'_, D> {
    fn drop(&mut self) {
        let _actual_host = self.server.close_all(|_| {});
        let _original = self.signer.close();
        let _actual_dht = self.dht.close();
    }
}
