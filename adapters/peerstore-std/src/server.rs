//! Caller-driven actual PEERSTORE IPC, one original immutable output per MQ.
//! An explicitly started bounded worker owns every storage syscall. Socket poll
//! only admits jobs/receives original completions; partial cursors survive waits.
use crate::worker::{self, Command, Completion, Job, ResultData, Worker};
use gnunet_peerstore::{self as core, Request};
use gnunet_service_runtime::{
    accepted::{AcceptState, AcceptedConnection, SocketEvent},
    clock::{ClockSubscription, RuntimeClock},
    credentials::UnixAccess,
    framing::{Accounting, Budget, Class, Framed, Limits as FrameLimits, OwnedFrame, ReadStep},
    service::{Listener, PeerAddress, ServiceOptions, ShutdownMode},
};
use gnunet_types::Error as ProtocolError;
use std::{
    fmt,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::{Duration, Instant, Sleep};
/// Actual native or protocol failure, retaining the original IO cause.
#[derive(Debug)]
pub enum Error {
    /// Original native error.
    Io(io::Error),
    /// Protocol/storage classification. Backend retains native cause.
    Protocol(ProtocolError),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => e.fmt(f),
            Self::Protocol(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Protocol(e) => Some(e),
        }
    }
}
impl From<ProtocolError> for Error {
    fn from(e: ProtocolError) -> Self {
        Self::Protocol(e)
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
/// Actual reason for stopping this original physical source.
#[derive(Debug)]
pub enum CloseCause {
    /// Explicit caller stop.
    Requested,
    /// Clean native EOF.
    Eof,
    /// Original failure.
    Fault(Error),
    /// Explicit service shutdown.
    Shutdown,
}
/// Synchronous committed observations. Callbacks cannot reenter this borrowed owner.
#[derive(Debug)]
pub enum Event<'id> {
    /// Native socket option/accept diagnostic.
    Socket(SocketEvent),
    /// Unadmitted original source refused by ACL/credentials.
    Rejected(PeerAddress),
    /// Actual physical source admitted, no peer authentication.
    Accepted(core::Client<'id>),
    /// Complete official input accepted.
    Input(core::Client<'id>),
    /// Original immutable output admitted by its actual MQ.
    Queued(core::Output<'id>),
    /// Actual positive native frame progress.
    Write {
        /// Original output.
        output: core::Output<'id>,
        /// Actual positive bytes.
        bytes: usize,
        /// Actual full-frame write.
        complete: bool,
    },
    /// Actual socket stopped before logical detach.
    Closed {
        /// Original pending/exposure/store uncertainty.
        loss: core::Loss<'id>,
        /// Original reason, independently retained.
        cause: CloseCause,
    },
    /// Actual unadmitted stream is already stopped.
    AdmissionFailed(Error),
    /// Original admitted storage job completed on the actual worker.
    Storage {
        /// Original private worker job.
        job: Job,
        /// Original source, absent only for maintenance.
        client: Option<core::Client<'id>>,
        /// Actual failure classification, if any.
        failure: Option<ProtocolError>,
    },
}
/// One bounded reactor result. WaitDeadline cancels observation only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// One actual operation progressed.
    Activity,
    /// Caller wait elapsed; original work remains.
    WaitDeadline,
    /// All local sources actually stopped after shutdown.
    Stopped,
}
/// Fixed actual MQ and syscall budgets, independent of database quota.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum physical accepted MQ owners.
    pub clients: usize,
    /// Per-syscall read/write prefix cap.
    pub io_slice_bytes: usize,
    /// Explicit relative expiry-maintenance interval.
    pub maintenance_interval: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            clients: 16,
            io_slice_bytes: 65535,
            maintenance_interval: Duration::from_secs(300),
        }
    }
}
/// Actual local counters, without application consumption claims.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report {
    /// Actually attached physical sources.
    pub accepted: u64,
    /// Actually stopped physical sources.
    pub closed: u64,
    /// Complete official inputs accepted.
    pub inputs: u64,
    /// Positive original native bytes written.
    pub written_bytes: u64,
    /// Complete original native frames written.
    pub written_frames: u64,
    /// Records actually expired by committed maintenance.
    pub expired: u64,
    /// Actual storage commands admitted by the explicit bounded worker.
    pub storage_submitted: u64,
    /// Actual original storage completions received.
    pub storage_received: u64,
    /// Original unknown storage outcomes, never rewritten as known failures.
    pub storage_unknown: u64,
}
struct Peer<'id> {
    client: core::Client<'id>,
    io: Framed<core::Output<'id>>,
    held: Option<(OwnedFrame, core::Output<'id>)>,
    cursor: usize,
}
#[derive(Clone, Copy)]
enum Effect<'id> {
    Store(core::Store<'id>),
    Scan(core::Scan<'id>),
    Expire,
}
impl<'id> Effect<'id> {
    fn client(self) -> Option<core::Client<'id>> {
        match self {
            Self::Store(s) => Some(s.client()),
            Self::Scan(s) => Some(s.client()),
            Self::Expire => None,
        }
    }
}
struct Work<'id> {
    job: Job,
    effect: Effect<'id>,
    ready: Option<Completion>,
}
/// Independent local-source cleanup and actual original worker join facts.
#[derive(Debug)]
pub struct Shutdown {
    /// Actual local counters.
    pub report: Report,
    /// Original joined worker outcome; None is never quiescence.
    pub worker: Option<worker::Stopped>,
    /// First independent cleanup/join refusal.
    pub failure: Option<Error>,
}
/// One actual service, fixed metadata/slabs borrowed independently from backend.
pub struct Server<'id, 'slots, 'bytes, 'worker> {
    core: core::Service<'id, 'slots, 'bytes>,
    worker: &'worker mut Worker,
    jobs: Vec<Option<Work<'id>>>,
    job_cursor: usize,
    worker_ended: bool,
    peers: Vec<Option<Peer<'id>>>,
    limits: Limits,
    options: ServiceOptions,
    unix: UnixAccess,
    accept: AcceptState,
    cursor: usize,
    class: usize,
    listener_cursor: usize,
    clock: Arc<dyn RuntimeClock>,
    subscription: Box<dyn ClockSubscription>,
    revision: u64,
    next_maintenance: Instant,
    timer: Pin<Box<Sleep>>,
    shutdown: Option<ShutdownMode>,
    report: Report,
}
impl<'id, 'slots, 'bytes, 'worker> Server<'id, 'slots, 'bytes, 'worker> {
    /// Construct finite ownership, without opening listeners/files or tasks.
    pub fn new(
        core: core::Service<'id, 'slots, 'bytes>,
        worker: &'worker mut Worker,
        limits: Limits,
        options: ServiceOptions,
        unix: UnixAccess,
        clock: Arc<dyn RuntimeClock>,
    ) -> Result<Self, Error> {
        if limits.clients == 0
            || limits.io_slice_bytes == 0
            || limits.maintenance_interval.is_zero()
            || Instant::now()
                .checked_add(limits.maintenance_interval)
                .is_none()
            || core.client_capacity() < limits.clients
            || worker.capacity()
                < limits
                    .clients
                    .checked_add(1)
                    .ok_or(ProtocolError::Overflow)?
        {
            return Err(ProtocolError::InvalidInput.into());
        }
        let mut peers = Vec::new();
        peers
            .try_reserve_exact(limits.clients)
            .map_err(|_| ProtocolError::Capacity)?;
        peers.resize_with(limits.clients, || None);
        let mut jobs = Vec::new();
        jobs.try_reserve_exact(worker.capacity())
            .map_err(|_| ProtocolError::Capacity)?;
        jobs.resize_with(worker.capacity(), || None);
        let subscription = clock.subscribe()?;
        let revision = clock.sample()?.revision;
        Ok(Self {
            core,
            worker,
            jobs,
            job_cursor: 0,
            worker_ended: false,
            peers,
            limits,
            options,
            unix,
            accept: AcceptState::default(),
            cursor: 0,
            class: 0,
            listener_cursor: 0,
            clock,
            subscription,
            revision,
            next_maintenance: Instant::now(),
            timer: Box::pin(tokio::time::sleep(Duration::ZERO)),
            shutdown: None,
            report: Report::default(),
        })
    }
    /// Actual source/output/maintenance counters.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.report
    }
    /// Shared original clock, without a new listener.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    fn framing(&self) -> FrameLimits {
        FrameLimits {
            frame_bytes: self.core.record_capacity(),
            ordinary: Budget {
                frames: 1,
                bytes: self.core.record_capacity(),
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.limits.io_slice_bytes,
        }
    }
    /// Admit only an actual canonical accepted connection after original ACL and
    /// kernel credential checks; no handshake or peer-key permission is invented.
    pub fn admit(
        &mut self,
        accepted: AcceptedConnection,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<Option<core::Client<'id>>, Error> {
        let (connection, address, diagnostics) = accepted.into_parts();
        for d in diagnostics {
            observe(Event::Socket(SocketEvent::Diagnostic(d)))
        }
        let allowed = match address {
            PeerAddress::Tcp(p) => self.options.access.allows(p.ip()),
            PeerAddress::Unix => self.unix.allows(&connection)?,
        };
        if !allowed {
            drop(connection);
            observe(Event::Rejected(address));
            return Ok(None);
        }
        if self.shutdown.is_some() {
            drop(connection);
            return Err(ProtocolError::Closed.into());
        }
        let i = self
            .peers
            .iter()
            .position(Option::is_none)
            .ok_or(ProtocolError::Capacity)?;
        let mut io = Framed::new(connection, self.framing())?;
        let client = match self.core.attach() {
            Ok(c) => c,
            Err(e) => {
                io.retire();
                return Err(e.into());
            }
        };
        self.peers[i] = Some(Peer {
            client,
            io,
            held: None,
            cursor: 0,
        });
        self.report.accepted = self.report.accepted.saturating_add(1);
        observe(Event::Accepted(client));
        Ok(Some(client))
    }
    fn stop(
        &mut self,
        index: usize,
        cause: CloseCause,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<core::Loss<'id>, Error> {
        let mut p = self.peers[index]
            .take()
            .ok_or(ProtocolError::StaleGeneration)?;
        p.io.retire();
        drop(p.held.take());
        self.accept.client_closed();
        let loss = self.core.detach(p.client)?;
        self.report.closed = self.report.closed.saturating_add(1);
        observe(Event::Closed { loss, cause });
        Ok(loss)
    }
    /// Actual physical stop before pure source retirement; no clock is required.
    pub fn close(
        &mut self,
        client: core::Client<'id>,
        cause: CloseCause,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<core::Loss<'id>, Error> {
        let i = self
            .peers
            .iter()
            .position(|p| p.as_ref().is_some_and(|p| p.client == client))
            .ok_or(ProtocolError::StaleGeneration)?;
        self.stop(i, cause, observe)
    }
    /// Independent actual cleanup of every original MQ, even on clock/storage
    /// fault. Original committed/unknown stores are never replayed or rolled back.
    pub fn close_all(&mut self, observe: &mut impl FnMut(Event<'id>)) -> Result<(), Error> {
        self.shutdown = Some(ShutdownMode::Immediate);
        self.worker.request_stop();
        let mut first = None;
        for i in 0..self.peers.len() {
            if self.peers[i].is_some()
                && let Err(e) = self.stop(i, CloseCause::Shutdown, observe)
                && first.is_none()
            {
                first = Some(e)
            }
        }
        match first {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
    /// Explicit service lifetime. Soft waits for actual sources to close.
    pub fn request_shutdown(&mut self, mode: ShutdownMode) {
        if self.shutdown != Some(ShutdownMode::Immediate) {
            self.shutdown = Some(mode)
        }
    }
    fn peer(
        &mut self,
        cx: &mut Context<'_>,
        index: usize,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        if self.shutdown == Some(ShutdownMode::Immediate)
            || (self.shutdown == Some(ShutdownMode::Soft)
                && self.core.is_monitor(
                    self.peers[index]
                        .as_ref()
                        .ok_or(ProtocolError::StaleGeneration)?
                        .client,
                )?)
        {
            return Poll::Ready(
                self.stop(index, CloseCause::Shutdown, observe)
                    .map(|_| Progress::Activity),
            );
        }
        let cursor = self.peers[index]
            .as_ref()
            .ok_or(ProtocolError::StaleGeneration)?
            .cursor;
        for n in 0..3 {
            let class = (cursor + n) % 3;
            let p = self.peers[index]
                .as_mut()
                .ok_or(ProtocolError::StaleGeneration)?;
            let result = match class {
                0 => match p.io.poll_write(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(e)) => Poll::Ready(
                        self.stop(index, CloseCause::Fault(e.into()), observe)
                            .map(|_| Progress::Activity),
                    ),
                    Poll::Ready(Ok(w)) => {
                        self.core.exposed(w.origin)?;
                        if w.complete {
                            self.core.written(w.origin)?;
                            self.report.written_frames =
                                self.report.written_frames.saturating_add(1)
                        }
                        self.report.written_bytes =
                            self.report.written_bytes.saturating_add(w.bytes as u64);
                        observe(Event::Write {
                            output: w.origin,
                            bytes: w.bytes,
                            complete: w.complete,
                        });
                        Poll::Ready(Ok(Progress::Activity))
                    }
                },
                1 => {
                    if let Some(bytes) = p.io.frame() {
                        if self
                            .jobs
                            .iter()
                            .flatten()
                            .any(|j| j.effect.client() == Some(p.client))
                        {
                            continue;
                        }
                        let result = match Request::decode(bytes) {
                            Ok(Request::Store(e)) => {
                                if self
                                    .jobs
                                    .iter()
                                    .flatten()
                                    .any(|j| j.effect.client() == Some(p.client))
                                    || !self.worker.available()
                                {
                                    continue;
                                }
                                let Some(slot) = self.jobs.iter().position(Option::is_none) else {
                                    continue;
                                };
                                let n = Request::Store(e).encoded_len()?;
                                let mut original = Vec::new();
                                original
                                    .try_reserve_exact(n)
                                    .map_err(|_| ProtocolError::Capacity)?;
                                original.resize(n, 0);
                                Request::Store(e).encode(&mut original)?;
                                match self.core.begin_store(p.client, e) {
                                    Err(reason) => Err(reason),
                                    Ok(effect) => {
                                        match self.worker.submit(Command::Store(original)) {
                                            Ok(job) => {
                                                self.jobs[slot] = Some(Work {
                                                    job,
                                                    effect: Effect::Store(effect),
                                                    ready: None,
                                                });
                                                self.report.storage_submitted =
                                                    self.report.storage_submitted.saturating_add(1);
                                                Ok(())
                                            }
                                            Err(error) => {
                                                self.core.store_unsubmitted(effect)?;
                                                Err(error)
                                            }
                                        }
                                    }
                                }
                            }
                            Ok(r) => self.core.receive_control(p.client, r),
                            Err(ProtocolError::Unsupported) if self.options.tolerant => Ok(()),
                            Err(e) => Err(e),
                        };
                        match result {
                            Ok(()) => {
                                p.io.release_frame();
                                self.report.inputs = self.report.inputs.saturating_add(1);
                                observe(Event::Input(p.client));
                                Poll::Ready(Ok(Progress::Activity))
                            }
                            Err(ProtocolError::WouldBlock) => Poll::Pending,
                            Err(ProtocolError::OutcomeUnknown) => {
                                return Poll::Ready(Err(ProtocolError::OutcomeUnknown.into()));
                            }
                            Err(e) => Poll::Ready(
                                self.stop(index, CloseCause::Fault(e.into()), observe)
                                    .map(|_| Progress::Activity),
                            ),
                        }
                    } else {
                        match p.io.poll_read(cx) {
                            Poll::Pending => Poll::Pending,
                            Poll::Ready(Ok(ReadStep::Progress { .. })) => {
                                Poll::Ready(Ok(Progress::Activity))
                            }
                            Poll::Ready(Ok(ReadStep::Eof)) => Poll::Ready(
                                self.stop(index, CloseCause::Eof, observe)
                                    .map(|_| Progress::Activity),
                            ),
                            Poll::Ready(Err(e)) => Poll::Ready(
                                self.stop(index, CloseCause::Fault(e.into()), observe)
                                    .map(|_| Progress::Activity),
                            ),
                        }
                    }
                }
                _ => {
                    if p.io.queued_frames() != 0 {
                        Poll::Pending
                    } else {
                        let outgoing = if let Some(pair) = p.held.take() {
                            Some(pair)
                        } else {
                            let Some(prepared) = self.core.output(p.client)? else {
                                continue;
                            };
                            p.io.reserve(prepared.bytes.len(), Class::Ordinary)?;
                            let mut bytes = Vec::new();
                            if bytes.try_reserve_exact(prepared.bytes.len()).is_err() {
                                return Poll::Ready(
                                    self.stop(
                                        index,
                                        CloseCause::Fault(ProtocolError::Capacity.into()),
                                        observe,
                                    )
                                    .map(|_| Progress::Activity),
                                );
                            }
                            bytes.extend_from_slice(prepared.bytes);
                            Some((OwnedFrame::new(bytes), prepared.output))
                        };
                        if let Some((frame, output)) = outgoing {
                            match p.io.enqueue_owned(frame, output, Class::Ordinary) {
                                Ok(()) => {
                                    self.core.queued(output)?;
                                    observe(Event::Queued(output));
                                    Poll::Ready(Ok(Progress::Activity))
                                }
                                Err(rejected) => {
                                    let reason = rejected.reason;
                                    p.held = Some(rejected.value);
                                    if matches!(
                                        reason,
                                        ProtocolError::Capacity | ProtocolError::WouldBlock
                                    ) {
                                        Poll::Pending
                                    } else {
                                        Poll::Ready(
                                            self.stop(
                                                index,
                                                CloseCause::Fault(reason.into()),
                                                observe,
                                            )
                                            .map(|_| Progress::Activity),
                                        )
                                    }
                                }
                            }
                        } else {
                            Poll::Pending
                        }
                    }
                }
            };
            if result.is_ready() {
                if let Some(p) = self.peers[index].as_mut() {
                    p.cursor = (class + 1) % 3
                }
                return result;
            }
        }
        Poll::Pending
    }
    fn submit_scan(&mut self) -> Result<bool, Error> {
        if !self.worker.available() {
            return Ok(false);
        }
        let Some(slot) = self.jobs.iter().position(Option::is_none) else {
            return Ok(false);
        };
        let Some(request) = self.core.scan_request() else {
            return Ok(false);
        };
        let scan = request.scan;
        if self
            .jobs
            .iter()
            .flatten()
            .any(|j| j.effect.client() == Some(scan.client()))
        {
            return Ok(false);
        }
        let request = Request::IterateStart(core::Iteration {
            rid: 0,
            filter: request.filter,
            reserved: 0,
        });
        let n = request.encoded_len()?;
        let mut query = Vec::new();
        query
            .try_reserve_exact(n)
            .map_err(|_| ProtocolError::Capacity)?;
        query.resize(n, 0);
        request.encode(&mut query)?;
        self.core.scan_started(scan)?;
        match self.worker.submit(Command::Scan {
            query,
            after: scan.after(),
        }) {
            Ok(job) => {
                self.jobs[slot] = Some(Work {
                    job,
                    effect: Effect::Scan(scan),
                    ready: None,
                });
                self.report.storage_submitted = self.report.storage_submitted.saturating_add(1);
                Ok(true)
            }
            Err(e) => {
                self.core.scan_unsubmitted(scan)?;
                Err(e.into())
            }
        }
    }
    fn apply_work(
        &mut self,
        index: usize,
        observe: &mut impl FnMut(Event<'id>),
        stopping: bool,
    ) -> Result<bool, Error> {
        let work = self.jobs[index]
            .as_ref()
            .ok_or(ProtocolError::StaleGeneration)?;
        let Some(completion) = work.ready.as_ref() else {
            return Ok(false);
        };
        if completion.job() != &work.job {
            return Err(ProtocolError::StaleGeneration.into());
        }
        let failure = match &completion.data {
            ResultData::Store { result, .. } => result.as_ref().err().copied(),
            ResultData::Scan(result) => result.as_ref().err().copied(),
            ResultData::Expire(result) => result.as_ref().err().copied(),
        };
        let result = match (work.effect, &completion.data) {
            (Effect::Store(effect), ResultData::Store { request, result }) => {
                let Request::Store(e) = Request::decode(request)? else {
                    return Err(ProtocolError::StaleGeneration.into());
                };
                match self.core.complete_store(effect, e.record, *result) {
                    Err(ProtocolError::StaleGeneration) => {
                        if result.is_ok() {
                            self.core.committed_after_loss(e.record)
                        } else {
                            Ok(())
                        }
                    }
                    other => other,
                }
            }
            (Effect::Scan(scan), ResultData::Scan(result)) => {
                let row = match result {
                    Ok(Some(row)) => {
                        let core::Response::Record(e) = core::Response::decode(&row.frame)? else {
                            return Err(ProtocolError::StaleGeneration.into());
                        };
                        Ok(Some(core::Row {
                            sequence: row.sequence,
                            record: e.record,
                        }))
                    }
                    Ok(None) => Ok(None),
                    Err(e) => Err(*e),
                };
                match self.core.complete_scan(scan, row) {
                    Err(ProtocolError::StaleGeneration) => Ok(()),
                    other => other,
                }
            }
            (Effect::Expire, ResultData::Expire(result)) => {
                if let Ok(n) = result {
                    self.report.expired = self.report.expired.saturating_add(*n)
                }
                Ok(())
            }
            _ => return Err(ProtocolError::StaleGeneration.into()),
        };
        if result == Err(ProtocolError::WouldBlock) {
            // One original frame is this MQ's declared retained-output budget.
            // A completed scan cannot block later worker receipts globally or
            // silently spend monitor credit: explicitly retire this full source.
            if let Some(client) = work.effect.client() {
                self.close(
                    client,
                    CloseCause::Fault(ProtocolError::Capacity.into()),
                    observe,
                )?;
                return Ok(true);
            }
            return Err(ProtocolError::Capacity.into());
        }
        let work = self.jobs[index]
            .take()
            .ok_or(ProtocolError::StaleGeneration)?;
        if failure == Some(ProtocolError::OutcomeUnknown) {
            self.report.storage_unknown = self.report.storage_unknown.saturating_add(1);
            self.shutdown = Some(ShutdownMode::Immediate);
            self.worker.request_stop();
        }
        observe(Event::Storage {
            job: work.job,
            client: work.effect.client(),
            failure,
        });
        match result {
            Err(ProtocolError::OutcomeUnknown) if stopping => Ok(true),
            Err(e) => Err(e.into()),
            Ok(()) => {
                if failure == Some(ProtocolError::OutcomeUnknown) && !stopping {
                    Err(ProtocolError::OutcomeUnknown.into())
                } else {
                    Ok(true)
                }
            }
        }
    }
    fn poll_worker(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'id>),
        stopping: bool,
    ) -> Poll<Result<Progress, Error>> {
        for n in 0..self.jobs.len() {
            let i = (self.job_cursor + n) % self.jobs.len();
            if self.jobs[i].as_ref().is_some_and(|w| w.ready.is_some())
                && self.apply_work(i, observe, stopping)?
            {
                self.job_cursor = (i + 1) % self.jobs.len();
                return Poll::Ready(Ok(Progress::Activity));
            }
        }
        if self.worker_ended {
            return Poll::Pending;
        }
        match self.worker.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => {
                if stopping {
                    self.worker_ended = true;
                    self.report.storage_unknown = self
                        .report
                        .storage_unknown
                        .saturating_add(self.jobs.iter().flatten().count() as u64);
                    self.jobs.iter_mut().for_each(|j| *j = None);
                }
                Poll::Ready(Err(e.into()))
            }
            Poll::Ready(Ok(None)) => {
                self.worker_ended = true;
                Poll::Ready(Ok(Progress::Activity))
            }
            Poll::Ready(Ok(Some(completion))) => {
                let i = self
                    .jobs
                    .iter()
                    .position(|w| w.as_ref().is_some_and(|w| &w.job == completion.job()))
                    .ok_or(ProtocolError::StaleGeneration)?;
                self.report.storage_received = self.report.storage_received.saturating_add(1);
                self.jobs[i]
                    .as_mut()
                    .ok_or(ProtocolError::StaleGeneration)?
                    .ready = Some(completion);
                self.apply_work(i, observe, stopping)?;
                Poll::Ready(Ok(Progress::Activity))
            }
        }
    }
    /// Stop every local source independently, drain original admitted disk jobs,
    /// then join that original explicit worker. No clock or new task is needed.
    pub async fn shutdown(&mut self, mut observe: impl FnMut(Event<'id>)) -> Shutdown {
        let mut failure = self.close_all(&mut observe).err();
        while !self.worker_ended {
            if let Err(e) = poll_fn(|cx| self.poll_worker(cx, &mut observe, true)).await
                && failure.is_none()
            {
                failure = Some(e)
            }
        }
        for n in 0..self.jobs.len() {
            if self.jobs[n].is_some()
                && let Err(e) = self.apply_work(n, &mut observe, true)
                && failure.is_none()
            {
                failure = Some(e)
            }
        }
        let worker = match poll_fn(|cx| self.worker.poll_join(cx)).await {
            Ok(stopped) => Some(stopped),
            Err(e) => {
                if failure.is_none() {
                    failure = Some(e.into())
                }
                None
            }
        };
        Shutdown {
            report: self.report,
            worker,
            failure,
        }
    }
    fn accept(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        if self.shutdown.is_some() || !self.accept.ready() || self.peers.iter().all(Option::is_some)
        {
            return Poll::Pending;
        }
        for n in 0..listeners.len() {
            let i = (self.listener_cursor + n) % listeners.len();
            match listeners[i].poll_canonical_connection(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(e)) => {
                    self.listener_cursor = (i + 1) % listeners.len();
                    observe(Event::Socket(self.accept.failed(e)));
                    return Poll::Ready(Ok(Progress::Activity));
                }
                Poll::Ready(Ok(a)) => {
                    self.listener_cursor = (i + 1) % listeners.len();
                    if let Err(e) = self.admit(a, observe) {
                        observe(Event::AdmissionFailed(e))
                    }
                    return Poll::Ready(Ok(Progress::Activity));
                }
            }
        }
        Poll::Pending
    }
    /// One bounded fair source/scan/accept/maintenance effect. All original
    /// partial bytes remain owned across cancellation of the waiting future.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        deadline: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        if self.shutdown.is_some() && self.peers.iter().all(Option::is_none) {
            return Poll::Ready(Ok(Progress::Stopped));
        }
        if let Some((client, reason)) = self.core.fault() {
            self.close(client, CloseCause::Fault(reason.into()), observe)?;
            return Poll::Ready(Ok(Progress::Activity));
        }
        if self.shutdown != Some(ShutdownMode::Immediate) {
            match self.subscription.poll_changed(cx, self.revision) {
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Ready(Ok(s)) => self.revision = s.revision,
                Poll::Pending => {}
            }
        }
        // An accepted no-iteration MONITOR_START owes its original SYNC
        // before any later storage completion can notify live records. Keep
        // that bounded preparation ahead of the rotating business classes.
        // A blocked source retains the barrier; core notify faults that exact
        // slow monitor instead of crossing it or blocking worker retirement.
        if self.shutdown != Some(ShutdownMode::Immediate) && self.core.progress()? {
            return Poll::Ready(Ok(Progress::Activity));
        }
        for n in 0..5 {
            let class = (self.class + n) % 5;
            let result = match class {
                0 if self.shutdown != Some(ShutdownMode::Immediate) => {
                    if self.submit_scan()? {
                        Poll::Ready(Ok(Progress::Activity))
                    } else {
                        Poll::Pending
                    }
                }
                1 => {
                    let mut result = Poll::Pending;
                    for n in 0..self.peers.len() {
                        let i = (self.cursor + n) % self.peers.len();
                        if self.peers[i].is_none() {
                            continue;
                        }
                        let p = self.peer(cx, i, observe);
                        if p.is_ready() {
                            self.cursor = (i + 1) % self.peers.len();
                            result = p;
                            break;
                        }
                    }
                    result
                }
                2 => self.accept(cx, listeners, observe),
                3 if self.shutdown != Some(ShutdownMode::Immediate)
                    && Instant::now() >= self.next_maintenance =>
                {
                    if !self.worker.available()
                        || self
                            .jobs
                            .iter()
                            .flatten()
                            .any(|j| matches!(j.effect, Effect::Expire))
                    {
                        Poll::Pending
                    } else {
                        let Some(slot) = self.jobs.iter().position(Option::is_none) else {
                            return Poll::Pending;
                        };
                        let sample = self.clock.sample()?;
                        self.revision = sample.revision;
                        let job = self
                            .worker
                            .submit(Command::Expire(sample.now.as_micros()))?;
                        self.jobs[slot] = Some(Work {
                            job,
                            effect: Effect::Expire,
                            ready: None,
                        });
                        self.report.storage_submitted =
                            self.report.storage_submitted.saturating_add(1);
                        self.next_maintenance = Instant::now()
                            .checked_add(self.limits.maintenance_interval)
                            .ok_or(ProtocolError::Overflow)?;
                        Poll::Ready(Ok(Progress::Activity))
                    }
                }
                4 => self.poll_worker(cx, observe, false),
                _ => Poll::Pending,
            };
            if result.is_ready() {
                self.class = (class + 1) % 5;
                return result;
            }
        }
        let maintenance = (self.next_maintenance > Instant::now()
            && self.shutdown != Some(ShutdownMode::Immediate))
        .then_some(self.next_maintenance);
        if let Some(at) = deadline.into_iter().chain(maintenance).min() {
            self.timer.as_mut().reset(at);
            if self.timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref()
            }
        }
        Poll::Pending
    }
    /// Cancellation-safe caller-driven wait, no spawned task.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        deadline: Option<Instant>,
        mut observe: impl FnMut(Event<'id>),
    ) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll(cx, listeners, deadline, &mut observe)).await
    }
}
