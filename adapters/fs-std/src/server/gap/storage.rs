//! Explicit native DATASTORE cache/replication/advertisement port and shared resolver.
//! No Index/WAL, worker, resolver service, task, retry mutation or private wire.
use super::super::{IndexResolver, Resolution, cadet_server::source};
use gnunet_datastore_host::{self as ds, Client, Interruption, Operation, Outcome, Step};
use gnunet_fs::gap::{self as gap, storage as pure};
use gnunet_service_runtime::{clock::RuntimeClock, framing::OwnedFrame};
use gnunet_types::{Duration as Timeout, Error};
use gnunet_wire::official::datastore::{Request, Response};
use std::{
    error::Error as StdError,
    fmt,
    future::Future,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::Instant;
/// Original actual port/source failure, retaining native certainty and cause.
pub type Failure = Box<dyn StdError + Send + Sync>;
/// Original native terminal, including a real late reply and interrupted outcome.
pub struct Terminal {
    /// Original local operation label supplied at admission, never wire data.
    pub token: u64,
    /// Actual original DATASTORE completion certainty, never inferred from code0.
    pub outcome: Outcome,
    /// Original caller interruption, independent of any actual late reply.
    pub interruption: Option<Interruption>,
    /// Original actual DATA/STATUS/END, absent for local/lost completions.
    pub frame: Option<OwnedFrame>,
    /// Original MQ/setup failure, if observed before this completion.
    pub cause: Option<Failure>,
    /// Independent physical close/drain failure, preserving the original cause.
    pub cleanup: Option<Failure>,
}
impl fmt::Debug for Terminal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FsStorageTerminal")
            .field("token", &self.token)
            .field("outcome", &self.outcome)
            .field("interruption", &self.interruption)
            .field("frame_bytes", &self.frame.as_ref().map(OwnedFrame::len))
            .field("cause", &self.cause)
            .field("cleanup", &self.cleanup)
            .finish()
    }
}
impl fmt::Display for Terminal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "original FS storage completion: {self:?}")
    }
}
impl StdError for Terminal {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.cause
            .as_ref()
            .or(self.cleanup.as_ref())
            .map(|e| e.as_ref() as &(dyn StdError + 'static))
    }
}
/// One bounded native storage progress action; idle is Pending, never fake END.
pub enum Progress {
    /// Actual native IO/connection/timeout progress.
    Activity,
    /// Original actual terminal, retained independently of later work.
    Complete(Terminal),
}
/// Dedicated explicit serialized DATASTORE connection. Mutation/selection tokens
/// are retained until their original actual completion or physical retirement.
pub trait Port {
    /// Same source-clock identity; the driver rejects a different clock.
    fn clock(&self) -> Arc<dyn RuntimeClock>;
    /// Explicit permanent original-owner retirement, not a row-level failure.
    fn closed(&self) -> bool;
    /// Admit one copied original official request. Conflict preserves prior work.
    fn start(&mut self, token: u64, request: Request<'_>) -> Result<(), Failure>;
    /// Drive and settle original work without side-effect replay.
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Failure>>;
    /// Poll under an original absolute native bound. A port without that
    /// capability refuses explicitly; ordinary GAP polling remains unchanged.
    fn poll_until(
        &mut self,
        _cx: &mut Context<'_>,
        _hard: Instant,
    ) -> Poll<Result<Progress, Failure>> {
        Poll::Ready(Err(Error::Unsupported.into()))
    }
    /// Cancel the exact active caller token, physically retire its original
    /// native source if needed and transfer its actual terminal. No clock sample
    /// or fabricated completion is allowed at this cleanup boundary.
    fn cancel_retained(&mut self, _token: u64) -> Result<Terminal, Failure> {
        Err(Error::Unsupported.into())
    }
    /// Stop future admission; already admitted operations drain their original
    /// finite deadline/receipt without inventing a cancellation or completion.
    fn request_retire(&mut self) -> Result<(), Failure>;
    /// Physical close must return the original terminal separately from cleanup.
    fn close(&mut self) -> Result<Option<Terminal>, Failure>;
}
struct Active<'id> {
    token: u64,
    operation: Operation<'id>,
    cause: Option<Failure>,
}
/// Actual unmodified Rust native DATASTORE client, with one original request.
pub struct Datastore<'id, 'slots, 'bytes> {
    client: Client<'id, 'slots, 'bytes>,
    timeout: Timeout,
    active: Option<Active<'id>>,
    closed: bool,
    retiring: bool,
}
impl<'id, 'slots, 'bytes> Datastore<'id, 'slots, 'bytes> {
    /// Consume one explicit idle native client, without opening an extra worker.
    pub fn new(client: Client<'id, 'slots, 'bytes>, timeout: Timeout) -> Result<Self, Failure> {
        if client.pending() != 0
            || client.retained_replies() != (0, 0)
            || timeout.0 == 0
            || timeout.0 > client.protocol_limits().max_lifetime.0
        {
            return Err(Error::InvalidInput.into());
        }
        Ok(Self {
            client,
            timeout,
            active: None,
            closed: false,
            retiring: false,
        })
    }
    fn completed(&mut self) -> Result<Option<Terminal>, Failure> {
        let Some(active) = self.active.as_ref() else {
            return Ok(None);
        };
        let taken = match self.client.take(active.operation) {
            Ok(t) => t,
            Err(ds::Error::Protocol(Error::NotReady)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let active = self.active.take().ok_or(Error::StaleGeneration)?;
        Ok(Some(Terminal {
            token: active.token,
            outcome: taken.completion.outcome,
            interruption: taken.completion.interruption,
            frame: taken.into_frame(),
            cause: active.cause,
            cleanup: None,
        }))
    }
    fn failed(&mut self, cause: Failure) -> Result<Progress, Failure> {
        self.closed = true;
        if let Some(a) = &mut self.active
            && a.cause.is_none()
        {
            a.cause = Some(cause)
        }
        let physical = self.client.close().map_err(|e| Box::new(e) as Failure);
        let terminal = self.completed()?;
        match (physical, terminal) {
            (Ok(()), Some(t)) => Ok(Progress::Complete(t)),
            (Err(e), Some(mut t)) => {
                t.cleanup = Some(e);
                Err(Box::new(t))
            }
            (Err(e), None) => Err(e),
            (Ok(()), None) => Err(Error::Closed.into()),
        }
    }
}
impl Datastore<'_, '_, '_> {
    fn poll_original(
        &mut self,
        cx: &mut Context<'_>,
        hard: Option<Instant>,
    ) -> Poll<Result<Progress, Failure>> {
        if self.active.is_none() {
            return Poll::Pending;
        }
        match self.completed() {
            Ok(Some(t)) => return Poll::Ready(Ok(Progress::Complete(t))),
            Ok(None) => {}
            Err(e) => return Poll::Ready(Err(e)),
        }
        let step = {
            let mut wait = std::pin::pin!(self.client.drive(hard));
            wait.as_mut().poll(cx)
        };
        match step {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(self.failed(e.into())),
            Poll::Ready(Ok(Step::Unavailable(e))) => Poll::Ready(self.failed(e.into())),
            Poll::Ready(Ok(Step::Closed)) => {
                self.closed = true;
                match self.completed() {
                    Ok(Some(t)) => Poll::Ready(Ok(Progress::Complete(t))),
                    Ok(None) => Poll::Ready(Err(Error::Closed.into())),
                    Err(e) => Poll::Ready(Err(e)),
                }
            }
            Poll::Ready(Ok(Step::Lost { cause, .. })) => {
                if let Some(a) = &mut self.active {
                    a.cause = Some(Box::new(NativeLoss(cause)))
                }
                match self.completed() {
                    Ok(Some(t)) => Poll::Ready(Ok(Progress::Complete(t))),
                    Ok(None) => Poll::Ready(Ok(Progress::Activity)),
                    Err(e) => Poll::Ready(Err(e)),
                }
            }
            Poll::Ready(Ok(Step::ConnectRetry { error, .. })) => {
                if let Some(a) = &mut self.active
                    && a.cause.is_none()
                {
                    a.cause = Some(error.into())
                }
                Poll::Ready(Ok(Progress::Activity))
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(Progress::Activity)),
        }
    }
}
impl Port for Datastore<'_, '_, '_> {
    fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.client.clock()
    }
    fn closed(&self) -> bool {
        self.closed
    }
    fn start(&mut self, token: u64, request: Request<'_>) -> Result<(), Failure> {
        if self.closed || self.retiring {
            return Err(Error::Closed.into());
        }
        if self.active.is_some() {
            return Err(Error::Conflict.into());
        }
        if !matches!(
            request,
            Request::Put(_) | Request::Replication | Request::ZeroAnonymity { .. }
        ) {
            return Err(Error::Unsupported.into());
        }
        let operation = self.client.submit(request, None, self.timeout)?;
        self.active = Some(Active {
            token,
            operation,
            cause: None,
        });
        Ok(())
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Failure>> {
        self.poll_original(cx, None)
    }
    fn poll_until(
        &mut self,
        cx: &mut Context<'_>,
        hard: Instant,
    ) -> Poll<Result<Progress, Failure>> {
        self.poll_original(cx, Some(hard))
    }
    fn cancel_retained(&mut self, token: u64) -> Result<Terminal, Failure> {
        if self
            .active
            .as_ref()
            .is_none_or(|active| active.token != token)
        {
            return Err(Error::StaleGeneration.into());
        }
        if let Some(terminal) = self.completed()? {
            return Ok(terminal);
        }
        let operation = self
            .active
            .as_ref()
            .ok_or(Error::StaleGeneration)?
            .operation;
        if let Some(Step::Lost { cause, .. }) = self.client.cancel_and_retire(operation)?
            && let Some(active) = &mut self.active
            && active.cause.is_none()
        {
            active.cause = Some(Box::new(NativeLoss(cause)));
        }
        self.completed()?.ok_or_else(|| Error::NotReady.into())
    }
    fn request_retire(&mut self) -> Result<(), Failure> {
        self.retiring = true;
        Ok(())
    }
    fn close(&mut self) -> Result<Option<Terminal>, Failure> {
        self.closed = true;
        let physical = self.client.close();
        let terminal = self.completed()?;
        match physical {
            Ok(()) => Ok(terminal),
            Err(e) => {
                if let Some(mut t) = terminal {
                    t.cleanup = Some(e.into());
                    Err(Box::new(t))
                } else {
                    Err(e.into())
                }
            }
        }
    }
}
#[derive(Debug)]
struct NativeLoss(ds::Loss);
impl fmt::Display for NativeLoss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "original DATASTORE MQ loss: {:?}", self.0)
    }
}
impl StdError for NativeLoss {}
/// Exact rejected selected DATA/peer PUT, preserving its actual cause/provenance.
pub struct Rejected {
    /// Actual original complete frame, without a fabricated UID or source policy.
    pub frame: OwnedFrame,
    /// Original local refusal.
    pub cause: Failure,
}
impl fmt::Debug for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FsStorageRejected")
            .field("frame_bytes", &self.frame.len())
            .field("cause", &self.cause)
            .finish()
    }
}
impl fmt::Display for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "original FS storage record refused: {self:?}")
    }
}
impl StdError for Rejected {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.cause.as_ref())
    }
}
/// Original canonical pressure control retired by final physical close.
#[derive(Debug)]
pub struct RetiredControl {
    /// Exact original locally composed official16-byte message.
    pub bytes: [u8; 16],
    /// Original actual target identity, never rebound.
    pub peer: [u8; 32],
    /// Whether an actual native operation was admitted.
    pub admitted: bool,
    /// Actual last local CORE frame cursor, not peer compliance.
    pub written: usize,
}

/// Finite retained source/storage observations; full raw bytes are retained once.
#[derive(Default)]
pub struct Report {
    /// Actual complete original storage terminals observed.
    pub terminals: u64,
    /// First original non-success/uncertain terminal, if not returned as fatal.
    pub first_terminal: Option<Terminal>,
    /// Actual row/type6/local optional cache refusals.
    pub rejected: u64,
    /// First exact original rejected frame and original cause.
    pub first_rejected: Option<Rejected>,
    /// First actual selected DATA before any type6 transform.
    pub first_selected: Option<OwnedFrame>,
    /// First original control retired by forced physical cleanup.
    pub first_control_retired: Option<RetiredControl>,
}
struct Resolving<'id> {
    token: pure::Token<'id>,
    record: OwnedFrame,
    job: Resolution,
}
/// Production composition of fixed pure ownership and an explicit native store
/// port. The resolver is the weak port of the original single index worker.
pub struct Driver<'id, 'slots, 'bytes> {
    owner: pure::Owner<'id, 'slots, 'bytes>,
    port: Box<dyn Port + 'slots>,
    resolver: Option<IndexResolver>,
    clock: Arc<dyn RuntimeClock>,
    resolving: Option<Resolving<'id>>,
    stopping: bool,
    closed: bool,
    report: Report,
}
impl<'id, 'slots, 'bytes> Driver<'id, 'slots, 'bytes> {
    /// Connect explicit ports before polling. A distinct clock is rejected.
    pub fn new(
        owner: pure::Owner<'id, 'slots, 'bytes>,
        port: Box<dyn Port + 'slots>,
        resolver: Option<IndexResolver>,
        clock: Arc<dyn RuntimeClock>,
    ) -> Result<Self, Failure> {
        if !Arc::ptr_eq(&clock, &port.clock()) || owner.active().is_some() {
            return Err(Error::Conflict.into());
        }
        Ok(Self {
            owner,
            port,
            resolver,
            clock,
            resolving: None,
            stopping: false,
            closed: false,
            report: Report::default(),
        })
    }
    /// Same source-clock identity, without another clock listener.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    /// Exact pure source/peer/receipt state.
    #[must_use]
    pub const fn owner(&self) -> &pure::Owner<'id, 'slots, 'bytes> {
        &self.owner
    }
    /// Read original actual bounded raw observations.
    #[must_use]
    pub const fn report(&self) -> &Report {
        &self.report
    }
    /// Register only actual current remote CORE generations.
    pub fn attach(&mut self, n: gap::Neighbor<'id>, identity: [u8; 32]) -> Result<(), Error> {
        self.owner.attach(n, identity)
    }
    /// Retire exactly an actual original remote generation.
    pub fn disconnect(&mut self, n: gap::Neighbor<'id>) -> Result<(), Error> {
        self.owner.disconnect(n)
    }
    /// Decode/apply the full original16-byte control without affecting queries.
    pub fn pause(
        &mut self,
        n: gap::Neighbor<'id>,
        message: gnunet_wire::official::fs_gap::MigrationStop,
        now: u64,
    ) -> Result<(), Error> {
        self.owner.pause(n, message.duration, now)
    }
    fn copy(frame: &[u8]) -> Result<OwnedFrame, Error> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(frame.len())
            .map_err(|_| Error::Capacity)?;
        bytes.extend_from_slice(frame);
        Ok(OwnedFrame::new(bytes))
    }
    fn rejected(&mut self, frame: OwnedFrame, cause: Failure) {
        self.report.rejected = self.report.rejected.saturating_add(1);
        if self.report.first_rejected.is_none() {
            self.report.first_rejected = Some(Rejected { frame, cause })
        }
    }
    /// Optional cache ownership after the ordinary router accepted/validated the
    /// same actual block. Capacity decline cannot replay or block its positive.
    pub fn receive(
        &mut self,
        n: gap::Neighbor<'id>,
        checked: gap::CheckedPut<'_>,
        interest: gap::CacheInterest,
        now: u64,
    ) -> Result<(), Error> {
        if let pure::CacheAdmission::Declined(reason) =
            self.owner
                .receive_checked(n, checked, interest.priority, interest.requested, now)?
        {
            if self.report.first_rejected.is_none() {
                let original = Self::copy(checked.bytes())?;
                self.rejected(
                    original,
                    match reason {
                        pure::Declined::Capacity => Error::Capacity,
                        pure::Declined::Disabled => Error::PermissionDenied,
                        pure::Declined::Expired => Error::Timeout,
                        pure::Declined::TooLarge => Error::TooLarge,
                    }
                    .into(),
                );
            } else {
                self.report.rejected = self.report.rejected.saturating_add(1);
            }
        }
        Ok(())
    }
    fn selected(
        &mut self,
        token: pure::Token<'id>,
        record: OwnedFrame,
        now: u64,
    ) -> Result<(), Failure> {
        let Response::Data(data) = Response::decode(record.bytes())? else {
            return Err(Error::Malformed.into());
        };
        if data.kind == 6 {
            let descriptor = match <[u8; 72]>::try_from(data.value) {
                Ok(v) => v,
                Err(_) => {
                    self.owner.failed(token, false, now)?;
                    self.rejected(record, Error::Malformed.into());
                    return Ok(());
                }
            };
            let Some(resolver) = self.resolver.as_ref() else {
                self.owner.failed(token, false, now)?;
                self.rejected(record, Error::Unsupported.into());
                return Ok(());
            };
            match resolver.resolve(*data.key, descriptor) {
                Ok(job) => self.resolving = Some(Resolving { token, record, job }),
                Err(e) => {
                    self.owner.failed(token, false, now)?;
                    if e.is_fatal() {
                        return Err(Box::new(e));
                    }
                    self.rejected(record, Box::new(e))
                }
            }
            return Ok(());
        }
        match self.owner.selected(token, Some(data), now) {
            Ok(()) => {
                if self.report.first_selected.is_none() {
                    self.report.first_selected = Some(record)
                }
            }
            Err(e) => {
                self.owner.failed(token, false, now)?;
                self.rejected(record, e.into())
            }
        }
        Ok(())
    }
    fn terminal(
        &mut self,
        terminal: Terminal,
        now: u64,
        entropy: &mut impl gap::Entropy,
    ) -> Result<(), Failure> {
        self.report.terminals = self.report.terminals.saturating_add(1);
        let token = self
            .owner
            .active()
            .filter(|t| t.value() == terminal.token)
            .ok_or(Error::StaleGeneration)?;
        if self.port.closed()
            || terminal.interruption.is_some()
            || matches!(terminal.outcome, Outcome::Unknown)
        {
            self.owner
                .failed(token, matches!(terminal.outcome, Outcome::Unknown), now)?;
            return Err(Box::new(terminal));
        }
        match terminal.outcome {
            Outcome::Status { code, .. } => {
                let Some(frame) = terminal.frame.as_ref() else {
                    return Err(Box::new(terminal));
                };
                let Response::Status(status) = Response::decode(frame.bytes())? else {
                    return Err(Box::new(terminal));
                };
                if status.code != code {
                    return Err(Box::new(terminal));
                }
                if let Err(error) =
                    self.owner
                        .cache_status(token, code, status.min_expiration, now, entropy)
                {
                    let mut original = terminal;
                    original.cause = Some(error.into());
                    return Err(Box::new(original));
                }
                if code != 1 && self.report.first_terminal.is_none() {
                    self.report.first_terminal = Some(terminal)
                }
            }
            Outcome::Data { .. } => {
                let frame = terminal.frame.ok_or(Error::Malformed)?;
                self.selected(token, frame, now)?
            }
            Outcome::NotFound => {
                let Some(frame) = terminal.frame.as_ref() else {
                    return Err(Box::new(terminal));
                };
                if !matches!(Response::decode(frame.bytes())?, Response::End) {
                    return Err(Box::new(terminal));
                }
                self.owner.selected(token, None, now)?
            }
            _ => {
                self.owner.failed(token, false, now)?;
                if self.report.first_terminal.is_none() {
                    self.report.first_terminal = Some(terminal)
                }
            }
        }
        Ok(())
    }
    /// Drive one original storage/resolve action and admit at most one next
    /// request. The native port itself retains deadlines/partial suffixes.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        now: u64,
        entropy: &mut impl gap::Entropy,
    ) -> Poll<Result<bool, Failure>> {
        if self.closed {
            return Poll::Pending;
        }
        if let Some(mut resolving) = self.resolving.take() {
            match resolving.job.poll(cx) {
                Poll::Pending => {
                    self.resolving = Some(resolving);
                    return Poll::Pending;
                }
                Poll::Ready(Ok(value)) => {
                    let Response::Data(data) = Response::decode(resolving.record.bytes())? else {
                        return Poll::Ready(Err(Error::Malformed.into()));
                    };
                    if self.stopping {
                        self.owner.failed(resolving.token, false, now)?;
                        self.rejected(resolving.record, Error::Closed.into());
                    } else {
                        match self
                            .owner
                            .selected_resolved(resolving.token, data, &value, now)
                        {
                            Ok(()) => {
                                if self.report.first_selected.is_none() {
                                    self.report.first_selected = Some(resolving.record)
                                }
                            }
                            Err(e) => {
                                self.owner.failed(resolving.token, false, now)?;
                                self.rejected(resolving.record, e.into())
                            }
                        }
                    }
                    return Poll::Ready(Ok(true));
                }
                Poll::Ready(Err(e)) => {
                    self.owner.failed(resolving.token, false, now)?;
                    if e.is_fatal() {
                        return Poll::Ready(Err(Box::new(Rejected {
                            frame: resolving.record,
                            cause: Box::new(e),
                        })));
                    }
                    self.rejected(resolving.record, Box::new(e));
                    return Poll::Ready(Ok(true));
                }
            }
        }
        match self.port.poll(cx) {
            Poll::Ready(Ok(Progress::Activity)) => return Poll::Ready(Ok(true)),
            Poll::Ready(Ok(Progress::Complete(t))) => {
                return Poll::Ready(self.terminal(t, now, entropy).map(|()| true));
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => {}
        }
        if self.port.closed() {
            return Poll::Ready(Err(Error::Closed.into()));
        }
        let admitted = {
            let Some(command) = self.owner.next_command(now)? else {
                return Poll::Pending;
            };
            match command {
                pure::Command::Put(write) => self
                    .port
                    .start(write.token.value(), Request::Put(write.data)),
                pure::Command::Replication(token) => {
                    self.port.start(token.value(), Request::Replication)
                }
            }
        };
        match admitted {
            Ok(()) => Poll::Ready(Ok(true)),
            Err(e) => {
                if let Some(token) = self.owner.active() {
                    self.owner.failed(token, false, now)?
                }
                Poll::Ready(Err(e))
            }
        }
    }
    /// Fairly offer one selected block into a dedicated real GAP push path.
    pub fn offer(
        &mut self,
        router: &mut gap::Router<'id, '_, '_>,
        now: u64,
    ) -> Result<bool, Error> {
        let Some(push) = self.owner.next_push(now)? else {
            return Ok(false);
        };
        let token = push.token;
        let neighbor = push.neighbor;
        let admission = match router.queue_push(neighbor, push.frame, push.metadata.anonymity, now)
        {
            Ok(a) => a,
            Err(Error::Capacity | Error::WouldBlock) => return Ok(false),
            Err(e) => return Err(e),
        };
        self.owner.bind_push(token, neighbor, admission.path)?;
        Ok(true)
    }
    /// Preserve original native receipts for dedicated unsolicited paths.
    pub fn sent(&mut self, fact: gap::SendRetired<'id>, written: bool) -> Result<(), Error> {
        self.owner.sent(fact, written)
    }
    /// Apply original pauses/residence only to dedicated unsolicited paths.
    /// Already admitted suffixes retain their original physical drain.
    pub fn sweep(
        &mut self,
        router: &mut gap::Router<'id, '_, '_>,
        now: u64,
    ) -> Result<bool, Error> {
        let mut changed = false;
        let n = self.owner.paths().count();
        for i in (0..n).rev() {
            let (path, target) = self.owner.paths().nth(i).ok_or(Error::StaleGeneration)?;
            let pending = router.pending_path() == Some(path);
            let finished = match router.path_done(path) {
                Ok(v) => v,
                Err(Error::StaleGeneration) => true,
                Err(e) => return Err(e),
            };
            let expired = self
                .owner
                .path_metadata(path)
                .is_some_and(|m| m.expiration.as_micros() <= now);
            let due = expired
                || router
                    .path_route(path)
                    .and_then(|r| router.residence_deadline(r))
                    .is_ok_and(|end| now >= end);
            if !finished && (self.stopping || self.owner.blocked(target, now) || due) {
                router.cancel(path)?;
                changed = true
            }
            if !pending && (finished || self.stopping || self.owner.blocked(target, now) || due) {
                self.owner.retire_path(path)?;
                changed = true
            }
        }
        Ok(changed)
    }
    /// Original peer-pause/selection and unsolicited residence targets.
    pub fn next_deadline(&self, router: &gap::Router<'id, '_, '_>, now: u64) -> Option<u64> {
        self.owner
            .next_deadline(now)
            .into_iter()
            .chain(self.owner.paths().filter_map(|(path, _)| {
                self.owner
                    .path_metadata(path)
                    .filter(|m| !m.expiration.is_never())
                    .map(|m| m.expiration.as_micros())
                    .filter(|end| *end > now)
            }))
            .chain(self.owner.paths().filter_map(|(p, _)| {
                router
                    .path_route(p)
                    .and_then(|r| router.residence_deadline(r))
                    .ok()
                    .filter(|end| *end > now)
            }))
            .min()
    }
    /// Prepare an exact original official control, without peer compliance claim.
    pub fn next_stop(&mut self, now: u64) -> Result<Option<pure::StopOffer<'id>>, Error> {
        self.owner.next_stop(now)
    }
    /// Actual completed or physically retired original control.
    pub fn stop_sent(&mut self, token: pure::Token<'id>, written: bool) -> Result<(), Error> {
        self.owner.stop_sent(token, written)
    }
    /// Stop unadmitted work. Exposed DS operations retain their original token;
    /// a queued resolution still settles through the one existing worker.
    pub fn request_shutdown(&mut self) -> Result<(), Failure> {
        if !self.stopping {
            self.stopping = true;
            self.owner.request_shutdown();
            self.port.request_retire()?
        }
        Ok(())
    }
    /// Only local original store/control/path owners have settled.
    #[must_use]
    pub fn quiesced(&self) -> bool {
        self.stopping && self.resolving.is_none() && self.owner.quiesced()
    }
    /// Explicit final physical closure; an active original uncertain completion
    /// is returned as failure, never erased by a successful close syscall.
    pub fn close(&mut self, now: u64) -> Result<(), Failure> {
        self.stopping = true;
        self.owner.request_shutdown();
        let terminal = self.port.close()?;
        self.closed = true;
        if let Some(t) = terminal {
            if let Some(token) = self.owner.active() {
                self.owner
                    .failed(token, matches!(t.outcome, Outcome::Unknown), now)?
            }
            return Err(Box::new(t));
        }
        if self.resolving.is_some() {
            return Err(Error::WouldBlock.into());
        }
        Ok(())
    }
}

// Native CORE scheduling remains in the original Router; this child impl keeps
// the optional storage/control composition separate from query/source routing.
use super::{Error as RouterError, Router};
use gnunet_core_client_host::{self as core, ConnectionEpoch, Message, PayloadState, Peer, SendId};
use gnunet_service_runtime::clock::Deadline;
use gnunet_types::AbsoluteTime;
use std::pin::Pin;
pub(super) struct Control<'c, 'g> {
    offer: pure::StopOffer<'g>,
    epoch: ConnectionEpoch<'c>,
    peer: Peer<'c>,
    send: Option<SendId<'c>>,
    bytes: [u8; 16],
    message: Option<Message>,
    deadline: Option<Deadline>,
    written: usize,
    total: usize,
    canceling: bool,
}
impl<
    'c,
    'g,
    'slots,
    'bytes,
    S: source::BlockSource,
    E: gap::Entropy,
    const P: usize,
    const N: usize,
> Router<'c, 'g, 'slots, 'bytes, S, E, P, N>
{
    /// Install explicit optional storage ports before the first CORE poll. The
    /// same clock/weak resolver are supplied by the foreground's sole worker.
    pub fn install_storage(
        &mut self,
        driver: Driver<'g, 'slots, 'bytes>,
    ) -> Result<(), RouterError> {
        if self.storage.is_some()
            || self.epoch.is_some()
            || !self.peers.is_empty()
            || self.send.is_some()
            || !Arc::ptr_eq(&self.clock, &driver.clock())
        {
            return Err(Error::Conflict.into());
        }
        self.storage = Some(driver);
        Ok(())
    }
    /// Actual optional storage ownership/receipts; absence means no cache backend.
    #[must_use]
    pub const fn storage(&self) -> Option<&Driver<'g, 'slots, 'bytes>> {
        self.storage.as_ref()
    }
    pub(super) fn control_matches(&self, send: SendId<'c>) -> bool {
        self.control.as_ref().is_some_and(|c| c.send == Some(send))
    }
    pub(super) fn control_payload(&mut self, state: PayloadState<'c>) -> Result<bool, RouterError> {
        let Some(c) = self
            .control
            .as_mut()
            .filter(|c| c.send == Some(state.send()))
        else {
            return Ok(false);
        };
        if state.epoch() != c.epoch
            || state.peer() != c.peer
            || state.frame_bytes() != c.total
            || state.written() < c.written
        {
            return Err(Error::Authentication.into());
        }
        c.written = state.written();
        Ok(true)
    }
    pub(super) fn finish_control(
        &mut self,
        epoch: ConnectionEpoch<'c>,
        peer: Peer<'c>,
        send: SendId<'c>,
        payload: Option<PayloadState<'c>>,
        completion: core::SendCompletion<Message>,
    ) -> Result<(), RouterError> {
        if let Some(state) = payload {
            self.control_payload(state)?;
        }
        let c = self.control.as_ref().ok_or(Error::StaleGeneration)?;
        if c.epoch != epoch
            || c.peer != peer
            || c.send != Some(send)
            || completion.source.as_ref() != c.bytes
        {
            return Err(Error::Authentication.into());
        }
        let complete = payload.is_some_and(|p| p.complete());
        if completion.outcome == core::SendOutcome::Written && !complete {
            return Err(Error::Conflict.into());
        }
        let confirmed = completion.outcome == core::SendOutcome::Written && complete;
        self.storage
            .as_mut()
            .ok_or(Error::Conflict)?
            .stop_sent(c.offer.token, confirmed)?;
        self.report.completions = self.report.completions.saturating_add(1);
        self.report.last_completion = Some(super::Completion {
            payload,
            send,
            outcome: completion.outcome,
            source: completion.source,
        });
        self.control = None;
        Ok(())
    }
    pub(super) fn storage_poll(&mut self, cx: &mut Context<'_>) -> Result<bool, RouterError> {
        if let Some(error) = self.storage_retirement_error.take() {
            return Err(RouterError::Storage(error));
        }
        let Some(storage) = &mut self.storage else {
            return Ok(false);
        };
        let mut changed = storage.sweep(&mut self.gap, self.last_now)?;
        match storage.poll(cx, self.last_now, &mut self.entropy) {
            Poll::Pending => {}
            Poll::Ready(Ok(ready)) => changed |= ready,
            Poll::Ready(Err(e)) => return Err(RouterError::Storage(e)),
        }
        changed |= storage.offer(&mut self.gap, self.last_now)?;
        Ok(changed)
    }
    pub(super) fn storage_deadline(&mut self, cx: &mut Context<'_>) -> Result<bool, RouterError> {
        let target = self
            .storage
            .as_ref()
            .and_then(|s| s.next_deadline(&self.gap, self.last_now));
        let mut changed = false;
        if self.storage_timer.as_ref().map(|(t, _)| *t) != target {
            self.storage_timer = target
                .map(|t| {
                    Deadline::at(self.clock.clone(), AbsoluteTime::from_micros(t)).map(|d| (t, d))
                })
                .transpose()?;
            changed = true
        }
        if let Some((_, deadline)) = &mut self.storage_timer
            && let Poll::Ready(result) = Pin::new(deadline).poll(cx)
        {
            result?;
            self.storage_timer = None;
            changed = true
        }
        Ok(changed)
    }
    pub(super) fn storage_stop(&mut self) {
        self.storage_timer = None;
        if let Some(s) = &mut self.storage
            && let Err(e) = s.request_shutdown()
            && self.storage_retirement_error.is_none()
        {
            self.storage_retirement_error = Some(e)
        }
    }
    pub(super) fn retain_storage_failure(existing: &mut Option<Failure>, error: Failure) {
        *existing = Some(match existing.take() {
            None => error,
            Some(cause) => Box::new(RouterError::Retirement {
                cause: Box::new(RouterError::Storage(cause)),
                cleanup: Box::new(RouterError::Storage(error)),
            }) as Failure,
        });
    }
    pub(super) fn storage_forced_control(&mut self) -> Result<(), RouterError> {
        if let Some(control) = self.control.take() {
            let storage = self.storage.as_mut().ok_or(Error::Conflict)?;
            if storage.report.first_control_retired.is_none() {
                storage.report.first_control_retired = Some(RetiredControl {
                    bytes: control.bytes,
                    peer: control.peer.identity().0,
                    admitted: control.send.is_some(),
                    written: control.written,
                });
            }
            storage.stop_sent(control.offer.token, false)?;
        }
        Ok(())
    }
    pub(super) fn storage_quiesced(&self) -> bool {
        self.control.is_none()
            && self.storage_retirement_error.is_none()
            && self.storage.as_ref().is_none_or(Driver::quiesced)
    }
    pub(super) fn storage_control(&mut self, cx: &mut Context<'_>) -> Result<bool, RouterError> {
        let mut changed = false;
        if self.control.is_none()
            && self.send.is_none()
            && !self.stopping
            && self.control_turn
            && let Some(offer) = self
                .storage
                .as_mut()
                .map(|s| s.next_stop(self.last_now))
                .transpose()?
                .flatten()
        {
            let actual = self
                .peers
                .iter()
                .copied()
                .find(|p| p.live && !p.local && p.neighbor == Some(offer.neighbor))
                .ok_or(Error::StaleGeneration);
            let actual = match actual {
                Ok(actual) => actual,
                Err(error) => {
                    self.storage
                        .as_mut()
                        .ok_or(Error::Conflict)?
                        .stop_sent(offer.token, false)?;
                    return Err(error.into());
                }
            };
            let mut bytes = [0; 16];
            if let Err(error) = offer.message.encode(&mut bytes) {
                self.storage
                    .as_mut()
                    .ok_or(Error::Conflict)?
                    .stop_sent(offer.token, false)?;
                return Err(error.into());
            }
            let deadline = match Deadline::after(self.clock.clone(), self.limits.send_timeout) {
                Ok(deadline) => deadline,
                Err(error) => {
                    self.storage
                        .as_mut()
                        .ok_or(Error::Conflict)?
                        .stop_sent(offer.token, false)?;
                    return Err(error.into());
                }
            };
            self.control_turn = false;
            self.control = Some(Control {
                offer,
                epoch: actual.epoch,
                peer: actual.peer,
                send: None,
                bytes,
                message: None,
                deadline: Some(deadline),
                written: 0,
                total: gnunet_wire::official::core::SEND_PREFIX + 16,
                canceling: false,
            });
            changed = true
        }
        let Some(c) = &mut self.control else {
            return Ok(changed);
        };
        let timed = if let Some(deadline) = &mut c.deadline {
            match Pin::new(deadline).poll(cx) {
                Poll::Pending => false,
                Poll::Ready(r) => {
                    r?;
                    c.deadline = None;
                    true
                }
            }
        } else {
            false
        };
        let live = self.peers.iter().any(|p| {
            p.live && p.epoch == c.epoch && p.peer == c.peer && p.neighbor == Some(c.offer.neighbor)
        });
        if (!c.canceling && (!live || self.stopping)) || timed {
            c.canceling = true;
            let original = (c.send, c.epoch, c.peer, c.offer.token, c.written, c.total);
            if let Some(send) = original.0 {
                if timed && original.4 != 0 && original.4 < original.5 {
                    let loss = self.native.reconnect()?;
                    self.native_event(loss, self.last_now)?;
                } else if let Some(completion) = self.native.cancel(send)? {
                    self.finish_control(original.1, original.2, send, None, completion)?;
                }
            } else {
                self.storage
                    .as_mut()
                    .ok_or(Error::Conflict)?
                    .stop_sent(original.3, false)?;
                self.control = None;
            }
            return Ok(true);
        }
        if c.send.is_some() {
            return Ok(changed);
        }
        match self.native.request_available(c.peer, 16, 16) {
            Ok(false) | Err(core::Error::Protocol(Error::NotReady | Error::Closed)) => {
                return Ok(changed);
            }
            Err(e) => return Err(e.into()),
            Ok(true) => {}
        }
        let message = match c.message.take() {
            Some(m) => m,
            None => Message::copy_from(&c.bytes)?,
        };
        let delay =
            u64::try_from(self.limits.send_timeout.as_micros()).map_err(|_| Error::Overflow)?;
        let target = self.last_now.checked_add(delay).ok_or(Error::Overflow)?;
        match self.native.send(c.peer, u32::MAX, target, message) {
            Ok(send) => {
                c.send = Some(send);
                Ok(true)
            }
            Err(rejected) => {
                c.message = Some(rejected.value);
                match rejected.reason {
                    Error::Capacity | Error::WouldBlock | Error::NotReady => Ok(changed),
                    e => Err(e.into()),
                }
            }
        }
    }
}
