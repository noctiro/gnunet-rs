//! One actual generic SET MQ, with nonreused request and iteration ownership.
use crate::{
    Bounds, Cause, CopyId, CopyTicket, DeadlineContext, DeadlineScope, DeadlineWrite, Error,
    IterationId, Limits, MutationId, OperationId, OperationType, Prepared,
};
use crate::{
    budget::NativeAlarm,
    events::*,
    prepared::Plan,
    session::{Session, Step, WriteLabel},
    types::Owner,
};
use gnunet_client_host::EndpointSource;
use gnunet_types::Error as Fault;
use gnunet_wire::official::set::{ClientRequest, Element};
use std::{
    future::poll_fn,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};
mod input;
#[derive(Clone, Copy, Eq, PartialEq)]
enum Tag {
    Mutation(u64),
    Operation(u32),
    Cancel(u32),
    Iterate(u64),
    IterAck(u64, bool),
    Copy(u64),
}
impl WriteLabel for Tag {
    fn write_label(self) -> DeadlineWrite {
        match self {
            Self::Mutation(serial) => DeadlineWrite::Mutation { serial },
            Self::Operation(request_id) => DeadlineWrite::Operation { request_id },
            Self::Cancel(request_id) => DeadlineWrite::Cancel { request_id },
            Self::Iterate(serial) => DeadlineWrite::Iterate { serial },
            Self::IterAck(serial, send_more) => DeadlineWrite::IterAck { serial, send_more },
            Self::Copy(serial) => DeadlineWrite::Copy { serial },
        }
    }
}
/// Failed admission returns the same unconsumed preparation for explicit retry.
pub struct CommitFailure {
    /// Original local admission error.
    pub error: Error,
    /// Original preparation, with its same accept/source authority.
    pub prepared: Prepared,
}
/// Local result of an iteration-cancel request; no stop processing ACK exists.
pub enum IterCancelDisposition {
    /// Zero-written Iterate was actually removed, without a wire generation.
    Unsent(IterationReceipt),
    /// Original cancel intent/IterAck0 queued; wait for actual local retirement.
    Pending,
    /// Partial original control/request forced physical MQ retirement.
    SourceRetired(SetLoss),
}
/// One independently owned native Set. Attached source loss makes it invalid;
/// elements, operations, cookies and partial results are never silently replayed.
pub struct Set {
    session: Session<Tag>,
    domain: Owner,
    owner: Owner,
    operation: OperationType,
    limits: Limits,
    serial: u64,
    request: u64,
    mutations: Vec<MutationReceipt>,
    operations: Vec<OperationReceipt>,
    iteration: Option<Box<IterationReceipt>>,
    generation: u32,
    copy: Option<CopyReceipt>,
    copy_connect: Option<CopyTicket>,
    alarm: NativeAlarm,
    closed: bool,
}
impl Set {
    pub(crate) fn new(
        source: EndpointSource,
        domain: Owner,
        operation: OperationType,
        ticket: Option<&CopyTicket>,
        limits: Limits,
        bounds: Bounds,
    ) -> Result<Self, Error> {
        let init = match ticket.as_ref() {
            Some(t) => {
                if !Arc::ptr_eq(&domain, &t.domain) || !t.epoch.live() {
                    return Err(Fault::Stale.into());
                }
                ClientRequest::CopyLazyConnect { cookie: t.cookie }
            }
            None => ClientRequest::Create {
                operation: operation as u32,
            },
        };
        let session = Session::new(source, crate::encode(init)?, limits, bounds)?;
        Ok(Self {
            session,
            domain,
            owner: Arc::new(()),
            operation,
            limits,
            serial: 1,
            request: 1,
            mutations: Vec::new(),
            operations: Vec::new(),
            iteration: None,
            generation: 0,
            copy: None,
            copy_connect: None,
            alarm: NativeAlarm::default(),
            closed: false,
        })
    }
    pub(crate) fn retain_copy(&mut self, ticket: CopyTicket) {
        self.copy_connect = Some(ticket);
    }
    /// Actual whole initializer write, with no service acceptance/processing ACK.
    #[must_use]
    pub fn initialized(&self) -> bool {
        self.session.ready()
    }
    /// Actual original attached source, without replacement authority.
    #[must_use]
    pub fn epoch(&self) -> Option<&crate::Epoch> {
        self.session.epoch()
    }
    /// Original source lifetime, without operation authority.
    #[must_use]
    pub fn native_deadline(&self) -> Instant {
        self.session.original().hard
    }
    fn next(&self) -> Result<(u64, u64), Error> {
        let n = self.serial.checked_add(1).ok_or(Fault::Overflow)?;
        Ok((self.serial, n))
    }
    fn require(&self) -> Result<(), Error> {
        self.session.check()?;
        if !self.initialized() {
            return Err(Fault::NotReady.into());
        }
        Ok(())
    }
    fn mutate(&mut self, element: Element<'_>, kind: MutationKind) -> Result<MutationId, Error> {
        self.require()?;
        if self.mutations.len() >= self.limits.queued_frames {
            return Err(Fault::Capacity.into());
        }
        let (serial, next) = self.next()?;
        let bytes = crate::encode(match kind {
            MutationKind::Add => ClientRequest::Add { element },
            MutationKind::Remove => ClientRequest::Remove { element },
        })?;
        let original = self.session.phase()?;
        self.mutations.try_reserve(1).map_err(|_| Fault::Capacity)?;
        self.session
            .enqueue(bytes, Tag::Mutation(serial), original, false)?;
        let id = MutationId {
            owner: self.owner.clone(),
            serial,
        };
        self.mutations.push(MutationReceipt {
            id: id.clone(),
            kind,
            written: 0,
            whole: false,
            original,
        });
        self.serial = next;
        Ok(id)
    }
    /// Queue a bounded original Add; continuation arrives only at local whole write.
    pub fn add(&mut self, element: Element<'_>) -> Result<MutationId, Error> {
        self.mutate(element, MutationKind::Add)
    }
    /// Queue a bounded original Remove; this does not acknowledge processing.
    pub fn remove(&mut self, element: Element<'_>) -> Result<MutationId, Error> {
        self.mutate(element, MutationKind::Remove)
    }
    fn commit_inner(&mut self, p: &Prepared, original: Bounds) -> Result<OperationId, Error> {
        self.require()?;
        original.check(self.session.clock().as_ref())?;
        if !p.mode.supports(self.operation) {
            return Err(Fault::Unsupported.into());
        }
        if self.operations.len() >= self.limits.operations {
            return Err(Fault::Capacity.into());
        }
        let acceptance = match &p.plan {
            Plan::Accept(a) => {
                if !Arc::ptr_eq(&self.domain, &a.domain)
                    || !a.epoch.live()
                    || a.operation != self.operation
                {
                    return Err(Fault::Stale.into());
                }
                Some(a.clone())
            }
            _ => None,
        };
        let request_id = u32::try_from(self.request).map_err(|_| Fault::Overflow)?;
        let next = self.request.checked_add(1).ok_or(Fault::Overflow)?;
        let bytes = crate::encode(p.request(request_id))?;
        self.operations
            .try_reserve(1)
            .map_err(|_| Fault::Capacity)?;
        self.session
            .enqueue(bytes, Tag::Operation(request_id), original, false)?;
        let id = OperationId {
            owner: self.owner.clone(),
            serial: u64::from(request_id),
        };
        self.operations.push(OperationReceipt {
            id: id.clone(),
            request_id,
            written: 0,
            request_written: false,
            half_done: false,
            current_size: None,
            cancellation: None,
            cancellation_written: false,
            original,
            acceptance,
        });
        self.request = next;
        Ok(id)
    }
    /// Bind a preparation to this actual Set MQ and original RID atomically.
    /// Admission failure returns the same preparation; prepare alone starts no IO.
    pub fn commit(
        &mut self,
        prepared: Prepared,
        original: Bounds,
    ) -> Result<OperationId, CommitFailure> {
        match self.commit_inner(&prepared, original) {
            Ok(id) => Ok(id),
            Err(error) => Err(CommitFailure { error, prepared }),
        }
    }
    fn cancel_for(
        &mut self,
        id: &OperationId,
        cause: CancellationCause,
    ) -> Result<CancelDisposition, Error> {
        if !Arc::ptr_eq(&self.owner, &id.owner) {
            return Err(Fault::Stale.into());
        }
        self.require()?;
        let at = self
            .operations
            .iter()
            .position(|x| x.id == *id)
            .ok_or(Fault::Stale)?;
        if self.operations[at].cancellation.is_some() {
            return Err(Fault::Conflict.into());
        }
        let rid = self.operations[at].request_id;
        if !self.operations[at].request_written {
            if self.session.remove_unwritten(Tag::Operation(rid)) {
                let mut receipt = self.operations.remove(at);
                receipt.cancellation = Some(cause);
                return Ok(CancelDisposition::Unsent(receipt));
            }
            self.operations[at].cancellation = Some(cause);
            return Ok(CancelDisposition::SourceRetired(
                self.lost(Cause::Requested, None),
            ));
        }
        let bytes = crate::encode(ClientRequest::Cancel { request_id: rid })?;
        let phase = self.session.phase()?;
        self.session.enqueue(bytes, Tag::Cancel(rid), phase, true)?;
        self.operations[at].cancellation = Some(cause);
        Ok(CancelDisposition::Queued)
    }
    /// Stop future result delivery for this original operation, without service ACK.
    /// A partly exposed unsent request is retired with its whole original MQ.
    pub fn cancel(&mut self, id: &OperationId) -> Result<CancelDisposition, Error> {
        self.cancel_for(id, CancellationCause::Requested)
    }
    /// Start one real enumeration. A prior retiring generation cannot be reused.
    pub fn iterate(&mut self, original: Bounds) -> Result<IterationId, Error> {
        self.require()?;
        if self.iteration.is_some() {
            return Err(Fault::WouldBlock.into());
        }
        if self.generation > u32::from(u16::MAX) {
            return Err(Fault::Overflow.into());
        }
        let (serial, next) = self.next()?;
        let id = IterationId {
            owner: self.owner.clone(),
            serial,
        };
        let receipt = Box::new(IterationReceipt {
            id: id.clone(),
            generation: u16::try_from(self.generation).map_err(|_| Fault::Overflow)?,
            written: 0,
            request_written: false,
            elements: 0,
            cancellation: None,
            stop_written: false,
            original,
            cleanup: None,
            awaiting_ack: false,
            ack_pending: None,
        });
        self.session.enqueue(
            crate::encode(ClientRequest::Iterate)?,
            Tag::Iterate(serial),
            original,
            false,
        )?;
        self.iteration = Some(receipt);
        self.serial = next;
        Ok(id)
    }
    /// Acknowledge exactly one original received element. False queues IterAck0;
    /// only its actual whole write retires that generation locally, with no ACK.
    pub fn iteration_continue(&mut self, id: &IterationId, send_more: bool) -> Result<(), Error> {
        self.require()?;
        let row = self
            .iteration
            .as_ref()
            .filter(|r| r.id == *id)
            .ok_or(Fault::Stale)?;
        if !row.awaiting_ack || row.ack_pending.is_some() {
            return Err(Fault::NotReady.into());
        }
        if send_more && row.cancellation.is_some() {
            return Err(Fault::Conflict.into());
        }
        let serial = row.id.serial;
        let bound = if !send_more {
            match row.cleanup.as_ref() {
                Some(original) => *original,
                None => self.session.phase()?,
            }
        } else {
            self.session.phase()?
        };
        self.session.enqueue(
            crate::encode(ClientRequest::IterAck {
                send_more: u32::from(send_more),
            })?,
            Tag::IterAck(serial, send_more),
            bound,
            true,
        )?;
        let row = self.iteration.as_mut().ok_or(Fault::Stale)?;
        row.awaiting_ack = false;
        row.ack_pending = Some(send_more);
        if !send_more {
            row.cancellation = Some(row.cancellation.unwrap_or(CancellationCause::Requested));
            if row.cleanup.is_none() {
                row.cleanup = Some(bound);
            }
        }
        Ok(())
    }
    /// Cancel enumeration without waiting for a nonexistent stop ACK. If the
    /// next original frame is outstanding, intent waits for it before IterAck0.
    pub fn cancel_iteration(&mut self, id: &IterationId) -> Result<IterCancelDisposition, Error> {
        self.require()?;
        let row = self
            .iteration
            .as_ref()
            .filter(|x| x.id == *id)
            .ok_or(Fault::Stale)?;
        if row.cancellation.is_some() {
            return Err(Fault::Conflict.into());
        }
        let serial = row.id.serial;
        if !row.request_written {
            if self.session.remove_unwritten(Tag::Iterate(serial)) {
                let mut r = self.iteration.take().ok_or(Fault::Stale)?;
                r.cancellation = Some(CancellationCause::Requested);
                return Ok(IterCancelDisposition::Unsent(*r));
            }
            self.iteration.as_mut().ok_or(Fault::Stale)?.cancellation =
                Some(CancellationCause::Requested);
            return Ok(IterCancelDisposition::SourceRetired(
                self.lost(Cause::Requested, None),
            ));
        }
        if self.session.contains(Tag::IterAck(serial, true)) {
            if self.session.remove_unwritten(Tag::IterAck(serial, true)) {
                let r = self.iteration.as_mut().ok_or(Fault::Stale)?;
                r.awaiting_ack = true;
                r.ack_pending = None;
            } else {
                self.iteration.as_mut().ok_or(Fault::Stale)?.cancellation =
                    Some(CancellationCause::Requested);
                return Ok(IterCancelDisposition::SourceRetired(
                    self.lost(Cause::Requested, None),
                ));
            }
        }
        let bound = self.session.phase()?;
        let row = self.iteration.as_mut().ok_or(Fault::Stale)?;
        row.cancellation = Some(CancellationCause::Requested);
        row.cleanup = Some(bound);
        if row.awaiting_ack {
            self.iteration_continue(id, false)?;
        }
        Ok(IterCancelDisposition::Pending)
    }
    /// Request one lazy-copy cookie. Its response is not a local eager snapshot.
    pub fn copy_lazy(&mut self, original: Bounds) -> Result<CopyId, Error> {
        self.require()?;
        if self.copy.is_some() {
            return Err(Fault::WouldBlock.into());
        }
        let (serial, next) = self.next()?;
        let id = CopyId {
            owner: self.owner.clone(),
            serial,
        };
        self.session.enqueue(
            crate::encode(ClientRequest::CopyLazyPrepare)?,
            Tag::Copy(serial),
            original,
            false,
        )?;
        self.copy = Some(CopyReceipt {
            id: id.clone(),
            written: 0,
            request_written: false,
            original,
        });
        self.serial = next;
        Ok(id)
    }
    fn lost(&mut self, cause: Cause, cleanup: Option<Error>) -> SetLoss {
        let transport = self.session.retire(true);
        self.alarm.clear();
        self.closed = true;
        self.copy_connect = None;
        SetLoss {
            deadline: None,
            transport,
            cause,
            cleanup,
            mutations: std::mem::take(&mut self.mutations),
            operations: std::mem::take(&mut self.operations),
            iteration: self.iteration.take(),
            copy: self.copy.take(),
        }
    }
    fn failed(&mut self, error: Error, cleanup: Option<Error>) -> SetLoss {
        let (cause, deadline) = error.into_cause_parts();
        let mut loss = self.lost(cause, cleanup);
        loss.deadline = deadline;
        loss
    }
    /// Clock-free physical retirement before original metadata is returned.
    pub fn close(&mut self) -> SetLoss {
        self.lost(Cause::Requested, None)
    }
    /// Physically retire this original MQ after its actual synchronous
    /// operation/admission failed. Move the original error into the loss without
    /// replacing it by Requested, sampling time or changing any receipt target.
    /// The caller supplies the error returned by this same original owner.
    pub fn retire_after(&mut self, error: Error) -> SetLoss {
        self.failed(error, None)
    }
    /// Conservative clock-free fence while a caller waits on unrelated output.
    /// Expired work retires the original MQ; it cannot move to a replacement.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<SetLoss> {
        if self.closed {
            return None;
        }
        // Session owns its transport waiter. It cannot overwrite this Set's
        // earlier operation target while internally polling read/write/connect.
        if let Some(context) = self.session.native_expired(cx) {
            return Some(self.failed(Error::deadline(context), None));
        }
        let target = self
            .operations
            .iter()
            .filter(|receipt| receipt.cancellation.is_none())
            .map(|receipt| {
                (
                    DeadlineScope::Operation {
                        serial: receipt.id.serial,
                        request_id: receipt.request_id,
                    },
                    receipt.original,
                )
            })
            .chain(self.iteration.as_ref().map(|receipt| {
                (
                    DeadlineScope::Iteration {
                        serial: receipt.id.serial,
                        generation: receipt.generation,
                        cleanup: receipt.cleanup.is_some(),
                    },
                    receipt.cleanup.unwrap_or(receipt.original),
                )
            }))
            .chain(self.copy.as_ref().map(|receipt| {
                (
                    DeadlineScope::Copy {
                        serial: receipt.id.serial,
                    },
                    receipt.original,
                )
            }))
            .min_by_key(|(_, bound)| bound.hard);
        let Some((scope, bound)) = target else {
            self.alarm.clear();
            return None;
        };
        self.alarm.poll(cx, Some(bound.hard)).then(|| {
            self.failed(
                Error::deadline(DeadlineContext::at(scope, bound, Instant::now(), None)),
                None,
            )
        })
    }
    /// Poll only original retained owners; dropping a progress future preserves them.
    pub fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<Result<SetProgress, Error>> {
        if self.closed {
            return Poll::Ready(Err(Fault::Closed.into()));
        }
        if let Some(loss) = self.poll_native_guard(cx) {
            return Poll::Ready(Ok(SetProgress::Lost(loss)));
        }
        if let Err(error) = self.session.check() {
            return Poll::Ready(Ok(SetProgress::Lost(self.failed(error, None))));
        }
        let now = match self.session.clock().sample() {
            Ok(sample) => sample.now.as_micros(),
            Err(error) => {
                return Poll::Ready(Ok(SetProgress::Lost(
                    self.lost(Cause::Failure(Error::clock(error)), None),
                )));
            }
        };
        let native = Instant::now();
        let expired = |bounds: Bounds| now >= bounds.expires || native >= bounds.hard;
        let deadline = self
            .operations
            .iter()
            .find_map(|receipt| {
                (receipt.cancellation.is_none() && expired(receipt.original)).then(|| {
                    DeadlineContext::at(
                        DeadlineScope::Operation {
                            serial: receipt.id.serial,
                            request_id: receipt.request_id,
                        },
                        receipt.original,
                        native,
                        Some(now),
                    )
                })
            })
            .or_else(|| {
                self.iteration.as_ref().and_then(|receipt| {
                    let bound = receipt.cleanup.unwrap_or(receipt.original);
                    expired(bound).then(|| {
                        DeadlineContext::at(
                            DeadlineScope::Iteration {
                                serial: receipt.id.serial,
                                generation: receipt.generation,
                                cleanup: receipt.cleanup.is_some(),
                            },
                            bound,
                            native,
                            Some(now),
                        )
                    })
                })
            })
            .or_else(|| {
                self.copy.as_ref().and_then(|receipt| {
                    expired(receipt.original).then(|| {
                        DeadlineContext::at(
                            DeadlineScope::Copy {
                                serial: receipt.id.serial,
                            },
                            receipt.original,
                            native,
                            Some(now),
                        )
                    })
                })
            });
        if let Some(context) = deadline {
            return Poll::Ready(Ok(SetProgress::Lost(
                self.failed(Error::deadline(context), None),
            )));
        }
        if self.copy_connect.as_ref().is_some_and(|x| !x.epoch.live())
            || self
                .operations
                .iter()
                .any(|x| x.acceptance.as_ref().is_some_and(|a| !a.epoch.live()))
        {
            return Poll::Ready(Ok(SetProgress::Lost(
                self.lost(Cause::OriginalSourceRetired, None),
            )));
        }
        let step = match self.session.poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(s)) => s,
            Poll::Ready(Err(error)) => {
                return Poll::Ready(Ok(SetProgress::Lost(self.failed(error, None))));
            }
        };
        let result = match step {
            Step::Attached(e) => Ok(SetProgress::Attached(e)),
            Step::Retry(e) => Ok(SetProgress::Retry(e)),
            Step::Activity => Ok(SetProgress::Activity),
            Step::Eof => return Poll::Ready(Ok(SetProgress::Lost(self.lost(Cause::Eof, None)))),
            Step::Written {
                epoch,
                tag,
                bytes,
                complete,
            } => self.written(epoch, tag, bytes, complete),
            Step::Frame { epoch, bytes } => self.frame(epoch, &bytes),
        };
        Poll::Ready(match result {
            Ok(p) => Ok(p),
            Err(e) => Ok(SetProgress::Lost(self.failed(e, None))),
        })
    }
    /// Await only the same source/operation owners, without a background task.
    pub async fn progress(&mut self) -> Result<SetProgress, Error> {
        poll_fn(|cx| self.poll_progress(cx)).await
    }
}
impl Drop for Set {
    fn drop(&mut self) {
        let _actual = self.close();
    }
}

#[cfg(all(test, unix))]
#[path = "set/timer_tests.rs"]
mod timer_tests;
