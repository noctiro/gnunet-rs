//! One actual session bridge; real SET sources remain separate original owners.
use crate::{
    Bounds, Error, Factory, Identity, Limits, Progress, SourceLossContext, SourceRefusal,
    core::{self, Action, Completion, EffectId, OfferId, SetId, TaskId, Validator},
};
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_set_client_host as set;
use gnunet_types::{AbsoluteTime, Error as Fault};
use gnunet_wire::official::consensus::{ClientResponse, Join, RoundContext};
use std::{
    future::Future,
    mem::size_of,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};
struct Source<'id> {
    id: SetId<'id>,
    native: Option<set::Set>,
    cursor: usize,
    mutation: Option<set::MutationId>,
    total: usize,
    initialized: bool,
    retired: Option<set::SetLoss>,
}
struct Task<'id> {
    id: TaskId<'id>,
    source: SetId<'id>,
    native: set::OperationId,
    peer: [u8; 32],
    terminal: bool,
}
struct Offer<'id> {
    id: OfferId<'id>,
    state: OfferState,
}
enum OfferState {
    Prepared(set::Prepared),
    Committing,
    Rejecting(set::RejectId),
}
struct Reconciliation<'id> {
    task: TaskId<'id>,
    source: SetId<'id>,
    peer: [u8; 32],
    context: RoundContext,
    incoming: Option<OfferId<'id>>,
    options: set::Options,
}
struct Commit<'id> {
    effect: EffectId<'id>,
    task: TaskId<'id>,
    source: SetId<'id>,
    peer: [u8; 32],
    prepared: Option<set::Prepared>,
    incoming: Option<OfferId<'id>>,
    original: Bounds,
}
struct LossWork<'id> {
    source: SetId<'id>,
    loss: set::SetLoss,
    cursor: usize,
}
/// One actual original core session. The ordinary SERVICE owns the real PILS
/// client and IPC client; this bridge owns every native generic SET dependency.
pub struct Bridge<'id, 'pils> {
    core: core::Session<'id>,
    identity: Identity<'pils>,
    factory: Factory,
    limits: Limits,
    original: Bounds,
    clock: Arc<dyn RuntimeClock>,
    listener: Option<set::Listener>,
    listener_created: bool,
    sources: Vec<Source<'id>>,
    tasks: Vec<Task<'id>>,
    offers: Vec<Offer<'id>>,
    commit: Option<Commit<'id>>,
    cancelling: Option<TaskId<'id>>,
    client: Option<EffectId<'id>>,
    terminal: Option<core::Terminal<'id>>,
    bound_event: Option<Progress<'id>>,
    listener_event: Option<set::ListenProgress>,
    fault: Option<Error>,
    source_refusal: Option<(SetId<'id>, SourceRefusal)>,
    loss: Option<LossWork<'id>>,
    first_source_loss: Option<SourceLossContext>,
    class: usize,
    source_cursor: usize,
    source_scan: usize,
    timer: Option<(u64, Pin<Box<Deadline>>)>,
    alarm: Option<Pin<Box<tokio::time::Sleep>>>,
    stopped: bool,
    last_now: u64,
    rejection: Option<([u8; 32], Fault)>,
    task_fault: Option<(TaskId<'id>, Fault)>,
}
fn classify(error: &set::Error) -> Fault {
    match error {
        set::Error::Protocol(e) => *e,
        set::Error::Deadline(_) => Fault::Deadline,
        set::Error::UnexpectedStatus(_) => Fault::Malformed,
        set::Error::Clock(_) | set::Error::Client(_) => Fault::Unavailable,
        set::Error::Io(_) => Fault::Io,
    }
}
fn cause(cause: &set::Cause) -> Fault {
    match cause {
        set::Cause::Failure(e) => classify(e),
        set::Cause::Deadline => Fault::Deadline,
        set::Cause::Requested => Fault::Cancelled,
        set::Cause::Eof | set::Cause::OriginalSourceRetired => Fault::Unavailable,
    }
}
fn pressure(error: &set::Error) -> bool {
    matches!(
        error,
        set::Error::Protocol(Fault::WouldBlock | Fault::NotReady | Fault::Capacity)
    )
}
fn global_error(error: &Error) -> bool {
    match error {
        Error::Set(error) => matches!(
            error.origin(),
            set::LossOrigin::Clock | set::LossOrigin::Selector
        ),
        Error::Native(_) => true,
        Error::Protocol(_) | Error::Io(_) => false,
    }
}
fn global_loss(cause: &set::Cause) -> bool {
    // The SDK records where the failure actually arose. A source's original
    // bounds, transport or protocol failure retires only that population; a
    // failed shared clock or endpoint port still fences the whole session.
    matches!(
        cause.origin(),
        set::LossOrigin::Clock | set::LossOrigin::Selector
    )
}
fn operation_loss(
    receipt: Option<&set::OperationReceipt>,
    native_admitted: bool,
    cause: Fault,
) -> Completion {
    match receipt {
        Some(receipt) if receipt.request_written => Completion::Written,
        Some(receipt) if receipt.written == 0 => Completion::Unsent(cause),
        None if !native_admitted => Completion::Unsent(cause),
        _ => Completion::Lost(cause),
    }
}
fn local_admission_error(error: &Error) -> bool {
    matches!(
        error,
        Error::Protocol(Fault::Deadline | Fault::Capacity | Fault::Overflow)
    )
}
fn cancellation_cause(intent: Option<set::CancellationCause>) -> Fault {
    match intent {
        Some(set::CancellationCause::Deadline) => Fault::Deadline,
        _ => Fault::Cancelled,
    }
}
fn uncreated_population<'id>(
    core: &core::Session<'id>,
    row: &Source<'id>,
    effect: EffectId<'id>,
) -> Result<(), Error> {
    if row.native.is_some()
        || row.retired.is_some()
        || row.initialized
        || row.cursor != 0
        || row.mutation.is_some()
        || core.set_context(row.id)?.retired.is_some()
        || !core.effect().is_some_and(|pending| {
            pending.id == effect
                && matches!(pending.action, Action::PrepareSet { set } if set == row.id)
        })
    {
        return Err(Fault::StaleGeneration.into());
    }
    Ok(())
}
fn remove_uncreated_population<'id>(
    core: &core::Session<'id>,
    sources: &mut Vec<Source<'id>>,
    source: SetId<'id>,
    effect: EffectId<'id>,
) -> Result<(), Error> {
    let at = sources
        .iter()
        .position(|row| row.id == source)
        .ok_or(Fault::StaleGeneration)?;
    uncreated_population(core, &sources[at], effect)?;
    // Global complete_effect(Unsent) closes the logical set immediately and
    // emits no CloseSet. Remove only this proven never-created host row first.
    sources.swap_remove(at);
    Ok(())
}
fn retire_uncreated_population<'id>(
    core: &mut core::Session<'id>,
    row: &Source<'id>,
    effect: EffectId<'id>,
    cause: Fault,
) -> Result<core::Terminal<'id>, Error> {
    uncreated_population(core, row, effect)?;
    core.source_retired(
        row.id,
        cause,
        Some(core::RetiredEffect::Disposition {
            effect,
            completion: Completion::Unsent(cause),
        }),
    )?
    .ok_or_else(|| Fault::NotReady.into())
}
impl<'id, 'pils> Bridge<'id, 'pils> {
    /// Construct from an actual verified original PILS observation and a frozen
    /// real SET Factory. No source is inferred from peer order/configured bytes.
    pub fn new(
        domain: &'id core::Instance,
        identity: Identity<'pils>,
        join: Join<'_>,
        factory: Factory,
        limits: Limits,
        original: Bounds,
        now: u64,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let clock = factory.clock();
        let original = Self::clamp(clock.as_ref(), original, join.deadline)?;
        if identity.expiration().as_micros() <= now {
            return Err(Fault::Deadline.into());
        }
        let core = core::Session::new(
            domain,
            *identity.peer().as_bytes(),
            join,
            limits.core,
            limits.set.abi,
            now,
        )?;
        Ok(Self {
            core,
            identity,
            factory,
            limits,
            original,
            clock,
            listener: None,
            listener_created: false,
            sources: Vec::new(),
            tasks: Vec::new(),
            offers: Vec::new(),
            commit: None,
            cancelling: None,
            client: None,
            terminal: None,
            bound_event: None,
            listener_event: None,
            fault: None,
            source_refusal: None,
            loss: None,
            first_source_loss: None,
            class: 0,
            source_cursor: 0,
            source_scan: 0,
            timer: None,
            alarm: None,
            stopped: false,
            last_now: now,
            rejection: None,
            task_fault: None,
        })
    }
    fn clamp(clock: &dyn RuntimeClock, original: Bounds, end: u64) -> Result<Bounds, Error> {
        let native = Instant::now();
        let now = clock
            .sample()
            .map_err(|error| set::Error::Clock(gnunet_client_host::ConnectError::Protocol(error)))?
            .now
            .as_micros();
        let expires = end.min(original.expires);
        let us = expires
            .checked_sub(now)
            .filter(|n| *n != 0)
            .ok_or(Fault::Deadline)?;
        let hard = native
            .checked_add(Duration::from_micros(us))
            .ok_or(Fault::Overflow)?
            .min(original.hard);
        if Instant::now() >= hard {
            return Err(Fault::Deadline.into());
        }
        Ok(Bounds { expires, hard })
    }
    fn effect_bounds(&self) -> Result<Bounds, Error> {
        let end = self
            .core
            .effect()
            .and_then(|e| e.deadline())
            .ok_or(Fault::NotReady)?;
        Self::clamp(self.clock.as_ref(), self.original, end)
    }
    fn metadata(&self) -> Result<usize, Error> {
        self.sources
            .capacity()
            .checked_mul(size_of::<Source<'id>>())
            .and_then(|n| {
                self.tasks
                    .capacity()
                    .checked_mul(size_of::<Task<'id>>())
                    .and_then(|m| n.checked_add(m))
            })
            .and_then(|n| {
                self.offers
                    .capacity()
                    .checked_mul(size_of::<Offer<'id>>())
                    .and_then(|m| n.checked_add(m))
            })
            .ok_or_else(|| Fault::Overflow.into())
    }
    fn reserve<T>(values: &mut Vec<T>, max: usize, free: usize) -> Result<(), Error> {
        if values.len() >= max {
            return Err(Fault::Capacity.into());
        }
        if values.len() < values.capacity() {
            return Ok(());
        }
        let target = values
            .capacity()
            .max(2)
            .checked_mul(2)
            .ok_or(Fault::Overflow)?
            .min(max);
        if target.checked_mul(size_of::<T>()).ok_or(Fault::Overflow)? > free {
            return Err(Fault::Capacity.into());
        }
        let mut next = Vec::new();
        next.try_reserve_exact(target)
            .map_err(|_| Fault::Capacity)?;
        if next
            .capacity()
            .checked_mul(size_of::<T>())
            .ok_or(Fault::Overflow)?
            > free
        {
            return Err(Fault::Capacity.into());
        }
        next.append(values);
        *values = next;
        Ok(())
    }
    fn free(&self) -> Result<usize, Error> {
        self.limits
            .retained_bytes
            .checked_sub(self.metadata()?)
            .ok_or_else(|| Fault::Capacity.into())
    }
    fn source(&self, id: SetId<'id>) -> Result<usize, Error> {
        self.sources
            .iter()
            .position(|s| s.id == id)
            .ok_or_else(|| Fault::StaleGeneration.into())
    }
    fn task(&self, id: TaskId<'id>) -> Result<usize, Error> {
        self.tasks
            .iter()
            .position(|t| t.id == id)
            .ok_or_else(|| Fault::StaleGeneration.into())
    }
    fn settle(&mut self, id: EffectId<'id>, completion: Completion) -> Result<(), Error> {
        if self.terminal.is_some() {
            return Err(Fault::WouldBlock.into());
        }
        self.terminal = Some(self.core.complete_effect(id, completion)?);
        Ok(())
    }
    fn admit(&mut self, id: EffectId<'id>) -> Result<(), Error> {
        if !self.core.effect().ok_or(Fault::NotReady)?.is_admitted() {
            self.core.admit_effect(id)?;
        }
        Ok(())
    }
    /// Original session state, not native source authority.
    #[must_use]
    pub const fn session(&self) -> &core::Session<'id> {
        &self.core
    }
    /// Apply the original caller's opaque insertion with an explicit policy.
    pub fn insert(
        &mut self,
        element_type: u16,
        data: &[u8],
        now: u64,
        validator: &mut impl Validator,
    ) -> Result<(), Error> {
        self.core.insert(element_type, data, now, validator)?;
        Ok(())
    }
    /// Freeze original insertion; no SET/peer completion is inferred.
    pub fn conclude(&mut self, now: u64) -> Result<(), Error> {
        self.core.conclude(now)?;
        Ok(())
    }
    /// Cancel original logical work without reading a potentially failed clock.
    /// Admitted IPC/native dispositions remain owned until actually reported.
    pub fn cancel(&mut self, cause: Fault) -> Result<(), Error> {
        if !self.core.is_quiescent() {
            self.core.cancel(cause)?;
        }
        self.timer = None;
        self.alarm = None;
        Ok(())
    }
    /// Caller reports the actual disposition of the exact prior ClientFrame or
    /// CloseClient. It must physically stop partial output before Lost/Unsent.
    pub fn complete_client(
        &mut self,
        id: EffectId<'id>,
        completion: Completion,
    ) -> Result<core::Terminal<'id>, Error> {
        if self.client != Some(id) {
            return Err(Fault::StaleGeneration.into());
        }
        let terminal = self.core.complete_effect(id, completion)?;
        self.client = None;
        Ok(terminal)
    }
    /// Original logical next target; no retry creates a new public deadline.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        self.core.next_deadline()
    }
    /// Original unchanged native hard, usable while external output blocks.
    #[must_use]
    pub const fn native_deadline(&self) -> Instant {
        self.original.hard
    }
    /// All bridge sources and original core obligations really retired.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.core.is_quiescent()
            && self.listener.is_none()
            && self.sources.is_empty()
            && self.commit.is_none()
            && self.loss.is_none()
            && self.client.is_none()
            && self.terminal.is_none()
            && self.bound_event.is_none()
            && self.listener_event.is_none()
            && self.fault.is_none()
            && self.source_refusal.is_none()
    }
    /// Clock-free hard fence. True starts original cancellation; the caller must
    /// continue poll_retirement and settle its actual original IPC disposition.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        if self.core.is_quiescent() {
            return Ok(false);
        }
        let at = self.original.hard;
        let expired = if Instant::now() >= at {
            true
        } else {
            let alarm = self
                .alarm
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(at.into())));
            alarm.as_mut().poll(cx).is_ready()
        };
        if expired {
            self.cancel(Fault::Deadline)?;
        }
        Ok(expired)
    }
    fn listener_close(&mut self) {
        if let Some(mut listener) = self.listener.take() {
            self.listener_event = Some(set::ListenProgress::Lost(listener.close()));
        }
        self.offers.clear();
    }
    fn fail_effect(
        &mut self,
        id: EffectId<'id>,
        error: Error,
        incoming: bool,
    ) -> Result<(), Error> {
        if incoming {
            self.listener_close();
        }
        self.commit = None;
        let why = error.classified();
        let shared_port = global_error(&error);
        self.settle(id, Completion::Unsent(why))?;
        if shared_port {
            self.cancel(why)?;
        }
        self.fault = Some(error);
        Ok(())
    }
    fn output(&mut self, id: EffectId<'id>) -> Result<Option<Progress<'id>>, Error> {
        if self.client.is_some() {
            return Ok(None);
        }
        let effect = self.core.effect().ok_or(Fault::NotReady)?;
        let request = match &effect.action {
            Action::ClientElement { element_type, data } => ClientResponse::Element {
                element_type: *element_type,
                data,
            },
            Action::ClientDone => ClientResponse::Done,
            Action::CloseClient { cause } => {
                let cause = *cause;
                self.admit(id)?;
                self.client = Some(id);
                return Ok(Some(Progress::CloseClient { effect: id, cause }));
            }
            _ => return Err(Fault::InvalidInput.into()),
        };
        let length = request.encoded_len()?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| Fault::Capacity)?;
        bytes.resize(length, 0);
        request.encode(&mut bytes)?;
        self.admit(id)?;
        self.client = Some(id);
        Ok(Some(Progress::ClientFrame { effect: id, bytes }))
    }
    fn reserve_population(&mut self, source: SetId<'id>) -> Result<(), Error> {
        if self.sources.iter().any(|row| row.id == source) {
            return Ok(());
        }
        let total = self.core.set_len(source)?;
        let free = self.free()?;
        Self::reserve(&mut self.sources, self.limits.core.sets, free)?;
        // The ledger precedes every fallible clock/provider admission. An empty
        // row is proof of never-creation, retained through its exact CloseSet.
        self.sources.push(Source {
            id: source,
            native: None,
            cursor: 0,
            mutation: None,
            total,
            initialized: false,
            retired: None,
        });
        self.source_scan = self.sources.len();
        Ok(())
    }
    fn prepare(&mut self, id: EffectId<'id>, set: SetId<'id>) -> Result<bool, Error> {
        let at = self.source(set)?;
        if self.sources[at].native.is_none() {
            uncreated_population(&self.core, &self.sources[at], id)?;
            let original = self.effect_bounds()?;
            let native = self
                .factory
                .set(set::OperationType::Union, self.limits.set, original)?;
            self.sources[at].native = Some(native);
            self.source_scan = self.sources.len();
            return Ok(true);
        }
        let row = &mut self.sources[at];
        let native = row.native.as_mut().ok_or(Fault::Unavailable)?;
        if !native.initialized() || row.mutation.is_some() {
            return Ok(false);
        }
        if row.cursor == row.total {
            self.settle(id, Completion::Written)?;
            return Ok(true);
        }
        let element = self
            .core
            .set_element(set, row.cursor)?
            .ok_or(Fault::NotReady)?;
        match native.add(element) {
            Ok(mutation) => {
                row.mutation = Some(mutation);
                self.source_scan = self.sources.len();
                Ok(true)
            }
            Err(e) if pressure(&e) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
    fn reconcile(
        &mut self,
        id: EffectId<'id>,
        request: Reconciliation<'id>,
    ) -> Result<bool, Error> {
        let Reconciliation {
            task,
            source,
            peer,
            context,
            incoming,
            options,
        } = request;
        if self.commit.is_none() {
            let original = self.effect_bounds()?;
            let prepared = if let Some(offer) = incoming {
                let at = self
                    .offers
                    .iter()
                    .position(|o| o.id == offer)
                    .ok_or(Fault::StaleGeneration)?;
                let OfferState::Prepared(prepared) =
                    std::mem::replace(&mut self.offers[at].state, OfferState::Committing)
                else {
                    return Err(Fault::StaleGeneration.into());
                };
                prepared.with_options(options)
            } else {
                let mut bytes = [0; 16];
                context.encode(&mut bytes)?;
                set::Prepared::evaluate(
                    peer,
                    self.core.global_id(),
                    &bytes,
                    set::ResultMode::Symmetric,
                    options,
                )?
            };
            self.commit = Some(Commit {
                effect: id,
                task,
                source,
                peer,
                prepared: Some(prepared),
                incoming,
                original,
            });
        }
        let at = self.source(source)?;
        let native = self.sources[at].native.as_mut().ok_or(Fault::Unavailable)?;
        let commit = self.commit.as_mut().ok_or(Fault::NotReady)?;
        if commit.effect != id || commit.task != task || commit.source != source {
            return Err(Fault::StaleGeneration.into());
        }
        let epoch = native.epoch().cloned().ok_or(Fault::StaleGeneration)?;
        let Some(prepared) = commit.prepared.take() else {
            return Ok(false);
        };
        match native.commit(prepared, commit.original) {
            Ok(operation) => {
                if let Some(incoming) = commit.incoming {
                    let offer = self
                        .offers
                        .iter()
                        .position(|offer| offer.id == incoming)
                        .ok_or(Fault::StaleGeneration)?;
                    self.offers.swap_remove(offer);
                }
                self.bound_event = Some(Progress::OperationBound {
                    task,
                    set: source,
                    epoch,
                    operation: operation.clone(),
                });
                self.tasks.push(Task {
                    id: task,
                    source,
                    native: operation,
                    peer: commit.peer,
                    terminal: false,
                });
                self.source_scan = self.sources.len();
                Ok(true)
            }
            Err(failure) => {
                commit.prepared = Some(failure.prepared);
                if pressure(&failure.error) {
                    Ok(false)
                } else {
                    Err(failure.error.into())
                }
            }
        }
    }
    fn cancel_task(
        &mut self,
        id: EffectId<'id>,
        task: TaskId<'id>,
    ) -> Result<Option<Progress<'id>>, Error> {
        let at = self.task(task)?;
        if self.tasks[at].terminal {
            self.settle(id, Completion::Retired)?;
            self.cancelling = None;
            return Ok(Some(Progress::Activity));
        }
        if self.cancelling == Some(task) {
            return Ok(None);
        }
        let source = self.tasks[at].source;
        let native_id = self.tasks[at].native.clone();
        let s = self.source(source)?;
        let Some(native) = self.sources[s].native.as_mut() else {
            self.tasks[at].terminal = true;
            self.settle(id, Completion::Retired)?;
            return Ok(Some(Progress::Activity));
        };
        match native.cancel(&native_id) {
            Ok(set::CancelDisposition::Queued) => {
                self.cancelling = Some(task);
                self.source_scan = self.sources.len();
                Ok(Some(Progress::Activity))
            }
            Ok(set::CancelDisposition::Unsent(receipt)) => {
                self.tasks[at].terminal = true;
                self.settle(id, Completion::Retired)?;
                Ok(Some(Progress::Cancelled { task, receipt }))
            }
            Ok(set::CancelDisposition::SourceRetired(loss)) => {
                self.begin_loss(source, loss, false)?;
                Ok(Some(Progress::Activity))
            }
            Err(e) if pressure(&e) => Ok(None),
            Err(error) => {
                let loss = native.retire_after(error);
                self.begin_loss(source, loss, false)?;
                Ok(Some(Progress::Activity))
            }
        }
    }
    fn drive_effect(&mut self) -> Result<Option<Progress<'id>>, Error> {
        let Some(effect) = self.core.effect() else {
            return Ok(None);
        };
        let id = effect.id;
        if matches!(
            effect.action,
            Action::Listen { .. }
                | Action::PrepareSet { .. }
                | Action::Reconcile { .. }
                | Action::ClientElement { .. }
                | Action::ClientDone
        ) && !self.core.effect_io_allowed(id)
        {
            let source = match effect.action {
                Action::PrepareSet { set } | Action::Reconcile { set, .. } => Some(set),
                _ => None,
            };
            if let Some(source) = source
                && self.core.outcome().failure.is_none()
                && effect.deadline().is_some_and(|end| self.last_now >= end)
            {
                return self.expired_source(source, id);
            }
            return Ok(None);
        }
        enum Plan<'id> {
            Listen([u8; 64]),
            Prepare(SetId<'id>),
            Reconcile(Reconciliation<'id>),
            Cancel(TaskId<'id>),
            CloseSet(SetId<'id>),
            CloseListener,
            Reject(OfferId<'id>),
            Output,
        }
        let plan = match &effect.action {
            Action::Listen { global_id } => Plan::Listen(*global_id),
            Action::PrepareSet { set } => Plan::Prepare(*set),
            Action::Reconcile {
                task,
                set,
                peer,
                context,
                incoming,
                ..
            } => Plan::Reconcile(Reconciliation {
                task: *task,
                source: *set,
                peer: *peer,
                context: *context,
                incoming: *incoming,
                options: effect.action.set_options().ok_or(Fault::InvalidInput)?,
            }),
            Action::CancelTask { task } => Plan::Cancel(*task),
            Action::CloseSet { set } => Plan::CloseSet(*set),
            Action::CloseListener => Plan::CloseListener,
            Action::RejectOffer { offer } => Plan::Reject(*offer),
            Action::ClientElement { .. } | Action::ClientDone | Action::CloseClient { .. } => {
                Plan::Output
            }
        };
        if matches!(plan, Plan::Output) {
            return self.output(id);
        }
        self.admit(id)?;
        match plan {
            Plan::Listen(app) => {
                if self.listener.is_some() {
                    return Ok(None);
                }
                if self.listener_created {
                    return Err(Fault::Unavailable.into());
                }
                let attempt = self.effect_bounds().and_then(|bounds| {
                    self.factory
                        .listen(set::OperationType::Union, app, self.limits.set, bounds)
                        .map_err(Error::from)
                });
                match attempt {
                    Ok(listener) => {
                        self.listener = Some(listener);
                        self.listener_created = true;
                    }
                    Err(error) => self.fail_effect(id, error, false)?,
                }
                Ok(Some(Progress::Activity))
            }
            Plan::Prepare(source) => {
                // Failure to reserve the ownership ledger cannot be treated as
                // proven local retirement: no row exists to retain CloseSet.
                if let Err(error) = self.reserve_population(source) {
                    self.fail_effect(id, error, false)?;
                    return Ok(Some(Progress::Activity));
                }
                match self.prepare(id, source) {
                    Ok(true) => Ok(Some(Progress::Activity)),
                    Ok(false) => Ok(None),
                    Err(error) => {
                        self.refuse_source(source, id, error, false)?;
                        Ok(Some(Progress::Activity))
                    }
                }
            }
            Plan::Reconcile(request) => {
                let incoming = request.incoming.is_some();
                let source = request.source;
                if self.commit.is_none() {
                    let free = self.free()?;
                    if let Err(error) = Self::reserve(&mut self.tasks, self.limits.core.tasks, free)
                    {
                        self.fail_effect(id, error, incoming)?;
                        return Ok(Some(Progress::Activity));
                    }
                }
                match self.reconcile(id, request) {
                    Ok(true) => Ok(Some(Progress::Activity)),
                    Ok(false) => Ok(None),
                    Err(error) => {
                        self.refuse_source(source, id, error, incoming)?;
                        Ok(Some(Progress::Activity))
                    }
                }
            }
            Plan::Cancel(task) => self.cancel_task(id, task),
            Plan::CloseSet(source) => {
                let at = self.source(source)?;
                if let Some(native) = &mut self.sources[at].native {
                    let loss = native.close();
                    self.begin_loss(source, loss, false)?;
                    return Ok(Some(Progress::Activity));
                }
                self.sources.swap_remove(at);
                self.tasks.retain(|t| t.source != source);
                self.settle(id, Completion::Retired)?;
                Ok(Some(Progress::Activity))
            }
            Plan::CloseListener => {
                self.listener_close();
                self.settle(id, Completion::Retired)?;
                Ok(Some(Progress::Activity))
            }
            Plan::Reject(offer) => self.reject_offer(id, offer),
            Plan::Output => Err(Fault::InvalidInput.into()),
        }
    }
    fn source_refusal(&mut self, source: SetId<'id>, error: Error) -> Result<Fault, Error> {
        if self.source_refusal.is_some() || self.terminal.is_some() || self.loss.is_some() {
            return Err(Fault::WouldBlock.into());
        }
        let why = error.classified();
        self.source_refusal = Some((
            source,
            SourceRefusal {
                source: self.core.set_context(source).ok(),
                error,
                last_host_canonical: self.last_now,
                observed_native: Instant::now(),
            },
        ));
        Ok(why)
    }
    fn retire_uncreated(
        &mut self,
        source: SetId<'id>,
        effect: EffectId<'id>,
        error: Error,
    ) -> Result<(), Error> {
        let at = self.source(source)?;
        uncreated_population(&self.core, &self.sources[at], effect)?;
        let why = self.source_refusal(source, error)?;
        self.terminal = Some(retire_uncreated_population(
            &mut self.core,
            &self.sources[at],
            effect,
            why,
        )?);
        Ok(())
    }
    fn refuse_source(
        &mut self,
        source: SetId<'id>,
        effect: EffectId<'id>,
        error: Error,
        incoming: bool,
    ) -> Result<(), Error> {
        let at = self.source(source)?;
        if self.sources[at].native.is_none() {
            if global_error(&error)
                || !(local_admission_error(&error) || matches!(error, Error::Set(_)))
            {
                remove_uncreated_population(&self.core, &mut self.sources, source, effect)?;
                self.source_scan = self.sources.len();
                return self.fail_effect(effect, error, incoming);
            }
            uncreated_population(&self.core, &self.sources[at], effect)?;
            return self.retire_uncreated(source, effect, error);
        }
        match error {
            Error::Set(error) => {
                let loss = self.sources[at]
                    .native
                    .as_mut()
                    .ok_or(Fault::NotReady)?
                    .retire_after(error);
                self.begin_loss(source, loss, false)
            }
            error if local_admission_error(&error) => {
                let why = self.source_refusal(source, error)?;
                let loss = self.sources[at]
                    .native
                    .as_mut()
                    .ok_or(Fault::NotReady)?
                    .close();
                // Requested remains the physical receipt. The original business
                // refusal separately terminates these exact source tasks.
                self.begin_loss_with_cause(source, loss, false, Some(why))
            }
            error => {
                let loss = self.sources[at]
                    .native
                    .as_mut()
                    .ok_or(Fault::NotReady)?
                    .close();
                self.begin_loss_with_cause(source, loss, true, Some(error.classified()))?;
                self.fault = Some(error);
                Ok(())
            }
        }
    }
    fn expired_source(
        &mut self,
        source: SetId<'id>,
        effect: EffectId<'id>,
    ) -> Result<Option<Progress<'id>>, Error> {
        self.reserve_population(source)?;
        if self.sources[self.source(source)?].native.is_none() {
            self.retire_uncreated(source, effect, Fault::Deadline.into())?;
        } else {
            self.refuse_source(source, effect, Fault::Deadline.into(), false)?;
        }
        Ok(Some(Progress::Activity))
    }
    fn reject_offer(
        &mut self,
        effect: EffectId<'id>,
        offer: OfferId<'id>,
    ) -> Result<Option<Progress<'id>>, Error> {
        let Some(listener) = &mut self.listener else {
            // Only retirement of the original listener can discharge an
            // unwritten rejection without a corresponding whole-write fact.
            if let Some(at) = self.offers.iter().position(|row| row.id == offer) {
                self.offers.swap_remove(at);
            }
            self.settle(effect, Completion::Retired)?;
            return Ok(Some(Progress::Activity));
        };
        let at = self
            .offers
            .iter()
            .position(|row| row.id == offer)
            .ok_or(Fault::StaleGeneration)?;
        if matches!(self.offers[at].state, OfferState::Rejecting(_)) {
            return Ok(None);
        }
        let OfferState::Prepared(prepared) =
            std::mem::replace(&mut self.offers[at].state, OfferState::Committing)
        else {
            return Err(Fault::NotReady.into());
        };
        match listener.reject_prepared(prepared) {
            Ok(rejection) => {
                self.offers[at].state = OfferState::Rejecting(rejection);
                Ok(Some(Progress::Activity))
            }
            Err(failure) => {
                self.offers[at].state = OfferState::Prepared(failure.prepared);
                if pressure(&failure.error) {
                    return Ok(None);
                }
                let why = classify(&failure.error);
                self.listener_close();
                self.cancel(why)?;
                self.fault = Some(failure.error.into());
                Ok(Some(Progress::Activity))
            }
        }
    }
    fn record_source_loss(&mut self, source: SetId<'id>, loss: &set::SetLoss) {
        // Empty requested phase closes must not hide a later genuine failure.
        // This copy adds no clock sample, payload owner or queue. Missing core
        // labels never prevent physical retirement or receipt preservation.
        let important = !matches!(loss.cause, set::Cause::Requested)
            || !loss.operations.is_empty()
            || !loss.mutations.is_empty()
            || loss.iteration.is_some()
            || loss.copy.is_some();
        if important && self.first_source_loss.is_none() {
            self.first_source_loss = Some(SourceLossContext {
                source: self.core.set_context(source).ok(),
                origin: loss.cause.origin(),
                deadline: loss.deadline.as_deref().copied(),
                last_host_canonical: self.last_now,
                observed_native: Instant::now(),
            });
        }
    }
    fn begin_loss(
        &mut self,
        source: SetId<'id>,
        loss: set::SetLoss,
        force_global: bool,
    ) -> Result<(), Error> {
        self.begin_loss_with_cause(source, loss, force_global, None)
    }
    fn begin_loss_with_cause(
        &mut self,
        source: SetId<'id>,
        loss: set::SetLoss,
        force_global: bool,
        semantic_cause: Option<Fault>,
    ) -> Result<(), Error> {
        if self.loss.is_some() {
            return Err(Fault::WouldBlock.into());
        }
        let at = self.source(source)?;
        self.record_source_loss(source, &loss);
        self.sources[at].native = None;
        let global = force_global || global_loss(&loss.cause);
        let why = semantic_cause.unwrap_or_else(|| if self.core.effect().is_some_and(|effect| {
            effect.deadline().is_some_and(|end| self.last_now >= end)
                && matches!(effect.action, Action::PrepareSet { set } | Action::Reconcile { set, .. } if set == source)
        }) {
            Fault::Deadline
        } else {
            cause(&loss.cause)
        });
        // Install the original physical loss before any fallible core update;
        // an unexpected bookkeeping error must not discard its native facts.
        self.loss = Some(LossWork {
            source,
            loss,
            cursor: 0,
        });
        let loss = &self.loss.as_ref().ok_or(Fault::NotReady)?.loss;
        let pending = if let Some(effect) = self.core.effect() {
            let disposition = match &effect.action {
                Action::PrepareSet { set } if *set == source => {
                    let row = &self.sources[at];
                    Some(
                        if row.initialized && row.cursor == row.total && row.mutation.is_none() {
                            Completion::Written
                        } else if loss.transport.initializer_bytes == 0
                            && !row.initialized
                            && row.cursor == 0
                        {
                            Completion::Unsent(why)
                        } else {
                            Completion::Lost(why)
                        },
                    )
                }
                Action::Reconcile { task, set, .. } if *set == source => {
                    let native = self.tasks.iter().find(|t| t.id == *task);
                    let original =
                        native.and_then(|t| loss.operations.iter().find(|r| r.id == t.native));
                    Some(operation_loss(original, native.is_some(), why))
                }
                Action::CancelTask { task }
                    if self
                        .tasks
                        .iter()
                        .any(|t| t.id == *task && t.source == source) =>
                {
                    Some(Completion::Retired)
                }
                _ => None,
            };
            disposition.map(|completion| {
                if let Action::Reconcile {
                    task,
                    incoming: Some(offer),
                    ..
                } = effect.action
                    && self.tasks.iter().all(|row| row.id != task)
                {
                    core::RetiredEffect::Uncommitted {
                        effect: effect.id,
                        offer,
                        cause: why,
                    }
                } else {
                    core::RetiredEffect::Disposition {
                        effect: effect.id,
                        completion,
                    }
                }
            })
        } else {
            None
        };
        if self
            .commit
            .as_ref()
            .is_some_and(|commit| commit.source == source)
        {
            let mut commit = self.commit.take().ok_or(Fault::NotReady)?;
            if let Some(prepared) = commit.prepared.take()
                && let Some(incoming) = commit.incoming
            {
                let at = self
                    .offers
                    .iter()
                    .position(|offer| offer.id == incoming)
                    .ok_or(Fault::StaleGeneration)?;
                self.offers[at].state = OfferState::Prepared(prepared);
            }
        }
        if self.cancelling.is_some_and(|task| {
            self.tasks
                .iter()
                .any(|row| row.id == task && row.source == source)
        }) {
            self.cancelling = None;
        }
        let terminal = self.core.source_retired(source, why, pending)?;
        if let Some(terminal) = terminal {
            if self.terminal.is_some() {
                return Err(Fault::WouldBlock.into());
            }
            self.terminal = Some(terminal);
        }
        if global {
            self.cancel(why)?;
        }
        Ok(())
    }
    fn drain_loss(
        &mut self,
        _validator: &mut impl Validator,
    ) -> Result<Option<Progress<'id>>, Error> {
        let Some(work) = &mut self.loss else {
            return Ok(None);
        };
        if work.cursor < self.tasks.len() {
            let at = work.cursor;
            work.cursor += 1;
            if self.tasks[at].source == work.source && !self.tasks[at].terminal {
                // The source-retired boundary already invalidated every core
                // task, including never-committed plans. This marks only its
                // original native rows retired; it is not a peer SET callback.
                self.tasks[at].terminal = true;
            }
            return Ok(Some(Progress::Activity));
        }
        let work = self.loss.take().ok_or(Fault::NotReady)?;
        Ok(Some(Progress::Set {
            set: work.source,
            event: set::SetProgress::Lost(work.loss),
        }))
    }
    fn listen(&mut self, cx: &mut Context<'_>) -> Result<Option<Progress<'id>>, Error> {
        if self.listener.is_none() {
            return Ok(None);
        }
        if !self.core.listener_live()
            && self
                .core
                .effect()
                .is_none_or(|e| !matches!(e.action, Action::Listen { .. }))
        {
            self.listener_close();
            return Ok(Some(Progress::Activity));
        }
        let free = self.free()?;
        let max = self.limits.core.offers;
        let core = &mut self.core;
        let offers = &mut self.offers;
        let mut accepted = None;
        let mut rejected = None;
        let step = self
            .listener
            .as_mut()
            .ok_or(Fault::NotReady)?
            .poll_progress(cx, &mut |incoming| {
                let decide = (|| -> Result<(OfferId<'id>, RoundContext), Fault> {
                    let context = RoundContext::decode(incoming.context)?;
                    Self::reserve(offers, max, free).map_err(|e| match e {
                        Error::Protocol(e) => e,
                        Error::Set(_) | Error::Native(_) | Error::Io(_) => Fault::Capacity,
                    })?;
                    let id = core.offer(incoming.peer, context, self.last_now)?;
                    Ok((id, context))
                })();
                match decide {
                    Ok((id, context)) => {
                        accepted = Some((id, incoming.epoch.clone(), incoming.peer, context));
                        set::Decision::Accept {
                            mode: set::ResultMode::Symmetric,
                            options: set::Options {
                                force_delta: 0,
                                force_full: 0,
                                byzantine: 1,
                                byzantine_lower_bound: 0,
                            },
                        }
                    }
                    Err(error) => {
                        rejected = Some((incoming.peer, error));
                        set::Decision::Reject
                    }
                }
            });
        if let Some(rejected) = rejected {
            self.rejection = Some(rejected);
        }
        let event = match step {
            Poll::Pending => return Ok(None),
            Poll::Ready(Ok(event)) => event,
            Poll::Ready(Err(e)) => {
                self.listener_close();
                self.cancel(classify(&e))?;
                return Ok(Some(Progress::Fault(e.into())));
            }
        };
        match event {
            set::ListenProgress::Accepted(prepared) => {
                let (id, epoch, peer, context) = accepted.ok_or(Fault::StaleGeneration)?;
                self.offers.push(Offer {
                    id,
                    state: OfferState::Prepared(prepared),
                });
                Ok(Some(Progress::Offer {
                    offer: id,
                    epoch,
                    peer,
                    context,
                }))
            }
            set::ListenProgress::Written {
                epoch,
                rejected: Some(rejected),
                complete: true,
                bytes,
            } => {
                if let Some(effect) = self.core.effect()
                    && let Action::RejectOffer { offer } = effect.action
                    && let Some(at) = self.offers.iter().position(|row| row.id == offer)
                    && matches!(&self.offers[at].state, OfferState::Rejecting(id) if id.matches(&epoch, rejected))
                {
                    let effect = effect.id;
                    self.offers.swap_remove(at);
                    self.settle(effect, Completion::Written)?;
                }
                Ok(Some(Progress::Listener(set::ListenProgress::Written {
                    epoch,
                    rejected: Some(rejected),
                    complete: true,
                    bytes,
                })))
            }
            event @ set::ListenProgress::Written {
                complete: true,
                rejected: None,
                ..
            } => {
                if let Some(effect) = self.core.effect()
                    && matches!(effect.action, Action::Listen { .. })
                {
                    self.settle(effect.id, Completion::Written)?;
                }
                Ok(Some(Progress::Listener(event)))
            }
            set::ListenProgress::Lost(loss) => {
                if let Some(effect) = self.core.effect()
                    && matches!(effect.action, Action::Listen { .. })
                {
                    let completion = if loss.transport.initializer_written {
                        Completion::Written
                    } else if loss.transport.initializer_bytes == 0 {
                        Completion::Unsent(cause(&loss.cause))
                    } else {
                        Completion::Lost(cause(&loss.cause))
                    };
                    self.settle(effect.id, completion)?;
                }
                let why = cause(&loss.cause);
                self.listener_close();
                self.cancel(why)?;
                Ok(Some(Progress::Listener(set::ListenProgress::Lost(loss))))
            }
            other => Ok(Some(Progress::Listener(other))),
        }
    }
    fn actual_set(
        &mut self,
        source: SetId<'id>,
        event: set::SetProgress,
        validator: &mut impl Validator,
    ) -> Result<Option<Progress<'id>>, Error> {
        match &event {
            set::SetProgress::InitializerWritten { complete: true, .. } => {
                let at = self.source(source)?;
                self.sources[at].initialized = true;
            }
            set::SetProgress::MutationWritten(receipt) => {
                let at = self.source(source)?;
                if self.sources[at].mutation.as_ref() != Some(&receipt.id) {
                    return Err(Fault::StaleGeneration.into());
                }
                if receipt.whole {
                    self.sources[at].cursor = self.sources[at]
                        .cursor
                        .checked_add(1)
                        .ok_or(Fault::Overflow)?;
                    self.sources[at].mutation = None;
                }
            }
            set::SetProgress::OperationWritten {
                operation,
                complete: true,
                ..
            } => {
                let at = self
                    .tasks
                    .iter()
                    .position(|t| t.source == source && t.native == *operation)
                    .ok_or(Fault::StaleGeneration)?;
                if let Some(effect) = self.core.effect()
                    && matches!(effect.action,Action::Reconcile{task,..}if task==self.tasks[at].id)
                {
                    self.settle(effect.id, Completion::Written)?;
                    self.commit = None;
                }
            }
            set::SetProgress::Result {
                operation,
                current_size,
                status,
                element,
                terminal,
                ..
            } => {
                let at = self
                    .tasks
                    .iter()
                    .position(|t| t.source == source && t.native == *operation)
                    .ok_or(Fault::StaleGeneration)?;
                if !self.tasks[at].terminal {
                    let id = self.tasks[at].id;
                    let peer = self.tasks[at].peer;
                    let result = match status {
                        set::Status::AddLocal => Some(core::SetEvent::AddLocal {
                            element_type: element.element_type,
                            data: &element.data,
                        }),
                        set::Status::AddRemote => Some(core::SetEvent::AddRemote {
                            element_type: element.element_type,
                            data: &element.data,
                        }),
                        set::Status::Done if terminal.is_some() => Some(core::SetEvent::Done {
                            current_size: *current_size,
                        }),
                        set::Status::Failure if terminal.is_some() => {
                            Some(core::SetEvent::Failure(Fault::Unavailable))
                        }
                        set::Status::HalfDone => None,
                        _ => {
                            self.task_fault = Some((id, Fault::Malformed));
                            // This is local refusal, not an actual terminal reply.
                            // Retire original native IO before reporting failure.
                            self.cancel(Fault::Malformed)?;
                            None
                        }
                    };
                    if let Some(result) = result
                        && let Err(e) =
                            self.core
                                .set_result(id, peer, result, self.last_now, validator)
                        && (!matches!(e, Fault::Closed | Fault::StaleGeneration)
                            || self.core.task_live(id))
                    {
                        self.task_fault = Some((id, e));
                    }
                    if terminal.is_some() {
                        self.tasks[at].terminal = true;
                    }
                }
            }
            set::SetProgress::OperationCancelled(receipt) => {
                let at = self
                    .tasks
                    .iter()
                    .position(|t| t.source == source && t.native == receipt.id)
                    .ok_or(Fault::StaleGeneration)?;
                let task = self.tasks[at].id;
                let why = cancellation_cause(receipt.cancellation);
                if let Some(effect) = self.core.effect() {
                    if matches!(effect.action,Action::CancelTask{task:original}if original==task) {
                        self.settle(effect.id, Completion::Retired)?;
                        self.cancelling = None;
                    } else if !self.tasks[at].terminal {
                        self.core.set_result(
                            task,
                            self.tasks[at].peer,
                            core::SetEvent::Failure(why),
                            self.last_now,
                            validator,
                        )?;
                    }
                } else if !self.tasks[at].terminal {
                    self.core.set_result(
                        task,
                        self.tasks[at].peer,
                        core::SetEvent::Failure(why),
                        self.last_now,
                        validator,
                    )?;
                }
                self.tasks[at].terminal = true;
            }
            _ => {}
        }
        if let set::SetProgress::Lost(loss) = event {
            self.begin_loss(source, loss, false)?;
            Ok(Some(Progress::Activity))
        } else {
            Ok(Some(Progress::Set { set: source, event }))
        }
    }
    fn poll_sources(
        &mut self,
        cx: &mut Context<'_>,
        validator: &mut impl Validator,
    ) -> Result<Option<Progress<'id>>, Error> {
        if self.sources.is_empty() {
            return Ok(None);
        }
        if self.source_scan == 0 {
            self.source_scan = self.sources.len();
        }
        let count = self.source_scan.min(32);
        for _ in 0..count {
            self.source_cursor %= self.sources.len();
            let at = self.source_cursor;
            self.source_cursor += 1;
            self.source_scan -= 1;
            let source = self.sources[at].id;
            if self.sources[at].native.is_none() {
                continue;
            }
            if !self.core.set_live(source) {
                let loss = self.sources[at]
                    .native
                    .as_mut()
                    .ok_or(Fault::NotReady)?
                    .close();
                self.begin_loss(source, loss, false)?;
                return Ok(Some(Progress::Activity));
            }
            let step = self.sources[at]
                .native
                .as_mut()
                .ok_or(Fault::NotReady)?
                .poll_progress(cx);
            match step {
                Poll::Pending => {}
                Poll::Ready(Ok(event)) => {
                    // Ready can queue further local IO (Attached queues CREATE),
                    // so only a full blocked pass after this event may park.
                    // Preserve the rotating cursor while renewing finite debt.
                    self.source_scan = self.sources.len();
                    return self.actual_set(source, event, validator);
                }
                Poll::Ready(Err(error)) => {
                    let loss = self.sources[at]
                        .native
                        .as_mut()
                        .ok_or(Fault::NotReady)?
                        .retire_after(error);
                    self.begin_loss(source, loss, false)?;
                    return Ok(Some(Progress::Activity));
                }
            }
        }
        if self.source_scan != 0 {
            Ok(Some(Progress::Activity))
        } else {
            Ok(None)
        }
    }
    fn queued(&mut self) -> Option<Progress<'id>> {
        if let Some(event) = self.bound_event.take() {
            return Some(event);
        }
        if let Some((set, refusal)) = self.source_refusal.take() {
            return Some(Progress::SourceRefused { set, refusal });
        }
        if let Some(error) = self.fault.take() {
            return Some(Progress::Fault(error));
        }
        if let Some((task, cause)) = self.task_fault.take() {
            return Some(Progress::TaskFault { task, cause });
        }
        if let Some((peer, cause)) = self.rejection.take() {
            return Some(Progress::Rejected { peer, cause });
        }
        if let Some(event) = self.listener_event.take() {
            return Some(Progress::Listener(event));
        }
        self.terminal.take().map(Progress::Terminal)
    }
    fn clock_wait(&mut self, cx: &mut Context<'_>) -> Result<(), Error> {
        let target = self
            .core
            .next_deadline()
            .map(|at| at.min(self.original.expires));
        let Some(target) = target else {
            self.timer = None;
            return Ok(());
        };
        if self.timer.as_ref().is_none_or(|(at, _)| *at != target) {
            self.timer = None;
            self.timer = Some((
                target,
                Box::pin(Deadline::at(
                    self.clock.clone(),
                    AbsoluteTime::from_micros(target),
                )?),
            ));
        }
        if let Some((_, timer)) = &mut self.timer {
            match timer.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => {
                    self.timer = None;
                    cx.waker().wake_by_ref();
                }
                Poll::Ready(Err(e)) => return Err(e.into()),
                Poll::Pending => {}
            }
        }
        Ok(())
    }
    /// Stop all original dependency sockets/attempts without clock or allocation.
    /// Actual loss receipts stay in their pre-existing source slots; this grants
    /// no semantic terminal/peer ACK and does not close caller-owned IPC/PILS.
    pub fn retire_sources(&mut self) -> Result<(), Error> {
        if self.core.outcome().failure.is_none() && !self.core.outcome().client_done_written {
            return Err(Fault::NotReady.into());
        }
        let mut first = None;
        if let Some(mut listener) = self.listener.take() {
            let loss = listener.close();
            self.offers.clear();
            if let Some(effect) = self.core.effect()
                && matches!(effect.action, Action::Listen { .. })
            {
                let completion = if loss.transport.initializer_written {
                    Completion::Written
                } else if loss.transport.initializer_bytes == 0 {
                    Completion::Unsent(Fault::Cancelled)
                } else {
                    Completion::Lost(Fault::Cancelled)
                };
                if let Err(error) = self.settle(effect.id, completion) {
                    first = Some(error);
                }
            }
            self.listener_event = Some(set::ListenProgress::Lost(loss));
        }
        for at in 0..self.sources.len() {
            if let Some(mut native) = self.sources[at].native.take() {
                let source = self.sources[at].id;
                let loss = native.close();
                self.record_source_loss(source, &loss);
                self.sources[at].retired = Some(loss);
            }
        }
        if let Some(error) = first {
            Err(error)
        } else {
            Ok(())
        }
    }
    /// Physical dependency fact only; original logical debts may remain.
    #[must_use]
    pub fn physical_retired(&self) -> bool {
        self.listener.is_none() && self.sources.iter().all(|s| s.native.is_none())
    }
    /// Original first important SDK source-loss labels, stable across cleanup.
    /// No mutable source, timer or native IO is retained by this readonly copy.
    pub fn first_source_loss(&self) -> Option<SourceLossContext> {
        self.first_source_loss
    }

    /// Move an unconsumed local refusal during bounded cleanup, without clock,
    /// IO, new source authority or a claim that logical retirement completed.
    pub fn take_source_refusal(&mut self) -> Option<SourceRefusal> {
        self.source_refusal.take().map(|(_, refusal)| refusal)
    }

    /// After bounded cleanup stops, move an already physically retired source's
    /// actual receipt without inventing terminal results. Caller must report
    /// unresolved core bookkeeping separately and may not claim success.
    pub fn take_retired_loss(&mut self) -> Result<Option<set::SetLoss>, Error> {
        if !self.physical_retired() {
            return Err(Fault::NotReady.into());
        }
        if let Some(work) = self.loss.take() {
            self.record_source_loss(work.source, &work.loss);
            return Ok(Some(work.loss));
        }
        let Some(at) = self.sources.iter().position(|row| row.retired.is_some()) else {
            return Ok(None);
        };
        let source = self.sources[at].id;
        let loss = self.sources[at].retired.take();
        if let Some(loss) = &loss {
            self.record_source_loss(source, loss);
        }
        Ok(loss)
    }
    /// Closing-only physical/native retirement. This performs no clock sample,
    /// connection attempt, replacement source or normal request write. Historical
    /// last_now is reused only for matching failure metadata, never a new deadline.
    pub fn poll_retirement(
        &mut self,
        cx: &mut Context<'_>,
        validator: &mut impl Validator,
    ) -> Poll<Result<Progress<'id>, Error>> {
        let _waker = cx;
        if self.core.outcome().failure.is_none() && !self.core.outcome().client_done_written {
            return Poll::Ready(Err(Fault::NotReady.into()));
        }
        self.retire_sources()?;
        if let Some(progress) = self.queued() {
            return Poll::Ready(Ok(progress));
        }
        if let Some(progress) = self.drain_loss(validator)? {
            return Poll::Ready(Ok(progress));
        }
        if let Some(at) = self.sources.iter().position(|s| s.retired.is_some()) {
            let source = self.sources[at].id;
            let loss = self.sources[at].retired.take().ok_or(Fault::NotReady)?;
            self.begin_loss(source, loss, true)?;
            return Poll::Ready(Ok(Progress::Activity));
        }
        if self.client.is_some() {
            return Poll::Pending;
        }
        if self.core.effect().is_some()
            && let Some(progress) = self.drive_effect()?
        {
            return Poll::Ready(Ok(progress));
        }
        if self.core.retire_step()? {
            return Poll::Ready(Ok(Progress::Activity));
        }
        if self.core.is_quiescent() && self.sources.iter().all(|s| s.native.is_none()) {
            self.sources.clear();
            self.tasks.clear();
            self.offers.clear();
            self.commit = None;
            self.cancelling = None;
        }
        if self.is_quiescent() && !self.stopped {
            self.stopped = true;
            return Poll::Ready(Ok(Progress::Stopped(self.core.outcome())));
        }
        Poll::Pending
    }
    fn poll_normal(
        &mut self,
        cx: &mut Context<'_>,
        current: Option<Identity<'pils>>,
        validator: &mut impl Validator,
    ) -> Poll<Result<Progress<'id>, Error>> {
        if let Some(progress) = self.queued() {
            return Poll::Ready(Ok(progress));
        }
        if self.core.outcome().failure.is_some() || self.core.outcome().client_done_written {
            return self.poll_retirement(cx, validator);
        }
        if self.poll_native_guard(cx)? {
            return self.poll_retirement(cx, validator);
        }
        let now = self.clock.sample()?.now.as_micros();
        self.last_now = self.last_now.max(now);
        if now >= self.original.expires {
            self.cancel(Fault::Deadline)?;
            return self.poll_retirement(cx, validator);
        }
        let valid = current.is_some_and(|identity| {
            identity.epoch() == self.identity.epoch()
                && identity.peer() == self.identity.peer()
                && identity.expiration().as_micros() > now
        });
        if !valid {
            self.cancel(Fault::Unavailable)?;
            return Poll::Ready(Ok(Progress::Fault(Fault::Unavailable.into())));
        }
        if let Some(progress) = self.drain_loss(validator)? {
            return Poll::Ready(Ok(progress));
        }
        for _ in 0..3 {
            // A previous class may have observed cancellation or spent the
            // original native hard inside a fallible provider. Queued facts
            // above are diagnostics; new IO gets this clock-free fence again.
            if self.core.outcome().failure.is_some()
                || self.core.outcome().client_done_written
                || self.poll_native_guard(cx)?
            {
                return self.poll_retirement(cx, validator);
            }
            let class = self.class;
            self.class = (self.class + 1) % 3;
            let progress = match class {
                0 => self.listen(cx)?,
                1 => self.poll_sources(cx, validator)?,
                _ => {
                    let changed = self.core.step(now, self.limits.work_budget)?;
                    if self.core.outcome().failure.is_some() {
                        return self.poll_retirement(cx, validator);
                    }
                    if let Some(progress) = self.drive_effect()? {
                        Some(progress)
                    } else if changed {
                        Some(Progress::Activity)
                    } else {
                        None
                    }
                }
            };
            if let Some(progress) = progress {
                return Poll::Ready(Ok(progress));
            }
        }
        self.clock_wait(cx)?;
        Poll::Pending
    }
    /// Drive the original session with the caller's actual current PILS observation.
    /// Root polls/reports that PILS owner first; a lost or changed source prevents
    /// every new SET IO turn. No configured peer bytes substitute for this token.
    pub fn poll_progress(
        &mut self,
        cx: &mut Context<'_>,
        current: Option<Identity<'pils>>,
        validator: &mut impl Validator,
    ) -> Poll<Result<Progress<'id>, Error>> {
        match self.poll_normal(cx, current, validator) {
            Poll::Ready(Err(error)) => {
                let why = error.classified();
                self.cancel(why)?;
                Poll::Ready(Ok(Progress::Fault(error)))
            }
            other => other,
        }
    }
}

#[cfg(all(test, unix))]
mod source_tests;

#[cfg(test)]
mod admission_tests;
