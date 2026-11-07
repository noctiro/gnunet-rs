//! Original MQ, immutable output, operation and listener suggestion ownership.
use crate::{
    Cause, Command, ElementTypeOrder, EndpointSource, Epoch, Error, Instance, Limits, Operation,
    Reason, Step, Submission, WriteId,
    ipc::{self, Request, Response},
    scope::Scope,
};
use gnunet_client_host::channel::Channel;
use gnunet_service_runtime::{
    clock::{Deadline, RuntimeClock},
    framing::{Class, OwnedFrame},
};
use gnunet_types::Error as ProtocolError;
use std::{cell::Cell, collections::VecDeque, pin::Pin, rc::Rc, sync::Arc};
mod io;

#[derive(Clone)]
struct Lease {
    source: Rc<Cell<u64>>,
    epoch: u64,
}
impl Lease {
    fn current(&self) -> bool {
        self.epoch != 0 && self.source.get() == self.epoch
    }
}
#[derive(Clone, Copy, PartialEq)]
enum Disposition {
    Available,
    Abandoned,
    Consumed,
    Lost,
}
struct Pending {
    lease: Lease,
    clock: Arc<dyn RuntimeClock>,
    accept_id: u32,
    expires: u64,
    state: Cell<Disposition>,
    frame: OwnedFrame,
}
/// A non-Clone original incoming suggestion with unchanged context and source.
/// Drop marks it for REJECT on the original listener MQ's next drive. Source
/// retirement invalidates it before a replacement MQ can admit suggestions.
pub struct Incoming<'id> {
    epoch: Epoch<'id>,
    pending: Rc<Pending>,
}
impl Incoming<'_> {
    /// Original physical listener MQ.
    #[must_use]
    pub const fn epoch(&self) -> Epoch<'_> {
        self.epoch
    }
    /// Original exact REQUEST bytes; no peer authenticity is inferred here.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.pending.frame.bytes()
    }
    /// Decode actual peer/context metadata from its original source.
    pub fn request(&self) -> Result<Response<'_>, ProtocolError> {
        Response::decode(self.bytes())
    }
    /// Whether the listener still recognizes this unconsumed original input.
    /// ACCEPT additionally checks its finite deadline against the actual clock.
    #[must_use]
    pub fn pending(&self) -> bool {
        self.pending.state.get() == Disposition::Available && self.pending.lease.current()
    }
}
impl Drop for Incoming<'_> {
    fn drop(&mut self) {
        if self.pending.state.get() == Disposition::Available {
            self.pending.state.set(Disposition::Abandoned);
        }
    }
}
/// One unchanged actual RESULT correlated to the original operation and MQ.
pub struct ResultRecord<'id> {
    epoch: Epoch<'id>,
    operation: Operation<'id>,
    layout: ipc::ResultLayout,
    order: ElementTypeOrder,
    frame: OwnedFrame,
}
impl ResultRecord<'_> {
    /// Original actual MQ.
    #[must_use]
    pub const fn epoch(&self) -> Epoch<'_> {
        self.epoch
    }
    /// Original private Rust operation; not a caller-forged RID.
    #[must_use]
    pub const fn operation(&self) -> Operation<'_> {
        self.operation
    }
    /// Unchanged original message bytes, including the selected source ABI.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.frame.bytes()
    }
    /// Explicitly decode the configured source ABI; never infer packing.
    pub fn response(&self) -> Result<Response<'_>, ProtocolError> {
        Response::decode_with_layout(self.bytes(), self.layout)
    }
    /// Application type for an actual element, using the explicit producer
    /// profile. FAILURE/DONE carry no element. Raw bytes remain unchanged.
    pub fn element_type(&self) -> Result<Option<u16>, ProtocolError> {
        match self.response()? {
            Response::Result {
                status: ipc::ADD_LOCAL | ipc::DEL_LOCAL,
                element_type,
                ..
            } => Ok(Some(match self.order {
                ElementTypeOrder::CNativeLittle => element_type.swap_bytes(),
                ElementTypeOrder::Network | ElementTypeOrder::CNativeBig => element_type,
            })),
            Response::Result { .. } => Ok(None),
            _ => Err(ProtocolError::Malformed),
        }
    }
}
#[derive(Clone, Copy)]
struct Origin<'id> {
    epoch: Epoch<'id>,
    write: WriteId<'id>,
    operation: Option<Operation<'id>>,
    command: Command,
}
struct Queued<'id> {
    origin: Origin<'id>,
    expires: u64,
    removed: bool,
}
struct Active<'id> {
    operation: Operation<'id>,
    rid: u32,
    expires: u64,
    hard: Option<u64>,
    reason: Option<Reason>,
    exposed: bool,
    started: bool,
    pending: usize,
    cancel_queued: bool,
    incoming: Option<Lease>,
}
/// One explicit set MQ or independent listener MQ. There is no hidden peer
/// service, Resolver, storage, thread or task. A lost set is never reconstructed
/// or replayed; callers explicitly create a new set. Listener-only reconnect
/// retains its original finite intent and exposes a fresh source epoch.
pub struct Client<'id> {
    scope: Scope<'id>,
    channel: Channel<Origin<'id>>,
    clock: Arc<dyn RuntimeClock>,
    retry_source: Option<EndpointSource>,
    limits: Limits,
    listener: Option<[u8; 64]>,
    source: Rc<Cell<u64>>,
    epoch: Option<Epoch<'id>>,
    owner_until: u64,
    initialized: bool,
    initial_queued: bool,
    closed: bool,
    permanent: bool,
    operations: Vec<Option<Active<'id>>>,
    incoming: Vec<Option<Rc<Pending>>>,
    incoming_bytes: usize,
    writes: VecDeque<Queued<'id>>,
    events: VecDeque<Step<'id>>,
    next_rid: u64,
    alarm: Option<Pin<Box<Deadline>>>,
    alarm_at: Option<u64>,
    read_first: bool,
    yield_due: bool,
}
impl<'id> Client<'id> {
    /// Reserve a new empty set. `create_until` is an absolute finite deadline
    /// for connection/CREATE writing; each later operation has its own deadline.
    pub fn new_set(
        instance: &'id mut Instance,
        source: EndpointSource,
        limits: Limits,
        create_until: u64,
    ) -> Result<Self, Error> {
        Self::new(instance, source, limits, None, create_until)
    }
    /// Reserve a distinct listener MQ and finite absolute intent lifetime.
    /// It does not create a set or implicitly accept incoming requests.
    pub fn new_listener(
        instance: &'id mut Instance,
        source: EndpointSource,
        limits: Limits,
        app_id: [u8; 64],
        until: u64,
    ) -> Result<Self, Error> {
        Self::new(instance, source, limits, Some(app_id), until)
    }
    fn new(
        instance: &'id mut Instance,
        source: EndpointSource,
        limits: Limits,
        listener: Option<[u8; 64]>,
        until: u64,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let clock = source.clock();
        if until <= clock.sample()?.now.as_micros() || until == u64::MAX {
            return Err(ProtocolError::Deadline.into());
        }
        let retry_source = if listener.is_some() {
            Some(source.duplicate()?)
        } else {
            None
        };
        let channel = Channel::new(source, limits.framing())?;
        let mut operations = Vec::new();
        operations
            .try_reserve_exact(limits.operations)
            .map_err(|_| ProtocolError::Capacity)?;
        operations.resize_with(limits.operations, || None);
        let mut incoming = Vec::new();
        incoming
            .try_reserve_exact(limits.incoming)
            .map_err(|_| ProtocolError::Capacity)?;
        incoming.resize_with(limits.incoming, || None);
        let mut writes = VecDeque::new();
        writes
            .try_reserve_exact(limits.output.frames)
            .map_err(|_| ProtocolError::Capacity)?;
        let mut events = VecDeque::new();
        events
            .try_reserve_exact(limits.operations)
            .map_err(|_| ProtocolError::Capacity)?;
        Ok(Self {
            scope: Scope::new(instance),
            channel,
            clock,
            retry_source,
            limits,
            listener,
            source: Rc::new(Cell::new(0)),
            epoch: None,
            owner_until: until,
            initialized: false,
            initial_queued: false,
            closed: false,
            permanent: false,
            operations,
            incoming,
            incoming_bytes: 0,
            writes,
            events,
            next_rid: 0,
            alarm: None,
            alarm_at: None,
            read_first: false,
            yield_due: false,
        })
    }
    /// Current actual MQ, absent before attachment or after physical retirement.
    #[must_use]
    pub const fn epoch(&self) -> Option<Epoch<'id>> {
        self.epoch
    }
    /// CREATE/LISTEN has been fully locally written; no service ACK exists.
    #[must_use]
    pub const fn initialized(&self) -> bool {
        self.initialized && !self.closed
    }
    /// Consume a retained local end event after a native/clock error or close.
    pub fn next_event(&mut self) -> Option<Step<'id>> {
        self.events.pop_front()
    }
    fn index(&self, operation: Operation<'_>) -> Result<usize, ProtocolError> {
        if !self.scope.owns(operation) {
            return Err(ProtocolError::Stale);
        }
        self.operations
            .iter()
            .position(|state| state.as_ref().is_some_and(|s| s.operation == operation))
            .ok_or(ProtocolError::Stale)
    }
    fn sample(&mut self) -> Result<u64, Error> {
        match self.clock.sample() {
            Ok(s) => Ok(s.now.as_micros()),
            Err(error) => {
                let _lost = self.retire(Cause::Protocol(error));
                Err(error.into())
            }
        }
    }
    fn checked_until(&mut self, until: u64) -> Result<u64, Error> {
        let now = self.sample()?;
        if until <= now
            || until
                .checked_add(self.limits.retirement_grace_micros)
                .is_none_or(|n| n == u64::MAX)
        {
            return Err(ProtocolError::Deadline.into());
        }
        Ok(now)
    }
    fn enqueue(
        &mut self,
        request: Request<'_>,
        command: Command,
        operation: Option<Operation<'id>>,
        until: u64,
    ) -> Result<WriteId<'id>, Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        let epoch = self.epoch.ok_or(ProtocolError::NotReady)?;
        if self.writes.len() >= self.limits.output.frames {
            return Err(ProtocolError::WouldBlock.into());
        }
        let n = request.encoded_len()?;
        let framed = self.channel.framing_mut().ok_or(ProtocolError::NotReady)?;
        framed.reserve(n, Class::Ordinary)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(n)
            .map_err(|_| ProtocolError::Capacity)?;
        bytes.resize(n, 0);
        request.encode(&mut bytes)?;
        let write = self.scope.write()?;
        let origin = Origin {
            epoch,
            write,
            operation,
            command,
        };
        framed
            .enqueue_owned(OwnedFrame::new(bytes), origin, Class::Ordinary)
            .map_err(|e| e.reason)?;
        self.writes.push_back(Queued {
            origin,
            expires: until,
            removed: false,
        });
        self.alarm = None;
        self.alarm_at = None;
        Ok(write)
    }
    fn set_ready(&self) -> Result<(), ProtocolError> {
        if self.listener.is_some() || !self.initialized || self.closed {
            return Err(ProtocolError::NotReady);
        }
        Ok(())
    }
    /// Queue actual ADD after CREATE writing. Full-written observation is local
    /// submission only; there is no ADD ACK or persistence/replay inference.
    pub fn add(
        &mut self,
        element_type: u16,
        data: &[u8],
        until: u64,
    ) -> Result<WriteId<'id>, Error> {
        self.set_ready()?;
        self.checked_until(until)?;
        self.enqueue(
            Request::Add {
                element_type,
                reserved: 0,
                data,
            },
            Command::Add,
            None,
            until,
        )
    }
    fn admit(
        &mut self,
        request: Request<'_>,
        command: Command,
        until: u64,
        incoming: Option<Lease>,
    ) -> Result<Operation<'id>, Error> {
        self.set_ready()?;
        self.checked_until(until)?;
        if !self.events.is_empty() {
            return Err(ProtocolError::WouldBlock.into());
        }
        let index = self
            .operations
            .iter()
            .position(Option::is_none)
            .ok_or(ProtocolError::Capacity)?;
        let rid = u32::try_from(self.next_rid).map_err(|_| ProtocolError::Overflow)?;
        let operation = self.scope.operation()?;
        let hard = until
            .checked_add(self.limits.retirement_grace_micros)
            .ok_or(ProtocolError::Overflow)?;
        self.enqueue(request, command, Some(operation), hard)?;
        self.operations[index] = Some(Active {
            operation,
            rid,
            expires: until,
            hard: None,
            reason: None,
            exposed: false,
            started: false,
            pending: 1,
            cancel_queued: false,
            incoming,
        });
        self.next_rid += 1;
        Ok(operation)
    }
    /// Start an actual intersection operation on this set. Context is one
    /// complete standard message. Identity/port remain opaque endpoint metadata.
    pub fn evaluate(
        &mut self,
        peer: [u8; 32],
        app_id: [u8; 64],
        return_intersection: bool,
        context: Option<&[u8]>,
        until: u64,
    ) -> Result<Operation<'id>, Error> {
        let request_id = u32::try_from(self.next_rid).map_err(|_| ProtocolError::Overflow)?;
        self.admit(
            Request::Evaluate {
                request_id,
                peer,
                app_id,
                return_intersection: u32::from(return_intersection),
                context,
            },
            Command::Evaluate,
            until,
            None,
        )
    }
    /// Consume one still-current original listener suggestion into this set.
    /// Its source lease is retained until actual ACCEPT writing; a known source
    /// retirement before then cancels only this original admission.
    pub fn accept(
        &mut self,
        incoming: &mut Incoming<'_>,
        return_intersection: bool,
        until: u64,
    ) -> Result<Operation<'id>, Error> {
        if !incoming.pending() {
            return Err(ProtocolError::Stale.into());
        }
        let now = match incoming.pending.clock.sample() {
            Ok(sample) => sample.now.as_micros(),
            Err(error) => {
                incoming.pending.state.set(Disposition::Abandoned);
                let _lost = self.retire(Cause::Protocol(error));
                return Err(error.into());
            }
        };
        if now >= incoming.pending.expires {
            incoming.pending.state.set(Disposition::Abandoned);
            return Err(ProtocolError::Stale.into());
        }
        let request_id = u32::try_from(self.next_rid).map_err(|_| ProtocolError::Overflow)?;
        let operation = self.admit(
            Request::Accept {
                accept_id: incoming.pending.accept_id,
                request_id,
                return_intersection: u32::from(return_intersection),
            },
            Command::Accept,
            until,
            Some(incoming.pending.lease.clone()),
        )?;
        incoming.pending.state.set(Disposition::Consumed);
        Ok(operation)
    }
    /// Reject on this exact original listener MQ; returned WriteId is not an ACK.
    pub fn reject(&mut self, incoming: &mut Incoming<'_>) -> Result<WriteId<'id>, Error> {
        let now = self.sample()?;
        if self.listener.is_none()
            || !incoming.pending()
            || !Rc::ptr_eq(&self.source, &incoming.pending.lease.source)
            || now >= incoming.pending.expires
        {
            return Err(ProtocolError::Stale.into());
        }
        let until = now
            .checked_add(self.limits.retirement_grace_micros)
            .ok_or(ProtocolError::Overflow)?;
        let write = self.enqueue(
            Request::Reject {
                accept_id: incoming.pending.accept_id,
            },
            Command::Reject,
            None,
            until,
        )?;
        incoming.pending.state.set(Disposition::Consumed);
        Ok(write)
    }
    fn finish(
        &mut self,
        index: usize,
        reason: Reason,
        submission: Submission,
    ) -> Result<(), Error> {
        let state = self.operations[index].take().ok_or(ProtocolError::Stale)?;
        self.events
            .push_back(Step::LocalEnd(state.operation, reason, submission));
        Ok(())
    }
    fn cancel_index(&mut self, index: usize, reason: Reason, now: u64) -> Result<(), Error> {
        let state = self.operations[index]
            .as_mut()
            .ok_or(ProtocolError::Stale)?;
        if state.reason.is_some() {
            return Ok(());
        }
        let operation = state.operation;
        state.reason = Some(reason);
        let original_hard = state
            .expires
            .checked_add(self.limits.retirement_grace_micros)
            .ok_or(ProtocolError::Overflow)?;
        let until = now
            .saturating_add(self.limits.retirement_grace_micros)
            .min(original_hard);
        state.hard = Some(until);
        if until <= now {
            return Err(ProtocolError::Deadline.into());
        }
        let journal = &mut self.writes;
        let removed = self
            .channel
            .framing_mut()
            .ok_or(ProtocolError::NotReady)?
            .remove_unwritten(
                |origin, _| origin.operation == Some(operation),
                |origin, _| {
                    if let Some(q) = journal.iter_mut().find(|q| q.origin.write == origin.write) {
                        q.removed = true;
                    }
                },
            );
        self.writes.retain(|q| !q.removed);
        let state = self.operations[index]
            .as_mut()
            .ok_or(ProtocolError::Stale)?;
        state.pending = state
            .pending
            .checked_sub(removed)
            .ok_or(ProtocolError::Stale)?;
        if !state.exposed && state.pending == 0 {
            self.finish(index, reason, Submission::Unsent)?;
        }
        self.alarm = None;
        self.alarm_at = None;
        Ok(())
    }
    /// Cancel only the original operation. Wholly unwritten requests are removed;
    /// partial suffixes and original CANCEL drain on the same MQ under one finite
    /// bound. LocalEnd::CancelSubmitted is not a protocol FAILURE/DONE or ACK.
    pub fn cancel(&mut self, operation: Operation<'_>) -> Result<(), Error> {
        let index = self.index(operation)?;
        let now = self.sample()?;
        let result = self.cancel_index(index, Reason::Cancelled, now);
        if let Err(error) = &result {
            let cause = match error {
                Error::Protocol(error) => *error,
                _ => ProtocolError::Unavailable,
            };
            let _lost = self.retire(Cause::Protocol(cause));
        }
        result
    }
    fn retire(&mut self, cause: Cause) -> Step<'id> {
        let epoch = self.epoch.take();
        self.channel.close();
        self.source.set(0);
        self.closed = true;
        self.initialized = false;
        for slot in &mut self.incoming {
            if let Some(pending) = slot.take() {
                pending.state.set(Disposition::Lost);
            }
        }
        self.incoming_bytes = 0;
        self.writes.clear();
        self.alarm = None;
        self.alarm_at = None;
        for state in &mut self.operations {
            if let Some(state) = state.take() {
                let reason = state.reason.unwrap_or(if self.permanent {
                    Reason::Closed
                } else {
                    Reason::Lost
                });
                let submission = if state.exposed {
                    Submission::Unknown
                } else {
                    Submission::Unsent
                };
                self.events
                    .push_back(Step::LocalEnd(state.operation, reason, submission));
            }
        }
        Step::Lost(epoch, cause)
    }
    /// Permanently close the original native owner first; queued local ends
    /// remain consumable. Drop alone does not manufacture operation success.
    pub fn close(&mut self) -> Step<'id> {
        self.permanent = true;
        if self.closed {
            Step::Closed
        } else {
            self.retire(Cause::Closed)
        }
    }
    /// Explicitly reconnect only a lost listener, preserving its original finite
    /// lifetime. Old suggestions remain invalid and the new actual MQ gets a new
    /// epoch. Sets, ADDs, EVALUATEs and ACCEPTs are never reconstructed/replayed.
    pub fn reconnect_listener(&mut self) -> Result<(), Error> {
        if !self.closed || self.permanent || self.listener.is_none() {
            return Err(ProtocolError::InvalidInput.into());
        }
        if self.sample()? >= self.owner_until {
            return Err(ProtocolError::Deadline.into());
        }
        let source = self
            .retry_source
            .as_ref()
            .ok_or(ProtocolError::InvalidInput)?
            .duplicate()?;
        self.channel = Channel::new(source, self.limits.framing())?;
        self.initial_queued = false;
        self.initialized = false;
        self.closed = false;
        Ok(())
    }
    fn target(&self) -> Option<u64> {
        let owner = (!self.initialized || self.listener.is_some()).then_some(self.owner_until);
        owner
            .into_iter()
            .chain(self.writes.iter().map(|q| q.expires))
            .chain(
                self.operations
                    .iter()
                    .flatten()
                    .map(|s| s.hard.unwrap_or(s.expires)),
            )
            .chain(
                self.incoming
                    .iter()
                    .flatten()
                    .filter(|p| p.state.get() == Disposition::Available)
                    .map(|p| p.expires),
            )
            .min()
    }
    fn expire(&mut self, now: u64) -> Result<Option<Step<'id>>, Error> {
        if ((!self.initialized || self.listener.is_some()) && now >= self.owner_until)
            || self.writes.iter().any(|q| q.expires <= now)
            || self
                .operations
                .iter()
                .flatten()
                .any(|s| s.hard.is_some_and(|n| n <= now))
        {
            return Ok(Some(self.retire(Cause::Deadline)));
        }
        for pending in self.incoming.iter().flatten() {
            if pending.expires <= now && pending.state.get() == Disposition::Available {
                pending.state.set(Disposition::Abandoned);
            }
        }
        for index in 0..self.operations.len() {
            let reason = self.operations[index].as_ref().and_then(|s| {
                if s.reason.is_some() {
                    None
                } else if s.incoming.as_ref().is_some_and(|lease| !lease.current()) {
                    Some(Reason::IncomingLost)
                } else if now >= s.expires {
                    Some(Reason::Deadline)
                } else {
                    None
                }
            });
            if let Some(reason) = reason {
                self.cancel_index(index, reason, now)?;
            }
        }
        Ok(self.events.pop_front())
    }
    fn prepare(&mut self, now: u64) -> Result<(), Error> {
        if !self.initial_queued {
            let (request, command) = match self.listener {
                Some(app_id) => (
                    Request::Listen {
                        operation: 0,
                        app_id,
                    },
                    Command::Listen,
                ),
                None => (Request::Create, Command::Create),
            };
            self.enqueue(request, command, None, self.owner_until)?;
            self.initial_queued = true;
            return Ok(());
        }
        for index in 0..self.operations.len() {
            let Some(s) = &self.operations[index] else {
                continue;
            };
            if s.reason.is_some() && s.pending == 0 && !s.cancel_queued {
                let (rid, op, until) = (s.rid, s.operation, s.hard.ok_or(ProtocolError::Stale)?);
                self.enqueue(
                    Request::Cancel { request_id: rid },
                    Command::Cancel,
                    Some(op),
                    until,
                )?;
                let s = self.operations[index]
                    .as_mut()
                    .ok_or(ProtocolError::Stale)?;
                s.pending += 1;
                s.cancel_queued = true;
                return Ok(());
            }
        }
        for index in 0..self.incoming.len() {
            let Some(pending) = &self.incoming[index] else {
                continue;
            };
            if pending.expires <= now && pending.state.get() == Disposition::Available {
                pending.state.set(Disposition::Abandoned);
            }
            if pending.state.get() == Disposition::Abandoned && pending.lease.current() {
                let id = pending.accept_id;
                let until = now.saturating_add(self.limits.retirement_grace_micros).min(
                    pending
                        .expires
                        .saturating_add(self.limits.retirement_grace_micros),
                );
                if until <= now || until == u64::MAX {
                    return Err(ProtocolError::Deadline.into());
                }
                self.enqueue(
                    Request::Reject { accept_id: id },
                    Command::Reject,
                    None,
                    until,
                )?;
                if let Some(pending) = &self.incoming[index] {
                    pending.state.set(Disposition::Consumed);
                }
            }
            if self.incoming[index]
                .as_ref()
                .is_some_and(|p| p.state.get() != Disposition::Available)
            {
                let pending = self.incoming[index].take().ok_or(ProtocolError::Stale)?;
                self.incoming_bytes -= pending.frame.len();
            }
        }
        Ok(())
    }
    fn dispatch(&mut self) -> Result<Step<'id>, Error> {
        let epoch = self.epoch.ok_or(ProtocolError::NotReady)?;
        let frame = self
            .channel
            .framing()
            .and_then(|f| f.frame())
            .ok_or(ProtocolError::NotReady)?;
        match Response::decode_with_layout(frame, self.limits.result_layout)? {
            Response::Request { accept_id, .. } if self.listener.is_some() && self.initialized => {
                let Some(index) = self.incoming.iter().position(Option::is_none) else {
                    return Ok(Step::Capacity);
                };
                if self
                    .incoming
                    .iter()
                    .flatten()
                    .any(|p| p.accept_id == accept_id)
                {
                    return Err(ProtocolError::Malformed.into());
                }
                let charged = self
                    .incoming_bytes
                    .checked_add(frame.len())
                    .ok_or(ProtocolError::Capacity)?;
                if charged > self.limits.incoming_bytes {
                    return Ok(Step::Capacity);
                }
                let bytes = OwnedFrame::copy_from(frame)?;
                let now = self.clock.sample()?.now.as_micros();
                let expires = now
                    .checked_add(self.limits.incoming_lifetime_micros)
                    .filter(|n| *n < u64::MAX)
                    .ok_or(ProtocolError::Overflow)?
                    .min(self.owner_until);
                let pending = Rc::new(Pending {
                    lease: Lease {
                        source: self.source.clone(),
                        epoch: epoch.diagnostic(),
                    },
                    clock: self.clock.clone(),
                    accept_id,
                    expires,
                    state: Cell::new(Disposition::Available),
                    frame: bytes,
                });
                self.incoming[index] = Some(pending.clone());
                self.incoming_bytes = charged;
                self.release()?;
                Ok(Step::Incoming(Incoming { epoch, pending }))
            }
            Response::Result {
                request_id, status, ..
            } if self.listener.is_none() => {
                let Some(index) = self
                    .operations
                    .iter()
                    .position(|s| s.as_ref().is_some_and(|s| s.rid == request_id))
                else {
                    self.release()?;
                    return Ok(Step::Activity(0, 0));
                };
                let s = self.operations[index]
                    .as_ref()
                    .ok_or(ProtocolError::Stale)?;
                if s.reason.is_some() {
                    self.release()?;
                    return Ok(Step::Activity(0, 0));
                }
                if !s.started
                    || !matches!(
                        status,
                        ipc::ADD_LOCAL | ipc::DEL_LOCAL | ipc::FAILURE | ipc::DONE
                    )
                {
                    return Err(ProtocolError::Malformed.into());
                }
                let operation = s.operation;
                let bytes = OwnedFrame::copy_from(frame)?;
                self.release()?;
                if matches!(status, ipc::FAILURE | ipc::DONE) {
                    self.operations[index] = None;
                }
                Ok(Step::Result(ResultRecord {
                    epoch,
                    operation,
                    frame: bytes,
                    layout: self.limits.result_layout,
                    order: self.limits.element_type_order,
                }))
            }
            _ => Err(ProtocolError::Malformed.into()),
        }
    }
    fn release(&mut self) -> Result<(), Error> {
        if !self
            .channel
            .framing_mut()
            .ok_or(ProtocolError::NotReady)?
            .release_frame()
        {
            return Err(ProtocolError::Stale.into());
        }
        Ok(())
    }
}
impl Drop for Client<'_> {
    fn drop(&mut self) {
        self.channel.close();
        self.source.set(0);
        for pending in self.incoming.iter().flatten() {
            pending.state.set(Disposition::Lost);
        }
    }
}
