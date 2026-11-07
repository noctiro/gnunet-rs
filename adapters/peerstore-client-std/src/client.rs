//! Original logical metadata, immutable source bounds and physical retirement.
use crate::{
    Cancel, Command, EndpointSource, Epoch, Error, Filter, Instance, Kind, Limits, LossCause,
    Operation, Outcome, Progress, Reason, Record, Submission, WriteId,
    ipc::{self, Envelope, Iteration, Monitor, Request},
    scope::Scope,
};
use gnunet_client_host::channel::Channel;
use gnunet_service_runtime::{
    clock::{Deadline, RuntimeClock},
    framing::{Class, OwnedFrame},
};
use gnunet_types::Error as ProtocolError;
use std::{collections::VecDeque, pin::Pin, sync::Arc};
mod io;
#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Requests,
    Monitor,
}
#[derive(Clone, Copy)]
struct Origin<'a> {
    epoch: Epoch<'a>,
    operation: Operation<'a>,
    write: WriteId<'a>,
    command: Command,
}
struct State<'a> {
    operation: Operation<'a>,
    rid: u32,
    kind: Kind,
    source: Option<OwnedFrame>,
    expires: u64,
    epoch: Option<Epoch<'a>>,
    queued: bool,
    started: bool,
    exposed: bool,
    pending: usize,
    next_pending: bool,
    stop_queued: bool,
    credit: u64,
    synced: bool,
    reason: Option<Reason>,
    hard: Option<u64>,
    done: bool,
}
/// One caller-driven bounded MQ. `new` multiplexes STORE/iterators; `new_monitor`
/// reserves a separate explicit MQ because official MONITOR_NEXT has no RID.
/// The client creates no service/backend, background task or implicit Resolver.
pub struct Client<'a> {
    scope: Scope<'a>,
    channel: Channel<Origin<'a>>,
    clock: Arc<dyn RuntimeClock>,
    limits: Limits,
    mode: Mode,
    slots: Vec<Option<State<'a>>>,
    source_bytes: usize,
    next_rid: u64,
    epoch: Option<Epoch<'a>>,
    events: VecDeque<Progress<'a>>,
    alarm: Option<Pin<Box<Deadline>>>,
    alarm_at: Option<u64>,
    read_first: bool,
    yield_due: bool,
    closed: bool,
    clock_fault: Option<ProtocolError>,
    port_blocked: bool,
}
impl<'a> Client<'a> {
    /// Reserve bounded general STORE/iterator ownership without performing IO.
    pub fn new(
        instance: &'a mut Instance,
        source: EndpointSource,
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::construct(instance, source, limits, Mode::Requests)
    }
    /// Reserve one dedicated monitor MQ explicitly. Use a separate Instance from
    /// the general client; there is no implicit per-peer/per-operation thread.
    pub fn new_monitor(
        instance: &'a mut Instance,
        source: EndpointSource,
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::construct(instance, source, limits, Mode::Monitor)
    }
    fn construct(
        instance: &'a mut Instance,
        source: EndpointSource,
        limits: Limits,
        mode: Mode,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let clock = source.clock();
        let channel = Channel::new(source, limits.framing())?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(limits.operations)
            .map_err(|_| ProtocolError::Capacity)?;
        slots.resize_with(limits.operations, || None);
        let mut events = VecDeque::new();
        events
            .try_reserve_exact(limits.operations + 1)
            .map_err(|_| ProtocolError::Capacity)?;
        Ok(Self {
            scope: Scope::new(instance),
            channel,
            clock,
            limits,
            mode,
            slots,
            source_bytes: 0,
            next_rid: 0,
            epoch: None,
            events,
            alarm: None,
            alarm_at: None,
            read_first: false,
            yield_due: false,
            closed: false,
            clock_fault: None,
            port_blocked: false,
        })
    }
    fn index(&self, operation: Operation<'_>) -> Result<usize, ProtocolError> {
        if !self.scope.owns(operation) {
            return Err(ProtocolError::Stale);
        }
        self.slots
            .iter()
            .position(|state| {
                state
                    .as_ref()
                    .is_some_and(|state| state.operation == operation)
            })
            .ok_or(ProtocolError::Stale)
    }
    fn now(&self) -> Result<u64, ProtocolError> {
        Ok(self.clock.sample()?.now.as_micros())
    }
    fn admit(
        &mut self,
        request: Request<'_>,
        kind: Kind,
        expires: u64,
    ) -> Result<Operation<'a>, Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        if !self.events.is_empty() {
            return Err(ProtocolError::WouldBlock.into());
        }
        let now = self.sample()?;
        if expires <= now
            || expires == u64::MAX
            || expires
                .checked_add(self.limits.retirement_grace_micros)
                .is_none_or(|hard| hard == u64::MAX)
        {
            return Err(ProtocolError::Deadline.into());
        }
        let index = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(ProtocolError::Capacity)?;
        let len = request.encoded_len()?;
        let charged = self
            .source_bytes
            .checked_add(len)
            .ok_or(ProtocolError::Capacity)?;
        if len > self.limits.frame_bytes || charged > self.limits.source_bytes {
            return Err(ProtocolError::Capacity.into());
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| ProtocolError::Capacity)?;
        bytes.resize(len, 0);
        request.encode(&mut bytes)?;
        let rid = match request {
            Request::Store(envelope) => envelope.rid,
            Request::IterateStart(start) => start.rid,
            Request::MonitorStart(start) => start.rid,
            _ => return Err(ProtocolError::InvalidInput.into()),
        };
        let operation = self.scope.operation()?;
        self.slots[index] = Some(State {
            operation,
            rid,
            kind,
            source: Some(OwnedFrame::new(bytes)),
            expires,
            epoch: None,
            queued: false,
            started: false,
            exposed: false,
            pending: 0,
            next_pending: false,
            stop_queued: false,
            credit: 0,
            synced: false,
            reason: None,
            hard: None,
            done: false,
        });
        self.source_bytes = charged;
        self.next_rid += 1;
        self.alarm = None;
        self.alarm_at = None;
        Ok(operation)
    }
    fn rid(&self) -> Result<u32, ProtocolError> {
        u32::try_from(self.next_rid).map_err(|_| ProtocolError::Overflow)
    }
    /// Admit a real official STORE. `expires` is a finite original absolute UTC
    /// operation deadline, separate from the record's own cache expiry. Only a
    /// matching actual STORE_RESULT produces Outcome::StoreResult; loss never replays it.
    pub fn store(
        &mut self,
        record: Record<'_>,
        options: u32,
        expires: u64,
    ) -> Result<Operation<'a>, Error> {
        if self.mode != Mode::Requests || record.subsystem.is_none() || record.key.is_none() {
            return Err(ProtocolError::InvalidInput.into());
        }
        self.admit(
            Request::Store(Envelope {
                rid: self.rid()?,
                options,
                reserved: 0,
                record,
            }),
            Kind::Store,
            expires,
        )
    }
    /// Start an original iterator with official implicit credit1. Subsystem is
    /// required; optional peer/key selectors and empty C strings retain their meaning.
    pub fn iterate(&mut self, filter: Filter<'_>, expires: u64) -> Result<Operation<'a>, Error> {
        if self.mode != Mode::Requests || filter.subsystem.is_none() {
            return Err(ProtocolError::InvalidInput.into());
        }
        self.admit(
            Request::IterateStart(Iteration {
                rid: self.rid()?,
                filter,
                reserved: 0,
            }),
            Kind::Iteration,
            expires,
        )
    }
    /// Start this dedicated MQ's one monitor. Initial credit1 is restored only
    /// after each actual MONITOR_START write; a reconnect exposes a new epoch
    /// and fresh SYNC, never uninterrupted live-stream continuity.
    pub fn monitor(
        &mut self,
        filter: Filter<'_>,
        iterate_first: bool,
        expires: u64,
    ) -> Result<Operation<'a>, Error> {
        if self.mode != Mode::Monitor
            || filter.subsystem.is_none()
            || self.slots.iter().any(Option::is_some)
        {
            return Err(ProtocolError::InvalidInput.into());
        }
        self.admit(
            Request::MonitorStart(Monitor {
                rid: self.rid()?,
                filter,
                iterate_first,
            }),
            Kind::Monitor,
            expires,
        )
    }
    /// Actually active original physical MQ.
    #[must_use]
    pub const fn epoch(&self) -> Option<Epoch<'a>> {
        self.epoch
    }
    /// Whether this original operation remains logically active, excluding canceled debt.
    #[must_use]
    pub fn live(&self, operation: Operation<'_>) -> bool {
        self.index(operation).ok().is_some_and(|i| {
            self.slots[i]
                .as_ref()
                .is_some_and(|state| !state.done && state.reason.is_none())
        })
    }
    /// Remaining record credit from actually fully written starts/grants.
    pub fn credit(&self, operation: Operation<'_>) -> Result<u64, Error> {
        Ok(self.slots[self.index(operation)?]
            .as_ref()
            .ok_or(ProtocolError::Stale)?
            .credit)
    }
    /// Original earliest soft/hard absolute target; a clock listener wakes its owner.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        self.slots
            .iter()
            .filter_map(|state| state.as_ref())
            .map(|state| state.hard.unwrap_or(state.expires))
            .min()
    }
    /// No logical/debt rows or undelivered original observations remain. This
    /// grants no source/result authority; it permits exclusive compound helpers
    /// to start without swallowing an earlier operation's terminal observation.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.slots.iter().all(Option::is_none) && self.events.is_empty()
    }
    /// Original pending logical/debt slots, bounded by Limits.operations.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.slots.iter().filter(|state| state.is_some()).count()
    }
    /// Take one already retained actual/local terminal observation without IO.
    pub fn next_event(&mut self) -> Option<Progress<'a>> {
        self.events.pop_front()
    }
    fn drop_source(&mut self, index: usize) {
        if let Some(source) = self.slots[index]
            .as_mut()
            .and_then(|state| state.source.take())
        {
            self.source_bytes -= source.len();
        }
    }
    fn remove(&mut self, index: usize) {
        self.drop_source(index);
        self.slots[index] = None;
        self.alarm = None;
        self.alarm_at = None;
    }
    fn complete(&mut self, index: usize, outcome: Outcome, now: u64) -> Result<(), Error> {
        let state = self.slots[index].as_mut().ok_or(ProtocolError::Stale)?;
        if state.done {
            return Ok(());
        }
        state.done = true;
        if state.pending != 0 {
            state.hard = Some(
                now.saturating_add(self.limits.retirement_grace_micros)
                    .min(state.expires + self.limits.retirement_grace_micros),
            );
        }
        self.events.push_back(Progress::Completed {
            epoch: state.epoch,
            operation: state.operation,
            kind: state.kind,
            outcome,
        });
        let remove = state.pending == 0;
        self.drop_source(index);
        if remove {
            self.remove(index);
        }
        self.alarm = None;
        self.alarm_at = None;
        Ok(())
    }
    fn complete_retired(&mut self, index: usize, outcome: Outcome) -> Result<(), Error> {
        let state = self.slots[index].as_ref().ok_or(ProtocolError::Stale)?;
        if !state.done {
            self.events.push_back(Progress::Completed {
                epoch: state.epoch,
                operation: state.operation,
                kind: state.kind,
                outcome,
            });
        }
        self.remove(index);
        Ok(())
    }
    fn sample(&mut self) -> Result<u64, Error> {
        if let Some(error) = self.clock_fault {
            return Err(error.into());
        }
        if self.port_blocked {
            return Err(ProtocolError::Unavailable.into());
        }
        match self.now() {
            Ok(now) => Ok(now),
            Err(error) => {
                self.clock_fault = Some(error);
                let lost = self.refuse_clock(error)?;
                self.events.push_back(lost);
                Err(error.into())
            }
        }
    }
    fn refuse_ports(&mut self, error: Error) -> Result<Progress<'a>, Error> {
        self.port_blocked = true;
        self.retire(LossCause::Ports(error), false)
    }
    fn refuse_clock(&mut self, error: ProtocolError) -> Result<Progress<'a>, Error> {
        self.clock_fault = Some(error);
        self.retire(LossCause::Clock(error), false)
    }
    fn submission(state: &State<'_>) -> Submission {
        if state.exposed {
            Submission::Unknown
        } else {
            Submission::Unsent
        }
    }
    fn remove_unwritten(&mut self, index: usize) -> Result<(), Error> {
        let operation = self.slots[index]
            .as_ref()
            .ok_or(ProtocolError::Stale)?
            .operation;
        let count = self.channel.framing_mut().map_or(0, |frame| {
            frame.remove_unwritten(|origin, _| origin.operation == operation, |_, _| {})
        });
        let state = self.slots[index].as_mut().ok_or(ProtocolError::Stale)?;
        state.pending = state
            .pending
            .checked_sub(count)
            .ok_or(ProtocolError::Stale)?;
        if state.pending == 0 {
            state.next_pending = false;
        }
        Ok(())
    }
    fn retire_operation(
        &mut self,
        index: usize,
        reason: Reason,
        now: u64,
    ) -> Result<Cancel, Error> {
        if self.slots[index]
            .as_ref()
            .is_none_or(|state| state.done || state.reason.is_some())
        {
            return Err(ProtocolError::Stale.into());
        }
        self.remove_unwritten(index)?;
        let state = self.slots[index].as_mut().ok_or(ProtocolError::Stale)?;
        state.reason = Some(reason);
        state.hard = Some(
            now.saturating_add(self.limits.retirement_grace_micros)
                .min(state.expires + self.limits.retirement_grace_micros),
        );
        let submission = Self::submission(state);
        let kind = state.kind;
        let pending = state.pending;
        if kind == Kind::Monitor {
            let cause = if reason == Reason::Deadline {
                LossCause::Deadline
            } else {
                LossCause::Requested
            };
            let lost = self.retire(cause, false)?;
            // Retain the actual physical-retirement observation after cancellation.
            self.events.push_back(lost);
            return Ok(Cancel::MonitorClosed);
        }
        if submission == Submission::Unsent && pending == 0 {
            self.complete(index, Outcome::Local { reason, submission }, now)?;
            return Ok(Cancel::Unsent);
        }
        if kind == Kind::Store && pending == 0 {
            self.complete(index, Outcome::Local { reason, submission }, now)?;
            return Ok(Cancel::Unknown);
        }
        self.alarm = None;
        self.alarm_at = None;
        Ok(Cancel::Draining)
    }
    /// Cancel only this exact original operation. A partial frame drains on its
    /// original MQ, ITERATE_STOP remains FIFO, and monitor cancellation physically
    /// closes its dedicated MQ (there is no official MONITOR_STOP message).
    pub fn cancel(&mut self, operation: Operation<'_>) -> Result<Cancel, Error> {
        let index = self.index(operation)?;
        let now = self.sample()?;
        self.retire_operation(index, Reason::Cancelled, now)
    }
    /// Grant a real next round. Iterators require exhausted current credit and
    /// at most one pending grant; monitors add credit. The service clamps each
    /// increment to256; iteration grants must be nonzero. Monitor zero remains
    /// an official no-op. Credit changes only on actual full local writing.
    pub fn next(&mut self, operation: Operation<'_>, limit: u64) -> Result<(), Error> {
        let index = self.index(operation)?;
        let now = self.sample()?;
        if now
            >= self.slots[index]
                .as_ref()
                .ok_or(ProtocolError::Stale)?
                .expires
        {
            self.retire_operation(index, Reason::Deadline, now)?;
            return Err(ProtocolError::Deadline.into());
        }
        let state = self.slots[index].as_ref().ok_or(ProtocolError::Stale)?;
        if limit == 0 && state.kind != Kind::Monitor {
            return Err(ProtocolError::InvalidInput.into());
        }
        if state.done
            || state.reason.is_some()
            || !state.started
            || state.next_pending
            || state.kind == Kind::Store
            || (state.kind == Kind::Iteration && state.credit != 0)
        {
            return Err(ProtocolError::NotReady.into());
        }
        let limit = limit.min(ipc::MAX_ROUND);
        state
            .credit
            .checked_add(limit)
            .ok_or(ProtocolError::Overflow)?;
        let request = if state.kind == Kind::Monitor {
            Request::MonitorNext { limit }
        } else {
            Request::IterateNext {
                rid: state.rid,
                limit,
            }
        };
        self.enqueue(index, request, Command::Next { limit })?;
        self.slots[index]
            .as_mut()
            .ok_or(ProtocolError::Stale)?
            .next_pending = true;
        Ok(())
    }
    fn enqueue(
        &mut self,
        index: usize,
        request: Request<'_>,
        command: Command,
    ) -> Result<(), Error> {
        let epoch = self.epoch.ok_or(ProtocolError::NotReady)?;
        let state = self.slots[index].as_ref().ok_or(ProtocolError::Stale)?;
        let operation = state.operation;
        let pending = state
            .pending
            .checked_add(1)
            .ok_or(ProtocolError::Capacity)?;
        let size = request.encoded_len()?;
        let frame = self.channel.framing_mut().ok_or(ProtocolError::NotReady)?;
        frame.reserve(size, Class::Ordinary)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(size)
            .map_err(|_| ProtocolError::Capacity)?;
        bytes.resize(size, 0);
        request.encode(&mut bytes)?;
        let write = self.scope.write()?;
        frame
            .enqueue_owned(
                OwnedFrame::new(bytes),
                Origin {
                    epoch,
                    operation,
                    write,
                    command,
                },
                Class::Ordinary,
            )
            .map_err(|rejected| rejected.reason)?;
        let state = self.slots[index].as_mut().ok_or(ProtocolError::Stale)?;
        state.pending = pending;
        state.epoch = Some(epoch);
        Ok(())
    }
    fn prepare(&mut self) -> Result<(), Error> {
        let epoch = self.epoch.ok_or(ProtocolError::NotReady)?;
        for index in 0..self.slots.len() {
            let Some(state) = &self.slots[index] else {
                continue;
            };
            if state.done {
                continue;
            }
            if state.reason.is_some() {
                if state.kind == Kind::Iteration
                    && state.started
                    && state.pending == 0
                    && !state.stop_queued
                {
                    let rid = state.rid;
                    match self.enqueue(index, Request::IterateStop { rid }, Command::Stop) {
                        Ok(()) => {
                            self.slots[index]
                                .as_mut()
                                .ok_or(ProtocolError::Stale)?
                                .stop_queued = true
                        }
                        Err(Error::Protocol(ProtocolError::WouldBlock)) => {}
                        Err(error) => return Err(error),
                    }
                    return Ok(());
                }
                continue;
            }
            if state.queued {
                continue;
            }
            let pending = state
                .pending
                .checked_add(1)
                .ok_or(ProtocolError::Capacity)?;
            let source = state.source.as_ref().ok_or(ProtocolError::Stale)?;
            let frame = self.channel.framing_mut().ok_or(ProtocolError::NotReady)?;
            if !frame.capacity(source.len(), Class::Ordinary) {
                continue;
            }
            frame.reserve(source.len(), Class::Ordinary)?;
            let bytes = OwnedFrame::copy_from(source.bytes())?;
            let origin = Origin {
                epoch,
                operation: state.operation,
                write: self.scope.write()?,
                command: Command::Start,
            };
            frame
                .enqueue_owned(bytes, origin, Class::Ordinary)
                .map_err(|rejected| rejected.reason)?;
            let state = self.slots[index].as_mut().ok_or(ProtocolError::Stale)?;
            state.queued = true;
            state.epoch = Some(epoch);
            state.pending = pending;
            return Ok(());
        }
        Ok(())
    }
    fn retire(&mut self, cause: LossCause, retry: bool) -> Result<Progress<'a>, Error> {
        let epoch = self.epoch.take();
        self.channel.detach(); // physical fence always precedes logical result/restoration
        let mut monitor_retained = false;
        for index in 0..self.slots.len() {
            let Some(state) = &mut self.slots[index] else {
                continue;
            };
            state.pending = 0;
            if state.done {
                self.remove(index);
                continue;
            }
            if state.kind == Kind::Monitor && state.reason.is_none() && !self.closed && retry {
                state.epoch = None;
                state.queued = false;
                state.started = false;
                state.exposed = false;
                state.next_pending = false;
                state.stop_queued = false;
                state.credit = 0;
                state.synced = false;
                monitor_retained = true;
                continue;
            }
            let reason = state.reason.unwrap_or(if self.closed {
                Reason::Closed
            } else {
                Reason::Lost
            });
            let submission = Self::submission(state);
            self.complete_retired(index, Outcome::Local { reason, submission })?;
        }
        self.alarm = None;
        self.alarm_at = None;
        if retry && !self.closed {
            self.channel.schedule_retry()?;
        }
        Ok(Progress::Lost {
            epoch,
            cause,
            monitor_retained,
        })
    }
    /// Close the original MQ before any replacement. Stores/iterators terminate
    /// as local Unsent/Unknown; only monitor intent may restore on a new epoch.
    pub fn reconnect(&mut self) -> Result<Progress<'a>, Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        self.retire(LossCause::Requested, true)
    }
    /// Permanently close physical owners first. Retained completions remain
    /// available through next_event/drive, with no new key/socket/worker ownership.
    pub fn close(&mut self) -> Result<Option<Progress<'a>>, Error> {
        if self.closed {
            return Ok(None);
        }
        self.closed = true;
        self.channel.close();
        self.retire(LossCause::Closed, false).map(Some)
    }
    /// Explicitly recover a refused CLIENT clock/timer/Resolver port. Original
    /// STOREs and iterators are never reconstructed or replayed by this action.
    pub fn recover_ports(&mut self) -> Result<(), Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        if self.clock_fault.is_none() && !self.port_blocked {
            return Err(ProtocolError::NotReady.into());
        }
        if self.clock_fault.is_some() {
            self.now()?;
        }
        if self.port_blocked {
            self.channel.recover_ports()?;
        }
        self.clock_fault = None;
        self.port_blocked = false;
        Ok(())
    }
}
impl Drop for Client<'_> {
    fn drop(&mut self) {
        let _closed = self.close();
    }
}
