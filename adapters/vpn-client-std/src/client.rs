//! One native MQ, bounded original allocation slots and finite partial drains.
use crate::{
    Address, AfProfile, Cancel, EndpointSource, Epoch, Error, Family, Instance, Limits, LossCause,
    Operation, Outcome, Progress, Reason, Service, Submission, WriteId, ipc::Request, scope::Scope,
};
use gnunet_client_host::channel::Channel;
use gnunet_service_runtime::{
    clock::{Deadline, RuntimeClock},
    framing::{Class, OwnedFrame},
};
use gnunet_types::Error as ProtocolError;
use std::{collections::VecDeque, pin::Pin, sync::Arc};
mod io;
#[derive(Clone, Copy)]
struct Origin<'a> {
    epoch: Epoch<'a>,
    operation: Operation<'a>,
    write: WriteId<'a>,
}
struct State<'a> {
    operation: Operation<'a>,
    rid: [u8; 8],
    desired: Option<Family>,
    source: Option<OwnedFrame>,
    expires: u64,
    epoch: Option<Epoch<'a>>,
    pending: bool,
    exposed: bool,
    written: bool,
    reason: Option<Reason>,
    hard: Option<u64>,
}
/// Caller-driven official VPN address allocation client. It creates no task,
/// service, Resolver or platform device. Loss terminates original requests;
/// a later connection accepts only explicit new allocation intents.
pub struct Client<'a> {
    scope: Scope<'a>,
    channel: Channel<Origin<'a>>,
    clock: Arc<dyn RuntimeClock>,
    profile: AfProfile,
    limits: Limits,
    slots: Vec<Option<State<'a>>>,
    events: VecDeque<Progress<'a>>,
    next_rid: u64,
    epoch: Option<Epoch<'a>>,
    alarm: Option<Pin<Box<Deadline>>>,
    alarm_at: Option<u64>,
    read_first: bool,
    yield_due: bool,
    closed: bool,
    clock_fault: Option<ProtocolError>,
    port_blocked: bool,
}
impl<'a> Client<'a> {
    /// Reserve bounded ownership with the service endpoint's explicit AF profile.
    /// This performs no IO and never guesses a non-native endpoint's AF_INET6.
    pub fn new(
        instance: &'a mut Instance,
        source: EndpointSource,
        profile: AfProfile,
        limits: Limits,
    ) -> Result<Self, Error> {
        profile.validate()?;
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
            profile,
            limits,
            slots,
            events,
            next_rid: 0,
            epoch: None,
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
            .position(|state| state.as_ref().is_some_and(|s| s.operation == operation))
            .ok_or(ProtocolError::Stale)
    }
    fn now(&self) -> Result<u64, ProtocolError> {
        Ok(self.clock.sample()?.now.as_micros())
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
                let lost = self.refuse_clock(error)?;
                self.events.push_back(lost);
                Err(error.into())
            }
        }
    }
    fn admit(
        &mut self,
        build: impl FnOnce([u8; 8], u32) -> Request,
        desired: Option<Family>,
        lease_until: u64,
        response_until: u64,
    ) -> Result<Operation<'a>, Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        if !self.events.is_empty() {
            return Err(ProtocolError::WouldBlock.into());
        }
        let now = self.sample()?;
        if response_until <= now
            || response_until == u64::MAX
            || lease_until <= now
            || response_until
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
        let next = self
            .next_rid
            .checked_add(1)
            .ok_or(ProtocolError::Overflow)?;
        let rid = next.to_be_bytes(); // Opaque exact echo, independent of C host endianness.
        let request = build(rid, desired.map_or(0, |af| self.profile.value(af)));
        let len = request.encoded_len()?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| ProtocolError::Capacity)?;
        bytes.resize(len, 0);
        request.encode_with_profile(&mut bytes, self.profile)?;
        let operation = self.scope.operation()?;
        self.slots[index] = Some(State {
            operation,
            rid,
            desired,
            source: Some(OwnedFrame::new(bytes)),
            expires: response_until,
            epoch: None,
            pending: false,
            exposed: false,
            written: false,
            reason: None,
            hard: None,
        });
        self.next_rid = next;
        self.alarm = None;
        self.alarm_at = None;
        Ok(operation)
    }
    /// Request a real Internet redirect. `lease_until` is the official address
    /// expiration (FOREVER is allowed); `response_until` is a finite local wait.
    /// `desired=None` sends AF_UNSPEC. Only matching USE_IP is an allocation result.
    pub fn internet(
        &mut self,
        destination: Address,
        desired: Option<Family>,
        lease_until: u64,
        response_until: u64,
    ) -> Result<Operation<'a>, Error> {
        self.admit(
            |request_id, result_af| Request::Internet {
                reserved: 0,
                expires: lease_until,
                result_af,
                destination,
                request_id,
            },
            desired,
            lease_until,
            response_until,
        )
    }
    /// Request the named peer's TCP/UDP service. An address result does not
    /// authenticate the peer, install a host route or establish that service.
    pub fn service(
        &mut self,
        target: Service,
        desired: Option<Family>,
        lease_until: u64,
        response_until: u64,
    ) -> Result<Operation<'a>, Error> {
        self.admit(
            |request_id, result_af| Request::Service {
                reserved: 0,
                expires: lease_until,
                protocol: target.protocol.value(),
                result_af,
                peer: target.peer,
                service: target.descriptor,
                request_id,
            },
            desired,
            lease_until,
            response_until,
        )
    }
    /// Current retained original allocation/debt count.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }
    /// Earliest original response or partial-drain absolute deadline.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        self.slots
            .iter()
            .filter_map(|s| s.as_ref())
            .map(|s| s.hard.unwrap_or(s.expires))
            .min()
    }
    /// Consume one retained local completion, without IO.
    pub fn next_event(&mut self) -> Option<Progress<'a>> {
        self.events.pop_front()
    }
    fn finish(&mut self, index: usize, outcome: Outcome) -> Result<(), Error> {
        let state = self.slots[index].take().ok_or(ProtocolError::Stale)?;
        self.events.push_back(Progress::Completed {
            epoch: state.epoch,
            operation: state.operation,
            outcome,
        });
        self.alarm = None;
        self.alarm_at = None;
        Ok(())
    }
    fn submission(state: &State<'_>) -> Submission {
        if state.exposed {
            Submission::Unknown
        } else {
            Submission::Unsent
        }
    }
    fn cancel_index(&mut self, index: usize, reason: Reason, now: u64) -> Result<Cancel, Error> {
        let state = self.slots[index].as_ref().ok_or(ProtocolError::Stale)?;
        if state.reason.is_some() {
            return Err(ProtocolError::Stale.into());
        }
        let operation = state.operation;
        let removed = self.channel.framing_mut().map_or(0, |frame| {
            frame.remove_unwritten(|origin, _| origin.operation == operation, |_, _| {})
        });
        let state = self.slots[index].as_mut().ok_or(ProtocolError::Stale)?;
        if removed > 1 || (removed == 1 && !state.pending) {
            return Err(ProtocolError::Stale.into());
        }
        if removed == 1 {
            state.pending = false;
        }
        state.source = None;
        state.reason = Some(reason);
        if state.pending {
            state.hard = Some(
                now.saturating_add(self.limits.retirement_grace_micros)
                    .min(state.expires + self.limits.retirement_grace_micros),
            );
            self.alarm = None;
            self.alarm_at = None;
            return Ok(Cancel::Draining);
        }
        let submission = Self::submission(state);
        self.finish(index, Outcome::Local { reason, submission })?;
        Ok(match submission {
            Submission::Unsent => Cancel::Unsent,
            Submission::Unknown => Cancel::Unknown,
        })
    }
    /// Suppress this original callback. No CANCEL IPC exists. Wholly unwritten
    /// frames are removed; original partial frames drain under a fixed bound.
    /// An already exposed request may still create a lease after cancellation.
    pub fn cancel(&mut self, operation: Operation<'_>) -> Result<Cancel, Error> {
        let index = self.index(operation)?;
        let now = self.sample()?;
        self.cancel_index(index, Reason::Cancelled, now)
    }
    fn prepare(&mut self) -> Result<(), Error> {
        let epoch = self.epoch.ok_or(ProtocolError::NotReady)?;
        for state in self.slots.iter_mut().flatten() {
            let Some(source) = state.source.as_ref() else {
                continue;
            };
            if state.reason.is_some() {
                continue;
            }
            let frame = self.channel.framing_mut().ok_or(ProtocolError::NotReady)?;
            if !frame.capacity(source.len(), Class::Ordinary) {
                continue;
            }
            frame.reserve(source.len(), Class::Ordinary)?;
            let origin = Origin {
                epoch,
                operation: state.operation,
                write: self.scope.write()?,
            };
            let bytes = state.source.take().ok_or(ProtocolError::Stale)?;
            if let Err(rejected) = frame.enqueue_owned(bytes, origin, Class::Ordinary) {
                state.source = Some(rejected.value.0);
                return Err(rejected.reason.into());
            }
            state.pending = true;
            state.epoch = Some(epoch);
            return Ok(());
        }
        Ok(())
    }
    fn retire(&mut self, cause: LossCause, retry: bool) -> Result<Progress<'a>, Error> {
        let epoch = self.epoch.take();
        self.channel.detach(); // The physical fence precedes every logical settlement.
        for index in 0..self.slots.len() {
            let Some(state) = &self.slots[index] else {
                continue;
            };
            let reason = state.reason.unwrap_or(if self.closed {
                Reason::Closed
            } else {
                Reason::Lost
            });
            let submission = Self::submission(state);
            self.finish(index, Outcome::Local { reason, submission })?;
        }
        self.alarm = None;
        self.alarm_at = None;
        if retry && !self.closed {
            self.channel.schedule_retry()?;
        }
        Ok(Progress::Lost { epoch, cause })
    }
    fn refuse_clock(&mut self, error: ProtocolError) -> Result<Progress<'a>, Error> {
        self.clock_fault = Some(error);
        self.retire(LossCause::Clock(error), false)
    }
    fn refuse_ports(&mut self, error: Error) -> Result<Progress<'a>, Error> {
        self.port_blocked = true;
        self.retire(LossCause::Ports(error), false)
    }
    /// Close the old MQ before permitting a new one. Every old allocation ends
    /// as local Unsent/Unknown. No old intent or frame is reconstructed or replayed.
    pub fn reconnect(&mut self) -> Result<Progress<'a>, Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        self.retire(LossCause::Requested, true)
    }
    /// Permanently close original native ownership, preserving local completions.
    pub fn close(&mut self) -> Result<Option<Progress<'a>>, Error> {
        if self.closed {
            return Ok(None);
        }
        self.closed = true;
        self.channel.close();
        self.retire(LossCause::Closed, false).map(Some)
    }
    /// Explicitly recover refused clock/Resolver/timer ports. Recovery authorizes
    /// new operations only and cannot replay a prior uncertain allocation.
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
