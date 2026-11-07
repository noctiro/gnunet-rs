//! Full ARM public operation owner. Host effects are explicit; no spawned process,
//! timeout result, write acknowledgement or service readiness is fabricated.
use crate::{
    ConnectionEpoch, FrameSlot, FrameTicket,
    transport::{Frames, Link, Scope},
    wire::{List, Request, RequestStatus, ResultCode, ResultReply, WireId},
};
use gnunet_types::{AbsoluteTime, Error, GenerationalId};
use gnunet_wire::official::{Frame, message_type as mt};
/// Local startup notification maximum wait, not a remote request timeout.
pub const START_SIGNAL_WAIT: u64 = 60_000_000;
/// Opaque original operation ownership, independent from its wire counter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationId {
    scope: Scope,
    id: GenerationalId,
}
/// Raw native stdio inheritance flags. They are local startup options, never IPC.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StdioInheritance(pub u32);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Result,
    List,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Vacant,
    Remote {
        wire: WireId,
        kind: Kind,
        arm_stop: bool,
    },
    WaitStop,
    NeedSpawn,
    Spawning,
    CancelledSpawning,
    WaitSignal {
        result: ResultCode,
        deadline: AbsoluteTime,
    },
    Ready {
        kind: Kind,
        result: Option<ResultCode>,
        ready_order: u64,
        stop_first: bool,
    },
    ClosingSignal,
}
/// Small caller-owned operation metadata; no per-operation maximum-name buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationSlot {
    current: u32,
    next: Option<u32>,
    state: State,
    order: u64,
    enabled: bool,
    stdio: StdioInheritance,
    has_signal: bool,
    repeat_yes: bool,
    spawn_pending: bool,
}
impl OperationSlot {
    /// Vacant safely initialized slot for static storage or Vec::resize_with.
    pub const EMPTY: Self = Self {
        current: 0,
        next: Some(0),
        state: State::Vacant,
        order: 0,
        enabled: false,
        stdio: StdioInheritance(0),
        has_signal: false,
        repeat_yes: false,
        spawn_pending: false,
    };
}
/// Original public connection status callback observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionStatus {
    /// TEST confirmation, or source notify_running repeated confirmation.
    Connected,
    /// Actual MQ error after all pending operation failure callbacks.
    Disconnected,
    /// Actual MQ creation/configuration failure, not a remote service exit.
    Error,
}
/// Owned callback observation. Disconnected operations expose no undefined C
/// result/list fields. Completion retires callback authority before exposure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    /// Owner connection observation.
    Connection(ConnectionStatus),
    /// Result callback; result is absent exactly for Disconnected.
    Result {
        /// Original logical operation.
        operation: OperationId,
        /// Request callback status.
        status: RequestStatus,
        /// Real result or no defined result on disconnect.
        result: Option<ResultCode>,
    },
    /// List callback failed; there is no fabricated empty successful list.
    ListDisconnected {
        /// Original logical operation.
        operation: OperationId,
    },
}
/// Borrowed successful list callback or an owned ordinary callback observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Inbound<'a> {
    /// Owned connection/result notification.
    Event(Event),
    /// Fully validated list, borrowing caller's original RX frame.
    List {
        /// Original logical operation.
        operation: OperationId,
        /// Checked public service-info projection.
        list: List<'a>,
    },
}
/// One explicit host action. Repeated local lease returns the same original ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Effect {
    /// Create a real GNUNET_CLIENT-equivalent MQ (OS socket retry remains separate).
    Connect(ConnectionEpoch),
    /// Create pipe/build official ARM command/execute; report actual result.
    StartArm {
        /// Original operation and host resource identity.
        operation: OperationId,
        /// Actual inherited stdio flags, not wire fields.
        stdio: StdioInheritance,
    },
    /// Close only the original startup signal endpoint, not its spawned process.
    CloseStartupSignal {
        /// Original logical host resource to close.
        operation: OperationId,
    },
}
/// Only pre-existing startup retirement obligations after explicit disconnect.
/// No variant authorizes a new connection, pipe, command or child process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetirementEffect {
    /// Settle an original leased startup which has no report yet. The host must
    /// report an already retained real result, or Failed/false if never performed.
    ReportStartup {
        /// Original startup lease, never a newly admitted operation.
        operation: OperationId,
    },
    /// Close the exact original startup signal endpoint and acknowledge it.
    CloseStartupSignal {
        /// Original signal resource identity.
        operation: OperationId,
    },
}
/// Actual result of host command setup/creation; no true readiness guarantee.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupResult {
    /// Official arm BINARY missing.
    NotKnown,
    /// Real command execution/setup failed.
    Failed,
    /// Real start command succeeded; readiness still unproven.
    Starting,
}
impl StartupResult {
    fn code(self) -> ResultCode {
        match self {
            Self::NotKnown => ResultCode::IS_NOT_KNOWN,
            Self::Failed => ResultCode::START_FAILED,
            Self::Starting => ResultCode::STARTING,
        }
    }
}
/// Bounded sans-I/O equivalent of the six public control-owner operations.
/// Ordinary remote operations have no implicit deadline and are never replayed.
pub struct Client<'a> {
    abi: crate::wire::ArmAbi,
    scope: Scope,
    ops: &'a mut [OperationSlot],
    frames: Frames<'a>,
    link: Link,
    next_order: Option<u64>,
    next_ready: Option<u64>,
    next_wire: Option<u64>,
    currently_up: bool,
    closing: bool,
    draining: bool,
    notice: Option<ConnectionStatus>,
    repeat_connection: bool,
    current_local: Option<OperationId>,
}
impl<'a> Client<'a> {
    /// Initialize caller-owned metadata and aggregate TX bytes, without OS activity.
    /// Nonzero epoch must never be reused when resetting the same backing.
    pub fn new(
        ops: &'a mut [OperationSlot],
        frames: &'a mut [FrameSlot],
        bytes: &'a mut [u8],
        epoch: u64,
        abi: crate::wire::ArmAbi,
    ) -> Result<Self, Error> {
        if epoch == 0 {
            return Err(Error::InvalidInput);
        }
        if ops.is_empty() || ops.len() > u32::MAX as usize {
            return Err(Error::Capacity);
        }
        let scope = Scope {
            epoch,
            origin: ops.as_ptr() as usize,
        };
        let queue = Frames::new(scope, frames, bytes)?;
        ops.fill(OperationSlot::EMPTY);
        Ok(Self {
            abi,
            scope,
            ops,
            frames: queue,
            link: Link::new(scope),
            next_order: Some(1),
            next_ready: Some(1),
            next_wire: Some(1),
            currently_up: false,
            closing: false,
            draining: false,
            notice: None,
            repeat_connection: false,
            current_local: None,
        })
    }
    fn id(&self, i: usize) -> OperationId {
        OperationId {
            scope: self.scope,
            id: GenerationalId {
                index: i as u32,
                generation: self.ops[i].current,
            },
        }
    }
    fn index(&self, id: OperationId) -> Result<usize, Error> {
        let i = id.id.index as usize;
        if id.scope == self.scope
            && self
                .ops
                .get(i)
                .is_some_and(|o| o.current == id.id.generation && o.state != State::Vacant)
        {
            Ok(i)
        } else {
            Err(Error::StaleGeneration)
        }
    }
    fn open(&self) -> Result<(), Error> {
        if self.closing || self.link.closed {
            Err(Error::Closed)
        } else if self.link.initial || self.draining || self.notice.is_some() {
            Err(Error::NotReady)
        } else {
            Ok(())
        }
    }
    fn prepare(&self) -> Result<(usize, u32, u64), Error> {
        self.open()?;
        let i = self
            .ops
            .iter()
            .position(|o| o.state == State::Vacant && o.next.is_some())
            .ok_or(Error::Capacity)?;
        Ok((
            i,
            self.ops[i].next.ok_or(Error::Capacity)?,
            self.next_order.ok_or(Error::Capacity)?,
        ))
    }
    fn commit(
        &mut self,
        p: (usize, u32, u64),
        state: State,
        stdio: StdioInheritance,
    ) -> OperationId {
        let (i, generation, order) = p;
        self.ops[i] = OperationSlot {
            current: generation,
            next: generation.checked_add(1),
            state,
            order,
            enabled: true,
            stdio,
            has_signal: false,
            repeat_yes: false,
            spawn_pending: false,
        };
        self.next_order = order.checked_add(1);
        self.id(i)
    }
    fn vacant(&mut self, i: usize) {
        self.ops[i].state = State::Vacant;
        self.ops[i].enabled = false;
        self.ops[i].has_signal = false;
        self.ops[i].repeat_yes = false;
        self.ops[i].spawn_pending = false;
    }
    fn ready_stamp(&mut self) -> Result<u64, Error> {
        let n = self.next_ready.ok_or(Error::Capacity)?;
        self.next_ready = n.checked_add(1);
        Ok(n)
    }
    fn retire(&mut self, i: usize) {
        self.ops[i].enabled = false;
        self.ops[i].repeat_yes = false;
        if self.ops[i].has_signal {
            self.ops[i].state = State::ClosingSignal;
        } else if self.ops[i].spawn_pending {
            self.ops[i].state = State::CancelledSpawning;
        } else {
            self.vacant(i);
        }
    }
    fn remote(&mut self, name: Option<&[u8]>, stop: bool) -> Result<OperationId, Error> {
        let p = self.prepare()?;
        self.link.current.ok_or(Error::Unavailable)?;
        let wire = WireId(self.next_wire.ok_or(Error::Capacity)?);
        let effective = name.map(|n| &n[..n.iter().position(|b| *b == 0).unwrap_or(n.len())]);
        let request = match effective {
            Some(service) if stop => Request::Stop {
                reserved: 0,
                id: wire,
                service,
            },
            Some(service) => Request::Start {
                reserved: 0,
                id: wire,
                service,
            },
            None => Request::List {
                reserved: 0,
                id: wire,
            },
        };
        self.frames.push(request)?;
        self.next_wire = wire.0.checked_add(1);
        Ok(self.commit(
            p,
            State::Remote {
                wire,
                kind: if name.is_some() {
                    Kind::Result
                } else {
                    Kind::List
                },
                arm_stop: stop && effective.is_some_and(|n| n.eq_ignore_ascii_case(b"arm")),
            },
            StdioInheritance(0),
        ))
    }
    /// Queue official LIST, immediately admitted to the logical MQ like C.
    pub fn request_service_list(&mut self) -> Result<OperationId, Error> {
        self.remote(None, false)
    }
    /// Queue STOP. ARM itself keeps a tombstone after STOPPING until MQ loss.
    pub fn request_service_stop(&mut self, service: &[u8]) -> Result<OperationId, Error> {
        self.remote(Some(service), true)
    }
    /// Queue normal START or explicit local ARM startup. Non-ARM stdio is ignored.
    pub fn request_service_start(
        &mut self,
        service: &[u8],
        stdio: StdioInheritance,
        _now: AbsoluteTime,
    ) -> Result<OperationId, Error> {
        let name = &service[..service
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(service.len())];
        if !name.eq_ignore_ascii_case(b"arm") {
            return self.remote(Some(name), false);
        }
        let p = self.prepare()?;
        let state = if self.currently_up {
            State::WaitSignal {
                result: ResultCode::IS_STARTED_ALREADY,
                deadline: AbsoluteTime::from_micros(0),
            }
        } else {
            State::NeedSpawn
        };
        let id = self.commit(p, state, stdio);
        self.ops[p.0].repeat_yes = self.currently_up;
        Ok(id)
    }
    /// Only suppress callbacks; queued remote frames remain and may still execute.
    /// Original pipe resources are closed through an explicit local cleanup effect.
    pub fn operation_cancel(&mut self, id: OperationId) -> Result<(), Error> {
        let i = self.index(id)?;
        if !self.ops[i].enabled {
            return Err(Error::StaleGeneration);
        }
        self.ops[i].enabled = false;
        self.ops[i].repeat_yes = false;
        match self.ops[i].state {
            State::WaitStop => {}
            State::Spawning => self.ops[i].state = State::CancelledSpawning,
            _ => self.retire(i),
        }
        Ok(())
    }
    /// True only while original callback authority remains; cleanup may retain its
    /// slot after cancellation without authorizing further callbacks.
    pub fn owns_operation(&self, id: OperationId) -> bool {
        self.index(id).is_ok_and(|i| self.ops[i].enabled)
    }
    fn startup_effect(&mut self) -> Result<Option<Effect>, Error> {
        if let Some(id) = self.current_local {
            let i = self.index(id)?;
            if self.ops[i].spawn_pending {
                return Ok(Some(Effect::StartArm {
                    operation: id,
                    stdio: self.ops[i].stdio,
                }));
            }
            if self.ops[i].state == State::ClosingSignal {
                return Ok(Some(Effect::CloseStartupSignal { operation: id }));
            }
            return Err(Error::Malformed);
        }
        if let Some(i) = self
            .ops
            .iter()
            .position(|o| o.state == State::ClosingSignal)
        {
            let id = self.id(i);
            self.current_local = Some(id);
            return Ok(Some(Effect::CloseStartupSignal { operation: id }));
        }
        Ok(None)
    }
    /// Observe explicit disconnect before full callback/resource retirement.
    /// This grants no authority to begin another connection or startup.
    pub const fn is_disconnecting(&self) -> bool {
        self.closing
    }
    /// Take only original startup retirement debt, without sampling a clock.
    /// Refuse while open; this path cannot admit a fresh connection/startup.
    pub fn take_retirement_effect(&mut self) -> Result<Option<RetirementEffect>, Error> {
        if !self.closing {
            return Err(Error::NotReady);
        }
        Ok(match self.startup_effect()? {
            Some(Effect::StartArm { operation, .. }) => {
                Some(RetirementEffect::ReportStartup { operation })
            }
            Some(Effect::CloseStartupSignal { operation }) => {
                Some(RetirementEffect::CloseStartupSignal { operation })
            }
            Some(Effect::Connect(_)) => return Err(Error::Malformed),
            None => None,
        })
    }
    /// Lease cleanup, MQ creation or local startup. Pending failure callbacks must
    /// be drained first, matching synchronous C callback-before-reconnect ordering.
    pub fn take_effect(&mut self, now: AbsoluteTime) -> Result<Option<Effect>, Error> {
        self.take_effect_with_startup_capacity(now, true)
    }
    /// Lease effects while the host supplies actual free startup-resource credit.
    /// False defers only a new local startup lease; it cannot block an original
    /// startup lease, signal closure or MQ creation. No operation/result/deadline
    /// is changed by deferral. This explicit bounded host decomposition prevents
    /// a later startup from holding the cleanup lane needed to free its credit.
    pub fn take_effect_with_startup_capacity(
        &mut self,
        now: AbsoluteTime,
        available: bool,
    ) -> Result<Option<Effect>, Error> {
        if let Some(effect) = self.startup_effect()? {
            return Ok(Some(effect));
        }
        if self.draining || self.notice.is_some() || self.repeat_connection {
            return Ok(None);
        }
        if !self.closing
            && !self.link.closed
            && let Some(e) = self.link.take_connect(now)?
        {
            return Ok(Some(Effect::Connect(e)));
        }
        if !available {
            return Ok(None);
        }
        if let Some(i) = self
            .ops
            .iter()
            .enumerate()
            .filter(|(_, o)| o.state == State::NeedSpawn)
            .min_by_key(|(_, o)| o.order)
            .map(|(i, _)| i)
        {
            let id = self.id(i);
            self.ops[i].state = State::Spawning;
            self.ops[i].spawn_pending = true;
            self.current_local = Some(id);
            return Ok(Some(Effect::StartArm {
                operation: id,
                stdio: self.ops[i].stdio,
            }));
        }
        Ok(None)
    }
    /// Report a truly created MQ and queue TEST; no physical connection success yet.
    pub fn connection_admitted(&mut self, e: ConnectionEpoch) -> Result<(), Error> {
        self.link.can_report(e)?;
        self.frames.can_push(4)?;
        self.frames.push(Request::Test)?;
        self.link.admitted(e)
    }
    /// Report genuine configuration/MQ creation failure. Initial failure closes the
    /// unusable owner; retry-time failure emits Error without invented retries.
    pub fn connection_unavailable(&mut self, e: ConnectionEpoch) -> Result<(), Error> {
        self.link.unavailable(e)?;
        self.notice = Some(ConnectionStatus::Error);
        Ok(())
    }
    /// Actual retired/lost MQ. ARM-self-stop completes first, pending callbacks fail
    /// in request order, then connectionNO; no operation is transparently replayed.
    pub fn connection_lost(&mut self, e: ConnectionEpoch, now: AbsoluteTime) -> Result<(), Error> {
        self.link.lost(e, now)?;
        self.frames.clear();
        self.currently_up = false;
        self.repeat_connection = false;
        self.draining = true;
        self.notice = Some(ConnectionStatus::Disconnected);
        for o in &mut *self.ops {
            let kind = match o.state {
                State::Remote { kind, .. } | State::Ready { kind, .. } => kind,
                State::NeedSpawn | State::Spawning | State::WaitSignal { .. } => Kind::Result,
                State::WaitStop => {
                    if o.enabled {
                        o.state = State::Ready {
                            kind: Kind::Result,
                            result: Some(ResultCode::STOPPED),
                            ready_order: 0,
                            stop_first: true,
                        };
                    } else {
                        o.state = State::Vacant;
                    }
                    continue;
                }
                _ => continue,
            };
            o.state = State::Ready {
                kind,
                result: None,
                ready_order: o.order,
                stop_first: false,
            };
            o.repeat_yes = false;
        }
        Ok(())
    }
    /// Retire this logical owner. Returned original MQ is the host's close
    /// obligation. Drain only immediate Disconnected callbacks/pipe close effects;
    /// all old inbound and later connection/start attempts are invalidated.
    #[must_use]
    pub fn disconnect(&mut self) -> Option<ConnectionEpoch> {
        let old = self.link.stop();
        self.frames.clear();
        self.currently_up = false;
        self.closing = true;
        self.draining = true;
        self.notice = None;
        self.repeat_connection = false;
        for i in 0..self.ops.len() {
            let o = self.ops[i];
            match o.state {
                State::Remote { kind, .. } | State::Ready { kind, .. } => {
                    self.ops[i].state = State::Ready {
                        kind,
                        result: None,
                        ready_order: o.order,
                        stop_first: false,
                    }
                }
                State::NeedSpawn | State::WaitSignal { .. } => {
                    self.ops[i].state = State::Ready {
                        kind: Kind::Result,
                        result: None,
                        ready_order: o.order,
                        stop_first: false,
                    }
                }
                State::Spawning => {
                    self.ops[i].state = State::Ready {
                        kind: Kind::Result,
                        result: None,
                        ready_order: o.order,
                        stop_first: false,
                    }
                }
                State::WaitStop => self.retire(i),
                _ => {}
            }
        }
        old
    }
    /// Report actual local startup command and read-end ownership. Read readiness,
    /// EOF or original60s expiration all yield this stored result, not fake Timeout.
    pub fn startup_report(
        &mut self,
        id: OperationId,
        result: StartupResult,
        has_read_pipe: bool,
        now: AbsoluteTime,
    ) -> Result<(), Error> {
        self.startup_report_inner(id, result, has_read_pipe, Some(now))
    }
    /// Settle an original startup result only after explicit disconnect. A
    /// retained real result/read-pipe fact is preserved; no deadline is minted.
    /// No clock is required because disconnected/cancelled callbacks cannot
    /// become a new WaitSignal or reconnect attempt.
    pub fn retire_startup(
        &mut self,
        id: OperationId,
        result: StartupResult,
        has_read_pipe: bool,
    ) -> Result<(), Error> {
        if !self.closing {
            return Err(Error::NotReady);
        }
        self.startup_report_inner(id, result, has_read_pipe, None)
    }
    fn startup_report_inner(
        &mut self,
        id: OperationId,
        result: StartupResult,
        has_read_pipe: bool,
        now: Option<AbsoluteTime>,
    ) -> Result<(), Error> {
        let i = self.index(id)?;
        if self.current_local != Some(id) || !self.ops[i].spawn_pending {
            return Err(Error::StaleGeneration);
        }
        let old = self.ops[i].state;
        let canceled = !self.ops[i].enabled;
        // Preflight any live deadline before changing the original lease. The
        // closing-only path can reach only disconnected/cancelled retirement.
        let next = if matches!(old, State::Ready { result: None, .. }) || canceled {
            old
        } else {
            let now = now.ok_or(Error::NotReady)?;
            State::WaitSignal {
                result: result.code(),
                deadline: if has_read_pipe {
                    AbsoluteTime::from_micros(now.as_micros().saturating_add(START_SIGNAL_WAIT))
                } else {
                    // Original immediate local callback, not a sampled clock value.
                    AbsoluteTime::from_micros(0)
                },
            }
        };
        self.current_local = None;
        self.ops[i].spawn_pending = false;
        self.ops[i].has_signal = has_read_pipe;
        if matches!(old, State::Ready { result: None, .. }) {
            // Failure callback remains queued; it will release/close this actual
            // returned resource after callback authority is retired.
        } else if canceled {
            self.retire(i);
        } else {
            self.ops[i].state = next;
        }
        if !self.closing && result == StartupResult::Starting {
            self.link.connect_now();
        }
        Ok(())
    }
    /// Actual readiness/EOF of the original signal endpoint; no byte payload/ID is
    /// read from it. C's scheduled local result remains unchanged.
    pub fn startup_signal_ready(&mut self, id: OperationId) -> Result<(), Error> {
        let i = self.index(id)?;
        let State::WaitSignal { result, .. } = self.ops[i].state else {
            return Err(Error::StaleGeneration);
        };
        let order = self.ready_stamp()?;
        self.ops[i].state = State::Ready {
            kind: Kind::Result,
            result: Some(result),
            ready_order: order,
            stop_first: false,
        };
        Ok(())
    }
    /// Acknowledge actual local close of this original startup endpoint only.
    pub fn startup_signal_closed(&mut self, id: OperationId) -> Result<(), Error> {
        let i = self.index(id)?;
        if self.current_local != Some(id) || self.ops[i].state != State::ClosingSignal {
            return Err(Error::StaleGeneration);
        }
        self.current_local = None;
        self.vacant(i);
        Ok(())
    }
    /// Move one due local startup notification to callback-ready state. Ordinary
    /// remote requests have no deadline and remain untouched even at u64::MAX.
    pub fn tick(&mut self, now: AbsoluteTime) -> Result<usize, Error> {
        let found = self
            .ops
            .iter()
            .enumerate()
            .filter_map(|(i, o)| {
                if let State::WaitSignal { deadline, .. } = o.state {
                    (deadline.as_micros() != u64::MAX && deadline <= now)
                        .then_some((deadline, o.order, i))
                } else {
                    None
                }
            })
            .min();
        let Some((_, _, i)) = found else {
            return Ok(0);
        };
        self.startup_signal_ready(self.id(i))?;
        Ok(1)
    }
    /// Pull one synchronous callback observation. Safe host must dispatch/drain it
    /// before continuing I/O; callback authority is retired before it is exposed.
    pub fn next_event(&mut self) -> Option<Event> {
        loop {
            if self.repeat_connection {
                self.repeat_connection = false;
                if self.currently_up {
                    return Some(Event::Connection(ConnectionStatus::Connected));
                }
            }
            let i = self
                .ops
                .iter()
                .enumerate()
                .filter_map(|(i, o)| {
                    if let State::Ready {
                        ready_order,
                        stop_first,
                        ..
                    } = o.state
                    {
                        Some((
                            !stop_first,
                            if self.draining { o.order } else { ready_order },
                            i,
                        ))
                    } else {
                        None
                    }
                })
                .min()
                .map(|(_, _, i)| i);
            if let Some(i) = i {
                let o = self.ops[i];
                let State::Ready { kind, result, .. } = o.state else {
                    return None;
                };
                let id = self.id(i);
                self.repeat_connection = o.repeat_yes && self.currently_up;
                self.retire(i);
                if !o.enabled {
                    continue;
                }
                return Some(match kind {
                    Kind::Result => Event::Result {
                        operation: id,
                        status: if result.is_some() {
                            RequestStatus::SentOk
                        } else {
                            RequestStatus::Disconnected
                        },
                        result,
                    },
                    Kind::List => Event::ListDisconnected { operation: id },
                });
            }
            self.draining = false;
            return self.notice.take().map(Event::Connection);
        }
    }
    fn find_wire(&self, id: WireId) -> Option<usize> {
        self.ops
            .iter()
            .position(|o| matches!(o.state,State::Remote{wire,..}if wire==id))
    }
    fn receive_inner<'b>(&mut self, bytes: &'b [u8]) -> Result<Option<Inbound<'b>>, Error> {
        let f = Frame::decode(bytes)?;
        let t = f.header().message_type();
        if t == mt::ARM_TEST {
            if bytes.len() != 4 {
                return Err(Error::Malformed);
            }
            if !self.currently_up {
                self.currently_up = true;
                return Ok(Some(Inbound::Event(Event::Connection(
                    ConnectionStatus::Connected,
                ))));
            }
            return Ok(None);
        }
        if t == mt::ARM_RESULT {
            let r = ResultReply::decode(self.abi, bytes)?;
            let Some(i) = self.find_wire(r.id) else {
                return Ok(None);
            };
            let State::Remote { kind, arm_stop, .. } = self.ops[i].state else {
                return Err(Error::Malformed);
            };
            if arm_stop && r.result == ResultCode::STOPPING {
                let old = self.ops.iter().position(|o| o.state == State::WaitStop);
                self.ops[i].state = State::WaitStop;
                if let Some(old) = old {
                    let id = self.id(old);
                    let enabled = self.ops[old].enabled;
                    self.retire(old);
                    if enabled {
                        return Ok(Some(Inbound::Event(Event::Result {
                            operation: id,
                            status: RequestStatus::SentOk,
                            result: Some(ResultCode::IS_NOT_KNOWN),
                        })));
                    }
                }
                return Ok(None);
            }
            let id = self.id(i);
            let enabled = self.ops[i].enabled;
            self.retire(i);
            return Ok(if enabled && kind == Kind::Result {
                Some(Inbound::Event(Event::Result {
                    operation: id,
                    status: RequestStatus::SentOk,
                    result: Some(r.result),
                }))
            } else {
                None
            });
        }
        if t == mt::ARM_LIST_RESULT {
            let list = List::decode(self.abi, bytes)?;
            let Some(i) = self.find_wire(list.id()?) else {
                return Ok(None);
            };
            let State::Remote { kind, .. } = self.ops[i].state else {
                return Err(Error::Malformed);
            };
            let id = self.id(i);
            let enabled = self.ops[i].enabled;
            self.retire(i);
            return Ok(if enabled && kind == Kind::List {
                Some(Inbound::List {
                    operation: id,
                    list,
                })
            } else {
                None
            });
        }
        Ok(None)
    }
    /// Receive only registered RESULT/LIST_RESULT/TEST. Legal unknown direction
    /// frames are ignored; malformed registered input follows actual MQ-error flow.
    pub fn receive<'b>(
        &mut self,
        e: ConnectionEpoch,
        bytes: &'b [u8],
        now: AbsoluteTime,
    ) -> Result<Option<Inbound<'b>>, Error> {
        self.link.check(e)?;
        let parsed = self.receive_inner(bytes);
        if parsed.is_err() {
            self.connection_lost(e, now)?;
        }
        parsed
    }
    /// Lease immutable oldest MQ frame, independent from canceled callback slots.
    pub fn take_frame(&mut self) -> Result<Option<FrameTicket>, Error> {
        let e = self.link.current.ok_or(Error::NotReady)?;
        Ok(self.frames.take(e))
    }
    /// Borrow the exact same frame after unrelated operations or canceled futures.
    /// Its bytes cannot be used after mutable write completion releases ownership:
    ///
    /// ```compile_fail,E0502
    /// use gnunet_arm_core::{client::Client, FrameTicket};
    /// use gnunet_types::Error;
    /// fn invalid(owner: &mut Client<'_>, ticket: FrameTicket) -> Result<(), Error> {
    ///     let frame = owner.frame(ticket)?;
    ///     owner.frame_written(ticket)?;
    ///     assert!(!frame.is_empty());
    ///     Ok(())
    /// }
    /// ```
    ///
    /// End the borrow before reporting an actual full write:
    ///
    /// ```
    /// use gnunet_arm_core::{client::Client, FrameTicket};
    /// use gnunet_types::Error;
    /// fn after_actual_full_write(owner: &mut Client<'_>, ticket: FrameTicket)
    ///     -> Result<usize, Error> {
    ///     let n = owner.frame(ticket)?.len();
    ///     owner.frame_written(ticket)?;
    ///     Ok(n)
    /// }
    /// ```
    pub fn frame(&self, t: FrameTicket) -> Result<&[u8], Error> {
        self.frames
            .view(t, self.link.current.ok_or(Error::StaleGeneration)?)
    }
    /// Full local write only; it does not complete an ARM operation.
    pub fn frame_written(&mut self, t: FrameTicket) -> Result<(), Error> {
        self.frames
            .written(t, self.link.current.ok_or(Error::StaleGeneration)?)
    }
    /// Recover a leased frame after a dropped drive future.
    pub fn current_frame(&self) -> Option<FrameTicket> {
        self.frames.current()
    }
    /// Source TEST-confirmed state, distinct from MQ creation or process start.
    pub const fn currently_up(&self) -> bool {
        self.currently_up
    }
    /// Escalating backoff, never reset by TEST confirmation.
    pub const fn retry_backoff(&self) -> u64 {
        self.link.backoff
    }
    /// Earliest original local-start deadline or reconnect time; no remote timeout.
    pub fn next_wakeup(&self) -> Option<AbsoluteTime> {
        self.ops
            .iter()
            .filter_map(|o| {
                if let State::WaitSignal { deadline, .. } = o.state {
                    Some(deadline)
                } else {
                    None
                }
            })
            .chain(self.link.retry)
            .min()
    }
    /// Fully retired after explicit disconnect/initial creation failure and all
    /// immediate callback/resource obligations were drained.
    pub fn is_closed(&self) -> bool {
        (self.closing || self.link.closed)
            && self.ops.iter().all(|o| o.state == State::Vacant)
            && self.notice.is_none()
    }
}

#[cfg(test)]
mod retirement_tests;
