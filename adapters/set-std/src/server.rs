//! One caller-driven generic SET SERVICE and original shared CADET CLIENT.
use crate::ports::NativePorts;
use gnunet_cadet_host as cadet;
use gnunet_service_runtime::{
    accepted::{AcceptState, AcceptedConnection, SocketEvent},
    clock::{Deadline, RuntimeClock},
    credentials::UnixAccess,
    framing::{Accounting, Budget, Class, Framed, Limits as FrameLimits, OwnedFrame, ReadStep},
    service::{Listener, PeerAddress, ServiceOptions, ShutdownMode},
};
use gnunet_set::{
    Action, Client, Completion, EffectId, EffectScan, EffectScanStep, PeerOwner, Service, Terminal,
};
use gnunet_types::Error as Fault;
use gnunet_wire::official::{
    MessageHeader,
    set::{ClientRequest, PeerMessage},
};
use std::{
    collections::VecDeque,
    fmt,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
mod types;
pub use types::{
    CloseCause, Error, Event, FailedOperation, ForcedRetirement, Limits, Progress, Report,
    RetirementTrigger, Shutdown,
};
mod apps;
mod effects;
mod peers;
struct Write<'id> {
    id: EffectId<'id>,
    origin: u64,
    hard: Instant,
    charge: usize,
    written: usize,
    completed: bool,
    admitted: bool,
}
struct App<'id> {
    client: Client<'id>,
    io: Option<Framed<u64>>,
    writes: VecDeque<Write<'id>>,
    first: Option<Instant>,
    partial: Option<Instant>,
    cursor: usize,
    held_now: Option<u64>,
    detached: bool,
    retire_reason: Fault,
}
struct Bound<'id> {
    listener: Client<'id>,
    hash: [u8; 64],
    port: cadet::Port<'id>,
    close: Option<EffectId<'id>>,
    closing: bool,
    hard: Option<Instant>,
}
struct Input<'id> {
    packet: cadet::Received<'id>,
    at: usize,
    hard: Option<Instant>,
    held_now: Option<u64>,
    // A delivered packet never changes owner during local adoption.
    owner: Option<PeerOwner<'id>>,
}
struct Channel<'id> {
    listener: Option<Client<'id>>,
    app_id: [u8; 64],
    owner: Option<PeerOwner<'id>>,
    peer: [u8; 32],
    channel: cadet::Channel<'id>,
    opening: bool,
    closing: bool,
    // Local cancellation/error is independent of a later physical peer close.
    local_closing: bool,
    remote_closed: bool,
    retire_reason: Fault,
    first: Option<Instant>,
    input: Option<Input<'id>>,
    hard: Option<Instant>,
}
impl Channel<'_> {
    /// Mark local cancellation/error/completion without claiming physical close.
    /// Abandon its old input before a later remote Destroyed can arrive. The
    /// first cleanup target is independent of the now-ended business/input
    /// phase; a later close cannot renew an already captured cleanup target.
    fn mark_closing(&mut self, hard: Instant) {
        self.closing = true;
        self.local_closing = true;
        self.first = None;
        self.input = None;
        self.hard = Some(self.hard.map_or(hard, |old| old.min(hard)));
    }
}
struct Send<'id> {
    id: EffectId<'id>,
    channel: cadet::Channel<'id>,
    frame: OwnedFrame,
    charge: usize,
    hard: Instant,
}
struct Closing<'id> {
    id: EffectId<'id>,
    owner: PeerOwner<'id>,
    written: bool,
    outcome: Option<Completion>,
}
#[derive(Clone, Copy)]
enum PendingKind<'id> {
    OpenPort(Client<'id>),
    ClosePort(Client<'id>),
    Open(cadet::Channel<'id>),
    Send(cadet::Channel<'id>),
    Destroy(cadet::Channel<'id>),
    Ack(cadet::Channel<'id>),
    Internal,
}
struct Pending<'id> {
    transmit: cadet::Transmit<'id>,
    effect: Option<EffectId<'id>>,
    admitted: bool,
    kind: PendingKind<'id>,
    hard: Instant,
    completion: Option<Completion>,
}
struct Adopt<'id> {
    id: EffectId<'id>,
    channel: Option<cadet::Channel<'id>>,
}
/// Actual native service owner. Both brands are borrowed from foreground-owned
/// instances; no self-reference, worker, hidden task or private RPC is added.
pub struct Server<'id, 'slots> {
    core: Service<'id>,
    cadet: cadet::Client<'id, 'slots>,
    apps: Vec<Option<App<'id>>>,
    ports: Vec<Option<Bound<'id>>>,
    channels: Vec<Option<Channel<'id>>>,
    sends: VecDeque<Send<'id>>,
    closing: Vec<Closing<'id>>,
    pending: Option<Pending<'id>>,
    adopted: Option<Adopt<'id>>,
    effect_scan: EffectScan<'id>,
    progress_remaining: usize,
    ports_provider: NativePorts,
    limits: Limits,
    options: ServiceOptions,
    unix: UnixAccess,
    accept: AcceptState,
    clock: Arc<dyn RuntimeClock>,
    logical: Option<(u64, Deadline)>,
    timer: Pin<Box<Sleep>>,
    read_hard: Option<Instant>,
    forced_loss: Option<ForcedRetirement>,
    next_output: u64,
    app_cursor: usize,
    peer_cursor: usize,
    listener_cursor: usize,
    class: usize,
    shutdown: Option<ShutdownMode>,
    stopped: bool,
    failed: bool,
    report: Report,
}
fn slots<T>(count: usize) -> Result<Vec<Option<T>>, Fault> {
    let mut out = Vec::new();
    out.try_reserve(count).map_err(|_| Fault::Capacity)?;
    out.resize_with(count, || None);
    Ok(out)
}
fn buffer(size: usize) -> Result<Vec<u8>, Fault> {
    let mut out = Vec::new();
    out.try_reserve_exact(size).map_err(|_| Fault::Capacity)?;
    out.resize(size, 0);
    Ok(out)
}
fn retry(error: &cadet::Error) -> bool {
    matches!(
        error,
        cadet::Error::Protocol(Fault::WouldBlock | Fault::NotReady | Fault::Capacity)
    )
}
// One core step per native CPU class. Bookkeeping Activity carries only the
// remaining finite owner pass; it is not an admission, write or peer result.
fn progress_activity(remaining: &mut usize, span: usize, changed: bool) -> bool {
    if changed {
        *remaining = span;
        true
    } else {
        *remaining = remaining.saturating_sub(1);
        *remaining != 0
    }
}
impl<'id, 'slots> Server<'id, 'slots> {
    /// Own the original pure service and real shared CADET client. Construction
    /// allocates bounded metadata only; it opens no socket or listener.
    pub fn new(
        core: Service<'id>,
        cadet: cadet::Client<'id, 'slots>,
        limits: Limits,
        options: ServiceOptions,
        unix: UnixAccess,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let mut sends = VecDeque::new();
        sends
            .try_reserve(limits.peer_frames)
            .map_err(|_| Fault::Capacity)?;
        let mut closing = Vec::new();
        closing
            .try_reserve_exact(limits.channels)
            .map_err(|_| Fault::Capacity)?;
        let clock = cadet.clock();
        let progress_remaining = core.progress_span();
        Ok(Self {
            core,
            cadet,
            apps: slots(limits.clients)?,
            ports: slots(limits.ports)?,
            channels: slots(limits.channels)?,
            sends,
            closing,
            pending: None,
            adopted: None,
            effect_scan: EffectScan::new(),
            progress_remaining,
            ports_provider: NativePorts::new(),
            limits,
            options,
            unix,
            accept: AcceptState::default(),
            clock,
            logical: None,
            timer: Box::pin(tokio::time::sleep(Duration::ZERO)),
            read_hard: None,
            forced_loss: None,
            next_output: 0,
            app_cursor: 0,
            peer_cursor: 0,
            listener_cursor: 0,
            class: 0,
            shutdown: None,
            stopped: false,
            failed: false,
            report: Report::default(),
        })
    }
    /// Original shared process clock.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    /// True only after the actual shared CADET MQ attaches. Generic SET has
    /// no fixed global listening port; each real listener owns its own port.
    #[must_use]
    pub fn ready(&self) -> bool {
        !self.failed && self.shutdown.is_none() && self.cadet.epoch().is_some()
    }
    /// Same actual native attachment predicate as `ready`.
    #[must_use]
    pub fn initialized(&self) -> bool {
        self.ready()
    }
    /// Actual local diagnostic counters.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.report
    }
    fn now(&self) -> Result<u64, Error> {
        Ok(self.clock.sample()?.now.as_micros())
    }
    fn hard(&self) -> Result<Instant, Error> {
        Instant::now()
            .checked_add(self.limits.retirement_grace)
            .ok_or(Fault::Overflow.into())
    }
    fn core_result<T>(&mut self, result: Result<T, Fault>) -> Result<T, Error> {
        result.map_err(|error| match self.ports_provider.take_error() {
            Some(original) => Error::Entropy(original),
            None => error.into(),
        })
    }
    fn framing(&self) -> FrameLimits {
        FrameLimits {
            frame_bytes: self.limits.frame_bytes,
            ordinary: Budget {
                frames: self.limits.output_frames,
                bytes: self.limits.output_bytes,
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.limits.io_slice_bytes,
        }
    }
    fn channel_index(&self, channel: cadet::Channel<'id>) -> Option<usize> {
        self.channels
            .iter()
            .position(|p| p.as_ref().is_some_and(|p| p.channel == channel))
    }
    fn owner_channel(&self, owner: PeerOwner<'id>) -> Option<usize> {
        self.channels
            .iter()
            .position(|p| p.as_ref().is_some_and(|p| p.owner == Some(owner)))
    }
    fn terminal(
        &mut self,
        id: EffectId<'id>,
        completion: Completion,
        admitted: bool,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        let failure = self.core.failure_for_effect(id);
        let result = if admitted {
            self.core.complete_effect(id, completion)
        } else {
            match completion {
                Completion::Unsent(e) | Completion::Lost(e) => self.core.reject_effect(id, e),
                Completion::Written => return Err(Fault::Conflict.into()),
            }
        };
        let terminal = result?;
        let completion = terminal.completion;
        observe(Event::EffectTerminal(terminal));
        if let Some(failure) = failure {
            observe(Event::OperationFailed(FailedOperation {
                failure,
                completion,
            }));
        }
        self.restart_progress();
        Ok(())
    }
    fn reject(
        &mut self,
        id: EffectId<'id>,
        error: Fault,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        self.terminal(id, Completion::Unsent(error), false, observe)
    }
    fn accept(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        if self.shutdown.is_some() || !self.accept.ready() || self.apps.iter().all(Option::is_some)
        {
            return Poll::Pending;
        }
        for n in 0..listeners.len() {
            let i = (self.listener_cursor + n) % listeners.len();
            match listeners[i].poll_canonical_connection(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(error)) => {
                    self.listener_cursor = (i + 1) % listeners.len();
                    observe(Event::Socket(self.accept.failed(error)));
                    return Poll::Ready(Ok(Progress::Activity));
                }
                Poll::Ready(Ok(accepted)) => {
                    self.listener_cursor = (i + 1) % listeners.len();
                    if let Err(error) = self.admit(accepted, observe) {
                        observe(Event::AdmissionFailed(error));
                    }
                    return Poll::Ready(Ok(Progress::Activity));
                }
            }
        }
        Poll::Pending
    }
    fn logical(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        let target = self.core.next_deadline();
        if target != self.logical.as_ref().map(|(at, _)| *at) {
            self.logical = target
                .map(|t| {
                    Deadline::at(
                        self.clock.clone(),
                        gnunet_types::AbsoluteTime::from_micros(t),
                    )
                    .map(|d| (t, d))
                })
                .transpose()?;
        }
        if let Some((_, waiter)) = &mut self.logical
            && let Poll::Ready(result) = Pin::new(waiter).poll(cx)
        {
            result?;
            self.logical = None;
            let now = self.now()?;
            let result = self.core.tick(now, &mut self.ports_provider);
            return match self.core_result(result) {
                Ok(()) => Ok(true),
                Err(Error::Protocol(Fault::WouldBlock | Fault::NotReady | Fault::Capacity)) => {
                    Ok(false)
                }
                Err(error) => Err(error),
            };
        }
        Ok(false)
    }
    fn restart_progress(&mut self) {
        self.progress_remaining = self.core.progress_span();
    }
    fn progress(&mut self) -> Result<bool, Error> {
        if self.progress_remaining == 0 {
            return Ok(false);
        }
        let now = self.now()?;
        let result = self.core.progress(now, &mut self.ports_provider);
        let changed = match self.core_result(result) {
            Ok(progress) => progress,
            Err(Error::Protocol(Fault::WouldBlock | Fault::NotReady | Fault::Capacity)) => false,
            Err(error) => return Err(error),
        };
        Ok(progress_activity(
            &mut self.progress_remaining,
            self.core.progress_span(),
            changed,
        ))
    }
    /// Stop admission. Soft waits for original IPC clients; the foreground owns
    /// its fixed overall grace and may force actual immediate closure.
    pub fn request_shutdown(&mut self, mode: ShutdownMode) {
        if self.shutdown != Some(ShutdownMode::Immediate) {
            self.shutdown = Some(mode);
        }
    }
    fn timer_target(&self, wait: Option<Instant>) -> Option<Instant> {
        wait.into_iter()
            .chain(self.read_hard)
            .chain(self.pending.iter().map(|p| p.hard))
            .chain(self.ports.iter().flatten().filter_map(|p| p.hard))
            .chain(self.channels.iter().flatten().flat_map(|p| {
                p.hard
                    .into_iter()
                    .chain(p.first)
                    .chain(p.input.as_ref().and_then(|i| i.hard))
            }))
            .chain(self.sends.iter().filter_map(|send| {
                self.channel_index(send.channel)
                    .and_then(|index| self.channels[index].as_ref())
                    .filter(|channel| !channel.closing && !channel.remote_closed)
                    .map(|_| send.hard)
            }))
            .chain(self.apps.iter().flatten().flat_map(|a| {
                a.first
                    .into_iter()
                    .chain(a.partial)
                    .chain(a.writes.front().map(|w| w.hard))
            }))
            .min()
    }
    fn timer(&mut self, cx: &mut Context<'_>, wait: Option<Instant>) {
        if let Some(at) = self.timer_target(wait) {
            self.timer.as_mut().reset(at);
            if self.timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
    }
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        wait: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        if self.stopped {
            return Poll::Ready(Ok(Progress::Stopped));
        }
        if self.shutdown == Some(ShutdownMode::Immediate)
            || (self.shutdown == Some(ShutdownMode::Soft) && self.apps.iter().all(Option::is_none))
        {
            let result = self.shutdown(&mut *observe);
            return Poll::Ready(match result.failure {
                Some(error) => Err(error),
                None if result.drained => Ok(Progress::Stopped),
                None => Err(Fault::NotReady.into()),
            });
        }
        if self.failed {
            return Poll::Ready(Err(Fault::Closed.into()));
        }
        if self.guards(observe)?
            || self.settle_adopt(observe)?
            || self.settle_pending(observe)?
            || self.reap_apps(observe)?
        {
            self.restart_progress();
            return Poll::Ready(Ok(Progress::Activity));
        }
        if self.logical(cx)? {
            self.restart_progress();
            return Poll::Ready(Ok(Progress::Activity));
        }
        if wait.is_some_and(|until| Instant::now() >= until) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        for offset in 0..6 {
            // A canonical clock wait or an earlier IO class may consume the
            // native phase budget. Fence again before starting another class.
            if self.guards(observe)? {
                self.restart_progress();
                return Poll::Ready(Ok(Progress::Activity));
            }
            let class = (self.class + offset) % 6;
            let result = match class {
                0 => self.poll_apps(cx, observe),
                1 => self.poll_cadet(cx, observe),
                2 => {
                    if self.effect(observe)? {
                        Poll::Ready(Ok(Progress::Activity))
                    } else {
                        Poll::Pending
                    }
                }
                3 => {
                    if self.peer_work(observe)? {
                        Poll::Ready(Ok(Progress::Activity))
                    } else {
                        Poll::Pending
                    }
                }
                4 => {
                    if self.progress()? {
                        Poll::Ready(Ok(Progress::Activity))
                    } else {
                        Poll::Pending
                    }
                }
                _ => self.accept(cx, listeners, observe),
            };
            if result.is_ready() {
                // EffectScan bookkeeping alone cannot restart a CPU pass. Its
                // actual original settlements reset it through terminal().
                if class != 2 && class != 4 {
                    self.restart_progress();
                }
                self.class = (class + 1) % 6;
                return result;
            }
        }
        self.timer(cx, wait);
        Poll::Pending
    }
    /// Poll bounded actual work; first fatal error latches and permits only
    /// physical shutdown afterward, never reissuing an uncertain original.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        wait: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        let result = self.poll_inner(cx, listeners, wait, observe);
        if matches!(&result, Poll::Ready(Err(_))) {
            self.failed = true;
        }
        result
    }
    /// Cancellation-safe observation of this same owner; no hidden task is spawned.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        wait: Option<Instant>,
        mut observe: impl FnMut(Event<'id>),
    ) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll(cx, listeners, wait, &mut observe)).await
    }
}
impl Drop for Server<'_, '_> {
    fn drop(&mut self) {
        let _closed = self.shutdown(|_| {});
    }
}

impl<'id, 'slots> Server<'id, 'slots> {
    fn force_retirement(&mut self, reason: Fault, trigger: RetirementTrigger) {
        let snapshot = ForcedRetirement {
            reason,
            trigger,
            pending: self
                .pending
                .as_ref()
                .map(|pending| pending.transmit)
                .or_else(|| self.cadet.pending_transmit())
                .map(|pending| (pending.value(), pending.kind())),
            pending_terminal: self.pending.as_ref().and_then(|pending| pending.completion),
            peer: self.channels.iter().flatten().find_map(|channel| {
                let matches = match trigger {
                    RetirementTrigger::ChannelHard {
                        channel: original,
                        wire,
                    } => channel.channel.value() == original && channel.channel.wire_id() == wire,
                    RetirementTrigger::CancelledPending | RetirementTrigger::PendingHard => self
                        .pending
                        .as_ref()
                        .is_some_and(|pending| match pending.kind {
                            PendingKind::Open(original)
                            | PendingKind::Send(original)
                            | PendingKind::Destroy(original)
                            | PendingKind::Ack(original) => original == channel.channel,
                            _ => false,
                        }),
                    _ => false,
                };
                matches.then_some(channel.peer)
            }),
            channels: self.channels.iter().flatten().count(),
            queued_sends: self.sends.len(),
        };
        self.forced_loss.get_or_insert(snapshot);
    }
    fn guards(&mut self, observe: &mut impl FnMut(Event<'id>)) -> Result<bool, Error> {
        let now = Instant::now();
        // Original native alarms/cancellation run before canonical clock waits.
        for index in 0..self.apps.len() {
            if self.apps[index].as_ref().is_some_and(|a| {
                a.io.is_some()
                    && (a.first.is_some_and(|at| now >= at)
                        || a.partial.is_some_and(|at| now >= at)
                        || a.writes.front().is_some_and(|w| now >= w.hard))
            }) {
                self.stop_app(index, CloseCause::Deadline, observe)?;
                return Ok(true);
            }
        }
        let hard = self.hard()?;
        for bound in self.ports.iter_mut().flatten() {
            if !self.core.client_live(bound.listener) {
                bound.closing = true;
                bound.hard.get_or_insert(hard);
            }
        }
        for channel in self.channels.iter_mut().flatten() {
            if (channel.owner.is_none()
                && channel.listener.is_some_and(|l| !self.core.client_live(l)))
                || (channel
                    .owner
                    .is_some_and(|owner| !self.core.peer_owner_live(owner))
                    && !self
                        .adopted
                        .as_ref()
                        .is_some_and(|a| a.channel == Some(channel.channel)))
                || channel.first.is_some_and(|at| now >= at)
                || channel
                    .input
                    .as_ref()
                    .is_some_and(|i| i.hard.is_some_and(|at| now >= at))
            {
                if channel.first.is_some_and(|at| now >= at)
                    || channel
                        .input
                        .as_ref()
                        .is_some_and(|i| i.hard.is_some_and(|at| now >= at))
                {
                    channel.retire_reason = Fault::Deadline;
                }
                channel.mark_closing(hard);
            }
        }
        if self.retire_unannounced_ports(Fault::Cancelled, observe)? {
            return Ok(true);
        }
        for send in &self.sends {
            if now >= send.hard
                && let Some(index) = self.channel_index(send.channel)
            {
                let channel = self.channels[index].as_mut().ok_or(Fault::Stale)?;
                if !channel.closing && !channel.remote_closed {
                    channel.retire_reason = Fault::Deadline;
                    channel.mark_closing(hard);
                }
            }
        }
        let cancelled = self
            .pending
            .as_ref()
            .is_some_and(|pending| match pending.kind {
                PendingKind::Open(channel) | PendingKind::Send(channel) => self
                    .channel_index(channel)
                    .is_none_or(|i| self.channels[i].as_ref().is_none_or(|c| c.local_closing)),
                PendingKind::OpenPort(listener) => self
                    .ports
                    .iter()
                    .flatten()
                    .any(|p| p.listener == listener && p.closing),
                PendingKind::Internal
                    if pending.transmit.kind() == cadet::TransmitKind::PortOpen =>
                {
                    // The CADET restore token exposes no port handle. Retire
                    // its original MQ conservatively rather than guess a listener
                    // or keep writing a known-canceled listener's announcement.
                    self.ports.iter().flatten().any(|p| p.closing)
                }
                _ => false,
            });
        // Preserve the existing cancellation-first guard order. The snapshot
        // names the actual predicate; it does not renew or reinterpret targets.
        let trigger = if cancelled {
            Some(RetirementTrigger::CancelledPending)
        } else if self.read_hard.is_some_and(|at| now >= at) {
            Some(RetirementTrigger::ReadHard)
        } else if self
            .pending
            .as_ref()
            .is_some_and(|pending| now >= pending.hard)
        {
            Some(RetirementTrigger::PendingHard)
        } else if let Some(port) = self
            .ports
            .iter()
            .flatten()
            .find(|port| port.hard.is_some_and(|at| now >= at))
        {
            Some(RetirementTrigger::ClosingPortHard {
                port: port.port.value(),
            })
        } else {
            self.channels.iter().flatten().find_map(|channel| {
                channel
                    .hard
                    .filter(|at| now >= *at)
                    .map(|_| RetirementTrigger::ChannelHard {
                        channel: channel.channel.value(),
                        wire: channel.channel.wire_id(),
                    })
            })
        };
        if let Some(trigger) = trigger
            && self.cadet.epoch().is_some()
        {
            self.force_retirement(
                if cancelled {
                    Fault::Cancelled
                } else {
                    Fault::Deadline
                },
                trigger,
            );
            let lost = self.cadet.reconnect()?;
            self.native_event(lost, observe)?;
            return Ok(true);
        }
        Ok(false)
    }
    /// Synchronously close original IO before retiring its retained effects.
    /// A refusal leaves metadata in this owner for another clock-free cleanup;
    /// stopped is reported only when pure and physical debts are both absent.
    pub fn shutdown(&mut self, mut observe: impl FnMut(Event<'id>)) -> Shutdown {
        self.shutdown = Some(ShutdownMode::Immediate);
        self.logical = None;
        let mut failure = None;
        let mut pressure = None;
        if let Err(error) = self.settle_adopt(&mut observe) {
            cleanup_error(&mut failure, &mut pressure, error);
        }
        for index in 0..self.apps.len() {
            if self.apps[index].is_some()
                && let Err(error) = self.stop_app(index, CloseCause::Shutdown, &mut observe)
            {
                cleanup_error(&mut failure, &mut pressure, error);
            }
        }
        match self.cadet.close() {
            Ok(Some(report)) => {
                if let Err(error) = self.lost(report, cadet::LossCause::Requested, &mut observe) {
                    cleanup_error(&mut failure, &mut pressure, error);
                }
            }
            Ok(None) => {}
            Err(error) => cleanup_error(&mut failure, &mut pressure, error.into()),
        }
        if let Some(pending) = &mut self.pending {
            pending
                .completion
                .get_or_insert(Completion::Lost(Fault::Closed));
        }
        if let Err(error) = self.settle_pending(&mut observe) {
            cleanup_error(&mut failure, &mut pressure, error);
        }
        // Free original unadmitted payloads before requesting bounded shutdown
        // effects, so obsolete output cannot consume all close capacity.
        let queued = self.core.pending_effects();
        for _ in 0..queued {
            let Some(effect) = self.core.effect() else {
                break;
            };
            let id = effect.id;
            if let Err(error) = self.reject(id, Fault::Closed, &mut observe) {
                cleanup_error(&mut failure, &mut pressure, error);
                break;
            }
        }
        while let Some(send) = self.sends.front() {
            let id = send.id;
            match self.terminal(id, Completion::Unsent(Fault::Closed), true, &mut observe) {
                Ok(()) => {
                    let _removed = self.sends.pop_front();
                }
                Err(error) => {
                    cleanup_error(&mut failure, &mut pressure, error);
                    break;
                }
            }
        }
        for close in &mut self.closing {
            close.outcome.get_or_insert(Completion::Lost(Fault::Closed));
        }
        for index in 0..self.channels.len() {
            if self.channels[index].is_some()
                && let Err(error) = self.finish_channel(index, &mut observe)
            {
                cleanup_error(&mut failure, &mut pressure, error);
            }
        }
        if let Err(error) = self.settle_all_closing(&mut observe) {
            cleanup_error(&mut failure, &mut pressure, error);
        }
        for index in 0..self.ports.len() {
            let id = self.ports[index].as_ref().and_then(|p| p.close);
            if let Some(id) = id
                && let Err(error) =
                    self.terminal(id, Completion::Unsent(Fault::Closed), true, &mut observe)
            {
                cleanup_error(&mut failure, &mut pressure, error);
                continue;
            }
            self.ports[index] = None;
        }
        if let Err(error) = self.core.shutdown() {
            cleanup_error(&mut failure, &mut pressure, error.into());
        }
        let queued = self.core.pending_effects();
        for _ in 0..queued {
            let Some(effect) = self.core.effect() else {
                break;
            };
            let id = effect.id;
            if let Err(error) = self.reject(id, Fault::Closed, &mut observe) {
                cleanup_error(&mut failure, &mut pressure, error);
                break;
            }
        }
        // Previously full admitted sinks now released their real original work.
        // Retry only the closing algorithm, without sampling a clock or new IO.
        if !self.core.is_quiescent() {
            if let Err(error) = self.core.shutdown() {
                cleanup_error(&mut failure, &mut pressure, error.into());
            }
            let queued = self.core.pending_effects();
            for _ in 0..queued {
                let Some(effect) = self.core.effect() else {
                    break;
                };
                let id = effect.id;
                if let Err(error) = self.reject(id, Fault::Closed, &mut observe) {
                    cleanup_error(&mut failure, &mut pressure, error);
                    break;
                }
            }
        }
        for index in 0..self.apps.len() {
            if self.apps[index].is_some()
                && let Err(error) = self.stop_app(index, CloseCause::Shutdown, &mut observe)
            {
                cleanup_error(&mut failure, &mut pressure, error);
            }
        }
        let drained = self.apps.iter().all(Option::is_none)
            && self.channels.iter().all(Option::is_none)
            && self.ports.iter().all(Option::is_none)
            && self.sends.is_empty()
            && self.closing.is_empty()
            && self.pending.is_none()
            && self.adopted.is_none()
            && self.cadet.epoch().is_none()
            && self.core.is_quiescent();
        self.stopped = drained;
        if !drained && failure.is_none() {
            failure = pressure.or(Some(Fault::NotReady.into()));
        }
        Shutdown {
            report: self.report,
            failure,
            drained,
        }
    }
}

// Pure backpressure can be satisfied by the original physical retirements in
// this same call. Irrecoverable/native causes remain independent even if the
// eventual resource postcondition succeeds.
fn cleanup_error(failure: &mut Option<Error>, pressure: &mut Option<Error>, error: Error) {
    if matches!(
        &error,
        Error::Protocol(Fault::Capacity | Fault::WouldBlock | Fault::NotReady)
    ) {
        if pressure.is_none() {
            *pressure = Some(error);
        }
    } else if failure.is_none() {
        *failure = Some(error);
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, unix))]
#[path = "server/retirement_tests.rs"]
mod retirement_tests;
