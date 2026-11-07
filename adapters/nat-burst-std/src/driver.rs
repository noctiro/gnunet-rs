//! Foreground socket owner. Native hard/expiry guards precede logical clock waits.
use crate::{
    types::*,
    wire::{BurstMessage, MESSAGE_BYTES},
};
use gnunet_service_runtime::clock::{ClockSample, ClockSubscription, RuntimeClock};
use gnunet_types::Error as Fault;
use std::{
    future::{Future, poll_fn},
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::ReadBuf,
    net::UdpSocket,
    time::{Instant, Sleep},
};
use zeroize::{Zeroize, Zeroizing};

// One byte above the largest ordinary u16-length UDP datagram. A jumbo input
// filling this buffer is explicitly classified as possibly truncated, never as
// a 36-byte burst and never as a complete ordinary application datagram.
const RECEIVE_BYTES: usize = 65_536;

struct Slot<'id> {
    id: SocketId<'id>,
    socket: UdpSocket,
    local: u16,
    remote: SocketAddr,
    expires: Instant,
    pending: bool,
}

// Common admitted fields, independent of the public synchronization stage.
struct BoundParameters {
    remote: SocketAddr,
    public_peer: [u8; 32],
    local_order: crate::wire::Endian,
    remote_order: crate::wire::Endian,
    until: gnunet_types::AbsoluteTime,
}
struct Schedule {
    delay: u64,
    hard: Option<Instant>,
}

/// One original attempt with a fixed clock, remote address, ABI, and hard bound.
/// Poll it inside the caller's Tokio runtime with I/O and time enabled. Dropping a
/// `drive` future retains every pending whole datagram and original socket token;
/// dropping this owner retires its unselected sockets without waiting for clocks.
pub struct Burst<'id> {
    attempt: Attempt<'id>,
    parameters: BoundParameters,
    limits: Limits,
    clock: Arc<dyn RuntimeClock>,
    subscription: Option<Box<dyn ClockSubscription>>,
    revision: u64,
    start_at: u64,
    hard: Instant,
    alarm: Option<Pin<Box<Sleep>>>,
    default: Option<Arc<UdpSocket>>,
    local: SocketAddr,
    started: bool,
    default_written: bool,
    default_expires: Option<Instant>,
    next_port: u32,
    next_scan: Option<Instant>,
    slots: Vec<Slot<'id>>,
    cursor: usize,
    buffer: Zeroizing<Vec<u8>>,
    selection: Option<Selection<'id>>,
    end: Option<End<'id>>,
    report: Report,
}

impl<'id> Burst<'id> {
    /// Reserve one finite attempt. The supplied unconnected socket must already
    /// be bound to a nonzero local port. Its original owner keeps another Arc and
    /// remains the sole reader/dispatcher. No packets or new sockets are created
    /// until `poll_step`/`drive`. Readiness mismatch returns `NotReady`.
    pub fn new(
        instance: &'id Instance,
        default: Arc<UdpSocket>,
        parameters: Parameters,
        limits: Limits,
        clock: Arc<dyn RuntimeClock>,
    ) -> Result<Self, Error> {
        let delay = parameters
            .remote_sync
            .delay(parameters.local_rtt_micros)
            .ok_or(Fault::NotReady)?;
        Self::admit(
            instance,
            default,
            BoundParameters {
                remote: parameters.remote,
                public_peer: parameters.public_peer,
                local_order: parameters.local_order,
                remote_order: parameters.remote_order,
                until: parameters.until,
            },
            Schedule { delay, hard: None },
            limits,
            clock,
        )
    }

    /// Start the actual public scan after the original TRANSPORT 1253 already
    /// completed synchronization and delay. The supplied original hard is an
    /// upper bound, including a late clock sample and all preparation below.
    pub fn start_ready(
        instance: &'id Instance,
        default: Arc<UdpSocket>,
        parameters: ReadyParameters,
        limits: Limits,
        clock: Arc<dyn RuntimeClock>,
    ) -> Result<Self, Error> {
        let hard = Instant::from_std(parameters.hard);
        if Instant::now() >= hard {
            return Err(Fault::Deadline.into());
        }
        Self::admit(
            instance,
            default,
            BoundParameters {
                remote: parameters.remote,
                public_peer: parameters.public_peer,
                local_order: parameters.local_order,
                remote_order: parameters.remote_order,
                until: parameters.until,
            },
            Schedule {
                delay: 0,
                hard: Some(hard),
            },
            limits,
            clock,
        )
    }

    fn admit(
        instance: &'id Instance,
        default: Arc<UdpSocket>,
        parameters: BoundParameters,
        schedule: Schedule,
        limits: Limits,
        clock: Arc<dyn RuntimeClock>,
    ) -> Result<Self, Error> {
        let limits = limits.validate()?;
        let delay = schedule.delay;
        // Subscription/sampling and native metadata work cannot extend the
        // original hard lifetime reserved by this admission.
        let native_anchor = Instant::now();
        let subscription = clock.subscribe().map_err(Error::Clock)?;
        let sample = clock.sample().map_err(Error::Clock)?;
        if parameters.until.as_micros() == u64::MAX || parameters.until <= sample.now {
            return Err(Fault::Deadline.into());
        }
        let remaining = parameters.until.as_micros() - sample.now.as_micros();
        if delay >= remaining {
            return Err(Fault::Deadline.into());
        }
        let start_at = sample
            .now
            .as_micros()
            .checked_add(delay)
            .ok_or(Fault::Overflow)?;
        let derived = native_anchor
            .checked_add(std::time::Duration::from_micros(remaining))
            .ok_or(Fault::Overflow)?;
        let hard = schedule
            .hard
            .map_or(derived, |original| original.min(derived));
        if Instant::now() >= hard {
            return Err(Fault::Deadline.into());
        }
        let local = default.local_addr().map_err(|error| Error::Io {
            action: IoAction::LocalAddress,
            port: None,
            error,
        })?;
        if local.port() == 0
            || parameters.remote.port() == 0
            || local.is_ipv4() != parameters.remote.is_ipv4()
        {
            return Err(Fault::InvalidInput.into());
        }
        match default.peer_addr() {
            Ok(_) => return Err(Fault::InvalidInput.into()),
            Err(error) if error.kind() == io::ErrorKind::NotConnected => {}
            Err(error) => {
                return Err(Error::Io {
                    action: IoAction::PeerAddress,
                    port: Some(local.port()),
                    error,
                });
            }
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(limits.sockets)
            .map_err(|_| Fault::Capacity)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(RECEIVE_BYTES)
            .map_err(|_| Fault::Capacity)?;
        bytes.resize(RECEIVE_BYTES, 0);
        Ok(Self {
            attempt: instance.allocate()?,
            parameters,
            limits,
            clock,
            subscription: Some(subscription),
            revision: sample.revision,
            start_at,
            hard,
            alarm: None,
            default: Some(default),
            local,
            started: false,
            default_written: false,
            default_expires: None,
            next_port: 1024,
            next_scan: None,
            slots,
            cursor: 0,
            buffer: Zeroizing::new(bytes),
            selection: None,
            end: None,
            report: Report::default(),
        })
    }

    /// Original attempt, including allocation rather than just a reused slot.
    pub fn attempt(&self) -> Attempt<'id> {
        self.attempt
    }
    /// Original token for the caller-owned dispatcher socket.
    pub fn default_socket(&self) -> SocketId<'id> {
        SocketId {
            attempt: self.attempt,
            serial: 0,
        }
    }
    /// Immutable native hard bound, which clock rollback and input cannot renew.
    pub fn hard_deadline(&self) -> Instant {
        self.hard
    }
    /// Number of currently owned scan descriptors (excluding retained selection).
    pub fn scan_sockets(&self) -> usize {
        self.slots.len()
    }
    /// Borrow an original currently live scan socket for application handling
    /// after a Datagram callback. Its original expiry remains authoritative;
    /// this does not extend its lease or transfer descriptor ownership.
    pub fn scan_socket(&self, original: SocketId<'id>) -> Result<&UdpSocket, Error> {
        if original.attempt != self.attempt || original.is_default() {
            return Err(Fault::Stale.into());
        }
        self.slots
            .iter()
            .find(|slot| slot.id == original && Instant::now() < slot.expires)
            .map(|slot| &slot.socket)
            .ok_or(Fault::Stale.into())
    }
    /// Actual local progress only.
    pub fn report(&self) -> Report {
        self.report
    }
    /// Retained terminal reason, including the original clock or native error.
    pub fn end(&self) -> Option<&End<'id>> {
        self.end.as_ref()
    }
    /// Borrow a selected socket. Selection never establishes authentication.
    pub fn selection(&self) -> Option<&Selection<'id>> {
        self.selection.as_ref()
    }
    /// Transfer the selected socket to the caller. It is not closed by subsequent
    /// cancellation or drop of this attempt after this ownership transfer.
    pub fn take_selection(&mut self) -> Option<Selection<'id>> {
        self.selection.take()
    }

    /// Immediately retire every unselected scan descriptor and detach the default
    /// clone, even if clock sampling has failed. A retained selection is preserved.
    /// Socket Drop exposes no close errno, so `End` is not a kernel close ACK.
    pub fn cancel(&mut self) {
        self.finish(Cause::Cancelled);
    }

    /// Clock-free original descriptor expiry and native alarm registration.
    /// This performs no socket read/send or canonical clock operation.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> bool {
        let changed = self.expire_native();
        if self.end.is_none() {
            self.poll_alarm(cx, None);
        }
        changed
    }

    /// Consume this owner and move its actual terminal cause/counts. A live
    /// owner is explicitly cancelled first. Any untransferred selection drops;
    /// transfer it with take_selection before consuming when it must survive.
    pub fn into_end(mut self) -> Option<End<'id>> {
        self.cancel();
        self.end.take()
    }

    fn finish(&mut self, cause: Cause) {
        if self.end.is_some() {
            return;
        }
        self.slots.clear();
        self.default = None;
        self.subscription = None;
        self.alarm = None;
        self.next_scan = None;
        self.default_expires = None;
        self.buffer.zeroize();
        self.end = Some(End {
            attempt: self.attempt,
            cause,
            report: self.report,
        });
    }

    /// Inspect a datagram already read by the caller's original default-socket
    /// dispatcher. The complete input remains caller-owned; unrelated input is
    /// never swallowed. Stale tokens fail before touching the current owner.
    /// An accepted observation immediately retires all other owned scan sockets.
    pub fn on_datagram(
        &mut self,
        original: SocketId<'id>,
        remote: SocketAddr,
        bytes: &[u8],
    ) -> Result<Disposition, Error> {
        if original != self.default_socket() {
            return Err(Fault::Stale.into());
        }
        self.expire_native();
        if self.end.is_some() {
            return Ok(Disposition::Unrelated);
        }
        let sample = match self.clock.sample() {
            Ok(sample) => sample,
            Err(error) => {
                self.finish(Cause::Clock(error));
                return Err(Error::Clock(error));
            }
        };
        if sample.now >= self.parameters.until {
            self.finish(Cause::Deadline(DeadlineKind::Logical));
            return Ok(Disposition::Unrelated);
        }
        self.expire_native();
        if self.end.is_some() {
            return Ok(Disposition::Unrelated);
        }
        if !self.default_written || !self.matches(remote, bytes) {
            return Ok(Disposition::Unrelated);
        }
        let message = BurstMessage::decode(bytes, self.parameters.remote_order)?;
        let Some(socket) = self.default.take() else {
            return Err(Fault::Closed.into());
        };
        self.selection = Some(Selection {
            id: original,
            socket: SelectedSocket::Default(socket),
            remote,
            message,
        });
        self.finish(Cause::Selected);
        Ok(Disposition::Selected)
    }

    fn matches(&self, remote: SocketAddr, bytes: &[u8]) -> bool {
        let scope_matches = match (remote, self.parameters.remote) {
            (SocketAddr::V6(actual), SocketAddr::V6(expected)) => {
                expected.scope_id() == 0 || expected.scope_id() == actual.scope_id()
            }
            _ => true,
        };
        remote.ip() == self.parameters.remote.ip() && scope_matches && bytes.len() == MESSAGE_BYTES
    }

    fn expire_native(&mut self) -> bool {
        if self.end.is_some() {
            return false;
        }
        let now = Instant::now();
        if now >= self.hard {
            self.finish(Cause::Deadline(DeadlineKind::Hard));
            return true;
        }
        if self
            .default_expires
            .is_some_and(|until| !self.default_written && now >= until)
        {
            self.finish(Cause::Deadline(DeadlineKind::InitialSend));
            return true;
        }
        let before = self.slots.len();
        self.slots.retain(|slot| now < slot.expires);
        let retired = before - self.slots.len();
        self.report.expired += u32::try_from(retired).unwrap_or(u32::MAX);
        if self.cursor >= self.slots.len() {
            self.cursor = 0;
        }
        retired != 0
    }

    fn target(&self, logical: Option<ClockSample>) -> Instant {
        let mut target = self.hard;
        for slot in &self.slots {
            target = target.min(slot.expires);
        }
        if !self.default_written {
            if let Some(until) = self.default_expires {
                target = target.min(until);
            }
        } else if self.slots.len() < self.limits.sockets
            && let Some(next) = self.next_scan
        {
            target = target.min(next);
        }
        if let Some(sample) = logical {
            let logical_target = if self.started {
                self.parameters.until.as_micros()
            } else {
                self.start_at
            };
            let delay = logical_target.saturating_sub(sample.now.as_micros());
            if let Some(until) = Instant::now().checked_add(std::time::Duration::from_micros(delay))
            {
                target = target.min(until);
            }
        }
        target
    }

    fn poll_alarm(&mut self, cx: &mut Context<'_>, logical: Option<ClockSample>) {
        let target = self.target(logical);
        if let Some(alarm) = &mut self.alarm {
            alarm.as_mut().reset(target);
        } else {
            self.alarm = Some(Box::pin(tokio::time::sleep_until(target)));
        }
        if let Some(alarm) = &mut self.alarm
            && alarm.as_mut().poll(cx).is_ready()
        {
            cx.waker().wake_by_ref();
        }
    }

    fn poll_clock(&mut self, cx: &mut Context<'_>) -> Poll<Result<ClockSample, Fault>> {
        let Some(subscription) = &mut self.subscription else {
            return Poll::Ready(Err(Fault::Closed));
        };
        match subscription.poll_changed(cx, self.revision) {
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(sample)) => self.revision = sample.revision,
            Poll::Pending => {}
        }
        let sample = match self.clock.sample() {
            Ok(sample) => sample,
            Err(error) => return Poll::Ready(Err(error)),
        };
        self.revision = sample.revision;
        match subscription.poll_changed(cx, sample.revision) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Pending => Poll::Ready(Ok(sample)),
        }
    }

    fn status(&self) -> Step {
        if self.selection.is_some() {
            Step::Selected
        } else {
            Step::Stopped
        }
    }

    fn packet(&self, port: u16) -> [u8; MESSAGE_BYTES] {
        BurstMessage {
            peer: self.parameters.public_peer,
            local_port: u32::from(port),
        }
        .to_bytes(self.parameters.local_order)
    }

    fn sent(&mut self, result: io::Result<usize>, port: u16) -> bool {
        match result {
            Ok(MESSAGE_BYTES) => {
                self.report.datagrams_written += 1;
                true
            }
            Ok(0) => {
                self.finish(Cause::Io {
                    action: IoAction::Send,
                    port,
                    error: io::Error::new(io::ErrorKind::WriteZero, "zero UDP datagram write"),
                });
                false
            }
            Ok(written) => {
                self.finish(Cause::Partial { port, written });
                false
            }
            Err(error) => {
                self.finish(Cause::Io {
                    action: IoAction::Send,
                    port,
                    error,
                });
                false
            }
        }
    }

    fn later(&mut self, duration: std::time::Duration) -> Option<Instant> {
        match Instant::now().checked_add(duration) {
            Some(until) => Some(until.min(self.hard)),
            None => {
                self.finish(Cause::Overflow);
                None
            }
        }
    }

    fn open_next(&mut self, observe: &mut impl FnMut(Event<'_, 'id>)) {
        if Instant::now() >= self.hard {
            self.finish(Cause::Deadline(DeadlineKind::Hard));
            return;
        }
        if self.next_port == u32::from(self.local.port()) {
            self.next_port += 1;
        }
        if self.next_port > u32::from(u16::MAX) {
            self.next_scan = None;
            return;
        }
        let port = self.next_port as u16;
        self.next_port += 1;
        self.next_scan = self.later(self.limits.send_interval);
        if self.end.is_some() {
            return;
        }
        let mut local = self.local;
        local.set_port(port);
        // Anchor once before creating/exposing the descriptor. Attaching it to
        // the reactor or a later pending send cannot extend this original bound.
        let Some(expires) = self.later(self.limits.socket_lifetime) else {
            return;
        };
        self.report.ports_attempted += 1;
        let std_socket = match std::net::UdpSocket::bind(local) {
            Ok(socket) => socket,
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                observe(Event::Occupied {
                    port,
                    error: &error,
                });
                return;
            }
            Err(error) => {
                self.finish(Cause::Io {
                    action: IoAction::Bind,
                    port,
                    error,
                });
                return;
            }
        };
        if Instant::now() >= expires {
            drop(std_socket);
            if Instant::now() >= self.hard {
                self.finish(Cause::Deadline(DeadlineKind::Hard));
            }
            return;
        }
        if let Err(error) = std_socket.set_nonblocking(true) {
            // Retire this newly created handle before recording the original error.
            drop(std_socket);
            self.finish(Cause::Io {
                action: IoAction::Nonblocking,
                port,
                error,
            });
            return;
        }
        let socket = match UdpSocket::from_std(std_socket) {
            Ok(socket) => socket,
            Err(error) => {
                self.finish(Cause::Io {
                    action: IoAction::Reactor,
                    port,
                    error,
                });
                return;
            }
        };
        if Instant::now() >= expires {
            drop(socket);
            if Instant::now() >= self.hard {
                self.finish(Cause::Deadline(DeadlineKind::Hard));
            }
            return;
        }
        let mut remote = self.parameters.remote;
        remote.set_port(port);
        self.slots.push(Slot {
            id: SocketId {
                attempt: self.attempt,
                serial: u32::from(port),
            },
            socket,
            local: port,
            remote,
            expires,
            pending: true,
        });
        self.report.sockets_opened += 1;
    }

    /// Poll bounded foreground work. Non-burst scan input is synchronously passed
    /// unchanged to `observe`; callers choose whether to retain/copy it. No task or
    /// thread is spawned. Native hard/expiry alarms are registered before a clock
    /// revision race can suspend this owner. Returning Pending has real socket,
    /// clock-subscription, or finite timer wake sources.
    pub fn poll_step(
        &mut self,
        cx: &mut Context<'_>,
        mut observe: impl FnMut(Event<'_, 'id>),
    ) -> Poll<Step> {
        let mut activity = self.expire_native();
        if self.end.is_some() {
            return Poll::Ready(self.status());
        }
        self.poll_alarm(cx, None);
        let sample = match self.poll_clock(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => {
                self.finish(Cause::Clock(error));
                return Poll::Ready(self.status());
            }
            Poll::Ready(Ok(sample)) => sample,
        };
        if sample.now >= self.parameters.until {
            self.finish(Cause::Deadline(DeadlineKind::Logical));
            return Poll::Ready(self.status());
        }
        if !self.started && sample.now.as_micros() >= self.start_at {
            self.started = true;
            self.default_expires = self.later(self.limits.socket_lifetime);
            if self.end.is_some() {
                return Poll::Ready(self.status());
            }
        }
        let mut budget = self.limits.io_budget;
        if self.started && !self.default_written {
            if self.expire_native() && self.end.is_some() {
                return Poll::Ready(self.status());
            }
            let packet = self.packet(self.local.port());
            let result = match &self.default {
                Some(socket) => socket.poll_send_to(cx, &packet, self.parameters.remote),
                None => {
                    self.finish(Cause::Cancelled);
                    return Poll::Ready(self.status());
                }
            };
            if let Poll::Ready(result) = result {
                if !self.sent(result, self.local.port()) {
                    return Poll::Ready(self.status());
                }
                self.default_written = true;
                self.default_expires = None;
                self.next_scan = self.later(self.limits.send_interval);
                observe(Event::Written {
                    id: self.default_socket(),
                    remote: self.parameters.remote,
                });
                activity = true;
                budget -= 1;
            }
        }
        if budget != 0
            && self.default_written
            && self.slots.len() < self.limits.sockets
            && self.next_scan.is_some_and(|next| Instant::now() >= next)
        {
            self.open_next(&mut observe);
            activity = true;
            budget -= 1;
        }
        if self.end.is_some() {
            return Poll::Ready(self.status());
        }
        // At most one recvfrom per live socket per poll, rotating the starting
        // position so heavy input cannot starve later descriptors or new probes.
        let count = self.slots.len();
        let mut visited = 0;
        while budget != 0 && visited < count && !self.slots.is_empty() {
            if Instant::now() >= self.hard {
                self.finish(Cause::Deadline(DeadlineKind::Hard));
                return Poll::Ready(self.status());
            }
            let index = self.cursor % self.slots.len();
            self.cursor = (index + 1) % self.slots.len();
            visited += 1;
            if Instant::now() >= self.slots[index].expires {
                drop(self.slots.swap_remove(index));
                self.report.expired += 1;
                activity = true;
                continue;
            }
            if budget != 0 && self.slots[index].pending {
                let port = self.slots[index].local;
                let packet = self.packet(port);
                let remote = self.slots[index].remote;
                if let Poll::Ready(result) =
                    self.slots[index].socket.poll_send_to(cx, &packet, remote)
                {
                    budget -= 1;
                    activity = true;
                    if !self.sent(result, port) {
                        return Poll::Ready(self.status());
                    }
                    self.slots[index].pending = false;
                    observe(Event::Written {
                        id: self.slots[index].id,
                        remote,
                    });
                }
            }
            if budget == 0 {
                break;
            }
            if Instant::now() >= self.hard {
                self.finish(Cause::Deadline(DeadlineKind::Hard));
                return Poll::Ready(self.status());
            }
            if Instant::now() >= self.slots[index].expires {
                continue;
            }
            let received = {
                let mut read = ReadBuf::new(&mut self.buffer);
                match self.slots[index].socket.poll_recv_from(cx, &mut read) {
                    Poll::Pending => None,
                    Poll::Ready(Err(error)) => Some(Err(error)),
                    Poll::Ready(Ok(remote)) => Some(Ok((remote, read.filled().len()))),
                }
            };
            if let Some(result) = received {
                budget -= 1;
                activity = true;
                let (remote, length) = match result {
                    Ok(value) => value,
                    Err(error) => {
                        let port = self.slots[index].local;
                        self.finish(Cause::Io {
                            action: IoAction::Receive,
                            port,
                            error,
                        });
                        return Poll::Ready(self.status());
                    }
                };
                // A completed recvfrom cannot revive a socket whose original
                // bound elapsed while the syscall was being polled.
                let observed_at = Instant::now();
                if observed_at >= self.hard {
                    self.finish(Cause::Deadline(DeadlineKind::Hard));
                    return Poll::Ready(self.status());
                }
                if observed_at >= self.slots[index].expires {
                    self.buffer[..length].zeroize();
                    drop(self.slots.swap_remove(index));
                    self.report.expired += 1;
                    continue;
                }
                if self.matches(remote, &self.buffer[..length]) {
                    let message = match BurstMessage::decode(
                        &self.buffer[..length],
                        self.parameters.remote_order,
                    ) {
                        Ok(message) => message,
                        Err(_) => {
                            self.buffer[..length].zeroize();
                            continue;
                        }
                    };
                    let slot = self.slots.swap_remove(index);
                    self.selection = Some(Selection {
                        id: slot.id,
                        socket: SelectedSocket::Scan(slot.socket),
                        remote,
                        message,
                    });
                    self.finish(Cause::Selected);
                    return Poll::Ready(self.status());
                }
                observe(Event::Datagram {
                    id: self.slots[index].id,
                    remote,
                    bytes: &self.buffer[..length],
                    at_capacity: length == RECEIVE_BYTES,
                });
                self.buffer[..length].zeroize();
            }
        }
        if self.end.is_some() {
            return Poll::Ready(self.status());
        }
        if self.default_written && self.next_port > u32::from(u16::MAX) && self.slots.is_empty() {
            self.finish(Cause::Exhausted);
            return Poll::Ready(self.status());
        }
        self.poll_alarm(cx, Some(sample));
        if activity {
            Poll::Ready(Step::Progress)
        } else {
            Poll::Pending
        }
    }

    /// Cancellation-safe borrowed future for exactly one foreground progress step.
    /// The callback is immediate; no borrowed application datagram survives it.
    pub async fn drive(&mut self, mut observe: impl FnMut(Event<'_, 'id>)) -> Step {
        poll_fn(|cx| self.poll_step(cx, &mut observe)).await
    }
}

impl Drop for Burst<'_> {
    fn drop(&mut self) {
        self.finish(Cause::Cancelled);
    }
}
