use crate::{
    Epoch, Error, Instance, Kind, Limits, Loss, LossCause, Operation, Report, Submission, ipc,
    scope::Scope,
};
use gnunet_client_host::{EndpointSource, channel::Channel};
use gnunet_service_runtime::{
    clock::{Deadline, RuntimeClock},
    framing::OwnedFrame,
};
use gnunet_types::Error as Fault;
use std::{collections::VecDeque, pin::Pin, sync::Arc, time::Duration};
use tokio::time::{Instant, Sleep};
use zeroize::Zeroizing;
mod io;
#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Connecting,
    Attached,
    Creating,
    Active,
    Destroying,
    Disconnected,
    Closed,
}
#[derive(Clone, Copy, Eq, PartialEq)]
struct Origin<'a> {
    epoch: Epoch<'a>,
    operation: Operation<'a>,
}
struct PreparedFrame {
    kind: Kind,
    frame: OwnedFrame,
    len: usize,
    charge: usize,
}
struct Pending<'a> {
    operation: Operation<'a>,
    kind: Kind,
    frame: Option<OwnedFrame>,
    len: usize,
    charge: usize,
    sent: usize,
    queued: bool,
    expires: u64,
    hard: Instant,
}
impl Pending<'_> {
    fn submission(&self) -> Submission {
        if self.sent == 0 {
            Submission::Unsent
        } else {
            Submission::Partial {
                bytes: self.sent,
                total: self.len,
            }
        }
    }
}
/// One original caller-driven official MESSENGER native MQ. The owner keeps
/// partial RX/TX through dropped wait futures and never replays across reconnect.
/// This IPC port intentionally delegates rooms/crypto/message history to their
/// domain state; notifications cannot complete an arbitrary local request.
pub struct Client<'a> {
    scope: Scope<'a>,
    channel: Channel<Origin<'a>>,
    clock: Arc<dyn RuntimeClock>,
    limits: Limits,
    phase: Phase,
    epoch: Option<Epoch<'a>>,
    queue: VecDeque<Pending<'a>>,
    retired: Vec<Report<'a>>,
    bytes: usize,
    pending_loss: Option<Loss<'a>>,
    input_hard: Option<Instant>,
    initial_hard: Instant,
    initial_expires: u64,
    alarm: Option<Pin<Box<Deadline>>>,
    alarm_at: Option<u64>,
    native_alarm: Option<Pin<Box<Sleep>>>,
    native_at: Option<Instant>,
    read_first: bool,
    yield_due: bool,
}
fn bounds(clock: &dyn RuntimeClock, duration: Duration) -> Result<(u64, Instant), Fault> {
    if duration.is_zero() {
        return Err(Fault::InvalidInput);
    }
    let micros = u64::try_from(duration.as_micros()).map_err(|_| Fault::Overflow)?;
    if micros == 0 {
        return Err(Fault::InvalidInput);
    }
    let hard = Instant::now()
        .checked_add(duration)
        .ok_or(Fault::Overflow)?;
    let expires = clock
        .sample()?
        .now
        .as_micros()
        .checked_add(micros)
        .ok_or(Fault::Overflow)?;
    Ok((expires, hard))
}
impl<'a> Client<'a> {
    /// Reserve bounded metadata and the selected shared source clock. Does not
    /// open a socket, start a Resolver or create a task. Initial lifetime starts
    /// here and is never renewed by repeated progress waits or revision races.
    pub fn new(
        instance: &'a Instance,
        source: EndpointSource,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let clock = source.clock();
        let (initial_expires, initial_hard) = bounds(clock.as_ref(), limits.initial_lifetime)?;
        let mut queue = VecDeque::new();
        queue
            .try_reserve_exact(limits.operations)
            .map_err(|_| Fault::Capacity)?;
        let mut retired = Vec::new();
        retired
            .try_reserve_exact(limits.operations)
            .map_err(|_| Fault::Capacity)?;
        Ok(Self {
            scope: Scope::new(instance)?,
            channel: Channel::new(source, limits.framing())?,
            clock,
            limits,
            phase: Phase::Connecting,
            epoch: None,
            queue,
            retired,
            bytes: 0,
            pending_loss: None,
            input_hard: None,
            initial_hard,
            initial_expires,
            alarm: None,
            alarm_at: None,
            native_alarm: None,
            native_at: None,
            read_first: false,
            yield_due: false,
        })
    }
    /// Original actually attached source; no endpoint selection grants it early.
    pub const fn epoch(&self) -> Option<Epoch<'a>> {
        self.epoch
    }
    /// Selected canonical source, without creating a timer/listener/socket.
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    /// Frames whose whole local write event has not yet been delivered.
    pub fn pending(&self) -> usize {
        self.queue.len()
    }
    /// Current retained allocated outbound payload capacity, excluding RX.
    pub const fn retained_bytes(&self) -> usize {
        self.bytes
    }
    /// Exact original local frame exposure. Completed frames have already
    /// emitted Written; foreign, completed and retired tokens cannot alias.
    pub fn exposure(&self, operation: Operation<'a>) -> Result<Submission, Error> {
        Ok(self
            .queue
            .get(self.index(operation)?)
            .ok_or(Fault::StaleGeneration)?
            .submission())
    }
    fn index(&self, operation: Operation<'a>) -> Result<usize, Fault> {
        if !self.scope.same(operation.scope) {
            return Err(Fault::StaleGeneration);
        }
        self.queue
            .iter()
            .position(|p| p.operation == operation)
            .ok_or(Fault::StaleGeneration)
    }
    /// Submit an immutable original active IPC frame on an already attached MQ.
    /// First submit CREATE and observe its Written event before other requests.
    /// A SEND tail remains an opaque serialized message: the domain must check
    /// its signature/body and room authorization separately.
    pub fn submit(
        &mut self,
        request: ipc::Request<'_>,
        timeout: Duration,
    ) -> Result<Operation<'a>, Error> {
        let prepared = self.prepare_submission(request)?;
        if timeout.is_zero() || timeout.as_micros() == 0 {
            return Err(Fault::InvalidInput.into());
        }
        let micros = u64::try_from(timeout.as_micros()).map_err(|_| Fault::Overflow)?;
        let hard = Instant::now().checked_add(timeout).ok_or(Fault::Overflow)?;
        let now = self.admission_clock()?;
        let expires = now.checked_add(micros).ok_or(Fault::Overflow)?;
        self.admit_submission(prepared, expires, hard, now)
    }
    /// Submit using the caller's original absolute source-clock target and
    /// native hard bound. Both must belong to this client's exact shared clock
    /// domain; neither is recomputed, renewed or extended by preparation/waits.
    /// Expired input is refused before native I/O or operation admission. Real
    /// clock failure physically retires the original MQ and preserves its loss.
    pub fn submit_bounded(
        &mut self,
        request: ipc::Request<'_>,
        expires: u64,
        hard: Instant,
    ) -> Result<Operation<'a>, Error> {
        let prepared = self.prepare_submission(request)?;
        if expires == u64::MAX {
            return Err(Fault::InvalidInput.into());
        }
        if Instant::now() >= hard {
            return Err(Fault::Timeout.into());
        }
        let now = self.admission_clock()?;
        self.admit_submission(prepared, expires, hard, now)
    }
    fn prepare_submission(&self, request: ipc::Request<'_>) -> Result<PreparedFrame, Error> {
        let kind = Kind::from(request);
        let allowed = match self.phase {
            Phase::Attached => kind == Kind::Create,
            Phase::Active => kind != Kind::Create,
            _ => false,
        };
        if !allowed || self.pending_loss.is_some() {
            return Err(Fault::NotReady.into());
        }
        self.epoch.ok_or(Fault::NotReady)?;
        if self.queue.len() >= self.limits.operations {
            return Err(Fault::WouldBlock.into());
        }
        let n = request.encoded_len()?;
        if n > self.limits.frame_bytes || n > self.limits.source_bytes {
            return Err(Fault::TooLarge.into());
        }
        let free = self
            .limits
            .source_bytes
            .checked_sub(self.bytes)
            .ok_or(Fault::Conflict)?;
        if n > free {
            return Err(Fault::WouldBlock.into());
        }
        let mut buffer = Zeroizing::new(Vec::new());
        buffer.try_reserve_exact(n).map_err(|_| Fault::Capacity)?;
        let charge = buffer.capacity();
        if charge > free {
            return Err(Fault::WouldBlock.into());
        }
        buffer.resize(n, 0);
        request.encode(&mut buffer)?;
        Ok(PreparedFrame {
            kind,
            frame: OwnedFrame::new(core::mem::take(&mut *buffer)),
            len: n,
            charge,
        })
    }
    fn admission_clock(&mut self) -> Result<u64, Error> {
        match self.clock.sample() {
            Ok(sample) => Ok(sample.now.as_micros()),
            Err(error) => {
                let loss = self.lose(LossCause::Failure(error.into()));
                self.pending_loss = Some(loss);
                Err(error.into())
            }
        }
    }
    fn admit_submission(
        &mut self,
        prepared: PreparedFrame,
        expires: u64,
        hard: Instant,
        now: u64,
    ) -> Result<Operation<'a>, Error> {
        // This check follows allocation, encoding and sampling, so work done in
        // any of those stages cannot make an already expired bound admissible.
        if expires == u64::MAX {
            return Err(Fault::InvalidInput.into());
        }
        if now >= expires || Instant::now() >= hard {
            return Err(Fault::Timeout.into());
        }
        self.epoch.ok_or(Fault::NotReady)?;
        let operation = self.scope.operation()?;
        let kind = prepared.kind;
        self.queue.push_back(Pending {
            operation,
            kind,
            frame: Some(prepared.frame),
            len: prepared.len,
            charge: prepared.charge,
            sent: 0,
            queued: false,
            expires,
            hard,
        });
        self.bytes += prepared.charge;
        if kind == Kind::Create {
            self.phase = Phase::Creating;
        }
        if kind == Kind::Destroy {
            self.phase = Phase::Destroying;
        }
        Ok(operation)
    }
    /// Explicit local cancellation stops the entire original physical MQ first.
    /// No operation CANCEL exists on wire. Every other affected frame and prefix
    /// is returned; completed external service work is never called rolled back.
    pub fn cancel(&mut self, operation: Operation<'a>) -> Result<Loss<'a>, Error> {
        self.index(operation)?;
        Ok(self.lose(LossCause::Cancelled(operation)))
    }
    /// Permanently close the physical source before returning original metadata.
    /// If an admission clock failure is pending, preserve that first cause.
    pub fn close(&mut self) -> Loss<'a> {
        let loss = self
            .pending_loss
            .take()
            .unwrap_or_else(|| self.lose(LossCause::Closed));
        self.channel.close();
        self.phase = Phase::Closed;
        loss
    }
    /// Start a fresh source ONLY after actual loss/cancel and its report. No old
    /// CREATE/room/message frame is retained or replayed. A fresh CREATE must be
    /// submitted after the new Attached event. Refused clock/Resolver ports are
    /// recovered explicitly by this call; permanent DESTROY/close cannot restart.
    pub fn reconnect(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Disconnected || self.pending_loss.is_some() {
            return Err(Fault::NotReady.into());
        }
        self.retired
            .try_reserve_exact(self.limits.operations)
            .map_err(|_| Fault::Capacity)?;
        match self.channel.recover_ports() {
            Ok(()) | Err(Error::Protocol(Fault::NotReady)) => {}
            Err(error) => return Err(error),
        }
        let (expires, hard) = bounds(self.clock.as_ref(), self.limits.initial_lifetime)?;
        self.initial_expires = expires;
        self.initial_hard = hard;
        self.phase = Phase::Connecting;
        self.yield_due = false;
        Ok(())
    }
    fn lose(&mut self, cause: LossCause<'a>) -> Loss<'a> {
        // Physical retirement must precede erasure and externally visible loss.
        self.channel.detach();
        let epoch = self.epoch.take();
        for p in self.queue.drain(..) {
            self.retired.push(Report {
                operation: p.operation,
                kind: p.kind,
                submission: p.submission(),
            });
        }
        self.bytes = 0;
        self.input_hard = None;
        self.alarm = None;
        self.alarm_at = None;
        self.native_alarm = None;
        self.native_at = None;
        self.phase = Phase::Disconnected;
        Loss {
            epoch,
            cause,
            reports: core::mem::take(&mut self.retired),
        }
    }
}
impl Drop for Client<'_> {
    fn drop(&mut self) {
        self.channel.close();
        self.queue.clear();
    }
}
