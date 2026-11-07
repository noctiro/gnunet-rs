use crate::{
    Bounds, Call, CallInfo, Cause, Epoch, Error, Kind, Limits, Loss, Operation, Phase, Progress,
    Receipt, Role, budget::Bound, ipc, types::Domain,
};
use gnunet_client_host::{EndpointSource, channel::Channel};
use gnunet_service_runtime::framing::OwnedFrame;
use gnunet_types::Error as Fault;
use std::{
    collections::VecDeque,
    future::poll_fn,
    mem::size_of,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};
use zeroize::Zeroizing;
mod input;
mod output;
mod recovery;

struct Row {
    info: CallInfo,
    control: Option<Kind>,
}
struct Pending {
    receipt: Receipt,
    frame: Option<OwnedFrame>,
    capacity: usize,
    bound: Bound,
    queued: bool,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Register,
    Call,
}
/// One original native Line MQ, entered from a Tokio IO/time runtime. Its
/// initializer and media/control frames are retained without implicit replay.
/// Callers explicitly drive their own Resolver, devices, clock policy/signals.
pub struct Line {
    source: EndpointSource,
    channel: Channel<u64>,
    domain: Domain,
    epoch: Option<Epoch>,
    mode: Mode,
    registration: Option<recovery::Registration>,
    recoverable: bool,
    registration_timeout: bool,
    limits: Limits,
    overall: Bound,
    initial: Option<Bound>,
    input: Option<Bound>,
    input_bytes: usize,
    pending: VecDeque<Pending>,
    queued_bytes: usize,
    initializer: Receipt,
    rows: Vec<Option<Row>>,
    seen: Vec<[u8; 4]>,
    next_call: u64,
    next_operation: u64,
    retired: Vec<Receipt>,
    retired_calls: Vec<CallInfo>,
    read_first: bool,
    closed: bool,
    pending_loss: Option<Loss>,
    audio: Arc<crate::audio::Quota>,
}
impl Line {
    /// Freeze original731. Whole local write produces only Written(Register),
    /// with no invented registration ACK or remote-ready notification.
    pub fn register(
        source: EndpointSource,
        port: &[u8; 64],
        limits: Limits,
        original: Bounds,
    ) -> Result<Self, Error> {
        Self::new(
            source,
            ipc::Message::Register { reserved: 0, port },
            None,
            limits,
            original,
        )
    }
    /// Freeze original734 with the explicitly selected ego key. The private
    /// bytes go solely into zeroizing original transport storage; no key lookup,
    /// GNS search, media/device source or network-peer equality is implied.
    pub fn call(
        source: EndpointSource,
        target: &[u8; 32],
        port: &[u8; 64],
        ego: &gnunet_identity::SecretKey,
        limits: Limits,
        original: Bounds,
    ) -> Result<Self, Error> {
        Self::new(
            source,
            ipc::Message::Call {
                reserved: 0,
                target,
                port,
                private_key: ego.expose_serialized(),
            },
            Some(*target),
            limits,
            original,
        )
    }
    fn new(
        source: EndpointSource,
        message: ipc::Message<'_>,
        target: Option<[u8; 32]>,
        limits: Limits,
        original: Bounds,
    ) -> Result<Self, Error> {
        limits.validate()?;
        original.check(source.clock().as_ref())?;
        let [source] = EndpointSource::snapshot_all([&source])?;
        let source = source.fixed_endpoint()?;
        let domain = Domain(Arc::new(()));
        let operation = Operation {
            domain: domain.clone(),
            serial: 1,
        };
        let call = target.map(|_| Call {
            domain: domain.clone(),
            serial: 1,
        });
        let mode = if target.is_some() {
            Mode::Call
        } else {
            Mode::Register
        };
        let n = message.encoded_len()?;
        if n > limits.frame_bytes {
            return Err(Fault::TooLarge.into());
        }
        let initial = Bound::phase(source.clock().as_ref(), limits.initial_timeout, original)?;
        let write = Bound::phase(source.clock().as_ref(), limits.write_timeout, original)?;
        let registration = match &message {
            ipc::Message::Register { port, .. } => Some(recovery::Registration {
                port: **port,
                initial: initial.targets,
                established: false,
            }),
            _ => None,
        };
        let frame = encode(message, limits.frame_bytes)?;
        let capacity = frame.retained_bytes();
        let channel = Channel::new(source.duplicate()?, limits.framing())?;
        let mut pending = VecDeque::new();
        pending
            .try_reserve_exact(limits.pending)
            .map_err(|_| Fault::Capacity)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(limits.calls)
            .map_err(|_| Fault::Capacity)?;
        rows.resize_with(limits.calls, || None);
        let mut retired = Vec::new();
        retired
            .try_reserve_exact(limits.pending)
            .map_err(|_| Fault::Capacity)?;
        let mut retired_calls = Vec::new();
        retired_calls
            .try_reserve_exact(limits.calls)
            .map_err(|_| Fault::Capacity)?;
        let initializer = Receipt {
            bounds: write.targets,
            operation,
            call: call.clone(),
            kind: if mode == Mode::Call {
                Kind::Call
            } else {
                Kind::Register
            },
            epoch: None,
            total_bytes: n,
            written_bytes: 0,
            complete: false,
        };
        pending.push_back(Pending {
            receipt: initializer.clone(),
            frame: Some(frame),
            capacity,
            bound: write,
            queued: false,
        });
        if let Some(call) = call {
            rows[0] = Some(Row {
                info: CallInfo {
                    call,
                    epoch: None,
                    role: Role::Outgoing,
                    phase: Phase::Calling,
                    cid: None,
                    caller: None,
                    target,
                    suspended_local: false,
                    suspended_remote: false,
                    pickup_written: false,
                    remote_pickup: false,
                    hangup_written: false,
                    hangup_notified: false,
                },
                control: None,
            });
        }
        let mut line = Self {
            source,
            channel,
            domain,
            epoch: None,
            mode,
            registration,
            recoverable: false,
            registration_timeout: false,
            limits,
            overall: Bound::new(original),
            initial: Some(initial),
            input: None,
            input_bytes: 0,
            pending,
            queued_bytes: capacity,
            initializer,
            rows,
            seen: Vec::new(),
            next_call: if target.is_some() { 2 } else { 1 },
            next_operation: 2,
            retired,
            retired_calls,
            read_first: true,
            closed: false,
            pending_loss: None,
            audio: crate::audio::Quota::new(limits.audio_frames, limits.audio_retained_bytes),
        };
        if line.retained_bytes()? > limits.retained_bytes {
            return Err(Fault::Capacity.into());
        }
        line.check()?;
        Ok(line)
    }
    /// Exact original finite whole-Line targets, never refreshed by observations.
    pub const fn bounds(&self) -> Bounds {
        self.overall.targets
    }
    /// Actual original initializer exposure, including partial/whole write.
    pub fn initializer(&self) -> Receipt {
        self.initializer.clone()
    }
    /// Actual attachment identity, retained for diagnosis after retirement.
    pub fn epoch(&self) -> Option<Epoch> {
        self.epoch.clone()
    }
    /// This Line's actual outgoing original owner. Its CID remains None until
    /// observed from this MQ; use close() to cancel before a CID is observed.
    pub fn outgoing(&self) -> Option<Call> {
        (self.mode == Mode::Call)
            .then(|| {
                self.rows
                    .iter()
                    .flatten()
                    .next()
                    .map(|r| r.info.call.clone())
            })
            .flatten()
    }
    /// Snapshot exactly the original call; another Line's equal serial is stale.
    pub fn info(&self, call: &Call) -> Result<CallInfo, Error> {
        Ok(self.row(call)?.info.clone())
    }
    /// Release an ended, write-debt-free original call snapshot. Its wire CID
    /// stays in bounded history, preventing a later Ring from recycling it.
    pub fn release(&mut self, call: &Call) -> Result<CallInfo, Error> {
        let at = self.row_index(call)?;
        if self.rows[at]
            .as_ref()
            .ok_or(Fault::StaleGeneration)?
            .info
            .phase
            != Phase::Ended
            || self
                .pending
                .iter()
                .any(|p| p.receipt.call.as_ref() == Some(call))
        {
            return Err(Fault::NotReady.into());
        }
        Ok(self.rows[at].take().ok_or(Fault::StaleGeneration)?.info)
    }
    /// Whether the original physical MQ has already been stopped. Pending
    /// original loss facts may still be retrieved through poll_progress/close.
    pub const fn is_closed(&self) -> bool {
        self.closed
    }
    /// Borrow an already retained original source loss, including admission-time
    /// clock refusal. close()/poll_progress transfers that same cause once.
    pub fn retirement(&self) -> Option<&Loss> {
        self.pending_loss.as_ref()
    }
    /// Number of still-retained original immutable writes.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }
    /// SDK table/payload/Framed capacities, including original bound storage;
    /// shared CLIENT port objects, allocator headers, OS and caller observations
    /// are separate. This is not an exact process RSS measurement.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        let mut sum = 0usize;
        for n in [
            self.pending.capacity().checked_mul(size_of::<Pending>()),
            self.rows.capacity().checked_mul(size_of::<Option<Row>>()),
            self.seen.capacity().checked_mul(4),
            self.retired.capacity().checked_mul(size_of::<Receipt>()),
            self.retired_calls
                .capacity()
                .checked_mul(size_of::<CallInfo>()),
            self.pending
                .len()
                .checked_add(
                    1 + usize::from(self.initial.is_some()) + usize::from(self.input.is_some()),
                )
                .and_then(|n| n.checked_mul(size_of::<tokio::time::Sleep>())),
        ] {
            sum = sum
                .checked_add(n.ok_or(Fault::Overflow)?)
                .ok_or(Fault::Overflow)?;
        }
        for p in &self.pending {
            if let Some(frame) = &p.frame {
                sum = sum
                    .checked_add(frame.retained_bytes())
                    .ok_or(Fault::Overflow)?;
            }
        }
        if let Some(frame) = self.channel.framing() {
            sum = sum
                .checked_add(frame.retained_storage_bytes()?)
                .ok_or(Fault::Overflow)?;
        }
        sum = sum
            .checked_add(self.audio.snapshot().ok_or(Fault::Conflict)?.1)
            .ok_or(Fault::Overflow)?;
        Ok(sum)
    }
    fn row_index(&self, call: &Call) -> Result<usize, Error> {
        if call.domain != self.domain {
            return Err(Fault::StaleGeneration.into());
        }
        self.rows
            .iter()
            .position(|r| r.as_ref().is_some_and(|r| r.info.call == *call))
            .ok_or(Fault::StaleGeneration.into())
    }
    fn row(&self, call: &Call) -> Result<&Row, Error> {
        self.rows[self.row_index(call)?]
            .as_ref()
            .ok_or(Fault::StaleGeneration.into())
    }
    fn row_mut(&mut self, call: &Call) -> Result<&mut Row, Error> {
        let at = self.row_index(call)?;
        self.rows[at].as_mut().ok_or(Fault::StaleGeneration.into())
    }
    fn check(&mut self) -> Result<(), Error> {
        self.registration_timeout = false;
        if self.closed {
            return Err(Fault::Closed.into());
        }
        if Instant::now() >= self.overall.targets.hard {
            return Err(Fault::Deadline.into());
        }
        // Provider errors stay provider errors. Only comparisons against an
        // actual sampled time may authorize a registration-only phase retry.
        let now = self.source.clock().sample()?.now.as_micros();
        let native = Instant::now();
        if native >= self.overall.targets.hard || now >= self.overall.targets.expires {
            return Err(Fault::Deadline.into());
        }
        let expired = |bounds: Bounds| native >= bounds.hard || now >= bounds.expires;
        if self.initial.as_ref().is_some_and(|b| expired(b.targets)) {
            self.registration_timeout = self.replacement_registration();
            return Err(Fault::Deadline.into());
        }
        if self.input.as_ref().is_some_and(|b| expired(b.targets)) {
            return Err(Fault::Deadline.into());
        }
        if let Some(pending) = self.pending.iter().find(|p| expired(p.bound.targets)) {
            self.registration_timeout =
                pending.receipt.kind == Kind::Register && self.replacement_registration();
            return Err(Fault::Deadline.into());
        }
        Ok(())
    }
    fn expired(&mut self, cx: &mut Context<'_>) -> bool {
        self.registration_timeout = false;
        if self.overall.native(cx) {
            return true;
        }
        if self.initial.as_mut().is_some_and(|b| b.native(cx)) {
            self.registration_timeout = self.replacement_registration();
            return true;
        }
        if self.input.as_mut().is_some_and(|b| b.native(cx)) {
            return true;
        }
        let replacement = self.replacement_registration();
        for pending in &mut self.pending {
            if pending.bound.native(cx) {
                self.registration_timeout = replacement && pending.receipt.kind == Kind::Register;
                return true;
            }
        }
        false
    }
    /// Earliest actual original native target for an enclosing signal/output wait.
    pub fn native_deadline(&self) -> Instant {
        self.initial
            .iter()
            .chain(self.input.iter())
            .chain(self.pending.iter().map(|p| &p.bound))
            .map(|b| b.targets.hard)
            .chain(
                self.registration
                    .as_ref()
                    .filter(|_| self.recoverable && !self.registration_established())
                    .map(|r| r.initial.hard),
            )
            .chain(
                (self.recoverable && !self.registration_established())
                    .then_some(self.initializer.bounds.hard),
            )
            .chain(std::iter::once(self.overall.targets.hard))
            .min()
            .unwrap_or(self.overall.targets.hard)
    }
    fn lost(&mut self, cause: Cause) -> Loss {
        // Actual physical source first; no clock, allocator or port provider is
        // needed to preserve all original exposure and observed call facts.
        let initial = self.initial.as_ref().map(|b| b.targets);
        let input = self.input.as_ref().map(|b| b.targets);
        self.channel.close();
        self.closed = true;
        self.recoverable = recovery::allowed(&cause)
            || (matches!(cause, Cause::Deadline) && self.registration_timeout);
        self.initial = None;
        self.input = None;
        for mut p in self.pending.drain(..) {
            p.receipt.epoch = self.epoch.clone();
            self.retired.push(p.receipt);
        }
        for row in self.rows.iter().flatten() {
            self.retired_calls.push(row.info.clone());
        }
        self.queued_bytes = 0;
        Loss {
            overall: self.overall.targets,
            initial,
            input,
            cause,
            initializer: self.initializer.clone(),
            pending: std::mem::take(&mut self.retired),
            calls: std::mem::take(&mut self.retired_calls),
            input_bytes: self.input_bytes,
            audio: self.audio.snapshot(),
        }
    }
    /// Clock-free physical cancel. A pending original source loss is returned
    /// first, never replaced by a later Cancelled classification. No wire cancel
    /// ACK, call acceptance, processing or remote HangUp is synthesized. This
    /// also withdraws registration recovery after an already observed loss.
    pub fn close(&mut self) -> Option<Loss> {
        self.recoverable = false;
        if let Some(loss) = self.pending_loss.take() {
            return Some(loss);
        }
        if self.closed {
            None
        } else {
            Some(self.lost(Cause::Cancelled))
        }
    }
    /// Native-only original target guard for caller-side signal/output waits.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Loss> {
        if let Some(loss) = self.pending_loss.take() {
            return Some(loss);
        }
        if !self.closed && self.expired(cx) {
            Some(self.lost(Cause::Deadline))
        } else {
            None
        }
    }
    /// Poll one finite real event. Canceling the returned observation future
    /// changes no original cursor, input/write target, queue or Line epoch.
    pub fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
        if let Some(loss) = self.poll_native_guard(cx) {
            return Poll::Ready(Ok(Progress::Lost(loss)));
        }
        if self.closed {
            return Poll::Ready(Err(Fault::Closed.into()));
        }
        match self.poll_inner(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Ok(Progress::Lost(self.lost(cause(e))))),
            other => other,
        }
    }
    /// Await the next original event without spawning a task or selecting devices.
    pub async fn drive(&mut self) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll_progress(cx)).await
    }
}
impl Drop for Line {
    fn drop(&mut self) {
        let _actual = self.close();
    }
}
fn encode(message: ipc::Message<'_>, maximum: usize) -> Result<OwnedFrame, Error> {
    let n = message.encoded_len()?;
    if n > maximum {
        return Err(Fault::TooLarge.into());
    }
    let mut frame = Zeroizing::new(Vec::new());
    frame.try_reserve_exact(n).map_err(|_| Fault::Capacity)?;
    if frame.capacity() > maximum {
        return Err(Fault::Capacity.into());
    }
    frame.resize(n, 0);
    message.encode(&mut frame)?;
    Ok(OwnedFrame::new(std::mem::take(&mut *frame)))
}

fn cause(error: Error) -> Cause {
    match error {
        Error::Protocol(Fault::Deadline) => Cause::Deadline,
        other => Cause::Failure(other),
    }
}
