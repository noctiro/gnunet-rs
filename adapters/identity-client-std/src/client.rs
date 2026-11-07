use crate::{
    Cancellation, Completion, Ego, EgoView, Epoch, Error, Identity, Instance, KeyType, Kind,
    Limits, LocalReason, Loss, LossCause, Operation, Outcome, Progress, SecretKey, Submission, ipc,
    scope::Scope,
};
use gnunet_client_host::{EndpointSource, channel::Channel};
use gnunet_service_runtime::{
    clock::{Deadline, RuntimeClock},
    framing::OwnedFrame,
};
use gnunet_types::Error as Fault;
use std::{pin::Pin, sync::Arc, time::Duration};
use tokio::time::{Instant, Sleep};
use zeroize::Zeroizing;
mod io;
#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Operations,
    Monitor,
    Lookup,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Origin<'id> {
    Start(Epoch<'id>),
    Operation {
        epoch: Epoch<'id>,
        operation: Operation<'id>,
    },
}
struct State<'id> {
    operation: Operation<'id>,
    kind: Kind,
    source: Option<OwnedFrame>,
    len: usize,
    expires: u64,
    // Only explicit read-only lookups may have no overall deadline.
    hard: Option<Instant>,
    retirement: Option<Instant>,
    epoch: Option<Epoch<'id>>,
    queued: bool,
    sent: usize,
    written: bool,
    reason: Option<LocalReason>,
    key: Option<SecretKey>,
    outcome: Option<Outcome>,
}
impl State<'_> {
    fn submission(&self) -> Submission {
        if self.written {
            Submission::Written { bytes: self.len }
        } else if self.sent > 0 {
            Submission::Partial {
                bytes: self.sent,
                total: self.len,
            }
        } else {
            Submission::Unsent
        }
    }
}
struct Record<'id> {
    ego: Ego<'id>,
    identity: Identity,
}
enum Cache<'id> {
    Live(Record<'id>),
    Retired(Ego<'id>),
}
/// One general original-MQ client. Monitor mode sends the real START and keeps a
/// bounded opaque ego cache; operations-only mode allocates no cache. All shared
/// frame storage is zeroizing; canceling drive futures preserves native cursors.
pub struct Client<'id> {
    scope: Scope<'id>,
    channel: Channel<Origin<'id>>,
    clock: Arc<dyn RuntimeClock>,
    limits: Limits,
    mode: Mode,
    slots: Vec<Option<State<'id>>>,
    egos: Vec<Option<Cache<'id>>>,
    bytes: usize,
    epoch: Option<Epoch<'id>>,
    start_queued: bool,
    start_written: bool,
    initialized: bool,
    initial_hard: Option<Instant>,
    retry: bool,
    blocked: bool,
    closed: bool,
    paused: bool,
    yield_due: bool,
    read_first: bool,
    alarm: Option<Pin<Box<Deadline>>>,
    alarm_at: Option<u64>,
    native_alarm: Option<Pin<Box<Sleep>>>,
    native_at: Option<Instant>,
    pending_loss: Option<(Loss<'id>, Fault)>,
}
impl<'id> Client<'id> {
    /// Bound operation storage and subscribe to the explicit CLIENT source clock.
    /// No MQ, key, task or implicit Resolver is created. No monitor START is sent.
    pub fn new(
        instance: &'id Instance,
        source: EndpointSource,
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::construct(instance, source, limits, Mode::Operations)
    }
    /// Explicit monitor connection, initially incomplete until actual END_OF_LIST.
    pub fn monitor(
        instance: &'id Instance,
        source: EndpointSource,
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::construct(instance, source, limits, Mode::Monitor)
    }
    fn construct(
        instance: &'id Instance,
        source: EndpointSource,
        limits: Limits,
        mode: Mode,
    ) -> Result<Self, Error> {
        limits.validate(mode == Mode::Monitor)?;
        let scope = Scope::new(instance)?;
        let clock = source.clock();
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(limits.operations)
            .map_err(|_| Fault::Capacity)?;
        slots.resize_with(limits.operations, || None);
        let mut egos = Vec::new();
        if mode == Mode::Monitor {
            egos.try_reserve_exact(limits.egos)
                .map_err(|_| Fault::Capacity)?;
            egos.resize_with(limits.egos, || None);
        }
        let channel = Channel::new(source, limits.framing())?;
        Ok(Self {
            scope,
            channel,
            clock,
            limits,
            mode,
            slots,
            egos,
            bytes: 0,
            epoch: None,
            start_queued: false,
            start_written: false,
            initialized: false,
            initial_hard: None,
            retry: false,
            blocked: false,
            closed: false,
            paused: false,
            yield_due: false,
            read_first: false,
            alarm: None,
            alarm_at: None,
            native_alarm: None,
            native_at: None,
            pending_loss: None,
        })
    }
    /// Original canonical runtime clock. Cloning it creates no new listener/MQ.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    /// Exact current actual attachment, absent after physical loss/close.
    #[must_use]
    pub const fn epoch(&self) -> Option<Epoch<'id>> {
        self.epoch
    }
    /// True only after the original monitor START received actual end-of-list.
    #[must_use]
    pub const fn initialized(&self) -> bool {
        self.initialized
    }
    /// Number of original pending/tombstone/completion rows.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.slots.iter().flatten().count()
    }
    /// Borrow a current source-bound ego; old/deleted/source-lost handles refuse.
    pub fn ego(&self, ego: Ego<'id>) -> Result<EgoView<'_, 'id>, Error> {
        if !self.scope.same(ego.scope) || self.epoch != Some(ego.epoch) {
            return Err(Fault::StaleGeneration.into());
        }
        self.egos
            .iter()
            .find_map(|slot| match slot {
                Some(Cache::Live(r)) if r.ego == ego => Some(EgoView {
                    ego,
                    identity: &r.identity,
                }),
                _ => None,
            })
            .ok_or_else(|| Fault::StaleGeneration.into())
    }
    /// Current partial/live monitor directory. Check initialized before treating
    /// it as an ended initial snapshot. No borrowed key is copied or formatted.
    pub fn egos(&self) -> impl Iterator<Item = EgoView<'_, 'id>> + '_ {
        self.egos.iter().filter_map(|slot| match slot {
            Some(Cache::Live(r)) => Some(EgoView {
                ego: r.ego,
                identity: &r.identity,
            }),
            _ => None,
        })
    }
    fn index(&self, operation: Operation<'id>) -> Result<usize, Error> {
        if !self.scope.same(operation.scope) {
            return Err(Fault::StaleGeneration.into());
        }
        self.slots
            .iter()
            .position(|s| s.as_ref().is_some_and(|s| s.operation == operation))
            .ok_or_else(|| Fault::StaleGeneration.into())
    }
    fn name(&self, name: &[u8]) -> Result<(), Error> {
        if name.len() > self.limits.name_bytes {
            return Err(Fault::TooLarge.into());
        }
        if name.contains(&0) {
            return Err(Fault::InvalidInput.into());
        }
        Ok(())
    }
    fn append(
        &mut self,
        request: ipc::Request<'_>,
        kind: Kind,
        key: Option<SecretKey>,
        until: u64,
    ) -> Result<Operation<'id>, Error> {
        if self.closed {
            return Err(Fault::Closed.into());
        }
        if self.blocked || self.paused || self.pending_loss.is_some() {
            return Err(Fault::NotReady.into());
        }
        let now = match self.clock.sample() {
            Ok(sample) => sample.now.as_micros(),
            Err(error) => {
                // A provider fault invalidates the attached source even when
                // discovered while admitting another request, before any poll.
                self.blocked = true;
                let report = self.invalidate_source();
                self.pending_loss = Some((report, error));
                return Err(error.into());
            }
        };
        let forever = until == u64::MAX && matches!(kind, Kind::Lookup | Kind::LookupSuffix);
        if !forever && (until <= now || until == u64::MAX) {
            return Err(Fault::Deadline.into());
        }
        let hard = if forever {
            None
        } else {
            Some(
                Instant::now()
                    .checked_add(Duration::from_micros(until - now))
                    .ok_or(Fault::Overflow)?,
            )
        };
        let row = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(Fault::Capacity)?;
        let len = request.encoded_len()?;
        let bytes = self.bytes.checked_add(len).ok_or(Fault::Overflow)?;
        if len > self.limits.frame_bytes || bytes > self.limits.source_bytes {
            return Err(Fault::Capacity.into());
        }
        // The buffer is zeroizing even if encoding fails after copying a key.
        let mut encoded = Zeroizing::new(Vec::new());
        encoded
            .try_reserve_exact(len)
            .map_err(|_| Fault::Capacity)?;
        encoded.resize(len, 0);
        request.encode(encoded.as_mut_slice())?;
        let operation = self.scope.operation()?;
        let source = OwnedFrame::new(std::mem::take(&mut *encoded));
        self.slots[row] = Some(State {
            operation,
            kind,
            source: Some(source),
            len,
            expires: until,
            hard,
            retirement: None,
            epoch: None,
            queued: false,
            sent: 0,
            written: false,
            reason: None,
            key,
            outcome: None,
        });
        self.bytes = bytes;
        self.alarm = None;
        self.alarm_at = None;
        Ok(operation)
    }
    /// Import/create with explicit opaque material. This consumes/wipes the key
    /// on refusal. Duplicate intentionally first if the caller needs retention.
    /// Actual success still requires this original operation's RESULT_CODE.
    pub fn create(
        &mut self,
        name: &[u8],
        key: SecretKey,
        until: u64,
    ) -> Result<Operation<'id>, Error> {
        if self.mode == Mode::Lookup {
            return Err(Fault::Unsupported.into());
        }
        self.name(name)?;
        let frame_key = key.try_clone_secret();
        self.append(
            ipc::Request::Create {
                name,
                key: frame_key.view()?,
            },
            Kind::Create,
            Some(key),
            until,
        )
    }
    /// Generate using the caller's explicit entropy provider, then submit the
    /// actual CREATE. No hidden RNG/key file is used. Returned secret ownership
    /// appears only in the original completion/recovery outcome.
    pub fn create_generated(
        &mut self,
        name: &[u8],
        kind: KeyType,
        entropy: &mut impl gnunet_crypto::Entropy,
        until: u64,
    ) -> Result<Operation<'id>, Error> {
        self.name(name)?;
        let key = SecretKey::generate(kind, entropy)?;
        self.create(name, key, until)
    }
    /// Submit the exact official FIFO rename; no new ID is added to wire.
    pub fn rename(&mut self, old: &[u8], new: &[u8], until: u64) -> Result<Operation<'id>, Error> {
        if self.mode == Mode::Lookup {
            return Err(Fault::Unsupported.into());
        }
        self.name(old)?;
        self.name(new)?;
        self.append(ipc::Request::Rename { old, new }, Kind::Rename, None, until)
    }
    /// Submit official deletion. The RESULT_CODE is separate from monitor UPDATE.
    pub fn delete(&mut self, name: &[u8], until: u64) -> Result<Operation<'id>, Error> {
        if self.mode == Mode::Lookup {
            return Err(Fault::Unsupported.into());
        }
        self.name(name)?;
        self.append(ipc::Request::Delete { name }, Kind::Delete, None, until)
    }
    pub(crate) fn lookup(
        instance: &'id Instance,
        source: EndpointSource,
        name: &[u8],
        suffix: bool,
        until: u64,
        mut limits: Limits,
    ) -> Result<(Self, Operation<'id>), Error> {
        limits.operations = 1;
        limits.reconnect = false;
        let mut client = Self::construct(instance, source, limits, Mode::Lookup)?;
        client.name(name)?;
        let request = if suffix {
            ipc::Request::LookupSuffix { name }
        } else {
            ipc::Request::Lookup { name }
        };
        let operation = client.append(
            request,
            if suffix {
                Kind::LookupSuffix
            } else {
                Kind::Lookup
            },
            None,
            until,
        )?;
        Ok((client, operation))
    }
    fn local(state: &mut State<'id>, reason: LocalReason, code: Option<u32>) {
        let material = if reason == LocalReason::Cancelled {
            state.key = None;
            None
        } else {
            state.key.take()
        };
        state.outcome = Some(Outcome::Local {
            reason,
            submission: state.submission(),
            result_code: code,
            creation_material: material,
        });
        state.source = None;
    }
    fn retire_request(&mut self, row: usize, reason: LocalReason) -> Result<Cancellation, Error> {
        let state = self.slots[row].as_mut().ok_or(Fault::StaleGeneration)?;
        if state.outcome.is_some() {
            return Ok(Cancellation::Completed);
        }
        if state.reason == Some(LocalReason::Cancelled) {
            return Ok(Cancellation::Retiring);
        }
        if reason == LocalReason::Cancelled {
            state.key = None;
        }
        state.reason = Some(reason);
        if !state.queued {
            self.bytes = self.bytes.checked_sub(state.len).ok_or(Fault::Conflict)?;
            Self::local(state, reason, None);
            return Ok(Cancellation::Unsent);
        }
        if state.sent == 0 {
            let operation = state.operation;
            let removed = self
                .channel
                .framing_mut()
                .ok_or(Fault::StaleGeneration)?
                .remove_unwritten(
                    |origin, _| matches!(origin,Origin::Operation{operation:op,..}if op==operation),
                    |_, _| {},
                );
            if removed != 1 {
                return Err(Fault::Conflict.into());
            }
            self.bytes = self.bytes.checked_sub(state.len).ok_or(Fault::Conflict)?;
            state.queued = false;
            Self::local(state, reason, None);
            return Ok(Cancellation::Unsent);
        }
        if state.retirement.is_none() {
            // A late poll/cancel must not renew an already expired source.
            // Early cancellation starts its grace now; every path is capped by
            // the original native operation deadline plus that same grace.
            state.retirement = Some(
                state
                    .hard
                    .map_or_else(Instant::now, |hard| Instant::now().min(hard))
                    .checked_add(self.limits.retirement_grace)
                    .ok_or(Fault::Overflow)?,
            );
        }
        Ok(Cancellation::Retiring)
    }
    /// Suppress the callback. Zero-written originals may be removed; exposed
    /// requests retain FIFO tombstones and their immutable partial suffix until
    /// the real result or actual source stop. This never sends a wire CANCEL.
    pub fn cancel(&mut self, operation: Operation<'id>) -> Result<Cancellation, Error> {
        let row = self.index(operation)?;
        self.retire_request(row, LocalReason::Cancelled)
    }
    fn complete(&mut self) -> Option<Completion<'id>> {
        let row = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| {
                s.as_ref()
                    .filter(|s| s.outcome.is_some())
                    .map(|s| (i, s.operation.serial))
            })
            .min_by_key(|(_, n)| *n)
            .map(|(i, _)| i)?;
        let mut state = self.slots[row].take()?;
        Some(Completion {
            operation: state.operation,
            epoch: state.epoch,
            kind: state.kind,
            outcome: state.outcome.take()?,
        })
    }
    fn invalidate(&mut self, reason: LocalReason) -> Loss<'id> {
        let old = self.epoch.take();
        let (mut operations, mut exposed, mut egos) = (0, 0, 0);
        for state in self.slots.iter_mut().flatten() {
            if state.outcome.is_some() {
                continue;
            }
            operations += 1;
            if state.sent > 0 {
                exposed += 1;
            }
            let local = state.reason.unwrap_or(reason);
            Self::local(state, local, None);
        }
        for slot in &mut self.egos {
            match slot.take() {
                Some(Cache::Live(record)) => {
                    let ego = record.ego;
                    drop(record);
                    *slot = Some(Cache::Retired(ego));
                    egos += 1;
                }
                other => *slot = other,
            }
        }
        self.bytes = 0;
        self.start_queued = false;
        self.start_written = false;
        self.initialized = false;
        self.initial_hard = None;
        self.alarm = None;
        self.alarm_at = None;
        self.native_alarm = None;
        self.native_at = None;
        Loss {
            epoch: old,
            operations,
            exposed,
            egos,
        }
    }
    fn invalidate_source(&mut self) -> Loss<'id> {
        // Physical owner first, then wipe/revoke keys and publish exact outcomes.
        self.channel.detach();
        let report = self.invalidate(LocalReason::Lost);
        self.retry = self.limits.reconnect && !self.closed && !self.blocked;
        self.paused = !self.retry;
        report
    }
    fn lost(&mut self, cause: LossCause) -> Progress<'id> {
        let report = self.invalidate_source();
        Progress::Lost { report, cause }
    }
    /// Explicit original-MQ retirement and fresh monitor resnapshot policy.
    /// No old operation or key-containing frame is replayed.
    pub fn reconnect(&mut self) -> Result<Progress<'id>, Error> {
        if self.closed {
            return Err(Fault::Closed.into());
        }
        let event = self.lost(LossCause::Requested);
        self.retry = true;
        self.paused = false;
        Ok(event)
    }
    /// Recover an actual original CLIENT/clock port refusal without claiming a
    /// replacement connection exists. Explicit close cannot be recovered.
    pub fn recover_ports(&mut self) -> Result<(), Error> {
        if self.closed {
            return Err(Fault::Closed.into());
        }
        if !self.blocked {
            return Err(Fault::NotReady.into());
        }
        match self.channel.recover_ports() {
            Ok(()) | Err(Error::Protocol(Fault::NotReady)) => {}
            Err(error) => return Err(error),
        }
        self.blocked = false;
        self.paused = false;
        self.retry = true;
        Ok(())
    }
    /// Independently stop the original physical owner without reading a clock;
    /// queued completion/ego retirement observations remain available to poll.
    pub fn close(&mut self) -> Option<Loss<'id>> {
        if self.closed {
            return None;
        }
        self.channel.close();
        self.closed = true;
        self.retry = false;
        Some(self.invalidate(LocalReason::Closed))
    }
}
impl Drop for Client<'_> {
    fn drop(&mut self) {
        self.channel.close();
    }
}
