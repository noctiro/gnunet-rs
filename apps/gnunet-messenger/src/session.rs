//! Actual room/stdin/history owner; every source and original future stays local.
use crate::{
    Failure,
    input::Input,
    options::{INPUT_BYTES, Settings},
    output::{self, Failures, Report},
};
use gnunet_client_host::{EndpointSource, LiveConfiguration};
use gnunet_identity_client_host as identity;
use gnunet_messenger_host::{
    self as messenger, Api, Deadline, Hash, MemberSession, Operation, OsEntropy, Progress, Room,
    crypto::Entropy,
    domain::{self, Event, MessagePhase, OperationPhase, SessionPhase},
    wire::{
        body::{Body, Text},
        profile::Endian,
    },
};
use gnunet_program_host::reporting::Reporter;
use gnunet_resolver_broker::{Context as Broker, Driver};
use gnunet_service_runtime::clock::{Deadline as LogicalDeadline, RuntimeClock};
use gnunet_service_startup::{ControlReceiver, ParentControl};
use gnunet_types::{AbsoluteTime, Error as Fault};
use std::{
    cell::Cell,
    collections::VecDeque,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    signal::unix::{Signal, SignalKind, signal},
    time::{Instant, Sleep},
};
use zeroize::{Zeroize, Zeroizing};
pub(super) struct Inputs {
    pub settings: Settings,
    pub live: LiveConfiguration,
    pub context: Broker<128, 256>,
    pub resolver: Driver<128, 256>,
    pub source: Arc<dyn RuntimeClock>,
    pub reporter: Reporter,
    pub stop: Rc<Cell<bool>>,
    pub parent: Option<ParentControl>,
}
struct Signals {
    interrupt: Signal,
    terminate: Signal,
    parent: Option<ControlReceiver>,
    stop: Rc<Cell<bool>>,
    reporter: Reporter,
}
impl Signals {
    fn new(
        parent: Option<ParentControl>,
        stop: Rc<Cell<bool>>,
        reporter: Reporter,
    ) -> Result<Self, Failure> {
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
            parent: parent
                .map(ParentControl::register)
                .transpose()
                .map_err(|failure| Box::new(failure.error) as Failure)?,
            stop,
            reporter,
        })
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.reporter.register(cx);
        if self.stop.get() || self.reporter.failed() {
            return Poll::Ready(Ok(()));
        }
        for original in [&mut self.interrupt, &mut self.terminate] {
            if let Poll::Ready(signal) = original.poll_recv(cx) {
                return Poll::Ready(
                    signal.ok_or_else(|| io::Error::other("original signal stream ended")),
                );
            }
        }
        let mut consumed = 0;
        for _ in 0..4 {
            let Some(parent) = &mut self.parent else {
                break;
            };
            match parent.poll_signal(cx) {
                Poll::Ready(Ok(Some(code)))
                    if i32::from(code) == nix::libc::SIGINT
                        || i32::from(code) == nix::libc::SIGTERM =>
                {
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(Some(_))) => consumed += 1,
                Poll::Ready(Ok(None)) => {
                    self.parent = None;
                    break;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => break,
            }
        }
        if consumed == 4 {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}
struct Alarm {
    source: Arc<dyn RuntimeClock>,
    hard: Option<Instant>,
    native: Option<Pin<Box<Sleep>>>,
    until: Option<AbsoluteTime>,
    logical: Option<Pin<Box<LogicalDeadline>>>,
}
impl Alarm {
    fn new(source: Arc<dyn RuntimeClock>) -> Self {
        Self {
            source,
            hard: None,
            native: None,
            until: None,
            logical: None,
        }
    }
    fn set(&mut self, deadlines: impl Iterator<Item = Deadline>) -> Result<(), Fault> {
        let (mut hard, mut until) = (None, None);
        for deadline in deadlines {
            hard = Some(hard.map_or(deadline.hard(), |old: Instant| old.min(deadline.hard())));
            let absolute = AbsoluteTime::from_micros(deadline.expires());
            until = Some(until.map_or(absolute, |old: AbsoluteTime| old.min(absolute)));
        }
        if hard != self.hard {
            self.hard = hard;
            self.native = hard.map(|hard| Box::pin(tokio::time::sleep_until(hard)));
        }
        if until != self.until {
            self.until = until;
            self.logical = until
                .map(|until| LogicalDeadline::at(self.source.clone(), until).map(Box::pin))
                .transpose()?;
        }
        Ok(())
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Result<bool, Fault> {
        if self.hard.is_some_and(|hard| Instant::now() >= hard)
            || self
                .native
                .as_mut()
                .is_some_and(|t| t.as_mut().poll(cx).is_ready())
        {
            return Ok(true);
        }
        if let Some(logical) = &mut self.logical
            && let Poll::Ready(result) = logical.as_mut().poll(cx)
        {
            result?;
            return Ok(true);
        }
        Ok(false)
    }
}
#[derive(Clone, Copy)]
enum Purpose {
    Input,
    Setup,
    History,
}
#[derive(Clone, Copy)]
struct Original<'id> {
    operation: Operation<'id>,
    purpose: Purpose,
}
struct Pending<'id> {
    length: usize,
    deadline: Deadline,
    recipients: Vec<MemberSession<'id>>,
    next: usize,
}
struct Fetch {
    hash: Hash,
    deadline: Deadline,
}
struct State<'id> {
    room: Option<Room<'id>>,
    opening: Option<Deadline>,
    setup: Option<Deadline>,
    setup_step: u8,
    monitor_started: bool,
    joined: bool,
    eof: bool,
    pending: Option<Pending<'id>>,
    payload: Zeroizing<Vec<u8>>,
    originals: Vec<Original<'id>>,
    seen: Vec<Hash>,
    requested: Vec<Hash>,
    fetch: VecDeque<Fetch>,
    history: messenger::HistoryWorkspace,
    walked: bool,
    close: Option<Deadline>,
    leave: bool,
    room_closed: bool,
    destroy: bool,
    stop_requested: bool,
    recovering: bool,
    ever_joined: bool,
    // Admission only: API owns confirmation, original Span and recovery.
    talk_admitted: bool,
    recovery_input_warned: bool,
}
impl<'id> State<'id> {
    fn new(settings: &Settings) -> Result<Self, Failure> {
        let mut payload = Zeroizing::new(Vec::new());
        payload.try_reserve_exact(INPUT_BYTES)?;
        payload.resize(INPUT_BYTES, 0);
        let mut originals = Vec::new();
        originals.try_reserve_exact(settings.limits.operations)?;
        let mut seen = Vec::new();
        seen.try_reserve_exact(settings.limits.core.messages_per_room)?;
        let mut requested = Vec::new();
        requested.try_reserve_exact(settings.limits.core.messages_per_room)?;
        let mut fetch = VecDeque::new();
        fetch.try_reserve_exact(settings.limits.core.missing_per_room)?;
        Ok(Self {
            room: None,
            opening: None,
            setup: None,
            setup_step: 0,
            monitor_started: false,
            joined: false,
            eof: false,
            pending: None,
            payload,
            originals,
            seen,
            requested,
            fetch,
            history: messenger::HistoryWorkspace::new(settings.limits.core.messages_per_room)?,
            walked: false,
            close: None,
            leave: false,
            room_closed: false,
            destroy: false,
            stop_requested: false,
            recovering: false,
            ever_joined: false,
            talk_admitted: false,
            recovery_input_warned: false,
        })
    }
    fn retain(&mut self, operation: Operation<'id>, purpose: Purpose) -> Result<(), Fault> {
        if self.originals.iter().any(|o| o.operation == operation) {
            return Err(Fault::Replay);
        }
        if self.originals.len() == self.originals.capacity() {
            return Err(Fault::Capacity);
        }
        self.originals.push(Original { operation, purpose });
        Ok(())
    }
    fn budgets(&self) -> impl Iterator<Item = Deadline> + '_ {
        self.opening
            .into_iter()
            .chain(self.setup)
            .chain(self.pending.as_ref().map(|p| p.deadline))
            .chain(self.fetch.iter().map(|f| f.deadline))
            .chain(self.close)
    }
    fn fetch(
        &mut self,
        api: &mut Api<'id, OsEntropy>,
        hash: Hash,
        timeout: Duration,
    ) -> Result<(), Failure> {
        if hash == [0; 64]
            || self.requested.contains(&hash)
            || self.fetch.iter().any(|f| f.hash == hash)
        {
            return Ok(());
        }
        if self.fetch.len() == self.fetch.capacity()
            || self.requested.len() == self.requested.capacity()
        {
            return Err("bounded Messenger history request capacity exhausted".into());
        }
        self.fetch.push_back(Fetch {
            hash,
            deadline: api.deadline(timeout)?,
        });
        Ok(())
    }
}
fn retry(error: &messenger::Error) -> bool {
    matches!(
        error,
        messenger::Error::Local(Fault::NotReady | Fault::WouldBlock)
            | messenger::Error::Domain(domain::Error::Protocol(
                Fault::NotReady | Fault::WouldBlock
            ))
    )
}
fn room_key(settings: &Settings) -> Result<Hash, Failure> {
    let mut key = match &settings.room {
        Some(name) => gnunet_crypto::hash512(name),
        None => {
            let mut key = [0; 64];
            let mut entropy = OsEntropy::new();
            if let Err(error) = entropy.fill(&mut key) {
                return Err(match entropy.take_error() {
                    Some(original) => Box::new(output::EntropyFailure(original)) as Failure,
                    None => Box::new(error) as Failure,
                });
            }
            key
        }
    };
    let bits = if settings.public { 3u8 } else { 2u8 };
    key[0] = match settings.profile.endian {
        Endian::Little => bits,
        Endian::Big => bits.reverse_bits(),
    };
    Ok(key)
}
#[derive(Debug)]
struct LookupFailure {
    cause: identity::LossCause,
    operations: usize,
    exposed: usize,
}
impl std::fmt::Display for LookupFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "original IDENTITY lookup source: cause={:?}; operations={}; exposed={}",
            self.cause, self.operations, self.exposed
        )
    }
}
impl std::error::Error for LookupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.cause {
            identity::LossCause::Io(e) => Some(e),
            identity::LossCause::Protocol(e) | identity::LossCause::Resource(e) => Some(e),
            identity::LossCause::Ports(e) => Some(e),
            _ => None,
        }
    }
}
struct LookupInputs<'run, 'id> {
    instance: &'id identity::Instance,
    endpoint: EndpointSource,
    name: &'run [u8],
    source: &'run Arc<dyn RuntimeClock>,
    resolver: &'run mut Driver<128, 256>,
    signals: &'run mut Signals,
    reporter: &'run Reporter,
    timeout: Duration,
}
async fn lookup(input: LookupInputs<'_, '_>) -> Result<Option<identity::SecretKey>, Failure> {
    let LookupInputs {
        instance,
        endpoint,
        name,
        source,
        resolver,
        signals,
        reporter,
        timeout,
    } = input;
    let hard = Instant::now().checked_add(timeout).ok_or(Fault::Overflow)?;
    let until = source
        .sample()?
        .now
        .as_micros()
        .checked_add(u64::try_from(timeout.as_micros())?)
        .filter(|n| *n != u64::MAX)
        .map(AbsoluteTime::from_micros)
        .ok_or(Fault::Overflow)?;
    let mut native = Box::pin(tokio::time::sleep_until(hard));
    let mut logical = Box::pin(LogicalDeadline::at(source.clone(), until)?);
    let mut owner = identity::Lookup::exact(
        instance,
        endpoint,
        name,
        until.as_micros(),
        identity::Limits {
            reconnect: false,
            ..Default::default()
        },
    )?;
    let result: Result<Option<identity::SecretKey>, Failure> = async {
        loop {
            let event = {
                let mut observe_resolver = |event| {
                    reporter.debug(
                        "messenger.identity.resolver",
                        format_args!("Resolver: {event:?}"),
                    )
                };
                let mut resolving =
                    std::pin::pin!(resolver.drive_waiting(None, &mut observe_resolver));
                poll_fn(|cx| {
                    if let Poll::Ready(result) = signals.poll(cx) {
                        return Poll::Ready(
                            result.map(|()| None).map_err(|e| Box::new(e) as Failure),
                        );
                    }
                    if native.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Err(
                            "original ego lookup native deadline expired".into()
                        ));
                    }
                    if let Poll::Ready(result) = logical.as_mut().poll(cx) {
                        return Poll::Ready(Err(match result {
                            Ok(()) => "original ego lookup deadline expired".into(),
                            Err(e) => Box::new(e) as Failure,
                        }));
                    }
                    let event = owner.poll(cx, Some(hard));
                    if event.is_ready() {
                        return event.map(|v| v.map(Some).map_err(|e| Box::new(e) as Failure));
                    }
                    if reporter.failed() {
                        return Poll::Ready(Ok(None));
                    }
                    if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                        if let Err(error) = result {
                            return Poll::Ready(Err(Box::new(error) as Failure));
                        }
                        if event.is_pending() {
                            cx.waker().wake_by_ref();
                        }
                    }
                    event.map(|v| v.map(Some).map_err(|e| Box::new(e) as Failure))
                })
                .await?
            };
            match event {
                None => return Ok(None),
                Some(identity::LookupProgress::Finished {
                    outcome: identity::LookupOutcome::Found(ego),
                    ..
                }) => return Ok(Some(ego.into_secret())),
                Some(identity::LookupProgress::Finished {
                    outcome: identity::LookupOutcome::ResultCode(200),
                    ..
                }) => {
                    reporter.warning(
                        "messenger.ego.missing",
                        format_args!(
                            "requested ego is absent; using the official anonymous identity"
                        ),
                    );
                    return Ok(Some(identity::SecretKey::anonymous()));
                }
                Some(identity::LookupProgress::Finished { outcome, .. }) => {
                    return Err(format!("original ego lookup: {outcome:?}").into());
                }
                Some(identity::LookupProgress::Closed) => {
                    return Err("original ego lookup ended without a result".into());
                }
                Some(identity::LookupProgress::Source(identity::Progress::Lost {
                    cause,
                    report,
                })) => {
                    return Err(Box::new(LookupFailure {
                        cause,
                        operations: report.operations,
                        exposed: report.exposed,
                    }) as Failure);
                }
                Some(identity::LookupProgress::Source(identity::Progress::Unavailable(error))) => {
                    return Err(Box::new(error) as Failure);
                }
                Some(identity::LookupProgress::Source(identity::Progress::ConnectRetry {
                    error,
                    ..
                })) => return Err(Box::new(error) as Failure),
                Some(identity::LookupProgress::Source(event)) => reporter.debug(
                    "messenger.identity.activity",
                    format_args!("IDENTITY: {event:?}"),
                ),
            }
            tokio::task::yield_now().await;
        }
    }
    .await;
    let _original_close = owner.close();
    result
}
fn render<'id>(
    api: &Api<'id, OsEntropy>,
    state: &mut State<'id>,
    settings: &Settings,
    room: Room<'id>,
    hash: Hash,
    report: &mut Report,
) -> Result<Option<[Hash; 2]>, Failure> {
    let message = api.message(room, &hash)?;
    let parents = *message.parents();
    let attributed = message.original_signer().is_some();
    if message.phase() == MessagePhase::Applied && !state.seen.contains(&hash) {
        if state.seen.len() == state.seen.capacity() {
            return Err("bounded Messenger displayed-message inventory exhausted".into());
        }
        if output::message(api, room, message, settings.talk, settings.silence)? {
            report.displayed = report.displayed.saturating_add(1);
        }
        state.seen.push(hash);
    }
    Ok(attributed.then_some(parents))
}
// This is the same sole Input and fixed payload allocation. Offline input is
// explicitly unsent rather than acquiring an old member/recipient capability.
fn unavailable_input(
    result: io::Result<usize>,
    state: &mut State<'_>,
    reporter: &Reporter,
    report: &mut Report,
    errors: &mut Failures,
) {
    match result {
        Ok(0) => state.eof = true,
        Ok(_) => {
            report.input_chunks = report.input_chunks.saturating_add(1);
            if !state.recovery_input_warned {
                reporter.warning("messenger.input.unsent", format_args!(
                    "input received while disconnected was not sent; resend it after the room has joined"
                ));
                state.recovery_input_warned = true;
            }
        }
        Err(error) => errors.input = Some(error),
    }
    state.payload.as_mut_slice().zeroize();
}
async fn before_source_loss(
    input: &mut Input,
    state: &mut State<'_>,
    reporter: &Reporter,
    report: &mut Report,
    errors: &mut Failures,
    supplied: Option<io::Result<usize>>,
) {
    // Preserve initial pre-JOIN backpressure. After a joined source ends,
    // continue observing stdin during recovery so EOF can actually terminate it.
    if state.eof || !state.ever_joined {
        return;
    }
    if state.pending.take().is_some() {
        reporter.warning(
            "messenger.input.interrupted",
            format_args!(
                "pending input was interrupted by connection loss and was not resubmitted"
            ),
        );
        state.payload.as_mut_slice().zeroize();
    }
    let observed = match supplied {
        Some(result) => Poll::Ready(result),
        None => poll_fn(|cx| Poll::Ready(input.poll(cx, &mut state.payload))).await,
    };
    if let Poll::Ready(result) = observed {
        unavailable_input(result, state, reporter, report, errors);
    }
}
fn progress<'id>(
    event: Progress<'id>,
    api: &mut Api<'id, OsEntropy>,
    state: &mut State<'id>,
    settings: &Settings,
    reporter: &Reporter,
    report: &mut Report,
    errors: &mut Failures,
) -> Result<bool, Failure> {
    match event {
        Progress::Lost(loss) => {
            if !state.stop_requested
                && !state.eof
                && state.close.is_none()
                && !errors.failed()
                && !state.budgets().any(|deadline| deadline.expired(None))
                && api.can_reconnect(&loss)
            {
                reporter.warning(
                    "messenger.source.recovering",
                    format_args!("Messenger connection lost; restoring room membership. Outstanding messages will not be resent automatically."),
                );
                state.recovering = true;
                report.capture_recovery(loss, errors);
                // Those actual old jobs are failed/retired. A pending input
                // might contain recipients bound to the old member session;
                // abandon it explicitly rather than resubmitting its bytes.
                if state.pending.is_some() {
                    reporter.warning(
                        "messenger.input.interrupted",
                        format_args!(
                            "pending input was interrupted by MQ loss and was not resubmitted"
                        ),
                    );
                }
                state.pending = None;
                state.payload.as_mut_slice().zeroize();
                state.originals.clear();
                state.requested.clear();
                state.monitor_started = false;
                state.joined = false;
                state.walked = false;
                // The new authenticated membership establishes its current
                // name/subscription with fresh control messages. No old frame,
                // user payload, hash, operation or success is transplanted.
                state.setup_step = 0;
                // Keep a not-yet-admitted initial setup's original deadline.
                // An admitted TALK subscription is recovered by Api alone.
                api.reconnect()?;
                return Ok(false);
            }
            let expected = state.destroy
                && loss.control().is_some_and(|control| {
                    control.kind() == messenger::native::Kind::Destroy
                        && matches!(control.exposure(), messenger::Exposure::Written { .. })
                });
            report.capture(loss, errors);
            if !expected && errors.original.is_none() {
                errors.record_original(
                    "original Messenger source ended before graceful DESTROY".into(),
                );
            }
            return Ok(true);
        }
        Progress::LayoutNeeded(_) => {
            return Err(
                "original Messenger input needs an explicit original-producer layout".into(),
            );
        }
        Progress::Written { .. } => report.local_written = report.local_written.saturating_add(1),
        Progress::RoomClosed { closing, .. } => {
            if state.room == Some(closing.room()) {
                state.room_closed = true;
            }
        }
        Progress::Records(record) => {
            if let Some(error) = record.refusal() {
                reporter.warning(
                    "messenger.record.refused",
                    format_args!("original record: {error}"),
                );
            }
            if let Some(loss) = record.loss() {
                if let Some(source) = loss.general() {
                    report.record_source(source);
                }
                if let Some(source) = loss.monitor() {
                    report.record_source(source);
                }
            }
            match record.into_native() {
                gnunet_namestore_client_host::Progress::Lost {
                    cause,
                    report: original,
                } => {
                    report.record_source(&original);
                    if errors.records.is_none() {
                        errors.records = Some(cause);
                    }
                }
                gnunet_namestore_client_host::Progress::Unavailable(error) => {
                    if errors.original.is_none() {
                        errors.record_original(Box::new(error));
                    }
                }
                original => reporter.debug(
                    "messenger.records.activity",
                    format_args!("NAMESTORE: {original:?}"),
                ),
            }
        }
        Progress::State(event) => match event {
            Event::MessageChanged(room, hash, _) => {
                if let Some(parents) = render(api, state, settings, room, hash, report)?
                    && settings.history
                    && !settings.talk
                    && state.close.is_none()
                {
                    for parent in parents {
                        state.fetch(api, parent, settings.timeout)?;
                    }
                }
                if settings.history
                    && !state.walked
                    && api.message(room, &hash)?.phase() == MessagePhase::Applied
                    && api.message(room, &hash)?.history_complete()
                    && let Some(member) = api.state().local_member(room)?
                {
                    state.walked = true;
                    let mut original = match api.history(member, &hash, &mut state.history) {
                        Ok(original) => original,
                        Err(messenger::Error::Domain(domain::Error::Protocol(
                            Fault::PermissionDenied | Fault::NotReady | Fault::NotFound,
                        ))) => {
                            reporter.warning("messenger.history.unavailable",format_args!("cached history is outside the current member's available rights"));
                            return Ok(false);
                        }
                        Err(error) => return Err(Box::new(error)),
                    };
                    for _ in 0..settings.limits.core.messages_per_room {
                        let Some(message) = original.try_next()? else {
                            break;
                        };
                        let hash = *message.hash();
                        if message.phase() == MessagePhase::Applied && !state.seen.contains(&hash) {
                            if state.seen.len() == state.seen.capacity() {
                                return Err("bounded history output inventory exhausted".into());
                            }
                            if output::message(api, room, message, settings.talk, settings.silence)?
                            {
                                report.displayed = report.displayed.saturating_add(1);
                            }
                            state.seen.push(hash);
                        }
                    }
                }
            }
            Event::Missing(room, hash)
                if settings.history && state.close.is_none() && state.room == Some(room) =>
            {
                state.fetch(api, hash, settings.timeout)?
            }
            Event::OperationChanged(operation, phase) => {
                if let Some(index) = state
                    .originals
                    .iter()
                    .position(|o| o.operation == operation)
                    && matches!(
                        phase,
                        OperationPhase::Complete
                            | OperationPhase::Failed
                            | OperationPhase::Cancelled
                    )
                {
                    let original = state.originals.swap_remove(index);
                    if phase == OperationPhase::Complete {
                        report.completed = report.completed.saturating_add(1);
                    } else if matches!(original.purpose, Purpose::Input | Purpose::Setup) {
                        return Err(
                            "original Messenger input/setup operation failed or was canceled"
                                .into(),
                        );
                    }
                }
            }
            Event::ProviderFailed(binding, error) => {
                if state.originals.iter().any(|o| {
                    o.operation == binding.operation()
                        && matches!(o.purpose, Purpose::Input | Purpose::Setup)
                }) {
                    return Err(Box::new(error) as Failure);
                }
                reporter.warning(
                    "messenger.provider.refused",
                    format_args!("original provider: {error}"),
                );
            }
            original => reporter.debug(
                "messenger.state.activity",
                format_args!("state: {original:?}"),
            ),
        },
        original => reporter.debug(
            "messenger.native.activity",
            format_args!("Messenger: {original:?}"),
        ),
    }
    Ok(false)
}
fn advance<'id>(
    api: &mut Api<'id, OsEntropy>,
    state: &mut State<'id>,
    settings: &Settings,
    key: Hash,
    report: &mut Report,
) -> Result<(), Failure> {
    if !api.ready() {
        return Ok(());
    }
    if state.room.is_none() {
        let deadline = match state.opening {
            Some(d) => d,
            None => {
                let d = api.deadline(settings.timeout)?;
                state.opening = Some(d);
                d
            }
        };
        let result = match settings.door {
            Some(door) => api.enter_room_bounded(key, door, deadline),
            None => api.open_room_bounded(key, deadline),
        };
        match result {
            Ok((room, operation)) => {
                state.room = Some(room);
                state.retain(operation, Purpose::Setup)?;
                output::welcome(
                    &key,
                    settings.talk,
                    settings.silence,
                    settings.door.is_some(),
                )?;
            }
            Err(error) if retry(&error) => return Ok(()),
            Err(error) => return Err(Box::new(error)),
        }
    }
    let room = state.room.ok_or(Fault::Conflict)?;
    if !state.monitor_started {
        // A recovered room must first have its actual new source/member. An
        // early whole-zone watch would otherwise retain an empty/old watch set.
        if !api.state().joined(room)? || api.state().local_member(room)?.is_none() {
            return Ok(());
        }
        // This is a declared bounded observation window, not a reconnect or a
        // renewal of an old query. All key operations keep their own deadlines.
        match api.watch_records(settings.record_window) {
            Ok(_) => state.monitor_started = true,
            Err(error) if retry(&error) => return Ok(()),
            Err(error) => return Err(Box::new(error)),
        }
    }
    if !state.joined {
        if !api.state().joined(room)? || api.state().local_member(room)?.is_none() {
            return Ok(());
        }
        state.joined = true;
        state.ever_joined = true;
        state.recovering = false;
        state.recovery_input_warned = false;
        state.opening = None;
        output::joined(settings.talk, settings.silence)?;
    }
    if state.setup_step < 2 {
        let setup = match state.setup {
            Some(d) => d,
            None => {
                let d = api.deadline(settings.timeout)?;
                state.setup = Some(d);
                d
            }
        };
        if state.setup_step == 0 {
            if let Some(name) = &settings.ego {
                match api.send_bounded(
                    room,
                    Body::Name {
                        name: Text::new(name)?,
                    },
                    setup,
                ) {
                    Ok(op) => state.retain(op, Purpose::Setup)?,
                    Err(error) if retry(&error) => return Ok(()),
                    Err(error) => return Err(Box::new(error)),
                }
            }
            state.setup_step = 1;
        }
        if state.setup_step == 1 {
            if settings.talk && !state.talk_admitted {
                let discourse = [0; 32];
                match api.subscribe_bounded(room, discourse, Duration::from_secs(1), true, setup) {
                    Ok(op) => {
                        state.retain(op, Purpose::Setup)?;
                        state.talk_admitted = true;
                    }
                    Err(error) if retry(&error) => return Ok(()),
                    Err(error) => return Err(Box::new(error)),
                }
            }
            state.setup_step = 2;
            state.setup = None;
        }
    }
    if let Some(pending) = &mut state.pending {
        let bytes = &state.payload[..pending.length];
        let discourse = [0; 32];
        let body = if settings.talk {
            Body::Talk {
                discourse: &discourse,
                data: messenger::wire::SensitiveBytes::new(bytes),
            }
        } else {
            Body::Text {
                text: Text::new(bytes)?,
            }
        };
        let result = if settings.private {
            if let Some(recipient) = pending.recipients.get(pending.next) {
                api.send_private_bounded(room, *recipient, body, pending.deadline)
            } else {
                state.pending = None;
                state.payload.as_mut_slice().zeroize();
                return Ok(());
            }
        } else {
            api.send_bounded(room, body, pending.deadline)
        };
        match result {
            Ok(op) => {
                pending.next += 1;
                let done = !settings.private || pending.next == pending.recipients.len();
                state.retain(op, Purpose::Input)?;
                report.submitted = report.submitted.saturating_add(1);
                if done {
                    state.pending = None;
                    state.payload.as_mut_slice().zeroize();
                }
            }
            Err(error) if retry(&error) => {}
            Err(error) => return Err(Box::new(error)),
        }
    }
    if let Some(fetch) = state.fetch.front() {
        match api.request_message_bounded(room, fetch.hash, fetch.deadline) {
            Ok(op) => {
                let original = state.fetch.pop_front().ok_or(Fault::Conflict)?;
                state.requested.push(original.hash);
                state.retain(op, Purpose::History)?;
            }
            Err(error) if retry(&error) => {}
            Err(error) => return Err(Box::new(error)),
        }
    }
    Ok(())
}
struct Turn<'id> {
    stop: Option<io::Result<()>>,
    api: Option<Result<Progress<'id>, messenger::Error>>,
    resolver: Option<gnunet_resolver_broker::BrokerError>,
    input: Option<io::Result<usize>>,
    activity: bool,
    expired: bool,
    clock: Option<Fault>,
}
impl Turn<'_> {
    fn empty() -> Self {
        Self {
            stop: None,
            api: None,
            resolver: None,
            input: None,
            activity: false,
            expired: false,
            clock: None,
        }
    }
    fn ready(&self) -> bool {
        self.stop.is_some()
            || self.api.is_some()
            || self.resolver.is_some()
            || self.input.is_some()
            || self.activity
            || self.expired
            || self.clock.is_some()
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "One lexical scope owns original branded Instances, Api, buffers and all physical cleanup without self references or leaked storage"
)]
pub(super) async fn run(input: Inputs) -> Result<Report, Failure> {
    let Inputs {
        mut settings,
        live,
        context,
        mut resolver,
        source,
        reporter,
        stop,
        parent,
    } = input;
    let mut errors = Failures::default();
    let mut report = match Report::new(settings.limits) {
        Ok(report) => report,
        Err(error) => {
            errors.record_original(error);
            errors.resolver_close = resolver.disconnect().err();
            return errors.finish(Report::default());
        }
    };
    let outcome = async {
        if reporter.failed() || stop.get() {
            return Ok(());
        }
        let mut signals = Signals::new(parent, stop, reporter.clone())?;
        let stopping = poll_fn(|cx| {
            Poll::Ready(match signals.poll(cx) {
                Poll::Ready(result) => result.map(|()| true),
                Poll::Pending => Ok(false),
            })
        })
        .await?;
        if stopping {
            return Ok(());
        }
        let mut core_instance = messenger::domain::Instance::new();
        let instance = messenger::native::Instance::new();
        let record_instance = gnunet_namestore_client_host::Instance::new();
        let identity_instance = identity::Instance::new();
        let endpoint = |section: &'static [u8]| {
            EndpointSource::live(live.clone(), section, context.resolution_context())
        };
        let key = room_key(&settings)?;
        let secret = if let Some(name) = &settings.ego {
            let Some(secret) = lookup(LookupInputs {
                instance: &identity_instance,
                endpoint: endpoint(b"identity"),
                name,
                source: &source,
                resolver: &mut resolver,
                signals: &mut signals,
                reporter: &reporter,
                timeout: settings.timeout,
            })
            .await?
            else {
                return Ok(());
            };
            secret
        } else {
            identity::SecretKey::anonymous()
        };
        let mut api = Api::<OsEntropy>::new(
            &mut core_instance,
            &instance,
            endpoint(b"messenger"),
            secret,
            OsEntropy::new(),
            settings.limits,
        )?;
        let mut ended = false;
        let original = async {
            let mut state = State::new(&settings)?;
            let mut input = Input::new();
            let mut alarm = Alarm::new(source.clone());
            let mut stopping = false;
            let initial = api.enable_records(
                &record_instance,
                endpoint(b"namestore"),
                settings.secret.take().ok_or(Fault::InvalidInput)?,
                messenger::RecordLimits::default(),
            );
            if let Err(error) = initial {
                errors.api = Some(error);
                stopping = true;
            }
            while !ended {
                if !stopping {
                    match poll_fn(|cx| Poll::Ready(signals.poll(cx))).await {
                        Poll::Ready(Ok(())) => stopping = true,
                        Poll::Ready(Err(error)) => {
                            errors.signal = Some(error);
                            stopping = true;
                        }
                        Poll::Pending => {}
                    }
                }
                if (stopping || state.eof) && state.recovering && !state.joined {
                    // There is no current joined room to close gracefully.
                    // Stop the actual recovery owner now; its report retains
                    // the absence of a written DESTROY rather than inventing it.
                    let loss = api.close();
                    report.capture(loss, &mut errors);
                    ended = true;
                    break;
                }
                if errors.failed() || reporter.failed() {
                    let loss = api.close();
                    report.capture(loss, &mut errors);
                    break;
                }
                if !stopping {
                    // Drive/check the original Api native guard before any new
                    // caller effect, even when a previous class was always Ready.
                    if let Poll::Ready(event) =
                        poll_fn(|cx| Poll::Ready(api.poll_progress(cx))).await
                    {
                        if matches!(&event, Ok(Progress::Lost(_))) {
                            before_source_loss(
                                &mut input,
                                &mut state,
                                &reporter,
                                &mut report,
                                &mut errors,
                                None,
                            )
                            .await;
                        }
                        match event {
                            Ok(event) => match progress(
                                event,
                                &mut api,
                                &mut state,
                                &settings,
                                &reporter,
                                &mut report,
                                &mut errors,
                            ) {
                                Ok(done) => ended = done,
                                Err(error) => errors.record_original(error),
                            },
                            Err(error) => errors.api = Some(error),
                        }
                        if ended {
                            break;
                        }
                        if errors.failed() || reporter.failed() {
                            continue;
                        }
                    }
                    if state.budgets().any(|deadline| deadline.expired(None)) {
                        errors.original = Some(Box::new(Fault::Timeout));
                        continue;
                    }
                    if let Err(error) = advance(&mut api, &mut state, &settings, key, &mut report) {
                        errors.record_original(error);
                        continue;
                    }
                    if state.eof
                        && state.pending.is_none()
                        && state.originals.is_empty()
                        && state.fetch.is_empty()
                    {
                        stopping = true;
                    }
                }
                state.stop_requested = stopping;
                if stopping && state.close.is_none() {
                    state.pending = None;
                    state.payload.as_mut_slice().zeroize();
                    state.fetch.clear();
                    state.opening = None;
                    state.setup = None;
                    match api.deadline(settings.cleanup) {
                        Ok(deadline) => state.close = Some(deadline),
                        Err(error) => {
                            errors.cleanup = Some(error);
                            let loss = api.close();
                            report.capture(loss, &mut errors);
                            break;
                        }
                    }
                }
                if let Some(close) = state.close {
                    if !state.leave {
                        if let Some(room) = state.room {
                            match api.close_room_bounded(room, close) {
                                Ok(_) => state.leave = true,
                                Err(error) if retry(&error) => {}
                                Err(error) => {
                                    errors.cleanup = Some(error);
                                    continue;
                                }
                            }
                        } else {
                            state.room_closed = true;
                            state.leave = true;
                        }
                    }
                    if state.room_closed && !state.destroy {
                        match api.disconnect_bounded(close) {
                            Ok(_) => state.destroy = true,
                            Err(error) if retry(&error) => {}
                            Err(error) => {
                                errors.cleanup = Some(error);
                                continue;
                            }
                        }
                    }
                }
                if let Err(error) = alarm.set(state.budgets()) {
                    errors.record_original(Box::new(error));
                    continue;
                }
                let turn = {
                    let mut observe = |event| {
                        reporter.debug(
                            "messenger.resolver.activity",
                            format_args!("Resolver: {event:?}"),
                        )
                    };
                    let mut resolving = std::pin::pin!(resolver.drive_waiting(None, &mut observe));
                    poll_fn(|cx| {
                        let mut turn = Turn::empty();
                        reporter.register(cx);
                        if !stopping && let Poll::Ready(result) = signals.poll(cx) {
                            turn.stop = Some(result);
                            return Poll::Ready(turn);
                        }
                        match alarm.poll(cx) {
                            Ok(true) => {
                                turn.expired = true;
                                return Poll::Ready(turn);
                            }
                            Err(error) => {
                                turn.clock = Some(error);
                                return Poll::Ready(turn);
                            }
                            Ok(false) => {}
                        }
                        if reporter.failed() {
                            turn.stop = Some(Ok(()));
                            return Poll::Ready(turn);
                        }
                        if let Poll::Ready(event) = api.poll_progress(cx) {
                            turn.api = Some(event);
                        }
                        let failed_api = matches!(
                            &turn.api,
                            Some(Err(_) | Ok(Progress::Lost(_) | Progress::LayoutNeeded(_)))
                        );
                        if !reporter.failed()
                            && !failed_api
                            && let Poll::Ready(result) = resolving.as_mut().poll(cx)
                        {
                            match result {
                                Ok(_) => turn.activity = true,
                                Err(error) => turn.resolver = Some(error),
                            }
                        }
                        if !stopping
                            && !state.eof
                            && ((state.joined && state.setup_step == 2)
                                || (state.recovering && state.ever_joined && !state.joined))
                            && state.pending.is_none()
                            && state.originals.len() < settings.limits.operations / 2
                            && !reporter.failed()
                            && (!failed_api || matches!(&turn.api, Some(Ok(Progress::Lost(_)))))
                            && turn.resolver.is_none()
                            && let Poll::Ready(result) = input.poll(cx, &mut state.payload)
                        {
                            turn.input = Some(result);
                        }
                        if turn.ready() {
                            Poll::Ready(turn)
                        } else {
                            Poll::Pending
                        }
                    })
                    .await
                };
                if let Some(result) = turn.stop {
                    stopping = true;
                    if let Err(error) = result {
                        errors.signal = Some(error);
                    }
                }
                if turn.expired {
                    errors.record_original(
                        "original Messenger caller/cleanup deadline expired".into(),
                    );
                }
                if let Some(error) = turn.clock {
                    errors.record_original(Box::new(error));
                }
                if let Some(error) = turn.resolver {
                    errors.resolver = Some(error);
                }
                state.stop_requested = stopping;
                let unavailable = matches!(&turn.api, Some(Ok(Progress::Lost(_))));
                let mut input_result = turn.input;
                if unavailable {
                    before_source_loss(
                        &mut input,
                        &mut state,
                        &reporter,
                        &mut report,
                        &mut errors,
                        input_result.take(),
                    )
                    .await;
                } else if ((state.recovering && state.ever_joined && !state.joined)
                    || input_result
                        .as_ref()
                        .is_some_and(|r| matches!(r, Ok(0) | Err(_))))
                    && let Some(result) = input_result.take()
                {
                    unavailable_input(result, &mut state, &reporter, &mut report, &mut errors);
                }
                if let Some(event) = turn.api {
                    match event {
                        Ok(event) => match progress(
                            event,
                            &mut api,
                            &mut state,
                            &settings,
                            &reporter,
                            &mut report,
                            &mut errors,
                        ) {
                            Ok(done) => ended = done,
                            Err(error) => errors.record_original(error),
                        },
                        Err(error) => errors.api = Some(error),
                    }
                }
                if let Some(result) = input_result {
                    match result {
                        Ok(0) => state.eof = true,
                        Ok(mut length) => {
                            report.input_chunks = report.input_chunks.saturating_add(1);
                            if !settings.talk {
                                if state.payload.get(length.saturating_sub(1)) == Some(&b'\n') {
                                    length -= 1;
                                }
                                if let Some(n) =
                                    state.payload[..length].iter().position(|b| *b == 0)
                                {
                                    length = n;
                                }
                            }
                            let mut recipients = Vec::new();
                            if settings.private {
                                recipients
                                    .try_reserve_exact(settings.limits.core.sessions_per_room)?;
                                let room = state.room.ok_or(Fault::NotReady)?;
                                for (member, _, _, phase) in api.state().members(room)? {
                                    if phase == SessionPhase::Active {
                                        recipients.push(member);
                                    }
                                }
                                if recipients.is_empty() {
                                    errors.record_original(
                                        "no actual active member is available for private send"
                                            .into(),
                                    );
                                    continue;
                                }
                            }
                            match api.deadline(settings.timeout) {
                                Ok(deadline) => {
                                    state.pending = Some(Pending {
                                        length,
                                        deadline,
                                        recipients,
                                        next: 0,
                                    })
                                }
                                Err(error) => errors.api = Some(error),
                            }
                        }
                        Err(error) => errors.input = Some(error),
                    }
                }
                tokio::task::yield_now().await;
            }
            Ok::<(), Failure>(())
        }
        .await;
        if let Err(error) = original
            && errors.original.is_none()
        {
            errors.record_original(error);
        }
        if let Some(original) = api.entropy().last_error() {
            errors.entropy = Some(Box::new(output::EntropyFailure(*original)));
        }
        // This is outside the fallible original operation future: every early
        // error and normal stop still returns the same physical-close report.
        if !ended && report.stop.is_none() {
            let loss = api.close();
            report.capture(loss, &mut errors);
        }
        Ok::<(), Failure>(())
    }
    .await;
    if let Err(error) = outcome
        && errors.original.is_none()
    {
        errors.record_original(error);
    }
    if let Err(error) = resolver.disconnect() {
        errors.resolver_close = Some(error);
    }
    errors.logging = reporter.take_error();
    errors.finish(report)
}
