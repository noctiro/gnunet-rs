//! One retained CLI future with original same-owner MQ/FC/stdio obligations.
use crate::{
    Cause,
    budget::{Alarm, Start},
    control::Control,
    options::Settings,
    state::{Event, Report, SourceMeta, State},
    stdio::Stdio,
};
use gnunet_cadet_host::{self as cadet, Client, Step};
use gnunet_client_host::{EndpointSource, LiveConfiguration};
use gnunet_program_host::reporting::Reporter;
use gnunet_resolver_broker::{BrokerError, Context as Broker, Driver};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_service_startup::ParentControl;
use std::{
    cell::Cell,
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io::{self, Stdin, Stdout},
    rc::Rc,
    sync::Arc,
    task::Poll,
    time::Duration,
};
use tokio::time::Instant;
pub(super) struct Inputs {
    pub settings: Settings,
    pub live: LiveConfiguration,
    pub context: Broker<128, 256>,
    pub resolver: Driver<128, 256>,
    pub source: Arc<dyn RuntimeClock>,
    pub reporter: Reporter,
    pub stop: Rc<Cell<bool>>,
    pub parent: Option<ParentControl>,
    pub input: Stdin,
    pub output: Stdout,
}
#[derive(Debug, Default)]
struct Errors {
    original: [Option<Cause>; 4],
    additional_original: u64,
    loss: Option<cadet::LossCause>,
    native: Option<cadet::Error>,
    input: Option<io::Error>,
    signal: Option<io::Error>,
    output: Option<io::Error>,
    close: Option<cadet::Error>,
    resolver: Option<BrokerError>,
    resolver_close: Option<BrokerError>,
    logging: Option<io::Error>,
}
impl Errors {
    fn record(&mut self, error: Cause) {
        if let Some(slot) = self.original.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(error);
        } else {
            self.additional_original = self.additional_original.saturating_add(1);
        }
    }
    fn failed(&self) -> bool {
        self.original.iter().any(Option::is_some)
            || self.additional_original != 0
            || self.loss.is_some()
            || self.native.is_some()
            || self.input.is_some()
            || self.signal.is_some()
            || self.output.is_some()
            || self.close.is_some()
            || self.resolver.is_some()
            || self.resolver_close.is_some()
            || self.logging.is_some()
    }
}
#[derive(Debug)]
struct Failed {
    report: Report,
    errors: Errors,
}
impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CADET stream terminal facts: {:?}; causes: {:?}",
            self.report, self.errors
        )
    }
}
impl Error for Failed {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.errors
            .original
            .iter()
            .find_map(|error| error.as_deref())
            .or(match self.errors.loss.as_ref() {
                Some(cadet::LossCause::Io(error)) => Some(error as &dyn Error),
                Some(cadet::LossCause::Protocol(error)) => Some(error as &dyn Error),
                _ => None,
            })
            .or_else(|| self.errors.native.as_ref().map(|error| error as &dyn Error))
            .or_else(|| self.errors.input.as_ref().map(|error| error as &dyn Error))
            .or_else(|| self.errors.signal.as_ref().map(|error| error as &dyn Error))
            .or_else(|| self.errors.output.as_ref().map(|error| error as &dyn Error))
            .or_else(|| self.errors.close.as_ref().map(|error| error as &dyn Error))
            .or_else(|| {
                self.errors
                    .resolver
                    .as_ref()
                    .map(|error| error as &dyn Error)
            })
            .or_else(|| {
                self.errors
                    .resolver_close
                    .as_ref()
                    .map(|error| error as &dyn Error)
            })
            .or_else(|| {
                self.errors
                    .logging
                    .as_ref()
                    .map(|error| error as &dyn Error)
            })
    }
}
#[derive(Default)]
struct Turn<'id> {
    step: Option<(Result<Step<'id>, cadet::Error>, Start)>,
    signal: Option<io::Result<()>>,
    input: Option<(io::Result<usize>, Start)>,
    output: Option<io::Result<usize>>,
    resolver: Option<Result<gnunet_resolver_broker::Progress, BrokerError>>,
    failure: Option<Cause>,
    local: bool,
}
impl Turn<'_> {
    fn ready(&self) -> bool {
        self.step.is_some()
            || self.signal.is_some()
            || self.input.is_some()
            || self.output.is_some()
            || self.resolver.is_some()
            || self.failure.is_some()
            || self.local
    }
}
struct Driving<'a> {
    stdio: &'a mut Stdio,
    control: &'a mut Control,
    settings: &'a Settings,
    source: Arc<dyn RuntimeClock>,
    resolver: &'a mut Driver<128, 256>,
    reporter: &'a Reporter,
    report: &'a mut Report,
    errors: &'a mut Errors,
}
async fn drive<'id>(client: &mut Client<'id, '_>, state: &mut State<'id>, ports: Driving<'_>) {
    let Driving {
        stdio,
        control,
        settings: inputs,
        source,
        resolver,
        reporter,
        report,
        errors,
    } = ports;
    let mut alarm = Alarm::new(source.clone());
    let mut native_pause = Box::pin(tokio::time::sleep(Duration::ZERO));
    let mut echo_alarm = Box::pin(tokio::time::sleep(Duration::ZERO));
    let mut echo_target = None;
    let mut closing_alarm = None;
    let mut cursor = 0;
    loop {
        let turn = {
            let mut resolving =
                std::pin::pin!(resolver.drive_waiting(None, |event| reporter.debug(
                    "cadet.resolver.activity",
                    format_args!("Resolver: {event:?}")
                )));
            poll_fn(|cx| {
                let mut turn = Turn::default();
                reporter.register(cx);
                // Native checks/registration precede constructing/sampling any
                // canonical deadline or driving a new Resolver/provider effect.
                if let Some(hard) = state.close_hard {
                    let timer = closing_alarm
                        .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(hard)));
                    if Instant::now() >= hard || timer.as_mut().poll(cx).is_ready() {
                        turn.failure = Some(
                            io::Error::new(
                                io::ErrorKind::TimedOut,
                                "original CADET cleanup hard expired",
                            )
                            .into(),
                        );
                        return Poll::Ready(turn);
                    }
                }
                if let Err(error) = alarm.set(cx, state.budgets()).and_then(|()| alarm.poll(cx)) {
                    turn.failure = Some(Box::new(error));
                    return Poll::Ready(turn);
                }
                if reporter.failed() {
                    turn.signal = Some(Ok(()));
                    return Poll::Ready(turn);
                }
                if !state.closing
                    && let Poll::Ready(result) = control.poll(cx)
                {
                    turn.signal = Some(result);
                    return Poll::Ready(turn);
                }
                for offset in 0..4 {
                    if reporter.failed() {
                        turn.signal = Some(Ok(()));
                        break;
                    }
                    if let Err(error) = alarm.native_guard(cx) {
                        turn.failure = Some(Box::new(error));
                        break;
                    }
                    if state.close_hard.is_some_and(|hard| Instant::now() >= hard) {
                        turn.failure = Some(
                            io::Error::new(
                                io::ErrorKind::TimedOut,
                                "original CADET cleanup hard expired",
                            )
                            .into(),
                        );
                        break;
                    }
                    match (cursor + offset) % 4 {
                        0 => {
                            let start = match Start::sample(&source) {
                                Ok(start) => start,
                                Err(error) => {
                                    turn.failure = Some(Box::new(error));
                                    break;
                                }
                            };
                            if let Err(error) = alarm.native_guard(cx) {
                                turn.failure = Some(Box::new(error));
                                break;
                            }
                            match state.admit(client, start, inputs, report) {
                                Ok(progress) => turn.local |= progress,
                                Err(error) => {
                                    turn.failure = Some(error);
                                    break;
                                }
                            }
                            if let Err(error) =
                                alarm.set(cx, state.budgets()).and_then(|()| alarm.poll(cx))
                            {
                                turn.failure = Some(Box::new(error));
                                break;
                            }
                            if native_pause.as_mut().poll(cx).is_ready()
                                && let Poll::Ready(result) = client.poll(cx, alarm.hard())
                            {
                                if matches!(&result, Ok(Step::Blocked { .. })) {
                                    native_pause
                                        .as_mut()
                                        .reset(Instant::now() + Duration::from_millis(25));
                                }
                                turn.step = Some((result, start));
                            }
                        }
                        1 => {
                            if state.can_output(inputs) {
                                match state.output() {
                                    Err(error) => {
                                        turn.failure = Some(Box::new(error));
                                        break;
                                    }
                                    Ok(Some(bytes)) if !bytes.is_empty() => {
                                        let maximum = bytes.len().min(inputs.io_bytes).min(512);
                                        if let Poll::Ready(result) =
                                            stdio.write(cx, &bytes[..maximum])
                                        {
                                            turn.output = Some(result);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        2 => {
                            if state.can_input(inputs) {
                                let start = match Start::sample(&source) {
                                    Ok(start) => start,
                                    Err(error) => {
                                        turn.failure = Some(Box::new(error));
                                        break;
                                    }
                                };
                                if let Err(error) = alarm.native_guard(cx) {
                                    turn.failure = Some(Box::new(error));
                                    break;
                                }
                                if let Poll::Ready(result) = stdio.read(cx, state.input_space()) {
                                    turn.input = Some((result, start));
                                }
                            }
                        }
                        _ => {
                            if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                                turn.resolver = Some(result);
                            }
                        }
                    }
                    if matches!(
                        &turn.step,
                        Some((
                            Err(_) | Ok(Step::Lost { .. } | Step::Unavailable(_) | Step::Closed),
                            _
                        ))
                    ) || matches!(&turn.output, Some(Err(_)))
                        || matches!(&turn.input, Some((Err(_), _)))
                        || matches!(&turn.resolver, Some(Err(_)))
                    {
                        break;
                    }
                }
                cursor = (cursor + 1) % 4;
                let next = state.probe_wakeup();
                if next != echo_target {
                    echo_target = next;
                    if let Some(at) = next {
                        echo_alarm.as_mut().reset(at);
                    }
                }
                if next.is_some() && echo_alarm.as_mut().poll(cx).is_ready() {
                    turn.local = true;
                }
                if turn.ready() {
                    Poll::Ready(turn)
                } else {
                    Poll::Pending
                }
            })
            .await
        };
        let mut stop = false;
        let mut abort = false;
        if let Some(error) = turn.failure {
            errors.record(error);
            abort = true;
        }
        if let Some(result) = turn.signal {
            if let Err(error) = result {
                errors.signal = Some(error);
                abort = true;
            }
            stop = true;
            if reporter.failed() {
                abort = true;
            }
        }
        if let Some(result) = turn.resolver
            && let Err(error) = result
        {
            errors.resolver = Some(error);
            abort = true;
        }
        if let Some(result) = turn.output {
            match result {
                Ok(0) => {
                    errors.output = Some(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "stdout accepted zero bytes of a nonempty payload",
                    ));
                    abort = true;
                }
                Ok(count) => {
                    if let Err(error) = state.wrote_output(count, report) {
                        errors.record(Box::new(error));
                        abort = true;
                    }
                }
                Err(error) => {
                    errors.output = Some(error);
                    abort = true;
                }
            }
        }
        if let Some((result, start)) = turn.input {
            match result {
                Ok(0) => stop = true,
                Ok(count) => match start
                    .budget(inputs.operation)
                    .and_then(|budget| state.read_input(count, budget, report))
                {
                    Ok(()) => {}
                    Err(error) => {
                        errors.record(Box::new(error));
                        abort = true;
                    }
                },
                Err(error) => {
                    errors.input = Some(error);
                    abort = true;
                }
            }
        }
        if let Some((result, start)) = turn.step {
            match result {
                Err(error) => {
                    errors.native = Some(error);
                    abort = true;
                }
                Ok(event) => {
                    if let Step::ConnectRetry { error, .. } = &event {
                        reporter.warning(
                            "cadet.connect.retry",
                            format_args!("original CADET connection attempt: {error}"),
                        );
                    }
                    let echoes = report.echoes;
                    match state.step(event, start, inputs, report) {
                        Ok(Event::Continue) => {}
                        Ok(Event::End) => stop = true,
                        Ok(Event::Lost(cause)) => {
                            errors.loss = Some(cause);
                            abort = true;
                        }
                        Ok(Event::Failure(error)) => {
                            errors.native = Some(error);
                            abort = true;
                        }
                        Err(error) => {
                            errors.record(error);
                            abort = true;
                        }
                    }
                    if report.echoes != echoes {
                        reporter.message(
                            gnunet_program_host::policy::Level::INFO,
                            "cadet.echo.reply",
                            format_args!(
                                "echo round trip: {:?} microseconds",
                                report.last_echo_micros
                            ),
                        );
                    }
                }
            }
        }
        if abort || reporter.failed() {
            break;
        }
        if stop && let Err(error) = state.start_close(inputs, report) {
            errors.record(Box::new(error));
            break;
        }
        if state.finished() {
            break;
        }
        tokio::task::yield_now().await;
    }
}
pub(super) async fn run(inputs: Inputs) -> Result<Report, Cause> {
    let Inputs {
        settings,
        live,
        context,
        mut resolver,
        source,
        reporter,
        stop,
        parent,
        input,
        output,
    } = inputs;
    let mut report = Report::default();
    let mut errors = Errors::default();
    let mut instance = cadet::Instance::new();
    let mut ports = [cadet::PortSlot::new(); 1];
    let mut channels = [cadet::ChannelSlot::new(); 2];
    let outcome = async {
        let mut control = Control::new(parent, stop, reporter.clone())?;
        let mut stdio = Stdio::new(input, output);
        let initial = Start::sample(&source)?.budget(settings.operation)?;
        let mut state = State::new(&settings, initial)?;
        let endpoint = EndpointSource::live(live, b"cadet", context.resolution_context());
        let mut client = Client::new(
            &mut instance,
            endpoint,
            &mut ports,
            &mut channels,
            cadet::Limits {
                io_slice_bytes: settings.io_bytes,
                ..cadet::Limits::default()
            },
        )?;
        // No `?` after constructing the real client: every terminal branch
        // returns through the same close below before Resolver disconnect.
        drive(
            &mut client,
            &mut state,
            Driving {
                stdio: &mut stdio,
                control: &mut control,
                settings: &settings,
                source,
                resolver: &mut resolver,
                reporter: &reporter,
                report: &mut report,
                errors: &mut errors,
            },
        )
        .await;
        state.final_metadata(&mut report);
        match client.close() {
            Ok(loss) => report.close_loss = loss.map(SourceMeta::from_loss),
            Err(error) => errors.close = Some(error),
        }
        drop(client);
        drop(state);
        Ok::<(), Cause>(())
    }
    .await;
    if let Err(error) = outcome {
        errors.record(error);
    }
    if let Err(error) = resolver.disconnect() {
        errors.resolver_close = Some(error);
    }
    drop(resolver);
    reporter.debug(
        "cadet.stream.stopped",
        format_args!("actual local transfer/close facts: {report:?}"),
    );
    errors.logging = reporter.take_error();
    if errors.failed() {
        Err(Box::new(Failed { report, errors }))
    } else {
        Ok(report)
    }
}
