//! Fair original CADET, Resolver and stdio polling.
use super::failure::Errors;
use crate::{
    Cause,
    budget::{Alarm, Start},
    options::Settings,
    state::{Event, Report, State},
    stdio::Stdio,
};
use gnunet_cadet_host::{self as cadet, Client, Step};
use gnunet_program_host::{foreground::Stop as Control, reporting::Reporter};
use gnunet_resolver_broker::{BrokerError, Driver};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_service_startup::StopError;
use std::{
    future::{Future, poll_fn},
    io,
    sync::Arc,
    task::Poll,
    time::Duration,
};
use tokio::time::Instant;

#[derive(Default)]
struct Turn<'id> {
    step: Option<(Result<Step<'id>, cadet::Error>, Start)>,
    signal: Option<Result<(), StopError>>,
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
pub(super) struct Driving<'a> {
    pub(super) stdio: &'a mut Stdio,
    pub(super) control: &'a mut Control,
    pub(super) settings: &'a Settings,
    pub(super) source: Arc<dyn RuntimeClock>,
    pub(super) resolver: &'a mut Driver<128, 256>,
    pub(super) reporter: &'a Reporter,
    pub(super) report: &'a mut Report,
    pub(super) errors: &'a mut Errors,
}
pub(super) async fn drive<'id>(
    client: &mut Client<'id, '_>,
    state: &mut State<'id>,
    ports: Driving<'_>,
) {
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
