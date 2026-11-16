//! Actual room/stdin/history owner; every source and original future stays local.
mod admission;
mod alarm;
mod events;
mod lookup;
mod scheduling;
mod state;
use crate::{
    Failure,
    input::Input,
    options::{INPUT_BYTES, Settings},
    output::{self, Failures, Report},
};
use admission::advance;
use alarm::Alarm;
use events::{before_source_loss, progress, unavailable_input};
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
use gnunet_program_host::{binary_io, foreground::Stop as Signals, reporting::Reporter};
use gnunet_resolver_broker::{Context as Broker, Driver};
use gnunet_service_runtime::clock::{Deadline as LogicalDeadline, RuntimeClock};
use gnunet_service_startup::StopError;
use gnunet_types::{AbsoluteTime, Error as Fault};
use lookup::{LookupInputs, lookup};
pub(super) use scheduling::scheduled;
use state::*;
use std::{
    collections::VecDeque,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
use zeroize::{Zeroize, Zeroizing};
struct Inputs {
    pub settings: Settings,
    pub live: LiveConfiguration,
    pub context: Broker<128, 256>,
    pub resolver: Driver<128, 256>,
    pub source: Arc<dyn RuntimeClock>,
    pub reporter: Reporter,
    pub signals: Signals,
    pub initial: gnunet_service_runtime::clock::Bounds,
}
struct Turn<'id> {
    stop: Option<Result<(), StopError>>,
    api: Option<Result<Progress<'id>, messenger::Error>>,
    resolver: Option<gnunet_resolver_broker::BrokerError>,
    input: Option<io::Result<usize>>,
    output: Option<io::Result<output::Written>>,
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
            output: None,
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
            || self.output.is_some()
            || self.activity
            || self.expired
            || self.clock.is_some()
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "One lexical scope owns original branded Instances, Api, buffers and all physical cleanup without self references or leaked storage"
)]
async fn run(input: Inputs) -> Result<Report, Failure> {
    let Inputs {
        mut settings,
        live,
        context,
        mut resolver,
        source,
        reporter,
        mut signals,
        initial,
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
        initial.check(source.as_ref())?;
        if signals.stopped() {
            return Ok(());
        }
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
                initial,
            })
            .await?
            else {
                return Ok(());
            };
            secret
        } else {
            identity::SecretKey::anonymous()
        };
        initial.check(source.as_ref())?;
        let mut state = State::new(&settings)?;
        let mut input = Input::new();
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
            let mut alarm = Alarm::new(source.clone(), initial);
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
                if state.ever_joined {
                    alarm.startup = None;
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
                        if let Poll::Ready(output) = state.output.poll(cx) {
                            let failed = output.is_err();
                            turn.output = Some(output);
                            if failed {
                                return Poll::Ready(turn);
                            }
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
                if let Some(result) = turn.output {
                    match result {
                        Ok(written) => {
                            let _actual_bytes = written.bytes;
                            report.displayed = report.displayed.saturating_add(written.displayed);
                        }
                        Err(error) => errors.output = Some(error),
                    }
                }
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
        let hard = match state
            .close
            .map(Deadline::hard)
            .or_else(|| Instant::now().checked_add(settings.cleanup))
        {
            Some(hard) => hard,
            None => {
                errors.record_original(Box::new(Fault::Overflow));
                Instant::now()
            }
        };
        if !errors.failed()
            && !reporter.failed()
            && let Err(error) = state.output.drain(hard, &mut report, &reporter).await
        {
            errors.output = Some(error);
        }
        let retired =
            binary_io::settle([input.retire(), state.output.retire()], hard.into_std()).await;
        if let Some(input) = retired.get(0) {
            report.retired_input_bytes = input.count();
            report.input_closed = Some(input.closed().is_some_and(|closed| closed.close.is_none()));
            report.input_cancelled = Some(input.read_cancelled());
        }
        if let Some(output) = retired.get(1) {
            if let Some(count) = output.count()
                && let Err(error) = state.output.late(count, &mut report)
            {
                errors.output = Some(error);
            }
            report.output_closed =
                Some(output.closed().is_some_and(|closed| closed.close.is_none()));
            report.output_flushed =
                Some(output.closed().is_some_and(|closed| closed.flush.is_none()));
        }
        state.output.snapshot(&mut report);
        if !retired.successful() {
            errors.stdio = Some(retired);
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
