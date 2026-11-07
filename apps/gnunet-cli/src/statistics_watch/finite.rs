//! Finite GET/SET on the shared configured native owner, one held row at a time.
use super::{
    Failure,
    control::Signals,
    driver::{self, Bound, Errors, Failed, Inputs, Report, ResolverOwner},
    output::Output,
};
use gnunet_client::statistics_handle::{
    DestroyOutcome, DestroyReport, GetFlow, GetId, SetterAdmission,
};
use gnunet_ipc_unix::{
    IpcError,
    handle::{self, Event, Progress},
};
use gnunet_types::Error;
use std::{
    cell::RefCell,
    future::{Future, poll_fn},
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::Poll,
    time::Duration,
};
use tokio::time::{Instant, Sleep};
// Full official 16-bit frame range, one request, no unused WATCH registration.
type Owner<'id> = handle::StatisticsHandle<'id, 1, 65535, 0, 0, 1>;
const HARD: Duration = Duration::from_secs(10);
const CADENCE: Duration = Duration::from_millis(10);
// Each name byte needs at most6 JSON string bytes and4 byte-array bytes.
// Lossy UTF-8 adds no larger expansion. One full wire row fits below this cap.
const OUTPUT: usize = 1024 * 1024;
#[derive(Clone, Copy)]
pub(super) enum Mutation {
    Absolute(u64),
    Relative(i64),
}
#[derive(Clone, Copy)]
pub(super) enum Action {
    Get,
    Set { value: Mutation, persistent: bool },
}
struct Events<'id> {
    get: Option<GetId<'id>>,
    completed: bool,
    destroyed: Option<DestroyReport>,
    retry: bool,
    failed: Option<Failure>,
}
impl<'id> Events<'id> {
    fn callback(
        &mut self,
        event: Event<'id, '_>,
        output: &mut Output,
        report: &mut Report,
    ) -> GetFlow {
        match event {
            Event::GetValue { get, statistic } => {
                report.notifications = report.notifications.saturating_add(1);
                if Some(get) != self.get || self.completed {
                    self.failed = Some(Box::new(Error::Stale));
                } else if let Err(error) = output.stage_get(statistic) {
                    self.failed = Some(error);
                }
            }
            Event::GetComplete(completion) => {
                if Some(completion.get) != self.get || self.completed {
                    self.failed = Some(Box::new(Error::Stale));
                } else {
                    self.completed = true;
                    if let Err(error) = completion.result {
                        self.failed = Some(Box::new(error));
                    }
                }
            }
            Event::Connected(epoch) => {
                report.epochs = report.epochs.saturating_add(1);
                report.current_epoch = Some(epoch.value());
            }
            Event::ConnectRetry { .. } | Event::ConnectionUnavailable { .. } => {
                self.retry = true;
            }
            Event::ConnectionLost { epoch, cause } => {
                report.losses = report.losses.saturating_add(1);
                report.last_loss = Some((epoch.value(), cause));
                report.current_epoch = None;
                self.failed.get_or_insert_with(|| Box::new(cause));
            }
            Event::Destroyed(value) => {
                self.destroyed = Some(value);
                report.current_epoch = None;
            }
            _ => {}
        }
        if self.failed.is_some() {
            GetFlow::AbortIteration
        } else {
            GetFlow::Continue
        }
    }
}
pub(super) async fn command(inputs: Inputs, action: Action) -> Result<Report, Failure> {
    let Inputs {
        selector,
        parent,
        live,
        resolution,
        source,
        reports,
        stop: latch,
        resolver,
    } = inputs;
    let cleanup = Rc::new(RefCell::new(None));
    let mut resolver = ResolverOwner {
        driver: resolver,
        cleanup: cleanup.clone(),
        closed: false,
    };
    let mut report = Report::default();
    let mut errors = Errors::default();
    let mut instance = handle::Instance::new();
    let mut owner: Option<Owner<'_>> = None;
    let mut output = None;
    let mut events = Events {
        get: None,
        completed: false,
        destroyed: None,
        retry: false,
        failed: None,
    };
    let mut destroy_started = false;
    let mut original_hard = None;
    let result: Result<(), Failure> = async {
        if latch.get() || reports.failed() {
            return Err("STATISTICS stopped before native admission".into());
        }
        let mut signals = Signals::new(parent)?;
        let mut bound = Bound::new(HARD)?;
        original_hard = Some(bound.hard);
        output = Some(Output::with_capacity(OUTPUT)?);
        let output = output.as_mut().ok_or("original stdout owner absent")?;
        let marker = gnunet_client_host::EndpointSource::live(
            live.clone(),
            b"statistics",
            resolution.clone(),
        );
        if !Arc::ptr_eq(&marker.clock(), &source) {
            return Err("STATISTICS actual clock source mismatch".into());
        }
        owner = Owner::from_live_config(
            &mut instance,
            live,
            resolution,
            &selector.subsystem,
            handle::Limits {
                max_frame_bytes: 65535,
                write_chunk_bytes: 4096,
            },
        )?;
        let current = owner
            .as_mut()
            .ok_or("configured STATISTICS disabled; no original request admitted")?;
        let mut noop = false;
        match action {
            Action::Get => {
                events.get = Some(current.get(selector.selector())?);
            }
            Action::Set { value, persistent } => {
                let admission = match value {
                    Mutation::Absolute(value) => current.set(&selector.name, value, persistent)?,
                    Mutation::Relative(delta) => {
                        current.update(&selector.name, delta, persistent)?
                    }
                };
                noop = admission == SetterAdmission::Noop;
                if !noop {
                    // Admit exactly once, then retain this same owner's original
                    // queued envelope/barrier. No is_idle wait may erase the C API's
                    // non-transmitted-length condition for destroy(true).
                    current.destroy(true)?;
                    destroy_started = true;
                }
            }
        }
        let mut terminal = false;
        let mut cursor = false;
        let mut retry: Option<Pin<Box<Sleep>>> = None;
        loop {
            if bound.expired() {
                errors.deadline = true;
                break;
            }
            if let Some(error) = events.failed.take() {
                return Err(error);
            }
            if events.retry {
                report.connect_retries = report.connect_retries.saturating_add(1);
                events.retry = false;
                driver::harvest_retry(current, &mut report, &reports);
            }
            if !terminal && output.pending().1 == 0 {
                match action {
                    Action::Get if events.completed => {
                        output.stage_terminal(Some(report.rows_written), false)?;
                        terminal = true;
                    }
                    Action::Set { .. } if noop => {
                        output.stage_terminal(None, true)?;
                        terminal = true;
                    }
                    Action::Set { .. } => {
                        if let Some(receipt) = events.destroyed {
                            if receipt.outcome != DestroyOutcome::ProcessingConfirmed
                                || receipt.queued_mutations_discarded != 0
                                || receipt.unconfirmed_mutations != 0
                                || receipt.unconfirmed_persistent_mutations != 0
                            {
                                return Err(format!(
                                    "original SET lacks processing confirmation: {receipt:?}"
                                )
                                .into());
                            }
                            output.stage_terminal(None, false)?;
                            terminal = true;
                        }
                    }
                    _ => {}
                }
            }
            enum Step {
                Native(Result<Progress, IpcError>),
                Resolver(Result<(), Failure>),
                Output,
                Stop,
                Expired,
            }
            let held = output.pending().1 != 0;
            let step = {
                let mut driving = std::pin::pin!(current.drive(None, |event, _| events.callback(
                    event,
                    output,
                    &mut report
                )));
                let diagnostic = reports.clone();
                let mut resolving = std::pin::pin!(resolver.driver.drive_waiting(None, |event| {
                    diagnostic.debug(
                        "statistics.resolver",
                        format_args!("original Resolver={event:?}"),
                    )
                }));
                // A held row owns the original GET and prevents another input
                // read. Constructing an unpolled drive has no native side effect.
                poll_fn(|cx| {
                    if bound.guard(cx) {
                        return Poll::Ready(Ok(Step::Expired));
                    }
                    if driver::stop(cx, &mut signals, &reports, &latch)? {
                        return Poll::Ready(Ok(Step::Stop));
                    }
                    if held {
                        // The exact same logical clock is checked before every
                        // stdout effect; native time still bounds a stalled line.
                        source.sample()?;
                        if !cursor && let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                            return Poll::Ready(Ok(Step::Resolver(
                                result.map(|_| ()).map_err(|e| Box::new(e) as Failure),
                            )));
                        }
                        if retry
                            .as_mut()
                            .is_none_or(|timer| timer.as_mut().poll(cx).is_ready())
                        {
                            retry = None;
                            // The native future borrows output until dropped;
                            // stdout is driven in the outer branch below.
                            return Poll::Ready(Ok(Step::Output));
                        }
                        if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                            return Poll::Ready(Ok(Step::Resolver(
                                result.map(|_| ()).map_err(|e| Box::new(e) as Failure),
                            )));
                        }
                        return Poll::Pending;
                    }
                    for offset in 0..2 {
                        if reports.failed() || latch.get() {
                            return Poll::Ready(Ok(Step::Stop));
                        }
                        let resolve = (usize::from(cursor) + offset) % 2 == 0;
                        if resolve {
                            if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                                return Poll::Ready(Ok(Step::Resolver(
                                    result.map(|_| ()).map_err(|e| Box::new(e) as Failure),
                                )));
                            }
                        } else if let Poll::Ready(result) = driving.as_mut().poll(cx) {
                            return Poll::Ready(Ok(Step::Native(result)));
                        }
                    }
                    Poll::Pending
                })
                .await
            };
            cursor = !cursor;
            // Recheck original guards after an async wait, before stdout writes.
            if bound.expired() {
                errors.deadline = true;
            }
            match step {
                Err(error) => return Err(error),
                Ok(Step::Stop) => {
                    return Err("original STATISTICS command cancelled".into());
                }
                Ok(Step::Expired) => {
                    errors.deadline = true;
                    break;
                }
                Ok(Step::Native(Err(error))) => {
                    errors.native = Some(error);
                    break;
                }
                Ok(Step::Native(Ok(Progress::Closed))) if events.destroyed.is_none() => {
                    errors.protocol = Some(Error::Closed);
                    break;
                }
                Ok(Step::Resolver(Err(error))) => {
                    errors.resolver = Some(error);
                    break;
                }
                Ok(Step::Output) if !errors.deadline => match output.step() {
                    Ok(Some(true)) => {
                        output.release();
                        retry = None;
                        if terminal {
                            break;
                        }
                        report.rows_written =
                            report.rows_written.checked_add(1).ok_or(Error::Overflow)?;
                    }
                    Ok(Some(false)) => {
                        // Positive byte progress has no artificial cadence wait.
                        retry = None;
                        tokio::task::yield_now().await;
                    }
                    Ok(None) => {
                        let next = Instant::now()
                            .checked_add(CADENCE)
                            .ok_or(Error::Overflow)?
                            .min(bound.hard);
                        retry = Some(Box::pin(tokio::time::sleep_until(next)));
                    }
                    Err(error) => {
                        errors.output = Some(error);
                        break;
                    }
                },
                _ => {}
            }
            if errors.deadline {
                break;
            }
        }
        Ok(())
    }
    .await;
    if let Err(error) = result {
        errors.original = Some(error);
    }
    if let Some(output) = &mut output {
        let (prefix, total) = output.pending();
        report.output_prefix = prefix;
        report.output_total = total;
        errors.stdout_flush = output.flush().err();
        if original_hard.is_some_and(|hard| Instant::now() >= hard) {
            errors.deadline = true;
        }
    }
    if let Some(current) = owner.as_mut() {
        driver::harvest_terminal(current, &mut errors);
        if let Some(get) = events.get
            && current.owns_get(get)
        {
            match current.get_cancel(get) {
                Ok(()) => report.cancelled_original = true,
                Err(error) => errors.cancel = Some(error),
            }
        }
    }
    driver::retire(
        &mut owner,
        &mut events.destroyed,
        destroy_started,
        &mut resolver.driver,
        &reports,
        &mut report,
        &mut errors,
    )
    .await;
    resolver.close();
    errors.resolver_close = cleanup.borrow_mut().take();
    errors.logging = reports.take_error();
    if errors.failed() {
        Err(Box::new(Failed { errors, report }))
    } else {
        Ok(report)
    }
}
