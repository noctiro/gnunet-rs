//! Fair polling of the original query, native output and Resolver.
use super::report::{Errors, Observed, Report, observation, observed, take_errors};
use super::{Budget, Callback, Cause, Control, Line, Output, Request, Settings};
use crate::output;
use gnunet_program_host::reporting::Reporter;
use gnunet_resolver_broker::{BrokerError, Completion, Context as Broker, Driver, Query, Token};
use gnunet_service_startup::StopError;
use std::{
    cell::Cell,
    future::{Future, poll_fn},
    io,
    task::Poll,
};

#[derive(Default)]
struct Turn {
    callback: Option<Result<Option<Callback>, Cause>>,
    output: Option<io::Result<usize>>,
    driver: Option<Result<gnunet_resolver_broker::Progress, BrokerError>>,
    signal: Option<Result<(), StopError>>,
    failure: Option<Cause>,
}
impl Turn {
    fn ready(&self) -> bool {
        self.callback.is_some()
            || self.output.is_some()
            || self.driver.is_some()
            || self.signal.is_some()
            || self.failure.is_some()
    }
}
pub(super) struct Driving<'a> {
    pub(super) budget: &'a mut Budget,
    pub(super) output: &'a mut Output,
    pub(super) control: &'a mut Control,
    pub(super) driver: &'a mut Driver<16, 64>,
    pub(super) reporter: &'a Reporter,
    pub(super) settings: &'a Settings,
    pub(super) report: &'a mut Report,
    pub(super) errors: &'a mut Errors,
    pub(super) pending: &'a mut Option<Line>,
}
pub(super) async fn active(query: &mut Query<16, 64>, ports: Driving<'_>) {
    let Driving {
        budget,
        output,
        control,
        driver,
        reporter,
        settings,
        report,
        errors,
        pending,
    } = ports;
    let expected: Token = query.token();
    let reverse = matches!(&settings.request, Request::Reverse(_));
    let events = Cell::new(Observed::default());
    let mut cursor = 0;
    let mut queued_bytes = 0usize;
    loop {
        events.set(Observed::default());
        let turn = {
            let mut reading = std::pin::pin!(query.next());
            let mut driving =
                std::pin::pin!(driver.drive_waiting(Some(budget.hard), |event| observation(
                    event, &events, reporter
                )));
            poll_fn(|cx| {
                let mut turn = Turn::default();
                reporter.register(cx);
                if let Err(error) = budget.poll(cx) {
                    turn.failure = Some(Box::new(error));
                    return Poll::Ready(turn);
                }
                if let Poll::Ready(result) = control.poll(cx) {
                    turn.signal = Some(result);
                    return Poll::Ready(turn);
                }
                for offset in 0..3 {
                    if reporter.failed() {
                        turn.signal = Some(Ok(()));
                        break;
                    }
                    if let Err(error) = budget.native_guard(cx) {
                        turn.failure = Some(Box::new(error));
                        break;
                    }
                    match (cursor + offset) % 3 {
                        0 => {
                            if pending.is_none()
                                && let Poll::Ready(result) = reading.as_mut().poll(cx)
                            {
                                let value = match result {
                                    Err(error) => Err(Box::new(error) as Cause),
                                    Ok(None) => Ok(None),
                                    Ok(Some(delivery)) => {
                                        let result = if delivery.token() != &expected {
                                            Err("foreign Resolver callback token".into())
                                        } else {
                                            delivery
                                                .reply()
                                                .map_err(|error| Box::new(error) as Cause)
                                                .and_then(|reply| output::copy(reply, reverse))
                                                .map(Some)
                                        };
                                        drop(delivery);
                                        result
                                    }
                                };
                                turn.callback = Some(value);
                            }
                        }
                        1 => {
                            if let Poll::Ready(result) = driving.as_mut().poll(cx) {
                                turn.driver = Some(result);
                            }
                            let now = events.get();
                            if now.lost.is_some() || now.unavailable {
                                break;
                            }
                        }
                        _ => {
                            if let Some(line) = pending.as_mut()
                                && let Poll::Ready(result) = output.poll(cx, line)
                            {
                                turn.output = Some(result);
                            }
                        }
                    }
                    if matches!(
                        &turn.callback,
                        Some(Err(_) | Ok(None) | Ok(Some(Callback::Complete(_))))
                    ) || matches!(&turn.output, Some(Err(_)))
                        || matches!(&turn.driver, Some(Err(_)))
                    {
                        break;
                    }
                }
                cursor = (cursor + 1) % 3;
                if turn.ready() || events.get().changed {
                    Poll::Ready(turn)
                } else {
                    Poll::Pending
                }
            })
            .await
        };
        take_errors(driver, report);
        observed(events.get(), report, errors);
        if let Some(error) = turn.failure {
            errors.record(error);
        }
        if let Some(result) = turn.signal {
            report.stopped = true;
            if let Err(error) = result {
                errors.signal = Some(error);
            }
        }
        if let Some(result) = turn.driver
            && let Err(error) = result
        {
            errors.driver = Some(error);
        }
        if let Some(result) = turn.output {
            match result {
                Ok(count) => {
                    report.bytes_written = report.bytes_written.saturating_add(count);
                    if pending.as_ref().is_some_and(Line::finished) {
                        report.lines_written += 1;
                        drop(pending.take());
                    }
                }
                Err(error) => errors.output = Some(error),
            }
        }
        if let Some(result) = turn.callback {
            match result {
                Err(error) => errors.record(error),
                Ok(None) => {
                    report.stream_closed = true;
                    errors.record(
                        io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "original Resolver stream closed without a terminal callback",
                        )
                        .into(),
                    );
                }
                Ok(Some(Callback::Complete(reason))) => {
                    report.completion = Some(reason);
                    if reason != Completion::End {
                        errors.record(format!("original Resolver completion: {reason:?}").into());
                    }
                }
                Ok(Some(Callback::Line(line))) => {
                    report.rows += 1;
                    match queued_bytes.checked_add(line.len()) {
                        Some(bytes)
                            if report.rows <= settings.maximum_results
                                && bytes <= settings.maximum_output_bytes =>
                        {
                            queued_bytes = bytes;
                            *pending = Some(line);
                        }
                        _ => {
                            errors.record("bounded Resolver result/output capacity exceeded".into())
                        }
                    }
                }
            }
        }
        if errors.failed() || report.stopped || report.completion.is_some() || reporter.failed() {
            break;
        }
        tokio::task::yield_now().await;
    }
}
pub(super) async fn cleanup(ports: Driving<'_>, context: &Broker<16, 64>) {
    let Driving {
        budget,
        output,
        control: _,
        driver,
        reporter,
        settings: _,
        report,
        errors,
        pending,
    } = ports;
    let events = Cell::new(Observed::default());
    let mut cursor = 0;
    loop {
        if errors.failed() || reporter.failed() || report.stopped {
            break;
        }
        let need_driver = match context.pending_requests() {
            Ok(count) => {
                report.pending_requests = Some(count);
                if count == 0 && pending.is_none() {
                    break;
                }
                count != 0
            }
            Err(error) => {
                errors.driver = Some(error);
                break;
            }
        };
        events.set(Observed::default());
        let turn = {
            let mut driving =
                std::pin::pin!(driver.drive_waiting(Some(budget.hard), |event| observation(
                    event, &events, reporter
                )));
            poll_fn(|cx| {
                let mut turn = Turn::default();
                reporter.register(cx);
                if let Err(error) = budget.poll(cx) {
                    turn.failure = Some(Box::new(error));
                    return Poll::Ready(turn);
                }
                if reporter.failed() {
                    return Poll::Ready(turn);
                }
                for offset in 0..2 {
                    if reporter.failed() {
                        break;
                    }
                    if let Err(error) = budget.native_guard(cx) {
                        turn.failure = Some(Box::new(error));
                        break;
                    }
                    match (cursor + offset) % 2 {
                        0 => {
                            if need_driver && let Poll::Ready(result) = driving.as_mut().poll(cx) {
                                turn.driver = Some(result);
                            }
                            let now = events.get();
                            if now.lost.is_some() || now.unavailable {
                                break;
                            }
                        }
                        _ => {
                            if let Some(line) = pending.as_mut()
                                && let Poll::Ready(result) = output.poll(cx, line)
                            {
                                turn.output = Some(result);
                            }
                        }
                    }
                }
                cursor = (cursor + 1) % 2;
                if turn.ready() || events.get().changed {
                    Poll::Ready(turn)
                } else {
                    Poll::Pending
                }
            })
            .await
        };
        take_errors(driver, report);
        observed(events.get(), report, errors);
        if let Some(error) = turn.failure {
            errors.record(error);
        }
        if let Some(result) = turn.driver
            && let Err(error) = result
        {
            errors.driver = Some(error);
        }
        if let Some(result) = turn.output {
            match result {
                Ok(count) => {
                    report.bytes_written = report.bytes_written.saturating_add(count);
                    if pending.as_ref().is_some_and(Line::finished) {
                        report.lines_written += 1;
                        drop(pending.take());
                    }
                }
                Err(error) => errors.output = Some(error),
            }
        }
        tokio::task::yield_now().await;
    }
}
