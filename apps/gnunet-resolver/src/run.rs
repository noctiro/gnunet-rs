//! One original query through callback, output and physical-source retirement.
use gnunet_program_host::foreground::Stop as Control;
mod drive;
mod report;
mod scheduling;
use crate::{
    Cause,
    budget::Budget,
    options::{Request, Settings},
    output::{Callback, Line, Output},
};
use drive::{Driving, active, cleanup};
use gnunet_program_host::reporting::Reporter;
use gnunet_resolver_broker::{Context as Broker, Driver, Family};
use gnunet_types::Duration;
use report::{Errors, Failed, Report, take_errors};
pub(super) use scheduling::scheduled;
use std::{future::poll_fn, io, task::Poll};

struct Inputs {
    settings: Settings,
    context: Broker<16, 64>,
    resolver: Driver<16, 64>,
    reporter: Reporter,
    control: Control,
    budget: Budget,
}
async fn run(inputs: Inputs) -> Result<Report, Cause> {
    let Inputs {
        settings,
        context,
        mut resolver,
        reporter,
        mut control,
        mut budget,
    } = inputs;
    let mut report = Report::default();
    let mut errors = Errors::default();
    let mut pending = None;
    let mut output_owner = None;
    let outcome = async {
        if control.stopped() {
            report.stopped = true;
            return Ok::<(), Cause>(());
        }
        if let Poll::Ready(result) = poll_fn(|cx| Poll::Ready(control.poll(cx))).await {
            report.stopped = true;
            result?;
            return Ok(());
        }
        let output = output_owner.insert(Output::new()?);
        let initial = poll_fn(|cx| {
            if let Err(error) = budget.poll(cx) {
                return Poll::Ready(Err(Box::new(error) as Cause));
            }
            Poll::Ready(Ok(control.poll(cx)))
        })
        .await?;
        if let Poll::Ready(result) = initial {
            report.stopped = true;
            result?;
            return Ok(());
        }
        let mut query = match &settings.request {
            Request::Forward(name) => context.ip_get(name, Family::Any, Duration(5_000_000))?,
            Request::Reverse(address) => {
                context.hostname_get(*address, true, Duration(5_000_000))?
            }
        };
        report.token = Some(query.token().resource_id());
        active(
            &mut query,
            Driving {
                budget: &mut budget,
                output,
                control: &mut control,
                driver: &mut resolver,
                reporter: &reporter,
                settings: &settings,
                report: &mut report,
                errors: &mut errors,
                pending: &mut pending,
            },
        )
        .await;
        if report.completion.is_none() && !report.stream_closed {
            match query.cancel() {
                Ok(()) => report.cancelled = true,
                Err(error) => errors.cancel = Some(error),
            }
        }
        drop(query);
        cleanup(
            Driving {
                budget: &mut budget,
                output,
                control: &mut control,
                driver: &mut resolver,
                reporter: &reporter,
                settings: &settings,
                report: &mut report,
                errors: &mut errors,
                pending: &mut pending,
            },
            &context,
        )
        .await;
        Ok(())
    }
    .await;
    if let Err(error) = outcome {
        errors.record(error);
    }
    take_errors(&mut resolver, &mut report);
    match context.pending_requests() {
        Ok(count) => report.pending_requests = Some(count),
        Err(error) => {
            if errors.driver.is_none() {
                errors.driver = Some(error);
            }
        }
    }
    match resolver.queued_frames() {
        Ok(count) => report.queued_frames = Some(count),
        Err(error) => {
            if errors.driver.is_none() {
                errors.driver = Some(error);
            }
        }
    }
    report.pending_line = pending.as_ref().map(|line| (line.len(), line.offset()));
    if let Err(error) = resolver.disconnect() {
        errors.disconnect = Some(error);
    } else {
        report.disconnect = true;
    }
    drop(resolver);
    report.driver_dropped = true;
    if let Some(output) = output_owner {
        let retired = output.retire().await;
        if let Some(count) = retired.written() {
            match pending
                .as_mut()
                .ok_or_else(|| io::Error::other("retired stdout lost its original line"))
                .and_then(|line| line.written(count))
            {
                Ok(()) => {
                    report.bytes_written = report.bytes_written.saturating_add(count);
                    if pending.as_ref().is_some_and(Line::finished) {
                        report.lines_written += 1;
                        drop(pending.take());
                    }
                }
                Err(error) => errors.record(Box::new(error)),
            }
        }
        report.output_closed = retired.closed();
        report.output_flushed = retired.flushed();
        if !retired.successful() {
            errors.output_retirement = Some(retired);
        }
    }
    report.pending_line = pending.as_ref().map(|line| (line.len(), line.offset()));
    drop(pending);
    reporter.debug(
        "resolver.query.stopped",
        format_args!("actual callback/output/close facts: {report:?}"),
    );
    errors.logging = reporter.take_error();
    if errors.failed() {
        Err(Box::new(Failed { report, errors }))
    } else {
        Ok(report)
    }
}
