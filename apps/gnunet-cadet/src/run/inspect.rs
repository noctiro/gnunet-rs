//! Installed management queries over one original bounded CADET query stream.
mod format;

use super::Inputs;
use crate::{Cause, budget::Alarm, options::Bounds, stdio::Stdio};
use gnunet_cadet_host::inspect::{Inspector, Limits, Query, Report, Step};
use gnunet_client_host::EndpointSource;
use gnunet_types::Error as Fault;
use std::{
    future::{Future, poll_fn},
    io,
    task::{Poll, ready},
};
use tokio::time::Instant;

#[derive(Debug)]
struct Failure {
    query: Option<Report>,
    original: Option<Cause>,
    stdout: Option<crate::stdio::Retired>,
    resolver: Option<gnunet_resolver_broker::BrokerError>,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str("CADET inspection failed")?;
        if let Some(cause) = &self.original {
            write!(out, ". {cause}")?;
        }
        if let Some(query) = self.query {
            write!(out, ". Received {} entries", query.entries)?;
        }
        if let Some(cause) = &self.stdout {
            write!(out, ". stdout retirement: {cause}")?;
        }
        if let Some(cause) = &self.resolver {
            write!(out, ". Resolver retirement: {cause}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.stdout.as_ref().map(|cause| cause as _))
            .or_else(|| self.resolver.as_ref().map(|cause| cause as _))
    }
}

pub(super) async fn run(query: Query, bounds: Bounds, mut inputs: Inputs) -> Result<Report, Cause> {
    // Only the lazy stdout origin is used by inspection.
    let mut stdio = Stdio::new(0);
    let mut report = None;
    let result = async {
        if Instant::now() >= inputs.initial.hard {
            return Err(Fault::Deadline.into());
        }
        let endpoint = EndpointSource::live(
            inputs.live.clone(),
            b"cadet",
            inputs.context.resolution_context(),
        );
        let mut inspector = Inspector::new(
            endpoint,
            query,
            Limits {
                io_slice_bytes: bounds.io_bytes,
                ..Limits::default()
            },
        )?;
        let result = drive(&mut inspector, &mut inputs, &mut stdio).await;
        report = Some(inspector.close());
        result
    }
    .await;

    let hard = Instant::now()
        .checked_add(bounds.cleanup)
        .unwrap_or_else(Instant::now);
    let stdout = stdio.retire(hard).await;
    let resolver = inputs.resolver.disconnect().err();
    if let Some(report) = report {
        inputs.reporter.debug(
            "cadet.inspection.stopped",
            format_args!("CADET inspection: {report:?}"),
        );
    }
    let cause = Failure {
        query: report,
        original: result.err(),
        stdout: (!stdout.successful()).then_some(stdout),
        resolver,
    };
    if cause.original.is_some() || cause.stdout.is_some() || cause.resolver.is_some() {
        Err(Box::new(cause))
    } else {
        report.ok_or_else(|| Fault::NotReady.into())
    }
}

async fn drive(
    inspector: &mut Inspector,
    inputs: &mut Inputs,
    stdio: &mut Stdio,
) -> Result<(), Cause> {
    let mut alarm = Alarm::new(inputs.source.clone());
    let mut row = Vec::<u8>::new();
    let mut offset = 0;
    poll_fn(|cx| {
        alarm.set(cx, std::iter::once(inputs.initial))?;
        alarm.poll(cx)?;
        if let Poll::Ready(stop) = inputs.control.poll(cx) {
            stop?;
            return Poll::Ready(Err(Fault::Cancelled.into()));
        }
        let mut resolving = std::pin::pin!(inputs.resolver.drive_waiting(
            Some(inputs.initial.hard),
            |event| inputs.reporter.debug(
                "cadet.resolver.activity",
                format_args!("Resolver: {event:?}")
            ),
        ));
        if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
            result?;
        }
        if offset < row.len() {
            let written = ready!(stdio.write(cx, &row[offset..]))?;
            if written == 0 || written > row.len() - offset {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "invalid CADET inspection stdout progress",
                )
                .into()));
            }
            offset += written;
        } else {
            match ready!(inspector.poll(cx, Some(inputs.initial.hard)))? {
                Step::Entry(entry) => {
                    format::row(&mut row, entry.response()?)?;
                    offset = 0;
                }
                Step::Complete(_) => return Poll::Ready(Ok(())),
                Step::Interrupted { cause, .. } | Step::Unavailable(cause) => {
                    return Poll::Ready(Err(cause.into()));
                }
                Step::WaitDeadline => return Poll::Ready(Err(Fault::Deadline.into())),
                Step::Closed => return Poll::Ready(Err(Fault::Closed.into())),
                Step::Retry { cause, .. } => inputs.reporter.debug(
                    "cadet.connect.retry",
                    format_args!("CADET inspection connection: {cause}"),
                ),
                Step::Connected | Step::Queued | Step::Written { .. } | Step::Activity => {}
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    })
    .await
}
