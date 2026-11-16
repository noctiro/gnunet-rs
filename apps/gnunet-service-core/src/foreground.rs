//! Shared CORE service, original stop subscriptions and selected diagnostics.
use super::Failure;
use gnunet_core_host::{Limits, startup::PreparedService};
use gnunet_program_host::{policy::Level, reporting::Reporter, service, shared_clock::SharedClock};
use gnunet_service_runtime::accepted::SocketEvent;
use gnunet_service_startup::StopSignals;
use std::{
    cell::Cell,
    future::{Future, poll_fn},
    io::{self, Write},
    sync::Arc,
    task::Poll,
};
pub(super) async fn run(
    prepared: PreparedService<'_>,
    mut stop: StopSignals,
    clock: SharedClock,
    reports: Reporter,
    notification: impl Future<Output = Result<(), Failure>>,
) -> Result<(), Failure> {
    let ready = Cell::new(false);
    let shutdown = poll_fn(|cx| {
        reports.register(cx);
        if reports.failed() {
            return Poll::Ready(Ok(()));
        }
        stop.poll_stop(cx)
            .map(|result| result.map_err(io::Error::other))
    });
    let result = prepared
        .foreground_with_readiness(
            Limits::default(),
            |bound, peer| {
                if ready.get() {
                    return Ok(());
                }
                for error in bound.failures() {
                    reports.warning(
                        "core.listener.alternate",
                        format_args!("CORE alternate listener: {error}"),
                    );
                }
                if reports.failed() {
                    return Err(io::Error::other(
                        "CORE selected logger failed before readiness",
                    ));
                }
                let mut output = io::stdout().lock();
                write!(output, "READY ")?;
                for byte in peer.0 {
                    write!(output, "{byte:02x}")?;
                }
                writeln!(output)?;
                output.flush()?;
                ready.set(true);
                Ok(())
            },
            shutdown,
            |event| {
                if matches!(&event, SocketEvent::Failed(error) if error.is_emfile()) {
                    return;
                }
                let level = if matches!(&event, SocketEvent::Failed(_)) {
                    Level::WARNING
                } else {
                    Level::DEBUG
                };
                reports.message(level, "core.socket", format_args!("CORE socket: {event:?}"));
            },
            Arc::new(clock),
            notification,
        )
        .await;
    let report = service::retain_diagnostic(result, reports.take_error())?;
    if !ready.get() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "CORE stopped before actual activation",
        )
        .into());
    }
    let mut output = io::stdout().lock();
    writeln!(output, "STOPPED {report:?}")?;
    output.flush()?;
    Ok(())
}
