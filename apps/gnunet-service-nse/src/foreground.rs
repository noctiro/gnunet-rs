//! Shared NSE service, source-bound statistics and selected diagnostics.
use super::{Failure, statistics};
use gnunet_config::Configuration;
use gnunet_nse_host::{Limits, startup};
use gnunet_program_host::{policy::Level, reporting::Reporter, service, shared_clock::SharedClock};
use gnunet_service_runtime::{BoundListeners, accepted::SocketEvent};
use gnunet_service_startup::StopSignals;
use std::{
    cell::Cell,
    future::{Future, poll_fn},
    io::{self, Write},
    sync::Arc,
    task::Poll,
};

pub(super) async fn run(
    config: &Configuration,
    bound: BoundListeners,
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
    let mut instance = gnunet_ipc_unix::handle::Instance::new();
    let result = startup::foreground_listening_with_clock(
        config,
        bound,
        Limits::default(),
        |bound, peer| {
            if ready.get() {
                return Ok(());
            }
            for error in bound.failures() {
                reports.warning(
                    "nse.listener.alternate",
                    format_args!("nse alternate listener: {error}"),
                );
            }
            if reports.failed() {
                return Err(io::Error::other(
                    "NSE selected logger failed before readiness",
                ));
            }
            let mut output = io::stdout().lock();
            write!(output, "READY ")?;
            for byte in peer {
                write!(output, "{byte:02x}")?;
            }
            writeln!(output)?;
            output.flush()?;
            ready.set(true);
            Ok(())
        },
        notification,
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
            reports.message(level, "nse.socket", format_args!("nse socket: {event:?}"));
        },
        Arc::new(clock),
        |failure| {
            reports.warning(
                "nse.admission",
                format_args!(
                    "nse unadmitted subscriber {:?}: {}",
                    failure.peer, failure.error
                ),
            );
            if reports.failed() {
                return Err(Box::new(failure.error) as Failure);
            }
            Ok(())
        },
        || reports.failed(),
        statistics::Factory::new(&mut instance),
    )
    .await;
    let report = service::retain_diagnostic(result, reports.take_error())?;
    if !ready.get() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "NSE stopped before actual activation",
        )
        .into());
    }
    let mut output = io::stdout().lock();
    writeln!(output, "STOPPED {report:?}")?;
    output.flush()?;
    Ok(())
}
