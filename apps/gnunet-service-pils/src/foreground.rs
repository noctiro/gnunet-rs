//! Common authority, original stop subscription and physical source retirement.
use super::Failure;
use gnunet_pils_host::{
    service::{CloseCause, Handled, Progress},
    startup::{ForegroundExit, Prepared, foreground_listening_with_async_ready},
};
use gnunet_program_host::{policy::Level, reporting::Reporter, service};
use gnunet_service_runtime::{BoundListeners, accepted::SocketEvent};
use gnunet_service_startup::StopSignals;
use std::{
    future::{Future, poll_fn},
    io::{self, Write},
    task::Poll,
    time::Duration,
};

fn observe(reports: &Reporter, progress: &Progress) {
    if matches!(
        progress,
        Progress::Request {
            handled: Handled::Reply {
                crypto_error: Some(_)
            },
            ..
        } | Progress::AdmissionFailed { .. }
            | Progress::ClientClosed {
                cause: CloseCause::Io(_) | CloseCause::Protocol(_) | CloseCause::Output { .. },
                ..
            }
    ) {
        reports.warning("pils.service", format_args!("pils service: {progress:?}"));
    }
}
pub(super) async fn run(
    prepared: Prepared,
    bound: BoundListeners,
    mut stop: StopSignals,
    reports: Reporter,
    notification: impl Future<Output = Result<(), Failure>>,
) -> Result<(), Failure> {
    let outcome = foreground_listening_with_async_ready(
        prepared,
        bound,
        async |listeners: &BoundListeners, peer: [u8; 32]| {
            for error in listeners.failures() {
                reports.warning(
                    "pils.listener.alternate",
                    format_args!("pils alternate listener: {error}"),
                );
            }
            if reports.failed() {
                return Err(io::Error::other("PILS logger failed before readiness").into());
            }
            {
                let mut output = io::stdout().lock();
                write!(output, "READY ")?;
                for byte in peer {
                    write!(output, "{byte:02x}")?;
                }
                writeln!(output)?;
                output.flush()?;
            }
            let mut alarm = std::pin::pin!(tokio::time::sleep(Duration::from_secs(10)));
            let mut notification = std::pin::pin!(notification);
            poll_fn(|cx| {
                if alarm.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "PILS readiness acknowledgement deadline",
                    )
                    .into()));
                }
                notification.as_mut().poll(cx)
            })
            .await
        },
        poll_fn(|cx| {
            reports.register(cx);
            if reports.failed() {
                return Poll::Ready(Ok(()));
            }
            stop.poll_stop(cx).map_err(io::Error::other)
        }),
        |event| {
            if matches!(&event, SocketEvent::Failed(error) if error.is_emfile()) {
                return;
            }
            let level = if matches!(&event, SocketEvent::Failed(_)) {
                Level::WARNING
            } else {
                Level::DEBUG
            };
            reports.message(level, "pils.socket", format_args!("pils socket: {event:?}"));
        },
        |progress| {
            observe(&reports, progress);
            Ok(())
        },
    )
    .await;
    let (report, result) = match outcome {
        Ok(ForegroundExit::AfterReady(report)) => (report, Ok(())),
        Ok(ForegroundExit::BeforeReady(report)) if reports.failed() => (report, Ok(())),
        Ok(ForegroundExit::BeforeReady(report)) => (
            report,
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "PILS stopped before readiness acknowledgement",
            )
            .into()),
        ),
        Err(error) => (error.report(), Err(Box::new(error) as Failure)),
    };
    let result = service::retain_diagnostic(result, reports.take_error());
    let output = (|| -> io::Result<()> {
        let mut output = io::stdout().lock();
        writeln!(output, "STOPPED {report:?}")?;
        output.flush()
    })();
    service::retain_diagnostic(result, output.err())
}
