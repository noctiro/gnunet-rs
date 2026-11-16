//! Common authority, original stop subscription and physical source retirement.
use super::Failure;
use gnunet_pils_host::{
    service::{CloseCause, Handled, Progress},
    startup::Prepared,
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
    let mut host = prepared.into_host();
    let listeners = bound.listeners();
    let result = async {
        for error in bound.failures() {
            reports.warning(
                "pils.listener.alternate",
                format_args!("pils alternate listener: {error}"),
            );
        }
        if reports.failed() {
            return Err(io::Error::other("PILS selected logger failed before readiness").into());
        }
        let peer = host.identity().ok_or("PILS prepared authority is closed")?;
        {
            let mut output = io::stdout().lock();
            write!(output, "READY ")?;
            for byte in peer {
                write!(output, "{byte:02x}")?;
            }
            writeln!(output)?;
            output.flush()?;
        }
        service::acknowledge_ready(notification, &mut stop, &reports, Duration::from_secs(10))
            .await?;
        loop {
            let event = {
                let mut observer = |event| {
                    if matches!(&event, SocketEvent::Failed(error) if error.is_emfile()) {
                        return;
                    }
                    let level = if matches!(&event, SocketEvent::Failed(_)) {
                        Level::WARNING
                    } else {
                        Level::DEBUG
                    };
                    reports.message(level, "pils.socket", format_args!("pils socket: {event:?}"));
                };
                let mut driving = std::pin::pin!(host.drive(&listeners, &mut observer, None));
                poll_fn(|cx| {
                    reports.register(cx);
                    if reports.failed() {
                        return Poll::Ready(Ok(None));
                    }
                    if let Poll::Ready(result) = stop.poll_stop(cx) {
                        return Poll::Ready(
                            result
                                .map(|()| None)
                                .map_err(|error| Box::new(error) as Failure),
                        );
                    }
                    driving
                        .as_mut()
                        .poll(cx)
                        .map(|result| result.map(Some).map_err(|error| Box::new(error) as Failure))
                })
                .await?
            };
            match event {
                None | Some(Progress::Closed) => break,
                Some(progress) => observe(&reports, &progress),
            }
        }
        Ok(())
    }
    .await;
    host.close();
    while let Some(event) = host.next_event() {
        observe(&reports, &event);
    }
    let result = service::retain_diagnostic(result, reports.take_error());
    let output = (|| -> io::Result<()> {
        let mut output = io::stdout().lock();
        writeln!(output, "STOPPED {:?}", host.report())?;
        output.flush()
    })();
    service::retain_diagnostic(result, output.err())
}
