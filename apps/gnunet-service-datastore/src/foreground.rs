//! Original DATASTORE server and dedicated worker settlement.
use crate::{Failure, aggregate, control::Control, reporting::Reports, settings::Settings};
use gnunet_datastore_host::{
    backend::Store,
    server::{self, Progress, Server},
};
use gnunet_program_host::policy::Level;
use gnunet_service_runtime::{BoundListeners, clock::RuntimeClock, service::ShutdownMode};
use gnunet_service_startup::ControlReceiver;
use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io::{self, Write},
    sync::Arc,
    task::Poll,
};
#[derive(Debug)]
struct ServiceFailure(Arc<server::Error>);
impl fmt::Display for ServiceFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.0.as_ref(), f)
    }
}
impl Error for ServiceFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}
pub(crate) struct Inputs<'a, 'route, 'log> {
    pub(crate) bound: &'a BoundListeners,
    pub(crate) parent: Option<ControlReceiver>,
    pub(crate) backend: Store,
    pub(crate) settings: &'a Settings,
    pub(crate) clock: Arc<dyn RuntimeClock>,
    pub(crate) reports: &'a Reports<'route, 'log>,
}
pub(crate) async fn run<Ready: Future<Output = Result<(), Failure>>>(
    input: Inputs<'_, '_, '_>,
    ready: impl FnOnce() -> Ready,
) -> Result<(), Failure> {
    let Inputs {
        bound,
        parent,
        backend,
        settings,
        clock,
        reports,
    } = input;
    let mut control = Control::new(parent)?;
    let mut server = Server::new(
        backend,
        settings.service,
        settings.native,
        settings.options.clone(),
        settings.access,
        clock,
    )
    .await
    .map_err(|error| Box::new(ServiceFailure(error)) as Failure)?;
    reports.message(
        Level::INFO,
        "datastore.ready",
        format_args!(
            "DATASTORE actual server and original worker ready: {}",
            settings.directory.display()
        ),
    );
    let outcome = async {
        reports.startup_check()?;
        {
            let mut out = io::stdout().lock();
            writeln!(out, "READY datastore {}", settings.directory.display())?;
            out.flush()?;
        }
        ready().await?;
        let listeners = bound.listeners();
        loop {
            let selected = {
                let driving = server.drive(&listeners, None, |event| reports.observe(event));
                let mut driving = std::pin::pin!(driving);
                poll_fn(|cx| {
                    match control.poll(cx, reports) {
                        Poll::Ready(Ok(())) => return Poll::Ready(Ok(None)),
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => {}
                    }
                    driving.as_mut().poll(cx).map(|progress| Ok(Some(progress)))
                })
                .await
            };
            match selected {
                Ok(None | Some(Progress::Stopped | Progress::WaitDeadline)) => break Ok(()),
                Ok(Some(_)) => {}
                Err(error) => break Err(error),
            }
        }
    }
    .await;
    // Worker Stop completion and physical thread join remain separate from an
    // operation error, readiness failure or stopped socket. Always await both.
    server.request_shutdown(ShutdownMode::Immediate);
    let report = server.shutdown(|event| reports.observe(event)).await;
    let mut cleanup = Vec::new();
    let output = {
        let mut out = io::stdout().lock();
        writeln!(out, "STOPPED datastore {report:?}").and_then(|()| out.flush())
    };
    if let Some(error) = report.failure {
        cleanup.push(Box::new(ServiceFailure(error)) as Failure)
    }
    if !report.worker_quiesced {
        cleanup.push("DATASTORE worker did not reach actual native quiescence".into())
    }
    if let Err(error) = output {
        cleanup.push(Box::new(error))
    }
    aggregate(outcome, cleanup)
}
