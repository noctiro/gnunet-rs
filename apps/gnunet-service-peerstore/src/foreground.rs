//! Actual original PEERSTORE server/slabs, immutable output and worker drain.
use crate::{Failure, aggregate, buffer, control::Control, reporting::Reports, settings::Settings};
use gnunet_peerstore as core;
use gnunet_peerstore_host::{
    server::{Progress, Server},
    worker::Worker,
};
use gnunet_program_host::policy::Level;
use gnunet_service_runtime::{BoundListeners, clock::RuntimeClock, service::ShutdownMode};
use gnunet_service_startup::{ParentControl, daemon::ChildReady};
use std::{
    future::{Future, poll_fn},
    io::{self, Write},
    sync::Arc,
    task::Poll,
};
pub(crate) struct Inputs<'a, 'route, 'log> {
    pub(crate) bound: &'a BoundListeners,
    pub(crate) parent: Option<ParentControl>,
    pub(crate) worker: &'a mut Worker,
    pub(crate) settings: &'a Settings,
    pub(crate) clock: Arc<dyn RuntimeClock>,
    pub(crate) reports: &'a Reports<'route, 'log>,
    pub(crate) child: &'a mut ChildReady,
}
pub(crate) async fn run(input: Inputs<'_, '_, '_>) -> Result<(), Failure> {
    let Inputs {
        bound,
        parent,
        worker,
        settings,
        clock,
        reports,
        child,
    } = input;
    let mut control = Control::new(parent)?;
    let mut instance = core::Instance::new();
    let mut clients = Vec::new();
    clients.try_reserve_exact(settings.native.clients)?;
    clients.resize(settings.native.clients, core::ClientSlot::new());
    let mut opbytes = Vec::new();
    opbytes.try_reserve_exact(settings.operations)?;
    for _ in 0..settings.operations {
        opbytes.push(buffer(settings.filter_bytes)?);
    }
    let mut operations = Vec::new();
    operations.try_reserve_exact(settings.operations)?;
    for bytes in &mut opbytes {
        operations.push(core::OperationSlot::new(bytes));
    }
    let mut messagebytes = Vec::new();
    messagebytes.try_reserve_exact(settings.native.clients)?;
    for _ in 0..settings.native.clients {
        messagebytes.push(buffer(settings.core.record_bytes)?);
    }
    let mut messages = Vec::new();
    messages.try_reserve_exact(settings.native.clients)?;
    for bytes in &mut messagebytes {
        messages.push(core::MessageSlot::new(bytes));
    }
    let service = core::Service::new(
        &mut instance,
        &mut clients,
        &mut operations,
        &mut messages,
        settings.core,
    )?;
    let mut server = Server::new(
        service,
        worker,
        settings.native,
        settings.options.clone(),
        settings.access,
        clock,
    )?;
    // Only a fully constructed server with the real worker and all bound
    // listeners may notify the original daemon parent. Failed logging takes
    // the ordinary stop path and cannot mint a ready byte.
    reports.message(
        Level::INFO,
        "peerstore.ready",
        format_args!(
            "PEERSTORE actual server ready: {}",
            settings.directory.display()
        ),
    );
    let ready = if reports.failed() {
        None
    } else {
        let mut output = io::stdout().lock();
        Some(writeln!(output,"READY peerstore {} wire=0.29.1 store=wal-durable iterate=uid monitor=credit authentication=cache-only",settings.directory.display())
            .and_then(|()|output.flush()).and_then(|()|child.ready()))
    };
    let outcome = match ready {
        Some(Err(error)) => Err(Box::new(error) as Failure),
        None | Some(Ok(())) => {
            let listeners = bound.listeners();
            let mut stop_at = None;
            loop {
                let selected = {
                    let driving = server.drive(&listeners, stop_at, |event| reports.observe(event));
                    let mut driving = std::pin::pin!(driving);
                    poll_fn(|cx| {
                        match control.poll(cx, reports) {
                            Poll::Ready(Ok(())) => return Poll::Ready(Ok(None)),
                            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                            Poll::Pending => {}
                        }
                        driving.as_mut().poll(cx).map(|result| {
                            result.map(Some).map_err(|error| Box::new(error) as Failure)
                        })
                    })
                    .await
                };
                match selected {
                    Ok(None)
                        if stop_at.is_none() && settings.options.shutdown == ShutdownMode::Soft =>
                    {
                        server.request_shutdown(ShutdownMode::Soft);
                        match tokio::time::Instant::now().checked_add(settings.shutdown_grace) {
                            Some(original) => stop_at = Some(original),
                            None => break Err("PEERSTORE shutdown deadline overflow".into()),
                        }
                    }
                    Ok(None | Some(Progress::Stopped | Progress::WaitDeadline)) => break Ok(()),
                    Ok(Some(_)) => {}
                    Err(error) => break Err(error),
                }
            }
        }
    };
    // Always settle original source/immutable-output/store jobs and physically
    // join the one original worker, even when the driver or reporting failed.
    let stopped = server.shutdown(|event| reports.observe(event)).await;
    let mut cleanup = Vec::new();
    let output = {
        let mut output = io::stdout().lock();
        writeln!(
            output,
            "STOPPED peerstore local={:?} worker-joined={} worker={:?} cleanup={:?}",
            stopped.report,
            stopped.worker.is_some(),
            stopped.worker,
            stopped.failure
        )
        .and_then(|()| output.flush())
    };
    if let Some(error) = stopped.failure {
        cleanup.push(Box::new(error) as Failure);
    }
    match stopped.worker {
        Some(worker) => {
            if let Some(error) = worker.failure {
                cleanup.push(Box::new(error) as Failure);
            }
        }
        None => cleanup.push("PEERSTORE original worker join receipt missing".into()),
    }
    if let Err(error) = output {
        cleanup.push(Box::new(error) as Failure);
    }
    aggregate(outcome, cleanup)
}
