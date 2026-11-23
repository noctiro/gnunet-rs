//! OS-launched Apple provider sessions using the ordinary DNS service owners.
use crate::{Failure, foreground, settings::Settings};
use gnunet_native::dns_proxy::provider::{Controller, Event, StartRequest};
use gnunet_program_host::{logging::Logger, reporting::Reporter, shared_clock::SharedClock};
use gnunet_service_runtime::{BoundListeners, activation::Activation};
use std::{future::poll_fn, io, path::Path, task::Poll};

pub(crate) mod configuration;
mod runtime;
pub(super) use runtime::{Progress, Runtime};

#[cfg(target_os = "macos")]
mod system_extension;
#[cfg(target_os = "macos")]
pub(super) use system_extension::run as run_system_extension;

/// Drive one iOS app-extension session on the calling thread until retirement.
///
/// The extension supplies its installation paths and delivers original
/// NetworkExtension callbacks through the matching controller. This function
/// creates its own current-thread runtime and must run outside a Tokio runtime.
///
/// # Errors
/// Returns the original startup, service or bounded retirement diagnostic.
#[cfg(target_os = "ios")]
pub fn run_app_extension(
    controller: Controller,
    resources: &Path,
    binaries: &Path,
) -> Result<(), String> {
    run_session(controller, resources, binaries).map_err(|error| error.to_string())
}

fn run_session(controller: Controller, resources: &Path, binaries: &Path) -> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;
    runtime.block_on(serve(controller, resources, binaries))
}

async fn serve(
    mut controller: Controller,
    resources: &Path,
    binaries: &Path,
) -> Result<(), Failure> {
    loop {
        match poll_fn(|cx| controller.poll_event(cx)).await? {
            Event::Start(start) => {
                return start_service(&mut controller, start, resources, binaries).await;
            }
            Event::Stop(mut stop) => {
                poll_fn(|cx| stop.poll_complete(cx)).await?;
                return Ok(());
            }
            Event::Flow(flow) => drop(flow),
        }
    }
}
async fn start_service(
    controller: &mut Controller,
    start: StartRequest,
    resources: &Path,
    binaries: &Path,
) -> Result<(), Failure> {
    let (input, flows) = match prepare(start.configuration_file(), resources, binaries).await {
        Ok(prepared) => prepared,
        Err(error) => {
            start.reject();
            // A native stop can race a validation or listener failure before
            // any resource loans are issued. Retain that original obligation.
            if let Poll::Ready(Ok(Event::Stop(mut stop))) =
                poll_fn(|cx| Poll::Ready(controller.poll_event(cx))).await
                && let Err(retirement) = poll_fn(|cx| stop.poll_complete(cx)).await
            {
                return Err(
                    format!("DNS provider startup: {error}; native stop: {retirement}").into(),
                );
            }
            return Err(error);
        }
    };
    let mut native = Runtime::new(controller, start.session(), flows);
    let reports = input.reports.clone();
    let grace = input.settings.grace;
    let outcome = foreground::run_provider(
        input,
        async move {
            match start.ready() {
                Ok(()) => Ok(()),
                // The retained start callback already received failure. Let
                // the native event loop drive the original stop to retirement.
                Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
                Err(error) => Err(error.into()),
            }
        },
        &mut native,
    )
    .await;
    if native.is_closing() {
        return outcome;
    }
    // Host preparation may fail before entering foreground cleanup. No
    // gateway, listeners or statistics owner remain at this point.
    let retirement =
        tokio::time::timeout(grace, poll_fn(|cx| native.poll_cleanup(cx, true, &reports)))
            .await
            .map_err(|error| Box::new(error) as Failure)
            .and_then(|result| result);
    match (outcome, retirement) {
        (outcome, Ok(())) => outcome,
        (Ok(()), Err(error)) => Err(error),
        (Err(original), Err(error)) => {
            Err(format!("DNS provider startup: {original}; native retirement: {error}").into())
        }
    }
}

async fn prepare(
    filename: &Path,
    resources: &Path,
    binaries: &Path,
) -> Result<(foreground::Inputs, runtime::Resources), Failure> {
    let config = configuration::load(filename, resources, binaries)?;
    let clock = SharedClock::native(256)?;
    clock.testing_skew(&config)?;
    let logger = Logger::new(b"dns", std::process::id(), true)?;
    let reports = Reporter::new(logger, clock.clone());
    let settings = Settings::read_provider(&config)?;
    settings.statistics.validate()?;
    let flows = runtime::Resources::prepare(&config)?;
    let pending = BoundListeners::prepare_before_identity(&config, b"dns", Activation::default())?;
    let bound = pending.finish_with_access(settings.unix.into()).await?;
    for error in bound.failures() {
        reports.warning(
            "dns.listener.alternate",
            format_args!("dns alternate listener: {error}"),
        );
    }
    crate::startup_check(&reports)?;
    Ok((
        foreground::Inputs {
            config,
            settings,
            bound,
            clock,
            reports,
        },
        flows,
    ))
}
