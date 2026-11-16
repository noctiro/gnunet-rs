//! Native Windows identity, listener and parent-readiness startup composition.
use super::{Failure, foreground, reporting, retain_cleanup, retain_diagnostic, settings};
use gnunet_program_host::{logging::Logger, service as lifecycle, shared_clock::SharedClock};
use gnunet_service_runtime::{Activation, BoundListeners};
use gnunet_service_startup::{ParentControl, ReadyStatus};

/// Native owners captured by the fresh process before runtime/provider setup.
pub struct Startup<'a, 'log> {
    /// Standard selected SERVICE options and configuration location.
    pub selected: &'a lifecycle::Selected,
    /// Imported original listeners; recipient gains no creator cleanup lease.
    pub activation: Activation,
    /// Original supervisor or detached-launcher endpoint declaration.
    pub parent: Option<ParentControl>,
    /// Same native/shared clock used by service logging and reactor deadlines.
    pub clock: &'a SharedClock,
    /// Explicit selected diagnostic destination; never replaces process stderr.
    pub logger: &'a mut Logger<'log>,
}
/// Run normal ARM SERVICE after fresh capture and any console transition.
/// Owns its current-thread runtime; configured identity must match the actual
/// process token. Startup status, native admission and child exit stay distinct.
pub fn run(input: Startup<'_, '_>) -> Result<(), Failure> {
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err("ARM SERVICE must start before an existing runtime".into());
    }
    let Startup {
        selected,
        activation,
        parent,
        clock,
        logger,
    } = input;
    let reports = reporting::Reports::new(logger, clock);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    if selected.daemonize_requested() && parent.is_none() {
        return retain_diagnostic(
            lifecycle::detach(&runtime, activation).map_err(|error| error as Failure),
            reports.take_failure(),
        );
    }
    let connected = {
        let _entered = runtime.enter();
        parent.map(|parent| parent.register()).transpose()?
    };
    let (parent, mut ready) = match connected {
        Some(parent) => (Some(parent.control), Some(parent.ready)),
        None => (None, None),
    };
    let result = (|| -> Result<(), Failure> {
        reports.startup_check()?;
        let config = settings::configuration(selected.configuration())?;
        clock.testing_skew(&config)?;
        let settings = settings::Settings::read(&config)?;
        gnunet_service_startup::verify_configured_identity(&config, b"arm")?;
        let bound = if activation.is_empty() {
            runtime.block_on(BoundListeners::bind_configured(
                &config,
                b"arm",
                Default::default(),
            ))?
        } else {
            let _entered = runtime.enter();
            BoundListeners::from_activation(activation)?
        };
        for error in bound.failures() {
            reports.warning(
                "arm.listener.alternate",
                format_args!("ARM alternate listener: {error}"),
            );
        }
        reports.startup_check()?;
        runtime.block_on(foreground::run(foreground::Inputs {
            bound,
            parent,
            settings: &settings,
            config: &config,
            clock,
            reports: &reports,
            ready: &mut ready,
        }))
    })();
    let result = match result {
        Err(original) => match ready.as_mut().filter(|writer| writer.intent().is_none()) {
            Some(writer) => {
                match runtime.block_on(writer.signal(ReadyStatus::InitializationFailed)) {
                    Ok(_) => Err(original),
                    Err(error) => Err(retain_cleanup(original, Box::new(error))),
                }
            }
            None => Err(original),
        },
        result => result,
    };
    retain_diagnostic(result, reports.take_failure())
}
