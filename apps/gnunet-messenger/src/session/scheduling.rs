//! Original startup bounds, stop owner and Resolver admission.
use super::{Failure, Inputs, run};
use crate::options::Settings;
use gnunet_program_host::{
    foreground::{self, Stop},
    program::Prepared,
    reporting::Reporter,
    shared_clock::SharedClock,
};
use gnunet_service_runtime::clock::{Bounds, RuntimeClock};
use gnunet_service_startup::ClientStartup;
use std::{cell::Cell, rc::Rc, sync::Arc};
pub(crate) async fn scheduled(
    prepared: Prepared,
    config: gnunet_config::Configuration,
    settings: Settings,
    clock: SharedClock,
    reporter: Reporter,
    startup: ClientStartup,
) -> Result<(), Failure> {
    let source: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
    let initial = Bounds::after(source.as_ref(), settings.timeout)?;
    let stop = Rc::new(Cell::new(false));
    let signals = Stop::new(startup.parent, stop.clone(), reporter.clone())?;
    let live = gnunet_client_host::LiveConfiguration::new(config);
    let (mut context, resolver) = gnunet_resolver_broker::broker::<128, 256>(
        live.clone(),
        Default::default(),
        gnunet_resolver_broker::native_profile()?,
        source.clone(),
    )?;
    let product = run(Inputs {
        settings,
        live,
        context: context.clone(),
        resolver,
        source,
        reporter,
        signals,
        initial,
    });
    foreground::run(prepared, &mut context, clock, stop, product)
        .await
        .map(|_report| ())
}
