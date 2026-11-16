//! Original command bounds and native subscriptions precede Resolver admission.
use super::{Cause, Inputs, run};
use crate::{budget::Budget, options::Settings};
use gnunet_program_host::foreground::Stop as Control;
use gnunet_program_host::{
    foreground, program::Prepared, reporting::Reporter, shared_clock::SharedClock,
};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_service_startup::ClientStartup;
use std::{cell::Cell, rc::Rc, sync::Arc};

pub(crate) async fn scheduled(
    prepared: Prepared,
    settings: Settings,
    configuration: gnunet_config::Configuration,
    clock: SharedClock,
    reporter: Reporter,
    startup: ClientStartup,
) -> Result<(), Cause> {
    let source: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
    let budget = Budget::new(source.clone())?;
    let stop = Rc::new(Cell::new(false));
    let control = Control::new(startup.parent, stop.clone(), reporter.clone())?;
    let live = gnunet_client_host::LiveConfiguration::new(configuration);
    let (mut context, resolver) = gnunet_resolver_broker::broker::<16, 64>(
        live,
        Default::default(),
        gnunet_resolver_broker::native_profile()?,
        source,
    )?;
    let product = run(Inputs {
        settings,
        context: context.clone(),
        resolver,
        reporter,
        control,
        budget,
    });
    foreground::run(prepared, &mut context, clock, stop, product)
        .await
        .map(|_report| ())
}
