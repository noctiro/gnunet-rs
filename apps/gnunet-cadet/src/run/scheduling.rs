//! Initial deadline and native subscriptions precede Resolver construction.
use super::{Cause, Inputs, run};
use crate::{budget::Start, options::Settings};
use gnunet_program_host::{
    foreground::{self, Stop},
    program::Prepared,
    reporting::Reporter,
    shared_clock::SharedClock,
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
    let initial = Start::sample(&source)?.budget(settings.operation)?;
    if tokio::time::Instant::now() >= initial.hard {
        return Err(gnunet_types::Error::Deadline.into());
    }
    let stop = Rc::new(Cell::new(false));
    let control = Stop::new(startup.parent, stop.clone(), reporter.clone())?;
    let live = gnunet_client_host::LiveConfiguration::new(configuration);
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
        control,
        initial,
    });
    foreground::run(prepared, &mut context, clock, stop, product)
        .await
        .map(|_report| ())
}
