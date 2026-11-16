//! One shared PROGRAM scheduler, original Resolver and stop latch.
use super::{Failure, Settings, drive::run_native, reporting::Reports};
use crate::statistics::StatisticsFactory;
use gnunet_client_host::LiveConfiguration;
use gnunet_program_host::{program::Prepared, shared_clock::SharedClock};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_service_startup::ParentControl;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    sync::Arc,
};
pub(super) async fn scheduled<F: StatisticsFactory + 'static>(
    prepared: Prepared,
    clock: SharedClock,
    settings: Settings,
    parent: Option<ParentControl>,
    reports: Rc<RefCell<Reports>>,
) -> Result<(), Failure> {
    let actual: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
    let live = LiveConfiguration::new(prepared.main().config.duplicate()?);
    let (mut context, resolver) = gnunet_resolver_broker::broker::<64, 256>(
        live.clone(),
        settings.resolver,
        gnunet_resolver_broker::native_profile()?,
        actual,
    )?;
    let resolution = context.resolution_context();
    let stopping = Rc::new(Cell::new(false));
    let original = run_native::<F>(
        settings,
        parent,
        resolver,
        live,
        resolution,
        reports,
        stopping.clone(),
    );
    gnunet_program_host::foreground::run(prepared, &mut context, clock, stopping, original).await
}
