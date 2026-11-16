//! Shared PROGRAM scheduling retains the original product future and Resolver.
use crate::{
    Failure,
    reporting::{Cleanup, Reports},
    settings::Settings,
};
use gnunet_client_host::LiveConfiguration;
use gnunet_program_host::{program::Prepared, shared_clock::SharedClock};
use gnunet_resolver_broker::Driver;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_service_startup::ClientStartup;
use std::{cell::Cell, rc::Rc, sync::Arc};
// Own the concrete Resolver before handing any future to PROGRAM. All early
// constructor returns, rejected/unpolled tasks and scoped cancellation retain
// the one explicit disconnect cause through the same outer Reports.
pub(super) struct ResolverOwner {
    pub(super) driver: Driver<64, 256>,
    closed: bool,
    reports: Reports,
}
impl ResolverOwner {
    pub(super) fn close(&mut self) -> Option<Failure> {
        if self.closed {
            return None;
        }
        // Mark this original attempt before calling it, including on Err. The
        // Driver's own Drop still clears physical resources; it does not retry
        // this protocol transition or manufacture a successful disconnect.
        self.closed = true;
        self.driver
            .disconnect()
            .err()
            .map(|error| Box::new(error) as Failure)
    }
}
impl Drop for ResolverOwner {
    fn drop(&mut self) {
        if let Some(error) = self.close() {
            self.reports.cleanup(Cleanup::Resolver, error);
        }
    }
}
pub(super) async fn scheduled(
    prepared: Prepared,
    clock: SharedClock,
    settings: Settings,
    inherited: ClientStartup,
    reports: Reports,
) -> Result<(), Failure> {
    let config = prepared.main().config.duplicate()?;
    let runtime: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
    let live = LiveConfiguration::new(config.duplicate()?);
    let (mut program_context, resolver) = gnunet_resolver_broker::broker::<64, 256>(
        live.clone(),
        settings.resolver,
        gnunet_resolver_broker::native_profile()?,
        runtime.clone(),
    )?;
    let resolver = ResolverOwner {
        driver: resolver,
        closed: false,
        reports: reports.clone(),
    };
    let resolution = program_context.resolution_context();
    let stop = Rc::new(Cell::new(false));
    let product = crate::drive::run(
        settings,
        inherited,
        resolver,
        live,
        resolution,
        reports,
        stop.clone(),
    );
    gnunet_program_host::foreground::run(prepared, &mut program_context, clock, stop, product).await
}
