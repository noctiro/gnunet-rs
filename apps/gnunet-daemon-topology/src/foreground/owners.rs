//! Original provider retirement, including failed or canceled construction.
use crate::reporting::{Cleanup, Reports};
use gnunet_resolver_broker::Driver;
use gnunet_topology_host::{Error, Runtime};
pub(super) struct Resolver {
    pub driver: Driver<64, 256>,
    reports: Reports,
    closed: bool,
}
impl Resolver {
    pub fn new(driver: Driver<64, 256>, reports: Reports) -> Self {
        Self {
            driver,
            reports,
            closed: false,
        }
    }
    pub fn close(&mut self) -> Result<(), gnunet_resolver_broker::BrokerError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.driver.disconnect()
    }
}
impl Drop for Resolver {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            self.reports.cleanup(Cleanup::Resolver, Box::new(error));
        }
    }
}
pub(super) struct Providers<'id> {
    pub runtime: Runtime<'id>,
    reports: Reports,
    closed: bool,
}
impl<'id> Providers<'id> {
    pub fn new(runtime: Runtime<'id>, reports: Reports) -> Self {
        Self {
            runtime,
            reports,
            closed: false,
        }
    }
    pub fn close(&mut self) -> (Option<Error>, Option<Error>) {
        if self.closed {
            return (None, None);
        }
        self.closed = true;
        let original = self
            .runtime
            .close(&mut |event| super::observe(&self.reports, event))
            .err();
        (original, self.runtime.take_cleanup_error())
    }
}
impl Drop for Providers<'_> {
    fn drop(&mut self) {
        let (original, deferred) = self.close();
        if let Some(error) = original {
            self.reports.cleanup(Cleanup::Runtime, Box::new(error));
        }
        if let Some(error) = deferred {
            self.reports
                .cleanup(Cleanup::DeferredRuntime, Box::new(error));
        }
    }
}
pub(super) struct Owners<'id> {
    pub providers: Providers<'id>,
    pub statistics: crate::statistics::Forwarder<'id>,
    pub resolver: Resolver,
    pub reports: Reports,
}
impl Drop for Owners<'_> {
    fn drop(&mut self) {
        let (original, deferred) = self.providers.close();
        if let Some(error) = original {
            self.reports.cleanup(Cleanup::Runtime, Box::new(error));
        }
        if let Some(error) = deferred {
            self.reports
                .cleanup(Cleanup::DeferredRuntime, Box::new(error));
        }
        if let Some(error) = self.statistics.close() {
            self.reports.cleanup(Cleanup::Statistics, error);
        }
        // The original Resolver field retires after providers and statistics.
    }
}
