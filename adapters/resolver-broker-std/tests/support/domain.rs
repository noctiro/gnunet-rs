//! Explicit caller-owned broker reactor for finite tests and probe executables.
//! Each fixture constructs one domain and shares its resolution across all hosts.
use gnunet_client_host::resolution::SharedResolution;
use gnunet_config::Configuration;
use gnunet_resolver_broker::{
    Context, Driver, FamilyProfile, LiveConfiguration, SystemClock, broker,
};
use std::{io, sync::Arc};
pub struct Domain {
    pub context: Context<16, 1024>,
    driver: Option<Driver<16, 1024>>,
    task: Option<
        tokio::task::JoinHandle<std::result::Result<(), gnunet_resolver_broker::BrokerError>>,
    >,
}
impl Domain {
    pub fn new(config: Configuration) -> io::Result<Self> {
        let p = gnunet_resolver_broker::native_profile().map_err(io::Error::other)?;
        let profile = FamilyProfile::new(
            p.encode(gnunet_resolver_broker::Family::V4),
            p.encode(gnunet_resolver_broker::Family::V6),
        )
        .map_err(io::Error::other)?;
        let (context, driver) = broker(
            LiveConfiguration::new(config),
            Default::default(),
            profile,
            Arc::new(SystemClock),
        )
        .map_err(io::Error::other)?;
        Ok(Self {
            context,
            driver: Some(driver),
            task: None,
        })
    }
    pub fn start(&mut self) -> io::Result<()> {
        let mut driver = self
            .driver
            .take()
            .ok_or_else(|| io::Error::other("fixture driver already started"))?;
        self.task = Some(tokio::spawn(async move {
            loop {
                driver.drive_waiting(None, |_| {}).await?;
            }
        }));
        Ok(())
    }
    pub fn resolution(&self) -> SharedResolution {
        self.context.resolution_context()
    }
}
impl Drop for Domain {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
