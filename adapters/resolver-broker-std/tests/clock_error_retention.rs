//! Independent real public owner error-retention regression; no native connect.
#[path = "../../ipc-unix/tests/support/clock_source.rs"]
pub mod clock_source;
use gnunet_service_runtime::clock::{ClockSample, ClockSubscription, RuntimeClock};
use gnunet_types::Error;
use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};
struct Source {
    clock: clock_source::Adjustable,
    fail: AtomicU8,
}
impl RuntimeClock for Source {
    fn sample(&self) -> Result<ClockSample, Error> {
        match self.fail.load(Ordering::SeqCst) {
            1 => Err(Error::Io),
            2 => Err(Error::TimeUncertain),
            _ => self.clock.sample(),
        }
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Error> {
        self.clock.subscribe()
    }
}
#[expect(
    clippy::panic_in_result_fn,
    reason = "An admitted operation's retained source refusal must survive another successful admission before drive"
)]
fn check_retention(second_refusal: bool) -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        type Stats<'owner> =gnunet_ipc_unix::handle::StatisticsHandle<'owner, 8,64,4,64,16>;
        let source=Arc::new(Source{clock:clock_source::Adjustable::frozen(1_000_000,8)?,fail:AtomicU8::new(0)});
        let mut cfg=gnunet_config::Configuration::default();
        cfg.set_value(b"resolver",b"UNIXPATH",Some(b"/private/tmp/gnunet-clock-review-not-connected-resolver"))?;
        cfg.set_value(b"statistics",b"UNIXPATH",Some(b"/private/tmp/gnunet-clock-review-not-connected-statistics"))?;
        let profile=gnunet_resolver_broker::native_profile()?;
        let families=gnunet_resolver_broker::FamilyProfile::new(profile.encode(gnunet_resolver_broker::Family::V4),profile.encode(gnunet_resolver_broker::Family::V6))?;
        let(context,_driver)=gnunet_resolver_broker::broker::<4,64>(gnunet_resolver_broker::LiveConfiguration::new(cfg.duplicate()?),Default::default(),families,source.clone())?;
        let mut statistics_instance_1=gnunet_client::statistics_handle::Instance::new();
        let mut host=Stats::from_config(&mut statistics_instance_1, &cfg,context.resolution_context(),b"owner",Default::default())?.ok_or("disabled")?;
        source.fail.store(1,Ordering::SeqCst);
        let id=host.get(gnunet_client::statistics::Selector{subsystem:b"owner",name:b"first"})?;
        assert!(host.owns_get(id));assert_eq!(host.connection_epoch(),None);
        if second_refusal {
            source.fail.store(2,Ordering::SeqCst);
            host.set(b"second-refusal",6,false)?;
        }
        source.fail.store(0,Ordering::SeqCst);
        host.set(b"next",7,false)?;
        assert!(host.connection_epoch().is_some());
        let result=host.drive(Some(tokio::time::Instant::now()),|_,_|gnunet_client::statistics_handle::GetFlow::Continue).await;
        assert!(matches!(result,Err(gnunet_ipc_unix::IpcError::Io(ref error))if gnunet_client_host::resolution::PortError::from_io(error).is_some_and(|port| port.cause().get_ref().and_then(|cause|cause.downcast_ref::<Error>())==Some(&Error::Io))),"original clock error disappeared before drive: {result:?}");
        assert!(host.owns_get(id));host.destroy(false)?;
        Ok(())
    })
}
#[test]
fn admitted_clock_error_survives_later_epoch_creation_until_drive()
-> Result<(), Box<dyn std::error::Error>> {
    check_retention(false)
}
#[test]
fn later_refusal_cannot_replace_the_first_unreported_clock_cause()
-> Result<(), Box<dyn std::error::Error>> {
    check_retention(true)
}
