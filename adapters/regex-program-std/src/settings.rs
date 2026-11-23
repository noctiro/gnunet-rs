//! Official REGEX section plus explicitly bounded Rust implementation policies.
use crate::{Failure, statistics};
use gnunet_config::Configuration;
use gnunet_regex_server_host::startup;
use gnunet_service_runtime::credentials::UnixAccess;
use std::time::Duration;
/// Explicit finite capacities. These are local policies, never added wire fields.
#[derive(Clone, Debug)]
pub struct Settings {
    /// One explicit node-wide PILS/HELLO source selection, with no fallback.
    pub pils_profile: gnunet_pils::Profile,
    /// Actual distributed compiler/search/retained operation limits.
    pub core: gnunet_regex_service::Limits,
    /// Actual IPC buffering and first/partial/output native bounds.
    pub host: gnunet_regex_server_host::Limits,
    /// Original PILS and DHT operation metadata/signature bound.
    pub driver: gnunet_regex_server_host::driver::Limits,
    /// Actual shared Resolver envelope capacities.
    pub resolver: gnunet_resolver_broker::Limits,
    /// One bounded original STATISTICS publisher.
    pub statistics: statistics::Limits,
    /// Same booleans for target-account paths and actual kernel admission.
    pub unix: UnixAccess,
    /// First startup hard; failure/rotation never renew it.
    pub startup: Duration,
    /// Fixed unresolved-retirement diagnostic point, not a cancellation receipt.
    pub shutdown_grace: Duration,
    /// Independent finite STATISTICS final-delta/Destroy deadline.
    pub statistics_grace: Duration,
    /// Caller reactor observation quantum; does not renew any original job.
    pub tick: Duration,
}
impl Settings {
    /// Parse the real selected section. Absent UID/GID flags are false, matching
    /// generic SERVICE option semantics. No synthetic USERNAME fallback exists.
    pub fn read(config: &Configuration) -> Result<Self, Failure> {
        let shared = startup::Settings::read(config)?;
        let statistics = statistics::Limits {
            operation: duration(config, b"STATISTICS_TIMEOUT", Duration::from_secs(5))?,
            ..Default::default()
        };
        statistics.validate()?;
        let value = Self {
            pils_profile: shared.pils_profile,
            core: shared.core,
            host: shared.host,
            driver: shared.driver,
            resolver: gnunet_resolver_broker::Limits::default(),
            statistics,
            unix: shared.unix,
            startup: shared.startup,
            shutdown_grace: duration(config, b"RETIREMENT_NOTICE_DELAY", Duration::from_secs(5))?,
            statistics_grace: duration(
                config,
                b"STATISTICS_SHUTDOWN_GRACE",
                Duration::from_secs(5),
            )?,
            tick: duration(config, b"REACTOR_QUANTUM", Duration::from_millis(50))?,
        };
        // Check reactor/time limits before allocating factory/native resources.
        if value.tick > Duration::from_secs(1) {
            return Err("REGEX REACTOR_QUANTUM exceeds one second".into());
        }
        Ok(value)
    }
    pub(crate) fn service(
        &self,
        config: &Configuration,
    ) -> Result<gnunet_service_runtime::service::ServiceOptions, Failure> {
        startup::service_options(config)
    }
}
fn duration(config: &Configuration, key: &[u8], default: Duration) -> Result<Duration, Failure> {
    let value = if config.get(b"regex", key).is_some() {
        Duration::from_micros(config.get_time(b"regex", key)?)
    } else {
        default
    };
    if value.is_zero()
        || value > Duration::from_secs(86400)
        || tokio::time::Instant::now().checked_add(value).is_none()
    {
        return Err(format!(
            "REGEX {} requires a finite positive time <=24h",
            String::from_utf8_lossy(key)
        )
        .into());
    }
    Ok(value)
}
#[cfg(test)]
mod profile_tests {
    use super::*;
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Compare actual REGEX startup selection and its typed refusal"
    )]
    fn announcement_signer_inherits_node_profile_before_factory_startup() -> Result<(), Failure> {
        let mut config = Configuration::default();
        assert_eq!(
            Settings::read(&config)?.pils_profile,
            gnunet_pils::Profile::Reference029
        );
        config.set_value(b"PILS", b"PROFILE", Some(b"deterministic"))?;
        assert_eq!(
            Settings::read(&config)?.pils_profile,
            gnunet_pils::Profile::ReferenceDeterministic
        );
        config.set_value(b"PILS", b"PROFILE", Some(b"unknown"))?;
        let error = Settings::read(&config)
            .err()
            .ok_or("unknown REGEX signer profile admitted")?;
        assert_eq!(
            error.downcast_ref::<gnunet_types::Error>(),
            Some(&gnunet_types::Error::InvalidInput)
        );
        Ok(())
    }
}
