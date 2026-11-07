//! Official REGEX section plus explicitly bounded Rust implementation policies.
use crate::{Failure, statistics};
use gnunet_config::{Configuration, Environment, ProcessEnvironment, ProjectData};
use gnunet_service_runtime::{credentials::UnixAccess, service::ShutdownMode};
use std::{path::Path, sync::Arc, time::Duration};
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
        let pils_profile = gnunet_pils::Profile::configured(config.get(b"PILS", b"PROFILE"), None)?;
        let mut core = gnunet_regex_service::Limits::default();
        let mut host = gnunet_regex_server_host::Limits::default();
        core.clients = size(config, b"MAX_CLIENTS", core.clients, 1, 1024)?;
        host.clients = core.clients;
        core.jobs = size(config, b"MAX_JOBS", core.jobs, 1, 65536)?;
        core.branches = size(config, b"MAX_BRANCHES", core.branches, 1, 16384)?;
        core.outputs = size(config, b"MAX_RESULTS", core.outputs, 1, 65536)?;
        core.seen_results = size(config, b"MAX_SEEN_RESULTS", core.seen_results, 1, 262144)?;
        core.input_bytes = size(config, b"MAX_INPUT_BYTES", core.input_bytes, 1, 65535)?;
        core.retained_bytes = size(
            config,
            b"RETAINED_BYTES",
            core.retained_bytes,
            1024,
            256 * 1024 * 1024,
        )?;
        core.announcement_bytes = size(
            config,
            b"ANNOUNCEMENT_BYTES",
            core.announcement_bytes,
            1024,
            core.retained_bytes,
        )?;
        host.io_slice_bytes = size(config, b"IO_SLICE_BYTES", host.io_slice_bytes, 1, 65535)?;
        host.first_input = duration(config, b"FIRST_INPUT_TIMEOUT", host.first_input)?;
        host.partial_input = duration(config, b"PARTIAL_INPUT_TIMEOUT", host.partial_input)?;
        host.output_lifetime = duration(config, b"OUTPUT_TIMEOUT", host.output_lifetime)?;
        let driver = gnunet_regex_server_host::driver::Limits {
            operations: core.jobs,
            signature_lifetime: duration(config, b"SIGNATURE_TIMEOUT", Duration::from_secs(300))?,
        };
        let statistics = statistics::Limits {
            operation: duration(config, b"STATISTICS_TIMEOUT", Duration::from_secs(5))?,
            ..Default::default()
        };
        statistics.validate()?;
        let flags = |key: &[u8]| {
            config
                .get(b"regex", key)
                .map(|_| config.get_yesno(b"regex", key))
                .transpose()
                .map(|v| v.unwrap_or(false))
        };
        let value = Self {
            pils_profile,
            core,
            host,
            driver,
            resolver: gnunet_resolver_broker::Limits::default(),
            statistics,
            unix: UnixAccess {
                match_uid: flags(b"UNIX_MATCH_UID")?,
                match_gid: flags(b"UNIX_MATCH_GID")?,
            },
            startup: duration(config, b"STARTUP_TIMEOUT", Duration::from_secs(300))?,
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
        // Official regex uses GNUNET_SERVICE_OPTION_NONE: immediate shutdown.
        gnunet_service_runtime::service_options(config, b"regex", ShutdownMode::Immediate)
    }
}
fn size(
    config: &Configuration,
    key: &[u8],
    default: usize,
    min: usize,
    max: usize,
) -> Result<usize, Failure> {
    let value = if config.get(b"regex", key).is_some() {
        usize::try_from(config.get_size(b"regex", key)?)?
    } else {
        default
    };
    if !(min..=max).contains(&value) {
        return Err(format!(
            "REGEX resource {} outside {min}..={max}",
            String::from_utf8_lossy(key)
        )
        .into());
    }
    Ok(value)
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
pub(crate) fn configuration(selected: Option<&Path>) -> Result<Configuration, Failure> {
    let project = Arc::new(ProjectData::default());
    let mut config = Configuration::create(project.clone(), Default::default())?;
    let user = if let Some(path) = selected {
        Some(path.to_path_buf())
    } else {
        let raw = match ProcessEnvironment.variable(b"XDG_CONFIG_HOME") {
            Some(mut value) => {
                value.push(b'/');
                value.extend_from_slice(&project.config_file);
                value
            }
            None => project.user_config_file.clone(),
        };
        let path = config.expand_filename(&raw, &ProcessEnvironment)?;
        path.is_file().then_some(path)
    };
    config.load(user.as_deref())?;
    Ok(config)
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
