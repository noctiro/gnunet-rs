//! Native limits and admission policy shared by REGEX hosts.
use crate::{
    Limits, core,
    dht::NativeLimits,
    driver::{self, Failure},
};
use gnunet_config::Configuration;
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
};
use gnunet_types::Error as Fault;
use std::time::Duration;

/// Effective shared service and protocol-owner configuration.
#[derive(Clone, Debug)]
pub struct Settings {
    /// One explicit node-wide PILS profile.
    pub pils_profile: gnunet_pils::Profile,
    /// Genuine distributed compiler, request and retained state bounds.
    pub core: core::Limits,
    /// Actual native client frame, buffering and deadline bounds.
    pub host: Limits,
    /// Actual joint operation metadata and original signing bounds.
    pub driver: driver::Limits,
    /// Original local client credential requirements.
    pub unix: UnixAccess,
    /// Original absolute native startup budget.
    pub startup: Duration,
}

impl Settings {
    /// Read the official service section and explicit REGEX owner limits.
    pub fn read(config: &Configuration) -> Result<Self, Failure> {
        let pils_profile = gnunet_pils::Profile::configured(config.get(b"PILS", b"PROFILE"), None)?;
        let mut core = core::Limits::default();
        let mut host = Limits::default();
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
        let driver = driver::Limits {
            operations: core.jobs,
            signature_lifetime: duration(config, b"SIGNATURE_TIMEOUT", Duration::from_secs(300))?,
        };
        Ok(Self {
            pils_profile,
            core,
            host,
            driver,
            unix: UnixAccess::from_config(config, b"regex")?.unwrap_or_default(),
            startup: duration(config, b"STARTUP_TIMEOUT", Duration::from_secs(300))?,
        })
    }
}

/// Read the real SERVICE options for REGEX's immediate service shutdown policy.
pub fn service_options(config: &Configuration) -> Result<ServiceOptions, Failure> {
    gnunet_service_runtime::service_options(config, b"regex", ShutdownMode::Immediate)
}

/// Derive the actual native DHT request/IO budgets from the same service owners.
pub fn dht_limits(
    core: core::Limits,
    host: Limits,
    driver: driver::Limits,
) -> Result<NativeLimits, Fault> {
    Ok(NativeLimits {
        operations: driver.operations,
        bytes: core.retained_bytes,
        query_bytes: core.input_bytes.checked_add(1).ok_or(Fault::Overflow)?,
        block_bytes: core.block_bytes,
        paths: core.output_paths,
        output_lifetime: host.output_lifetime,
        partial_input: host.partial_input,
        io_slice_bytes: host.io_slice_bytes,
    })
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
