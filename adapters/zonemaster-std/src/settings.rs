//! Official zonemaster settings plus explicit Rust resource ceilings.
use crate::{Failure, nonce, owner, service};
use gnunet_config::Configuration;
use gnunet_config::ProcessEnvironment;
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
};
use gnunet_zonemaster::schedule;
use std::time::Duration;
/// Actual complete process resource/configuration policy.
pub struct Settings {
    /// Actual bounded publication scheduler.
    pub core: schedule::Limits,
    /// Actual native/worker/stream bounds.
    pub owner: owner::Limits,
    /// Shared durable expiration namespace; the worker performs actual IO.
    pub nonce: nonce::Config,
    /// Empty-handler SERVICE client bounds.
    pub service: service::Limits,
    /// Shared official listener/ACL/lifetime policy.
    pub options: ServiceOptions,
    /// Actual Unix kernel-credential checks.
    pub unix: UnixAccess,
    /// Actual configured NAMECACHE disable switch.
    pub cache_enabled: bool,
    /// Same process Resolver budget.
    pub resolver: gnunet_resolver_broker::Limits,
    /// Independent final statistics/CPU cleanup bound.
    pub grace: Duration,
}
fn number(c: &Configuration, section: &[u8], key: &[u8], default: usize) -> Result<usize, Failure> {
    Ok(if c.have_value(section, key) {
        usize::try_from(c.get_number(section, key)?)?
    } else {
        default
    })
}
fn time(
    c: &Configuration,
    section: &[u8],
    key: &[u8],
    default: Duration,
) -> Result<Duration, Failure> {
    let d = if c.have_value(section, key) {
        Duration::from_micros(c.get_time(section, key)?)
    } else {
        default
    };
    if d.is_zero()
        || d.as_micros() >= u128::from(u64::MAX)
        || tokio::time::Instant::now().checked_add(d).is_none()
    {
        return Err("zonemaster requires finite nonzero time policy".into());
    }
    Ok(d)
}
fn flag(c: &Configuration, section: &[u8], key: &[u8], default: bool) -> Result<bool, Failure> {
    Ok(if c.have_value(section, key) {
        c.get_yesno(section, key)?
    } else {
        default
    })
}
impl Settings {
    /// Read only actual official settings and explicit Rust budgets. This
    /// touches no key/store, listener, crypto worker, helper or route.
    pub fn read(c: &Configuration) -> Result<Self, Failure> {
        let mut core = schedule::Limits::default();
        let mut owner = owner::Limits::default();
        let mut service = service::Limits::default();
        let resources = b"zonemaster-rust";
        let nonce_directory = if c.have_value(resources, b"NONCE_DIRECTORY") {
            c.get_filename(resources, b"NONCE_DIRECTORY", &ProcessEnvironment)?
        } else {
            let raw = b"${GNUNET_DATA_HOME}/gns-publication-rust-v1";
            let expanded = c.expand_dollar(raw, &ProcessEnvironment)?;
            if expanded == raw {
                return Err("set [zonemaster-rust] NONCE_DIRECTORY or GNUNET_DATA_HOME".into());
            }
            c.expand_filename(&expanded, &ProcessEnvironment)?
        };
        let nonce = nonce::Config::new(
            nonce_directory,
            number(c, resources, b"MAX_NONCE_KEYS", 65536)?,
        )?;
        core.jobs = number(c, resources, b"MAX_JOBS", core.jobs)?;
        core.labels = number(c, resources, b"MAX_FENCE_LABELS", core.labels)?;
        core.bytes = number(c, resources, b"PAYLOAD_BYTES", core.bytes)?;
        core.window = u64::try_from(
            time(
                c,
                b"zonemaster",
                b"ZONE_PUBLISH_TIME_WINDOW",
                Duration::from_micros(core.window),
            )?
            .as_micros(),
        )?;
        core.job_timeout = u64::try_from(
            time(
                c,
                resources,
                b"JOB_TIMEOUT",
                Duration::from_micros(core.job_timeout),
            )?
            .as_micros(),
        )?;
        owner.workers = number(c, b"zonemaster", b"WORKER_COUNT", 4)?;
        owner.worker_queue = number(c, resources, b"WORKER_QUEUE", core.jobs)?;
        owner.publications =
            number(c, b"zonemaster", b"MAX_PARALLEL_BACKGROUND_QUERIES", 1000)?.max(1);
        owner.source_lifetime = time(c, resources, b"SOURCE_LIFETIME", owner.source_lifetime)?;
        owner.control_timeout = time(c, resources, b"CONTROL_TIMEOUT", owner.control_timeout)?;
        owner.retry = time(c, resources, b"CAPACITY_RETRY", owner.retry)?;
        owner.material.records = number(c, resources, b"MAX_RECORDS", owner.material.records)?;
        owner.namestore.records = owner.material.records;
        owner.cache.operations = owner.publications.min(core.jobs).max(1);
        owner.cache.block_bytes = gnunet_wire::official::namecache::MAX_WIRE_BLOCK_BYTES;
        service.clients = number(c, resources, b"MAX_CLIENTS", service.clients)?;
        service.idle = time(c, resources, b"CLIENT_IDLE_TIMEOUT", service.idle)?;
        service.partial = time(c, resources, b"CLIENT_PARTIAL_TIMEOUT", service.partial)?;
        let options =
            gnunet_service_runtime::service_options(c, b"zonemaster", ShutdownMode::Immediate)?;
        let unix = UnixAccess {
            match_uid: flag(c, b"zonemaster", b"UNIX_MATCH_UID", false)?,
            match_gid: flag(c, b"zonemaster", b"UNIX_MATCH_GID", false)?,
        };
        Ok(Self {
            core,
            owner,
            nonce,
            service,
            options,
            unix,
            cache_enabled: !flag(c, b"namecache", b"DISABLE", false)?,
            resolver: Default::default(),
            grace: time(c, resources, b"SHUTDOWN_GRACE", Duration::from_secs(10))?,
        })
    }
}
