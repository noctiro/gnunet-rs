//! Actual FS policy from existing official/Rust-owned configuration keys.
use crate::peer;
use gnunet_config::{Configuration, ProcessEnvironment};
use gnunet_fs::service as pure;
use gnunet_fs_host::{
    index,
    server::{
        Limits,
        cadet_server::{Limits as ServingLimits, source::Limits as SourceLimits},
    },
};
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use gnunet_types::{Duration as Timeout, Error as ProtocolError};
use std::{error::Error, path::PathBuf, time::Duration};
fn number(config: &Configuration, key: &[u8], default: usize) -> Result<usize, Box<dyn Error>> {
    config
        .get(b"fs-rust", key)
        .map(|_| config.get_number(b"fs-rust", key))
        .transpose()?
        .map(usize::try_from)
        .transpose()
        .map(|value| value.unwrap_or(default))
        .map_err(Into::into)
}
fn size(config: &Configuration, key: &[u8], default: u64) -> Result<u64, Box<dyn Error>> {
    Ok(config
        .get(b"fs-rust", key)
        .map(|_| config.get_size(b"fs-rust", key))
        .transpose()?
        .unwrap_or(default))
}
fn flag(config: &Configuration, section: &[u8], key: &[u8]) -> Result<bool, Box<dyn Error>> {
    flag_default(config, section, key, false)
}
fn flag_default(
    config: &Configuration,
    section: &[u8],
    key: &[u8],
    default: bool,
) -> Result<bool, Box<dyn Error>> {
    Ok(config
        .get(section, key)
        .map(|_| config.get_yesno(section, key))
        .transpose()?
        .unwrap_or(default))
}
fn finite_time(config: &Configuration, key: &[u8], default: u64) -> Result<u64, Box<dyn Error>> {
    let value = config
        .get(b"fs-rust", key)
        .map(|_| config.get_time(b"fs-rust", key))
        .transpose()?
        .unwrap_or(default);
    if value == 0 || value == u64::MAX {
        return Err("FS internal timeout/interval must be finite and nonzero".into());
    }
    Ok(value)
}
fn storage(config: &Configuration) -> Result<PathBuf, Box<dyn Error>> {
    if config.get(b"fs-rust", b"DIRECTORY").is_some() {
        return Ok(config.get_filename(b"fs-rust", b"DIRECTORY", &ProcessEnvironment)?);
    }
    let input = b"${GNUNET_DATA_HOME}/fs/index-rust";
    let expanded = config.expand_dollar(input, &ProcessEnvironment)?;
    if expanded == input {
        return Err("set [fs-rust] DIRECTORY or GNUNET_DATA_HOME".into());
    }
    Ok(config.expand_filename(&expanded, &ProcessEnvironment)?)
}
pub(super) fn filled<T: Clone>(length: usize, value: T) -> Result<Vec<T>, Box<dyn Error>> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| ProtocolError::Capacity)?;
    values.resize(length, value);
    Ok(values)
}
pub(super) struct Settings {
    pub pils_profile: gnunet_pils::Profile,
    pub directory: PathBuf,
    pub index: index::Limits,
    pub clients: usize,
    pub queries: usize,
    pub seen_per_query: usize,
    pub protocol: pure::Limits,
    pub native: Limits,
    pub datastore_timeout: Timeout,
    pub direct_cadet: bool,
    pub gap: peer::Settings,
    pub cadet_timeout: Duration,
    pub dht_timeout: Duration,
    pub serve_cadet: bool,
    pub serving: ServingLimits,
    pub source: SourceLimits,
    pub access: UnixAccess,
    pub options: ServiceOptions,
}
impl Settings {
    pub fn read(config: &Configuration) -> Result<Self, Box<dyn Error>> {
        let pils_profile = gnunet_pils::Profile::configured(config.get(b"PILS", b"PROFILE"), None)?;
        let defaults = index::Limits::default();
        let index = index::Limits {
            max_entries: number(config, b"INDEX_MAX_ENTRIES", defaults.max_entries)?,
            max_path_bytes: number(config, b"INDEX_MAX_PATH_BYTES", defaults.max_path_bytes)?,
            max_total_path_bytes: usize::try_from(size(
                config,
                b"INDEX_MAX_TOTAL_PATH_BYTES",
                u64::try_from(defaults.max_total_path_bytes)?,
            )?)?,
            max_file_bytes: size(config, b"INDEX_MAX_FILE_BYTES", defaults.max_file_bytes)?,
        };
        let clients = number(config, b"MAX_CLIENTS", 64)?;
        let queries = number(config, b"MAX_QUERIES", 128)?;
        let seen_per_query = number(config, b"SEEN_HASHES_PER_QUERY", 256)?;
        if clients == 0 || queries == 0 || seen_per_query == 0 {
            return Err("FS client/query/seen capacities must be nonzero".into());
        }
        queries
            .checked_mul(seen_per_query)
            .ok_or(ProtocolError::Capacity)?;
        let core_defaults = pure::Limits::default();
        let protocol = pure::Limits {
            max_block_bytes: number(config, b"MAX_BLOCK_BYTES", core_defaults.max_block_bytes)?,
            expire_ublocks: flag(config, b"fs-rust", b"EXPIRE_UBLOCKS")?,
        };
        let rescan_interval =
            Duration::from_micros(finite_time(config, b"RESCAN_INTERVAL", 10_000_000)?);
        if std::time::Instant::now()
            .checked_add(rescan_interval)
            .is_none()
        {
            return Err("FS rescan interval is not representable".into());
        }
        let native_defaults = Limits::default();
        let native = Limits {
            clients,
            route_slots: queries,
            index_queue: number(config, b"INDEX_QUEUE", native_defaults.index_queue)?,
            io_slice_bytes: number(config, b"IO_SLICE_BYTES", native_defaults.io_slice_bytes)?,
            rescan_interval,
        };
        let serving_defaults = ServingLimits::default();
        let source_defaults = SourceLimits::default();
        let official_cadet_clients = config
            .get(b"fs", b"MAX_CADET_CLIENTS")
            .map(|_| config.get_number(b"fs", b"MAX_CADET_CLIENTS"))
            .transpose()?
            .map(usize::try_from)
            .transpose()?
            .unwrap_or(128);
        let serving = ServingLimits {
            channels: number(config, b"CADET_SERVE_CHANNELS", serving_defaults.channels)?
                .min(official_cadet_clients.max(1)),
            block_bytes: number(
                config,
                b"CADET_SERVE_BLOCK_BYTES",
                protocol.max_block_bytes.min(serving_defaults.block_bytes),
            )?,
            idle_timeout: Duration::from_micros(finite_time(
                config,
                b"CADET_SERVE_IDLE_TIMEOUT",
                120_000_000,
            )?),
            write_timeout: Duration::from_micros(finite_time(
                config,
                b"CADET_SERVE_WRITE_TIMEOUT",
                10_000_000,
            )?),
            drain_timeout: Duration::from_micros(finite_time(
                config,
                b"CADET_SERVE_DRAIN_TIMEOUT",
                10_000_000,
            )?),
        };
        let source = SourceLimits {
            records: number(config, b"CADET_SERVE_RECORDS", source_defaults.records)?,
            block_bytes: serving.block_bytes,
        };
        if serving.channels == 0
            || serving.channels > 1024
            || serving.block_bytes == 0
            || serving.block_bytes > serving_defaults.block_bytes
            || source.records == 0
            || source.records > 4096
            || std::time::Instant::now()
                .checked_add(serving.idle_timeout)
                .is_none()
            || std::time::Instant::now()
                .checked_add(serving.write_timeout)
                .is_none()
            || std::time::Instant::now()
                .checked_add(serving.drain_timeout)
                .is_none()
        {
            return Err("invalid bounded FS CADET serving limits".into());
        }
        Ok(Self {
            pils_profile,
            directory: storage(config)?,
            index,
            clients,
            queries,
            seen_per_query,
            protocol,
            native,
            datastore_timeout: Timeout(finite_time(config, b"DATASTORE_TIMEOUT", 10_000_000)?),
            gap: peer::Settings::read(config, queries, native.io_slice_bytes)?,
            direct_cadet: flag_default(config, b"fs-rust", b"DIRECT_CADET", true)?,
            cadet_timeout: Duration::from_micros(finite_time(
                config,
                b"CADET_TIMEOUT",
                30_000_000,
            )?),
            dht_timeout: Duration::from_micros(finite_time(
                config,
                b"DHT_QUERY_TIMEOUT",
                30_000_000,
            )?),
            serve_cadet: flag_default(config, b"fs-rust", b"SERVE_CADET", true)?
                && official_cadet_clients != 0,
            serving,
            source,
            access: UnixAccess {
                match_uid: flag(config, b"fs", b"UNIX_MATCH_UID")?,
                match_gid: flag(config, b"fs", b"UNIX_MATCH_GID")?,
            },
            options: service_options(config, b"fs", ShutdownMode::Immediate)?,
        })
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Compare actual FS startup selection and its typed refusal"
    )]
    fn loc_signer_inherits_node_profile_before_storage_selection() -> Result<(), Box<dyn Error>> {
        let mut config = Configuration::default();
        config.set_value(
            b"fs-rust",
            b"DIRECTORY",
            Some(b"/private/tmp/fs-profile-selection"),
        )?;
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
        config.set_value(b"fs-rust", b"DIRECTORY", None)?;
        let error = Settings::read(&config)
            .err()
            .ok_or("unknown FS signer profile admitted")?;
        assert_eq!(
            error.downcast_ref::<ProtocolError>(),
            Some(&ProtocolError::InvalidInput)
        );
        Ok(())
    }
}
