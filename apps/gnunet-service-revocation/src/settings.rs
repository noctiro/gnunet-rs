//! Official configuration with explicit finite internal resource/ABI profiles.
use crate::{Failure, statistics};
use gnunet_config::Configuration;
use gnunet_revocation::{DEFAULT_POLICY, RevocationConfig};
use gnunet_revocation_host::server::Limits;
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use std::{path::PathBuf, time::Duration};
const LOCAL: &[u8] = b"revocation-rust";
fn n(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Failure> {
    Ok(c.get(LOCAL, key)
        .map(|_| c.get_number(LOCAL, key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn duration(c: &Configuration, key: &[u8], default: Duration) -> Result<Duration, Failure> {
    let micros = c
        .get(LOCAL, key)
        .map(|_| c.get_time(LOCAL, key))
        .transpose()?
        .unwrap_or(u64::try_from(default.as_micros())?);
    if micros == 0
        || micros == u64::MAX
        || std::time::Instant::now()
            .checked_add(Duration::from_micros(micros))
            .is_none()
    {
        return Err("REVOCATION bounds must be finite/nonzero".into());
    }
    Ok(Duration::from_micros(micros))
}
pub(super) struct Settings {
    pub limits: Limits,
    pub policy: RevocationConfig,
    pub options: ServiceOptions,
    pub unix: UnixAccess,
    pub store: PathBuf,
    pub grace: Duration,
    pub resolver: gnunet_resolver_broker::Limits,
    pub core_order: gnunet_core_client_host::ClassOrder,
    pub statistics: statistics::Limits,
    pub statistics_grace: Duration,
}
impl Settings {
    pub fn read(c: &Configuration) -> Result<Self, Failure> {
        let mut limits = Limits::default();
        limits.clients = n(c, b"MAX_CLIENTS", limits.clients)?;
        limits.peers = n(c, b"MAX_PEERS", limits.peers)?;
        limits.certificates = n(c, b"MAX_CERTIFICATES", limits.certificates)?;
        limits.snapshot_bytes = n(c, b"SNAPSHOT_BYTES", limits.snapshot_bytes)?;
        limits.network_inputs = n(c, b"NETWORK_INPUTS", limits.network_inputs)?;
        limits.io_slice_bytes = n(c, b"IO_SLICE_BYTES", limits.io_slice_bytes)?;
        limits.first_input = duration(c, b"FIRST_INPUT_TIMEOUT", limits.first_input)?;
        limits.operation_lifetime = duration(c, b"OPERATION_LIFETIME", limits.operation_lifetime)?;
        limits.output_lifetime = duration(c, b"OUTPUT_LIFETIME", limits.output_lifetime)?;
        limits.retirement_grace = duration(c, b"RETIREMENT_GRACE", limits.retirement_grace)?;
        limits.listener_lifetime = duration(c, b"LISTENER_LIFETIME", limits.listener_lifetime)?;
        limits.retry = duration(c, b"RETRY_INTERVAL", limits.retry)?;
        limits.reconciliation_interval = duration(
            c,
            b"RECONCILIATION_INTERVAL",
            limits.reconciliation_interval,
        )?;
        limits.tick = duration(c, b"TICK_INTERVAL", limits.tick)?;
        limits.setu_abi = match c.get(LOCAL, b"SETU_ABI").unwrap_or(b"native") {
            b"native" => gnunet_setu_client_host::ipc::Abi::native(),
            b"little64" => gnunet_setu_client_host::ipc::Abi {
                order: gnunet_setu_client_host::ipc::Order::Little,
                align64: 8,
            },
            b"little32" => gnunet_setu_client_host::ipc::Abi {
                order: gnunet_setu_client_host::ipc::Order::Little,
                align64: 4,
            },
            b"big64" => gnunet_setu_client_host::ipc::Abi {
                order: gnunet_setu_client_host::ipc::Order::Big,
                align64: 8,
            },
            b"big32" => gnunet_setu_client_host::ipc::Abi {
                order: gnunet_setu_client_host::ipc::Order::Big,
                align64: 4,
            },
            _ => return Err("SETU_ABI must be native/little64/little32/big64/big32".into()),
        };
        let bits = c
            .get(b"revocation", b"WORKBITS")
            .map(|_| c.get_number(b"revocation", b"WORKBITS"))
            .transpose()?
            .unwrap_or(u64::from(DEFAULT_POLICY.matching_bits));
        let epoch = c
            .get(b"revocation", b"EPOCH_DURATION")
            .map(|_| c.get_time(b"revocation", b"EPOCH_DURATION"))
            .transpose()?
            .unwrap_or(DEFAULT_POLICY.epoch_duration);
        if bits >= 512 || epoch == 0 {
            return Err("REVOCATION work policy invalid".into());
        }
        let store = if c.get(LOCAL, b"STORE_DIRECTORY").is_some() {
            c.get_filename(
                LOCAL,
                b"STORE_DIRECTORY",
                &gnunet_config::ProcessEnvironment,
            )?
        } else {
            let path = c.get_filename(
                b"revocation",
                b"DATABASE",
                &gnunet_config::ProcessEnvironment,
            )?;
            let mut path = path.into_os_string();
            path.push(".rust-store");
            PathBuf::from(path)
        };
        let yes = |key: &[u8]| -> Result<bool, Failure> {
            Ok(c.get(b"revocation", key)
                .map(|_| c.get_yesno(b"revocation", key))
                .transpose()?
                .unwrap_or(false))
        };
        let native_order = if cfg!(target_endian = "little") {
            gnunet_core_client_host::ClassOrder::Little
        } else {
            gnunet_core_client_host::ClassOrder::Big
        };
        let core_order = match c.get(LOCAL, b"CORE_CLASS_ORDER").unwrap_or(b"native") {
            b"native" => native_order,
            b"little" => gnunet_core_client_host::ClassOrder::Little,
            b"big" => gnunet_core_client_host::ClassOrder::Big,
            _ => return Err("CORE_CLASS_ORDER must be native/little/big".into()),
        };
        Ok(Self {
            limits,
            policy: RevocationConfig {
                matching_bits: u32::try_from(bits)?,
                epoch_duration: epoch,
            },
            options: service_options(c, b"revocation", ShutdownMode::Immediate)?,
            unix: UnixAccess {
                match_uid: yes(b"UNIX_MATCH_UID")?,
                match_gid: yes(b"UNIX_MATCH_GID")?,
            },
            store,
            grace: duration(c, b"SHUTDOWN_GRACE", Duration::from_secs(5))?,
            resolver: gnunet_resolver_broker::Limits {
                max_frame_bytes: 65535,
                io_chunk_bytes: limits.io_slice_bytes,
                max_queued_frames: 8,
            },
            core_order,
            statistics: statistics::Limits {
                operation: duration(c, b"STATISTICS_TIMEOUT", Duration::from_secs(5))?,
                ..Default::default()
            },
            statistics_grace: duration(c, b"STATISTICS_SHUTDOWN_GRACE", Duration::from_secs(5))?,
        })
    }
}
