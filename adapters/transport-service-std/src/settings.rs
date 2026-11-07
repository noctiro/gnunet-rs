//! Official TRANSPORT configuration plus explicit bounded Rust resource policy.
//! Reading this policy neither opens a store/socket nor manufactures identity.
use crate::{Failure, discovery, pils, publication, validated};
use gnunet_config::{Configuration, ProcessEnvironment};
use gnunet_peerstore_client_host as peerstore;
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use std::{num::NonZeroUsize, path::PathBuf, time::Duration};
const LOCAL: &[u8] = b"transport-rust";
/// Actual public provider, source and service limits selected before runtime IO.
pub struct Settings {
    /// Pure protocol metadata/payload/control pools.
    pub core: gnunet_transport::Limits,
    /// Actual independent DV Actor/worker/shared-pool production composition.
    pub dv: crate::dv_settings::Policy,
    /// Original accepted-source/native frame/output deadlines.
    pub native: gnunet_transport_host::NativeLimits,
    /// Maximum actual local accepted IPC sources, matching the pure core limit.
    pub clients: usize,
    /// Per-source retained original native FIFO byte cap; allocation is lazy.
    pub pending_bytes: usize,
    /// Actual external URL/HELLO discovery pool and original source bounds.
    pub discovery: discovery::Limits,
    /// Shared actual PEERSTORE writer/query framing/source budgets.
    pub peerstore: peerstore::Limits,
    /// Actual one-node PILS source and original pending effect metadata.
    pub pils: pils::Limits,
    /// Actual validated-address STORE source and original operation bounds.
    pub validated: validated::Limits,
    /// Source-owned address/HELLO output caps and original publication budgets.
    pub publication: publication::Limits,
    /// Explicit official PILS/HELLO source profile shared by discovery and
    /// own publication. Conflicting global/local choices never fall back.
    pub profile: gnunet_pils::Profile,
    /// Original general provider work budget, distinct from queued/written.
    pub operation: Duration,
    /// Local source-recovery budget and stable-generation interval for restart
    /// backoff. This policy does not require an accepted client to send a frame.
    pub recovery: Duration,
    /// Official optional burst orchestration and finite original work budget.
    pub burst: gnunet_transport::burst::Policy,
    /// Inclusive sender scalar numeric width; independent from request lifetime.
    pub sender_monotime_horizon: Duration,
    /// Original finite native source cleanup grace; disk join remains real IO.
    pub grace: Duration,
    /// Bounded maintenance scheduling interval; not a forged completion timer.
    pub tick: Duration,
    /// New, independently marked Rust-owned public monotime generation store.
    pub stamp_path: PathBuf,
    /// Original listener ACL, tolerance and shutdown settings, default SOFT.
    pub options: ServiceOptions,
    /// Unix filesystem creation and kernel admission policy. Absent flags impose
    /// no UID/GID match; an explicit UID match takes precedence over GID matching.
    pub unix: UnixAccess,
    /// Original caller-driven shared Resolver IPC bounds.
    pub resolver: gnunet_resolver_broker::Limits,
}
fn number(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Failure> {
    Ok(c.get(LOCAL, key)
        .map(|_| c.get_number(LOCAL, key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn bytes(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Failure> {
    Ok(c.get(LOCAL, key)
        .map(|_| c.get_size(LOCAL, key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn bounded(value: usize, min: usize, max: usize) -> Result<usize, Failure> {
    if !(min..=max).contains(&value) {
        return Err("TRANSPORT resource parameter is outside its explicit bounded range".into());
    }
    Ok(value)
}
fn duration(c: &Configuration, key: &[u8], default: Duration) -> Result<Duration, Failure> {
    let value = c
        .get(LOCAL, key)
        .map(|_| c.get_time(LOCAL, key))
        .transpose()?
        .map(Duration::from_micros)
        .unwrap_or(default);
    if value.is_zero()
        || value == Duration::MAX
        || u64::try_from(value.as_micros()).is_err()
        || value.as_micros() == u128::from(u64::MAX)
        || tokio::time::Instant::now().checked_add(value).is_none()
    {
        return Err("TRANSPORT native budgets must be finite, positive and representable".into());
    }
    Ok(value)
}
fn yes(c: &Configuration, section: &[u8], key: &[u8], default: bool) -> Result<bool, Failure> {
    Ok(c.get(section, key)
        .map(|_| c.get_yesno(section, key))
        .transpose()?
        .unwrap_or(default))
}
impl Settings {
    /// Parse actual official listener keys and all local resource limits before
    /// privilege change, worker/storage startup, or network admission.
    pub fn read(c: &Configuration) -> Result<Self, Failure> {
        let use_burst = yes(c, b"transport", b"USE_BURST_NAT", false)?;
        let profile = gnunet_pils::Profile::configured(
            c.get(b"PILS", b"PROFILE"),
            c.get(LOCAL, b"PILS_PROFILE"),
        )?;
        let defaults = gnunet_transport::Limits::default();
        let clients = bounded(number(c, b"MAX_CLIENTS", defaults.clients)?, 1, 128)?;
        let core = gnunet_transport::Limits {
            clients,
            queues: bounded(number(c, b"MAX_QUEUES", defaults.queues)?, 1, 1024)?,
            peers: bounded(number(c, b"MAX_PEERS", defaults.peers)?, 1, 1024)?,
            messages: bounded(number(c, b"MAX_MESSAGES", defaults.messages)?, 8, 4096)?,
            bytes: bounded(
                bytes(c, b"PAYLOAD_BYTES", defaults.bytes)?,
                65535,
                256 * 1024 * 1024,
            )?,
            control_messages: bounded(
                number(c, b"CONTROL_MESSAGES", defaults.control_messages)?,
                1,
                128,
            )?,
            control_bytes: bounded(
                bytes(c, b"CONTROL_BYTES", defaults.control_bytes)?,
                120,
                65535,
            )?,
            assemblies: bounded(number(c, b"MAX_ASSEMBLIES", defaults.assemblies)?, 1, 1024)?,
            assemblies_per_peer: bounded(
                number(c, b"ASSEMBLIES_PER_PEER", defaults.assemblies_per_peer)?,
                1,
                1024,
            )?,
        };
        if core.assemblies_per_peer > core.assemblies {
            return Err("ASSEMBLIES_PER_PEER exceeds the shared assembly pool".into());
        }
        core.messages
            .checked_mul(8192)
            .ok_or("TRANSPORT retry bitmap capacity overflow")?;
        core.bytes
            .checked_add(core.control_bytes)
            .ok_or("TRANSPORT byte budget overflow")?;
        let pending_bytes = bounded(
            bytes(c, b"PENDING_BYTES", 256 * 1024)?,
            65535,
            16 * 1024 * 1024,
        )?;
        clients
            .checked_mul(pending_bytes)
            .ok_or("TRANSPORT native FIFO budget overflow")?;
        if c.get(LOCAL, b"CLIENT_INITIAL_LIFETIME").is_some() {
            return Err("CLIENT_INITIAL_LIFETIME was removed: idle applications have no INIT; remove the option and use CLIENT_SOURCE_LIFETIME for the accepted-source lease".into());
        }
        let operation = duration(c, b"OPERATION_LIFETIME", Duration::from_secs(60))?;
        let recovery = duration(c, b"RECOVERY_WINDOW", Duration::from_secs(10))?;
        let burst_lifetime = operation
            .checked_add(Duration::from_secs(60))
            .ok_or(gnunet_types::Error::Overflow)?;
        let burst = gnunet_transport::burst::Policy::checked(
            use_burst,
            gnunet_wire::official::RelativeTime::from_micros(
                u64::try_from(burst_lifetime.as_micros())
                    .map_err(|_| gnunet_types::Error::Overflow)?,
            ),
        )?;
        let sender_monotime_horizon =
            duration(c, b"SENDER_MONOTIME_HORIZON", Duration::from_secs(300))?;
        if !(Duration::from_secs(60)..=Duration::from_secs(86400))
            .contains(&sender_monotime_horizon)
        {
            return Err("SENDER_MONOTIME_HORIZON must be between one minute and one day".into());
        }
        let grace = duration(c, b"SHUTDOWN_GRACE", Duration::from_secs(5))?;
        let tick = duration(c, b"MAINTENANCE_INTERVAL", Duration::from_millis(50))?;
        if tick < Duration::from_millis(1) || tick > Duration::from_secs(1) {
            return Err("MAINTENANCE_INTERVAL must be between1ms and1s".into());
        }
        let native = gnunet_transport_host::NativeLimits {
            lifetime: duration(c, b"CLIENT_SOURCE_LIFETIME", Duration::from_secs(86400))?,
            input: duration(c, b"CLIENT_INPUT_LIFETIME", Duration::from_secs(10))?,
            output: duration(c, b"CLIENT_OUTPUT_LIFETIME", Duration::from_secs(10))?,
        };
        let slice = bounded(bytes(c, b"IO_SLICE_BYTES", 65535)?, 1, 65535)?;
        let discovery_peers = bounded(
            number(c, b"DISCOVERY_PEERS", 16.min(core.peers))?,
            1,
            64.min(core.peers),
        )?;
        let ps_defaults = peerstore::Limits::default();
        let peerstore = peerstore::Limits {
            operations: bounded(
                number(
                    c,
                    b"PEERSTORE_OPERATIONS",
                    ps_defaults.operations.max(discovery_peers),
                )?,
                discovery_peers,
                128,
            )?,
            frame_bytes: 65535,
            source_bytes: bounded(
                bytes(c, b"PEERSTORE_SOURCE_BYTES", ps_defaults.source_bytes)?,
                65535,
                16 * 1024 * 1024,
            )?,
            output: gnunet_service_runtime::framing::Budget {
                frames: bounded(
                    number(c, b"PEERSTORE_OUTPUT_FRAMES", ps_defaults.output.frames)?,
                    1,
                    256,
                )?,
                bytes: bounded(
                    bytes(c, b"PEERSTORE_OUTPUT_BYTES", ps_defaults.output.bytes)?,
                    65535,
                    16 * 1024 * 1024,
                )?,
            },
            io_slice_bytes: slice,
            retirement_grace_micros: u64::try_from(grace.as_micros())?,
        };
        let dd = discovery::Limits::default();
        let discovery = discovery::Limits {
            peers: discovery_peers,
            cache_records: bounded(number(c, b"DISCOVERY_RECORDS", dd.cache_records)?, 1, 16384)?,
            cache_bytes: bounded(
                bytes(c, b"DISCOVERY_BYTES", dd.cache_bytes)?,
                1,
                16 * 1024 * 1024,
            )?,
            address_bytes: bounded(
                bytes(c, b"ADDRESS_BYTES", dd.address_bytes)?,
                1,
                65535 - 128,
            )?,
            hello_bytes: bounded(
                bytes(c, b"HELLO_BYTES", dd.hello_bytes)?,
                gnunet_hello::MESSAGE_FIXED_LEN,
                65535,
            )?,
            hello_addresses: bounded(number(c, b"HELLO_ADDRESSES", dd.hello_addresses)?, 1, 4096)?,
            record_quantum: NonZeroUsize::new(bounded(
                number(c, b"DISCOVERY_RECORD_QUANTUM", dd.record_quantum.get())?,
                1,
                256,
            )?)
            .ok_or("nonzero discovery record quantum required")?,
            io_quantum: NonZeroUsize::new(bounded(
                number(c, b"DISCOVERY_IO_QUANTUM", dd.io_quantum.get())?,
                1,
                128,
            )?)
            .ok_or("nonzero discovery IO quantum required")?,
            query_lifetime: duration(c, b"DISCOVERY_QUERY_LIFETIME", dd.query_lifetime)?,
            query_refresh: duration(c, b"DISCOVERY_QUERY_REFRESH", dd.query_refresh)?,
            monitor_lifetime: duration(c, b"DISCOVERY_MONITOR_LIFETIME", dd.monitor_lifetime)?,
            idle: duration(c, b"DISCOVERY_IDLE_LIFETIME", dd.idle)?,
            initialization: duration(c, b"DISCOVERY_INITIAL_LIFETIME", dd.initialization)?,
            partial_frame: duration(c, b"DISCOVERY_PARTIAL_LIFETIME", dd.partial_frame)?,
            retry: duration(c, b"DISCOVERY_RETRY", dd.retry)?,
            retirement: grace,
            signature_profile: profile.hello(),
        };
        if discovery.cache_bytes < discovery.address_bytes {
            return Err("DISCOVERY_BYTES must fit at least ADDRESS_BYTES".into());
        }
        discovery
            .peers
            .checked_add(1)
            .and_then(|n| n.checked_mul(peerstore.frame_bytes))
            .ok_or("TRANSPORT discovery original frame budget overflow")?;
        let pd = pils::Limits::default();
        let jobs = bounded(number(c, b"PILS_JOBS", pd.jobs)?, 1, 32)?;
        let pils = pils::Limits {
            client: gnunet_pils_host::client::Limits {
                pending_operations: jobs,
                frame_bytes: 65535,
                io_slice_bytes: slice,
            },
            source: duration(c, b"PILS_SOURCE_LIFETIME", pd.source)?,
            initial: duration(c, b"PILS_INITIAL_LIFETIME", pd.initial)?,
            input: duration(c, b"PILS_INPUT_LIFETIME", pd.input)?,
            retire: duration(c, b"PILS_RETIREMENT", pd.retire)?,
            jobs,
        };
        let vd = validated::Limits::default();
        let validated = validated::Limits {
            client: peerstore::Limits {
                operations: 1,
                ..peerstore
            },
            operation,
            initial: duration(c, b"PEERSTORE_INITIAL_LIFETIME", vd.initial)?,
            input: duration(c, b"PEERSTORE_INPUT_LIFETIME", vd.input)?,
            source: duration(c, b"PEERSTORE_SOURCE_LIFETIME", vd.source)?,
            retry: duration(c, b"PEERSTORE_RETRY", vd.retry)?,
        };
        let output = gnunet_transport::own::PublicationBounds::checked(
            core.control_messages,
            core.control_bytes,
            pils.client.frame_bytes,
            peerstore.frame_bytes,
        )?;
        let publication = publication::Limits {
            signature_profile: profile.hello(),
            addresses: core.control_messages,
            hello: gnunet_hello::Limits {
                maximum_input_bytes: 65535,
                maximum_address_bytes: output.address_bytes,
                maximum_addresses: core.control_messages,
            },
            output,
            operation,
            retirement: grace,
        };
        let stamp_path = if c.get(LOCAL, b"MONOTIME_STORE").is_some() {
            c.get_filename(LOCAL, b"MONOTIME_STORE", &ProcessEnvironment)?
        } else {
            let raw = b"$GNUNET_DATA_HOME/transport-rust-monotime";
            let value = c.expand_dollar(raw, &ProcessEnvironment)?;
            if value == raw {
                return Err("set GNUNET_DATA_HOME or [transport-rust] MONOTIME_STORE to an independent Rust-owned directory".into());
            }
            c.expand_filename(&value, &ProcessEnvironment)?
        };
        if !stamp_path.is_absolute() || stamp_path.file_name().is_none() {
            return Err("MONOTIME_STORE must be an absolute final directory path".into());
        }
        let dv = crate::dv_settings::Policy::read(c, &stamp_path, operation)?;
        Ok(Self {
            core,
            dv,
            native,
            clients,
            pending_bytes,
            discovery,
            peerstore,
            pils,
            validated,
            publication,
            profile,
            operation,
            recovery,
            burst,
            sender_monotime_horizon,
            grace,
            tick,
            stamp_path,
            options: service_options(c, b"transport", ShutdownMode::Soft)?,
            unix: UnixAccess {
                match_uid: yes(c, b"transport", b"UNIX_MATCH_UID", false)?,
                match_gid: yes(c, b"transport", b"UNIX_MATCH_GID", false)?,
            },
            resolver: gnunet_resolver_broker::Limits {
                max_frame_bytes: 65535,
                io_chunk_bytes: slice,
                max_queued_frames: bounded(number(c, b"RESOLVER_QUEUE_FRAMES", 8)?, 1, 64)?,
            },
        })
    }
}
