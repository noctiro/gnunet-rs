//! Explicit foreground peer resources; no sockets, workers or hidden defaults.
use gnunet_cadet::{connection, peer, tunnel::controller};
use gnunet_cadet_host::{connection as bridge, management, node};
use gnunet_config::{Configuration, ProcessEnvironment};
use gnunet_core_client_host::Limits as CoreLimits;
use gnunet_service_runtime::framing::Budget;
use gnunet_types::Error as ProtocolError;
use std::{error::Error, path::PathBuf, time::Duration};

pub(super) const CORE_PEERS: usize = 64;
pub(super) const SENDS: usize = 32;
pub(super) const PILS_OPERATIONS: usize = 32;
pub(super) const PATH_PEERS: usize = 16;
pub(super) const FRAME_BYTES: usize = bridge::MAX_PEER_FRAME;
const MAX_PAYLOAD_MEMORY: usize = 128 * 1024 * 1024;

pub(crate) struct Settings {
    pub enabled: bool,
    pub tunnels: usize,
    pub channels: usize,
    pub routes: usize,
    pub discovery_replication: u32,
    pub origins: usize,
    pub frames: usize,
    pub skipped: usize,
    pub window: usize,
    pub payload: usize,
    pub plaintext_bytes: usize,
    pub ciphertext_bytes: usize,
    pub payload_memory: usize,
    pub monotime_file: Option<PathBuf>,
    pub monotime_reservation: u64,
    pub shutdown_grace: Duration,
    pub forced_drain: Duration,
    pub node: node::Limits,
    pub connection: connection::Limits,
    pub bridge: bridge::Limits,
}
fn number(config: &Configuration, key: &[u8], default: usize) -> Result<usize, Box<dyn Error>> {
    config
        .get(b"cadet-rust", key)
        .map(|_| config.get_number(b"cadet-rust", key))
        .transpose()?
        .map(usize::try_from)
        .transpose()
        .map(|n| n.unwrap_or(default))
        .map_err(Into::into)
}
fn interval(config: &Configuration, key: &[u8], default: u64) -> Result<u64, Box<dyn Error>> {
    let micros = config
        .get(b"cadet-rust", key)
        .map(|_| config.get_time(b"cadet-rust", key))
        .transpose()?
        .unwrap_or(default);
    if micros == 0
        || micros == u64::MAX
        || std::time::Instant::now()
            .checked_add(Duration::from_micros(micros))
            .is_none()
    {
        return Err("CADET peer timers must be finite, positive and representable".into());
    }
    Ok(micros)
}
impl Settings {
    pub fn read(
        config: &Configuration,
        payload: usize,
        io_slice: usize,
    ) -> Result<Self, Box<dyn Error>> {
        let enabled = config
            .get(b"cadet-rust", b"PEER_CORE")
            .map(|_| config.get_yesno(b"cadet-rust", b"PEER_CORE"))
            .transpose()?
            .unwrap_or(true);
        let tunnels = number(config, b"PEER_TUNNELS", 32)?;
        let channels = number(config, b"PEER_CHANNELS", 64)?;
        let routes = number(config, b"PEER_ROUTES", 128)?;
        let discovery_replication = config
            .get(b"cadet", b"DHT_REPLICATION_LEVEL")
            .map(|_| config.get_number(b"cadet", b"DHT_REPLICATION_LEVEL"))
            .transpose()?
            .map(u32::try_from)
            .transpose()?
            .unwrap_or(3);
        let origins = number(config, b"PEER_ORIGINS", 128)?;
        let frames = number(config, b"PEER_FRAMES", SENDS)?;
        let skipped = number(config, b"PEER_SKIPPED_KEYS", 32)?;
        let window = number(config, b"PEER_WINDOW", 1)?;
        let used = number(config, b"PEER_USED_CHANNELS", 4096)?;
        let reserve = number(config, b"PEER_MONOTIME_RESERVATION", 1024)?;
        let monitor_queries = number(config, b"PEER_MONITOR_QUERIES", 4)?;
        let monitor_records = number(config, b"PEER_MONITOR_RECORDS", 4096)?;
        let monitor_identities = number(config, b"PEER_MONITOR_PATH_IDENTITIES", 8192)?;
        let monitor_bytes = number(config, b"PEER_MONITOR_BYTES", 256 * 1024)?;
        let monitor_total = monitor_queries
            .checked_mul(monitor_bytes)
            .ok_or(ProtocolError::Overflow)?;
        let opening = interval(config, b"PEER_OPEN_TIMEOUT", 120_000_000)?;
        let idle = interval(config, b"PEER_IDLE_TIMEOUT", 120_000_000)?;
        let shutdown = interval(config, b"PEER_SHUTDOWN_GRACE", 5_000_000)?;
        let forced = interval(config, b"PEER_FORCED_DRAIN", 5_000_000)?;
        let send = interval(config, b"PEER_SEND_TIMEOUT", 10_000_000)?;
        let send_retire = interval(config, b"PEER_SEND_RETIRE_GRACE", 5_000_000)?;
        let plaintext_bytes = payload.checked_add(12).ok_or(ProtocolError::Overflow)?;
        let ciphertext_bytes = plaintext_bytes
            .checked_mul(2)
            .and_then(|n| n.checked_add(112))
            .ok_or(ProtocolError::Overflow)?;
        let bytes = channels
            .checked_mul(window)
            .and_then(|n| n.checked_mul(payload))
            .and_then(|n| n.checked_mul(2))
            .and_then(|n| {
                frames
                    .checked_mul(FRAME_BYTES)
                    .and_then(|f| n.checked_add(f))
            })
            .and_then(|n| n.checked_add(plaintext_bytes))
            .and_then(|n| n.checked_add(ciphertext_bytes))
            .ok_or(ProtocolError::Overflow)?;
        if !(1..=CORE_PEERS).contains(&tunnels)
            || !(1..=4096).contains(&channels)
            || !(1..=4096).contains(&routes)
            || !(1..=4096).contains(&origins)
            || !(1..=4096).contains(&frames)
            || !(1..=256).contains(&skipped)
            || !(1..=4).contains(&window)
            || !(4..=64348).contains(&payload)
            || used < channels
            || used > 1_048_576
            || reserve == 0
            || reserve > 1_048_576
            || !(1..=16).contains(&monitor_queries)
            || !(1..=16384).contains(&monitor_records)
            || !(1..=65536).contains(&monitor_identities)
            || !(256..=4_194_304).contains(&monitor_bytes)
            || monitor_total > 16 * 1024 * 1024
            || bytes > MAX_PAYLOAD_MEMORY
            || io_slice == 0
        {
            return Err("invalid bounded CADET peer pool/route/key/window resources".into());
        }
        let monotime_file = if enabled {
            Some(
                if config.get(b"cadet-rust", b"PEER_MONOTIME_FILE").is_some() {
                    config.get_filename(
                        b"cadet-rust",
                        b"PEER_MONOTIME_FILE",
                        &ProcessEnvironment,
                    )?
                } else {
                    config
                        .get_filename(b"paths", b"GNUNET_DATA_HOME", &ProcessEnvironment)?
                        .join("cadet")
                        .join("rust-monotime")
                },
            )
        } else {
            None
        };
        let channel = peer::Limits {
            window: u8::try_from(window)?,
            payload_bytes: payload,
            ..peer::Limits::default()
        };
        let mut tunnel = controller::Limits::default();
        tunnel.crypto.maximum_gap = u32::try_from(skipped)?;
        Ok(Self {
            enabled,
            tunnels,
            channels,
            routes,
            discovery_replication,
            origins,
            frames,
            skipped,
            window,
            payload,
            plaintext_bytes,
            ciphertext_bytes,
            payload_memory: bytes,
            monotime_file,
            monotime_reservation: u64::try_from(reserve)?,
            shutdown_grace: Duration::from_micros(shutdown),
            forced_drain: Duration::from_micros(forced),
            node: node::Limits {
                management: management::Limits {
                    queries: monitor_queries,
                    records: monitor_records,
                    path_identities: monitor_identities,
                    snapshot_bytes: monitor_bytes,
                },
                pending_frames: frames,
                used_channels: used,
                channel,
                tunnel,
                opening_micros: opening,
                idle_micros: idle,
                ..node::Limits::default()
            },
            connection: connection::Limits {
                frame_bytes: FRAME_BYTES,
                native_order: if cfg!(target_endian = "little") {
                    connection::NativeOrder::Little
                } else {
                    connection::NativeOrder::Big
                },
                ..connection::Limits::default()
            },
            bridge: bridge::Limits {
                send_budget: Some(bridge::SendBudget {
                    lifetime_micros: send,
                    retirement_grace_micros: send_retire,
                }),
                core: CoreLimits {
                    sends: SENDS,
                    source_bytes: SENDS * 65535,
                    frame_bytes: 65535,
                    output: Budget {
                        frames: SENDS + 4,
                        bytes: (SENDS + 4) * 65535,
                    },
                    io_slice_bytes: io_slice,
                },
                class_order: if cfg!(target_endian = "little") {
                    gnunet_core_client_host::ClassOrder::Little
                } else {
                    gnunet_core_client_host::ClassOrder::Big
                },
                ..bridge::Limits::default()
            },
        })
    }
}
