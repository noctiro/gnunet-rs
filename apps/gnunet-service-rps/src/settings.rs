//! Official RPS options and separate bounded native/core resources.
use crate::Cause;
use gnunet_config::Configuration;
use gnunet_rps::{Config, Limits};
use gnunet_rps_host::server;
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use std::time::Duration;

fn number(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Cause> {
    Ok(c.get(b"rps-rust", key)
        .map(|_| c.get_number(b"rps-rust", key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn size(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Cause> {
    Ok(c.get(b"rps-rust", key)
        .map(|_| c.get_size(b"rps-rust", key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn time(c: &Configuration, section: &[u8], key: &[u8], default: u64) -> Result<u64, Cause> {
    let value = c
        .get(section, key)
        .map(|_| c.get_time(section, key))
        .transpose()?
        .unwrap_or(default);
    if value == 0
        || value == u64::MAX
        || std::time::Instant::now()
            .checked_add(Duration::from_micros(value))
            .is_none()
    {
        return Err("RPS interval must be finite, nonzero and representable".into());
    }
    Ok(value)
}
pub(super) struct Settings {
    pub core: Config,
    pub limits: Limits,
    pub native: server::Limits,
    pub cadet: gnunet_cadet_host::Limits,
    pub core_client: gnunet_core_client_host::Limits,
    pub peerstore: gnunet_peerstore_client_host::Limits,
    pub nse: gnunet_nse_client_host::Limits,
    pub access: UnixAccess,
    pub options: ServiceOptions,
    pub resolver: gnunet_resolver_broker::Limits,
    pub shutdown_grace: Duration,
    pub startup_timeout: Duration,
    pub discovery_lifetime: u64,
}
impl Settings {
    pub fn read(c: &Configuration) -> Result<Self, Cause> {
        let minimum = c
            .get(b"rps", b"MINSIZE")
            .map(|_| c.get_number(b"rps", b"MINSIZE"))
            .transpose()?
            .map(usize::try_from)
            .transpose()?
            .unwrap_or(10);
        let d = Limits::default();
        let limits = Limits {
            groups: number(c, b"MAX_GROUPS", d.groups)?,
            clients: number(c, b"MAX_CLIENTS", d.clients)?,
            peers_per_group: number(c, b"MAX_PEERS_PER_GROUP", d.peers_per_group)?,
            view: number(c, b"MAX_VIEW_PEERS", d.view)?,
            sampler: number(c, b"MAX_SAMPLER_SLOTS", d.sampler)?,
            effects: number(c, b"MAX_EFFECTS", d.effects)?,
            retained_bytes: size(c, b"CORE_RETAINED_BYTES", d.retained_bytes)?,
        };
        let core = Config {
            view_size: minimum,
            sampler_size: minimum,
            round_interval: time(c, b"rps", b"ROUNDINTERVAL", 30_000_000)?,
            probe_timeout: time(c, b"rps-rust", b"PROBE_TIMEOUT", 30_000_000)?,
        };
        if minimum == 0
            || minimum > limits.view
            || minimum > limits.sampler
            || core.round_interval < 2
            || core.round_interval > u64::MAX / 2
        {
            return Err(
                "RPS initial sampler/view must fit its finite resource and timing bounds".into(),
            );
        }
        limits.validate(core)?;
        let nd = server::Limits::default();
        let native = server::Limits {
            clients: limits.clients,
            groups: limits.groups,
            channels: number(c, b"MAX_CADET_CHANNELS", nd.channels)?,
            seed_peers: number(c, b"MAX_DISCOVERY_PEERS", nd.seed_peers)?,
            frame_bytes: size(c, b"FRAME_BYTES", nd.frame_bytes)?,
            io_slice_bytes: size(c, b"IO_SLICE_BYTES", nd.io_slice_bytes)?,
            output_frames: number(c, b"MAX_CLIENT_OUTPUT_FRAMES", nd.output_frames)?,
            output_bytes: size(c, b"CLIENT_OUTPUT_BYTES", nd.output_bytes)?,
            peer_frames: number(c, b"MAX_PEER_OUTPUT_FRAMES", nd.peer_frames)?,
            peer_bytes: size(c, b"PEER_OUTPUT_BYTES", nd.peer_bytes)?,
            first_input: Duration::from_micros(time(c, b"rps-rust", b"FIRST_INPUT", 30_000_000)?),
            partial_input: Duration::from_micros(time(
                c,
                b"rps-rust",
                b"PARTIAL_INPUT",
                15_000_000,
            )?),
            retirement_grace: Duration::from_micros(time(
                c,
                b"rps-rust",
                b"RETIREMENT_GRACE",
                5_000_000,
            )?),
            reply_profile: match c.get(b"rps-rust", b"IPC_NATIVE_BYTE_ORDER") {
                None => nd.reply_profile,
                Some(b"little" | b"LITTLE") => {
                    gnunet_wire::official::rps::ReplyCountProfile::CNativeLittle
                }
                Some(b"big" | b"BIG") => gnunet_wire::official::rps::ReplyCountProfile::CNativeBig,
                Some(_) => return Err("IPC_NATIVE_BYTE_ORDER must be little or big".into()),
            },
        };
        if limits.groups == 0
            || limits.clients == 0
            || limits.effects == 0
            || limits.peers_per_group == 0
            || limits.view == 0
            || limits.view > 2047
            || limits.sampler == 0
            || limits.sampler > gnunet_rps::Sampler::MAX_SLOTS
            || limits.retained_bytes == 0
            || !(1..=4096).contains(&native.channels)
            || native.channels < minimum
        {
            return Err("invalid RPS bounded resource configuration".into());
        }
        let cd = gnunet_cadet_host::Limits::default();
        let cadet = gnunet_cadet_host::Limits {
            frame_bytes: size(c, b"CADET_FRAME_BYTES", cd.frame_bytes)?,
            io_slice_bytes: size(c, b"CADET_IO_SLICE_BYTES", cd.io_slice_bytes)?,
            max_payload_bytes: size(c, b"CADET_PAYLOAD_BYTES", cd.max_payload_bytes)?,
            max_send_credit: u32::try_from(number(
                c,
                b"CADET_SEND_CREDIT",
                cd.max_send_credit as usize,
            )?)?,
        };
        let rd = gnunet_resolver_broker::Limits::default();
        let resolver = gnunet_resolver_broker::Limits {
            max_frame_bytes: size(c, b"RESOLVER_FRAME_BYTES", rd.max_frame_bytes)?,
            io_chunk_bytes: size(c, b"RESOLVER_IO_SLICE_BYTES", rd.io_chunk_bytes)?,
            max_queued_frames: number(c, b"RESOLVER_OUTPUT_FRAMES", rd.max_queued_frames)?,
        };
        let yes = |key: &[u8], default: bool| {
            c.get(b"rps", key)
                .map(|_| c.get_yesno(b"rps", key))
                .transpose()
                .map(|v| v.unwrap_or(default))
        };
        Ok(Self {
            core,
            limits,
            native,
            cadet,
            resolver,
            core_client: gnunet_core_client_host::Limits::default(),
            peerstore: gnunet_peerstore_client_host::Limits::default(),
            nse: gnunet_nse_client_host::Limits::default(),
            access: UnixAccess {
                match_uid: yes(b"UNIX_MATCH_UID", false)?,
                match_gid: yes(b"UNIX_MATCH_GID", true)?,
            },
            options: service_options(c, b"rps", ShutdownMode::Immediate)?,
            shutdown_grace: Duration::from_micros(time(
                c,
                b"rps-rust",
                b"SHUTDOWN_GRACE",
                10_000_000,
            )?),
            startup_timeout: Duration::from_micros(time(
                c,
                b"rps-rust",
                b"STARTUP_TIMEOUT",
                30_000_000,
            )?),
            discovery_lifetime: time(c, b"rps-rust", b"DISCOVERY_LIFETIME", 3_600_000_000)?,
        })
    }
}
