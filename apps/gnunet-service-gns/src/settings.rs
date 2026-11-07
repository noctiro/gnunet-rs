//! Public GNS SERVICE configuration and explicit Rust resource policies.
use crate::Cause;
use gnunet_config::Configuration;
use gnunet_gns_service_host::{
    auxiliary::{dns, registry, system},
    native, refresh, server,
};
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use std::{path::PathBuf, time::Duration};

fn number(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Cause> {
    c.get(b"gns-rust", key)
        .map(|_| c.get_number(b"gns-rust", key))
        .transpose()?
        .map(usize::try_from)
        .transpose()
        .map(|v| v.unwrap_or(default))
        .map_err(Into::into)
}
fn size(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Cause> {
    c.get(b"gns-rust", key)
        .map(|_| c.get_size(b"gns-rust", key))
        .transpose()?
        .map(usize::try_from)
        .transpose()
        .map(|v| v.unwrap_or(default))
        .map_err(Into::into)
}
fn micros(c: &Configuration, key: &[u8], default: u64) -> Result<u64, Cause> {
    let v = c
        .get(b"gns-rust", key)
        .map(|_| c.get_time(b"gns-rust", key))
        .transpose()?
        .unwrap_or(default);
    if v == 0
        || v == u64::MAX
        || std::time::Instant::now()
            .checked_add(Duration::from_micros(v))
            .is_none()
    {
        return Err("GNS request/cleanup time bounds must be finite and nonzero".into());
    }
    Ok(v)
}
pub(super) struct Settings {
    pub access: UnixAccess,
    pub options: ServiceOptions,
    pub core: gnunet_gns_service_host::Limits,
    pub frontend: server::Limits,
    pub interception: Option<gnunet_gns_service_host::interceptor::Limits>,
    pub native: native::Limits,
    pub refresh: refresh::Limits,
    pub system: system::Limits,
    pub dns: dns::DnsLimits,
    pub registry: registry::Limits,
    pub resolver: gnunet_resolver_broker::Limits,
    pub resolv_conf: PathBuf,
    pub resolv_conf_bytes: usize,
    pub protocols: PathBuf,
    pub services: PathBuf,
    pub shutdown_grace: Duration,
}
impl Settings {
    pub fn read(c: &Configuration) -> Result<Self, Cause> {
        let intercept_dns = c
            .get(b"gns", b"INTERCEPT_DNS")
            .map(|_| c.get_yesno(b"gns", b"INTERCEPT_DNS"))
            .transpose()?
            .unwrap_or(false);
        let mut core = gnunet_gns_service_host::Limits::default();
        // Explicit Rust capability policy, not an official wire/config key.
        core.dns = c
            .get(b"gns-rust", b"DNS")
            .map(|_| c.get_yesno(b"gns-rust", b"DNS"))
            .transpose()?
            .unwrap_or(core.dns);
        core.cache = !c
            .get(b"namecache", b"DISABLE")
            .map(|_| c.get_yesno(b"namecache", b"DISABLE"))
            .transpose()?
            .unwrap_or(false);
        core.queries = number(c, b"MAX_QUERIES", core.queries)?;
        core.steps = u32::try_from(number(c, b"MAX_STEPS", core.steps as usize)?)?;
        core.records = number(c, b"MAX_RECORDS", core.records)?;
        core.record_bytes = size(c, b"MAX_RECORD_BYTES", core.record_bytes)?;
        core.frames = number(c, b"MAX_RECURSION_FRAMES", core.frames)?;
        core.servers = number(c, b"MAX_SERVERS", core.servers)?;
        if !(1..=64).contains(&core.queries)
            || !(1..=5957).contains(&core.records)
            || !(16..=64512).contains(&core.record_bytes)
            || core.steps == 0
            || !(1..=128).contains(&core.frames)
            || !(1..=256).contains(&core.servers)
        {
            return Err("GNS Rust query/record/recursion resource policy is out of bounds".into());
        }
        let fd = server::Limits::default();
        let frontend = server::Limits {
            peers: number(c, b"MAX_CLIENTS", fd.peers)?,
            calls: number(
                c,
                b"MAX_CLIENT_CALLS",
                core.queries.checked_mul(2).ok_or("GNS calls overflow")?,
            )?,
            per_peer: number(c, b"MAX_CALLS_PER_CLIENT", fd.per_peer)?,
            output: gnunet_service_runtime::framing::Budget {
                frames: number(c, b"MAX_CLIENT_OUTPUT_FRAMES", fd.output.frames)?,
                bytes: size(c, b"MAX_CLIENT_OUTPUT_BYTES", fd.output.bytes)?,
            },
            io_chunk_bytes: size(c, b"IO_SLICE_BYTES", fd.io_chunk_bytes)?,
            query_timeout: gnunet_types::Duration(micros(c, b"QUERY_TIMEOUT", fd.query_timeout.0)?),
            input_timeout: Duration::from_micros(micros(c, b"INPUT_TIMEOUT", 15_000_000)?),
        };
        if !(1..=1024).contains(&frontend.peers)
            || !(1..=4096).contains(&frontend.calls)
            || !(1..=64).contains(&frontend.per_peer)
            || frontend.per_peer > frontend.calls
            || !(1..=256).contains(&frontend.output.frames)
            || !(65535..=16 * 1024 * 1024).contains(&frontend.output.bytes)
            || !(1..=65535).contains(&frontend.io_chunk_bytes)
        {
            return Err("GNS IPC resource policy is out of bounds".into());
        }
        let interception = if intercept_dns {
            let d = gnunet_gns_service_host::interceptor::Limits::default();
            let requests = number(c, b"MAX_INTERCEPT_REQUESTS", core.queries)?;
            let packet_bytes = size(c, b"INTERCEPT_PACKET_BYTES", d.packet_bytes)?;
            let arena_bytes = size(c, b"INTERCEPT_ARENA_BYTES", d.arena_bytes)?;
            let work = number(c, b"INTERCEPT_WORK", d.work)?;
            let source_bytes = size(c, b"INTERCEPT_SOURCE_BYTES", d.source_bytes)?;
            if !(1..=4096).contains(&requests)
                || !(512..=65519).contains(&packet_bytes)
                || !(512..=16 * 1024 * 1024).contains(&arena_bytes)
                || !(1..=64 * 1024 * 1024).contains(&work)
                || !(16..=64 * 1024 * 1024).contains(&source_bytes)
            {
                return Err("GNS DNS interception resource policy is out of bounds".into());
            }
            Some(gnunet_gns_service_host::interceptor::Limits {
                requests,
                packet_bytes,
                records: core.records,
                record_bytes: core.record_bytes,
                arena_bytes,
                work,
                source_bytes,
                timeout: Duration::from_micros(frontend.query_timeout.0),
                input_timeout: frontend.input_timeout,
                ..d
            })
        } else {
            None
        };
        let defaults = refresh::Limits::default();
        let jobs = if core.cache {
            number(c, b"MAX_REFRESHES", defaults.jobs)?
        } else {
            0
        };
        if jobs > 64 {
            return Err("GNS background refresh capacity exceeds64".into());
        }
        let refresh = if jobs == 0 {
            refresh::Limits {
                jobs: 0,
                bytes: 0,
                ..defaults
            }
        } else {
            let bytes = size(c, b"REFRESH_BYTES", defaults.bytes)?;
            if bytes == 0 || bytes > 8 * 1024 * 1024 {
                return Err("GNS background refresh byte budget is out of bounds".into());
            }
            refresh::Limits {
                jobs,
                bytes,
                timeout: gnunet_types::Duration(micros(c, b"REFRESH_TIMEOUT", defaults.timeout.0)?),
            }
        };
        let capacity = core
            .queries
            .checked_add(refresh.jobs)
            .ok_or("GNS native operation capacity overflow")?;
        let mut native = native::Limits {
            operations: capacity,
            ..Default::default()
        };
        native.namecache.operations = native.namecache.operations.max(capacity);
        native.dht.protocol.gets = native.dht.protocol.gets.max(capacity);
        let dns_defaults = dns::DnsLimits::default();
        let dns = dns::DnsLimits {
            operations: core.queries,
            records: core.records,
            exchanges: u32::try_from(number(
                c,
                b"DNS_EXCHANGES",
                dns_defaults.exchanges as usize,
            )?)?,
            timeout_micros: micros(c, b"DNS_EXCHANGE_TIMEOUT", dns_defaults.timeout_micros)?,
            ..dns_defaults
        };
        let rd = gnunet_resolver_broker::Limits::default();
        let resolver = gnunet_resolver_broker::Limits {
            max_frame_bytes: size(c, b"RESOLVER_FRAME_BYTES", rd.max_frame_bytes)?,
            io_chunk_bytes: size(c, b"RESOLVER_IO_SLICE_BYTES", rd.io_chunk_bytes)?,
            max_queued_frames: number(
                c,
                b"RESOLVER_OUTPUT_FRAMES",
                core.queries.max(rd.max_queued_frames) + 1,
            )?,
        };
        let path = |key: &[u8], default: &str| -> Result<PathBuf, Cause> {
            Ok(if c.get(b"gns-rust", key).is_some() {
                c.get_filename(b"gns-rust", key, &gnunet_config::ProcessEnvironment)?
            } else {
                PathBuf::from(default)
            })
        };
        let yes = |key: &[u8], default: bool| -> Result<bool, Cause> {
            Ok(c.get(b"gns", key)
                .map(|_| c.get_yesno(b"gns", key))
                .transpose()?
                .unwrap_or(default))
        };
        Ok(Self {
            access: UnixAccess {
                match_uid: yes(b"UNIX_MATCH_UID", false)?,
                match_gid: yes(b"UNIX_MATCH_GID", true)?,
            },
            options: service_options(c, b"gns", ShutdownMode::Immediate)?,
            core,
            frontend,
            interception,
            native,
            refresh,
            dns,
            resolver,
            system: system::Limits {
                operations: core.queries,
                records: core.records,
                bytes: core.record_bytes,
                lifetime: gnunet_types::Duration(micros(
                    c,
                    b"SYSTEM_ADDRESS_LIFETIME",
                    60_000_000,
                )?),
            },
            registry: registry::Limits::default(),
            resolv_conf: path(b"RESOLV_CONF", "/etc/resolv.conf")?,
            resolv_conf_bytes: size(c, b"RESOLV_CONF_BYTES", 65536)?,
            protocols: path(b"PROTOCOLS_FILE", "/etc/protocols")?,
            services: path(b"SERVICES_FILE", "/etc/services")?,
            shutdown_grace: Duration::from_micros(micros(c, b"SHUTDOWN_GRACE", 10_000_000)?),
        })
    }
}
