//! Official PROGRAM options plus explicit bounded Rust resource policy.
use crate::Cause;
use gnunet_config::Configuration;
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Target},
};
use gnunet_wire::official::RelativeTime;
use gnunet_zoneimport_host::{self as host, core};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
pub(super) struct Selection {
    size: Target<u32>,
    minimum: Target<u64>,
}
impl Selection {
    pub(super) fn new() -> Self {
        Self {
            size: Target::new(1024),
            minimum: Target::new(0),
        }
    }
    pub(super) fn descriptors(&self) -> Options<'static> {
        let mut options = Options::new();
        options.add(helpers::uint(
            b's',
            b"size",
            b"MAPSIZE",
            b"initial name-table capacity hint (hard limits remain independent)",
            self.size.clone(),
        ));
        options.add(helpers::relative_time(
            b'm',
            b"minimum-expiration",
            b"RELATIVETIME",
            b"minimum expiration time for imported DNS records",
            self.minimum.clone(),
        ));
        options
    }
    pub(super) fn finish(
        self,
        config: &Configuration,
        arguments: &[Vec<u8>],
    ) -> Result<Settings, Cause> {
        if arguments.is_empty() || arguments.len() > 16 {
            return Err("provide from1through16 numeric DNS resolver IP addresses".into());
        }
        let mut servers = Vec::new();
        servers.try_reserve_exact(arguments.len())?;
        for argument in arguments {
            let text = std::str::from_utf8(argument)?;
            let ip: IpAddr = text.parse()?;
            if ip.is_unspecified() || ip.is_multicast() {
                return Err("DNS resolver must be one concrete unicast IP address".into());
            }
            let address = SocketAddr::new(ip, 53);
            if !servers.contains(&address) {
                servers.push(address);
            }
        }
        let initial_names = usize::try_from(self.size.get()?)
            .map_err(|_| "initial table hint does not fit usize")?;
        if initial_names == 0 || initial_names > 1_000_000 {
            return Err("-s must be from1through1000000".into());
        }
        let core = core::Limits {
            names: number(config, b"NAMES", 65536, 1, 1_000_000)?,
            zones: number(config, b"ZONES", 4096, 1, 65536)?,
            jobs: number(config, b"JOBS", 100, 1, 4096)?,
            name_bytes: number(
                config,
                b"NAME_BYTES",
                16 * 1024 * 1024,
                1,
                256 * 1024 * 1024,
            )?,
            records_per_set: number(config, b"RECORDS_PER_SET", 4096, 1, 4096)?,
        };
        let minimum = self.minimum.get()?;
        let policy = core::Policy {
            minimum_expiration: RelativeTime::from_micros(minimum),
            operation: RelativeTime::from_micros(
                u64::try_from(number(config, b"OPERATION_SECONDS", 30, 1, 3600)?)? * 1_000_000,
            ),
            ..core::Policy::default()
        };
        let mut host = host::Limits {
            dns_requests: number(config, b"DNS_REQUESTS", 64, 1, 64)?,
            tcp_requests: number(config, b"TCP_REQUESTS", 4, 1, 16)?,
            response_bytes: number(config, b"RESPONSE_BYTES", 65535, 12, 65535)?,
            io_bytes: number(config, b"IO_BYTES", 8192, 1, 65535)?,
            dns_arena_bytes: number(
                config,
                b"DNS_ARENA_BYTES",
                4 * 1024 * 1024,
                4096,
                16 * 1024 * 1024,
            )?,
            dns_records: number(config, b"DNS_RECORDS", 8192, 1, 8192)?,
            ..host::Limits::default()
        };
        if host.tcp_requests > host.dns_requests {
            return Err("TCP_REQUESTS must not exceed DNS_REQUESTS".into());
        }
        host.identity.egos = core.zones;
        host.namestore.operations = core.jobs.min(32);
        host.namestore.records = core.records_per_set;
        Ok(Settings {
            servers,
            core,
            policy,
            host,
            initial_names,
            input_bytes: number(
                config,
                b"INPUT_BYTES",
                16 * 1024 * 1024,
                1,
                256 * 1024 * 1024,
            )?,
            cleanup: Duration::from_secs(u64::try_from(number(
                config,
                b"CLEANUP_SECONDS",
                5,
                1,
                60,
            )?)?),
        })
    }
}
pub(super) struct Settings {
    pub servers: Vec<SocketAddr>,
    pub core: core::Limits,
    pub policy: core::Policy,
    pub host: host::Limits,
    pub initial_names: usize,
    pub input_bytes: usize,
    pub cleanup: Duration,
}
fn number(
    config: &Configuration,
    key: &[u8],
    default: usize,
    minimum: usize,
    maximum: usize,
) -> Result<usize, Cause> {
    let Some(value) = config.get(b"zoneimport-rust", key) else {
        return Ok(default);
    };
    let text = std::str::from_utf8(value)?;
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("invalid [zoneimport-rust] {}", String::from_utf8_lossy(key)).into());
    }
    let value: usize = text.parse()?;
    if !(minimum..=maximum).contains(&value) {
        return Err(format!(
            "out of range [zoneimport-rust] {}",
            String::from_utf8_lossy(key)
        )
        .into());
    }
    Ok(value)
}
