//! Actual official NAT and per-registration configuration; Rust-only resource
//! limits do not create private protocol or competing address authorization.
use crate::{Error, helpers};
use gnunet_config::Configuration;
use gnunet_nat::{address::SocketAddress, state::Options};
use gnunet_types::Error as Fault;
use std::{net::IpAddr, time::Duration};
/// Configuration failure retains its actual source class.
#[derive(Debug)]
pub enum ConfigError {
    /// Actual configuration parser/getter/path failure.
    Configuration(gnunet_config::Error),
    /// Bounded native/protocol failure.
    Host(Error),
}
impl From<gnunet_config::Error> for ConfigError {
    fn from(e: gnunet_config::Error) -> Self {
        Self::Configuration(e)
    }
}
impl From<Error> for ConfigError {
    fn from(e: Error) -> Self {
        Self::Host(e)
    }
}
impl From<Fault> for ConfigError {
    fn from(e: Fault) -> Self {
        Self::Host(e.into())
    }
}
impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configuration(e) => e.fmt(f),
            Self::Host(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Configuration(e) => Some(e),
            Self::Host(e) => Some(e),
        }
    }
}
fn yes(c: &Configuration, section: &[u8], key: &[u8], default: bool) -> Result<bool, ConfigError> {
    Ok(if c.have_value(section, key) {
        c.get_yesno(section, key)?
    } else {
        default
    })
}
fn time(
    c: &Configuration,
    section: &[u8],
    key: &[u8],
    default: u64,
) -> Result<Duration, ConfigError> {
    let n = if c.have_value(section, key) {
        c.get_time(section, key)?
    } else {
        default
    };
    let value = Duration::from_micros(n);
    if n == 0 || n == u64::MAX || tokio::time::Instant::now().checked_add(value).is_none() {
        return Err(Fault::InvalidInput.into());
    }
    Ok(value)
}
fn number(c: &Configuration, key: &[u8], default: usize) -> Result<usize, ConfigError> {
    let n = if c.have_value(b"nat-rust", key) {
        usize::try_from(c.get_number(b"nat-rust", key)?).map_err(|_| Fault::Overflow)?
    } else {
        default
    };
    if n == 0 || n > 65536 {
        return Err(Fault::Capacity.into());
    }
    Ok(n)
}
/// Original effective registration HOLE_EXTERNAL selector.
#[derive(Clone, Debug)]
pub enum External {
    /// No configured external hole.
    None,
    /// Actual user-configured literal endpoint.
    Literal(SocketAddress),
    /// Original host+port requiring real Resolver callbacks.
    Dns {
        /// Exact bounded host from configuration.
        host: Vec<u8>,
        /// User-configured external port.
        port: u16,
    },
    /// Actual global external-IP monitor, with configured port.
    Auto(u16),
}
/// Source-specific configuration resolved from the actual REGISTER section.
#[derive(Clone, Debug)]
pub struct Registration {
    /// Pure core options from actual NAT config.
    pub options: Options,
    /// Original source's external address mode.
    pub external: External,
}
/// Effective service settings. Each timer is finite; its original native target
/// is assigned once when scheduled/admitted, never reset by a poll or rollback.
#[derive(Clone, Debug)]
pub struct Settings {
    /// Actual ENABLE_UPNP setting.
    pub enable_upnp: bool,
    /// Actual ENABLE_IPSCAN setting.
    pub enable_ipscan: bool,
    /// Actual DISABLEV6 setting.
    pub disable_v6: bool,
    /// Actual RETURN_LOCAL_ADDRESSES setting.
    pub return_local_addresses: bool,
    /// Actual USE_STUN setting.
    pub use_stun: bool,
    /// Configured complete interface-scan interval.
    pub interface_interval: Duration,
    /// Configured periodic dynamic-DNS interval.
    pub dyndns_interval: Duration,
    /// Configured external-IP monitor interval.
    pub external_interval: Duration,
    /// Configured STUN freshness, independent from query deadline.
    pub stun_stale: Duration,
    /// Configured STUN refresh interval.
    pub stun_interval: Duration,
    /// Bounded original public STUN server entries.
    pub stun_servers: Vec<(Vec<u8>, u16)>,
    /// Maximum received datagrams per original dedicated STUN server probe.
    pub stun_datagrams: usize,
    /// Original per-provider/request network deadline.
    pub job_timeout: Duration,
    /// Independent explicit cleanup deadline.
    pub cleanup_timeout: Duration,
    /// Actual mapping-check interval (official5minutes).
    pub mapping_interval: Duration,
    /// Maximum concurrently owned jobs, including cleanup.
    pub jobs: usize,
    /// Maximum actual/potential mapping leases.
    pub mappings: usize,
    /// Actual native interface limits.
    pub interfaces: gnunet_native::interfaces::Limits,
    /// Actual child bounds.
    pub helper_limits: helpers::Limits,
    /// Actual Rust helper paths.
    pub helper_paths: helpers::Paths,
}
impl Settings {
    /// Read actual official keys and explicit Rust metadata budgets. No socket,
    /// helper launch, permission operation, key or system configuration is touched.
    pub fn read(c: &Configuration) -> Result<Self, ConfigError> {
        let mut servers = Vec::new();
        let raw = c
            .get(b"nat", b"STUN_SERVERS")
            .unwrap_or(b"stun.gnunet.org stun.services.mozilla.com:3478 stun.ekiga.net:3478");
        if raw.len() > 8192 {
            return Err(Fault::TooLarge.into());
        }
        let raw = core::str::from_utf8(raw).map_err(|_| Fault::Malformed)?;
        for token in raw.split_ascii_whitespace() {
            if servers.len() >= 32 {
                return Err(Fault::Capacity.into());
            }
            let (host, port) = crate::stun::parse_server(token)?;
            let mut h = Vec::new();
            h.try_reserve_exact(host.len())
                .map_err(|_| Fault::Capacity)?;
            h.extend_from_slice(host.as_bytes());
            servers.try_reserve(1).map_err(|_| Fault::Capacity)?;
            servers.push((h, port));
        }
        let helper_paths = helpers::Paths {
            server: c.suid_binary_path(b"gnunet-helper-nat-server")?,
            client: c.suid_binary_path(b"gnunet-helper-nat-client")?,
        };
        let jobs = number(c, b"MAX_JOBS", 256)?;
        let mappings = number(c, b"MAX_MAPPINGS", 256)?;
        Ok(Self {
            enable_upnp: yes(c, b"nat", b"ENABLE_UPNP", true)?,
            enable_ipscan: yes(c, b"nat", b"ENABLE_IPSCAN", true)?,
            disable_v6: yes(c, b"nat", b"DISABLEV6", false)?,
            return_local_addresses: yes(c, b"nat", b"RETURN_LOCAL_ADDRESSES", false)?,
            use_stun: yes(c, b"nat", b"USE_STUN", true)?,
            interface_interval: time(c, b"nat", b"IFC_SCAN_FREQUENCY", 900_000_000)?,
            dyndns_interval: time(c, b"nat", b"DYNDNS_FREQUENCY", 420_000_000)?,
            external_interval: time(c, b"nat", b"HOSTNAME_DNS_FREQUENCY", 1_200_000_000)?,
            stun_stale: time(c, b"nat", b"STUN_STALE", 3_600_000_000)?,
            stun_interval: time(c, b"nat", b"STUN_FREQUENCY", 300_000_000)?,
            stun_servers: servers,
            stun_datagrams: number(c, b"MAX_STUN_DATAGRAMS", 1024)?,
            job_timeout: time(c, b"nat-rust", b"JOB_TIMEOUT", 30_000_000)?,
            cleanup_timeout: time(c, b"nat-rust", b"CLEANUP_TIMEOUT", 1_000_000)?,
            mapping_interval: Duration::from_secs(300),
            jobs,
            mappings,
            interfaces: gnunet_native::interfaces::Limits {
                nodes: number(c, b"MAX_INTERFACE_NODES", 4096)?,
                addresses: number(c, b"MAX_INTERFACE_ADDRESSES", 1024)?,
                name_bytes: 256,
            },
            helper_limits: helpers::Limits {
                children: number(c, b"MAX_HELPERS", 256)?,
                ..helpers::Limits::default()
            },
            helper_paths,
        })
    }
    /// Parse only the actual caller's REGISTER section and HOLE_EXTERNAL.
    pub fn registration(
        &self,
        c: &Configuration,
        section: &[u8],
    ) -> Result<Registration, ConfigError> {
        let mut options = Options {
            return_local_addresses: self.return_local_addresses,
            disable_v6: self.disable_v6,
            auto_external_port: None,
        };
        let external = if let Some(raw) = c.get(section, b"HOLE_EXTERNAL") {
            let raw = core::str::from_utf8(raw).map_err(|_| Fault::Malformed)?;
            if raw.len() > 2048 || raw.as_bytes().contains(&0) {
                return Err(Fault::TooLarge.into());
            }
            let (host, port) = if let Some(rest) = raw.strip_prefix('[') {
                let (host, port) = rest.rsplit_once("]:").ok_or(Fault::Malformed)?;
                (host, port)
            } else {
                raw.rsplit_once(':').ok_or(Fault::Malformed)?
            };
            let port: u16 = port.parse().map_err(|_| Fault::Malformed)?;
            if host.eq_ignore_ascii_case("AUTO") {
                options.auto_external_port = Some(port);
                External::Auto(port)
            } else if let Ok(ip) = host.parse::<IpAddr>() {
                let address = match ip {
                    IpAddr::V4(ip) => SocketAddress::V4 {
                        ip: ip.octets(),
                        port,
                    },
                    IpAddr::V6(ip) => SocketAddress::V6 {
                        ip: ip.octets(),
                        port,
                        scope: 0,
                        flow: 0,
                    },
                };
                External::Literal(address)
            } else {
                if host.is_empty()
                    || host.len() > 253
                    || host
                        .chars()
                        .any(|c| c.is_control() || c.is_whitespace() || c == '[' || c == ']')
                {
                    return Err(Fault::InvalidInput.into());
                }
                let mut h = Vec::new();
                h.try_reserve_exact(host.len())
                    .map_err(|_| Fault::Capacity)?;
                h.extend_from_slice(host.as_bytes());
                External::Dns { host: h, port }
            }
        } else {
            External::None
        };
        Ok(Registration { options, external })
    }
}
