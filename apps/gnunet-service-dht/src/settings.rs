//! Actual official configuration plus explicit finite native resource limits.
use crate::Cause;
use gnunet_block::{
    bloom::NativeEndian,
    plugins::{Plugin, RevocationConfig},
};
use gnunet_config::Configuration;
use gnunet_dht_service_host::{Blocks, Limits, Underlays, ip};
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use std::time::Duration;
pub(super) struct Settings {
    pub native: Limits,
    pub access: UnixAccess,
    pub options: ServiceOptions,
    pub resolver: gnunet_resolver_broker::Limits,
    pub shutdown_grace: Duration,
    revocation: Option<RevocationConfig>,
    group_profile: NativeEndian,
}
fn number(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Cause> {
    Ok(c.get(b"dht-rust", key)
        .map(|_| c.get_number(b"dht-rust", key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn size(c: &Configuration, section: &[u8], key: &[u8], default: usize) -> Result<usize, Cause> {
    Ok(c.get(section, key)
        .map(|_| c.get_size(section, key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn duration(c: &Configuration, key: &[u8], default: Duration) -> Result<Duration, Cause> {
    let micros = c
        .get(b"dht-rust", key)
        .map(|_| c.get_time(b"dht-rust", key))
        .transpose()?
        .unwrap_or(u64::try_from(default.as_micros())?);
    let d = Duration::from_micros(micros);
    if micros == 0 || micros == u64::MAX || std::time::Instant::now().checked_add(d).is_none() {
        return Err("DHT native budgets must be finite, nonzero and representable".into());
    }
    Ok(d)
}
fn underlays(c: &Configuration) -> Result<Underlays, Cause> {
    let enabled = |section: &[u8], default: bool| {
        c.get(section, b"ENABLED")
            .map(|_| c.get_yesno(section, b"ENABLED"))
            .transpose()
            .map(|v| v.unwrap_or(default))
    };
    let gnunet = enabled(b"dhtu-gnunet", true)?;
    let ip_enabled = enabled(b"dhtu-ip", false)?;
    if !gnunet && !ip_enabled {
        return Err("no DHT underlay is enabled".into());
    }
    let ip = if ip_enabled {
        let defaults = ip::Config::default();
        let network_size = c
            .get(b"dhtu-ip", b"NSE")
            .map(|_| c.get_number(b"dhtu-ip", b"NSE"))
            .transpose()?
            .unwrap_or(4);
        let port = c
            .get(b"dhtu-ip", b"UDP_PORT")
            .map(|_| c.get_number(b"dhtu-ip", b"UDP_PORT"))
            .transpose()?
            .unwrap_or(6666);
        let port = u16::try_from(port).map_err(|_| "[dhtu-ip] UDP_PORT must fit16 bits")?;
        let bind = match c.get(b"dht-rust", b"IP_BIND") {
            Some(v) => Some(std::str::from_utf8(v)?.parse::<std::net::IpAddr>()?),
            None => None,
        };
        Some(ip::Config {
            bind,
            port,
            network_size,
            ..defaults
        })
    } else {
        if c.get(b"dht-rust", b"IP_BIND").is_some() {
            return Err("[dht-rust] IP_BIND requires [dhtu-ip] ENABLED=YES".into());
        }
        None
    };
    Ok(Underlays { gnunet, ip })
}
impl Settings {
    pub fn read(c: &Configuration) -> Result<Self, Cause> {
        let mut native = Limits {
            underlays: underlays(c)?,
            pils_profile: gnunet_pils::Profile::configured(c.get(b"PILS", b"PROFILE"), None)?,
            ..Limits::default()
        };
        native.local.clients = number(c, b"MAX_CLIENTS", native.local.clients)?;
        native.local.queries = number(c, b"MAX_QUERIES", native.local.queries)?;
        native.local.monitors = number(c, b"MAX_MONITORS", native.local.monitors)?;
        native.local.cache_records = number(c, b"CACHE_RECORDS", native.local.cache_records)?;
        native.local.cache_bytes = size(c, b"dhtcache", b"QUOTA", native.local.cache_bytes)?;
        native.network.cache_path_bytes = size(
            c,
            b"dht-rust",
            b"CACHE_PATH_BYTES",
            native.network.cache_path_bytes,
        )?;
        native.network.peers = number(c, b"MAX_PEERS", native.network.peers)?;
        native.network.routes = number(c, b"MAX_ROUTES", native.network.routes)?;
        native.network.output_frames =
            number(c, b"NETWORK_OUTPUT_FRAMES", native.network.output_frames)?;
        native.network.output_bytes = size(
            c,
            b"dht-rust",
            b"NETWORK_OUTPUT_BYTES",
            native.network.output_bytes,
        )?;
        native.network.bucket_size = c
            .get(b"dht", b"BUCKET_SIZE")
            .map(|_| c.get_number(b"dht", b"BUCKET_SIZE"))
            .transpose()?
            .map(usize::try_from)
            .transpose()?
            .unwrap_or(8);
        native.network.cache_results = c
            .get(b"dht", b"CACHE_RESULTS")
            .map(|_| c.get_yesno(b"dht", b"CACHE_RESULTS"))
            .transpose()?
            .unwrap_or(false);
        native.try_connect = !c
            .get(b"dht", b"DISABLE_TRY_CONNECT")
            .map(|_| c.get_yesno(b"dht", b"DISABLE_TRY_CONNECT"))
            .transpose()?
            .unwrap_or(false);
        native.native_sends = number(c, b"MAX_NATIVE_SENDS", native.native_sends)?;
        native.initial = duration(c, b"INITIAL_LIFETIME", native.initial)?;
        native.source_lifetime = duration(c, b"SOURCE_LIFETIME", native.source_lifetime)?;
        native.input_lifetime = duration(c, b"INPUT_LIFETIME", native.input_lifetime)?;
        native.output_lifetime = duration(c, b"OUTPUT_LIFETIME", native.output_lifetime)?;
        native.retirement = duration(c, b"RETIREMENT_GRACE", native.retirement)?;
        native.discovery_lifetime = duration(c, b"DISCOVERY_LIFETIME", native.discovery_lifetime)?;
        native.addresses = number(c, b"HELLO_CANDIDATES", native.addresses)?;
        native.address_bytes = size(
            c,
            b"dht-rust",
            b"HELLO_CANDIDATE_BYTES",
            native.address_bytes,
        )?;
        let group_profile = match c.get(b"dht-rust", b"BLOCK_NATIVE_BYTE_ORDER") {
            None => NativeEndian::native(),
            Some(b"little" | b"LITTLE") => NativeEndian::Little,
            Some(b"big" | b"BIG") => NativeEndian::Big,
            Some(_) => return Err("DHT BLOCK_NATIVE_BYTE_ORDER must be little or big".into()),
        };
        native.network.group_profile = group_profile;
        let yes = |key: &[u8]| {
            c.get(b"dht", key)
                .map(|_| c.get_yesno(b"dht", key))
                .transpose()
                .map(|v| v.unwrap_or(false))
        };
        let revocation = match (
            c.get(b"revocation", b"WORKBITS"),
            c.get(b"revocation", b"EPOCH_DURATION"),
        ) {
            (None, None) => None,
            (Some(_), Some(_)) => Some(RevocationConfig::from_native_values(
                c.get_number(b"revocation", b"WORKBITS")?,
                c.get_time(b"revocation", b"EPOCH_DURATION")?,
            )),
            _ => {
                return Err(
                    "revocation BLOCK plugin needs both WORKBITS and EPOCH_DURATION".into(),
                );
            }
        };
        let resolver = gnunet_resolver_broker::Limits::default();
        Ok(Self {
            native,
            access: UnixAccess {
                match_uid: yes(b"UNIX_MATCH_UID")?,
                match_gid: yes(b"UNIX_MATCH_GID")?,
            },
            options: service_options(c, b"dht", ShutdownMode::Immediate)?,
            resolver,
            shutdown_grace: duration(c, b"SHUTDOWN_GRACE", Duration::from_secs(30))?,
            revocation,
            group_profile,
        })
    }
    pub fn blocks(&self) -> Result<Blocks, Cause> {
        let installed = [
            Plugin::Test,
            Plugin::Dht,
            Plugin::Fs,
            Plugin::Gns,
            Plugin::Dns,
            Plugin::Regex,
            Plugin::SetTest,
            Plugin::Consensus,
            Plugin::SetIntersection,
            Plugin::SetUnion,
        ];
        let mut plugins = Vec::new();
        plugins.try_reserve_exact(installed.len() + usize::from(self.revocation.is_some()))?;
        plugins.extend_from_slice(&installed);
        if let Some(config) = self.revocation {
            plugins.push(Plugin::Revocation(config));
        }
        Ok(Blocks {
            plugins,
            group_profile: self.group_profile,
            hello_profile: self.native.pils_profile.hello(),
        })
    }
}
