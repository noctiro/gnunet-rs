use crate::Failure;
use gnunet_config::{Configuration, ProcessEnvironment};
use gnunet_hostlist::{Modes, Uri};
use gnunet_hostlist_host::{Limits, Proxy, ProxyKind};
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
pub(super) struct Settings {
    pub modes: Modes,
    pub state: gnunet_hostlist::Limits,
    pub limits: Limits,
    pub startup: Duration,
    pub resolver: gnunet_resolver_broker::Limits,
    pub servers: Vec<Uri>,
    pub proxy: Option<Arc<Proxy>>,
    pub binds: Vec<SocketAddr>,
    pub external: Option<Vec<u8>>,
    pub port: u16,
    pub store: Option<PathBuf>,
    pub store_bytes: usize,
}
const SECTION: &[u8] = b"hostlist-rust";
fn number(config: &Configuration, key: &[u8], default: usize) -> Result<usize, Failure> {
    Ok(config
        .get(SECTION, key)
        .map(|_| config.get_number(SECTION, key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn duration(config: &Configuration, key: &[u8], default: Duration) -> Result<Duration, Failure> {
    let micros = config
        .get(SECTION, key)
        .map(|_| config.get_time(SECTION, key))
        .transpose()?
        .unwrap_or(u64::try_from(default.as_micros())?);
    let duration = Duration::from_micros(micros);
    if micros == 0
        || micros == u64::MAX
        || std::time::Instant::now().checked_add(duration).is_none()
    {
        return Err("HOSTLIST time limits must be finite nonzero".into());
    }
    Ok(duration)
}
impl Settings {
    pub fn read(config: &Configuration, modes: Modes) -> Result<Self, Failure> {
        let mut limits = Limits::default();
        let mut state = gnunet_hostlist::Limits::default();
        state.urls = number(config, b"MAX_URLS", state.urls)?;
        state.learned = number(config, b"MAX_LEARNED", state.learned)?;
        state.hellos = number(config, b"MAX_HELLOS", state.hellos)?;
        state.hello_bytes = number(config, b"HELLO_BYTES", state.hello_bytes)?;
        limits.peers = number(config, b"MAX_PEERS", limits.peers)?;
        limits.connections = number(config, b"HTTP_CLIENTS", limits.connections)?;
        limits.per_ip = number(config, b"HTTP_CLIENTS_PER_IP", limits.per_ip)?;
        limits.io_slice = number(config, b"IO_SLICE_BYTES", limits.io_slice)?;
        limits.operation = duration(config, b"OPERATION_LIFETIME", limits.operation)?;
        state.operation_micros = u64::try_from(limits.operation.as_micros())?;
        limits.http_lifetime = duration(config, b"HTTP_LIFETIME", limits.http_lifetime)?;
        limits.grace = duration(config, b"RETIREMENT_GRACE", limits.grace)?;
        limits.lifetime = duration(config, b"DAEMON_LIFETIME", limits.lifetime)?;
        limits.tick = duration(config, b"TICK_INTERVAL", limits.tick)?;
        limits.rebuild = duration(config, b"REBUILD_INTERVAL", limits.rebuild)?;
        limits.save_interval = duration(config, b"SAVE_INTERVAL", limits.save_interval)?;
        limits.hello.maximum_input_bytes = number(config, b"HELLO_FRAME_BYTES", 65535)?;
        limits.hello.maximum_address_bytes = number(config, b"ADDRESS_BYTES", 65535)?;
        limits.hello.maximum_addresses = number(config, b"MAX_ADDRESSES", 256)?;
        limits.http.body_bytes = number(config, b"BODY_BYTES", limits.http.body_bytes)?;
        state.body_bytes = limits.http.body_bytes;
        limits.http.wire_bytes = number(config, b"HTTP_WIRE_BYTES", limits.http.wire_bytes)?;
        limits.http.header_bytes = number(config, b"HTTP_HEADER_BYTES", limits.http.header_bytes)?;
        limits.http.headers = number(config, b"HTTP_HEADERS", limits.http.headers)?;
        limits.http.frames = number(config, b"HTTP_FRAMES", limits.http.frames)?;
        limits.http.probes = number(config, b"HTTP_PROBES", limits.http.probes)?;
        limits.publication.binary_bytes = limits.http.body_bytes;
        limits.publication.json_bytes =
            number(config, b"JSON_BYTES", limits.publication.json_bytes)?;
        limits.publication.retained_bytes = number(
            config,
            b"RETAINED_PUBLICATION_BYTES",
            limits.publication.retained_bytes,
        )?;
        limits.publication.entries = state.hellos;
        limits.profile = match config
            .get(SECTION, b"HELLO_PROFILE")
            .unwrap_or(b"reference029")
        {
            b"reference029" => gnunet_hello::SignatureProfile::Gnunet029,
            b"deterministic" => gnunet_hello::SignatureProfile::DeterministicPidDerivation,
            _ => return Err("HELLO_PROFILE must be reference029/deterministic".into()),
        };
        limits.core_order = match config
            .get(SECTION, b"CORE_CLASS_ORDER")
            .unwrap_or(b"native")
        {
            b"native" => limits.core_order,
            b"little" => gnunet_core_client_host::ClassOrder::Little,
            b"big" => gnunet_core_client_host::ClassOrder::Big,
            _ => return Err("CORE_CLASS_ORDER must be native/little/big".into()),
        };
        let mut servers = Vec::new();
        servers.try_reserve_exact(state.urls)?;
        if modes.bootstrap {
            let input = config
                .get(b"hostlist", b"SERVERS")
                .ok_or("HOSTLIST SERVERS missing")?;
            for uri in input
                .split(|b| b.is_ascii_whitespace())
                .filter(|s| !s.is_empty())
            {
                gnunet_hostlist_host::http::validate_uri(uri)?;
                if servers.len() >= state.urls {
                    return Err("HOSTLIST configured URL capacity".into());
                }
                servers.push(Uri::copy_from(uri)?);
            }
            if servers.is_empty() {
                return Err("HOSTLIST SERVERS empty".into());
            }
        }
        let proxy = if let Some(endpoint) = config.get(b"hostlist", b"PROXY") {
            let kind = config.get(b"hostlist", b"PROXY_TYPE").unwrap_or(b"HTTP");
            let kind = if kind.eq_ignore_ascii_case(b"HTTP") {
                ProxyKind::Http
            } else if kind.eq_ignore_ascii_case(b"HTTP_1_0") {
                ProxyKind::Http10
            } else if kind.eq_ignore_ascii_case(b"SOCKS4") {
                ProxyKind::Socks4
            } else if kind.eq_ignore_ascii_case(b"SOCKS4A") {
                ProxyKind::Socks4a
            } else if kind.eq_ignore_ascii_case(b"SOCKS5") {
                ProxyKind::Socks5
            } else if kind.eq_ignore_ascii_case(b"SOCKS5_HOSTNAME") {
                ProxyKind::Socks5Hostname
            } else {
                return Err("invalid HOSTLIST PROXY_TYPE".into());
            };
            Some(Arc::new(Proxy::new(
                kind,
                endpoint,
                config.get(b"hostlist", b"PROXY_USERNAME"),
                config.get(b"hostlist", b"PROXY_PASSWORD"),
            )?))
        } else {
            None
        };
        let mut binds = Vec::new();
        let mut port = 0u16;
        let mut external = None;
        if modes.provide {
            port = u16::try_from(config.get_number(b"hostlist", b"HTTPPORT")?)?;
            if port == 0 {
                return Err("HOSTLIST HTTPPORT must be 1..65535".into());
            }
            let ipv4 = config
                .get(b"hostlist", b"BINDTOIPV4")
                .map(|bytes| {
                    std::str::from_utf8(bytes)?
                        .parse::<Ipv4Addr>()
                        .map_err(|e| Box::new(e) as Failure)
                })
                .transpose()?
                .unwrap_or(Ipv4Addr::UNSPECIFIED);
            let ipv6 = config
                .get(b"hostlist", b"BINDTOIPV6")
                .map(|bytes| {
                    std::str::from_utf8(bytes)?
                        .parse::<Ipv6Addr>()
                        .map_err(|e| Box::new(e) as Failure)
                })
                .transpose()?
                .unwrap_or(Ipv6Addr::UNSPECIFIED);
            binds.push(SocketAddr::new(ipv6.into(), port));
            binds.push(SocketAddr::new(ipv4.into(), port));
            external = config
                .get(b"hostlist", b"EXTERNAL_DNS_NAME")
                .map(<[u8]>::to_vec);
        }
        let store = if modes.bootstrap || modes.learning {
            let path = config.get_filename(b"hostlist", b"HOSTLISTFILE", &ProcessEnvironment)?;
            let mut owned = path.into_os_string();
            owned.push(".rust-hostlist");
            Some(PathBuf::from(owned))
        } else {
            None
        };
        Ok(Self {
            modes,
            state,
            limits,
            startup: duration(config, b"STARTUP_TIMEOUT", Duration::from_secs(30))?,
            resolver: gnunet_resolver_broker::Limits {
                max_frame_bytes: 65535,
                io_chunk_bytes: limits.io_slice,
                max_queued_frames: 8,
            },
            servers,
            proxy,
            binds,
            external,
            port,
            store,
            store_bytes: number(config, b"STORE_BYTES", 65536)?,
        })
    }
}
