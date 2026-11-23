use crate::{GnBytes, GnNodeOptions};
use gnunet_config::Configuration;
use gnunet_node_host::{
    MachineInputs, Node, Paths, PeerTransport, ResolverInputs, Settings, TcpBind, Timing, UdpBind,
    Upstreams, VpnProvider,
};
use gnunet_service_runtime::network::SocketPolicy;
use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

pub(crate) const MAX_PATH: usize = 4096;
const MAX_ADDRESS: usize = 128;
const MAX_DNS_TEXT: usize = 4096;

pub(crate) struct Options {
    paths: Paths,
    config_file: Option<PathBuf>,
    bootstrap_data_dir: Option<PathBuf>,
    peers: PeerTransport,
    vpn: Option<Box<dyn VpnProvider + Send>>,
    socket_policy: SocketPolicy,
    resolver: MachineInputs,
    timing: Timing,
}

impl Options {
    #[expect(
        unsafe_code,
        reason = "SDK copies only caller-provided readable UTF-8 ranges"
    )]
    pub(crate) unsafe fn read(raw: &GnNodeOptions, outbound_only: bool) -> Option<Self> {
        // SAFETY: the ABI caller lends every nonempty range through this call.
        let (state, ipc, config, bootstrap, tcp, udp4, udp6, dns) = unsafe {
            (
                raw.state_dir.text(MAX_PATH)?,
                raw.ipc_dir.text(MAX_PATH)?,
                raw.config_file.text(MAX_PATH)?,
                raw.bootstrap_data_dir.text(MAX_PATH)?,
                raw.tcp_bind.text(MAX_ADDRESS)?,
                raw.udp4_bind.text(MAX_ADDRESS)?,
                raw.udp6_bind.text(MAX_ADDRESS)?,
                raw.dns_servers.text(MAX_DNS_TEXT)?,
            )
        };
        let paths = Paths {
            state: path(state)?,
            ipc: path(ipc)?,
        };
        let config_file = if config.is_empty() {
            None
        } else {
            Some(path(config)?)
        };
        let bootstrap_data_dir = if bootstrap.is_empty() {
            None
        } else {
            Some(path(bootstrap)?)
        };
        let peers = if outbound_only {
            if [tcp, udp4, udp6].iter().any(|value| !value.is_empty()) {
                return None;
            }
            PeerTransport::OutboundTcp
        } else {
            PeerTransport::Listening {
                tcp: TcpBind::Address(tcp.parse().ok()?),
                udp: UdpBind {
                    ipv4: udp4.parse().ok()?,
                    ipv6: if udp6.is_empty() {
                        None
                    } else {
                        Some(udp6.parse().ok()?)
                    },
                },
            }
        };
        let timing = Timing::new(
            Duration::from_millis(raw.startup_timeout_ms.into()),
            Duration::from_millis(raw.drain_timeout_ms.into()),
        )
        .ok()?;
        Some(Self {
            paths,
            config_file,
            bootstrap_data_dir,
            peers,
            vpn: None,
            socket_policy: SocketPolicy::default(),
            resolver: MachineInputs {
                dns_endpoints: parse_dns(dns)?.into_endpoints(),
                ..MachineInputs::default()
            },
            timing,
        })
    }

    pub(crate) fn with_vpn(
        mut self,
        vpn: Box<dyn VpnProvider + Send>,
        socket_policy: SocketPolicy,
    ) -> Self {
        self.vpn = Some(vpn);
        self.socket_policy = socket_policy;
        self
    }

    pub(crate) fn prepare(self) -> Result<Node, Box<dyn Error>> {
        let mut config = Configuration::default();
        if let Some(path) = &self.config_file {
            config.load_explicit(None, Some(path))?;
        }
        Node::new(Settings {
            config,
            bootstrap_data_dir: self.bootstrap_data_dir,
            paths: self.paths,
            peers: self.peers,
            vpn: self.vpn,
            socket_policy: self.socket_policy,
            resolver: ResolverInputs::Datagram(self.resolver),
            nat_helpers: None,
            timing: self.timing,
        })
    }
}

impl GnBytes {
    #[expect(unsafe_code, reason = "The caller lends one bounded UTF-8 input range")]
    pub(crate) unsafe fn dns_upstreams(self) -> Option<Upstreams> {
        // SAFETY: the ABI caller lends the bytes through decoding and copying.
        parse_dns(unsafe { self.text(MAX_DNS_TEXT)? })
    }

    #[expect(
        unsafe_code,
        reason = "C range is borrowed only for input decoding after bounds checks"
    )]
    pub(crate) unsafe fn text(&self, maximum: usize) -> Option<&str> {
        if self.len == 0 {
            return Some("");
        }
        if self.len > maximum || self.data.is_null() {
            return None;
        }
        // SAFETY: the caller supplies a readable buffer with the stated extent.
        let bytes = unsafe { std::slice::from_raw_parts(self.data, self.len) };
        if bytes.contains(&0) {
            return None;
        }
        std::str::from_utf8(bytes).ok()
    }
}

pub(crate) fn path(text: &str) -> Option<PathBuf> {
    let path = PathBuf::from(text);
    (path.is_absolute() && !text.contains('$')).then_some(path)
}

fn parse_dns(text: &str) -> Option<Upstreams> {
    let mut endpoints =
        [SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0); Upstreams::MAX_ENDPOINTS];
    let mut count = 0;
    for value in text.split_ascii_whitespace() {
        *endpoints.get_mut(count)? = if let Ok(ip) = value.parse::<IpAddr>() {
            SocketAddr::new(ip, 53)
        } else {
            value.parse::<SocketAddr>().ok()?
        };
        count += 1;
    }
    Upstreams::new(endpoints[..count].iter().copied()).ok()
}
