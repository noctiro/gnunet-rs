use crate::{MachineInputs, NatHelperPrograms, SystemDns};
use gnunet_config::Configuration;
use gnunet_native::{filesystem::Directory, os_bytes};
use gnunet_service_runtime::network::{SocketPolicy, shorten_unixpath};
use gnunet_tcp_communicator_runtime::startup::PeerMode;
use gnunet_transport_runtime::startup::IncludedHellos;
use gnunet_vpn_host::startup::{ApplicationSettings, DiscoveryEndpoint, LocalEndpoints};
use std::{
    error::Error,
    io,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    num::{NonZeroU16, NonZeroU64},
    path::{Component, Path, PathBuf},
    time::Duration,
};

const IPC_SERVICES: &[&str] = &[
    "pils",
    "resolver",
    "transport",
    "peerstore",
    "core",
    "nat",
    "nse",
    "dht",
    "cadet",
];

/// Application-selected directories. Both must exist and be private to the
/// current user. The IPC path must fit the native Unix socket address layout.
pub struct Paths {
    /// Contains the peer private key and independent Rust journals.
    pub state: PathBuf,
    /// Contains the local IPC endpoints for the node and its clients.
    pub ipc: PathBuf,
}

/// Numeric listener selection for the peer-facing TCP communicator.
pub enum TcpBind {
    /// Bind this address. Port zero selects an ephemeral port.
    Address(SocketAddr),
    /// Bind both enabled IP families on an explicit shared port.
    DualStack(NonZeroU16),
}

/// Numeric listener addresses for the peer-facing UDP communicator.
pub struct UdpBind {
    /// IPv4 bind address. Port zero selects an ephemeral port.
    pub ipv4: SocketAddrV4,
    /// Optional native IPv6 bind. Port zero selects an ephemeral port.
    pub ipv6: Option<SocketAddrV6>,
}

/// The allowed Internet-facing communicator bindings for this node.
pub enum PeerTransport {
    /// Ordinary TCP and UDP bindings, with the optional configured communicators.
    Listening {
        /// Numeric external TCP bind selection.
        tcp: TcpBind,
        /// Numeric external UDP bind selection.
        udp: UdpBind,
    },
    /// Dial peers using the original TCP communicator without listening on a
    /// peer-facing socket. Local service IPC remains available.
    OutboundTcp,
}

/// Nonzero start and drain budgets for one native node owner.
pub struct Timing {
    pub(crate) startup: Duration,
    pub(crate) transport_drain: NonZeroU64,
}

impl Timing {
    /// Accept a finite startup interval and a TRANSPORT grace interval that
    /// has a positive duration representable in whole microseconds.
    pub fn new(startup: Duration, transport_drain: Duration) -> io::Result<Self> {
        if startup.is_zero() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let transport_drain = u64::try_from(transport_drain.as_micros())
            .ok()
            .and_then(NonZeroU64::new)
            .ok_or(io::ErrorKind::InvalidInput)?;
        Ok(Self {
            startup,
            transport_drain,
        })
    }

    /// Time available for node startup.
    #[must_use]
    pub const fn startup(&self) -> Duration {
        self.startup
    }

    /// Grace period for draining outbound TRANSPORT work.
    #[must_use]
    pub const fn transport_drain(&self) -> Duration {
        Duration::from_micros(self.transport_drain.get())
    }
}

/// DNS source for one native node's embedded Resolver.
pub enum ResolverInputs {
    /// Hosts, upstream datagrams and application-owned network updates.
    Datagram(MachineInputs),
    /// System policy with its original DNS, search and cache authority.
    System(SystemDns),
}

/// Explicit inputs from an application, extension or service manager.
pub struct Settings {
    /// GNUnet service settings, including any selected resource directory.
    pub config: Configuration,
    /// Explicit application data directory containing packaged `hellos`.
    /// When supplied, it selects the startup HELLO source.
    pub bootstrap_data_dir: Option<PathBuf>,
    /// Private persistent state and local IPC directories.
    pub paths: Paths,
    /// Internet peer transport and listener policy.
    pub peers: PeerTransport,
    /// An explicitly supplied, independently owned application packet provider.
    /// Its host ensures that upstream networking bypasses its own VPN routes.
    pub vpn: Option<Box<dyn crate::VpnProvider + Send>>,
    /// Required protection of every original peer or upstream Internet socket
    /// for a protected host, or the default operating-system routing policy.
    pub socket_policy: SocketPolicy,
    /// Original Resolver backend.
    pub resolver: ResolverInputs,
    /// Deployment-selected native NAT reversal programs.
    pub nat_helpers: Option<NatHelperPrograms>,
    /// Startup and transport drain budgets.
    pub timing: Timing,
}

/// Prepared configuration and namespace owners for one native node.
/// Its driver runs on the caller's Tokio reactor and takes one stop future.
pub struct Node {
    pub(crate) config: Configuration,
    pub(crate) resolver: ResolverInputs,
    pub(crate) nat_helpers: Option<NatHelperPrograms>,
    pub(crate) state: PathBuf,
    pub(crate) ipc: PathBuf,
    pub(crate) key: PathBuf,
    pub(crate) timing: Timing,
    pub(crate) tcp_mode: PeerMode,
    pub(crate) vpn: Option<ApplicationVpn>,
    pub(crate) socket_policy: SocketPolicy,
    pub(crate) included_hellos: Option<IncludedHellos>,
    pub(crate) quic: crate::quic::Communicators,
    #[cfg(unix)]
    pub(crate) unix: Option<crate::unix::Configured>,
    _state_directory: Directory,
    _ipc_directory: Directory,
}

pub(crate) struct ApplicationVpn {
    pub(crate) settings: ApplicationSettings,
    pub(crate) endpoints: LocalEndpoints,
    pub(crate) provider: Box<dyn crate::VpnProvider + Send>,
}

impl Node {
    /// Qualify private directories and route the node's services to original
    /// local endpoints. The caller keeps the namespace stable through `run`.
    /// This opens directory handles without opening a peer key or starting IPC.
    pub fn new(settings: Settings) -> Result<Self, Box<dyn Error>> {
        Self::prepare(settings, &Directory::open)
    }

    /// Open both private directory owners below a required Linux mount point.
    /// The caller keeps this mount and its namespace stable through `run`.
    ///
    /// # Errors
    /// Fails before key or IPC setup if the selected mount or either original
    /// directory fails mount, namespace or access qualification.
    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    pub fn new_on_mount(settings: Settings, mount: &Path) -> Result<Self, Box<dyn Error>> {
        let mount = gnunet_native::filesystem::MountPoint::open(mount)?;
        Self::prepare(settings, &|path| mount.open_directory(path))
    }

    fn prepare(
        settings: Settings,
        open_directory: &dyn Fn(&Path) -> io::Result<Directory>,
    ) -> Result<Self, Box<dyn Error>> {
        let Settings {
            mut config,
            bootstrap_data_dir,
            paths,
            peers,
            vpn,
            socket_policy,
            resolver,
            nat_helpers,
            timing,
        } = settings;
        let state_directory = private_directory(&paths.state, open_directory)?;
        let ipc_directory = private_directory(&paths.ipc, open_directory)?;

        let services = IPC_SERVICES
            .iter()
            .copied()
            .chain(vpn.is_some().then_some("vpn"));
        for name in services.clone() {
            configure_ipc(&mut config, &paths.ipc, name)?;
        }
        let key = paths.state.join("peer.key");
        set_path(&mut config, b"peer", b"PRIVATE_KEY", &key)?;
        config.set_value(b"communicator-tcp", b"USERNAME", None)?;
        let tcp_mode = match peers {
            PeerTransport::Listening { tcp, udp } => {
                configure_listeners(&mut config, tcp, udp)?;
                PeerMode::Listening
            }
            PeerTransport::OutboundTcp => {
                qualify_outbound(&config)?;
                PeerMode::OutboundOnly
            }
        };
        let vpn = vpn
            .map(|provider| -> Result<_, Box<dyn Error>> {
                let settings = ApplicationSettings::read(&config)?;
                let discovery = if settings.uses_regex() {
                    DiscoveryEndpoint::Regex(configure_ipc(&mut config, &paths.ipc, "regex")?)
                } else {
                    DiscoveryEndpoint::Configured
                };
                Ok(ApplicationVpn {
                    settings,
                    endpoints: LocalEndpoints {
                        vpn: paths.ipc.join("vpn"),
                        cadet: paths.ipc.join("cadet"),
                        discovery,
                    },
                    provider,
                })
            })
            .transpose()?;
        let quic = crate::quic::Communicators::read(&config)?;
        let included_hellos = match bootstrap_data_dir {
            Some(directory) => Some(IncludedHellos::in_data_directory(&directory, &config)?),
            None => IncludedHellos::configured(&config)?,
        };
        #[cfg(unix)]
        let unix = crate::unix::read(
            &config,
            &paths.ipc,
            services.chain(
                vpn.as_ref()
                    .is_some_and(|vpn| vpn.settings.uses_regex())
                    .then_some("regex"),
            ),
        )?;
        #[cfg(not(unix))]
        if config.get(b"communicator-unix", b"UNIXPATH").is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the UNIX communicator requires native AF_UNIX datagrams",
            )
            .into());
        }
        Ok(Self {
            config,
            resolver,
            nat_helpers,
            state: paths.state,
            ipc: paths.ipc,
            key,
            timing,
            tcp_mode,
            vpn,
            socket_policy,
            included_hellos,
            quic,
            #[cfg(unix)]
            unix,
            _state_directory: state_directory,
            _ipc_directory: ipc_directory,
        })
    }

    /// Configuration that local official IPC clients use for this node.
    #[must_use]
    pub fn configuration(&self) -> &Configuration {
        &self.config
    }
}

fn configure_ipc(
    config: &mut Configuration,
    directory: &Path,
    name: &str,
) -> Result<PathBuf, Box<dyn Error>> {
    let section = name.as_bytes();
    let endpoint = directory.join(name);
    if shorten_unixpath(&endpoint)? != endpoint {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "GNUnet IPC requires a shorter private socket directory",
        )
        .into());
    }
    set_path(config, section, b"UNIXPATH", &endpoint)?;
    config.set_value(section, b"PORT", None)?;
    config.set_value(section, b"USERNAME", None)?;
    config.set_value(section, b"UNIX_MATCH_GID", Some(b"NO"))?;
    config.set_value(
        section,
        b"UNIX_MATCH_UID",
        Some(if cfg!(unix) { b"YES" } else { b"NO" }),
    )?;
    Ok(endpoint)
}

fn configure_listeners(
    config: &mut Configuration,
    tcp: TcpBind,
    udp: UdpBind,
) -> Result<(), Box<dyn Error>> {
    let bindto = match tcp {
        TcpBind::Address(address) => address.to_string(),
        TcpBind::DualStack(port) => port.to_string(),
    };
    config.set_value(b"communicator-tcp", b"BINDTO", Some(bindto.as_bytes()))?;
    config.set_value(b"communicator-tcp", b"DISABLE_V6", Some(b"NO"))?;
    let section = b"communicator-udp";
    config.set_value(section, b"USERNAME", None)?;
    config.set_value(section, b"BINDTO", Some(udp.ipv4.to_string().as_bytes()))?;
    if udp
        .ipv6
        .is_some_and(|address| address.ip().to_ipv4_mapped().is_some())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UDP IPv6 bind requires a native IPv6 address",
        )
        .into());
    }
    let bind_v6 = udp.ipv6.map(|address| address.to_string());
    config.set_value(section, b"BINDTO6", bind_v6.as_deref().map(str::as_bytes))?;
    config.set_value(
        section,
        b"DISABLE_V6",
        Some(if bind_v6.is_some() { b"NO" } else { b"YES" }),
    )?;
    Ok(())
}

fn qualify_outbound(config: &Configuration) -> Result<(), Box<dyn Error>> {
    let mut listeners = config.get(b"communicator-unix", b"UNIXPATH").is_some();
    for section in [b"communicator-quic".as_slice(), b"communicator-http3"] {
        listeners |= config.get(section, b"BINDTO").is_some();
    }
    if config.get(b"dhtu-ip", b"ENABLED").is_some() {
        listeners |= config.get_yesno(b"dhtu-ip", b"ENABLED")?;
    }
    if listeners {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "outbound TCP mode requires the listening communicators and IP DHTU to be disabled",
        )
        .into());
    }
    Ok(())
}

fn private_directory(
    path: &Path,
    open: &dyn Fn(&Path) -> io::Result<Directory>,
) -> io::Result<Directory> {
    if !path.is_absolute()
        || path.components().any(|part| part == Component::ParentDir)
        || os_bytes::encode(path.as_os_str())
            .iter()
            .any(|byte| matches!(byte, 0 | b'$'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "absolute literal private directory required",
        ));
    }
    let owned = open(path)?;
    owned.validate_private()?;
    Ok(owned)
}

fn set_path(
    config: &mut Configuration,
    section: &[u8],
    key: &[u8],
    path: &Path,
) -> Result<(), gnunet_config::Error> {
    let bytes = os_bytes::encode(path.as_os_str());
    config.set_value(section, key, Some(&bytes))
}
