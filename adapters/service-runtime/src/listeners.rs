//! Configured native TCP listeners with platform-specific local socket owners.
#![forbid(unsafe_code)]
#[cfg(any(unix, windows))]
use crate::CreatedPath;
#[cfg(any(unix, windows))]
use crate::local::Listener as LocalListener;
use crate::{
    acl::AccessPolicy,
    service::{Listener, ServiceOptions, ShutdownMode},
};
use gnunet_config::Configuration;
#[cfg(any(unix, windows))]
use gnunet_config::ProcessEnvironment;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    error::Error,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
};
use tokio::net::TcpListener;
#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::ListenerPreparation;
#[cfg(windows)]
mod windows;

/// Filesystem access for a newly bound local endpoint, not peer authentication.
/// Existing parent permissions and inherited listeners are never changed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LocalListenerAccess {
    /// Unix effective owner, or Windows primary-token user, has sole access.
    #[default]
    Owner,
    /// Also allow Unix effective group or the Windows primary-token group SID.
    Group,
    /// Allow every user to connect; only the owner controls the endpoint's ACL.
    Everyone,
}
impl From<crate::credentials::UnixAccess> for LocalListenerAccess {
    /// Select creation permissions corresponding to a configured Unix policy.
    /// UID takes precedence over GID. The driver must still authenticate peers;
    /// this mapping does not make Unix UID/GID checks available on Windows.
    fn from(access: crate::credentials::UnixAccess) -> Self {
        if access.match_uid {
            Self::Owner
        } else if access.match_gid {
            Self::Group
        } else {
            Self::Everyone
        }
    }
}
#[derive(Debug)]
enum Owned {
    #[cfg(any(unix, windows))]
    Unix(LocalListener),
    Tcp(TcpListener),
}
/// Owned configured or inherited listeners, plus guards for newly bound Unix paths.
///
/// Fields drop in declaration order: all sockets close before owned paths are
/// unlinked. Inherited Unix paths are never registered for removal. A successful
/// bind may include failed alternate endpoints, available through [`Self::failures`].
/// Borrowed listeners cannot escape the owning set:
///
/// ```compile_fail,E0515
/// use gnunet_service_runtime::BoundListeners;
/// use gnunet_service_runtime::service::Listener;
/// fn escape(owner: BoundListeners) -> Vec<Listener<'static>> {
///     owner.listeners()
/// }
/// ```
#[derive(Debug)]
pub struct BoundListeners {
    sockets: Vec<Owned>,
    // Drop order matters: listeners close before their owned path is removed.
    #[cfg(any(unix, windows))]
    paths: Vec<CreatedPath>,
    failures: Vec<io::Error>,
}
impl BoundListeners {
    /// Borrow all live listeners for a service driver; the owner must outlive them.
    #[must_use]
    pub fn listeners(&self) -> Vec<Listener<'_>> {
        self.sockets
            .iter()
            .map(|s| match s {
                #[cfg(any(unix, windows))]
                Owned::Unix(s) => Listener::Unix(s),
                Owned::Tcp(s) => Listener::Tcp(s),
            })
            .collect()
    }
    /// Newly created Unix paths owned by this set; excludes inherited listeners.
    #[cfg(any(unix, windows))]
    pub fn unix_paths(&self) -> impl Iterator<Item = &std::path::Path> {
        self.paths.iter().map(|p| p.path())
    }
    /// Endpoint failures retained when at least one other listener bound.
    #[must_use]
    pub fn failures(&self) -> &[io::Error] {
        &self.failures
    }

    /// Close all original listeners, then remove their owned local nodes. Each
    /// failed node stays owned by this set for another `close` attempt. Errors
    /// report every failed cleanup in path visitation order. Drop only performs
    /// best-effort cleanup; use this operation when failures must be observable.
    #[cfg(any(unix, windows))]
    pub fn close(&mut self) -> Result<(), Vec<io::Error>> {
        self.sockets.clear();
        let mut errors = Vec::new();
        self.paths.retain_mut(|path| match path.remove() {
            Ok(()) => false,
            Err(error) => {
                errors.push(error);
                true
            }
        });
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    #[cfg(any(unix, windows))]
    /// Bind one owned local endpoint with native permissions/ACLs established
    /// before listen. The owner retains original socket/path cleanup and native
    /// preparation diagnostics; inherited sockets gain no path authority.
    pub async fn bind_local(
        path: std::path::PathBuf,
        access: LocalListenerAccess,
    ) -> io::Result<Self> {
        let (socket, guard, failures) = local(path, access).await?;
        Ok(Self {
            sockets: vec![Owned::Unix(socket)],
            paths: vec![guard],
            failures,
        })
    }
    /// Bind configured UNIXPATH and TCP addresses without adopting activation.
    /// Local paths use official GNUnet shortening; partial endpoint failures are
    /// retained. Call during startup with namespace/ACL mutation excluded. Unix
    /// also requires exclusion of unrelated file creators during its brief umask
    /// change. Windows validates the parent ACL and protects the new node before
    /// listening. No endpoint binding grants peer credential authority.
    #[cfg(any(unix, windows))]
    pub async fn bind_configured(
        config: &Configuration,
        section: &[u8],
        access: LocalListenerAccess,
    ) -> Result<Self, Box<dyn Error>> {
        let (path, addresses) = configured_addresses(config, section)?;
        let mut bound = Self::empty();
        if let Some(path) = path {
            let result = local(path, access).await;
            match result {
                Ok((socket, guard, warnings)) => {
                    bound.sockets.push(Owned::Unix(socket));
                    bound.paths.push(guard);
                    bound.failures.extend(warnings);
                }
                Err(error) => bound.failures.push(error),
            }
        }
        for address in addresses {
            match tcp(address) {
                Ok(socket) => bound.sockets.push(Owned::Tcp(socket)),
                Err(error) => bound.failures.push(error),
            }
        }
        bound.require_listener()
    }
}
#[cfg(any(unix, windows))]
async fn local(
    path: std::path::PathBuf,
    access: LocalListenerAccess,
) -> io::Result<(LocalListener, CreatedPath, Vec<io::Error>)> {
    #[cfg(unix)]
    {
        unix::unix_with_access(path, access).await
    }
    #[cfg(windows)]
    {
        windows::bind_local(path, access).await
    }
}

fn tcp(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = Socket::new(
        if address.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        },
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    #[cfg(windows)]
    {
        use std::os::windows::io::AsSocket;
        gnunet_native::network::set_exclusive_address_use(socket.as_socket())?;
    }
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(5)?;
    TcpListener::from_std(socket.into())
}

impl BoundListeners {
    /// Bind configured official plain TCP IPC on every native platform.
    /// PORT must be nonzero. BINDTO and DISABLEV6 select addresses; this explicit
    /// TCP entry point does not open UNIXPATH or adopt inherited handles. Partial
    /// endpoint failures remain available in `failures`. Apply `service_options`
    /// at admission; successful binding alone grants no peer authority.
    pub fn bind_tcp(config: &Configuration, section: &[u8]) -> Result<Self, Box<dyn Error>> {
        let mut bound = Self::empty();
        for address in configured_tcp_addresses(config, section)? {
            match tcp(address) {
                Ok(socket) => bound.sockets.push(Owned::Tcp(socket)),
                Err(error) => bound.failures.push(error),
            }
        }
        bound.require_listener()
    }
    fn empty() -> Self {
        Self {
            sockets: Vec::new(),
            #[cfg(any(unix, windows))]
            paths: Vec::new(),
            failures: Vec::new(),
        }
    }
    fn require_listener(mut self) -> Result<Self, Box<dyn Error>> {
        if self.sockets.is_empty() {
            return Err(self
                .failures
                .pop()
                .unwrap_or_else(|| io::ErrorKind::AddrNotAvailable.into())
                .into());
        }
        Ok(self)
    }
}
#[cfg(any(unix, windows))]
fn configured_addresses(
    config: &Configuration,
    section: &[u8],
) -> Result<(Option<std::path::PathBuf>, Vec<SocketAddr>), Box<dyn Error>> {
    let path = config
        .get(section, b"UNIXPATH")
        .map(|_| config.get_filename(section, b"UNIXPATH", &ProcessEnvironment))
        .transpose()?
        .map(|path| crate::network::shorten_unixpath(&path))
        .transpose()?;
    let addresses = configured_tcp_addresses(config, section)?;
    if path.is_none() && addresses.is_empty() {
        return Err("service requires UNIXPATH or a nonzero PORT".into());
    }
    Ok((path, addresses))
}
fn configured_tcp_addresses(
    config: &Configuration,
    section: &[u8],
) -> Result<Vec<SocketAddr>, Box<dyn Error>> {
    let port = config
        .get(section, b"PORT")
        .map(|_| config.get_number(section, b"PORT"))
        .transpose()?
        .unwrap_or(0);
    let port = u16::try_from(port).map_err(|_| "service PORT exceeds 65535")?;
    let disable6 = matches!(config.get_yesno(section, b"DISABLEV6"), Ok(true));
    let mut addresses = Vec::new();
    if port != 0 {
        if let Some(host) = config.get(section, b"BINDTO") {
            let host = std::str::from_utf8(host)?;
            // Like C service startup, resolve synchronously here. No Tokio
            // blocking worker is created before the private Unix bind/umask.
            for address in (host, port).to_socket_addrs()? {
                if disable6 && address.is_ipv6() {
                    continue;
                }
                if addresses.len() >= 64 {
                    return Err("service listener capacity exceeded".into());
                }
                addresses.push(address);
            }
            if addresses.is_empty() {
                return Err("BINDTO resolved no address in the enabled families".into());
            }
        } else {
            if !disable6 {
                addresses.push(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port));
            }
            addresses.push(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port));
        }
    }
    Ok(addresses)
}

/// Parse the same explicit service section's address ACLs and TOLERANT setting.
///
/// The service driver must apply the returned options when accepting/dispatching
/// clients. Malformed configured policy is an error. UNIX_MATCH_UID/GID credential
/// checks, CLOSE_LSOCKS, daemonization and user switching are not supplied here.
pub fn service_options(
    config: &Configuration,
    section: &[u8],
    shutdown: ShutdownMode,
) -> Result<ServiceOptions, Box<dyn Error>> {
    Ok(ServiceOptions {
        access: AccessPolicy::from_config(config, section)?,
        tolerant: if config.get(section, b"TOLERANT").is_some() {
            config.get_yesno(section, b"TOLERANT")?
        } else {
            false
        },
        shutdown,
    })
}
