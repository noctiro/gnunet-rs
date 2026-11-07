//! Shared official Unix/TCP listener setup, using an explicit service section.
#![forbid(unsafe_code)]
use crate::activation::{ActivatedSocket, Activation};
use crate::{CreatedPath, private_parents};
use crate::{
    acl::AccessPolicy,
    network::shorten_unixpath,
    service::{Listener, ServiceOptions, ShutdownMode},
};
use gnunet_config::{Configuration, ProcessEnvironment};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    error::Error,
    fs, io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
    path::PathBuf,
    time::Duration,
};
use tokio::net::{TcpListener, UnixListener, UnixStream};

#[derive(Debug)]
enum Owned {
    Unix(UnixListener),
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
                Owned::Unix(s) => Listener::Unix(s),
                Owned::Tcp(s) => Listener::Tcp(s),
            })
            .collect()
    }
    /// Newly created Unix paths owned by this set; excludes inherited listeners.
    pub fn unix_paths(&self) -> impl Iterator<Item = &std::path::Path> {
        self.paths.iter().map(|p| p.path())
    }
    /// Endpoint failures retained when at least one other listener bound.
    #[must_use]
    pub fn failures(&self) -> &[io::Error] {
        &self.failures
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
    socket.set_reuse_address(true)?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(5)?;
    TcpListener::from_std(socket.into())
}
/// Filesystem creation permissions for a newly bound Unix endpoint.
/// This is not a peer-credential check. Drivers must separately apply their
/// kernel UID/GID policy to each original accepted connection. Existing parents
/// and inherited sockets are never chmod/chown'ed by this policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnixListenerAccess {
    /// Restrict the new endpoint and parents to the owning UID.
    pub match_uid: bool,
    /// Allow the owning group when UID matching is disabled.
    pub match_gid: bool,
}
impl Default for UnixListenerAccess {
    fn default() -> Self {
        Self {
            match_uid: true,
            match_gid: false,
        }
    }
}
impl UnixListenerAccess {
    fn modes(self) -> (u32, u32) {
        if self.match_uid {
            (0o700, 0o700)
        } else if self.match_gid {
            (0o770, 0o750)
        } else {
            (0o777, 0o755)
        }
    }
}
fn access_parents(path: &std::path::Path, mode: u32) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let mut component = PathBuf::new();
    for part in parent.components() {
        component.push(part.as_os_str());
        // FreeBSD reports EISDIR for mkdir("/"). Existing directories need
        // no creation syscall and must retain their current permissions.
        match fs::metadata(&component) {
            Ok(metadata) if metadata.is_dir() => continue,
            Ok(_) => return Err(io::ErrorKind::NotADirectory.into()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        match fs::DirBuilder::new().mode(mode).create(&component) {
            Ok(()) => {
                // Initial creation is at most this restrictive under the current
                // umask. Only the directory just created by this owner is widened
                // to its requested mode; existing parents are never changed.
                fs::set_permissions(&component, fs::Permissions::from_mode(mode))?;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::AlreadyExists | io::ErrorKind::IsADirectory
                ) =>
            {
                if !fs::metadata(&component)?.is_dir() {
                    return Err(io::ErrorKind::NotADirectory.into());
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
async fn unix(path: PathBuf) -> io::Result<(UnixListener, CreatedPath)> {
    unix_with_access(path, UnixListenerAccess::default()).await
}
async fn unix_with_access(
    path: PathBuf,
    access: UnixListenerAccess,
) -> io::Result<(UnixListener, CreatedPath)> {
    let (socket_mode, parent_mode) = access.modes();
    if access == UnixListenerAccess::default() {
        private_parents(&path)?;
    } else {
        access_parents(&path, parent_mode)?;
    }
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            let observed = (metadata.dev(), metadata.ino());
            match tokio::time::timeout(Duration::from_secs(5), UnixStream::connect(&path)).await {
                Ok(Err(error))
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                    ) =>
                {
                    let old = CreatedPath::from_observed(path.clone(), observed.0, observed.1);
                    old.remove()?;
                }
                Ok(Ok(_)) => return Err(io::ErrorKind::AddrInUse.into()),
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err(io::ErrorKind::TimedOut.into()),
            }
        }
        Ok(_) => return Err(io::ErrorKind::AlreadyExists.into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let socket = crate::activation::bind_unix_private(&path)?;
    let guard = CreatedPath::capture(path)?;
    // Aggregate field order closes the actual listener before unlinking its
    // original inode on every later permission/nonblocking/conversion failure.
    let pending = crate::PrivateListener {
        listener: socket,
        path: guard,
        warnings: Vec::new(),
    };
    // The bind is initially private; widening happens only after capturing the
    // exact newly created inode and before exposing the listener to its driver.
    fs::set_permissions(pending.path.path(), fs::Permissions::from_mode(socket_mode))?;
    pending.listener.set_nonblocking(true)?;
    let crate::PrivateListener {
        listener: socket,
        path: guard,
        warnings: _,
    } = pending;
    Ok((UnixListener::from_std(socket)?, guard))
}
fn configured_addresses(
    config: &Configuration,
    section: &[u8],
) -> Result<(Option<PathBuf>, Vec<SocketAddr>), Box<dyn Error>> {
    let unixpath = config
        .get(section, b"UNIXPATH")
        .map(|_| config.get_filename(section, b"UNIXPATH", &ProcessEnvironment))
        .transpose()?
        .map(|p| shorten_unixpath(&p))
        .transpose()?;
    let port = config
        .get(section, b"PORT")
        .map(|_| config.get_number(section, b"PORT"))
        .transpose()?
        .unwrap_or(0);
    let port = u16::try_from(port).map_err(|_| "service PORT exceeds 65535")?;
    if unixpath.is_none() && port == 0 {
        return Err("service requires UNIXPATH or a nonzero PORT".into());
    }
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
    Ok((unixpath, addresses))
}

impl BoundListeners {
    /// Bind the explicit service section, or adopt all captured inherited listeners.
    ///
    /// Nonempty activation bypasses configured addresses entirely. Fresh sockets use
    /// UNIXPATH, PORT, BINDTO and DISABLEV6 from `section`; ACL/TOLERANT policy is
    /// provided separately by [`service_options`] for application by the driver.
    /// BINDTO uses native synchronous resolution as official service startup does;
    /// callers wanting local-only startup should supply a numeric loopback address.
    /// Call in a startup section without unrelated file creators: private Unix bind
    /// temporarily changes the process umask synchronously, never across an await.
    /// No listener exists when all endpoints fail. Partial success retains failures.
    pub async fn bind(
        config: &Configuration,
        section: &[u8],
        activation: Activation,
    ) -> Result<Self, Box<dyn Error>> {
        let mut bound = Self::empty();
        if !activation.sockets.is_empty() {
            bound.adopt(activation)?;
            return Ok(bound);
        }
        let (unixpath, addresses) = configured_addresses(config, section)?;
        if let Some(path) = unixpath {
            match unix(path).await {
                Ok((socket, guard)) => {
                    bound.sockets.push(Owned::Unix(socket));
                    bound.paths.push(guard);
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

    /// Prepare listeners for an explicit fresh-process identity transition.
    /// Nonempty activation is adopted once and bypasses configuration entirely.
    /// Otherwise only configured TCP sockets bind now, retaining privileged
    /// ports in this original owner; new Unix paths bind in
    /// [`ListenerPreparation::finish`] after the caller changes identity.
    /// This method itself never changes UID/GID or touches Unix path ownership.
    ///
    /// Call while entered on the same current-thread runtime used by `finish`.
    /// No accept or application callback runs during preparation. A missing or
    /// failed TCP alternative is retained when a configured Unix path can still
    /// succeed later; it is not reported as an actual usable listener.
    pub fn prepare_before_identity(
        config: &Configuration,
        section: &[u8],
        activation: Activation,
    ) -> Result<ListenerPreparation, Box<dyn Error>> {
        let mut bound = Self::empty();
        if !activation.sockets.is_empty() {
            bound.adopt(activation)?;
            return Ok(ListenerPreparation {
                bound,
                unixpath: None,
            });
        }
        let (unixpath, addresses) = configured_addresses(config, section)?;
        for address in addresses {
            match tcp(address) {
                Ok(socket) => bound.sockets.push(Owned::Tcp(socket)),
                Err(error) => bound.failures.push(error),
            }
        }
        if unixpath.is_none() {
            bound = bound.require_listener()?;
        }
        Ok(ListenerPreparation { bound, unixpath })
    }

    fn empty() -> Self {
        Self {
            sockets: Vec::new(),
            paths: Vec::new(),
            failures: Vec::new(),
        }
    }
    fn adopt(&mut self, activation: Activation) -> io::Result<()> {
        for socket in activation.sockets {
            match socket {
                ActivatedSocket::Unix(s) => {
                    s.set_nonblocking(true)?;
                    self.sockets.push(Owned::Unix(UnixListener::from_std(s)?));
                }
                ActivatedSocket::Tcp(s) => {
                    s.set_nonblocking(true)?;
                    self.sockets.push(Owned::Tcp(TcpListener::from_std(s)?));
                }
            }
        }
        Ok(())
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

/// Original inherited or prebound TCP listener owner plus one deferred Unix
/// endpoint. It is not READY and may still contain no successful listener.
/// Drop closes the original sockets; no new Unix path exists before `finish`.
#[derive(Debug)]
pub struct ListenerPreparation {
    bound: BoundListeners,
    unixpath: Option<PathBuf>,
}
impl ListenerPreparation {
    /// Bind the deferred new Unix path under the caller's current identity,
    /// keeping inherited and prebound sockets unchanged. No chown, fd-number
    /// reconstruction or identity change occurs here. Unix first remains the
    /// listener visitation order, matching ordinary configured `bind`.
    ///
    /// Every newly created path has the shared original inode guard. A failure
    /// or canceled future closes owned sockets before removing owned paths;
    /// inherited Unix paths are never registered for removal. Alternate endpoint
    /// failures remain visible through [`BoundListeners::failures`]. At least one
    /// actual successful listener is required to return a `BoundListeners` value.
    pub async fn finish(self) -> Result<BoundListeners, Box<dyn Error>> {
        self.finish_with_access(UnixListenerAccess::default()).await
    }

    /// Finish with explicit filesystem permissions for a new Unix endpoint.
    /// UID matching takes precedence over GID matching. Newly created socket /
    /// parent modes are respectively 0700/0700, 0770/0750, or 0777/0755. Existing
    /// parents, inherited sockets and foreign paths keep their ownership/modes.
    /// This startup-only operation requires the same exclusion of hostile path
    /// replacement and unrelated file creators as the private bind. It does not
    /// authenticate peers; the accepting driver must check kernel credentials.
    pub async fn finish_with_access(
        mut self,
        access: UnixListenerAccess,
    ) -> Result<BoundListeners, Box<dyn Error>> {
        if let Some(path) = self.unixpath.take() {
            match unix_with_access(path, access).await {
                Ok((socket, guard)) => {
                    self.bound.sockets.insert(0, Owned::Unix(socket));
                    self.bound.paths.push(guard);
                }
                Err(error) => self.bound.failures.push(error),
            }
        }
        self.bound.require_listener()
    }
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
