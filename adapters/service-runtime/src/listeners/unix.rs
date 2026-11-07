//! Unix activation, private path ownership and identity-transition preparation.
use super::{BoundListeners, Owned, configured_tcp_addresses, tcp};
use crate::activation::{ActivatedSocket, Activation};
use crate::{CreatedPath, network::shorten_unixpath, private_parents};
use gnunet_config::{Configuration, ProcessEnvironment};
use std::{
    error::Error,
    fs, io,
    net::SocketAddr,
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
    path::PathBuf,
    time::Duration,
};
use tokio::net::{TcpListener, UnixListener, UnixStream};
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
    let addresses = configured_tcp_addresses(config, section)?;
    if unixpath.is_none() && addresses.is_empty() {
        return Err("service requires UNIXPATH or a nonzero PORT".into());
    }
    Ok((unixpath, addresses))
}

impl BoundListeners {
    /// Bind the explicit service section, or adopt all captured inherited listeners.
    ///
    /// Nonempty activation bypasses configured addresses entirely. Fresh sockets use
    /// UNIXPATH, PORT, BINDTO and DISABLEV6 from `section`; ACL/TOLERANT policy is
    /// provided separately by [`service_options`](super::service_options) for application by the driver.
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
