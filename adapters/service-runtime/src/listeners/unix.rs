//! Unix activation, private path ownership and identity-transition preparation.
use super::{BoundListeners, LocalListenerAccess, Owned, configured_addresses, tcp};
use crate::CreatedPath;
use crate::activation::{ActivatedSocket, Activation};
use gnunet_config::Configuration;
use std::{error::Error, io, path::PathBuf};
use tokio::net::{TcpListener, UnixListener};
pub(super) async fn unix_with_access(
    path: PathBuf,
    access: LocalListenerAccess,
) -> io::Result<(UnixListener, CreatedPath, Vec<io::Error>)> {
    let prepared = crate::local_listener::prepare(path, access, 5).await?;
    let (socket, path, warnings) = prepared.into_parts();
    Ok((UnixListener::from_std(socket.into())?, path, warnings))
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
        Self::bind_configured(config, section, LocalListenerAccess::default()).await
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
        self.finish_with_access(LocalListenerAccess::default())
            .await
    }

    /// Finish with explicit filesystem permissions for a new Unix endpoint.
    /// Owner, group and everyone select socket / parent modes 0700/0700,
    /// 0770/0750 and 0777/0755 respectively. Existing
    /// parents, inherited sockets and foreign paths keep their ownership/modes.
    /// This startup-only operation requires the same exclusion of hostile path
    /// replacement and unrelated file creators as the private bind. It does not
    /// authenticate peers; the accepting driver must check kernel credentials.
    pub async fn finish_with_access(
        mut self,
        access: LocalListenerAccess,
    ) -> Result<BoundListeners, Box<dyn Error>> {
        if let Some(path) = self.unixpath.take() {
            match unix_with_access(path, access).await {
                Ok((socket, guard, warnings)) => {
                    self.bound.sockets.insert(0, Owned::Unix(socket));
                    self.bound.paths.push(guard);
                    self.bound.failures.extend(warnings);
                }
                Err(error) => self.bound.failures.push(error),
            }
        }
        self.bound.require_listener()
    }
}
