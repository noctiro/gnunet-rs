//! Configured Windows AF_UNIX listeners with native endpoint ACLs and cleanup.
use super::{BoundListeners, LocalListenerAccess, Owned};
use crate::activation::{ActivatedSocket, Activation};
use crate::local::Listener;
use gnunet_native::local_path::LocalPath;
use std::{io, path::PathBuf};

pub(super) async fn bind_local(
    path: PathBuf,
    access: LocalListenerAccess,
) -> io::Result<(Listener, LocalPath, Vec<io::Error>)> {
    let prepared = crate::local_listener::prepare(path, access, 5).await?;
    let (socket, path, warnings) = prepared.into_parts();
    Ok((Listener::from_bound_socket(socket)?, path, warnings))
}

impl BoundListeners {
    /// Bind configured endpoints or adopt original inherited listeners without rebinding.
    /// Call under the caller's I/O-enabled runtime after verifying process identity.
    pub async fn bind(
        config: &gnunet_config::Configuration,
        section: &[u8],
        activation: Activation,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if activation.is_empty() {
            Self::bind_configured(config, section, LocalListenerAccess::default()).await
        } else {
            Ok(Self::from_activation(activation)?)
        }
    }
    /// Register the actual inherited set without rebinding addresses or adopting
    /// path cleanup. Every descriptor becomes nonblocking before registration.
    /// Caller enters an I/O-enabled runtime and separately retains creator leases.
    pub fn from_activation(activation: Activation) -> io::Result<Self> {
        tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        let mut sockets = Vec::new();
        sockets
            .try_reserve_exact(activation.len())
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        for socket in activation.into_sockets() {
            let socket = match socket {
                ActivatedSocket::Unix(socket) => Owned::Unix(Listener::from_bound_socket(socket)?),
                ActivatedSocket::Tcp(socket) => {
                    socket.set_nonblocking(true)?;
                    Owned::Tcp(tokio::net::TcpListener::from_std(socket)?)
                }
            };
            sockets.push(socket);
        }
        Ok(Self {
            sockets,
            paths: Vec::new(),
            failures: Vec::new(),
        })
    }
}
