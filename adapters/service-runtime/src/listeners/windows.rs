//! Configured Windows AF_UNIX listeners with native endpoint ACLs and cleanup.
use super::{BoundListeners, LocalListenerAccess, Owned};
use crate::activation::{ActivatedSocket, Activation};
use crate::credentials::UnixAccess;
use crate::local::Listener;
use gnunet_native::local_path::LocalPath;
use std::{io, path::PathBuf};

pub(super) async fn bind_local(
    path: PathBuf,
    access: LocalListenerAccess,
) -> io::Result<(Listener, LocalPath, Vec<io::Error>)> {
    let prepared = crate::local_listener::prepare(path, access, 5).await?;
    Listener::from_prepared(prepared)
}

impl LocalListenerAccess {
    /// Check whether the selected Windows DACL meets the service restriction.
    #[must_use]
    pub fn satisfies(self, restriction: UnixAccess) -> bool {
        restriction.permits_windows_access(self.into())
    }
}

impl BoundListeners {
    /// Bind configured endpoints or adopt original inherited listeners without rebinding.
    /// Apply the configured local-access policy before registering inherited listeners
    /// or listening on a newly bound local endpoint.
    /// Call under the caller's I/O-enabled runtime after verifying process identity.
    pub async fn bind(
        config: &gnunet_config::Configuration,
        section: &[u8],
        activation: Activation,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let access = UnixAccess::from_config(config, section)?;
        if activation.is_empty() {
            Self::bind_configured(config, section, access.map(Into::into).unwrap_or_default()).await
        } else {
            Ok(Self::from_activation_with_access(
                activation,
                access.unwrap_or_default(),
            )?)
        }
    }
    /// Register the actual inherited set without rebinding addresses or adopting
    /// path cleanup. Every descriptor becomes nonblocking before registration.
    /// Caller enters an I/O-enabled runtime and separately retains creator leases.
    pub fn from_activation(activation: Activation) -> io::Result<Self> {
        Self::from_activation_with_access(activation, UnixAccess::default())
    }

    /// Validate the original local ACL policy before registering any listener.
    /// TCP listeners use their independent IP admission policy.
    ///
    /// # Errors
    /// A restricted AF_UNIX listener requires pre-listen protection that satisfies
    /// `access`. Validation or registration failure closes the transferred sockets.
    pub fn from_activation_with_access(
        activation: Activation,
        access: UnixAccess,
    ) -> io::Result<Self> {
        activation.validate_local_access(access)?;
        tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        let mut sockets = Vec::new();
        sockets
            .try_reserve_exact(activation.len())
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        for socket in activation.into_sockets() {
            let socket = match socket {
                ActivatedSocket::Unix(socket) => Owned::Unix(Listener::from_activated(socket)?),
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
