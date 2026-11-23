//! One original local bind shared by ordinary services and managed activation.
use crate::{CreatedPath, LocalListenerAccess};
use socket2::Socket;
use std::{io, path::PathBuf};
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(windows)]
use gnunet_native::{
    local_path::{EndpointAccess, EndpointPrincipals, ProtectedListener},
    socket_activation::Source,
};
#[cfg(windows)]
pub use windows::AccountBind;

#[cfg(windows)]
impl From<LocalListenerAccess> for EndpointAccess {
    fn from(access: LocalListenerAccess) -> Self {
        match access {
            LocalListenerAccess::Owner => Self::Owner,
            LocalListenerAccess::Group => Self::PrimaryGroup,
            LocalListenerAccess::Everyone => Self::Everyone,
        }
    }
}

/// A freshly bound, listening socket with its original path cleanup owner.
/// Field order closes the socket before path retirement on every later error.
/// Inherited listeners never gain a path guard through this constructor.
#[derive(Debug)]
pub struct PreparedLocalListener {
    #[cfg(unix)]
    socket: Socket,
    #[cfg(unix)]
    path: CreatedPath,
    #[cfg(unix)]
    warnings: Vec<io::Error>,
    #[cfg(windows)]
    listener: ProtectedListener,
}
impl PreparedLocalListener {
    /// Borrow the original unregistered Windows listener with its pre-listen
    /// access evidence for child activation.
    ///
    /// Keep this owner while the child serves the pathname, or through the
    /// retirement of a child whose startup failed. Dropping it removes the
    /// local pathname even if the child still owns a duplicate socket.
    #[cfg(windows)]
    pub fn launch_source(&self) -> Source<'_> {
        self.listener.launch_source()
    }

    /// Transfer the original socket, its paired cleanup guard and native
    /// diagnostics. Register the socket before releasing its guard on failure;
    /// an inherited endpoint never acquires this constructor's cleanup authority.
    pub fn into_parts(self) -> (Socket, CreatedPath, Vec<io::Error>) {
        #[cfg(unix)]
        {
            (self.socket, self.path, self.warnings)
        }
        #[cfg(windows)]
        {
            let (socket, path, _) = self.listener.into_parts();
            (socket, path, Vec::new())
        }
    }

    #[cfg(windows)]
    pub(crate) fn into_protected_parts(
        self,
    ) -> (
        Socket,
        CreatedPath,
        Vec<io::Error>,
        gnunet_native::local_path::EndpointProtection,
    ) {
        let (socket, path, protection) = self.listener.into_parts();
        (socket, path, Vec::new(), protection)
    }
}

/// Prepare a private local endpoint before registering it as an accepting or
/// nonconsuming listener. Existing live, foreign and symlink paths are refused;
/// a bounded stale probe never arms cleanup before establishing refusal.
/// Cancellation during that probe leaves the observed existing entry intact.
/// Call with namespace/ACL changes excluded. Unix commits node permissions
/// before the first listen without changing process umask. Uses the caller's
/// I/O runtime; no application connection is admitted during preparation.
pub async fn prepare(
    path: PathBuf,
    access: LocalListenerAccess,
    backlog: i32,
) -> io::Result<PreparedLocalListener> {
    tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
    #[cfg(unix)]
    {
        unix::prepare(path, access, backlog).await
    }
    #[cfg(windows)]
    {
        let principals = EndpointPrincipals::for_current_process(access.into())?;
        windows::prepare(path, principals, backlog).await
    }
}
