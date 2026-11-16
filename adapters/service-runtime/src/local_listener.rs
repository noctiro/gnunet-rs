//! One original local bind shared by ordinary services and managed activation.
use crate::{CreatedPath, LocalListenerAccess};
use socket2::Socket;
use std::{io, path::PathBuf};
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

/// A freshly bound, listening socket with its original path cleanup owner.
/// Field order closes the socket before path retirement on every later error.
/// Inherited listeners never gain a path guard through this constructor.
#[derive(Debug)]
pub struct PreparedLocalListener {
    socket: Socket,
    path: CreatedPath,
    warnings: Vec<io::Error>,
}
impl PreparedLocalListener {
    /// Transfer the original socket, its paired cleanup guard and native
    /// diagnostics. Register the socket before releasing its guard on failure;
    /// an inherited endpoint never acquires this constructor's cleanup authority.
    pub fn into_parts(self) -> (Socket, CreatedPath, Vec<io::Error>) {
        (self.socket, self.path, self.warnings)
    }
}

/// Prepare a private local endpoint before registering it as an accepting or
/// nonconsuming listener. Existing live, foreign and symlink paths are refused;
/// a bounded stale probe never arms cleanup before establishing refusal.
/// Cancellation during that probe leaves the observed existing entry intact.
/// Call during startup with namespace/ACL changes excluded. Unix additionally
/// requires excluding unrelated file creation during its brief umask change;
/// no callback or await crosses that native guard. Uses the caller's I/O runtime.
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
        windows::prepare(path, access, backlog).await
    }
}
