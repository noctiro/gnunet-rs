//! Windows original-node ACL and bounded stale-probe ownership before listen.
use super::PreparedLocalListener;
use crate::{LocalListenerAccess, local::Stream};
use gnunet_native::local_path::{EndpointAccess, LocalPath, prepare_parents};
use socket2::{Domain, SockAddr, Socket, Type};
use std::{io, path::PathBuf, time::Duration};
// Field declaration order closes the socket before attempting node cleanup on
// every ACL, listen, nonblocking or runtime-registration failure.
pub(super) async fn prepare(
    path: PathBuf,
    access: LocalListenerAccess,
    backlog: i32,
) -> io::Result<PreparedLocalListener> {
    tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
    // Resolve once so a process current-directory change cannot redirect later
    // operations. The native AF_UNIX address remains the original Unicode path.
    let path = std::path::absolute(path)?;
    let address = SockAddr::unix(&path)?;
    let access = match access {
        LocalListenerAccess::Owner => EndpointAccess::Owner,
        LocalListenerAccess::Group => EndpointAccess::PrimaryGroup,
        LocalListenerAccess::Everyone => EndpointAccess::Everyone,
    };
    prepare_parents(&path, access)?;
    match LocalPath::inspect(path.clone()) {
        Ok(mut old) => {
            // A probe never arms automatic deletion of a live endpoint. Keep
            // the stale candidate out of a cleanup owner until refusal proves
            // it reclaimable under the caller's startup namespace exclusion.
            match tokio::time::timeout(Duration::from_secs(5), Stream::connect(&path)).await {
                Ok(Err(error))
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                    ) =>
                {
                    old.remove()?
                }
                Ok(Ok(_)) => return Err(io::ErrorKind::AddrInUse.into()),
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err(io::ErrorKind::TimedOut.into()),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    socket.bind(&address)?;
    let path = LocalPath::capture(path)?;
    let pending = PreparedLocalListener {
        socket,
        path,
        warnings: Vec::new(),
    };
    pending.path.set_access(access)?;
    pending.socket.listen(backlog)?;
    Ok(pending)
}
