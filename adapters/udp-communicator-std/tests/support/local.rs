//! Native local-listener fixture with the original endpoint cleanup at caller.
use gnunet_service_runtime::local::Listener;
use std::{io, path::Path};
pub(crate) fn bind(path: &Path) -> io::Result<Listener> {
    #[cfg(unix)]
    {
        Listener::bind(path)
    }
    #[cfg(windows)]
    {
        use socket2::{Domain, SockAddr, Socket, Type};
        let name = path.to_str().ok_or(io::ErrorKind::InvalidInput)?;
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        socket.bind(&SockAddr::unix(name)?)?;
        socket.listen(8)?;
        Listener::from_bound_socket(socket)
    }
}
