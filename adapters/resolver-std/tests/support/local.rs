//! Raw caller-owned local listener used by shared native wire/recovery tests.
use gnunet_service_runtime::local::Listener;
use std::{io, path::Path};

pub fn bind(path: &Path) -> io::Result<Listener> {
    #[cfg(unix)]
    {
        Listener::bind(path)
    }
    #[cfg(windows)]
    {
        let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
        socket.bind(&socket2::SockAddr::unix(path)?)?;
        socket.listen(5)?;
        Listener::from_bound_socket(socket)
    }
}
