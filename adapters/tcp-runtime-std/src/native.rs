use gnunet_service_runtime::connection::Connection;
use gnunet_service_runtime::network::SocketPolicy;
use gnunet_tcp_communicator_host::Connect;
use std::{io, net::SocketAddr};
use tokio::{io::Interest, net::TcpStream};
/// One original nonblocking native connect admitted by an actual connect syscall.
/// Constructing this value starts the attempt. Waiting/poll cancellation retains
/// the same socket; neither admission nor writability authenticates its peer.
pub struct NativeConnect {
    stream: TcpStream,
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn refused_policy_precedes_the_original_tcp_connect() -> io::Result<()> {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let policy = SocketPolicy::protected(move |socket| {
            let native = socket2::SockRef::from(&socket);
            if !native
                .local_addr()?
                .as_socket()
                .is_some_and(|address| address.port() == 0)
                || native.peer_addr().is_ok()
            {
                return Err(io::Error::other(
                    "TCP policy observed an already-used socket",
                ));
            }
            observed.fetch_add(1, Ordering::Relaxed);
            Err(io::ErrorKind::PermissionDenied.into())
        });
        let address = SocketAddr::from(([127, 0, 0, 1], 1));
        let result = NativeConnect::begin_with_socket_policy(address, &policy);
        if calls.load(Ordering::Relaxed) != 1
            || !matches!(result, Err(error) if error.kind() == io::ErrorKind::PermissionDenied)
        {
            return Err(io::Error::other(
                "TCP connect bypassed original protection refusal",
            ));
        }
        Ok(())
    }
}
impl NativeConnect {
    /// Create/options/connect the original native socket. Success includes actual
    /// EINPROGRESS; synchronous refusal returns its original cause and drops it.
    /// The caller must run inside its intended Tokio reactor while constructing.
    pub fn begin(address: SocketAddr) -> io::Result<Self> {
        Self::begin_with_socket_policy(address, &SocketPolicy::default())
    }
    /// Apply the original caller policy before the first native connect effect.
    pub fn begin_with_socket_policy(
        address: SocketAddr,
        socket_policy: &SocketPolicy,
    ) -> io::Result<Self> {
        let socket = socket_policy.open_tcp(address)?;
        socket.set_nonblocking(true)?;
        socket.set_tcp_nodelay(true)?;
        match socket.connect(&address.into()) {
            Ok(()) => {}
            Err(e) if gnunet_native::network::connect_in_progress(&e) => {}
            Err(e) => return Err(e),
        }
        let stream = TcpStream::from_std(socket.into())?;
        Ok(Self { stream })
    }
    /// Transfer the exact already-started socket into the manager's original
    /// retained future. It checks actual SO_ERROR/peer state after readiness.
    pub fn into_future(self) -> Connect<'static> {
        Box::pin(async move {
            loop {
                self.stream.writable().await?;
                let connected = self.stream.try_io(Interest::WRITABLE, || {
                    if let Some(error) = self.stream.take_error()? {
                        return Err(error);
                    }
                    match self.stream.peer_addr() {
                        Ok(_) => Ok(()),
                        Err(e) if e.kind() == io::ErrorKind::NotConnected => {
                            Err(io::ErrorKind::WouldBlock.into())
                        }
                        Err(e) => Err(e),
                    }
                });
                match connected {
                    Ok(()) => return Ok(Connection::from_tcp(self.stream)),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
            }
        })
    }
}
