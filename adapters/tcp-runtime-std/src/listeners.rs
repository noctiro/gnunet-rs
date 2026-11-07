use crate::settings::Settings;
use gnunet_service_runtime::{Activation, activation::ActivatedSocket, service::Listener};
use socket2::{Domain, Protocol, Socket, Type};
use std::{io, net::SocketAddr, net::TcpListener as StdListener};
use tokio::net::TcpListener;
/// Prepared original TCP descriptor owners. Construction performs no async task,
/// peer/key operation or path binding. A process may apply USERNAME after this
/// step, then register exactly these same sockets in its selected runtime.
pub struct PreparedListeners {
    sockets: Vec<StdListener>,
    addresses: Vec<SocketAddr>,
}
impl PreparedListeners {
    /// Reserve all descriptor metadata before the first Resolver callback.
    pub(crate) fn reserve(maximum: usize) -> io::Result<Self> {
        let mut sockets = Vec::new();
        let mut addresses = Vec::new();
        sockets
            .try_reserve_exact(maximum)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        addresses
            .try_reserve_exact(maximum)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        Ok(Self { sockets, addresses })
    }
    /// Perform the original socket/bind/listen effect, then retain that exact
    /// descriptor and its kernel-selected address. No allocation follows bind.
    pub(crate) fn bind(&mut self, address: SocketAddr) -> io::Result<()> {
        if self.sockets.len() == self.sockets.capacity()
            || self.addresses.len() == self.addresses.capacity()
        {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "prebound listener capacity",
            ));
        }
        let socket = Socket::new(
            if address.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            },
            Type::STREAM,
            Some(Protocol::TCP),
        )?;
        socket.set_reuse_address(true)?;
        if address.is_ipv6() {
            socket.set_only_v6(true)?;
        }
        socket.set_nonblocking(true)?;
        socket.bind(&address.into())?;
        socket.listen(5)?;
        let listener: StdListener = socket.into();
        let actual = listener.local_addr()?;
        self.addresses.push(actual);
        self.sockets.push(listener);
        Ok(())
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.sockets.is_empty()
    }

    /// Register the original prebound/adopted descriptors in the current runtime.
    /// No socket is rebound or reconstructed from a remembered raw FD.
    pub fn finish(self) -> io::Result<Listeners> {
        let mut sockets = Vec::new();
        sockets
            .try_reserve_exact(self.sockets.len())
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        for socket in self.sockets {
            sockets.push(TcpListener::from_std(socket)?);
        }
        Ok(Listeners {
            sockets,
            addresses: self.addresses,
        })
    }
}
/// Actual owned TCP listeners. Original inherited descriptor paths are not
/// rebound; all accepted streams use the shared canonical accept policy.
pub struct Listeners {
    sockets: Vec<TcpListener>,
    addresses: Vec<SocketAddr>,
}
impl Listeners {
    /// Bind official numeric/bare-port options or adopt actual inherited TCP
    /// listeners. Each newly created socket uses source backlog5 and v6-only mode.
    pub fn bind(settings: &Settings, activation: Activation) -> io::Result<Self> {
        Self::prepare(settings, activation)?.finish()
    }
    /// Bind/adopt the original TCP descriptors before a configured process
    /// identity change. New sockets retain the existing backlog/v6-only policy.
    pub fn prepare(settings: &Settings, activation: Activation) -> io::Result<PreparedListeners> {
        if activation.sockets.is_empty() && settings.hostname.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hostname BINDTO needs the original shared Resolver prebinding owner",
            ));
        }
        let mut prepared =
            PreparedListeners::reserve(activation.sockets.len().max(settings.bindings.len()))?;
        if activation.sockets.is_empty() {
            for address in &settings.bindings {
                prepared.bind(*address)?;
            }
        } else {
            for original in activation.sockets {
                match original {
                    ActivatedSocket::Tcp(listener) => {
                        listener.set_nonblocking(true)?;
                        prepared.addresses.push(listener.local_addr()?);
                        prepared.sockets.push(listener);
                    }
                    ActivatedSocket::Unix(_) => {
                        return Err(io::Error::other(
                            "TCP communicator inherited a non-TCP listener",
                        ));
                    }
                }
            }
        }
        if prepared.is_empty() {
            return Err(io::Error::other("no actual TCP listener"));
        }
        Ok(prepared)
    }
    /// Exact kernel-bound endpoints, including actual selected port0 values.
    #[must_use]
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }
    /// Borrow canonical accept ports from these same original listener owners.
    #[must_use]
    pub fn ports(&self) -> Vec<Listener<'_>> {
        self.sockets.iter().map(Listener::Tcp).collect()
    }
}
