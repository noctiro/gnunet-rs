use crate::settings::{Binding, PeerMode, Settings};
use gnunet_service_runtime::{
    Activation,
    activation::ActivatedSocket,
    network::{SocketOpenError, SocketPolicy},
    service::Listener,
};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener as StdListener},
};
use tokio::net::TcpListener;
/// Prepared original TCP descriptor owners. Construction performs no async task,
/// peer/key operation or path binding. A process may apply USERNAME after this
/// step, then register exactly these same sockets in its selected runtime.
pub struct PreparedListeners {
    sockets: Vec<StdListener>,
    addresses: Vec<SocketAddr>,
    socket_policy: SocketPolicy,
}
impl PreparedListeners {
    /// Reserve all descriptor metadata before the first Resolver callback.
    pub(crate) fn reserve(maximum: usize) -> io::Result<Self> {
        Self::reserve_with_socket_policy(maximum, SocketPolicy::default())
    }
    fn reserve_with_socket_policy(maximum: usize, socket_policy: SocketPolicy) -> io::Result<Self> {
        let mut sockets = Vec::new();
        let mut addresses = Vec::new();
        sockets
            .try_reserve_exact(maximum)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        addresses
            .try_reserve_exact(maximum)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        Ok(Self {
            sockets,
            addresses,
            socket_policy,
        })
    }
    /// Perform the original socket/bind/listen effect, then retain that exact
    /// descriptor and its kernel-selected address. No allocation follows bind.
    pub(crate) fn bind(&mut self, address: SocketAddr) -> io::Result<()> {
        self.check_capacity()?;
        self.bind_socket(address, self.socket_policy.open_tcp(address)?)
    }

    fn bind_wildcard_v6(&mut self, port: u16) -> io::Result<()> {
        self.check_capacity()?;
        let address = SocketAddr::from((Ipv6Addr::UNSPECIFIED, port));
        match self.socket_policy.open_tcp(address) {
            Ok(socket) => self.bind_socket(address, socket),
            Err(SocketOpenError::Create(error))
                if gnunet_native::network::socket_family_unavailable(&error) =>
            {
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    fn check_capacity(&self) -> io::Result<()> {
        if self.sockets.len() == self.sockets.capacity()
            || self.addresses.len() == self.addresses.capacity()
        {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "prebound listener capacity",
            ));
        }
        Ok(())
    }

    fn bind_socket(&mut self, address: SocketAddr, socket: socket2::Socket) -> io::Result<()> {
        #[cfg(unix)]
        socket.set_reuse_address(true)?;
        #[cfg(windows)]
        {
            use std::os::windows::io::AsSocket;
            gnunet_native::network::set_exclusive_address_use(socket.as_socket())?;
        }
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
            mode: PeerMode::Listening,
            socket_policy: self.socket_policy,
        })
    }
}
/// Actual owned TCP listeners. Original inherited descriptor paths are not
/// rebound; all accepted streams use the shared canonical accept policy.
pub struct Listeners {
    sockets: Vec<TcpListener>,
    addresses: Vec<SocketAddr>,
    mode: PeerMode,
    socket_policy: SocketPolicy,
}
impl Listeners {
    /// Explicitly own no listening sockets. This constructor performs no bind,
    /// listen, inherited-descriptor adoption or address publication.
    #[must_use]
    pub fn outbound_only() -> Self {
        Self::outbound_only_with_socket_policy(SocketPolicy::default())
    }
    /// Own no ingress while retaining the original outbound socket policy.
    #[must_use]
    pub fn outbound_only_with_socket_policy(socket_policy: SocketPolicy) -> Self {
        Self {
            sockets: Vec::new(),
            addresses: Vec::new(),
            mode: PeerMode::OutboundOnly,
            socket_policy,
        }
    }
    /// Original sealed native ingress choice, retained through peer replacement.
    #[must_use]
    pub const fn mode(&self) -> PeerMode {
        self.mode
    }
    pub(crate) fn socket_policy(&self) -> &SocketPolicy {
        &self.socket_policy
    }
    /// Bind official numeric/bare-port options or adopt actual inherited TCP
    /// listeners. Each newly created socket uses source backlog5 and v6-only mode.
    pub fn bind(settings: &Settings, activation: Activation) -> io::Result<Self> {
        Self::prepare(settings, activation)?.finish()
    }
    /// Prepare each new original socket before its first bind/listen.
    pub fn bind_with_socket_policy(
        settings: &Settings,
        activation: Activation,
        socket_policy: SocketPolicy,
    ) -> io::Result<Self> {
        Self::prepare_with_socket_policy(settings, activation, socket_policy)?.finish()
    }
    /// Bind/adopt the original TCP descriptors before a configured process
    /// identity change. New sockets retain the existing backlog/v6-only policy.
    pub fn prepare(settings: &Settings, activation: Activation) -> io::Result<PreparedListeners> {
        Self::prepare_with_socket_policy(settings, activation, SocketPolicy::default())
    }
    /// Prepare ingress only for listening settings. Protected admission rejects
    /// activated listeners because their bind/listen is past.
    pub fn prepare_with_socket_policy(
        settings: &Settings,
        activation: Activation,
        socket_policy: SocketPolicy,
    ) -> io::Result<PreparedListeners> {
        let binding = settings.binding().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "outbound-only TCP cannot prepare listeners",
            )
        })?;
        if !activation.is_empty() {
            if socket_policy.is_protected() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "protected TCP listeners must be prepared before their original bind/listen",
                ));
            }
            let mut prepared =
                PreparedListeners::reserve_with_socket_policy(activation.len(), socket_policy)?;
            for original in activation.into_sockets() {
                match original {
                    ActivatedSocket::Tcp(listener) => {
                        let address = listener.local_addr()?;
                        if settings.disable_v6() && address.is_ipv6() {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "IPv6 TCP activation conflicts with DISABLE_V6",
                            ));
                        }
                        prepared.addresses.push(address);
                        prepared.sockets.push(listener);
                    }
                    ActivatedSocket::Unix(_) => {
                        return Err(io::Error::other(
                            "TCP communicator inherited a non-TCP listener",
                        ));
                    }
                }
            }
            for listener in &prepared.sockets {
                listener.set_nonblocking(true)?;
            }
            return Ok(prepared);
        }

        match binding {
            Binding::Numeric(address) => {
                let mut prepared = PreparedListeners::reserve_with_socket_policy(1, socket_policy)?;
                prepared.bind(*address)?;
                Ok(prepared)
            }
            Binding::Wildcard(port) => {
                let with_v6 = !settings.disable_v6();
                let mut prepared = PreparedListeners::reserve_with_socket_policy(
                    1 + usize::from(with_v6),
                    socket_policy,
                )?;
                prepared.bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, *port)))?;
                if with_v6 {
                    prepared.bind_wildcard_v6(*port)?;
                }
                Ok(prepared)
            }
            Binding::Hostname(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hostname BINDTO needs the original shared Resolver prebinding owner",
            )),
        }
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
