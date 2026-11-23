//! One original UDP bind with an explicit native address family.
#[cfg(windows)]
use std::os::windows::io::AsSocket;
use std::{
    io,
    net::{SocketAddr, UdpSocket},
};

#[cfg(test)]
pub(super) fn bind(address: SocketAddr) -> io::Result<UdpSocket> {
    bind_with_socket_policy(address, &Default::default())
}

pub(super) fn bind_with_socket_policy(
    address: SocketAddr,
    socket_policy: &gnunet_service_runtime::network::SocketPolicy,
) -> io::Result<UdpSocket> {
    let socket = socket_policy.open_udp(address)?;
    if address.is_ipv6() {
        // The C communicator's shared bind selects V6ONLY regardless of host
        // defaults. Rust uses one socket for listener and dial as well.
        socket.set_only_v6(true)?;
    }
    #[cfg(windows)]
    gnunet_native::network::set_exclusive_address_use(socket.as_socket())?;
    socket.bind(&address.into())?;
    #[cfg(windows)]
    gnunet_native::network::suppress_udp_connection_resets(socket.as_socket())?;
    Ok(socket.into())
}
