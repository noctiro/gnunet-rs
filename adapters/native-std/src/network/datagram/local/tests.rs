use super::*;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV6, UdpSocket},
    num::NonZeroU32,
    time::{Duration, Instant},
};

#[cfg(windows)]
type LocalDatagram = LocalDatagramIo<UdpSocket>;

fn listener(bind: IpAddr) -> io::Result<(LocalDatagram, u16)> {
    let address = SocketAddr::new(bind, 0);
    let socket = Socket::new(
        Domain::for_address(address),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.bind(&address.into())?;
    let socket = UdpSocket::from(socket);
    let port = socket.local_addr()?.port();
    Ok((LocalDatagram::new(socket)?, port))
}

fn exchange(bind: IpAddr, destination: IpAddr) -> io::Result<()> {
    let (server, port) = listener(bind)?;
    let (foreign, _) = listener(bind)?;
    let endpoint = SocketAddr::new(destination, port);
    let client = UdpSocket::bind(SocketAddr::new(bind, 0))?;
    client.set_read_timeout(Some(Duration::from_secs(1)))?;
    client.send_to(b"query", endpoint)?;
    let mut buffer = [0; 16];
    let deadline = Instant::now() + Duration::from_secs(1);
    let (bytes, path) = loop {
        match server.receive(&mut buffer) {
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            result => break result?,
        }
    };
    if &buffer[..bytes] != b"query" || path.local != endpoint {
        return Err(io::Error::other(
            "wildcard receive changed the payload or destination",
        ));
    }
    if !matches!(foreign.send(&path, b"wrong"), Err(error) if error.kind() == io::ErrorKind::InvalidInput)
    {
        return Err(io::Error::other(
            "a foreign listener accepted the original reply path",
        ));
    }
    server.send(&path, b"reply")?;
    let (bytes, source) = client.recv_from(&mut buffer)?;
    if source != endpoint || &buffer[..bytes] != b"reply" {
        return Err(io::Error::other("wildcard reply lost its original source"));
    }
    Ok(())
}

#[test]
fn ipv4_wildcard_replies_from_the_address_the_client_used() -> io::Result<()> {
    // Linux provides the entire loopback subnet so this exercises a source
    // different from ordinary IPv4 route selection without configuring an alias.
    #[cfg(target_os = "linux")]
    let destination = Ipv4Addr::new(127, 0, 0, 2);
    #[cfg(not(target_os = "linux"))]
    let destination = Ipv4Addr::LOCALHOST;
    exchange(Ipv4Addr::UNSPECIFIED.into(), destination.into())
}

#[test]
fn ipv6_wildcard_retains_its_local_address() -> io::Result<()> {
    exchange(Ipv6Addr::UNSPECIFIED.into(), Ipv6Addr::LOCALHOST.into())
}

#[test]
fn link_local_endpoints_require_the_original_ingress() -> io::Result<()> {
    let ingress = NonZeroU32::new(7).ok_or(io::ErrorKind::InvalidInput)?;
    let bound = SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 53);
    let ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let peer = SocketAddrV6::new(ip, 4900, 0, ingress.get());
    let (_, local) = return_endpoints(bound, peer.into(), ip.into(), ingress)?;
    if local != SocketAddrV6::new(ip, 53, 0, ingress.get()).into() {
        return Err(io::Error::other("link-local destination lost its zone"));
    }
    let foreign = SocketAddrV6::new(ip, 4900, 0, ingress.get() + 1);
    if return_endpoints(bound, foreign.into(), ip.into(), ingress).is_ok() {
        return Err(io::Error::other("accepted a conflicting IPv6 peer zone"));
    }
    Ok(())
}
