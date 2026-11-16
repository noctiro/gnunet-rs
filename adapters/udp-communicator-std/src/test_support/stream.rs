//! Original loopback TCP pair, created entirely by the entered native reactor.
use std::{
    io,
    net::{Ipv4Addr, SocketAddrV4},
};
use tokio::net::{TcpListener, TcpStream};
pub(crate) async fn pair() -> io::Result<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await?;
    let (peer, original) = tokio::join!(
        TcpStream::connect(listener.local_addr()?),
        listener.accept()
    );
    let peer = peer?;
    let (original, _) = original?;
    original.set_nodelay(true)?;
    peer.set_nodelay(true)?;
    Ok((original, peer))
}
