//! Private loopback socket pairs for platform-independent framing witnesses.
use gnunet_service_runtime::connection::Connection;
use std::{
    io,
    net::{Ipv4Addr, SocketAddrV4},
};
use tokio::net::{TcpListener, TcpStream};
pub(crate) async fn pair() -> io::Result<(Connection, TcpStream)> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await?;
    let peer = TcpStream::connect(listener.local_addr()?).await?;
    let (original, _) = listener.accept().await?;
    original.set_nodelay(true)?;
    peer.set_nodelay(true)?;
    Ok((Connection::from_tcp(original), peer))
}
