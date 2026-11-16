//! Private loopback IPC peers and an explicit numeric-only Resolver port.
use super::Failure;
use gnunet_client_host::{
    EndpointSource,
    resolution::{AddressLookup, ResolutionContext, ResolutionTimer},
};
use gnunet_service_runtime::{
    clock::{Deadline, RuntimeClock},
    connection::ConnectionLease,
};
use gnunet_wire::official::{MessageHeader, dns as dns_wire};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub(super) struct Ports(pub(super) Arc<dyn RuntimeClock>);
struct Lookup(u8);
struct Lease;
impl ConnectionLease for Lease {}
impl AddressLookup for Lookup {
    fn poll_next(&mut self, _: &mut Context<'_>) -> Poll<io::Result<Option<IpAddr>>> {
        match self.0 {
            0 => {
                self.0 = 1;
                Poll::Ready(Ok(Some(IpAddr::V4(Ipv4Addr::LOCALHOST))))
            }
            1 => Poll::Ready(Err(io::Error::other("numeric callback not returned"))),
            _ => Poll::Ready(Ok(None)),
        }
    }
    fn address_effect_done(&mut self) -> io::Result<()> {
        if self.0 != 1 {
            return Err(io::Error::other("no numeric callback to acknowledge"));
        }
        self.0 = 2;
        Ok(())
    }
    fn connected(self: Box<Self>) -> io::Result<Box<dyn ConnectionLease>> {
        if self.0 != 2 {
            return Err(io::Error::other("original numeric effect not acknowledged"));
        }
        Ok(Box::new(Lease))
    }
}
impl ResolutionContext for Ports {
    fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.0.clone()
    }
    fn lookup(&self, host: &[u8], _: Duration) -> io::Result<Option<Box<dyn AddressLookup>>> {
        if host != b"127.0.0.1" {
            return Err(io::Error::other("fixture accepts only numeric loopback"));
        }
        Ok(Some(Box::new(Lookup(0))))
    }
    fn timer(&self, delay: Duration) -> io::Result<ResolutionTimer> {
        let timer = Deadline::after(self.0.clone(), delay).map_err(io::Error::other)?;
        Ok(Box::pin(
            async move { timer.await.map_err(io::Error::other) },
        ))
    }
}

pub(super) fn source(
    address: SocketAddr,
    service: &'static [u8],
    ports: Arc<Ports>,
) -> Result<EndpointSource, Failure> {
    let mut config = gnunet_config::Configuration::default();
    config.set_value(service, b"HOSTNAME", Some(b"127.0.0.1"))?;
    config.set_value(
        service,
        b"PORT",
        Some(address.port().to_string().as_bytes()),
    )?;
    Ok(EndpointSource::configuration(config, service, ports))
}

pub(super) async fn frame(stream: &mut TcpStream) -> Result<Vec<u8>, Failure> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let size = MessageHeader::decode(&header)?.size();
    if !(4..=2048).contains(&size) {
        return Err("fixture IPC frame bound".into());
    }
    let mut bytes = vec![0; size];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}

pub(super) async fn notify(stream: &mut TcpStream, id: [u8; 8], dns: &[u8]) -> Result<(), Failure> {
    let response = dns_wire::Response { id, dns };
    let mut bytes = vec![0; response.encoded_len()?];
    response.encode(&mut bytes)?;
    stream.write_all(&bytes).await?;
    Ok(())
}
