//! Actual interface snapshots feed the communicator's numeric classification port.
use gnunet_native::interfaces::{self, InterfaceAddress};
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
pub(super) struct Scanner {
    rows: Vec<InterfaceAddress>,
    valid: bool,
    alarm: Pin<Box<Sleep>>,
}
impl Scanner {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            rows: interfaces::snapshot(Default::default())?,
            valid: true,
            alarm: Box::pin(tokio::time::sleep(Duration::from_secs(300))),
        })
    }
    pub fn classify(&self, address: SocketAddr) -> io::Result<u32> {
        if address.ip().is_loopback() {
            return Ok(1);
        }
        if !self.valid {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "original interface snapshot unavailable",
            ));
        }
        Ok(interfaces::classify(&self.rows, address))
    }
    pub fn poll_refresh(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.alarm.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        self.alarm
            .as_mut()
            .reset(Instant::now() + Duration::from_secs(300));
        match interfaces::snapshot(Default::default()) {
            Ok(rows) => {
                self.rows = rows;
                self.valid = true;
                Poll::Ready(Ok(()))
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl Scanner {
    pub fn advertised(&self, bound: &[SocketAddr]) -> io::Result<Vec<SocketAddr>> {
        let mut addresses = Vec::new();
        addresses.try_reserve_exact(128).map_err(io::Error::other)?;
        for local in bound {
            for row in self
                .rows
                .iter()
                .filter(|row| row.is_up() && row.address.is_ipv4() == local.is_ipv4())
            {
                if !local.ip().is_unspecified() && row.address.ip() != local.ip() {
                    continue;
                }
                let mut address = row.address;
                address.set_port(local.port());
                if !addresses.contains(&address) {
                    if addresses.len() == 128 {
                        return Err(io::Error::other("UDP interface address capacity"));
                    }
                    addresses.push(address);
                }
            }
        }
        Ok(addresses)
    }
    pub fn discovery(
        &self,
        bound: &[SocketAddr],
    ) -> io::Result<Vec<gnunet_udp_communicator_host::discovery::Interface>> {
        use gnunet_udp_communicator_host::discovery::Interface;
        use std::net::{IpAddr, Ipv4Addr};
        let mut interfaces = Vec::new();
        interfaces.try_reserve_exact(64).map_err(io::Error::other)?;
        for row in self
            .rows
            .iter()
            .filter(|row| row.is_up() && !row.is_loopback() && row.index != 0)
        {
            let Some(local) = bound.iter().find(|local| {
                local.is_ipv4() == row.address.is_ipv4()
                    && (local.ip().is_unspecified() || local.ip() == row.address.ip())
            }) else {
                continue;
            };
            let broadcast = match (row.address.ip(), row.netmask) {
                (IpAddr::V4(ip), Some(IpAddr::V4(mask)))
                    if row.flags & (nix::libc::IFF_BROADCAST as u32) != 0 =>
                {
                    Some(Ipv4Addr::from(u32::from(ip) | !u32::from(mask)))
                }
                (IpAddr::V4(_), _) => continue,
                (IpAddr::V6(_), _) => None,
            };
            if row.address.ip().is_unspecified() || row.address.ip().is_multicast() {
                continue;
            }
            let mut source = row.address;
            source.set_port(local.port());
            let row = Interface {
                source,
                index: row.index,
                broadcast,
            };
            if !interfaces.contains(&row) {
                if interfaces.len() == 64 {
                    return Err(io::Error::other("UDP discovery interface capacity"));
                }
                interfaces.push(row);
            }
        }
        Ok(interfaces)
    }
}
