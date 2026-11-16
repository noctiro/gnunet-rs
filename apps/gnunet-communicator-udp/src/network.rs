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
pub(super) struct Snapshot {
    rows: Vec<InterfaceAddress>,
    advertised: Vec<SocketAddr>,
    discovery: Option<Vec<gnunet_udp_communicator_host::discovery::Interface>>,
}
impl Snapshot {
    fn new(rows: Vec<InterfaceAddress>, bound: &[SocketAddr], discovery: bool) -> io::Result<Self> {
        let mut snapshot = Self {
            rows,
            advertised: Vec::new(),
            discovery: None,
        };
        snapshot.advertised = snapshot.advertised_addresses(bound)?;
        if discovery {
            snapshot.discovery = Some(snapshot.discovery_interfaces(bound)?);
        }
        Ok(snapshot)
    }
    fn classify(&self, address: SocketAddr) -> u32 {
        interfaces::classify(&self.rows, address)
    }
    /// Prepare both consumers before committing either one. The guards retain
    /// the original owners, and their commits perform no fallible work or I/O.
    fn install(
        self,
        addresses: &mut crate::addresses::Addresses<'_, '_>,
        comm: &mut gnunet_udp_communicator_host::communicator::Communicator<'_>,
    ) -> Result<Vec<InterfaceAddress>, crate::Cause> {
        let addresses = addresses
            .prepare_interfaces(&self.advertised, &mut |address| Ok(self.classify(address)))?;
        let discovery = self
            .discovery
            .as_ref()
            .map(|rows| comm.prepare_interfaces(rows))
            .transpose()?;
        addresses.commit();
        if let Some(discovery) = discovery {
            discovery.commit();
        }
        Ok(self.rows)
    }
}

pub(super) struct Scanner {
    rows: Vec<InterfaceAddress>,
    discovery: bool,
    alarm: Pin<Box<Sleep>>,
}
impl Scanner {
    pub fn new(
        bound: &[SocketAddr],
        discovery: bool,
        addresses: &mut crate::addresses::Addresses<'_, '_>,
        comm: &mut gnunet_udp_communicator_host::communicator::Communicator<'_>,
    ) -> Result<Self, crate::Cause> {
        let snapshot = Snapshot::new(interfaces::snapshot(Default::default())?, bound, discovery)?;
        Ok(Self {
            rows: snapshot.install(addresses, comm)?,
            discovery,
            alarm: Box::pin(tokio::time::sleep(Duration::from_secs(300))),
        })
    }
    pub fn install(
        &mut self,
        replacement: Snapshot,
        addresses: &mut crate::addresses::Addresses<'_, '_>,
        comm: &mut gnunet_udp_communicator_host::communicator::Communicator<'_>,
    ) -> Result<(), crate::Cause> {
        self.rows = replacement.install(addresses, comm)?;
        Ok(())
    }
    pub fn classify(&self, address: SocketAddr) -> io::Result<u32> {
        Ok(interfaces::classify(&self.rows, address))
    }
    pub fn poll_refresh(
        &mut self,
        cx: &mut Context<'_>,
        bound: &[SocketAddr],
    ) -> Poll<io::Result<Snapshot>> {
        if self.alarm.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        self.alarm
            .as_mut()
            .reset(Instant::now() + Duration::from_secs(300));
        Poll::Ready(
            interfaces::snapshot(Default::default())
                .and_then(|rows| Snapshot::new(rows, bound, self.discovery)),
        )
    }
}

impl Snapshot {
    fn advertised_addresses(&self, bound: &[SocketAddr]) -> io::Result<Vec<SocketAddr>> {
        let mut addresses = Vec::new();
        addresses.try_reserve_exact(128).map_err(io::Error::other)?;
        for local in bound {
            for row in self
                .rows
                .iter()
                .filter(|row| row.is_usable() && row.address.is_ipv4() == local.is_ipv4())
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
    fn discovery_interfaces(
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
            .filter(|row| row.is_usable() && !row.is_loopback() && row.index != 0)
        {
            let Some(local) = bound.iter().find(|local| {
                local.is_ipv4() == row.address.is_ipv4()
                    && (local.ip().is_unspecified() || local.ip() == row.address.ip())
            }) else {
                continue;
            };
            let broadcast = match (row.address.ip(), row.netmask) {
                (IpAddr::V4(ip), Some(IpAddr::V4(mask))) if row.supports_ipv4_broadcast() => {
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

#[cfg(test)]
mod tests;
