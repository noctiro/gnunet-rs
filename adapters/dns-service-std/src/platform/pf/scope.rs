//! Frozen native address scope used by startup state retirement and monitoring.
use gnunet_native::interfaces::InterfaceAddress;
use std::{
    io,
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
};

pub(in crate::platform) struct Scope(Vec<Address>);

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct Address {
    index: NonZeroU32,
    name: Vec<u8>,
    address: SocketAddr,
}

impl Scope {
    pub fn new(rows: Vec<InterfaceAddress>) -> io::Result<Self> {
        let mut addresses = Vec::new();
        addresses
            .try_reserve_exact(rows.len())
            .map_err(io::Error::other)?;
        for row in rows {
            addresses.push(Address {
                index: NonZeroU32::new(row.index).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotConnected,
                        "PF address has no original native interface index",
                    )
                })?,
                name: row.name,
                address: row.address,
            });
        }
        addresses.sort_unstable();
        addresses.dedup();
        if addresses
            .windows(2)
            .any(|rows| rows[0].index == rows[1].index && rows[0].name != rows[1].name)
        {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "PF native interface index has conflicting names",
            ));
        }
        Ok(Self(addresses))
    }

    pub fn contains_interface(&self, index: NonZeroU32) -> bool {
        self.0
            .binary_search_by_key(&index, |address| address.index)
            .is_ok()
    }

    pub fn names(&self) -> impl Iterator<Item = &[u8]> {
        self.0
            .chunk_by(|left, right| left.index == right.index)
            .map(|addresses| addresses[0].name.as_slice())
    }

    pub fn ip_addresses(&self) -> io::Result<Vec<IpAddr>> {
        let mut ips = Vec::new();
        ips.try_reserve_exact(self.0.len())
            .map_err(io::Error::other)?;
        ips.extend(self.0.iter().map(|row| row.address.ip()));
        ips.sort_unstable();
        ips.dedup();
        Ok(ips)
    }

    pub fn require_same(&self, current: &Self) -> io::Result<()> {
        if self.0 != current.0 {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "PF original native address scope changed; startup state retirement must be repeated",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
