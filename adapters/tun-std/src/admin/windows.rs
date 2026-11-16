//! Actual original-interface Windows getters, without synthetic Unix flags.
use super::*;
use gnunet_native::wintun::{Family, Ipv4Addresses};
impl OwnedTun {
    pub(crate) fn admin_source(&self, until: Instant) -> Result<(), AdminFailure> {
        if !self.epoch.current() {
            return Err(AdminFailure::SourceRetired);
        }
        if Instant::now() >= until {
            return Err(AdminFailure::Deadline);
        }
        self.session().adapter().port().interface()?;
        Ok(())
    }
    /// Observe original link state and only the requested IP-family rows. Family
    /// MTUs remain independent; requested-family errors are never hidden. A fresh
    /// owner selects an address only when exactly one row exists; after creation
    /// it queries its own original primary row. Multiple rows remain ambiguous.
    /// Getters form a time-local group, not an atomic restoration image.
    pub fn snapshot(
        &self,
        until: Instant,
        options: SnapshotOptions,
    ) -> Result<NativeSnapshot, AdminFailure> {
        self.admin_source(until)?;
        let started_at = Instant::now();
        let port = self.session().adapter().port();
        let interface = port.interface()?;
        let ipv4_mtu = options
            .ipv4
            .then(|| port.ip_interface(Family::V4))
            .transpose()?
            .map(|row| row.mtu);
        self.admin_source(until)?;
        let ipv6_mtu = options
            .ipv6
            .then(|| port.ip_interface(Family::V6))
            .transpose()?
            .map(|row| row.mtu);
        self.admin_source(until)?;
        let (address, netmask) = if options.ipv4 {
            let rows = if let Some(address) = self.ipv4 {
                port.find_address(address.into())?
                    .map_or(Ipv4Addresses::Unassigned, Ipv4Addresses::Single)
            } else {
                port.ipv4_addresses()?
            };
            match rows {
                Ipv4Addresses::Unassigned => {
                    (Ipv4Observation::Unassigned, Ipv4Observation::Unassigned)
                }
                Ipv4Addresses::Multiple { count } => (
                    Ipv4Observation::Ambiguous { count },
                    Ipv4Observation::Ambiguous { count },
                ),
                Ipv4Addresses::Single(row) => {
                    let std::net::IpAddr::V4(address) = row.address else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "IPv6 row in native IPv4 selection",
                        )
                        .into());
                    };
                    let shift = 32u32.checked_sub(u32::from(row.prefix)).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "native IPv4 prefix overflow")
                    })?;
                    let mask = u32::MAX.checked_shl(shift).unwrap_or(0);
                    (
                        Ipv4Observation::Present(address),
                        Ipv4Observation::Present(Ipv4Addr::from(mask)),
                    )
                }
            }
        } else {
            (Ipv4Observation::NotRequested, Ipv4Observation::NotRequested)
        };
        self.admin_source(until)?;
        let observed_at = Instant::now();
        if observed_at >= until {
            return Err(AdminFailure::Deadline);
        }
        Ok(NativeSnapshot {
            epoch: self.epoch(),
            interface: self.info.clone(),
            deadline: until,
            started_at,
            observed_at,
            options,
            link_mtu: interface.mtu,
            ipv4_mtu,
            ipv6_mtu,
            flags: None,
            up: interface.administratively_up(),
            windows_status: Some((interface.admin_status, interface.operational_status)),
            address,
            netmask,
            close_error: None,
        })
    }
}
