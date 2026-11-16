//! Native route keys, explicit mutations and independent kernel observations.
use super::{
    InterfacePort,
    address::{decode_address, socket_address, validate_prefix},
    check,
};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use windows_sys::Win32::{
    NetworkManagement::{IpHelper::*, Ndis::NET_LUID_LH},
    Networking::WinSock::MIB_IPPROTO_NETMGMT,
};
/// Caller-selected route intent, without live or recovered cleanup authority.
#[derive(Clone, Copy, Debug)]
pub struct Route {
    /// Canonical destination network.
    pub destination: IpAddr,
    /// Address-family prefix length.
    pub prefix: u8,
    /// Same-family gateway; None selects an interface route.
    pub gateway: Option<IpAddr>,
    /// Route metric offset, separate from the interface metric.
    pub metric: u32,
}
impl Route {
    fn validate(self) -> io::Result<()> {
        validate_prefix(self.destination, self.prefix)?;
        if self
            .gateway
            .is_some_and(|gateway| gateway.is_ipv4() != self.destination.is_ipv4())
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let canonical = match self.destination {
            IpAddr::V4(ip) => self.prefix == 32 || u32::from(ip) & (u32::MAX >> self.prefix) == 0,
            IpAddr::V6(ip) => {
                self.prefix == 128 || u128::from(ip) & (u128::MAX >> self.prefix) == 0
            }
        };
        if !canonical {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "noncanonical route destination",
            ));
        }
        Ok(())
    }
}
/// Actual selected route properties. A snapshot grants no delete/restart lease.
#[derive(Clone, Copy, Debug)]
pub struct RouteObservation {
    /// Actual returned destination prefix address.
    pub destination: IpAddr,
    /// Actual returned prefix length.
    pub prefix: u8,
    /// Actual returned output interface index.
    pub interface: u32,
    /// Actual returned next hop; an unspecified next hop means on-link.
    pub gateway: Option<IpAddr>,
    /// The native route targets the local host instead of a forwarding link.
    pub loopback: bool,
    /// Actual route metric offset.
    pub metric: u32,
    /// Actual native route protocol.
    pub protocol: i32,
    /// Actual native route origin.
    pub origin: i32,
    /// Remaining native valid lifetime in seconds.
    pub valid_seconds: u32,
    /// Remaining native preferred lifetime in seconds.
    pub preferred_seconds: u32,
}
impl InterfacePort {
    #[expect(
        unsafe_code,
        reason = "Initialize fills one exact SDK route row before the original qualified LUID and explicit route key are assigned"
    )]
    fn route_key(&self, route: Route) -> io::Result<MIB_IPFORWARD_ROW2> {
        route.validate()?;
        let actual = self.row()?;
        let mut row = MIB_IPFORWARD_ROW2::default();
        // SAFETY: exact initialized SDK row, no retained pointer.
        unsafe { InitializeIpForwardEntry(&mut row) };
        row.InterfaceLuid = NET_LUID_LH { Value: self.luid() };
        row.DestinationPrefix.Prefix = socket_address(route.destination, actual.InterfaceIndex);
        row.DestinationPrefix.PrefixLength = route.prefix;
        let gateway = route.gateway.unwrap_or_else(|| {
            if route.destination.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            }
        });
        row.NextHop = socket_address(gateway, actual.InterfaceIndex);
        row.Metric = route.metric;
        row.Protocol = MIB_IPPROTO_NETMGMT;
        Ok(row)
    }
    /// Create the explicit route on this original interface. Existing routes
    /// remain errors. The caller authorizes/serializes route administration;
    /// this operation does not infer reachability, packet forwarding or ownership
    /// of a later route sharing the same key.
    #[expect(
        unsafe_code,
        reason = "Create borrows one initialized route record containing the explicit intent and original qualified interface LUID"
    )]
    pub fn create_route(&self, route: Route) -> io::Result<()> {
        let row = self.route_key(route)?;
        // SAFETY: original interface and exact explicit native route request.
        check(unsafe { CreateIpForwardEntry2(&row) })
    }
    /// Query the exact route key and original interface without a table dump.
    #[expect(
        unsafe_code,
        reason = "Get fills only the initialized native route record selected by original LUID, destination prefix and next hop"
    )]
    pub fn route(&self, route: Route) -> io::Result<RouteObservation> {
        let mut row = self.route_key(route)?;
        // SAFETY: exact original interface/route selection and writable SDK row.
        check(unsafe { GetIpForwardEntry2(&mut row) })?;
        // SAFETY: the successful SDK call initialized the full native LUID.
        if unsafe { row.InterfaceLuid.Value } != self.luid() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native route LUID changed",
            ));
        }
        let actual = self.row()?;
        if row.InterfaceIndex != actual.InterfaceIndex {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native route output interface changed",
            ));
        }
        let destination = decode_address(&row.DestinationPrefix.Prefix)?;
        let gateway = decode_address(&row.NextHop)?;
        if row.DestinationPrefix.PrefixLength > if destination.is_ipv4() { 32 } else { 128 }
            || gateway.is_ipv4() != destination.is_ipv4()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native route prefix/family",
            ));
        }
        Ok(RouteObservation {
            destination,
            prefix: row.DestinationPrefix.PrefixLength,
            interface: row.InterfaceIndex,
            gateway: if gateway.is_unspecified() {
                None
            } else {
                Some(gateway)
            },
            loopback: row.Loopback,
            metric: row.Metric,
            protocol: row.Protocol,
            origin: row.Origin,
            valid_seconds: row.ValidLifetime,
            preferred_seconds: row.PreferredLifetime,
        })
    }
    /// Delete the explicit original-interface route key. Absence/refusal remains
    /// an error. The caller's live administration owner must authorize deletion;
    /// a Route value or prior query does not supply that authority.
    #[expect(
        unsafe_code,
        reason = "Delete borrows one initialized original-interface route key under caller-controlled administrative exclusion"
    )]
    pub fn delete_route(&self, route: Route) -> io::Result<()> {
        let row = self.route_key(route)?;
        // SAFETY: exact native selection; caller owns this administrative effect.
        check(unsafe { DeleteIpForwardEntry2(&row) })
    }
}

/// Actual exact-key native route lookup; absence retains the native error code
/// after original-interface and IP-family qualification.
#[derive(Clone, Copy, Debug)]
pub enum RouteLookup {
    /// The original native getter returned this record.
    Present(RouteObservation),
    /// Native ERROR_NOT_FOUND with a still-qualified original interface/family.
    Absent {
        /// Original native status, without errno normalization.
        errno: i32,
    },
}
impl InterfacePort {
    /// Query without treating an unavailable interface or family as absence.
    pub fn find_route(&self, route: Route) -> io::Result<RouteLookup> {
        match self.route(route) {
            Ok(row) => Ok(RouteLookup::Present(row)),
            Err(error)
                if error.raw_os_error()
                    == Some(windows_sys::Win32::Foundation::ERROR_NOT_FOUND as i32) =>
            {
                let family = if route.destination.is_ipv4() {
                    super::Family::V4
                } else {
                    super::Family::V6
                };
                self.ip_interface(family)?;
                self.row()?;
                Ok(RouteLookup::Absent {
                    errno: windows_sys::Win32::Foundation::ERROR_NOT_FOUND as i32,
                })
            }
            Err(error) => Err(error),
        }
    }
}

/// Classify selected IP Helper route statuses without discarding the original
/// error. NotFound can denote the interface/family scope; it is not an absence
/// proof. Callers must perform a source-qualified read before reconciliation.
pub fn route_error_kind(error: &io::Error) -> io::ErrorKind {
    use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS};
    match error.raw_os_error().map(|code| code as u32) {
        Some(ERROR_OBJECT_ALREADY_EXISTS) => io::ErrorKind::AlreadyExists,
        Some(ERROR_NOT_FOUND) => io::ErrorKind::NotFound,
        _ => error.kind(),
    }
}
