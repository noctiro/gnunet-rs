//! Actual interface acquisition and publication; incomplete native scans never
//! become a successful empty snapshot or synthesize mass address removals.
use crate::{Error, deadline::Gate};
use gnunet_nat::{
    address::SocketAddress,
    state::{Advertised, Core, Provider},
};
use gnunet_wire::official::nat::AddressClass;
use std::net::SocketAddr;
/// Convert an actual host address, preserving IPv6 scope and flow information.
pub fn portable(address: SocketAddr) -> SocketAddress {
    match address {
        SocketAddr::V4(a) => SocketAddress::V4 {
            ip: a.ip().octets(),
            port: a.port(),
        },
        SocketAddr::V6(a) => SocketAddress::V6 {
            ip: a.ip().octets(),
            port: a.port(),
            scope: a.scope_id(),
            flow: a.flowinfo(),
        },
    }
}
/// Convert portable fields to the actual host socket representation.
pub fn native(address: SocketAddress) -> SocketAddr {
    match address {
        SocketAddress::V4 { ip, port } => SocketAddr::new(ip.into(), port),
        SocketAddress::V6 {
            ip,
            port,
            scope,
            flow,
        } => std::net::SocketAddrV6::new(ip.into(), port, flow, scope).into(),
    }
}
/// One real bounded complete scan. No timer/task/socket or route is created.
pub fn snapshot(
    limits: gnunet_native::interfaces::Limits,
    disable_v6: bool,
) -> Result<Vec<Advertised>, Error> {
    let rows = gnunet_native::interfaces::snapshot(limits)?;
    let mut addresses = Vec::new();
    addresses
        .try_reserve_exact(rows.len())
        .map_err(|_| gnunet_types::Error::Capacity)?;
    for row in rows {
        if !row.is_up() {
            continue;
        }
        let address = portable(row.address).with_port(0);
        if address.is_unspecified() || disable_v6 && matches!(address, SocketAddress::V6 { .. }) {
            continue;
        }
        let value = Advertised {
            address,
            class: address.classify(AddressClass::LAN),
        };
        if !addresses.contains(&value) {
            addresses.push(value);
        }
    }
    Ok(addresses)
}
/// Apply a real snapshot only to its original interface-provider generation.
/// The original job gate is checked both before/after native enumeration.
pub fn scan(
    core: &mut Core,
    provider: Provider,
    gate: &Gate,
    limits: gnunet_native::interfaces::Limits,
    disable_v6: bool,
) -> Result<Vec<Advertised>, Error> {
    gate.check()?;
    let addresses = snapshot(limits, disable_v6)?;
    let now = gate.check()?;
    core.publish_snapshot(provider, &addresses, None, now)?;
    Ok(addresses)
}
