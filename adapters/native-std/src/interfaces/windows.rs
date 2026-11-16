//! Bounded native unicast-interface facts from one original adapter allocation.
use super::{InterfaceAddress, InterfaceState, Limits};
use crate::network::adapters::{Snapshot, invalid};
use std::{
    io,
    mem::{offset_of, size_of},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_FRIENDLY_NAME,
    GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_UNICAST_ADDRESS_LH,
};
const SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;

fn netmask(address: SocketAddr, prefix: u8) -> io::Result<IpAddr> {
    match address {
        SocketAddr::V4(_) if prefix <= 32 => {
            let bits = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            Ok(Ipv4Addr::from(bits.to_be_bytes()).into())
        }
        SocketAddr::V6(_) if prefix <= 128 => {
            let bits = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            Ok(Ipv6Addr::from(bits.to_be_bytes()).into())
        }
        _ => Err(invalid(
            "native interface prefix exceeds its address family",
        )),
    }
}
#[expect(
    unsafe_code,
    reason = "Each byte is copied only after the original snapshot checks its initialized extent"
)]
fn name(snapshot: &Snapshot, pointer: *const u8, maximum: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for offset in 0..=maximum {
        // SAFETY: u8 is plain and the reader validates the original allocation.
        let byte = unsafe { snapshot.read(pointer.wrapping_add(offset), 1)? };
        if byte == 0 {
            return Ok(bytes);
        }
        if offset == maximum {
            return Err(invalid("native interface name exceeds limit"));
        }
        bytes
            .try_reserve(1)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        bytes.push(byte);
    }
    Err(invalid("unterminated native interface name"))
}
fn consume(remaining: &mut usize) -> io::Result<()> {
    *remaining = remaining
        .checked_sub(1)
        .ok_or_else(|| invalid("native interface traversal limit or cycle"))?;
    Ok(())
}
#[expect(
    unsafe_code,
    reason = "Only plain checked SDK layouts/unions are copied; linked pointers and lengths remain within the owned snapshot"
)]
fn rows(
    snapshot: &Snapshot,
    limits: Limits,
    mut access: impl FnMut(u32) -> io::Result<i32>,
) -> io::Result<Vec<InterfaceAddress>> {
    let mut rows = Vec::new();
    let mut remaining = limits.nodes;
    let mut adapter = snapshot.base().cast::<IP_ADAPTER_ADDRESSES_LH>();
    while !adapter.is_null() {
        consume(&mut remaining)?;
        let length = snapshot.record_length(
            adapter.cast(),
            offset_of!(IP_ADAPTER_ADDRESSES_LH, Ipv6IfIndex) + size_of::<u32>(),
        )?;
        // SAFETY: this plain SDK prefix includes every field inspected below.
        let info = unsafe { snapshot.read(adapter, length)? };
        adapter = info.Next;
        let label = name(snapshot, info.AdapterName, limits.name_bytes)?;
        let mut unicast = info.FirstUnicastAddress;
        while !unicast.is_null() {
            consume(&mut remaining)?;
            let length = snapshot.record_length(
                unicast.cast(),
                offset_of!(IP_ADAPTER_UNICAST_ADDRESS_LH, OnLinkPrefixLength) + size_of::<u8>(),
            )?;
            // SAFETY: complete relevant plain SDK fields are within this snapshot.
            let item = unsafe { snapshot.read(unicast, length)? };
            unicast = item.Next;
            let address = snapshot.address(item.Address, info.Ipv6IfIndex)?;
            // SAFETY: adapter flags/index are initialized scalar union members.
            let index = if address.is_ipv4() {
                // SAFETY: IfIndex is an initialized scalar in the checked SDK prefix.
                unsafe { info.Anonymous1.Anonymous.IfIndex }
            } else {
                info.Ipv6IfIndex
            };
            let state = InterfaceState::Windows {
                access_type: access(index)?,
                // SAFETY: adapter Flags is the initialized scalar union member.
                flags: unsafe { info.Anonymous2.Flags },
                oper_status: info.OperStatus,
                if_type: info.IfType,
                dad_state: item.DadState,
            };
            if rows.len() == limits.addresses {
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "interface address capacity exceeded",
                ));
            }
            rows.try_reserve(1)
                .map_err(|_| io::ErrorKind::OutOfMemory)?;
            let mut copied = Vec::new();
            copied
                .try_reserve_exact(label.len())
                .map_err(|_| io::ErrorKind::OutOfMemory)?;
            copied.extend_from_slice(&label);
            rows.push(InterfaceAddress {
                name: copied,
                index,
                state,
                address,
                netmask: Some(netmask(address, item.OnLinkPrefixLength)?),
            });
        }
    }
    Ok(rows)
}
#[expect(
    unsafe_code,
    reason = "GetIfEntry2 writes one initialized SDK row for the captured interface index"
)]
fn access_type(index: u32) -> io::Result<i32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetIfEntry2, MIB_IF_ROW2};
    if index == 0 {
        return Err(invalid("native interface index is zero"));
    }
    let mut row = MIB_IF_ROW2 {
        InterfaceIndex: index,
        ..Default::default()
    };
    // SAFETY: the complete initialized SDK row is borrowed for this call only.
    let result = unsafe { GetIfEntry2(&mut row) };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    Ok(row.AccessType)
}
/// Snapshot native unicast addresses, preserving adapter state, DAD, full address
/// scopes and prefix masks. No network request or route mutation is issued.
/// The 8 MiB native buffer, list nodes, rows and names are bounded. Any malformed
/// or excessive result fails the entire snapshot rather than implying removals.
pub fn snapshot(limits: Limits) -> io::Result<Vec<InterfaceAddress>> {
    if limits.nodes == 0 || limits.addresses == 0 || limits.name_bytes == 0 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let flags = GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER
        | GAA_FLAG_SKIP_FRIENDLY_NAME;
    match Snapshot::capture(SNAPSHOT_BYTES, flags)? {
        Some(snapshot) => rows(&snapshot, limits, access_type),
        None => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;
    use windows_sys::Win32::{
        NetworkManagement::Ndis::IfOperStatusUp,
        Networking::WinSock::{
            AF_INET6, IpDadStatePreferred, IpDadStateTentative, SOCKADDR_IN6, SOCKET_ADDRESS,
        },
    };

    #[expect(
        unsafe_code,
        reason = "The fixture writes only complete SDK layouts/scalars at checked aligned offsets in its owned initialized allocation"
    )]
    #[test]
    fn scoped_address_prefix_and_dad_survive_without_accepting_cycles() -> io::Result<()> {
        let mut snapshot = Snapshot::new(4096, 4096)?;
        let adapter_offset = 0;
        let unicast_offset = size_of::<IP_ADAPTER_ADDRESSES_LH>().next_multiple_of(16);
        let address_offset =
            (unicast_offset + size_of::<IP_ADAPTER_UNICAST_ADDRESS_LH>()).next_multiple_of(16);
        let name_offset = address_offset + size_of::<SOCKADDR_IN6>();
        let base = snapshot.blocks.as_mut_ptr().cast::<u8>();
        snapshot.contains(base, name_offset + 5)?;
        let ip = "fe80::1234".parse::<Ipv6Addr>().map_err(io::Error::other)?;
        let mut address = SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            ..Default::default()
        };
        address.sin6_addr.u.Byte = ip.octets();
        let unicast = IP_ADAPTER_UNICAST_ADDRESS_LH {
            Address: SOCKET_ADDRESS {
                lpSockaddr: base.wrapping_add(address_offset).cast(),
                iSockaddrLength: size_of::<SOCKADDR_IN6>() as i32,
            },
            DadState: IpDadStatePreferred,
            OnLinkPrefixLength: 64,
            ..Default::default()
        };
        let adapter = IP_ADAPTER_ADDRESSES_LH {
            AdapterName: base.wrapping_add(name_offset),
            FirstUnicastAddress: base.wrapping_add(unicast_offset).cast(),
            OperStatus: IfOperStatusUp,
            Ipv6IfIndex: 7,
            IfType: 6,
            ..Default::default()
        };
        // SAFETY: checked aligned ranges fit these SDK layouts and the five name bytes.
        unsafe {
            ptr::write(base.add(adapter_offset).cast(), adapter);
            ptr::write(
                base.cast::<u32>(),
                size_of::<IP_ADAPTER_ADDRESSES_LH>() as u32,
            );
            ptr::write(base.add(unicast_offset).cast(), unicast);
            ptr::write(
                base.add(unicast_offset).cast::<u32>(),
                size_of::<IP_ADAPTER_UNICAST_ADDRESS_LH>() as u32,
            );
            ptr::write(base.add(address_offset).cast(), address);
            ptr::copy_nonoverlapping(c"test".as_ptr().cast(), base.add(name_offset), 5);
        }
        let limits = Limits {
            nodes: 8,
            addresses: 8,
            name_bytes: 16,
        };
        let captured = rows(&snapshot, limits, |_| {
            Ok(windows_sys::Win32::NetworkManagement::Ndis::NET_IF_ACCESS_BROADCAST)
        })?;
        if captured.len() != 1
            || captured[0].name != b"test"
            || captured[0].index != 7
            || !captured[0].is_usable()
            || captured[0].address != SocketAddr::V6(std::net::SocketAddrV6::new(ip, 0, 0, 7))
            || captured[0].netmask
                != Some(
                    "ffff:ffff:ffff:ffff::"
                        .parse::<IpAddr>()
                        .map_err(io::Error::other)?,
                )
        {
            return Err(io::Error::other("native interface facts changed"));
        }
        // SAFETY: the complete original unicast layout remains in this owned allocation.
        unsafe {
            (*base
                .add(unicast_offset)
                .cast::<IP_ADAPTER_UNICAST_ADDRESS_LH>())
            .DadState = IpDadStateTentative;
        }
        if rows(&snapshot, limits, |_| {
            Ok(windows_sys::Win32::NetworkManagement::Ndis::NET_IF_ACCESS_BROADCAST)
        })?[0]
            .is_usable()
        {
            return Err(io::Error::other("tentative address became usable"));
        }
        // SAFETY: this intentional cycle still points inside the original allocation.
        unsafe {
            (*base
                .add(unicast_offset)
                .cast::<IP_ADAPTER_UNICAST_ADDRESS_LH>())
            .Next = base.add(unicast_offset).cast();
        }
        if rows(&snapshot, limits, |_| {
            Ok(windows_sys::Win32::NetworkManagement::Ndis::NET_IF_ACCESS_BROADCAST)
        })
        .is_ok()
        {
            return Err(io::Error::other("cyclic native list was accepted"));
        }
        Ok(())
    }
}
