//! Bounded Windows DNS-server snapshots from the native adapter configuration.
use crate::network::adapters::{Snapshot, invalid};
use std::{
    io,
    mem::{offset_of, size_of},
    net::SocketAddr,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_FRIENDLY_NAME, GAA_FLAG_SKIP_MULTICAST,
    GAA_FLAG_SKIP_UNICAST, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_DNS_SERVER_ADDRESS_XP,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
mod suffix;
pub use suffix::{SearchDomain, Source as DomainSource};

const FLAGS: u32 = GAA_FLAG_SKIP_UNICAST
    | GAA_FLAG_SKIP_ANYCAST
    | GAA_FLAG_SKIP_MULTICAST
    | GAA_FLAG_SKIP_FRIENDLY_NAME;

/// Bounds for one synchronous native snapshot, not a background discovery task.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum initialized native output storage, including alignment rounding.
    pub snapshot_bytes: usize,
    /// Maximum distinct IP/port/scope tuples; overflow fails without truncation.
    pub servers: usize,
    /// Maximum UTF-16 units in a native suffix query, including its terminator.
    pub domain_units: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            snapshot_bytes: 4 * 1024 * 1024,
            servers: 256,
            domain_units: 256,
        }
    }
}
impl Snapshot {
    #[expect(
        unsafe_code,
        reason = "Only bounded plain SDK records and scalar address fields are interpreted; linked pointers and declared socket extents are checked against the original allocation"
    )]
    fn servers(&self, maximum: usize) -> io::Result<Vec<SocketAddr>> {
        let mut servers = Vec::new();
        let mut adapter = self.base().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let mut remaining = 8192usize;
        while !adapter.is_null() {
            remaining = remaining.checked_sub(1).ok_or_else(|| {
                invalid("native DNS list exceeds traversal bound or contains a cycle")
            })?;
            let length = self.record_length(
                adapter.cast(),
                offset_of!(IP_ADAPTER_ADDRESSES_LH, Ipv6IfIndex) + size_of::<u32>(),
            )?;
            // SAFETY: SDK adapter fields are plain C integers, pointers and unions;
            // the minimum extent includes every field read below.
            let info = unsafe { self.read(adapter, length)? };
            adapter = info.Next;
            if info.OperStatus != IfOperStatusUp {
                continue;
            }
            let mut server = info.FirstDnsServerAddress;
            while !server.is_null() {
                remaining = remaining.checked_sub(1).ok_or_else(|| {
                    invalid("native DNS list exceeds traversal bound or contains a cycle")
                })?;
                let length = self
                    .record_length(server.cast(), size_of::<IP_ADAPTER_DNS_SERVER_ADDRESS_XP>())?;
                // SAFETY: the complete plain SDK DNS record is in this snapshot.
                let item = unsafe { self.read(server, length)? };
                server = item.Next;
                let mut address = self.address(item.Address, info.Ipv6IfIndex)?;
                if address.port() == 0 {
                    address.set_port(53);
                }
                if servers.contains(&address) {
                    continue;
                }
                if servers.len() == maximum {
                    return Err(io::Error::new(
                        io::ErrorKind::OutOfMemory,
                        "DNS server capacity exceeded",
                    ));
                }
                servers
                    .try_reserve(1)
                    .map_err(|_| io::ErrorKind::OutOfMemory)?;
                servers.push(address);
            }
        }
        Ok(servers)
    }
}
/// Snapshot IPv4/IPv6 DNS servers of operational adapters in native API order,
/// retaining ports and IPv6 interface scopes and deduplicating exact tuples.
/// No DNS query, environment fallback, registry mutation or resolver process is
/// used. A missing configuration yields an empty list. This synchronous call can
/// be expensive; call at startup or explicit configuration refresh, not per query.
/// At most three attempts handle native buffer-size races. Native errors retain
/// their Win32 code; malformed extents, cycles and resource limits fail the whole
/// snapshot. This does not emulate Windows NRPT or per-query DNS routing policy.
pub fn servers(limits: Limits) -> io::Result<Vec<SocketAddr>> {
    if limits.servers == 0 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    match Snapshot::capture(limits.snapshot_bytes, FLAGS)? {
        Some(snapshot) => snapshot.servers(limits.servers),
        None => Ok(Vec::new()),
    }
}

/// Independent projections of one original adapter snapshot and the primary
/// computer DNS domain. A failed optional domain query does not discard servers.
#[derive(Debug)]
pub struct Configuration {
    /// Actual operational-adapter IP/port/scope tuples in native order.
    pub servers: io::Result<Vec<SocketAddr>>,
    /// One GNUnet search domain: primary domain, otherwise the first nonempty
    /// operational-adapter suffix. This does not emulate Windows search lists,
    /// domain devolution, NRPT or per-query interface routing.
    pub domain: io::Result<Option<SearchDomain>>,
}
/// Capture bounded Windows DNS inputs without issuing queries or reading a
/// synthetic resolv.conf. The primary domain and adapter suffix retain their
/// distinct origin. Each projection owns its result and original error.
///
/// # Errors
/// Returns invalid bounds or original adapter-capture errors. Projection errors
/// remain in their corresponding fields, without an empty-success substitution.
pub fn configuration(limits: Limits) -> io::Result<Configuration> {
    if limits.servers == 0 || !(1..=32768).contains(&limits.domain_units) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let snapshot = Snapshot::capture(limits.snapshot_bytes, FLAGS)?;
    let servers = match &snapshot {
        Some(snapshot) => snapshot.servers(limits.servers),
        None => Ok(Vec::new()),
    };
    let domain = suffix::primary(limits.domain_units).and_then(|primary| match primary {
        Some(domain) => Ok(Some(domain)),
        None => match &snapshot {
            Some(snapshot) => snapshot.domain(limits.domain_units),
            None => Ok(None),
        },
    });
    Ok(Configuration { servers, domain })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::{Ipv6Addr, SocketAddrV6},
        ptr,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET6, SOCKADDR_IN6};
    fn offsets() -> (usize, usize) {
        let dns = size_of::<IP_ADAPTER_ADDRESSES_LH>().next_multiple_of(16);
        (
            dns,
            (dns + size_of::<IP_ADAPTER_DNS_SERVER_ADDRESS_XP>()).next_multiple_of(16),
        )
    }
    #[expect(
        unsafe_code,
        reason = "The fixture writes complete SDK objects and their length headers at checked aligned offsets in its own initialized allocation; pointers remain within that same owned allocation"
    )]
    fn fixture() -> io::Result<Snapshot> {
        let mut snapshot = Snapshot::new(4096, 4096)?;
        let base = snapshot.blocks.as_mut_ptr().cast::<u8>();
        let (dns_offset, address_offset) = offsets();
        snapshot.contains(base, address_offset + size_of::<SOCKADDR_IN6>())?;
        let adapter = IP_ADAPTER_ADDRESSES_LH {
            FirstDnsServerAddress: base.wrapping_add(dns_offset).cast(),
            OperStatus: IfOperStatusUp,
            Ipv6IfIndex: 7,
            ..Default::default()
        };
        let mut server = IP_ADAPTER_DNS_SERVER_ADDRESS_XP::default();
        server.Address.lpSockaddr = base.wrapping_add(address_offset).cast();
        server.Address.iSockaddrLength = size_of::<SOCKADDR_IN6>() as i32;
        let mut address = SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            ..Default::default()
        };
        address.sin6_addr.u.Byte = "fe80::53"
            .parse::<Ipv6Addr>()
            .map_err(io::Error::other)?
            .octets();
        // SAFETY: offsets are aligned and checked against this initialized allocation;
        // all values are complete SDK layouts with no destructor or borrowed storage.
        unsafe {
            ptr::write(base.cast::<IP_ADAPTER_ADDRESSES_LH>(), adapter);
            ptr::write(
                base.cast::<u32>(),
                size_of::<IP_ADAPTER_ADDRESSES_LH>() as u32,
            );
            ptr::write(
                base.add(dns_offset)
                    .cast::<IP_ADAPTER_DNS_SERVER_ADDRESS_XP>(),
                server,
            );
            ptr::write(
                base.add(dns_offset).cast::<u32>(),
                size_of::<IP_ADAPTER_DNS_SERVER_ADDRESS_XP>() as u32,
            );
            ptr::write(base.add(address_offset).cast::<SOCKADDR_IN6>(), address);
        }
        Ok(snapshot)
    }
    #[test]
    fn scoped_ipv6_server_retains_the_actual_adapter_index_and_default_port() -> io::Result<()> {
        let snapshot = fixture()?;
        let expected = SocketAddr::V6(SocketAddrV6::new(
            "fe80::53".parse().map_err(io::Error::other)?,
            53,
            0,
            7,
        ));
        if snapshot.servers(1)? != [expected] {
            return Err(invalid("native IPv6 scope/port was lost"));
        }
        Ok(())
    }
    #[test]
    #[expect(
        unsafe_code,
        reason = "The fixture updates complete SDK fields and terminated UTF-16 inside its checked original aligned allocation"
    )]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions compare independent server and suffix projections of the same original snapshot"
    )]
    fn adapter_suffix_keeps_its_native_index_and_cannot_discard_valid_servers() -> io::Result<()> {
        let mut snapshot = fixture()?;
        let base = snapshot.blocks.as_mut_ptr().cast::<u8>();
        let (_, address) = offsets();
        let text = address + size_of::<SOCKADDR_IN6>();
        let suffix = [0x4f8b_u16, 46, 120, 0];
        snapshot.contains(base.wrapping_add(text), size_of_val(&suffix))?;
        // SAFETY: the complete adapter already exists in this aligned snapshot;
        // the checked string range is disjoint and retains a terminating NUL.
        unsafe {
            ptr::copy_nonoverlapping(
                suffix.as_ptr().cast::<u8>(),
                base.add(text),
                size_of_val(&suffix),
            );
            (*base.cast::<IP_ADAPTER_ADDRESSES_LH>()).DnsSuffix = base.add(text).cast();
        }
        let domain = snapshot
            .domain(256)?
            .ok_or_else(|| invalid("native fixture suffix missing"))?;
        assert_eq!(domain.name, "例.x");
        assert_eq!(
            domain.source,
            DomainSource::Interface {
                ipv4_index: 0,
                ipv6_index: 7
            }
        );
        // SAFETY: changing this initialized pointer field does not dereference
        // the one-past address; the projection must reject it before reading.
        unsafe {
            (*base.cast::<IP_ADAPTER_ADDRESSES_LH>()).DnsSuffix = base.add(snapshot.used).cast();
        }
        assert!(snapshot.domain(256).is_err());
        assert_eq!(snapshot.servers(1)?.len(), 1);
        Ok(())
    }
    #[test]
    #[expect(
        unsafe_code,
        reason = "Only a native pointer field within the fixture's checked initialized SDK DNS record is changed; the parser must reject it before dereferencing"
    )]
    fn escaped_native_pointer_is_rejected() -> io::Result<()> {
        let mut snapshot = fixture()?;
        let base = snapshot.blocks.as_mut_ptr().cast::<u8>();
        let (dns_offset, _) = offsets();
        // SAFETY: fixture owns a complete aligned DNS record at dns_offset.
        unsafe {
            (*base
                .add(dns_offset)
                .cast::<IP_ADAPTER_DNS_SERVER_ADDRESS_XP>())
            .Address
            .lpSockaddr = base.wrapping_add(snapshot.used + 16).cast();
        }
        if snapshot.servers(1).is_ok() {
            return Err(invalid("escaped DNS pointer was accepted"));
        }
        Ok(())
    }
    #[test]
    #[expect(
        unsafe_code,
        reason = "The fixture changes only its original aligned DNS record's Next field to an in-allocation cycle, exercising the finite traversal bound"
    )]
    fn cyclic_native_list_is_rejected_without_returning_a_partial_snapshot() -> io::Result<()> {
        let mut snapshot = fixture()?;
        let (dns_offset, _) = offsets();
        let server = snapshot
            .blocks
            .as_mut_ptr()
            .cast::<u8>()
            .wrapping_add(dns_offset)
            .cast::<IP_ADAPTER_DNS_SERVER_ADDRESS_XP>();
        // SAFETY: this complete original SDK record remains in the fixture's allocation.
        unsafe {
            (*server).Next = server;
        }
        if snapshot.servers(1).is_ok() {
            return Err(invalid("cyclic DNS list was accepted"));
        }
        Ok(())
    }
}
