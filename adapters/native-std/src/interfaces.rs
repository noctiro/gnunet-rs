//! Actual owned getifaddrs snapshot with finite metadata/address limits.
//! No libgnunet, shell command, DNS, route mutation or background monitor.
use std::{
    ffi::CStr,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    ptr,
};
/// Explicit snapshot limits; exceeding a limit fails the whole snapshot instead
/// of silently turning an incomplete scan into address removals.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum native linked-list nodes examined, including non-IP entries.
    pub nodes: usize,
    /// Maximum retained IP address rows.
    pub addresses: usize,
    /// Maximum bytes in one native interface name.
    pub name_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            nodes: 4096,
            addresses: 1024,
            name_bytes: 256,
        }
    }
}
/// Actual kernel-provided interface address. Scope/flow/netmask are retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceAddress {
    /// Bounded original native interface name, without NUL.
    pub name: Vec<u8>,
    /// Actual native interface index, or0 if unavailable.
    pub index: u32,
    /// Actual original interface flag bits.
    pub flags: u32,
    /// Actual interface Internet address.
    pub address: SocketAddr,
    /// Actual netmask when supplied by getifaddrs.
    pub netmask: Option<IpAddr>,
}
impl InterfaceAddress {
    /// Actual IFF_UP flag. No routability or remote connectivity is inferred.
    pub fn is_up(&self) -> bool {
        self.flags & (libc::IFF_UP as u32) != 0
    }
    /// Actual loopback interface flag.
    pub fn is_loopback(&self) -> bool {
        self.flags & (libc::IFF_LOOPBACK as u32) != 0
    }
}
/// Classify an Internet destination against a complete caller-owned interface
/// snapshot, using official NT values: loopback1, local-prefix2, otherwise WAN3.
/// This does not enumerate interfaces, read a clock, authenticate a peer, infer
/// wireless hardware or certify reachability. A caller whose snapshot failed
/// must report that failure instead of supplying an invented empty snapshot.
pub fn classify(rows: &[InterfaceAddress], remote: SocketAddr) -> u32 {
    if remote.ip().is_loopback() {
        return 1;
    }
    let local = rows.iter().any(|row| {
        if row.address.ip().is_loopback() {
            return false;
        }
        match (remote.ip(), row.address.ip(), row.netmask) {
            (IpAddr::V4(remote), IpAddr::V4(local), Some(IpAddr::V4(mask))) => remote
                .octets()
                .into_iter()
                .zip(local.octets())
                .zip(mask.octets())
                .all(|((r, l), m)| r & m == l & m),
            (IpAddr::V6(remote), IpAddr::V6(local), Some(IpAddr::V6(mask))) => remote
                .octets()
                .into_iter()
                .zip(local.octets())
                .zip(mask.octets())
                .all(|((r, l), m)| r & m == l & m),
            _ => false,
        }
    });
    if local { 2 } else { 3 }
}
struct List(*mut libc::ifaddrs);
impl Drop for List {
    #[expect(
        unsafe_code,
        reason = "freeifaddrs releases exactly the successful getifaddrs list owned by this RAII object"
    )]
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: successful getifaddrs ownership is transferred exactly once; no view outlives this owner.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
}
fn capacity() -> io::Error {
    io::Error::new(
        io::ErrorKind::OutOfMemory,
        "interface snapshot limit/allocation exceeded",
    )
}
#[expect(
    unsafe_code,
    reason = "copy native IP sockaddr fields from one live getifaddrs list; validate family before native cast"
)]
fn address(raw: *const libc::sockaddr) -> Option<SocketAddr> {
    if raw.is_null() {
        return None;
    }
    // SAFETY: getifaddrs supplies a valid sockaddr for its indicated family;
    // each family branch copies only the corresponding complete native struct.
    let family = unsafe { (*raw).sa_family } as i32;
    match family {
        libc::AF_INET => {
            // SAFETY: this live getifaddrs address has the IPv4 family; copy
            // its complete native struct without assuming alignment.
            let a = unsafe { ptr::read_unaligned(raw.cast::<libc::sockaddr_in>()) };
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes())),
                u16::from_be(a.sin_port),
            ))
        }
        libc::AF_INET6 => {
            // SAFETY: this live getifaddrs address has the IPv6 family; copy
            // its complete native struct without assuming alignment.
            let a = unsafe { ptr::read_unaligned(raw.cast::<libc::sockaddr_in6>()) };
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(a.sin6_addr.s6_addr),
                u16::from_be(a.sin6_port),
                a.sin6_flowinfo,
                a.sin6_scope_id,
            )))
        }
        _ => None,
    }
}
/// Obtain one real complete owned snapshot. Native errors/unsupported metadata
/// are returned as actual IO failures; no cached or fabricated interface exists.
#[expect(
    unsafe_code,
    reason = "bounded traversal/copy of a successful native getifaddrs allocation held by one RAII owner"
)]
pub fn snapshot(limits: Limits) -> io::Result<Vec<InterfaceAddress>> {
    if limits.nodes == 0
        || limits.addresses == 0
        || limits.name_bytes == 0
        || limits.name_bytes > 65535
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid interface limits",
        ));
    }
    let mut head = ptr::null_mut();
    // SAFETY: head is an initialized writable pointer slot for getifaddrs.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let owner = List(head);
    let mut rows = Vec::new();
    let mut at = owner.0;
    let mut nodes = 0usize;
    while !at.is_null() {
        nodes = nodes.checked_add(1).ok_or_else(capacity)?;
        if nodes > limits.nodes {
            return Err(capacity());
        }
        // SAFETY: at is a node owned by this live native list; pointers are read
        // only while owner is live, and every retained field is copied.
        let node = unsafe { &*at };
        at = node.ifa_next;
        let Some(endpoint) = address(node.ifa_addr) else {
            continue;
        };
        if rows.len() >= limits.addresses {
            return Err(capacity());
        }
        if node.ifa_name.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing interface name",
            ));
        }
        // SAFETY: getifaddrs owns this nonnull, NUL-terminated interface name;
        // the bounded scan stops at that NUL while the original list is live.
        let n = unsafe { libc::strnlen(node.ifa_name, limits.name_bytes + 1) };
        if n > limits.name_bytes {
            return Err(capacity());
        }
        // SAFETY: strnlen found a terminating NUL within the live allocation;
        // if_nametoindex receives this same original native interface string.
        let name = unsafe { CStr::from_ptr(node.ifa_name) }.to_bytes();
        // SAFETY: the same original NUL-terminated native interface name remains
        // live for this synchronous, read-only lookup.
        let index = unsafe { libc::if_nametoindex(node.ifa_name) };
        let mut copied = Vec::new();
        copied
            .try_reserve_exact(name.len())
            .map_err(|_| capacity())?;
        copied.extend_from_slice(name);
        rows.try_reserve(1).map_err(|_| capacity())?;
        let netmask = address(node.ifa_netmask).map(|s| s.ip());
        rows.push(InterfaceAddress {
            name: copied,
            index,
            flags: node.ifa_flags as u32,
            address: endpoint,
            netmask,
        });
    }
    Ok(rows)
}
