//! Owned getifaddrs snapshot; raw pointers never outlive their native owner.
use super::{InterfaceAddress, InterfaceState, Limits};
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
use std::num::NonZeroU32;
use std::{
    ffi::CStr,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    ptr,
};
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

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
#[expect(
    unsafe_code,
    reason = "copy the index from the variable-length native link address owned by getifaddrs"
)]
fn link_index(raw: *const libc::sockaddr) -> Option<NonZeroU32> {
    const OFFSET: usize = std::mem::offset_of!(libc::sockaddr_dl, sdl_index);
    if raw.is_null() {
        return None;
    }
    // SAFETY: a nonnull getifaddrs address has native length and family bytes.
    let (family, length) = unsafe { ((*raw).sa_family, (*raw).sa_len) };
    if i32::from(family) != libc::AF_LINK
        || usize::from(length) < OFFSET + std::mem::size_of::<u16>()
    {
        return None;
    }
    // SAFETY: the AF_LINK length covers exactly this potentially unaligned field.
    let index = unsafe { raw.cast::<u8>().add(OFFSET).cast::<u16>().read_unaligned() };
    NonZeroU32::new(u32::from(index))
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
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    let mut links = Vec::new();
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
        let endpoint = address(node.ifa_addr);
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
        let link = link_index(node.ifa_addr);
        #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd")))]
        let link: Option<u32> = None;
        if endpoint.is_none() && link.is_none() {
            continue;
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
        // the name borrows the live getifaddrs list.
        let name = unsafe { CStr::from_ptr(node.ifa_name) }.to_bytes();
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
        if let Some(index) = link {
            links.try_reserve(1).map_err(|_| capacity())?;
            links.push((name, index));
            continue;
        }
        let Some(endpoint) = endpoint else { continue };
        if rows.len() >= limits.addresses {
            return Err(capacity());
        }
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
        let index = 0;
        #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd")))]
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
            state: InterfaceState::UnixFlags(node.ifa_flags as u32),
            address: endpoint,
            netmask,
        });
    }
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    attach_link_indices(&mut rows, links);
    Ok(rows)
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
fn attach_link_indices(rows: &mut [InterfaceAddress], mut links: Vec<(&[u8], NonZeroU32)>) {
    links.sort_unstable();
    links.dedup();
    for row in rows {
        let name = row.name.as_slice();
        let start = links.partition_point(|&(candidate, _)| candidate < name);
        if let Some(&(candidate, index)) = links.get(start)
            && candidate == name
            && links.get(start + 1).is_none_or(|&(next, _)| next != name)
        {
            row.index = index.get();
        }
    }
}

#[cfg(all(
    test,
    any(target_os = "macos", target_os = "ios", target_os = "freebsd")
))]
mod tests {
    use super::*;

    #[test]
    fn addresses_take_only_unique_indices_from_the_original_snapshot() -> io::Result<()> {
        let observed = NonZeroU32::new(7).ok_or_else(|| io::Error::other("test index"))?;
        let conflicting = NonZeroU32::new(8).ok_or_else(|| io::Error::other("test index"))?;
        let mut rows =
            [b"unique".as_slice(), b"ambiguous", b"missing"].map(|name| InterfaceAddress {
                name: name.to_vec(),
                index: 0,
                state: InterfaceState::UnixFlags(0),
                address: SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
                netmask: None,
            });
        attach_link_indices(
            &mut rows,
            vec![
                (b"unique", observed),
                (b"ambiguous", conflicting),
                (b"unique", observed),
                (b"ambiguous", observed),
            ],
        );
        if rows.map(|row| row.index) != [observed.get(), 0, 0] {
            return Err(io::Error::other("invalid original snapshot index binding"));
        }
        Ok(())
    }
}
