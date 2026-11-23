//! Native Netlink endpoints; Linux and FreeBSD have different sockaddr headers.
use super::super::invalid;
use std::{
    io,
    os::fd::{AsRawFd, OwnedFd},
};
#[cfg(target_os = "linux")]
type Address = libc::sockaddr_nl;
#[cfg(target_os = "linux")]
const FAMILY: libc::c_int = libc::AF_NETLINK;
// FreeBSD's public netlink ABI is not yet exposed by the libc crate.
#[cfg(target_os = "freebsd")]
const FAMILY: libc::c_int = 38;
#[cfg(target_os = "freebsd")]
#[repr(C)]
struct Address {
    len: u8,
    nl_family: libc::sa_family_t,
    pad: u16,
    nl_pid: u32,
    nl_groups: u32,
}

fn address() -> Address {
    #[expect(
        unsafe_code,
        reason = "Native Netlink addresses contain scalar fields/padding; zero is valid before native length/family initialization"
    )]
    // SAFETY: zero is valid for every native Netlink address field and its padding.
    let mut address: Address = unsafe { std::mem::zeroed() };
    address.nl_family = FAMILY as libc::sa_family_t;
    #[cfg(target_os = "freebsd")]
    {
        address.len = std::mem::size_of::<Address>() as u8;
    }
    address
}

pub(in crate::routes) fn open() -> io::Result<(OwnedFd, u32)> {
    let socket = socket2::Socket::new(
        socket2::Domain::from(FAMILY),
        socket2::Type::RAW,
        Some(socket2::Protocol::from(0)),
    )?;
    socket.set_recv_buffer_size(16_384)?;
    socket.set_send_buffer_size(4_096)?;
    let fd: OwnedFd = socket.into();
    let mut local = address();
    #[expect(
        unsafe_code,
        reason = "bind receives one exact initialized native Netlink address and its native size; no pointer escapes"
    )]
    // SAFETY: the initialized address remains live for the synchronous call.
    let result = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&local as *const Address).cast(),
            std::mem::size_of::<Address>() as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    // FreeBSD connects Netlink sockets to the kernel during socket attachment.
    // Linux requires an explicit kernel peer before the shared write path.
    #[cfg(target_os = "linux")]
    {
        let kernel = address();
        #[expect(
            unsafe_code,
            reason = "connect receives an exact initialized kernel Netlink address and its native size; no pointer escapes"
        )]
        // SAFETY: the initialized kernel address remains live for this call.
        let result = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                (&kernel as *const Address).cast(),
                std::mem::size_of::<Address>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let mut size = std::mem::size_of::<Address>() as libc::socklen_t;
    #[expect(
        unsafe_code,
        reason = "getsockname writes a local initialized sockaddr_nl with the exact provided capacity"
    )]
    // SAFETY: local storage and length pointer remain exclusive/live for this call.
    let result = unsafe {
        libc::getsockname(
            fd.as_raw_fd(),
            (&mut local as *mut Address).cast(),
            &mut size,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if size as usize != std::mem::size_of::<Address>()
        || local.nl_family != FAMILY as libc::sa_family_t
        || local.nl_pid == 0
    {
        return Err(invalid());
    }
    #[cfg(target_os = "freebsd")]
    if local.len as usize != std::mem::size_of::<Address>() {
        return Err(invalid());
    }
    crate::platform::nonblocking(&fd)?;
    Ok((fd, local.nl_pid))
}

/// recvmsg supplies the original sender separately from the echoed message pid.
pub(in crate::routes) fn source(
    peer: &libc::sockaddr_storage,
    size: libc::socklen_t,
) -> io::Result<()> {
    if (size as usize) < std::mem::size_of::<Address>()
        || peer.ss_family != FAMILY as libc::sa_family_t
    {
        return Err(invalid());
    }
    #[cfg(target_os = "freebsd")]
    if peer.ss_len as usize != std::mem::size_of::<Address>() {
        return Err(invalid());
    }
    #[expect(
        unsafe_code,
        reason = "The kernel returned a full native Netlink address in aligned initialized sockaddr_storage; read only its initialized scalar sender/group fields"
    )]
    // SAFETY: native family/size were checked and sockaddr_storage provides
    // sufficient alignment; the immutable peer borrow outlives this read.
    let sender = unsafe { &*std::ptr::from_ref(peer).cast::<Address>() };
    if sender.nl_pid != 0 || sender.nl_groups != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "route reply sender is not the unicast kernel",
        ));
    }
    Ok(())
}

#[cfg(all(test, target_os = "freebsd"))]
mod tests {
    use super::super::wire;
    use super::*;
    #[test]
    fn layout_matches_native_headers() -> io::Result<()> {
        let values = [
            std::mem::size_of::<Address>() as u64,
            std::mem::align_of::<Address>() as u64,
            std::mem::offset_of!(Address, nl_family) as u64,
            std::mem::offset_of!(Address, nl_pid) as u64,
            std::mem::offset_of!(Address, nl_groups) as u64,
            FAMILY as u64,
            0,
            16,
            8,
            12,
            8,
            4,
            u64::from(wire::RTM_NEWROUTE),
            u64::from(wire::RTM_DELROUTE),
            u64::from(wire::RTM_GETROUTE),
            u64::from(wire::NLM_F_REQUEST),
            u64::from(wire::NLM_F_MULTI),
            u64::from(wire::NLM_F_ACK),
            u64::from(wire::NLM_F_DUMP_INTR),
            u64::from(wire::NLM_F_DUMP),
            u64::from(wire::NLM_F_EXCL),
            u64::from(wire::NLM_F_CREATE),
            u64::from(wire::NLMSG_NOOP),
            u64::from(wire::NLMSG_ERROR),
            u64::from(wire::NLMSG_DONE),
            u64::from(wire::NLMSG_OVERRUN),
            u64::from(wire::RTPROT_STATIC),
            u64::from(wire::RT_SCOPE_UNIVERSE),
            u64::from(wire::RTN_UNICAST),
            u64::from(wire::RTM_F_CLONED),
            u64::from(wire::RTA_DST),
            u64::from(wire::RTA_OIF),
            u64::from(wire::RTA_GATEWAY),
            u64::from(wire::RTA_PRIORITY),
            u64::from(wire::RTA_PREFSRC),
            u64::from(wire::RTA_METRICS),
            u64::from(wire::RTA_CACHEINFO),
            u64::from(wire::RTA_TABLE),
            u64::from(wire::RTA_KNH_ID),
            u64::from(wire::RTA_WEIGHT),
            u64::from(wire::RTA_RTFLAGS),
            u64::from(wire::RTA_EXPIRES),
            u64::from(wire::RTA_NH_ID),
            0,
            u32::MAX as u64,
        ];
        crate::native_abi::check("freebsd_route_abi.c", &values)
    }
}
