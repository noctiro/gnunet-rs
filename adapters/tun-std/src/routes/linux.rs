//! Linux rtnetlink interface routes; no policy tables or gateway negotiation.
use super::*;
pub(super) fn netlink() -> io::Result<(OwnedFd, u32)> {
    let socket = socket2::Socket::new(
        socket2::Domain::from(libc::AF_NETLINK),
        socket2::Type::RAW,
        Some(socket2::Protocol::from(libc::NETLINK_ROUTE)),
    )?;
    socket.set_recv_buffer_size(16_384)?;
    socket.set_send_buffer_size(4_096)?;
    let fd: OwnedFd = socket.into();
    #[expect(
        unsafe_code,
        reason = "Linux sockaddr_nl contains scalar fields/padding; all-zero is the documented kernel/autobind address"
    )]
    // SAFETY: zero is valid for every sockaddr_nl field and its private padding.
    let (mut local, kernel): (libc::sockaddr_nl, libc::sockaddr_nl) = unsafe { std::mem::zeroed() };
    local.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let mut kernel = kernel;
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    #[expect(
        unsafe_code,
        reason = "bind/connect receive exact initialized Linux sockaddr_nl objects and their actual libc sizes; no pointer escapes"
    )]
    // SAFETY: both addresses are initialized and remain live for their synchronous calls.
    let result = unsafe {
        let n = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        let bound = libc::bind(
            fd.as_raw_fd(),
            (&local as *const libc::sockaddr_nl).cast(),
            n,
        );
        if bound < 0 {
            bound
        } else {
            libc::connect(
                fd.as_raw_fd(),
                (&kernel as *const libc::sockaddr_nl).cast(),
                n,
            )
        }
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut size = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    #[expect(
        unsafe_code,
        reason = "getsockname writes a local initialized sockaddr_nl with the exact provided capacity"
    )]
    // SAFETY: local storage and length pointer remain exclusive/live for this call.
    let result = unsafe {
        libc::getsockname(
            fd.as_raw_fd(),
            (&mut local as *mut libc::sockaddr_nl).cast(),
            &mut size,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if size as usize != std::mem::size_of::<libc::sockaddr_nl>()
        || local.nl_family != libc::AF_NETLINK as libc::sa_family_t
        || local.nl_pid == 0
    {
        return Err(invalid());
    }
    crate::platform::nonblocking(&fd)?;
    Ok((fd, local.nl_pid))
}
fn attribute(frame: &mut Vec<u8>, kind: u16, data: &[u8]) {
    let at = frame.len();
    let n = 4 + data.len();
    frame.resize(at + ((n + 3) & !3), 0);
    put16(frame, at, n as u16);
    put16(frame, at + 2, kind);
    frame[at + 4..at + n].copy_from_slice(data)
}
pub(super) fn prepare(info: &Info, action: &Action, sequence: u32) -> io::Result<Session> {
    let Action::Route {
        add,
        destination,
        prefix,
        gateway,
    } = action
    else {
        return Err(crate::platform::invalid("not a route effect"));
    };
    if gateway.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native executor covers interface routes only",
        ));
    }
    if info.index == 0 {
        return Err(crate::platform::invalid("zero interface index"));
    }
    let (raw, _) = network(*destination, *prefix)?;
    let (fd, pid) = netlink()?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(128)
        .map_err(|_| io::Error::other("route frame allocation"))?;
    frame.resize(28, 0);
    let kind = if *add {
        libc::RTM_NEWROUTE
    } else {
        libc::RTM_DELROUTE
    };
    put16(&mut frame, 4, kind);
    let flags = libc::NLM_F_REQUEST
        | libc::NLM_F_ACK
        | if *add {
            libc::NLM_F_CREATE | libc::NLM_F_EXCL
        } else {
            0
        };
    put16(&mut frame, 6, flags as u16);
    put32(&mut frame, 8, sequence);
    put32(&mut frame, 12, pid);
    // Linux UAPI rtmsg is eight u8 fields followed by one native u32 flags.
    frame[16] = if destination.is_ipv4() {
        libc::AF_INET as u8
    } else {
        libc::AF_INET6 as u8
    };
    frame[17] = *prefix;
    frame[20] = libc::RT_TABLE_MAIN;
    frame[21] = libc::RTPROT_STATIC;
    frame[22] = libc::RT_SCOPE_LINK;
    frame[23] = libc::RTN_UNICAST;
    attribute(&mut frame, libc::RTA_DST, &raw);
    attribute(&mut frame, libc::RTA_OIF, &info.index.to_ne_bytes());
    let n = frame.len() as u32;
    put32(&mut frame, 0, n);
    Ok(Session {
        fd,
        frame,
        sequence,
        kind,
        pid,
        index: info.index,
    })
}
pub(super) fn ack(
    bytes: &[u8],
    sequence: u32,
    kind: u16,
    _pid: u32,
    _index: u32,
    request: &[u8],
) -> io::Result<Option<io::Result<()>>> {
    let mut at = 0;
    while at < bytes.len() {
        let b = bytes.get(at..).ok_or_else(invalid)?;
        if b.len() < 16 {
            return Err(invalid());
        }
        let n = word(b, 0)? as usize;
        if n < 16 || n > b.len() {
            return Err(invalid());
        }
        let ty = short(b, 4)?;
        let seq = word(b, 8)?;
        if ty == libc::NLMSG_OVERRUN as u16 {
            return Err(io::Error::from_raw_os_error(libc::ENOBUFS));
        }
        if seq == sequence && ty == libc::NLMSG_ERROR as u16 {
            if n < 36
                || short(b, 24)? != kind
                || word(b, 28)? != sequence
                || b.get(20..36) != request.get(..16)
            {
                return Err(invalid());
            }
            let error = i32::from_ne_bytes(range(b, 16)?);
            return if error == 0 {
                Ok(Some(Ok(())))
            } else if error < 0 {
                let code = error.checked_neg().ok_or_else(invalid)?;
                Ok(Some(Err(io::Error::from_raw_os_error(code))))
            } else {
                Err(invalid())
            };
        }
        let padded = (n + 3) & !3;
        if padded > b.len() {
            if n == b.len() {
                break;
            } else {
                return Err(invalid());
            }
        }
        at = at.checked_add(padded).ok_or_else(invalid)?;
    }
    Ok(None)
}
