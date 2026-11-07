//! macOS RTM_ADD/DELETE scoped interface routes and original reply correlation.
use super::*;
use std::{
    mem::{offset_of, size_of},
    net::IpAddr,
};
const SO_USELOOPBACK: libc::c_int = 0x0040; // Local SDK sys/socket.h public option.
pub(super) fn socket() -> io::Result<OwnedFd> {
    let socket = socket2::Socket::new(
        socket2::Domain::from(libc::PF_ROUTE),
        socket2::Type::RAW,
        None,
    )?;
    socket.set_recv_buffer_size(16_384)?;
    socket.set_send_buffer_size(4_096)?;
    let fd: OwnedFd = socket.into();
    let value = 1 as libc::c_int;
    #[expect(
        unsafe_code,
        reason = "SO_USELOOPBACK receives one initialized c_int option to retain this socket's own kernel route replies; exact public SDK value"
    )]
    // SAFETY: level/option and buffer type/length match sys/socket.h.
    let r = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_USELOOPBACK,
            (&value as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    crate::platform::nonblocking(&fd)?;
    Ok(fd)
}
pub(super) fn address(value: IpAddr, bytes: &[u8], scope: u32) -> Vec<u8> {
    match value {
        IpAddr::V4(_) => {
            let mut b = vec![0; size_of::<libc::sockaddr_in>()];
            b[0] = b.len() as u8;
            b[1] = libc::AF_INET as u8;
            let at = offset_of!(libc::sockaddr_in, sin_addr);
            b[at..at + 4].copy_from_slice(bytes);
            b
        }
        IpAddr::V6(_) => {
            let mut b = vec![0; size_of::<libc::sockaddr_in6>()];
            b[0] = b.len() as u8;
            b[1] = libc::AF_INET6 as u8;
            let at = offset_of!(libc::sockaddr_in6, sin6_addr);
            b[at..at + 16].copy_from_slice(bytes);
            put32(&mut b, offset_of!(libc::sockaddr_in6, sin6_scope_id), scope);
            b
        }
    }
}
pub(super) fn link(info: &Info) -> io::Result<Vec<u8>> {
    let start = offset_of!(libc::sockaddr_dl, sdl_data);
    let n = start + info.name.len();
    let mut b = vec![0; n];
    b[0] = u8::try_from(n).map_err(|_| invalid())?;
    b[1] = libc::AF_LINK as u8;
    put16(
        &mut b,
        offset_of!(libc::sockaddr_dl, sdl_index),
        u16::try_from(info.index)
            .map_err(|_| crate::platform::invalid("route interface index overflow"))?,
    );
    b[offset_of!(libc::sockaddr_dl, sdl_nlen)] = info.name.len() as u8;
    b[start..].copy_from_slice(info.name.as_bytes());
    Ok(b)
}
pub(super) fn append(frame: &mut Vec<u8>, address: &[u8]) {
    frame.extend_from_slice(address);
    frame.resize((frame.len() + 3) & !3, 0)
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
        return Err(crate::platform::invalid("zero route interface"));
    }
    let (raw, mask) = network(*destination, *prefix)?;
    let index = u16::try_from(info.index)
        .map_err(|_| crate::platform::invalid("route interface index overflow"))?;
    let pid = std::process::id();
    let _pid_checked = i32::try_from(pid).map_err(|_| invalid())?;
    let fd = socket()?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(512)
        .map_err(|_| io::Error::other("route frame allocation"))?;
    frame.resize(size_of::<libc::rt_msghdr>(), 0);
    frame[2] = libc::RTM_VERSION as u8;
    let kind = if *add {
        libc::RTM_ADD
    } else {
        libc::RTM_DELETE
    };
    frame[3] = kind as u8;
    put16(&mut frame, offset_of!(libc::rt_msghdr, rtm_index), index);
    let host = usize::from(*prefix) == raw.len() * 8;
    let flags =
        libc::RTF_UP | libc::RTF_STATIC | libc::RTF_IFSCOPE | if host { libc::RTF_HOST } else { 0 };
    put32(
        &mut frame,
        offset_of!(libc::rt_msghdr, rtm_flags),
        flags as u32,
    );
    put32(
        &mut frame,
        offset_of!(libc::rt_msghdr, rtm_addrs),
        (libc::RTA_DST | libc::RTA_GATEWAY | libc::RTA_NETMASK | libc::RTA_IFP) as u32,
    );
    put32(&mut frame, offset_of!(libc::rt_msghdr, rtm_pid), pid);
    put32(&mut frame, offset_of!(libc::rt_msghdr, rtm_seq), sequence);
    let scope = if matches!(destination,IpAddr::V6(a)if a.is_unicast_link_local()) {
        info.index
    } else {
        0
    };
    let gateway = link(info)?;
    append(&mut frame, &address(*destination, &raw, scope));
    append(&mut frame, &gateway);
    append(&mut frame, &address(*destination, &mask, 0));
    append(&mut frame, &gateway);
    let len = u16::try_from(frame.len()).map_err(|_| invalid())?;
    put16(&mut frame, 0, len);
    Ok(Session {
        fd,
        frame,
        sequence,
        kind: kind as u16,
        pid,
        index: info.index,
    })
}
type RouteAddresses<'a> = (Option<&'a [u8]>, Option<&'a [u8]>);
fn route_addresses(bytes: &[u8]) -> io::Result<RouteAddresses<'_>> {
    let flags = word(bytes, offset_of!(libc::rt_msghdr, rtm_addrs))?;
    let mut at = size_of::<libc::rt_msghdr>();
    let mut destination = None;
    let mut mask = None;
    for bit in 0..8 {
        if flags & (1 << bit) == 0 {
            continue;
        }
        let n = usize::from(*bytes.get(at).ok_or_else(invalid)?);
        let rounded = (n.max(1) + 3) & !3;
        let end = at.checked_add(n).ok_or_else(invalid)?;
        if end > bytes.len() || (at + rounded > bytes.len() && end != bytes.len()) {
            return Err(invalid());
        }
        let value = &bytes[at..end];
        if bit == 0 {
            destination = Some(value)
        }
        if bit == 2 {
            mask = Some(value)
        }
        at = if end == bytes.len() {
            end
        } else {
            at + rounded
        };
    }
    Ok((destination, mask))
}
fn same_address(got: &[u8], expected: &[u8], mask: bool) -> bool {
    if expected.len() < 2 {
        return false;
    }
    let (offset, length) = if expected[1] == libc::AF_INET as u8 {
        (offset_of!(libc::sockaddr_in, sin_addr), 4)
    } else if expected[1] == libc::AF_INET6 as u8 {
        (offset_of!(libc::sockaddr_in6, sin6_addr), 16)
    } else {
        return false;
    };
    if !mask && (got.len() < offset + length || got.get(1) != expected.get(1)) {
        return false;
    }
    (0..length).all(|n| got.get(offset + n).copied().unwrap_or(0) == expected[offset + n])
}
fn host_mask(expected: &[u8]) -> bool {
    let (offset, length) = match expected.get(1).copied() {
        Some(v) if v == libc::AF_INET as u8 => (offset_of!(libc::sockaddr_in, sin_addr), 4),
        Some(v) if v == libc::AF_INET6 as u8 => (offset_of!(libc::sockaddr_in6, sin6_addr), 16),
        _ => return false,
    };
    expected
        .get(offset..offset + length)
        .is_some_and(|b| b.iter().all(|b| *b == 0xff))
}
pub(super) fn ack(
    bytes: &[u8],
    sequence: u32,
    kind: u16,
    pid: u32,
    index: u32,
    request: &[u8],
) -> io::Result<Option<io::Result<()>>> {
    if bytes.len() < 4 {
        return Err(invalid());
    }
    if bytes[2] != libc::RTM_VERSION as u8 || u16::from(bytes[3]) != kind {
        return Ok(None);
    }
    if bytes.len() < size_of::<libc::rt_msghdr>() || usize::from(short(bytes, 0)?) != bytes.len() {
        return Err(invalid());
    }
    if word(bytes, offset_of!(libc::rt_msghdr, rtm_seq))? != sequence
        || word(bytes, offset_of!(libc::rt_msghdr, rtm_pid))? != pid
    {
        return Ok(None);
    }
    // A different library in this process can use its own route sequence
    // namespace. Match the original destination/netmask and scope as well.
    if u32::from(short(bytes, offset_of!(libc::rt_msghdr, rtm_index))?) != index {
        return Ok(None);
    }
    let (got_destination, got_mask) = route_addresses(bytes)?;
    let (expected_destination, expected_mask) = route_addresses(request)?;
    let Some(expected_destination) = expected_destination else {
        return Err(invalid());
    };
    let Some(got_destination) = got_destination else {
        return Err(invalid());
    };
    if !same_address(got_destination, expected_destination, false) {
        return Ok(None);
    }
    match (got_mask, expected_mask) {
        (Some(got), Some(expected)) if same_address(got, expected, true) => {}
        (None, None) => {}
        (None, Some(expected))
            if host_mask(expected)
                && word(bytes, offset_of!(libc::rt_msghdr, rtm_flags))? & libc::RTF_HOST as u32
                    != 0 => {}
        _ => return Ok(None),
    }
    let error = i32::from_ne_bytes(range(bytes, offset_of!(libc::rt_msghdr, rtm_errno))?);
    if error < 0 {
        return Err(invalid());
    }
    if error > 0 {
        return Ok(Some(Err(io::Error::from_raw_os_error(error))));
    }
    let flags = word(bytes, offset_of!(libc::rt_msghdr, rtm_flags))?;
    if flags & libc::RTF_DONE as u32 == 0
        || u32::from(short(bytes, offset_of!(libc::rt_msghdr, rtm_index))?) != index
    {
        return Err(invalid());
    }
    Ok(Some(Ok(())))
}
