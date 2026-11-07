//! Actual scoped RTM_GET, followed by exact comparison of returned kernel route.
use super::*;
use std::mem::{offset_of, size_of};
pub(super) fn prepare(target: &RouteQueryTarget, sequence: u32) -> io::Result<Session> {
    let index = u16::try_from(target.interface.index)
        .map_err(|_| crate::platform::invalid("route query interface index"))?;
    let (raw, mask) = network(target.destination, target.prefix)?;
    let fd = super::super::macos::socket()?;
    let pid = std::process::id();
    let _checked = i32::try_from(pid).map_err(|_| invalid())?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(512)
        .map_err(|_| io::Error::other("route query allocation"))?;
    frame.resize(size_of::<libc::rt_msghdr>(), 0);
    frame[2] = libc::RTM_VERSION as u8;
    frame[3] = libc::RTM_GET as u8;
    put16(&mut frame, offset_of!(libc::rt_msghdr, rtm_index), index);
    put32(
        &mut frame,
        offset_of!(libc::rt_msghdr, rtm_flags),
        (libc::RTF_IFSCOPE
            | if usize::from(target.prefix) == raw.len() * 8 {
                libc::RTF_HOST
            } else {
                0
            }) as u32,
    );
    put32(
        &mut frame,
        offset_of!(libc::rt_msghdr, rtm_addrs),
        (libc::RTA_DST | libc::RTA_NETMASK | libc::RTA_IFP) as u32,
    );
    put32(&mut frame, offset_of!(libc::rt_msghdr, rtm_pid), pid);
    put32(&mut frame, offset_of!(libc::rt_msghdr, rtm_seq), sequence);
    let scope = if matches!(target.destination, IpAddr::V6(a) if a.is_unicast_link_local()) {
        target.interface.index
    } else {
        0
    };
    super::super::macos::append(
        &mut frame,
        &super::super::macos::address(target.destination, &raw, scope),
    );
    super::super::macos::append(
        &mut frame,
        &super::super::macos::address(target.destination, &mask, 0),
    );
    super::super::macos::append(&mut frame, &super::super::macos::link(&target.interface)?);
    let len = u16::try_from(frame.len()).map_err(|_| invalid())?;
    put16(&mut frame, 0, len);
    Ok(Session {
        fd,
        frame,
        sequence,
        kind: libc::RTM_GET as u16,
        pid,
        index: target.interface.index,
    })
}
fn addresses(b: &[u8]) -> io::Result<[Option<&[u8]>; 8]> {
    let flags = word(b, offset_of!(libc::rt_msghdr, rtm_addrs))?;
    if flags & !0xff != 0 {
        return Err(invalid());
    }
    let mut result = [None; 8];
    let mut at = size_of::<libc::rt_msghdr>();
    for (bit, address) in result.iter_mut().enumerate() {
        if flags & (1 << bit) == 0 {
            continue;
        }
        let n = usize::from(*b.get(at).ok_or_else(invalid)?);
        let padded = (n.max(1) + 3) & !3;
        let end = at.checked_add(n).ok_or_else(invalid)?;
        if end > b.len() || (at + padded > b.len() && end != b.len()) {
            return Err(invalid());
        }
        *address = Some(&b[at..end]);
        at = if end == b.len() { end } else { at + padded };
    }
    if at != b.len() {
        return Err(invalid());
    }
    Ok(result)
}
fn ip(b: &[u8], index: u32) -> io::Result<IpAddr> {
    let family = *b.get(1).ok_or_else(invalid)?;
    if family == libc::AF_INET as u8 {
        Ok(IpAddr::from(range::<4>(
            b,
            offset_of!(libc::sockaddr_in, sin_addr),
        )?))
    } else if family == libc::AF_INET6 as u8 {
        let mut raw = range::<16>(b, offset_of!(libc::sockaddr_in6, sin6_addr))?;
        let address = std::net::Ipv6Addr::from(raw);
        let scope = word(b, offset_of!(libc::sockaddr_in6, sin6_scope_id))?;
        if address.is_unicast_link_local() {
            let embedded = u32::from(u16::from_be_bytes([raw[2], raw[3]]));
            if (scope != 0 && scope != index) || (embedded != 0 && embedded != index) {
                return Err(invalid());
            }
            raw[2..4].fill(0);
        } else if scope != 0 {
            return Err(invalid());
        }
        Ok(IpAddr::from(raw))
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "route Get returned non-IP destination/gateway",
        ))
    }
}
fn prefix(mask: Option<&[u8]>, destination: IpAddr, flags: u32) -> io::Result<u8> {
    let width = if destination.is_ipv4() { 32 } else { 128 };
    if flags & libc::RTF_HOST as u32 != 0 && mask.is_none() {
        return Ok(width);
    }
    let mask = mask.ok_or_else(invalid)?;
    let family = if destination.is_ipv4() {
        libc::AF_INET as u8
    } else {
        libc::AF_INET6 as u8
    };
    if mask.get(1).is_some_and(|f| *f != 0 && *f != family) {
        return Err(invalid());
    }
    let (offset, length) = if destination.is_ipv4() {
        (offset_of!(libc::sockaddr_in, sin_addr), 4)
    } else {
        (offset_of!(libc::sockaddr_in6, sin6_addr), 16)
    };
    let mut count = 0;
    let mut zero = false;
    for i in 0..length {
        let byte = mask.get(offset + i).copied().unwrap_or(0);
        for bit in (0..8).rev() {
            if byte & (1 << bit) == 0 {
                zero = true;
            } else if zero {
                return Err(invalid());
            } else {
                count += 1;
            }
        }
    }
    if flags & libc::RTF_HOST as u32 != 0 && count != width {
        return Err(invalid());
    }
    Ok(count)
}
fn link_index(b: &[u8]) -> io::Result<u32> {
    if b.get(1).copied() != Some(libc::AF_LINK as u8) {
        return Err(invalid());
    }
    Ok(u32::from(short(
        b,
        offset_of!(libc::sockaddr_dl, sdl_index),
    )?))
}
pub(super) fn reply(
    b: &[u8],
    target: &RouteQueryTarget,
    sequence: u32,
    pid: u32,
    _: &mut Scan,
) -> io::Result<Option<Reply>> {
    if b.len() < 4 {
        return Err(invalid());
    }
    if b[2] != libc::RTM_VERSION as u8 || b[3] != libc::RTM_GET as u8 {
        return Ok(None);
    }
    if b.len() < size_of::<libc::rt_msghdr>() || usize::from(short(b, 0)?) != b.len() {
        return Err(invalid());
    }
    if word(b, offset_of!(libc::rt_msghdr, rtm_seq))? != sequence
        || word(b, offset_of!(libc::rt_msghdr, rtm_pid))? != pid
    {
        return Ok(None);
    }
    let index = u32::from(short(b, offset_of!(libc::rt_msghdr, rtm_index))?);
    let flags = word(b, offset_of!(libc::rt_msghdr, rtm_flags))?;
    let all = addresses(b)?;
    let destination = ip(all[0].ok_or_else(invalid)?, target.interface.index)?;
    let prefix = prefix(all[2], destination, flags)?;
    let error = i32::from_ne_bytes(range(b, offset_of!(libc::rt_msghdr, rtm_errno))?);
    if error < 0 {
        return Err(invalid());
    }
    if error != 0 {
        // Error replies echo the original query. Correlate that exact tuple
        // before ESRCH can become absence of this requested scoped route.
        if destination != target.destination
            || prefix != target.prefix
            || index != target.interface.index
        {
            return Ok(None);
        }
        if error == libc::ESRCH {
            return Ok(Some(Reply {
                outcome: RouteQueryOutcome::Absent,
                evidence: RouteQueryEvidence::MacRouteReply,
                errno: Some(error),
            }));
        }
        return Err(io::Error::from_raw_os_error(error));
    }
    if flags & libc::RTF_DONE as u32 == 0 {
        return Err(invalid());
    }
    let mut gateway = None;
    let mut direct = false;
    let mut unsupported =
        flags & (libc::RTF_REJECT | libc::RTF_BLACKHOLE | libc::RTF_WASCLONED) as u32 != 0;
    if let Some(value) = all[1] {
        if value.get(1).copied() == Some(libc::AF_LINK as u8) {
            direct = link_index(value)? == index && index != 0;
            unsupported |= !direct;
        } else {
            gateway = Some(ip(value, index)?);
        }
    } else {
        unsupported = true;
    }
    if let Some(ifp) = all[4] {
        unsupported |= link_index(ifp)? != index;
    }
    let record = RouteRecord {
        destination,
        prefix,
        interface: index,
        gateway,
        direct,
        flags,
        table: None,
        kind: None,
        scope: None,
        protocol: None,
        metric: None,
        unsupported,
    };
    // A broader route/default is genuine Different evidence, never proof of the
    // requested prefix or permission to delete the route the kernel returned.
    let outcome = if record.exact(target) {
        RouteQueryOutcome::Exact(record)
    } else {
        RouteQueryOutcome::Different(record)
    };
    Ok(Some(Reply {
        outcome,
        evidence: RouteQueryEvidence::MacRouteReply,
        errno: None,
    }))
}
