//! Shared Linux/FreeBSD Netlink route framing and correlated acknowledgements.
mod socket;
pub(super) use socket::{open, source};
pub(super) mod wire;
use super::{Action, Info, Session, invalid, network, put16, put32, range, short, word};
use std::io;
#[cfg(target_os = "freebsd")]
use wire::RTA_RTFLAGS;
pub(super) use wire::{DIRECT_SCOPE, RT_SCOPE_UNIVERSE, RTN_UNICAST};
use wire::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST, NLMSG_ERROR, NLMSG_OVERRUN, RTA_DST,
    RTA_OIF, RTA_TABLE, RTM_DELROUTE, RTM_NEWROUTE, RTPROT_STATIC,
};
pub(super) fn attribute(frame: &mut Vec<u8>, kind: u16, data: &[u8]) {
    let at = frame.len();
    let n = 4 + data.len();
    frame.resize(at + ((n + 3) & !3), 0);
    put16(frame, at, n as u16);
    put16(frame, at + 2, kind);
    frame[at + 4..at + n].copy_from_slice(data)
}
pub(super) fn prepare(
    info: &Info,
    action: &Action,
    sequence: u32,
    table: Option<u32>,
) -> io::Result<Session> {
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
    let table = table.ok_or_else(invalid)?;
    let (fd, pid) = open()?;
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(128)
        .map_err(|_| io::Error::other("route frame allocation"))?;
    frame.resize(28, 0);
    let kind = if *add { RTM_NEWROUTE } else { RTM_DELROUTE };
    put16(&mut frame, 4, kind);
    let flags = NLM_F_REQUEST | NLM_F_ACK | if *add { NLM_F_CREATE | NLM_F_EXCL } else { 0 };
    put16(&mut frame, 6, flags);
    put32(&mut frame, 8, sequence);
    put32(&mut frame, 12, pid);
    // Both native rtmsg layouts are eight u8 fields followed by one u32 flags.
    frame[16] = if destination.is_ipv4() {
        libc::AF_INET as u8
    } else {
        libc::AF_INET6 as u8
    };
    frame[17] = *prefix;
    frame[20] = u8::try_from(table).unwrap_or(0);
    frame[21] = RTPROT_STATIC;
    frame[22] = DIRECT_SCOPE;
    frame[23] = RTN_UNICAST;
    // An explicit table is required even for FreeBSD FIB 0: an omitted zero
    // table in a dump means all FIBs, not the default FIB.
    attribute(&mut frame, RTA_TABLE, &table.to_ne_bytes());
    attribute(&mut frame, RTA_DST, &raw);
    attribute(&mut frame, RTA_OIF, &info.index.to_ne_bytes());
    #[cfg(target_os = "freebsd")]
    if *add {
        // FreeBSD treats RTPROT_STATIC as a fallback classification. Native
        // path flags, not protocol=4 alone, actually mark the route static.
        attribute(
            &mut frame,
            RTA_RTFLAGS,
            &(libc::RTF_STATIC as u32).to_ne_bytes(),
        );
    }
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
        if ty == NLMSG_OVERRUN {
            return Err(io::Error::from_raw_os_error(libc::ENOBUFS));
        }
        if seq == sequence && ty == NLMSG_ERROR {
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
            } else {
                Ok(Some(Err(kernel_error(error)?)))
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
// FreeBSD native Netlink reports positive native errno in ACK/DONE. Its Linux
// ABI translator negates it, but native FreeBSD programs must not do that.
pub(super) fn kernel_error(value: i32) -> io::Result<io::Error> {
    let code = if cfg!(target_os = "freebsd") {
        value
    } else {
        value.checked_neg().ok_or_else(invalid)?
    };
    if code <= 0 {
        return Err(invalid());
    }
    Ok(io::Error::from_raw_os_error(code))
}

#[cfg(test)]
mod tests;
