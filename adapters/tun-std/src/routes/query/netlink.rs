//! Complete bounded native-table Netlink dumps, never longest-prefix lookups.
use super::super::netlink::wire::{
    DUMP_EVIDENCE, NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_MULTI, NLM_F_REQUEST, NLMSG_DONE,
    NLMSG_ERROR, NLMSG_NOOP, NLMSG_OVERRUN, RTA_CACHEINFO, RTA_DST, RTA_EXPIRES, RTA_GATEWAY,
    RTA_KNH_ID, RTA_METRICS, RTA_NH_ID, RTA_OIF, RTA_PREFSRC, RTA_PRIORITY, RTA_RTFLAGS, RTA_TABLE,
    RTA_WEIGHT, RTM_F_CLONED, RTM_GETROUTE, RTM_NEWROUTE,
};
use super::super::netlink::{attribute, kernel_error, open};
use super::super::{Session, invalid, network, put16, put32, range, short, word};
use super::{Reply, RouteQueryOutcome, RouteQueryProblem, RouteQueryTarget, RouteRecord, Scan};
use std::{io, net::IpAddr};
pub(super) fn prepare(target: &RouteQueryTarget, sequence: u32) -> io::Result<Session> {
    let (fd, pid) = open()?;
    let mut frame = vec![0; 28];
    put16(&mut frame, 4, RTM_GETROUTE);
    put16(&mut frame, 6, NLM_F_REQUEST | NLM_F_DUMP);
    put32(&mut frame, 8, sequence);
    put32(&mut frame, 12, pid);
    frame[16] = if target.destination.is_ipv4() {
        libc::AF_INET as u8
    } else {
        libc::AF_INET6 as u8
    };
    let table = target.table.ok_or_else(invalid)?;
    frame[20] = u8::try_from(table).unwrap_or(0);
    attribute(&mut frame, RTA_TABLE, &table.to_ne_bytes());
    let n = frame.len() as u32;
    put32(&mut frame, 0, n);
    Ok(Session {
        fd,
        frame,
        sequence,
        kind: RTM_GETROUTE,
        pid,
        index: target.interface.index,
    })
}
pub(super) fn reply(
    bytes: &[u8],
    target: &RouteQueryTarget,
    sequence: u32,
    pid: u32,
    scan: &mut Scan,
    request: &[u8],
) -> io::Result<Option<Reply>> {
    let mut at = 0;
    let mut done = false;
    while at < bytes.len() {
        let b = bytes.get(at..).ok_or_else(invalid)?;
        let n = word(b, 0)? as usize;
        if n < 16 || n > b.len() {
            return Err(invalid());
        }
        let b = &b[..n];
        let kind = short(b, 4)?;
        if kind == NLMSG_OVERRUN {
            return Err(io::Error::other("route inventory overrun"));
        }
        if word(b, 8)? == sequence {
            if done || short(b, 6)? & NLM_F_DUMP_INTR != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "interrupted route inventory; no absence inferred",
                ));
            }
            if kind == RTM_NEWROUTE && short(b, 6)? & NLM_F_MULTI == 0 {
                return Err(invalid());
            }
            if kind == NLMSG_DONE {
                if n != 16 && n < 20 {
                    return Err(invalid());
                }
                if n >= 20 {
                    let error = i32::from_ne_bytes(range(b, 16)?);
                    if error != 0 {
                        return Err(kernel_error(error)?);
                    }
                }
                done = true;
            } else if kind == NLMSG_ERROR {
                if let Some(result) = super::super::netlink::ack(
                    b,
                    sequence,
                    RTM_GETROUTE,
                    pid,
                    target.interface.index,
                    request,
                )? {
                    result?;
                }
            } else if kind == RTM_NEWROUTE {
                if let Some(record) = record(b, target)? {
                    scan.count = scan.count.checked_add(1).ok_or_else(invalid)?;
                    if scan.first.is_none() {
                        scan.first = Some(record);
                    }
                }
            } else if kind != NLMSG_NOOP {
                return Err(invalid());
            }
        }
        let padded = (n + 3) & !3;
        if padded > bytes.len() - at {
            if n == bytes.len() - at {
                at = bytes.len();
            } else {
                return Err(invalid());
            }
        } else {
            at += padded;
        }
    }
    if !done {
        return Ok(None);
    }
    let outcome = if scan.count > 1 {
        RouteQueryOutcome::Unknown(RouteQueryProblem::Ambiguous {
            records: scan.count,
        })
    } else if let Some(record) = scan.first.take() {
        if record.exact(target) {
            RouteQueryOutcome::Exact(record)
        } else {
            RouteQueryOutcome::Different(record)
        }
    } else {
        RouteQueryOutcome::Absent
    };
    Ok(Some(Reply {
        outcome,
        evidence: DUMP_EVIDENCE,
        errno: None,
    }))
}
fn ip(bytes: &[u8], v4: bool) -> io::Result<IpAddr> {
    if v4 {
        if bytes.len() != 4 {
            return Err(invalid());
        }
        Ok(IpAddr::from(range::<4>(bytes, 0)?))
    } else {
        if bytes.len() != 16 {
            return Err(invalid());
        }
        Ok(IpAddr::from(range::<16>(bytes, 0)?))
    }
}
fn record(b: &[u8], target: &RouteQueryTarget) -> io::Result<Option<RouteRecord>> {
    if b.len() < 28 {
        return Err(invalid());
    }
    let v4 = target.destination.is_ipv4();
    if b[16]
        != if v4 {
            libc::AF_INET as u8
        } else {
            libc::AF_INET6 as u8
        }
    {
        return Ok(None);
    }
    if b[17] > if v4 { 32 } else { 128 } {
        return Err(invalid());
    }
    let mut table = u32::from(b[20]);
    let mut extended_table = false;
    let mut destination = None;
    let mut gateway = None;
    let mut interface = None;
    let mut metric = None;
    #[cfg(target_os = "freebsd")]
    let mut path_flags = None;
    #[cfg(target_os = "freebsd")]
    let mut metadata = 0u32;
    let mut unsupported = b[18] != 0 || b[19] != 0; // source-specific/TOS policy is not a plain interface route.
    let mut at = 28;
    while at < b.len() {
        let n = usize::from(short(b, at)?);
        if n < 4 || n > b.len() - at {
            return Err(invalid());
        }
        let kind = short(b, at + 2)?;
        let value = &b[at + 4..at + n];
        if kind == RTA_DST {
            if destination.is_some() {
                return Err(invalid());
            }
            destination = Some(ip(value, v4)?);
        } else if kind == RTA_GATEWAY {
            if gateway.is_some() {
                return Err(invalid());
            }
            gateway = Some(ip(value, v4)?);
        } else if kind == RTA_OIF {
            if interface.is_some() || value.len() != 4 {
                return Err(invalid());
            }
            interface = Some(word(value, 0)?);
        } else if kind == RTA_PRIORITY {
            if metric.is_some() || value.len() != 4 {
                return Err(invalid());
            }
            metric = Some(word(value, 0)?);
        } else if kind == RTA_TABLE {
            if extended_table || value.len() != 4 {
                return Err(invalid());
            }
            table = word(value, 0)?;
            extended_table = true;
        } else if cfg!(target_os = "freebsd")
            && matches!(
                kind,
                RTA_KNH_ID | RTA_WEIGHT | RTA_RTFLAGS | RTA_EXPIRES | RTA_NH_ID
            )
        {
            // Native RTA_KNH_ID, WEIGHT, RTFLAGS, EXPIRES and NH_ID. These
            // numbers have different Linux meanings, so never interpret them
            // as FreeBSD attributes on a Linux socket.
            #[cfg(target_os = "freebsd")]
            {
                let bit = 1u32 << kind;
                if metadata & bit != 0 || value.len() != 4 {
                    return Err(invalid());
                }
                metadata |= bit;
                if kind == RTA_RTFLAGS {
                    path_flags = Some(word(value, 0)?);
                } else if matches!(kind, RTA_WEIGHT | RTA_EXPIRES) {
                    // An explicit weight or expiry is outside the plain,
                    // persistent interface-route tuple installed here.
                    unsupported = true;
                }
            }
        } else if cfg!(target_os = "linux") && kind == 20 {
            // RTA_PREF=20 in pinned Linux UAPI/GNU libc bindings.
            if value.len() != 1 {
                return Err(invalid());
            }
            unsupported |= value[0] != 0; // Non-default IPv6 router preference.
        } else if kind != RTA_METRICS
            && !(cfg!(target_os = "linux") && matches!(kind, RTA_PREFSRC | RTA_CACHEINFO))
        {
            unsupported = true;
        }
        let padded = (n + 3) & !3;
        if padded > b.len() - at {
            if n == b.len() - at {
                at = b.len();
            } else {
                return Err(invalid());
            }
        } else {
            at += padded;
        }
    }
    #[cfg(target_os = "freebsd")]
    if !extended_table {
        // FreeBSD emits RTA_TABLE for every route, including FIB 0. The byte
        // header alone cannot distinguish FIB 0 from larger table identifiers.
        return Err(invalid());
    }
    let destination = match destination {
        Some(value) => value,
        None if b[17] == 0 => {
            if v4 {
                IpAddr::from([0u8; 4])
            } else {
                IpAddr::from([0u8; 16])
            }
        }
        None => return Err(invalid()),
    };
    if Some(table) != target.table || destination != target.destination || b[17] != target.prefix {
        return Ok(None);
    }
    network(destination, b[17])?;
    let message_flags = word(b, 24)?;
    unsupported |= message_flags & RTM_F_CLONED != 0;
    #[cfg(target_os = "linux")]
    let (flags, direct) = (message_flags, gateway.is_none());
    #[cfg(target_os = "freebsd")]
    let (flags, direct) = {
        // FreeBSD reports RTF_* on the path attribute, not in rtm_flags.
        // Omission cannot establish supported direct-route semantics.
        unsupported |= path_flags.is_none() || message_flags != 0;
        let flags = path_flags.unwrap_or(0);
        (
            flags,
            gateway.is_none() && flags & libc::RTF_GATEWAY as u32 == 0,
        )
    };
    Ok(Some(RouteRecord {
        destination,
        prefix: b[17],
        interface: interface.unwrap_or(0),
        gateway,
        direct,
        flags,
        table: Some(table),
        kind: Some(b[23]),
        scope: Some(b[22]),
        protocol: Some(b[21]),
        metric,
        unsupported,
    }))
}

#[cfg(test)]
mod tests;
