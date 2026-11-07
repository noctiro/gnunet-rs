//! Complete bounded main-table Linux route dump, not a longest-prefix lookup.
use super::*;
pub(super) fn prepare(target: &RouteQueryTarget, sequence: u32) -> io::Result<Session> {
    let (fd, pid) = super::super::linux::netlink()?;
    let mut frame = vec![0; 28];
    put32(&mut frame, 0, 28);
    put16(&mut frame, 4, libc::RTM_GETROUTE);
    put16(
        &mut frame,
        6,
        (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16,
    );
    put32(&mut frame, 8, sequence);
    put32(&mut frame, 12, pid);
    frame[16] = if target.destination.is_ipv4() {
        libc::AF_INET as u8
    } else {
        libc::AF_INET6 as u8
    };
    frame[20] = libc::RT_TABLE_MAIN;
    Ok(Session {
        fd,
        frame,
        sequence,
        kind: libc::RTM_GETROUTE,
        pid,
        index: target.interface.index,
    })
}
pub(super) fn reply(
    bytes: &[u8],
    target: &RouteQueryTarget,
    sequence: u32,
    _: u32,
    scan: &mut Scan,
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
        if kind == libc::NLMSG_OVERRUN as u16 {
            return Err(io::Error::other("route inventory overrun"));
        }
        if word(b, 8)? == sequence {
            if done || short(b, 6)? & libc::NLM_F_DUMP_INTR as u16 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "interrupted route inventory; no absence inferred",
                ));
            }
            if kind == libc::NLMSG_DONE as u16 {
                if n != 16 && n < 20 {
                    return Err(invalid());
                }
                if n >= 20 {
                    let error = i32::from_ne_bytes(range(b, 16)?);
                    if error != 0 {
                        return Err(kernel(error)?);
                    }
                }
                done = true;
            } else if kind == libc::NLMSG_ERROR as u16 {
                let error = i32::from_ne_bytes(range(b, 16)?);
                if error != 0 {
                    return Err(kernel(error)?);
                }
            } else if kind == libc::RTM_NEWROUTE {
                if let Some(record) = record(b, target)? {
                    scan.count += 1;
                    if scan.first.is_none() {
                        scan.first = Some(record);
                    }
                }
            } else if kind != libc::NLMSG_NOOP as u16 {
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
        evidence: RouteQueryEvidence::LinuxDump,
        errno: None,
    }))
}
fn kernel(value: i32) -> io::Result<io::Error> {
    if value >= 0 {
        return Err(invalid());
    }
    Ok(io::Error::from_raw_os_error(
        value.checked_neg().ok_or_else(invalid)?,
    ))
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
    let mut unsupported = b[18] != 0 || b[19] != 0; // source-specific/TOS policy is not a plain interface route.
    let mut at = 28;
    while at < b.len() {
        let n = usize::from(short(b, at)?);
        if n < 4 || n > b.len() - at {
            return Err(invalid());
        }
        let kind = short(b, at + 2)?;
        let value = &b[at + 4..at + n];
        if kind == libc::RTA_DST {
            if destination.is_some() {
                return Err(invalid());
            }
            destination = Some(ip(value, v4)?);
        } else if kind == libc::RTA_GATEWAY {
            if gateway.is_some() {
                return Err(invalid());
            }
            gateway = Some(ip(value, v4)?);
        } else if kind == libc::RTA_OIF {
            if interface.is_some() || value.len() != 4 {
                return Err(invalid());
            }
            interface = Some(word(value, 0)?);
        } else if kind == libc::RTA_PRIORITY {
            if metric.is_some() || value.len() != 4 {
                return Err(invalid());
            }
            metric = Some(word(value, 0)?);
        } else if kind == libc::RTA_TABLE {
            if extended_table || value.len() != 4 {
                return Err(invalid());
            }
            table = word(value, 0)?;
            extended_table = true;
        } else if kind == 20 {
            // RTA_PREF=20 in pinned Linux UAPI/GNU libc bindings.
            if value.len() != 1 {
                return Err(invalid());
            }
            unsupported |= value[0] != 0; // Non-default IPv6 router preference.
        } else if !matches!(
            kind,
            libc::RTA_PREFSRC | libc::RTA_CACHEINFO | libc::RTA_METRICS
        ) {
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
    if table != u32::from(libc::RT_TABLE_MAIN)
        || destination != target.destination
        || b[17] != target.prefix
    {
        return Ok(None);
    }
    network(destination, b[17])?;
    let flags = word(b, 24)?;
    unsupported |= flags & libc::RTM_F_CLONED != 0;
    Ok(Some(RouteRecord {
        destination,
        prefix: b[17],
        interface: interface.unwrap_or(0),
        gateway,
        direct: gateway.is_none(),
        flags,
        table: Some(table),
        kind: Some(b[23]),
        scope: Some(b[22]),
        protocol: Some(b[21]),
        metric,
        unsupported,
    }))
}
