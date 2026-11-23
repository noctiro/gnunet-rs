//! Linux route-table operations for directly attached default routes.

use crate::linux_netlink::{Header, Socket, aligned};
use std::{io, num::NonZeroU32, time::Instant};

const REQUEST_SEQUENCE: u32 = 1;
const ROUTE_HEADER: usize = 12;
const ATTRIBUTE_HEADER: usize = 4;
const RTA_PREF: u16 = 20;
const RTNH_F_LINKDOWN: u32 = 16;
const MAX_DATAGRAMS: usize = 1024;

#[cfg(test)]
mod tests;

/// Native family of a routing table entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    /// An IPv4 route in its own policy table.
    Ipv4,
    /// An IPv6 route in its own policy table.
    Ipv6,
}

impl Family {
    const fn native(self) -> u8 {
        match self {
            Self::Ipv4 => libc::AF_INET as u8,
            Self::Ipv6 => libc::AF_INET6 as u8,
        }
    }

    const fn expected_scope(self) -> u8 {
        match self {
            Self::Ipv4 => libc::RT_SCOPE_LINK,
            Self::Ipv6 => libc::RT_SCOPE_UNIVERSE,
        }
    }

    const fn address_bytes(self) -> usize {
        match self {
            Self::Ipv4 => 4,
            Self::Ipv6 => 16,
        }
    }
}

/// The numeric attributes of one directly attached static default route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectDefault {
    /// IP family of the row.
    pub family: Family,
    /// Original policy table number.
    pub table: NonZeroU32,
    /// Original Linux interface index.
    pub interface: NonZeroU32,
    /// Route metric selected when establishing the table lease.
    pub metric: NonZeroU32,
}

/// A mutation of one exact native route selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteChange {
    /// Create without replacing an existing route.
    Install,
    /// Remove the specified route from its original table and interface index.
    Remove,
}

/// Outcome of the original acknowledged mutation.
#[derive(Debug)]
pub enum Acknowledgment {
    /// The original kernel acknowledged application.
    Applied,
    /// The original kernel rejected the operation.
    Rejected(io::Error),
}

/// Submit one exact route mutation and wait for its original kernel acknowledgment.
///
/// # Errors
/// Reports submission or observation failures. After submission an observation
/// failure leaves native exposure unknown and requires separate reconciliation.
pub fn change(
    target: DirectDefault,
    action: RouteChange,
    deadline: Instant,
) -> io::Result<Acknowledgment> {
    let socket = Socket::open(libc::NETLINK_ROUTE)?;
    let (request, frame) = change_request(target, action, socket.port())?;
    socket.send(&frame, deadline)?;
    let mut buffer = [0; 512];
    let size = socket.receive(&mut buffer, deadline)?;
    acknowledgment(request, &buffer[..size])
}

fn change_request(
    target: DirectDefault,
    action: RouteChange,
    port: u32,
) -> io::Result<(Header, [u8; 52])> {
    let mut frame = [0; 52];
    let (kind, flags) = match action {
        RouteChange::Install => (libc::RTM_NEWROUTE, libc::NLM_F_CREATE | libc::NLM_F_EXCL),
        RouteChange::Remove => (libc::RTM_DELROUTE, 0),
    };
    let request = Header {
        length: frame.len() as u32,
        kind,
        flags: (libc::NLM_F_REQUEST | libc::NLM_F_ACK | flags) as u16,
        sequence: REQUEST_SEQUENCE,
        port,
    };
    request.write(&mut frame)?;
    let (body, attributes) = frame[Header::SIZE..].split_at_mut(ROUTE_HEADER);
    body[0] = target.family.native();
    body[4] = u8::try_from(target.table.get()).unwrap_or(libc::RT_TABLE_UNSPEC);
    body[5] = libc::RTPROT_STATIC;
    body[6] = target.family.expected_scope();
    body[7] = libc::RTN_UNICAST;
    for (attribute, (kind, value)) in attributes.as_chunks_mut::<8>().0.iter_mut().zip([
        (libc::RTA_TABLE, target.table),
        (libc::RTA_OIF, target.interface),
        (libc::RTA_PRIORITY, target.metric),
    ]) {
        write_attribute(attribute, kind, value);
    }
    Ok((request, frame))
}

fn acknowledgment(request: Header, mut received: &[u8]) -> io::Result<Acknowledgment> {
    let (reply, body) = Header::take(&mut received)?;
    if !received.is_empty()
        || reply.kind != libc::NLMSG_ERROR as u16
        || reply.port != request.port
        || reply.sequence != request.sequence
        || i32::from(reply.flags) & (libc::NLM_F_MULTI | libc::NLM_F_DUMP_INTR) != 0
    {
        return Err(invalid(
            "Linux route ACK does not match the original mutation",
        ));
    }
    let (status, echo) = body
        .split_first_chunk::<4>()
        .ok_or_else(|| invalid("short Linux route ACK"))?;
    if Header::read(echo)? != request {
        return Err(invalid("Linux route ACK echoes a different mutation"));
    }
    match i32::from_ne_bytes(*status) {
        0 => Ok(Acknowledgment::Applied),
        status if status < 0 && status != i32::MIN => {
            Ok(Acknowledgment::Rejected(netlink_error(status)))
        }
        _ => Err(invalid("invalid Linux route ACK status")),
    }
}

/// Whether the exact route is distinguishable in the current inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DefaultPresence {
    /// The route is absent. The table may still have unrelated entries.
    Absent,
    /// Exactly one matching entry, without a competing deletion candidate.
    Exact,
    /// A duplicate or a changed route matching the native deletion selectors.
    Conflicting,
}

/// Complete evidence from the kernel for the requested family and table.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RouteInventory {
    occupied: bool,
    exact: bool,
    conflicting: bool,
    unrelated: bool,
}

impl RouteInventory {
    /// A missing table and a present table without routes are both vacant.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        !self.occupied
    }

    /// Whether the table contains exactly the selected default and no other entries.
    #[must_use]
    pub const fn is_exclusive_default(self) -> bool {
        self.exact && !self.conflicting && !self.unrelated
    }

    /// Whether the selected default route can be distinguished from other rows.
    #[must_use]
    pub const fn default_route(self) -> DefaultPresence {
        if self.conflicting {
            DefaultPresence::Conflicting
        } else if self.exact {
            DefaultPresence::Exact
        } else {
            DefaultPresence::Absent
        }
    }
}

/// Read a bounded, complete Linux route inventory in the calling thread's namespace.
///
/// # Errors
/// Reports native errors, lost or malformed evidence and the original deadline.
pub fn inventory(target: DirectDefault, deadline: Instant) -> io::Result<RouteInventory> {
    let socket = Socket::open(libc::NETLINK_ROUTE)?;
    let strict = socket.strict_dump()?;
    let (request, length) = request(target, socket.port(), strict)?;
    socket.send(&request[..length], deadline)?;

    let mut buffer = [0; 32 * 1024];
    let mut scan = Scan::default();
    for _ in 0..MAX_DATAGRAMS {
        let length = socket.receive(&mut buffer, deadline)?;
        if scan.receive(&buffer[..length], target, socket.port(), strict)? {
            return Ok(scan.inventory);
        }
    }
    Err(io::Error::other(
        "Linux route inventory exceeded its datagram bound",
    ))
}

fn request(target: DirectDefault, port: u32, strict: bool) -> io::Result<([u8; 36], usize)> {
    let mut bytes = [0; 36];
    let length = Header::SIZE + ROUTE_HEADER + if strict { 8 } else { 0 };
    Header {
        length: length as u32,
        kind: libc::RTM_GETROUTE,
        flags: (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16,
        sequence: REQUEST_SEQUENCE,
        port,
    }
    .write(&mut bytes)?;
    bytes[Header::SIZE] = target.family.native();
    if strict {
        write_attribute(
            &mut bytes[Header::SIZE + ROUTE_HEADER..],
            libc::RTA_TABLE,
            target.table,
        );
    }
    Ok((bytes, length))
}

fn write_attribute(bytes: &mut [u8], kind: u16, value: NonZeroU32) {
    bytes[..2].copy_from_slice(&8_u16.to_ne_bytes());
    bytes[2..4].copy_from_slice(&kind.to_ne_bytes());
    bytes[4..].copy_from_slice(&value.get().to_ne_bytes());
}

#[derive(Default)]
struct Scan {
    inventory: RouteInventory,
    saw_record: bool,
}

impl Scan {
    fn receive(
        &mut self,
        mut bytes: &[u8],
        target: DirectDefault,
        port: u32,
        strict: bool,
    ) -> io::Result<bool> {
        while !bytes.is_empty() {
            let (header, body) = Header::take(&mut bytes)?;
            if header.kind == libc::NLMSG_OVERRUN as u16 {
                return Err(io::Error::other("Linux route inventory overrun"));
            }
            if header.sequence != REQUEST_SEQUENCE || header.port != port {
                return Err(invalid("unrelated Linux route inventory response"));
            }
            if header.flags & libc::NLM_F_DUMP_INTR as u16 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Linux route inventory changed during enumeration",
                ));
            }
            match i32::from(header.kind) {
                libc::NLMSG_DONE => {
                    if !bytes.is_empty() {
                        return Err(invalid("records after Linux route inventory completion"));
                    }
                    let status = if body.is_empty() {
                        0
                    } else {
                        word(body)? as i32
                    };
                    // A family-specific strict table dump uses ENOENT for a FIB
                    // that has never existed. No other error establishes vacancy.
                    if status == 0 || (strict && !self.saw_record && status == -libc::ENOENT) {
                        return Ok(true);
                    }
                    return Err(netlink_error(status));
                }
                libc::NLMSG_ERROR => return Err(netlink_error(word(body)? as i32)),
                libc::NLMSG_NOOP => {}
                _ if header.kind == libc::RTM_NEWROUTE => {
                    if header.flags & libc::NLM_F_MULTI as u16 == 0 {
                        return Err(invalid("missing Linux route inventory multipart flag"));
                    }
                    self.saw_record = true;
                    self.observe(body, target)?;
                }
                _ => return Err(invalid("unexpected Linux route inventory record")),
            }
        }
        Ok(false)
    }

    fn observe(&mut self, body: &[u8], target: DirectDefault) -> io::Result<()> {
        let Some((header, mut attributes)) = body.split_first_chunk::<ROUTE_HEADER>() else {
            return Err(invalid("short Linux route record"));
        };
        let [
            family,
            prefix,
            source_prefix,
            tos,
            short_table,
            protocol,
            scope,
            kind,
            ..,
        ] = *header;
        if family != target.family.native() {
            return Err(invalid("wrong Linux route family"));
        }
        let mut table = None;
        let mut interface = None;
        let mut metric = None;
        let flags = word(&header[8..])?;
        let mut plain = flags & !RTNH_F_LINKDOWN == 0;
        while !attributes.is_empty() {
            let (kind, value) = attribute(&mut attributes)?;
            match kind {
                libc::RTA_TABLE => unique(&mut table, value)?,
                libc::RTA_OIF => unique(&mut interface, value)?,
                libc::RTA_PRIORITY => unique(&mut metric, value)?,
                libc::RTA_DST if prefix == 0 => {
                    plain &= value.len() == target.family.address_bytes()
                        && value.iter().all(|&byte| byte == 0);
                }
                libc::RTA_CACHEINFO => {} // Kernel-generated lifetime statistics.
                RTA_PREF if target.family == Family::Ipv6 => plain &= value == [0],
                _ => plain = false,
            }
        }
        if table.unwrap_or(u32::from(short_table)) != target.table.get() {
            return Ok(());
        }
        self.inventory.occupied = true;
        if prefix != 0 || source_prefix != 0 || tos != 0 || protocol != libc::RTPROT_STATIC {
            self.inventory.unrelated = true;
            return Ok(());
        }
        // The deletion request includes the metric, original device, protocol,
        // scope and type. Nexthop groups can still contain that device.
        if metric != Some(target.metric.get())
            || interface.is_some_and(|index| index != target.interface.get())
        {
            self.inventory.unrelated = true;
            return Ok(());
        }
        if !plain
            || interface != Some(target.interface.get())
            || scope != target.family.expected_scope()
            || kind != libc::RTN_UNICAST
            || self.inventory.exact
        {
            self.inventory.conflicting = true;
        } else {
            self.inventory.exact = true;
        }
        Ok(())
    }
}

fn attribute<'a>(attributes: &mut &'a [u8]) -> io::Result<(u16, &'a [u8])> {
    let bytes = *attributes;
    let Some(&[len0, len1, kind0, kind1]) = bytes.first_chunk::<ATTRIBUTE_HEADER>() else {
        return Err(invalid("short Linux route attribute"));
    };
    let length = usize::from(u16::from_ne_bytes([len0, len1]));
    let kind = u16::from_ne_bytes([kind0, kind1]);
    let value = bytes
        .get(ATTRIBUTE_HEADER..length)
        .ok_or_else(|| invalid("invalid Linux route attribute length"))?;
    *attributes = if length == bytes.len() {
        &[]
    } else {
        bytes
            .get(aligned(length)?..)
            .ok_or_else(|| invalid("short Linux route attribute padding"))?
    };
    Ok((kind, value))
}

fn word(bytes: &[u8]) -> io::Result<u32> {
    bytes
        .first_chunk::<4>()
        .copied()
        .map(u32::from_ne_bytes)
        .ok_or_else(|| invalid("short Linux route inventory integer"))
}

fn unique(slot: &mut Option<u32>, value: &[u8]) -> io::Result<()> {
    if value.len() != 4 || slot.replace(word(value)?).is_some() {
        return Err(invalid("malformed or duplicate Linux route attribute"));
    }
    Ok(())
}

fn netlink_error(status: i32) -> io::Error {
    match status.checked_neg().filter(|&errno| errno > 0) {
        Some(errno) => io::Error::from_raw_os_error(errno),
        None => invalid("invalid Linux route inventory error"),
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
