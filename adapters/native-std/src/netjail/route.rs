//! Acknowledged Linux link, address and route operations for TESTING namespaces.
use super::PrivateNetworkNamespace;
use crate::linux_netlink::{Header, Socket, aligned};
use std::{
    io,
    net::Ipv4Addr,
    num::NonZeroU32,
    os::fd::{AsFd, AsRawFd},
    time::{Duration, Instant},
};

const CREATE: u16 = (libc::NLM_F_CREATE | libc::NLM_F_EXCL) as u16;
const REQUEST: u16 = (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16;
const NESTED: u16 = libc::NLA_F_NESTED as u16;
const TYPE_MASK: u16 = 0x3fff;
const VETH_INFO_PEER: u16 = 1; // linux/veth.h
const LINK_BODY_SIZE: usize = size_of::<libc::ifinfomsg>();
const ATTR_HEADER_SIZE: usize = size_of::<libc::rtattr>();
const RESPONSE_CAPACITY: usize = 32 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

/// Portable subset of Linux interface names for generated fixture links.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkName {
    bytes: [u8; libc::IFNAMSIZ],
    length: u8,
}

impl LinkName {
    /// Validate a nonempty ASCII interface name that fits Linux's `IFNAMSIZ`.
    pub fn new(name: &str) -> io::Result<Self> {
        let bytes = name.as_bytes();
        if bytes.is_empty()
            || bytes.len() >= libc::IFNAMSIZ
            || matches!(name, "." | "..")
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TESTING interface name",
            ));
        }
        let mut stored = [0; libc::IFNAMSIZ];
        stored[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: stored,
            length: (bytes.len() + 1) as u8,
        })
    }

    fn native(&self) -> &[u8] {
        &self.bytes[..usize::from(self.length)]
    }
}

/// A checked IPv4 subnet prefix width.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Prefix(u8);

impl Ipv4Prefix {
    /// Construct an IPv4 prefix in `0..=32`.
    pub fn new(bits: u8) -> io::Result<Self> {
        if bits > 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid IPv4 prefix width",
            ));
        }
        Ok(Self(bits))
    }

    /// Number of prefix bits.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    fn broadcast(self, address: Ipv4Addr) -> Option<Ipv4Addr> {
        (self.0 < 31).then(|| Ipv4Addr::from(u32::from(address) | (u32::MAX >> self.0)))
    }
}

/// Serialized route requests on a socket opened in a fresh TESTING namespace.
/// A failed exchange closes the request channel to prevent reusing an
/// uncertain socket state. The namespace owner handles fixture teardown.
pub struct RouteSocket {
    socket: Option<Socket>,
    sequence: u32,
    deadline: Instant,
}

impl RouteSocket {
    /// Open the native route socket in the retained private namespace.
    pub fn open(namespace: &PrivateNetworkNamespace, deadline: Instant) -> io::Result<Self> {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TESTING topology deadline elapsed",
            ));
        }
        let socket = namespace.with_worker(|| Socket::open(libc::NETLINK_ROUTE))?;
        Ok(Self {
            socket: Some(socket),
            sequence: 0,
            deadline,
        })
    }

    /// Exclusively create one bridge in this socket's namespace.
    pub fn create_bridge(&mut self, name: LinkName) -> io::Result<()> {
        let mut request = Message::link(libc::RTM_NEWLINK, None, false);
        request.attribute(libc::IFLA_IFNAME, name.native())?;
        request.nested(libc::IFLA_LINKINFO, |request| {
            request.attribute(libc::IFLA_INFO_KIND, c"bridge".to_bytes_with_nul())
        })?;
        self.mutate(request, CREATE)
    }

    /// Exclusively create a veth in this namespace and its peer in the exact
    /// retained private namespace designated by `peer_namespace`.
    pub fn create_veth(
        &mut self,
        host: LinkName,
        peer: LinkName,
        peer_namespace: &PrivateNetworkNamespace,
    ) -> io::Result<()> {
        let request = Message::veth(host, peer, peer_namespace.as_fd())?;
        self.mutate(request, CREATE)
    }

    /// Attach a link to the named bridge after a route-socket lookup of both.
    pub fn attach_to_bridge(&mut self, link: LinkName, bridge: LinkName) -> io::Result<()> {
        if link == bridge {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a bridge cannot be its own port",
            ));
        }
        let bridge_index = self.lookup(bridge, Some(c"bridge".to_bytes_with_nul()))?;
        let link_index = self.lookup(link, None)?;
        let mut request = Message::link(libc::RTM_NEWLINK, Some(link_index), false);
        request.attribute(libc::IFLA_MASTER, &bridge_index.get().to_ne_bytes())?;
        self.mutate(request, 0)
    }

    /// Bring the named interface up, including the fresh namespace's loopback.
    pub fn set_up(&mut self, link: LinkName) -> io::Result<()> {
        let index = self.lookup(link, None)?;
        self.mutate(Message::link(libc::RTM_NEWLINK, Some(index), true), 0)
    }

    /// Exclusively assign an IPv4 address and its broadcast where applicable.
    pub fn add_ipv4(
        &mut self,
        link: LinkName,
        address: Ipv4Addr,
        prefix: Ipv4Prefix,
    ) -> io::Result<()> {
        let index = self.lookup(link, None)?;
        let mut request = Message::new(libc::RTM_NEWADDR);
        request.extend(&[
            libc::AF_INET as u8,
            prefix.get(),
            0,
            libc::RT_SCOPE_UNIVERSE,
        ])?;
        request.extend(&index.get().to_ne_bytes())?;
        let ip = address.octets();
        request.attribute(libc::IFA_ADDRESS, &ip)?;
        request.attribute(libc::IFA_LOCAL, &ip)?;
        if let Some(broadcast) = prefix.broadcast(address) {
            request.attribute(libc::IFA_BROADCAST, &broadcast.octets())?;
        }
        self.mutate(request, CREATE)
    }

    /// Declare an IPv4 gateway address reachable on the named interface.
    pub fn add_on_link_route(&mut self, link: LinkName, host: Ipv4Addr) -> io::Result<()> {
        let index = self.lookup(link, None)?;
        let mut request = Message::route(32, libc::RT_SCOPE_LINK, index)?;
        request.attribute(libc::RTA_DST, &host.octets())?;
        self.mutate(request, CREATE)
    }

    /// Retire only the legacy lowest-address broadcast route generated by the
    /// kernel for the original interface, while keeping its connected prefix.
    /// On kernels where the lowest address is unicast the route is absent.
    pub fn remove_legacy_broadcast(
        &mut self,
        link: LinkName,
        boundary: Ipv4Addr,
        source: Ipv4Addr,
    ) -> io::Result<()> {
        let index = self.lookup(link, None)?;
        let mut request = Message::new(libc::RTM_DELROUTE);
        request.extend(&[
            libc::AF_INET as u8,
            32,
            0,
            0,
            libc::RT_TABLE_LOCAL,
            libc::RTPROT_KERNEL,
            libc::RT_SCOPE_LINK,
            libc::RTN_BROADCAST,
            0,
            0,
            0,
            0,
        ])?;
        request.attribute(libc::RTA_OIF, &index.get().to_ne_bytes())?;
        request.attribute(libc::RTA_DST, &boundary.octets())?;
        request.attribute(libc::RTA_PREFSRC, &source.octets())?;
        self.mutate(request, 0)
    }

    /// Exclusively install the IPv4 default route through the specified gateway.
    pub fn add_default_route(&mut self, link: LinkName, gateway: Ipv4Addr) -> io::Result<()> {
        self.add_gateway_route(link, None, gateway)
    }

    /// Route one IPv4 host through the selected next hop.
    pub fn add_host_route_via(
        &mut self,
        link: LinkName,
        host: Ipv4Addr,
        gateway: Ipv4Addr,
    ) -> io::Result<()> {
        self.add_gateway_route(link, Some(host), gateway)
    }

    fn add_gateway_route(
        &mut self,
        link: LinkName,
        host: Option<Ipv4Addr>,
        gateway: Ipv4Addr,
    ) -> io::Result<()> {
        let index = self.lookup(link, None)?;
        let mut request = Message::route(
            if host.is_some() { 32 } else { 0 },
            libc::RT_SCOPE_UNIVERSE,
            index,
        )?;
        if let Some(host) = host {
            request.attribute(libc::RTA_DST, &host.octets())?;
        }
        request.attribute(libc::RTA_GATEWAY, &gateway.octets())?;
        self.mutate(request, CREATE)
    }

    fn lookup(&mut self, name: LinkName, kind: Option<&[u8]>) -> io::Result<NonZeroU32> {
        let mut request = Message::link(libc::RTM_GETLINK, None, false);
        request.attribute(libc::IFLA_IFNAME, name.native())?;
        let mut index = None;
        self.exchange(request, 0, |body| {
            if index.is_some() {
                return Err(invalid("duplicate route link reply"));
            }
            index = Some(link_index(body, name, kind)?);
            Ok(())
        })?;
        index.ok_or_else(|| {
            self.socket = None;
            invalid("missing route link reply")
        })
    }

    fn mutate(&mut self, request: Message, flags: u16) -> io::Result<()> {
        self.exchange(request, flags, |_| {
            Err(invalid("unexpected route link reply"))
        })
    }

    fn exchange(
        &mut self,
        mut request: Message,
        flags: u16,
        link_reply: impl FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| invalid("route request sequence exhausted"))?;
        let socket = self.socket.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "route request channel is closed")
        })?;
        let header = Header {
            length: request.end as u32,
            kind: request.kind,
            flags: REQUEST | flags,
            sequence: self.sequence,
            port: socket.port(),
        };
        header.write(&mut request.bytes)?;
        let deadline = Instant::now()
            .checked_add(REQUEST_TIMEOUT)
            .map_or(self.deadline, |limit| self.deadline.min(limit));
        socket.send(&request.bytes[..request.end], deadline)?;
        acknowledge(&socket, header, deadline, link_reply)?;
        self.socket = Some(socket);
        Ok(())
    }
}

fn acknowledge(
    socket: &Socket,
    request: Header,
    deadline: Instant,
    mut link_reply: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    let mut buffer = [0; RESPONSE_CAPACITY];
    let mut acknowledged = false;
    // A single lookup has one NEWLINK response followed by one ACK. Mutations have only an ACK.
    for _ in 0..2 {
        let length = socket.receive(&mut buffer, deadline)?;
        let mut records = &buffer[..length];
        while !records.is_empty() {
            let (reply, body) = Header::take(&mut records)?;
            if acknowledged
                || reply.port != request.port
                || reply.sequence != request.sequence
                || i32::from(reply.flags) & (libc::NLM_F_MULTI | libc::NLM_F_DUMP_INTR) != 0
            {
                return Err(invalid("route reply does not match the original request"));
            }
            match reply.kind {
                kind if kind == libc::NLMSG_ERROR as u16 => {
                    let (status, echo) = body
                        .split_first_chunk::<4>()
                        .ok_or_else(|| invalid("short route ACK status"))?;
                    if Header::read(echo)? != request {
                        return Err(invalid("route ACK echoes a different request"));
                    }
                    let status = i32::from_ne_bytes(*status);
                    if status != 0 {
                        let errno = status
                            .checked_neg()
                            .filter(|value| *value > 0)
                            .ok_or_else(|| invalid("invalid route ACK status"))?;
                        if request.kind != libc::RTM_DELROUTE || errno != libc::ESRCH {
                            return Err(io::Error::from_raw_os_error(errno));
                        }
                    }
                    acknowledged = true;
                }
                libc::RTM_NEWLINK => link_reply(body)?,
                _ => return Err(invalid("unexpected route reply type")),
            }
        }
        if acknowledged {
            return Ok(());
        }
    }
    Err(invalid("route request was not acknowledged"))
}

fn link_index(body: &[u8], name: LinkName, kind: Option<&[u8]>) -> io::Result<NonZeroU32> {
    let (info, attrs) = body
        .split_first_chunk::<LINK_BODY_SIZE>()
        .ok_or_else(|| invalid("short interface information"))?;
    let raw = i32::from_ne_bytes([info[4], info[5], info[6], info[7]]);
    let index = u32::try_from(raw)
        .ok()
        .and_then(NonZeroU32::new)
        .ok_or_else(|| invalid("invalid native interface index"))?;
    if attribute(attrs, libc::IFLA_IFNAME)? != Some(name.native()) {
        return Err(invalid("route reply reports a different interface name"));
    }
    if let Some(expected) = kind {
        let info = attribute(attrs, libc::IFLA_LINKINFO)?
            .ok_or_else(|| invalid("route reply lacks interface kind"))?;
        if attribute(info, libc::IFLA_INFO_KIND)? != Some(expected) {
            return Err(invalid("route reply reports a different interface kind"));
        }
    }
    Ok(index)
}

fn attribute(mut bytes: &[u8], wanted: u16) -> io::Result<Option<&[u8]>> {
    let mut found = None;
    while !bytes.is_empty() {
        let &[len0, len1, kind0, kind1] = bytes
            .first_chunk::<ATTR_HEADER_SIZE>()
            .ok_or_else(|| invalid("short native interface attribute"))?;
        let length = usize::from(u16::from_ne_bytes([len0, len1]));
        let kind = u16::from_ne_bytes([kind0, kind1]);
        let value = bytes
            .get(ATTR_HEADER_SIZE..length)
            .ok_or_else(|| invalid("invalid native interface attribute extent"))?;
        if kind & TYPE_MASK == wanted && found.replace(value).is_some() {
            return Err(invalid("duplicate native interface attribute"));
        }
        bytes = if length == bytes.len() {
            &[]
        } else {
            bytes
                .get(aligned(length)?..)
                .ok_or_else(|| invalid("invalid native interface attribute padding"))?
        };
    }
    Ok(found)
}

struct Message {
    kind: u16,
    bytes: [u8; 256],
    end: usize,
}

impl Message {
    fn new(kind: u16) -> Self {
        Self {
            kind,
            bytes: [0; 256],
            end: Header::SIZE,
        }
    }

    fn link(kind: u16, index: Option<NonZeroU32>, up: bool) -> Self {
        let mut message = Self::new(kind);
        let start = message.end;
        message.end += LINK_BODY_SIZE;
        let body = &mut message.bytes[start..message.end];
        if let Some(index) = index {
            body[4..8].copy_from_slice(&index.get().to_ne_bytes());
        }
        if up {
            let state = libc::IFF_UP.cast_unsigned().to_ne_bytes();
            body[8..12].copy_from_slice(&state);
            body[12..16].copy_from_slice(&state);
        }
        message
    }

    fn route(prefix: u8, scope: u8, index: NonZeroU32) -> io::Result<Self> {
        let mut message = Self::new(libc::RTM_NEWROUTE);
        message.extend(&[
            libc::AF_INET as u8,
            prefix,
            0,
            0,
            libc::RT_TABLE_MAIN,
            libc::RTPROT_STATIC,
            scope,
            libc::RTN_UNICAST,
            0,
            0,
            0,
            0,
        ])?;
        message.attribute(libc::RTA_OIF, &index.get().to_ne_bytes())?;
        Ok(message)
    }

    fn veth(
        host: LinkName,
        peer: LinkName,
        namespace: std::os::fd::BorrowedFd<'_>,
    ) -> io::Result<Self> {
        let mut message = Self::link(libc::RTM_NEWLINK, None, false);
        message.attribute(libc::IFLA_IFNAME, host.native())?;
        message.nested(libc::IFLA_LINKINFO, |message| {
            message.attribute(libc::IFLA_INFO_KIND, c"veth".to_bytes_with_nul())?;
            message.nested(libc::IFLA_INFO_DATA, |message| {
                message.encode_attribute(VETH_INFO_PEER, |message| {
                    message.extend(&[0; LINK_BODY_SIZE])?;
                    message.attribute(libc::IFLA_IFNAME, peer.native())?;
                    message.attribute(libc::IFLA_NET_NS_FD, &namespace.as_raw_fd().to_ne_bytes())
                })
            })
        })?;
        Ok(message)
    }

    fn extend(&mut self, value: &[u8]) -> io::Result<()> {
        let end = self
            .end
            .checked_add(value.len())
            .ok_or_else(|| invalid("route request length overflow"))?;
        self.bytes
            .get_mut(self.end..end)
            .ok_or_else(|| invalid("route request exceeds capacity"))?
            .copy_from_slice(value);
        self.end = end;
        Ok(())
    }

    fn attribute(&mut self, kind: u16, value: &[u8]) -> io::Result<()> {
        self.encode_attribute(kind, |message| message.extend(value))
    }

    fn nested(
        &mut self,
        kind: u16,
        entries: impl FnOnce(&mut Self) -> io::Result<()>,
    ) -> io::Result<()> {
        self.encode_attribute(kind | NESTED, entries)
    }

    fn encode_attribute(
        &mut self,
        kind: u16,
        contents: impl FnOnce(&mut Self) -> io::Result<()>,
    ) -> io::Result<()> {
        let start = self.end;
        self.extend(&[0; ATTR_HEADER_SIZE])?;
        contents(self)?;
        let length = (self.end - start) as u16;
        self.extend(&[0; 3][..aligned(self.end)? - self.end])?;
        self.bytes[start..start + 2].copy_from_slice(&length.to_ne_bytes());
        self.bytes[start + 2..start + 4].copy_from_slice(&kind.to_ne_bytes());
        Ok(())
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assert the exact UAPI attribute shape after fallible encoding"
    )]
    fn veth_namespace_descriptor_is_nested_after_the_peer_link_header() -> io::Result<()> {
        let host = LinkName::new("fixture-host")?;
        let peer = LinkName::new("fixture-peer")?;
        let descriptor = File::open("/dev/null")?;
        let message = Message::veth(host, peer, descriptor.as_fd())?;
        assert_eq!(message.kind, libc::RTM_NEWLINK);
        let attrs = &message.bytes[Header::SIZE + LINK_BODY_SIZE..message.end];
        assert_eq!(attribute(attrs, libc::IFLA_IFNAME)?, Some(host.native()));
        let Some(info) = attribute(attrs, libc::IFLA_LINKINFO)? else {
            return Err(invalid("missing veth link information"));
        };
        assert_eq!(
            attribute(info, libc::IFLA_INFO_KIND)?,
            Some(c"veth".to_bytes_with_nul())
        );
        let Some(data) = attribute(info, libc::IFLA_INFO_DATA)? else {
            return Err(invalid("missing veth link data"));
        };
        let Some(peer_info) = attribute(data, VETH_INFO_PEER)? else {
            return Err(invalid("missing veth peer information"));
        };
        let (header, peer_attrs) = peer_info
            .split_first_chunk::<LINK_BODY_SIZE>()
            .ok_or_else(|| invalid("veth peer lost its ifinfomsg"))?;
        assert_eq!(*header, [0; LINK_BODY_SIZE]);
        assert_eq!(
            attribute(peer_attrs, libc::IFLA_IFNAME)?,
            Some(peer.native())
        );
        assert_eq!(
            attribute(peer_attrs, libc::IFLA_NET_NS_FD)?,
            Some(descriptor.as_raw_fd().to_ne_bytes().as_slice())
        );
        assert_eq!(attribute(attrs, libc::IFLA_NET_NS_FD)?, None);
        Ok(())
    }
}
