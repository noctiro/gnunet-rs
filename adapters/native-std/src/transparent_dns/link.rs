//! Bounded kernel-origin route-link notifications without policy mutation.
use super::NetworkNamespace;
use crate::linux_netlink::{Header, Socket, aligned};
use std::{
    ffi::CStr,
    fmt, io,
    mem::size_of,
    num::NonZeroU32,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};

/// Suggested bounded receive storage; a larger native message fails closed.
pub const EVENT_BUFFER_BYTES: usize = 64 * 1024;
const ATTR_TYPE_MASK: u16 = 0x3fff;
const LINK_QUERY_TIMEOUT: Duration = Duration::from_millis(10);

/// The original reported interface role from `ifinfomsg.ifi_flags`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkRole {
    /// The kernel reported a loopback interface.
    Loopback,
    /// The kernel reported a non-loopback interface.
    Network,
}

/// Parent and link kind from one kernel route-link record.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinkAttachment {
    /// Current master interface, when present in the record.
    pub master: Option<NonZeroU32>,
    /// The native link kind is `vrf`.
    pub vrf: bool,
}

/// One actual interface notification from the kernel route socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkEvent<'name> {
    /// RTM_NEWLINK reports creation or a link-state/property change.
    Changed {
        /// Positive native interface index observed in this message.
        ifindex: u32,
        /// The original `IFLA_IFNAME` in this notification, when present.
        name: Option<&'name CStr>,
        /// The same notification's interface role.
        role: LinkRole,
        /// Master membership and kind from the same notification.
        attachment: LinkAttachment,
    },
    /// RTM_DELLINK reports removal of this interface index.
    Deleted {
        /// Positive native interface index observed in this message.
        ifindex: u32,
    },
}

pub(super) struct LinkRecord<'name> {
    pub(super) index: NonZeroU32,
    pub(super) role: LinkRole,
    pub(super) name: Option<&'name CStr>,
    pub(super) attachment: LinkAttachment,
}

enum LinkSelector<'name> {
    Name(&'name CStr),
    Index(NonZeroU32),
}

/// A separate kernel-unicast socket preserves the monitor's original backlog.
#[derive(Debug)]
pub(super) struct LinkQuery {
    socket: Socket,
    namespace: NetworkNamespace,
    sequence: u32,
    buffer: Vec<u8>,
    startup_until: Option<Instant>,
}

impl LinkQuery {
    #[cfg(test)]
    pub(super) const fn fixture(descriptor: OwnedFd, namespace: NetworkNamespace) -> Self {
        Self {
            socket: Socket::fixture(descriptor),
            namespace,
            sequence: 0,
            buffer: Vec::new(),
            startup_until: None,
        }
    }

    pub(super) fn open(startup_until: Option<Instant>) -> io::Result<Self> {
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(EVENT_BUFFER_BYTES)
            .map_err(io::Error::other)?;
        buffer.resize(EVENT_BUFFER_BYTES, 0);
        let socket = Socket::open(libc::NETLINK_ROUTE)?;
        let namespace = NetworkNamespace::observe(socket.as_fd())?;
        Ok(Self {
            socket,
            namespace,
            sequence: 0,
            buffer,
            startup_until,
        })
    }

    pub(super) fn finish_startup(&mut self) {
        self.startup_until = None;
    }

    pub(super) const fn namespace(&self) -> NetworkNamespace {
        self.namespace
    }

    pub(super) fn by_name(&mut self, name: &CStr) -> io::Result<LinkRecord<'_>> {
        let record = self.lookup(LinkSelector::Name(name))?;
        if record.name != Some(name) {
            return Err(invalid("native link lookup returned another name"));
        }
        Ok(record)
    }

    pub(super) fn by_index(&mut self, index: NonZeroU32) -> io::Result<LinkRecord<'_>> {
        let record = self.lookup(LinkSelector::Index(index))?;
        if record.index != index || record.name.is_none() {
            return Err(invalid("native link lookup returned another index"));
        }
        Ok(record)
    }

    fn advance_sequence(&mut self, open: impl FnOnce() -> io::Result<Socket>) -> io::Result<u32> {
        let sequence = if let Some(sequence) = self.sequence.checked_add(1) {
            sequence
        } else {
            // Bind a distinct port while the old port remains owned. Late
            // responses to the old sequence space stay on the old descriptor.
            let replacement = open()?;
            self.namespace
                .require(NetworkNamespace::observe(replacement.as_fd())?)?;
            self.socket = replacement;
            1
        };
        self.sequence = sequence;
        Ok(sequence)
    }

    fn lookup(&mut self, selector: LinkSelector<'_>) -> io::Result<LinkRecord<'_>> {
        const PREFIX: usize = Header::SIZE + size_of::<libc::ifinfomsg>();
        const ATTRIBUTE: usize = size_of::<libc::rtattr>();
        let mut request = [0; PREFIX + ATTRIBUTE + libc::IFNAMSIZ];
        let mut length = PREFIX;
        match selector {
            LinkSelector::Index(index) => {
                request[Header::SIZE + 4..Header::SIZE + 8]
                    .copy_from_slice(&index.get().to_ne_bytes());
            }
            LinkSelector::Name(name) => {
                let name = name.to_bytes_with_nul();
                let attr_len = ATTRIBUTE + name.len();
                if name.len() > libc::IFNAMSIZ {
                    return Err(invalid("native link lookup name is too long"));
                }
                request[PREFIX..PREFIX + 2].copy_from_slice(&(attr_len as u16).to_ne_bytes());
                request[PREFIX + 2..PREFIX + ATTRIBUTE]
                    .copy_from_slice(&libc::IFLA_IFNAME.to_ne_bytes());
                request[PREFIX + ATTRIBUTE..PREFIX + attr_len].copy_from_slice(name);
                length += aligned(attr_len)?;
            }
        }
        let now = Instant::now();
        let deadline = now + LINK_QUERY_TIMEOUT;
        let deadline = self
            .startup_until
            .map_or(deadline, |limit| deadline.min(limit));
        if deadline <= now {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let sequence = self.advance_sequence(|| Socket::open(libc::NETLINK_ROUTE))?;
        let header = Header {
            length: length as u32,
            kind: libc::RTM_GETLINK,
            flags: libc::NLM_F_REQUEST as u16,
            sequence,
            port: self.socket.port(),
        };
        header.write(&mut request)?;
        self.socket.send(&request[..length], deadline)?;
        let used = loop {
            let used = self.socket.receive(&mut self.buffer, deadline)?;
            let reply = Header::read(&self.buffer[..used])?;
            if reply.port != header.port || reply.sequence == 0 || reply.sequence > sequence {
                return Err(invalid("foreign native link query response"));
            }
            if reply.sequence == sequence {
                break used;
            }
            // An expired earlier read can leave a late kernel answer. Its
            // sequence cannot carry identity for this or any later request.
        };
        let mut bytes = &self.buffer[..used];
        let (reply, body) = Header::take(&mut bytes)?;
        if !bytes.is_empty()
            || i32::from(reply.flags) & (libc::NLM_F_MULTI | libc::NLM_F_DUMP_INTR) != 0
        {
            return Err(invalid("invalid native single-link query response"));
        }
        match reply.kind {
            libc::RTM_NEWLINK => link_record(body),
            _ if i32::from(reply.kind) == libc::NLMSG_ERROR => {
                let Some((status, echo)) = body.split_first_chunk::<4>() else {
                    return Err(invalid("short native link query acknowledgement"));
                };
                if Header::read(echo)? != header {
                    return Err(invalid("native link query error echoes a foreign request"));
                }
                native_error(status)?;
                Err(invalid("native link query returned no link"))
            }
            _ => Err(invalid("unexpected native link query result")),
        }
    }
}

/// The original owned NETLINK_ROUTE subscription and its namespace.
#[derive(Debug)]
pub struct LinkMonitor {
    socket: OwnedFd,
    namespace: NetworkNamespace,
}

impl LinkMonitor {
    /// Subscribe in the calling network namespace to actual link notifications.
    /// No dump request, route, rule, interface or privilege change is issued.
    ///
    /// # Errors
    /// Preserves native socket/bind/identity errors; no partial fd escapes.
    #[expect(
        unsafe_code,
        reason = "own and bind one real nonblocking CLOEXEC NETLINK_ROUTE socket"
    )]
    pub fn subscribe() -> io::Result<Self> {
        // SAFETY: native scalar socket parameters borrow no memory.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the successful new descriptor is transferred exactly once.
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: sockaddr_nl has an integer-only zero representation.
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        address.nl_groups = libc::RTMGRP_LINK.cast_unsigned();
        // SAFETY: exact initialized native address; zero pid requests autobind.
        if unsafe {
            libc::bind(
                socket.as_raw_fd(),
                (&raw const address).cast(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let namespace = NetworkNamespace::observe(socket.as_fd())?;
        Ok(Self { socket, namespace })
    }

    /// Kernel namespace of the original route-link subscription socket.
    #[must_use]
    pub const fn namespace(&self) -> NetworkNamespace {
        self.namespace
    }

    /// Consume at most one complete datagram from the original subscription.
    /// Every callback is a kernel observation; it does not pin an interface.
    ///
    /// # Errors
    /// Preserves native errors, including WouldBlock and ENOBUFS. Refuses a
    /// non-kernel sender or malformed native header/body/attribute extent.
    /// Use [`Self::is_notification_loss`] to recognize lost kernel evidence.
    #[expect(
        unsafe_code,
        reason = "recvmsg writes only the supplied bounded payload and initialized native source/iovec storage"
    )]
    pub fn read<'name>(
        &self,
        buffer: &'name mut [u8],
        mut event: impl FnMut(LinkEvent<'name>),
    ) -> io::Result<()> {
        if buffer.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "link event buffer is empty",
            ));
        }
        // SAFETY: these native output records permit initialized zero storage.
        let mut source: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        // SAFETY: msghdr permits all-zero pointers, counts and flags before setup.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        let mut vector = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: buffer.len(),
        };
        message.msg_name = (&raw mut source).cast();
        message.msg_namelen = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        message.msg_iov = &raw mut vector;
        message.msg_iovlen = 1;
        // SAFETY: every output extent is live and exclusive until return.
        let received = unsafe {
            libc::recvmsg(
                self.socket.as_raw_fd(),
                &raw mut message,
                libc::MSG_DONTWAIT,
            )
        };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        let received =
            usize::try_from(received).map_err(|_| invalid("link message length overflow"))?;
        // nlmsg_pid can describe an initiating user request. Only recvmsg's
        // actual source port identifies kernel origin; a header pid cannot.
        let kernel_sender = message.msg_namelen as usize == size_of::<libc::sockaddr_nl>()
            && i32::from(source.nl_family) == libc::AF_NETLINK
            && source.nl_pid == 0;
        let packet = notification_payload(buffer, received, message.msg_flags, kernel_sender)?;
        parse(packet, &mut event)
    }

    /// Whether this receive error proves that native link observations are
    /// incomplete. Discard the old capture generation and resubscribe before
    /// using a replacement snapshot.
    #[must_use]
    pub fn is_notification_loss(error: &io::Error) -> bool {
        error.raw_os_error() == Some(libc::ENOBUFS)
            || error
                .get_ref()
                .is_some_and(|source| source.is::<NotificationLoss>())
    }
}

impl AsFd for LinkMonitor {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }
}

impl AsRawFd for LinkMonitor {
    fn as_raw_fd(&self) -> i32 {
        self.socket.as_raw_fd()
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Debug)]
enum NotificationLoss {
    Truncated,
    InterruptedDump,
}

impl fmt::Display for NotificationLoss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated native link notification",
            Self::InterruptedDump => "native link dump was interrupted",
        })
    }
}

impl std::error::Error for NotificationLoss {}

fn notification_payload(
    bytes: &[u8],
    received: usize,
    flags: libc::c_int,
    kernel_sender: bool,
) -> io::Result<&[u8]> {
    if !kernel_sender {
        return Err(invalid(
            "link notification did not originate from the kernel",
        ));
    }
    let truncated = || io::Error::new(io::ErrorKind::InvalidData, NotificationLoss::Truncated);
    if flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(truncated());
    }
    bytes.get(..received).ok_or_else(truncated)
}

fn parse<'name>(
    mut bytes: &'name [u8],
    event: &mut impl FnMut(LinkEvent<'name>),
) -> io::Result<()> {
    if bytes.is_empty() {
        return Err(invalid("empty native link notification"));
    }
    while !bytes.is_empty() {
        let (header, body) = Header::take(&mut bytes)?;
        if i32::from(header.flags) & libc::NLM_F_DUMP_INTR != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                NotificationLoss::InterruptedDump,
            ));
        }
        match i32::from(header.kind) {
            libc::NLMSG_OVERRUN => return Err(io::Error::from_raw_os_error(libc::ENOBUFS)),
            libc::NLMSG_ERROR => {
                if body.len() < size_of::<i32>() + size_of::<libc::nlmsghdr>() {
                    return Err(invalid("short native link error record"));
                }
                native_error(body)?;
            }
            libc::NLMSG_DONE => {
                if !body.is_empty() {
                    native_error(body)?;
                }
            }
            kind if kind == i32::from(libc::RTM_NEWLINK)
                || kind == i32::from(libc::RTM_DELLINK) =>
            {
                let record = link_record(body)?;
                let ifindex = record.index.get();
                event(if kind == i32::from(libc::RTM_DELLINK) {
                    LinkEvent::Deleted { ifindex }
                } else {
                    LinkEvent::Changed {
                        ifindex,
                        name: record.name,
                        role: record.role,
                        attachment: record.attachment,
                    }
                });
            }
            _ => {}
        }
    }
    Ok(())
}

fn native_error(body: &[u8]) -> io::Result<()> {
    let code: [u8; 4] = body
        .get(..size_of::<i32>())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| invalid("short native link status"))?;
    let code = i32::from_ne_bytes(code);
    if code == 0 {
        return Ok(());
    }
    let errno = code
        .checked_neg()
        .filter(|errno| *errno > 0)
        .ok_or_else(|| invalid("invalid native link error status"))?;
    Err(io::Error::from_raw_os_error(errno))
}

#[expect(
    unsafe_code,
    reason = "only a complete integer-only native ifinfomsg is copied from bounded initialized bytes"
)]
fn link_record(body: &[u8]) -> io::Result<LinkRecord<'_>> {
    let (info, mut bytes) = body
        .split_first_chunk::<{ size_of::<libc::ifinfomsg>() }>()
        .ok_or_else(|| invalid("short native interface record"))?;
    // SAFETY: checked complete integer-only native link record.
    let link = unsafe { info.as_ptr().cast::<libc::ifinfomsg>().read_unaligned() };
    let index = u32::try_from(link.ifi_index)
        .ok()
        .and_then(NonZeroU32::new)
        .ok_or_else(|| invalid("native link has no positive interface index"))?;
    let role = if link.ifi_flags & libc::IFF_LOOPBACK.cast_unsigned() != 0 {
        LinkRole::Loopback
    } else {
        LinkRole::Network
    };
    let mut name = None;
    let mut master = None;
    let mut link_info = None;
    while !bytes.is_empty() {
        let (kind, payload) = attribute(&mut bytes)?;
        match kind {
            libc::IFLA_IFNAME => {
                if name.is_some() || !(2..=libc::IFNAMSIZ).contains(&payload.len()) {
                    return Err(invalid("invalid or duplicate native interface name"));
                }
                name = Some(
                    CStr::from_bytes_with_nul(payload)
                        .map_err(|_| invalid("invalid native interface name terminator"))?,
                );
            }
            libc::IFLA_MASTER => {
                if master.is_some() {
                    return Err(invalid("duplicate native interface master"));
                }
                let bytes = <[u8; 4]>::try_from(payload)
                    .map_err(|_| invalid("invalid native interface master size"))?;
                master = Some(
                    NonZeroU32::new(u32::from_ne_bytes(bytes))
                        .filter(|master| master.get() <= i32::MAX as u32 && *master != index)
                        .ok_or_else(|| invalid("invalid native interface master index"))?,
                );
            }
            libc::IFLA_LINKINFO => {
                if link_info.is_some() {
                    return Err(invalid("duplicate native interface link info"));
                }
                link_info = Some(is_vrf(payload)?);
            }
            _ => {}
        }
    }
    Ok(LinkRecord {
        index,
        role,
        name,
        attachment: LinkAttachment {
            master,
            vrf: link_info.unwrap_or_default(),
        },
    })
}

fn is_vrf(mut bytes: &[u8]) -> io::Result<bool> {
    let mut kind = None;
    while !bytes.is_empty() {
        let (attribute_type, payload) = attribute(&mut bytes)?;
        if attribute_type == libc::IFLA_INFO_KIND {
            if kind.is_some() {
                return Err(invalid("duplicate native interface kind"));
            }
            kind = Some(
                CStr::from_bytes_with_nul(payload)
                    .map_err(|_| invalid("invalid native interface kind"))?,
            );
        }
    }
    Ok(kind == Some(c"vrf"))
}

fn attribute<'a>(bytes: &mut &'a [u8]) -> io::Result<(u16, &'a [u8])> {
    let record = *bytes;
    let Some(([lo, hi, type_lo, type_hi], _)) = record.split_first_chunk::<4>() else {
        return Err(invalid("short native link attribute"));
    };
    let length = usize::from(u16::from_ne_bytes([*lo, *hi]));
    let payload = record
        .get(size_of::<libc::rtattr>()..length)
        .ok_or_else(|| invalid("invalid native link attribute extent"))?;
    *bytes = if length == record.len() {
        &[]
    } else {
        record
            .get(aligned(length)?..)
            .ok_or_else(|| invalid("truncated native link attribute padding"))?
    };
    Ok((
        u16::from_ne_bytes([*type_lo, *type_hi]) & ATTR_TYPE_MASK,
        payload,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::File, num::NonZeroU64};

    #[test]
    fn query_rollover_uses_a_distinct_port_and_retains_its_bounds() -> io::Result<()> {
        let until = Instant::now() + Duration::from_secs(1);
        let mut query = LinkQuery::open(Some(until))?;
        let original_port = query.socket.port();
        let original_buffer = query.buffer.as_ptr();
        let original_namespace = query.namespace();
        query.sequence = u32::MAX - 1;

        let last = query.advance_sequence(|| Err(io::ErrorKind::Unsupported.into()))?;
        if last != u32::MAX || query.socket.port() != original_port {
            return Err(invalid("query socket changed before sequence exhaustion"));
        }
        let first = query.advance_sequence(|| Socket::open(libc::NETLINK_ROUTE))?;
        if first != 1
            || query.socket.port() == original_port
            || query.namespace() != original_namespace
            || query.buffer.as_ptr() != original_buffer
            || query.startup_until != Some(until)
        {
            return Err(invalid("query rollover lost its port isolation or bounds"));
        }
        Ok(())
    }

    #[test]
    fn failed_query_replacements_keep_the_original_sequence_and_descriptor() -> io::Result<()> {
        let namespace = NetworkNamespace::fixture(NonZeroU64::MIN);
        let original = OwnedFd::from(File::open("/dev/null")?);
        let original_fd = original.as_raw_fd();
        let mut query = LinkQuery::fixture(original, namespace);
        query.sequence = u32::MAX;

        let open_error = query.advance_sequence(|| Err(io::ErrorKind::PermissionDenied.into()));
        let invalid_socket = Socket::fixture(OwnedFd::from(File::open("/dev/null")?));
        let observe_error = query.advance_sequence(|| Ok(invalid_socket));
        if !matches!(open_error, Err(error) if error.kind() == io::ErrorKind::PermissionDenied)
            || !matches!(observe_error, Err(error) if error.raw_os_error() == Some(libc::ENOTSOCK))
            || query.sequence != u32::MAX
            || query.socket.as_fd().as_raw_fd() != original_fd
            || query.namespace() != namespace
        {
            return Err(invalid(
                "query rollover failure replaced the original owner",
            ));
        }
        Ok(())
    }

    #[expect(
        unsafe_code,
        reason = "write only fully initialized native integer-only netlink fixture records into owned aligned-independent bytes"
    )]
    fn packet(kind: u16, index: i32, role: LinkRole) -> io::Result<Vec<u8>> {
        let size = size_of::<libc::nlmsghdr>() + size_of::<libc::ifinfomsg>();
        let mut packet = vec![0; size];
        let header = libc::nlmsghdr {
            nlmsg_len: u32::try_from(size).map_err(io::Error::other)?,
            nlmsg_type: kind,
            nlmsg_flags: 0,
            nlmsg_seq: 0,
            nlmsg_pid: 0,
        };
        // SAFETY: the integer-only fixture is initialized before selecting index.
        let mut link: libc::ifinfomsg = unsafe { std::mem::zeroed() };
        link.ifi_index = index;
        if role == LinkRole::Loopback {
            link.ifi_flags = libc::IFF_LOOPBACK.cast_unsigned();
        }
        // SAFETY: both complete extents are owned; unaligned writes avoid any
        // assumption about Vec<u8> alignment and the native records are initialized.
        unsafe {
            packet
                .as_mut_ptr()
                .cast::<libc::nlmsghdr>()
                .write_unaligned(header);
            packet
                .as_mut_ptr()
                .add(size_of::<libc::nlmsghdr>())
                .cast::<libc::ifinfomsg>()
                .write_unaligned(link);
        }
        Ok(packet)
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assert bounded parser outcomes without opening any native socket"
    )]
    fn complete_link_batches_preserve_actual_indices_and_reported_role() -> io::Result<()> {
        let mut bytes = packet(libc::RTM_NEWLINK, 7, LinkRole::Loopback)?;
        bytes.extend_from_slice(&packet(libc::RTM_DELLINK, 9, LinkRole::Network)?);
        let mut events = Vec::new();
        parse(&bytes, &mut |event| events.push(event))?;
        assert_eq!(
            events,
            [
                LinkEvent::Changed {
                    ifindex: 7,
                    name: None,
                    role: LinkRole::Loopback,
                    attachment: LinkAttachment::default(),
                },
                LinkEvent::Deleted { ifindex: 9 }
            ]
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assert the exact native notification and validate fixture construction"
    )]
    fn original_name_is_preserved_and_must_have_one_valid_extent() -> io::Result<()> {
        let name = c"renamed";
        let add_name = |bytes: &mut Vec<u8>, payload: &[u8]| -> io::Result<()> {
            let length = size_of::<libc::rtattr>() + payload.len();
            let length_field = u16::try_from(length).map_err(io::Error::other)?;
            bytes.extend_from_slice(&length_field.to_ne_bytes());
            bytes.extend_from_slice(&libc::IFLA_IFNAME.to_ne_bytes());
            bytes.extend_from_slice(payload);
            bytes.resize(bytes.len() + aligned(length)? - length, 0);
            let size = u32::try_from(bytes.len()).map_err(io::Error::other)?;
            bytes[..size_of::<u32>()].copy_from_slice(&size.to_ne_bytes());
            Ok(())
        };
        let mut valid = packet(libc::RTM_NEWLINK, 7, LinkRole::Network)?;
        add_name(&mut valid, name.to_bytes_with_nul())?;
        let mut expected = None;
        parse(&valid, &mut |event| expected = Some(event))?;
        assert_eq!(
            expected,
            Some(LinkEvent::Changed {
                ifindex: 7,
                name: Some(name),
                role: LinkRole::Network,
                attachment: LinkAttachment::default(),
            })
        );

        for payload in [b"unterminated".as_slice(), b"split\0name\0", b"\0"] {
            let mut malformed = packet(libc::RTM_NEWLINK, 7, LinkRole::Network)?;
            add_name(&mut malformed, payload)?;
            assert!(parse(&malformed, &mut |_| {}).is_err());
        }
        add_name(&mut valid, c"original".to_bytes_with_nul())?;
        assert!(parse(&valid, &mut |_| {}).is_err());
        Ok(())
    }

    #[test]
    fn original_vrf_attributes_are_qualified_from_the_same_snapshot() -> io::Result<()> {
        fn append(bytes: &mut Vec<u8>, kind: u16, payload: &[u8]) -> io::Result<()> {
            let extent = size_of::<libc::rtattr>() + payload.len();
            let length = u16::try_from(extent).map_err(io::Error::other)?;
            bytes.extend_from_slice(&length.to_ne_bytes());
            bytes.extend_from_slice(&kind.to_ne_bytes());
            bytes.extend_from_slice(payload);
            bytes.resize(bytes.len() + aligned(extent)? - extent, 0);
            Ok(())
        }
        let master_index = NonZeroU32::new(11).ok_or(io::ErrorKind::InvalidInput)?;
        let mut slave = packet(libc::RTM_NEWLINK, 7, LinkRole::Network)?;
        append(&mut slave, libc::IFLA_IFNAME, b"eth0\0")?;
        append(
            &mut slave,
            libc::IFLA_MASTER,
            &master_index.get().to_ne_bytes(),
        )?;
        let observed = link_record(&slave[Header::SIZE..])?;
        if observed.name != Some(c"eth0")
            || observed.attachment.master != Some(master_index)
            || observed.attachment.vrf
        {
            return Err(invalid("original slave record lost its native master"));
        }
        let mut master = packet(libc::RTM_NEWLINK, 11, LinkRole::Network)?;
        let mut kind = Vec::new();
        append(&mut kind, libc::IFLA_INFO_KIND, b"vrf\0")?;
        append(&mut master, libc::IFLA_LINKINFO | 0x8000, &kind)?;
        let observed = link_record(&master[Header::SIZE..])?;
        if observed.index != master_index
            || !observed.attachment.vrf
            || observed.attachment.master.is_some()
        {
            return Err(invalid("original master record lost its native kind"));
        }
        append(
            &mut slave,
            libc::IFLA_MASTER,
            &master_index.get().to_ne_bytes(),
        )?;
        if link_record(&slave[Header::SIZE..]).is_ok() {
            return Err(invalid("duplicate native master relationship was accepted"));
        }
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assert malformed/truncated/overrun records fail before claiming link observations"
    )]
    fn incomplete_and_overrun_records_fail_closed() -> io::Result<()> {
        let valid = packet(libc::RTM_NEWLINK, 7, LinkRole::Network)?;
        let missing_index = packet(libc::RTM_DELLINK, 0, LinkRole::Network)?;
        let overrun = packet(
            u16::try_from(libc::NLMSG_OVERRUN).map_err(io::Error::other)?,
            7,
            LinkRole::Network,
        )?;
        let mut interrupted = valid.clone();
        let at = std::mem::offset_of!(libc::nlmsghdr, nlmsg_flags);
        let flag = u16::try_from(libc::NLM_F_DUMP_INTR).map_err(io::Error::other)?;
        interrupted[at..at + size_of::<u16>()].copy_from_slice(&flag.to_ne_bytes());
        for (bytes, lost) in [
            (&valid[..valid.len() - 1], false),
            (&missing_index, false),
            (&overrun, true),
            (&interrupted, true),
            (&[], false),
        ] {
            let mut events = Vec::new();
            assert!(
                parse(bytes, &mut |event| events.push(event))
                    .is_err_and(|error| LinkMonitor::is_notification_loss(&error) == lost)
            );
            assert!(events.is_empty());
        }
        assert_eq!(
            parse(&overrun, &mut |_| {})
                .err()
                .and_then(|error| error.raw_os_error()),
            Some(libc::ENOBUFS),
        );
        let mut malformed_attribute = valid;
        malformed_attribute.push(0);
        let length = u32::try_from(malformed_attribute.len()).map_err(io::Error::other)?;
        malformed_attribute[..size_of::<u32>()].copy_from_slice(&length.to_ne_bytes());
        let mut events = Vec::new();
        assert!(parse(&malformed_attribute, &mut |event| events.push(event)).is_err());
        assert!(events.is_empty());
        Ok(())
    }

    #[test]
    fn only_kernel_origin_truncation_reports_notification_loss() {
        let storage = [0];
        for (received, flags) in [(1, libc::MSG_TRUNC), (1, libc::MSG_CTRUNC), (2, 0)] {
            assert!(
                notification_payload(&storage, received, flags, true)
                    .is_err_and(|error| LinkMonitor::is_notification_loss(&error))
            );
            assert!(
                notification_payload(&storage, received, flags, false)
                    .is_err_and(|error| !LinkMonitor::is_notification_loss(&error))
            );
        }
        assert!(notification_payload(&storage, 1, 0, true).is_ok_and(|bytes| bytes == storage));
    }
}
