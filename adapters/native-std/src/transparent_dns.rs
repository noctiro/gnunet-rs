//! Linux transparent UDP DNS sockets with complete destination metadata.
//!
//! The caller owns TPROXY policy and async readiness. These sockets install no
//! routes, rules or privileges. Ancillary interface IDs describe receive ingress;
//! they do not recover an application's earlier output-device or scope choice.
//! A reply socket binds the original DNS endpoint: pktinfo alone cannot change
//! the listener's custom UDP source port. Reply sockets remain unconnected so
//! TPROXY does not adopt them as established client-flow receive sockets.
//! A VRF receive carries the original slave in pktinfo and the original master
//! in a link-scoped peer sockaddr. The admitted route observes both devices.
//! The reply socket binds the master, then supplies the exact received slave
//! through pktinfo. Kernel device replacement across submission remains possible.

mod address;
mod ancillary;
/// Exact upstream socket marks and explicit native ingress observations.
pub mod exclusion;
/// Original kernel route-link notifications with bounded native framing.
pub mod link;
mod namespace;
pub use namespace::NetworkNamespace;

use exclusion::{AdmittedDatagram, IngressObservation, ReplyQualification};
use std::{
    io,
    mem::size_of,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    num::{NonZeroU16, NonZeroU32},
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
    ptr,
    sync::Arc,
};

const DNS_PORT: u16 = 53;

/// Capture listener port, distinct from the original DNS reply source port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransparentPort(NonZeroU16);

impl TransparentPort {
    /// Validate an explicit nonzero UDP port distinct from DNS port 53.
    #[must_use]
    pub const fn new(port: u16) -> Option<Self> {
        match NonZeroU16::new(port) {
            Some(port) if port.get() != DNS_PORT => Some(Self(port)),
            _ => None,
        }
    }

    /// Return the configured capture UDP port.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

/// Address family of one wildcard transparent capture listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListenerFamily {
    /// Bind the IPv4 wildcard address.
    Ipv4,
    /// Bind the IPv6 wildcard address with `IPV6_V6ONLY`.
    Ipv6,
}

#[derive(Debug)]
struct Datagram {
    bytes: usize,
    peer: SocketAddr,
    original: SocketAddr,
    interface: NonZeroU32,
    namespace: NetworkNamespace,
}

/// One family-specific, nonblocking transparent UDP capture listener.
/// IPv6 listeners are V6ONLY; callers retain a separate IPv4 listener.
#[derive(Debug)]
pub struct Listener {
    socket: OwnedFd,
    family: ListenerFamily,
    namespace: NetworkNamespace,
    source: Arc<()>,
}

impl Listener {
    fn bind(
        family: ListenerFamily,
        port: TransparentPort,
        expected_namespace: NetworkNamespace,
        source: Arc<()>,
    ) -> io::Result<Self> {
        let local = match family {
            ListenerFamily::Ipv4 => SocketAddr::from((Ipv4Addr::UNSPECIFIED, port.get())),
            ListenerFamily::Ipv6 => SocketAddr::from((Ipv6Addr::UNSPECIFIED, port.get())),
        };
        let ipv4 = family == ListenerFamily::Ipv4;
        let socket = socket(ipv4)?;
        let namespace = NetworkNamespace::observe(socket.as_fd())?;
        expected_namespace.require(namespace)?;
        if ipv4 {
            option(&socket, libc::IPPROTO_IP, libc::IP_RECVORIGDSTADDR, 1)?;
            option(&socket, libc::IPPROTO_IP, libc::IP_PKTINFO, 1)?;
        } else {
            option(&socket, libc::IPPROTO_IPV6, libc::IPV6_RECVORIGDSTADDR, 1)?;
            option(&socket, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, 1)?;
        }
        bind(&socket, local)?;
        Ok(Self {
            socket,
            family,
            namespace,
            source,
        })
    }

    /// Receive one complete UDP body with its exact native destination metadata.
    /// Successful receives allocate no memory. `WouldBlock` leaves readiness to
    /// the caller; every other outcome consumes at most one datagram.
    ///
    /// # Errors
    /// Preserves `recvmsg` failures. `InvalidData` consumes and refuses truncated
    /// payload/control, missing/duplicate/contradictory metadata, non-DNS targets,
    /// invalid unicast endpoints or absent/inconsistent received IPv6 scope.
    #[expect(
        unsafe_code,
        reason = "recvmsg borrows one live nonblocking socket and exclusive bounded payload, address and aligned ancillary storage through synchronous return"
    )]
    fn recv(&self, payload: &mut [u8]) -> io::Result<Datagram> {
        if payload.is_empty() {
            return Err(invalid_input("transparent DNS receive buffer is empty"));
        }
        // SAFETY: these Linux ABI output records permit initialized zero storage.
        let mut peer = unsafe { std::mem::zeroed::<libc::sockaddr_storage>() };
        let mut control = ancillary::Control::new();
        let mut vector = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        // SAFETY: all pointer/scalar fields permit a zero starting value.
        let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
        message.msg_name = ptr::from_mut(&mut peer).cast();
        message.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        message.msg_iov = ptr::from_mut(&mut vector);
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr();
        message.msg_controllen = control.capacity();
        // SAFETY: every original output pointer above covers initialized storage
        // held exclusively until this synchronous nonblocking call returns.
        let received =
            unsafe { libc::recvmsg(self.socket.as_raw_fd(), &mut message, libc::MSG_DONTWAIT) };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        let bytes = usize::try_from(received)
            .map_err(|_| invalid_data("transparent DNS receive length overflow"))?;
        if bytes > payload.len() || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
            return Err(invalid_data(
                "truncated transparent DNS datagram or metadata",
            ));
        }
        let ipv4 = self.family == ListenerFamily::Ipv4;
        let peer = address::decode(&peer, message.msg_namelen, ipv4)?;
        let observed = control.parse(message.msg_controllen, ipv4)?;
        Ok(Datagram {
            bytes,
            peer,
            original: observed.original,
            interface: observed.interface,
            namespace: self.namespace,
        })
    }
}

impl AsFd for Listener {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }
}

impl AsRawFd for Listener {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

/// Original transparent UDP source socket, bound to one exact DNS endpoint.
/// The native binding also records the original source for [`Self::send`].
#[derive(Debug)]
pub struct ReplySocket {
    socket: OwnedFd,
    local: SocketAddr,
    namespace: NetworkNamespace,
    source: Arc<()>,
    bound_ingress: IngressObservation,
}

impl ReplySocket {
    /// Bind the received original destination as the reply's real UDP source.
    /// Set the caller's explicit nonzero bypass mark before binding or sending.
    /// No reuse option adopts or displaces another socket on that endpoint.
    ///
    /// # Errors
    /// Preserves native socket, transparent/mark option or original bind failure.
    pub fn bind(
        qualification: &ReplyQualification<'_>,
        bypass_mark: NonZeroU32,
    ) -> io::Result<Self> {
        qualification.ensure_fresh()?;
        let admitted = qualification.admitted();
        let datagram = admitted.datagram();
        let (local, binding) = reply_binding(admitted);
        let socket = socket(local.is_ipv4())?;
        let namespace = NetworkNamespace::observe(socket.as_fd())?;
        datagram.namespace.require(namespace)?;
        mark(&socket, bypass_mark)?;
        let index = i32::try_from(binding.index().get())
            .map_err(|_| invalid_data("transparent DNS device exceeds native index range"))?;
        option(&socket, libc::SOL_SOCKET, libc::SO_BINDTOIFINDEX, index)?;
        bind(&socket, local)?;
        Ok(Self {
            socket,
            local,
            namespace,
            source: Arc::clone(admitted.source()),
            bound_ingress: binding.clone(),
        })
    }

    /// Whether this socket's bound interface or VRF remains admissible.
    #[must_use]
    pub fn active(&self) -> bool {
        self.bound_ingress.active()
    }

    /// Whether the bound endpoint, namespace and capture owner match the datagram.
    /// Pktinfo selects each original ingress. Ordinary replies bind the
    /// physical ingress. A VRF reply binds the original master and may
    /// share a socket with other original slaves in that same VRF.
    #[must_use]
    pub fn route_matches(&self, admitted: &AdmittedDatagram) -> bool {
        let datagram = admitted.datagram();
        let (local, binding) = reply_binding(admitted);
        self.local == local
            && self.namespace == datagram.namespace
            && Arc::ptr_eq(&self.source, admitted.source())
            && admitted.ingress().active()
            && self.bound_ingress.same(binding)
    }

    /// Send one atomic reply to the received peer from the original DNS port.
    /// A fresh qualification is required for each native submission attempt.
    /// Pktinfo selects the original source address and received ingress. Send
    /// success acknowledges local submission, not peer receipt.
    ///
    /// # Errors
    /// Refuses a different original endpoint or namespace before sending.
    /// Preserves `sendmsg` failures, including `WouldBlock`. An unexpected short
    /// success returns its actual extent. The caller must retire that attempt
    /// without replay.
    #[expect(
        unsafe_code,
        reason = "sendmsg borrows the exact bound source socket, original peer, complete payload and initialized pktinfo without retaining pointers"
    )]
    pub fn send(&self, qualification: ReplyQualification<'_>, payload: &[u8]) -> io::Result<usize> {
        let admitted = qualification.admitted();
        let datagram = admitted.datagram();
        self.namespace.require(datagram.namespace)?;
        if !self.route_matches(admitted) {
            return Err(invalid_input(
                "transparent DNS reply belongs to a different source",
            ));
        }
        let (mut peer, length) = address::encode(datagram.peer);
        let (mut control, used) = ancillary::Control::outgoing(self.local, datagram.interface)?;
        let mut vector = libc::iovec {
            iov_base: payload.as_ptr().cast_mut().cast(),
            iov_len: payload.len(),
        };
        // SAFETY: these scalar/pointer fields permit an initialized zero record.
        let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
        message.msg_name = ptr::from_mut(&mut peer).cast();
        message.msg_namelen = length;
        message.msg_iov = ptr::from_mut(&mut vector);
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr();
        message.msg_controllen = used;
        qualification.ensure_fresh()?;
        // SAFETY: original source and all borrowed input extents remain valid
        // through one atomic nonblocking send; the kernel retains no pointers.
        let sent = unsafe {
            libc::sendmsg(
                self.socket.as_raw_fd(),
                &message,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        usize::try_from(sent).map_err(|_| invalid_data("transparent DNS send length overflow"))
    }
}

fn reply_binding(admitted: &AdmittedDatagram) -> (SocketAddr, &IngressObservation) {
    let mut address = admitted.datagram().original;
    let ingress = admitted.ingress();
    let binding = ingress.master().unwrap_or(ingress);
    if let SocketAddr::V6(local) = &mut address
        && local.scope_id() != 0
    {
        // Linux takes the socket's bound device from this sockaddr when
        // binding a link-local source. IPV6_PKTINFO separately selects the
        // original slave for sends to a peer scoped to a VRF master.
        local.set_scope_id(binding.index().get());
    }
    (address, binding)
}

impl AsFd for ReplySocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }
}

impl AsRawFd for ReplySocket {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

#[expect(
    unsafe_code,
    reason = "socket's nonnegative result transfers one new CLOEXEC nonblocking UDP descriptor into exactly one OwnedFd"
)]
fn socket(ipv4: bool) -> io::Result<OwnedFd> {
    let domain = if ipv4 { libc::AF_INET } else { libc::AF_INET6 };
    // SAFETY: constant Linux socket parameters contain no caller pointers.
    let raw = unsafe {
        libc::socket(
            domain,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::IPPROTO_UDP,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: this fresh successful original descriptor has no other Rust owner.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    if ipv4 {
        option(&socket, libc::IPPROTO_IP, libc::IP_TRANSPARENT, 1)?;
    } else {
        option(&socket, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 1)?;
        option(&socket, libc::IPPROTO_IPV6, libc::IPV6_TRANSPARENT, 1)?;
    }
    Ok(socket)
}

#[expect(
    unsafe_code,
    reason = "setsockopt borrows one live socket and initialized integer with its exact native extent through synchronous return"
)]
fn option(socket: &OwnedFd, level: i32, name: i32, value: i32) -> io::Result<()> {
    // SAFETY: options used here take exactly one initialized native int.
    let status = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            ptr::from_ref(&value).cast(),
            size_of::<i32>() as libc::socklen_t,
        )
    };
    if status < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[expect(
    unsafe_code,
    reason = "SO_MARK borrows one initialized 32-bit original mark without changing process credentials or namespace policy"
)]
fn mark(socket: &OwnedFd, value: NonZeroU32) -> io::Result<()> {
    let value = value.get();
    // SAFETY: Linux SO_MARK consumes the exact initialized u32 bits synchronously.
    let status = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            ptr::from_ref(&value).cast(),
            size_of::<u32>() as libc::socklen_t,
        )
    };
    if status < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[expect(
    unsafe_code,
    reason = "bind borrows one fully initialized same-family sockaddr and its exact native extent through synchronous return"
)]
fn bind(socket: &OwnedFd, local: SocketAddr) -> io::Result<()> {
    let (address, length) = address::encode(local);
    // SAFETY: the encoded original sockaddr remains initialized and live.
    if unsafe { libc::bind(socket.as_raw_fd(), ptr::from_ref(&address).cast(), length) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::TransparentPort;

    #[test]
    fn capture_port_preserves_the_original_dns_reply_port() {
        assert_eq!(TransparentPort::new(0), None);
        assert_eq!(TransparentPort::new(53), None);
        for port in [1, 52, 54, u16::MAX] {
            assert_eq!(
                TransparentPort::new(port).map(TransparentPort::get),
                Some(port)
            );
        }
    }
}
