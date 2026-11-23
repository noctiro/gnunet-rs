//! Exact-source UDP replies with Winsock's provider-specific extensions.
use super::{LocalReplyPath, invalid, return_endpoints};
use crate::network::datagram::send_windows::{
    CONTROL_DATA, SendMsg, align_control_header, extension_pointer, last_error,
};
use socket2::{SockAddr, SockRef, Type};
use std::{
    ffi::c_void,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroU32,
    os::windows::io::{AsRawSocket, AsSocket, BorrowedSocket, RawSocket},
    ptr,
    sync::Arc,
};
use windows_sys::Win32::Networking::WinSock::*;

/// Packet information and exact-source I/O on one original bound UDP socket.
/// The holder keeps its socket ownership and may supply its own readiness
/// registration. Both extension pointers belong to that socket's provider.
pub struct LocalDatagramIo<S> {
    socket: S,
    original: RawSocket,
    bound: SocketAddr,
    owner: Arc<()>,
    receive: LPFN_WSARECVMSG,
    send: SendMsg,
}

impl<S: AsSocket> LocalDatagramIo<S> {
    /// Enable packet information on the original unconnected nonblocking
    /// listener. An IPv6 listener must have been bound with `IPV6_V6ONLY`.
    ///
    /// # Errors
    /// Returns the actual socket, option or provider lookup error.
    pub fn new(socket: S) -> io::Result<Self> {
        let borrowed = socket.as_socket();
        let reference = SockRef::from(&borrowed);
        let bound = reference.local_addr()?.as_socket().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "UDP listener must use IP")
        })?;
        if bound.port() == 0
            || reference.r#type()? != Type::DGRAM
            || (bound.is_ipv6() && !reference.only_v6()?)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid UDP listener",
            ));
        }
        match reference.peer_addr() {
            Err(error) if error.kind() == io::ErrorKind::NotConnected => {}
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "UDP listener is connected",
                ));
            }
        }
        reference.set_nonblocking(true)?;
        enable_packet_info(borrowed, bound.is_ipv4())?;
        let receive = receive_provider(borrowed)?;
        let send = SendMsg::new(borrowed)?;
        let original = borrowed.as_raw_socket();
        Ok(Self {
            socket,
            original,
            bound,
            owner: Arc::new(()),
            receive,
            send,
        })
    }

    /// Borrow the original socket for its existing readiness registration.
    #[must_use]
    pub const fn socket(&self) -> &S {
        &self.socket
    }

    fn original(&self) -> io::Result<BorrowedSocket<'_>> {
        let socket = self.socket.as_socket();
        if socket.as_raw_socket() != self.original {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP listener was changed",
            ));
        }
        Ok(socket)
    }

    /// Receive a complete payload with its exact local unicast address and
    /// ingress interface on this listener.
    ///
    /// # Errors
    /// Returns native receive errors, `WouldBlock`, or `InvalidData` for
    /// truncated, absent or inconsistent address metadata.
    #[expect(
        unsafe_code,
        reason = "The synchronous SDK receive uses only initialized stack records and the caller's bounded mutable payload"
    )]
    pub fn receive(&self, payload: &mut [u8]) -> io::Result<(usize, LocalReplyPath)> {
        let socket = self.original()?;
        let function = self
            .receive
            .ok_or_else(|| io::Error::other("WSARecvMsg provider unavailable"))?;
        let mut control = [0_usize; 8];
        let mut iov = WSABUF {
            len: u32::try_from(payload.len()).map_err(|_| io::ErrorKind::InvalidInput)?,
            buf: payload.as_mut_ptr(),
        };
        let name_bytes = if self.bound.is_ipv4() {
            size_of::<SOCKADDR_IN>()
        } else {
            size_of::<SOCKADDR_IN6>()
        };
        let expected_family = if self.bound.is_ipv4() {
            AF_INET
        } else {
            AF_INET6
        };
        // SAFETY: initialized sockaddr_storage is valid for the exact reported
        // capacity. WSAMSG may write only through the borrowed stack pointers
        // and the caller's mutable payload, synchronously without OVERLAPPED.
        let ((bytes, control_len), address) = unsafe {
            SockAddr::try_init(|address, length| {
                let mut message = WSAMSG {
                    name: address.cast(),
                    namelen: *length,
                    lpBuffers: &raw mut iov,
                    dwBufferCount: 1,
                    Control: WSABUF {
                        len: size_of_val(&control) as u32,
                        buf: control.as_mut_ptr().cast(),
                    },
                    dwFlags: 0,
                };
                let mut bytes = 0;
                let result = function(
                    socket.as_raw_socket() as SOCKET,
                    &raw mut message,
                    &raw mut bytes,
                    ptr::null_mut(),
                    None,
                );
                if result == SOCKET_ERROR {
                    return Err(last_error());
                }
                if message.dwFlags & (MSG_TRUNC | MSG_CTRUNC | MSG_BCAST | MSG_MCAST) != 0
                    || message.namelen as usize != name_bytes
                    || message.Control.len as usize > size_of_val(&control)
                    || bytes as usize > payload.len()
                {
                    return Err(invalid("truncated or non-unicast UDP datagram"));
                }
                // The returned name extent contains the complete fixed sockaddr.
                if ptr::read_unaligned(address.cast::<ADDRESS_FAMILY>()) != expected_family {
                    return Err(invalid("unexpected UDP peer address family"));
                }
                *length = message.namelen;
                Ok((bytes as usize, message.Control.len as usize))
            })?
        };
        let mut peer = address
            .as_socket()
            .ok_or_else(|| invalid("unexpected UDP peer address"))?;
        if let SocketAddr::V6(peer) = &mut peer {
            peer.set_flowinfo(u32::from_be(peer.flowinfo()));
        }
        let (destination, ingress) =
            received_destination(&control, control_len, self.bound.is_ipv4())?;
        let (peer, local) = return_endpoints(self.bound, peer, destination, ingress)?;
        Ok((
            bytes,
            LocalReplyPath {
                owner: Arc::clone(&self.owner),
                peer,
                local,
                ingress,
            },
        ))
    }

    /// Send via the exact local source address retained by this listener.
    /// Link-local IPv6 also retains the receiving interface as its zone.
    ///
    /// # Errors
    /// Refuses foreign paths and returns the original native send error.
    pub fn send(&self, path: &LocalReplyPath, payload: &[u8]) -> io::Result<usize> {
        if !Arc::ptr_eq(&self.owner, &path.owner) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let scoped = [path.local, path.peer]
            .iter()
            .any(|endpoint| matches!(endpoint, SocketAddr::V6(address) if address.scope_id() != 0));
        let interface = scoped.then_some(path.ingress);
        self.send
            .send(self.original()?, path.local, interface, path.peer, payload)
    }
}

#[expect(
    unsafe_code,
    reason = "setsockopt reads one initialized DWORD for the selected original socket family"
)]
fn enable_packet_info(socket: BorrowedSocket<'_>, ipv4: bool) -> io::Result<()> {
    let (level, option) = if ipv4 {
        (IPPROTO_IP, IP_PKTINFO)
    } else {
        (IPPROTO_IPV6, IPV6_PKTINFO)
    };
    let enabled = 1_u32;
    // SAFETY: Winsock gets the original live socket and a complete DWORD.
    let status = unsafe {
        setsockopt(
            socket.as_raw_socket() as SOCKET,
            level,
            option,
            ptr::from_ref(&enabled).cast(),
            size_of_val(&enabled) as i32,
        )
    };
    if status == SOCKET_ERROR {
        Err(last_error())
    } else {
        Ok(())
    }
}

#[expect(
    unsafe_code,
    reason = "The WSAID_WSARECVMSG GUID selects the SDK's LPFN_WSARECVMSG function type"
)]
fn receive_provider(socket: BorrowedSocket<'_>) -> io::Result<LPFN_WSARECVMSG> {
    let pointer = extension_pointer(socket, &WSAID_WSARECVMSG)?;
    // SAFETY: Winsock returned a checked non-null provider pointer for exactly
    // the SDK extension GUID and the original socket.
    Ok(unsafe { std::mem::transmute::<*mut c_void, LPFN_WSARECVMSG>(pointer) })
}

#[expect(
    unsafe_code,
    reason = "Each initialized CMSGHDR and packet information body is independently bounded before access"
)]
fn received_destination(
    control: &[usize],
    length: usize,
    ipv4: bool,
) -> io::Result<(IpAddr, NonZeroU32)> {
    if length > size_of_val(control) {
        return Err(invalid("oversized Winsock control buffer"));
    }
    let address = control.as_ptr().cast::<u8>();
    let mut offset = 0;
    let mut destination = None;
    while offset < length {
        let remaining = length - offset;
        if remaining < CONTROL_DATA {
            return Err(invalid("short Winsock control header"));
        }
        // SAFETY: the checked initialized extent contains a CMSGHDR.
        let header = unsafe { address.add(offset).cast::<CMSGHDR>().read_unaligned() };
        if header.cmsg_len < CONTROL_DATA || header.cmsg_len > remaining {
            return Err(invalid("invalid Winsock control record length"));
        }
        // SAFETY: CONTROL_DATA is within the checked record, possibly one past
        // a zero-byte body. The selected full body is checked before reading.
        let body = unsafe { address.add(offset + CONTROL_DATA) };
        let body_bytes = header.cmsg_len - CONTROL_DATA;
        let packet_info = match (header.cmsg_level, header.cmsg_type) {
            (IPPROTO_IP, IP_PKTINFO) if ipv4 && body_bytes == size_of::<IN_PKTINFO>() => {
                // SAFETY: this complete bound body uses the Winsock IN_PKTINFO layout.
                let info = unsafe { body.cast::<IN_PKTINFO>().read_unaligned() };
                // SAFETY: the complete initialized IN_ADDR is readable as bits.
                let ip = Ipv4Addr::from(unsafe { info.ipi_addr.S_un.S_addr }.to_ne_bytes());
                Some((IpAddr::V4(ip), info.ipi_ifindex))
            }
            (IPPROTO_IPV6, IPV6_PKTINFO) if !ipv4 && body_bytes == size_of::<IN6_PKTINFO>() => {
                // SAFETY: this complete bound body uses the Winsock IN6_PKTINFO layout.
                let info = unsafe { body.cast::<IN6_PKTINFO>().read_unaligned() };
                // SAFETY: all 16 bytes of the native address are initialized.
                let ip = Ipv6Addr::from(unsafe { info.ipi6_addr.u.Byte });
                Some((IpAddr::V6(ip), info.ipi6_ifindex))
            }
            (IPPROTO_IP, IP_PKTINFO) | (IPPROTO_IPV6, IPV6_PKTINFO) => {
                return Err(invalid("unexpected Winsock packet info"));
            }
            _ => None,
        };
        if let Some((ip, index)) = packet_info {
            let ingress =
                NonZeroU32::new(index).ok_or_else(|| invalid("missing UDP ingress index"))?;
            if destination.replace((ip, ingress)).is_some() {
                return Err(invalid("duplicate Winsock packet info"));
            }
        }
        if header.cmsg_len == remaining {
            break;
        }
        let stride = align_control_header(header.cmsg_len);
        if stride > remaining {
            return Err(invalid("truncated Winsock control padding"));
        }
        offset += stride;
    }
    destination.ok_or_else(|| invalid("missing Winsock packet info"))
}
