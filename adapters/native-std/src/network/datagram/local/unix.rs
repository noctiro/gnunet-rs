//! Native IPv4 and IPv6 UDP packet information on Unix.
mod metadata;

use super::{LocalReplyPath, invalid, return_endpoints};
use metadata::Control;
use socket2::SockAddr;
use std::{
    io,
    mem::size_of,
    net::{SocketAddr, UdpSocket},
    os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd},
    sync::Arc,
};

/// One bound unconnected UDP socket which retains the destination of its reads.
pub struct LocalDatagram {
    socket: UdpSocket,
    bound: SocketAddr,
    owner: Arc<()>,
}

impl LocalDatagram {
    /// Prepare an original bound unconnected socket for nonblocking I/O.
    ///
    /// # Errors
    /// Returns native errors when reading the local address or enabling packet info.
    pub fn new(socket: UdpSocket) -> io::Result<Self> {
        let bound = socket.local_addr()?;
        if bound.port() == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        match socket.peer_addr() {
            Err(error) if error.kind() == io::ErrorKind::NotConnected => {}
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "UDP listener is connected",
                ));
            }
        }
        socket.set_nonblocking(true)?;
        metadata::enable(socket.as_fd(), bound.is_ipv4())?;
        Ok(Self {
            socket,
            bound,
            owner: Arc::new(()),
        })
    }

    /// Receive payload bytes, peer, exact local address and ingress on this socket.
    ///
    /// # Errors
    /// Returns native receive errors, `WouldBlock` or `InvalidData` for refused metadata.
    #[expect(
        unsafe_code,
        reason = "recvmsg borrows live storage and a nonblocking socket"
    )]
    pub fn receive(&self, payload: &mut [u8]) -> io::Result<(usize, LocalReplyPath)> {
        let mut control = Control::new();
        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        // SAFETY: the zeroed sockaddr storage and explicit extent are for this one recvmsg.
        let ((bytes, used), peer) = unsafe {
            SockAddr::try_init(|address, length| {
                // SAFETY: msghdr contains only scalar values and raw pointers.
                let mut msg: libc::msghdr = std::mem::zeroed();
                msg.msg_name = address.cast();
                msg.msg_namelen = *length;
                msg.msg_iov = &raw mut iov;
                msg.msg_iovlen = 1;
                msg.msg_control = control.as_mut_ptr();
                msg.msg_controllen = crate::ancillary_abi::extent(control.capacity())?;
                let bytes = libc::recvmsg(self.socket.as_raw_fd(), &raw mut msg, 0);
                if bytes < 0 {
                    return Err(io::Error::last_os_error());
                }
                if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
                    || msg.msg_namelen != address_length(self.bound)
                    || bytes as usize > payload.len()
                {
                    return Err(invalid("truncated UDP payload or address metadata"));
                }
                let expected = if self.bound.is_ipv4() {
                    libc::AF_INET
                } else {
                    libc::AF_INET6
                };
                // SAFETY: socket2 owns a zero-initialized native sockaddr_storage, now filled by recvmsg.
                if i32::from((*address.cast::<libc::sockaddr_storage>()).ss_family) != expected {
                    return Err(invalid("unexpected UDP peer address family"));
                }
                *length = msg.msg_namelen;
                Ok((
                    bytes as usize,
                    crate::ancillary_abi::extent(msg.msg_controllen)?,
                ))
            })?
        };
        let peer = peer
            .as_socket()
            .ok_or_else(|| invalid("unexpected UDP peer family"))?;
        let (destination, ingress) = control.destination(used, self.bound.is_ipv4())?;
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

    /// Send a reply using this listener's original local address and applicable zone.
    ///
    /// # Errors
    /// Refuses foreign paths and preserves native send errors without trying a different source.
    #[expect(
        unsafe_code,
        reason = "sendmsg borrows immutable initialized records for one native call"
    )]
    pub fn send(&self, path: &LocalReplyPath, payload: &[u8]) -> io::Result<usize> {
        if !Arc::ptr_eq(&self.owner, &path.owner) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if self.bound.is_ipv4() && self.bound.ip() == path.local.ip() {
            return self.socket.send_to(payload, path.peer);
        }
        let mut control = Control::new();
        let used = control.reply(path)?;
        let peer = SockAddr::from(path.peer);
        let mut iov = libc::iovec {
            iov_base: payload.as_ptr().cast_mut().cast(),
            iov_len: payload.len(),
        };
        // SAFETY: all pointers refer to storage that outlives this synchronous call.
        let bytes = unsafe {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_name = peer.as_ptr().cast_mut().cast();
            msg.msg_namelen = peer.len();
            msg.msg_iov = &raw mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr();
            msg.msg_controllen = crate::ancillary_abi::extent(used)?;
            libc::sendmsg(self.socket.as_raw_fd(), &raw const msg, 0)
        };
        if bytes < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(bytes as usize)
    }
}

impl AsFd for LocalDatagram {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }
}

impl AsRawFd for LocalDatagram {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

fn address_length(address: SocketAddr) -> libc::socklen_t {
    match address {
        SocketAddr::V4(_) => size_of::<libc::sockaddr_in>() as _,
        SocketAddr::V6(_) => size_of::<libc::sockaddr_in6>() as _,
    }
}
