//! Read-only BSD address and interface notifications for one native PF scope.
use socket2::{Domain, Socket, Type};
use std::{
    io,
    mem::{offset_of, size_of},
    num::NonZeroU32,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd},
};

/// Application-owned receive capacity for any native u16-length route record.
pub const MESSAGE_BYTES: usize = u16::MAX as usize;

/// A routing-socket notification relevant to DNS PF address scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    /// An address report needs a fresh complete interface snapshot.
    AddressAdded,
    /// The kernel removed an address from this native interface index.
    AddressRemoved(NonZeroU32),
    /// The kernel reported this interface's departure.
    InterfaceDeparted(NonZeroU32),
    /// The notification does not affect the address scope.
    Other,
}

/// One original, nonblocking routing-socket subscription.
pub struct Monitor(OwnedFd);

impl Monitor {
    /// Subscribe to native route events in the calling network context.
    ///
    /// # Errors
    /// Reports native socket setup failures. The socket issues no requests.
    pub fn subscribe() -> io::Result<Self> {
        let socket = Socket::new(
            Domain::from(libc::PF_ROUTE),
            Type::from(libc::SOCK_RAW),
            None,
        )?;
        #[cfg(target_os = "freebsd")]
        report_receive_overflow(&socket)?;
        socket.set_nonblocking(true)?;
        socket.set_recv_buffer_size(128 * 1024)?;
        Ok(Self(socket.into()))
    }

    /// Consume one original native event using the caller's fixed-size buffer.
    ///
    /// # Errors
    /// Preserves native errors including WouldBlock. Truncated, malformed or
    /// unexpected sender records fail the original subscription.
    #[expect(
        unsafe_code,
        reason = "recvmsg borrows one original fd and bounded initialized output buffers"
    )]
    pub fn read(&self, buffer: &mut [u8]) -> io::Result<Event> {
        // SAFETY: both native output structs permit a zero representation.
        let mut source: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        // SAFETY: all pointers and scalar fields can be initialized to zero.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        let mut vector = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: buffer.len(),
        };
        message.msg_name = (&raw mut source).cast();
        message.msg_namelen = size_of::<libc::sockaddr_storage>() as _;
        message.msg_iov = &raw mut vector;
        message.msg_iovlen = 1;
        // SAFETY: recvmsg only writes within the supplied live buffers.
        let bytes = unsafe { libc::recvmsg(self.0.as_raw_fd(), &raw mut message, 0) };
        if bytes < 0 {
            return Err(io::Error::last_os_error());
        }
        if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
            || message.msg_namelen < 2
            || i32::from(source.ss_family) != libc::AF_ROUTE
        {
            return Err(invalid());
        }
        let packet = buffer.get(..bytes as usize).ok_or_else(invalid)?;
        decode(packet)
    }
}

#[cfg(target_os = "freebsd")]
#[expect(
    unsafe_code,
    reason = "FreeBSD SO_RERROR is not exposed by the portable socket API"
)]
fn report_receive_overflow(socket: &Socket) -> io::Result<()> {
    // FreeBSD sys/socket.h. Without this flag PF_ROUTE discards records when
    // the receive buffer fills without reporting ENOBUFS to this socket.
    const SO_RERROR: libc::c_int = 0x0002_0000;
    let enabled: libc::c_int = 1;
    // SAFETY: the socket and initialized integer stay alive for the call.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_RERROR,
            (&raw const enabled).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl AsFd for Monitor {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl AsRawFd for Monitor {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

fn decode(packet: &[u8]) -> io::Result<Event> {
    let [low, high, version, kind, ..] = packet else {
        return Err(invalid());
    };
    if usize::from(u16::from_ne_bytes([*low, *high])) != packet.len()
        || i32::from(*version) != libc::RTM_VERSION
    {
        return Err(invalid());
    }
    match i32::from(*kind) {
        libc::RTM_NEWADDR | libc::RTM_DELADDR => {
            if packet.len() < size_of::<libc::ifa_msghdr>() {
                return Err(invalid());
            }
            let index = interface(packet, offset_of!(libc::ifa_msghdr, ifam_index))?;
            if i32::from(*kind) == libc::RTM_NEWADDR {
                Ok(Event::AddressAdded)
            } else {
                Ok(Event::AddressRemoved(index))
            }
        }
        #[cfg(target_os = "freebsd")]
        libc::RTM_IFANNOUNCE => {
            if packet.len() < size_of::<libc::if_announcemsghdr>() {
                return Err(invalid());
            }
            let action = u16_at(packet, offset_of!(libc::if_announcemsghdr, ifan_what))?;
            match i32::from(action) {
                libc::IFAN_ARRIVAL => Ok(Event::Other),
                libc::IFAN_DEPARTURE => {
                    interface(packet, offset_of!(libc::if_announcemsghdr, ifan_index))
                        .map(Event::InterfaceDeparted)
                }
                _ => Err(invalid()),
            }
        }
        _ => Ok(Event::Other),
    }
}

fn u16_at(packet: &[u8], offset: usize) -> io::Result<u16> {
    let bytes = packet.get(offset..offset + 2).ok_or_else(invalid)?;
    Ok(u16::from_ne_bytes(bytes.try_into().map_err(|_| invalid())?))
}

fn interface(packet: &[u8], offset: usize) -> io::Result<NonZeroU32> {
    NonZeroU32::new(u32::from(u16_at(packet, offset)?)).ok_or_else(invalid)
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid original PF routing notification",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_original_address_removal_preserves_the_native_interface_index() -> io::Result<()> {
        let mut packet = [0; size_of::<libc::ifa_msghdr>()];
        let length = u16::try_from(packet.len()).map_err(io::Error::other)?;
        packet[..2].copy_from_slice(&length.to_ne_bytes());
        packet[2] = libc::RTM_VERSION as u8;
        packet[3] = libc::RTM_DELADDR as u8;
        let offset = offset_of!(libc::ifa_msghdr, ifam_index);
        packet[offset..offset + 2].copy_from_slice(&7_u16.to_ne_bytes());
        let index = NonZeroU32::new(7).ok_or_else(invalid)?;
        if decode(&packet)? != Event::AddressRemoved(index)
            || decode(&packet[..packet.len() - 1]).is_ok()
        {
            return Err(io::Error::other(
                "PF route notification accepted a wrong or truncated index",
            ));
        }
        packet[3] = libc::RTM_NEWADDR as u8;
        if decode(&packet)? != Event::AddressAdded {
            return Err(io::Error::other(
                "PF route address addition did not request a recheck",
            ));
        }
        Ok(())
    }
}
