//! Preserve both native truncation flags and the complete returned address.
use super::{Address, PATH_CAPACITY, PATH_OFFSET, Received};
use socket2::SockAddr;
use std::{
    io,
    os::fd::{AsRawFd, BorrowedFd},
};

#[expect(
    unsafe_code,
    reason = "One recvmsg borrows the original fd and caller-provided datagram/address storage"
)]
pub(super) fn datagram(fd: BorrowedFd<'_>, buffer: &mut [u8]) -> io::Result<Received> {
    let mut iov = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    // SAFETY: the address buffer is zero-initialized by socket2. Its original
    // capacity, the live payload slice and the iovec stay valid for recvmsg.
    // No control buffer is provided, so no ancillary descriptor is accepted.
    let ((bytes, flags), address) = unsafe {
        SockAddr::try_init(|address, length| {
            let mut message: libc::msghdr = std::mem::zeroed();
            message.msg_name = address.cast();
            message.msg_namelen = *length;
            message.msg_iov = &raw mut iov;
            message.msg_iovlen = 1;
            let bytes = libc::recvmsg(fd.as_raw_fd(), &raw mut message, libc::MSG_DONTWAIT);
            if bytes < 0 {
                return Err(io::Error::last_os_error());
            }
            // An unrepresentable source becomes a rejected datagram, without
            // losing the socket or constructing an oversized SockAddr.
            *length = if message.msg_namelen <= *length {
                message.msg_namelen
            } else {
                0
            };
            Ok((bytes as usize, message.msg_flags))
        })?
    };
    let (source, source_error) = match Address::received(address) {
        Ok(source) => (Some(source), None),
        Err(error) => (None, Some(error)),
    };
    Ok(Received {
        bytes: bytes.min(buffer.len()),
        source,
        source_error,
        truncated: flags & libc::MSG_TRUNC != 0 || bytes > buffer.len(),
        ancillary_truncated: flags & libc::MSG_CTRUNC != 0,
    })
}

#[expect(
    unsafe_code,
    reason = "The platform-reported extents include or omit a filesystem NUL, which is not represented by the socket2 path accessor"
)]
pub(super) fn path_bytes(address: &SockAddr) -> Option<&[u8]> {
    let length = (address.len() as usize).checked_sub(PATH_OFFSET)?;
    if !address.is_unix() || !(1..=PATH_CAPACITY).contains(&length) {
        return None;
    }
    // SAFETY: socket2 owns initialized storage, and the checked range is
    // confined to the original sockaddr_un path field in that same storage.
    Some(unsafe {
        std::slice::from_raw_parts(address.as_ptr().cast::<u8>().add(PATH_OFFSET), length)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::{fd::AsFd, unix::net::UnixDatagram};

    #[test]
    fn original_datagram_truncation_and_unnamed_sender_are_kept() -> io::Result<()> {
        let (sender, receiver) = UnixDatagram::pair()?;
        let packet = [0x3b; 8];
        if sender.send(&packet)? != packet.len() {
            return Err(io::Error::other("short original Unix datagram send"));
        }
        let mut buffer = [0; 3];
        let message = datagram(receiver.as_fd(), &mut buffer)?;
        if message.bytes != buffer.len()
            || !message.truncated
            || message.ancillary_truncated
            || message.source.is_some()
            || !message
                .source_error
                .is_some_and(|error| error.kind() == io::ErrorKind::AddrNotAvailable)
            || buffer != packet[..buffer.len()]
        {
            return Err(io::Error::other("changed native datagram observations"));
        }
        Ok(())
    }
}
