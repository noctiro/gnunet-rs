//! Native Linux loopback check for the reference `ping` fixture.
use gnunet_nat::icmp::checksum;
use std::{
    io,
    mem::size_of,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::Duration,
};
use tokio::{io::Interest, io::unix::AsyncFd, time::timeout};

const SOURCE: [u8; 4] = [127, 0, 0, 1];
const DESTINATION: [u8; 4] = [127, 0, 0, 2];
const PAYLOAD: &[u8] = b"GNUnet netjail";
const ECHO_LEN: usize = 8 + PAYLOAD.len() + size_of::<u32>();
const MAX_IP_HEADER: usize = 60;
const REPLY_LIMIT: Duration = Duration::from_secs(10);
const MAX_UNRELATED: usize = 32;

#[derive(Clone, Copy)]
enum Kind {
    Datagram,
    Raw,
}

impl Kind {
    #[expect(
        unsafe_code,
        reason = "Adopt a fresh nonblocking Linux ICMP file descriptor exactly once"
    )]
    fn open(self) -> io::Result<OwnedFd> {
        let kind = match self {
            Self::Datagram => libc::SOCK_DGRAM,
            Self::Raw => libc::SOCK_RAW,
        };
        // SAFETY: all arguments are constant Linux ABI values. A nonnegative
        // return transfers a new descriptor to this function.
        let fd = unsafe {
            libc::socket(
                libc::AF_INET,
                kind | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                libc::IPPROTO_ICMP,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: this fresh descriptor has no other Rust owner.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn body(self, packet: &[u8]) -> Option<&[u8]> {
        if matches!(self, Self::Datagram) {
            return Some(packet);
        }
        // A Linux raw IPv4 socket also returns the original IPv4 header.
        let header = packet.get(..20)?;
        let header_len = usize::from(header[0] & 0x0f) * 4;
        let total_len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let fragments = u16::from_be_bytes([header[6], header[7]]) & 0x3fff;
        if header[0] >> 4 != 4
            || header_len < header.len()
            || total_len != packet.len()
            || fragments != 0
            || i32::from(header[9]) != libc::IPPROTO_ICMP
            || header[12..16] != DESTINATION
            || header[16..20] != SOURCE
        {
            return None;
        }
        packet.get(header_len..)
    }
}

struct Echo([u8; ECHO_LEN]);

impl Echo {
    fn new(identifier: u16, process: u32) -> Self {
        let mut request = [0; ECHO_LEN];
        request[0] = 8; // ICMPv4 Echo Request
        request[4..6].copy_from_slice(&identifier.to_be_bytes());
        request[6..8].copy_from_slice(&1_u16.to_be_bytes());
        request[8..8 + PAYLOAD.len()].copy_from_slice(PAYLOAD);
        request[8 + PAYLOAD.len()..].copy_from_slice(&process.to_be_bytes());
        let sum = checksum(&request);
        request[2..4].copy_from_slice(&sum.to_be_bytes());
        Self(request)
    }

    fn matches(&self, body: &[u8]) -> bool {
        body.len() == ECHO_LEN
            && body[..2] == [0, 0] // Echo Reply, code zero
            && body[4..] == self.0[4..]
            && checksum(body) == 0
    }
}

pub(super) async fn echo() -> io::Result<()> {
    timeout(REPLY_LIMIT, check_loopback()).await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "netjail loopback ICMP reply timed out",
        )
    })?
}

#[expect(
    unsafe_code,
    reason = "Register the exclusively owned nonblocking ICMP socket with the current runtime"
)]
async fn check_loopback() -> io::Result<()> {
    let (fd, kind) = match Kind::Datagram.open() {
        Ok(fd) => (fd, Kind::Datagram),
        Err(error)
            if error.kind() == io::ErrorKind::PermissionDenied
                || error.raw_os_error() == Some(libc::EPROTONOSUPPORT) =>
        {
            (Kind::Raw.open()?, Kind::Raw)
        }
        Err(error) => return Err(error),
    };
    connect_loopback(&fd)?;
    let process = std::process::id();
    let identifier = match kind {
        // Linux ping sockets write the bound local port into the echo identifier.
        Kind::Datagram => native_identifier(&fd)?,
        Kind::Raw => process as u16,
    };
    // SAFETY: the original OwnedFd stays open in the registration and is
    // neither replaced nor closed by the send and receive operations.
    let socket = unsafe { AsyncFd::register(fd) }.map_err(io::Error::from)?;
    let request = Echo::new(identifier, process);
    socket
        .async_io(Interest::WRITABLE, |fd| send(fd, &request.0))
        .await?;

    let mut buffer = [0; MAX_IP_HEADER + ECHO_LEN + 1];
    for _ in 0..MAX_UNRELATED {
        let size = socket
            .async_io(Interest::READABLE, |fd| receive(fd, &mut buffer))
            .await?;
        if size
            .and_then(|size| buffer.get(..size))
            .and_then(|packet| kind.body(packet))
            .is_some_and(|body| request.matches(body))
        {
            return Ok(());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "netjail received too many unrelated loopback ICMP packets",
    ))
}

fn address(octets: [u8; 4]) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(octets),
        },
        sin_zero: [0; 8],
    }
}

const ADDRESS_LEN: libc::socklen_t = size_of::<libc::sockaddr_in>() as libc::socklen_t;

#[expect(
    unsafe_code,
    reason = "Bind and connect the owned ICMP socket using fixed IPv4 loopback addresses"
)]
fn connect_loopback(fd: &OwnedFd) -> io::Result<()> {
    let local = address(SOURCE);
    // SAFETY: the sockaddr is initialized and remains live for the call.
    if unsafe { libc::bind(fd.as_raw_fd(), (&raw const local).cast(), ADDRESS_LEN) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let peer = address(DESTINATION);
    // SAFETY: the peer sockaddr is initialized and remains live for the call.
    if unsafe { libc::connect(fd.as_raw_fd(), (&raw const peer).cast(), ADDRESS_LEN) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[expect(
    unsafe_code,
    reason = "Read the Linux ping socket identifier through a correctly sized sockaddr_in"
)]
fn native_identifier(fd: &OwnedFd) -> io::Result<u16> {
    let mut local = address([0; 4]);
    let mut size = ADDRESS_LEN;
    // SAFETY: the initialized sockaddr is writable over the supplied size.
    if unsafe { libc::getsockname(fd.as_raw_fd(), (&raw mut local).cast(), &raw mut size) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let identifier = u16::from_be(local.sin_port);
    if size != ADDRESS_LEN
        || i32::from(local.sin_family) != libc::AF_INET
        || local.sin_addr.s_addr.to_ne_bytes() != SOURCE
        || identifier == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Linux ICMP socket returned an invalid original loopback binding",
        ));
    }
    Ok(identifier)
}

#[expect(
    unsafe_code,
    reason = "Send one initialized bounded ICMP message on the original loopback socket"
)]
fn send(fd: &OwnedFd, request: &[u8]) -> io::Result<()> {
    // SAFETY: the connected socket borrows the initialized request for this call.
    let size = unsafe { libc::send(fd.as_raw_fd(), request.as_ptr().cast(), request.len(), 0) };
    if size < 0 {
        return Err(io::Error::last_os_error());
    }
    if size as usize != request.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short ICMP echo request",
        ));
    }
    Ok(())
}

#[expect(
    unsafe_code,
    reason = "Receive into a bounded ICMP buffer and check the returned IPv4 source"
)]
fn receive(fd: &OwnedFd, packet: &mut [u8]) -> io::Result<Option<usize>> {
    let mut peer = address([0; 4]);
    let mut address_len = ADDRESS_LEN;
    // SAFETY: both initialized buffers stay exclusively writable across the
    // nonblocking call and the supplied lengths match their allocation.
    let size = unsafe {
        libc::recvfrom(
            fd.as_raw_fd(),
            packet.as_mut_ptr().cast(),
            packet.len(),
            libc::MSG_TRUNC,
            (&raw mut peer).cast(),
            &raw mut address_len,
        )
    };
    if size < 0 {
        return Err(io::Error::last_os_error());
    }
    let from_destination = address_len == ADDRESS_LEN
        && i32::from(peer.sin_family) == libc::AF_INET
        && peer.sin_addr.s_addr.to_ne_bytes() == DESTINATION;
    Ok(from_destination.then_some(size as usize))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_the_original_echo_reply() {
        let request = Echo::new(42, 1000);
        assert!(!request.matches(&request.0));
        let mut reply = request.0;
        reply[0] = 0;
        reply[2..4].fill(0);
        let sum = checksum(&reply);
        reply[2..4].copy_from_slice(&sum.to_be_bytes());
        assert!(request.matches(&reply));
        assert!(!Echo::new(43, 1000).matches(&reply));
        assert!(!Echo::new(42, 1001).matches(&reply));
        assert!(!request.matches(&reply[..reply.len() - 1]));
        let mut raw = [0; 20 + ECHO_LEN];
        raw[0] = 0x45;
        raw[2..4].copy_from_slice(&((20 + ECHO_LEN) as u16).to_be_bytes());
        raw[9] = libc::IPPROTO_ICMP as u8;
        raw[12..16].copy_from_slice(&DESTINATION);
        raw[16..20].copy_from_slice(&SOURCE);
        raw[20..].copy_from_slice(&reply);
        assert_eq!(Kind::Raw.body(&raw), Some(reply.as_slice()));
        raw[15] = 3;
        assert!(Kind::Raw.body(&raw).is_none());
        reply[2] ^= 1;
        assert!(!request.matches(&reply));
    }
}
