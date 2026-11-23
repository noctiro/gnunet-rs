use std::{io, net::SocketAddr, num::NonZeroU32};

#[cfg(unix)]
mod unix;

/// Prepared source selection for atomic, nonblocking UDP sends.
pub struct DatagramSource {
    source: SocketAddr,
    #[cfg(windows)]
    interface: NonZeroU32,
    #[cfg(unix)]
    control: unix::Control,
}

impl DatagramSource {
    /// Prepare a concrete local address and an original interface index.
    pub fn new(source: SocketAddr, interface: NonZeroU32) -> io::Result<Self> {
        if source.ip().is_unspecified() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(Self {
            source,
            #[cfg(windows)]
            interface,
            #[cfg(unix)]
            control: unix::Control::new(source, interface)?,
        })
    }

    /// Submit one datagram on the borrowed socket using this source.
    /// The caller owns readiness and deadline handling.
    #[cfg(unix)]
    pub fn send(
        &self,
        socket: std::os::fd::BorrowedFd<'_>,
        target: SocketAddr,
        packet: &[u8],
    ) -> io::Result<usize> {
        if self.source.is_ipv4() != target.is_ipv4() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.control.send(socket, target, packet)
    }

    /// Submit one datagram on the borrowed socket using this source.
    /// The caller owns readiness and deadline handling.
    #[cfg(windows)]
    pub fn send(
        &self,
        socket: std::os::windows::io::BorrowedSocket<'_>,
        target: SocketAddr,
        packet: &[u8],
    ) -> io::Result<usize> {
        super::send_windows::send_datagram_from(
            socket,
            self.source,
            self.interface.get(),
            target,
            packet,
        )
    }
}
