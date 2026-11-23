//! Bounded discovery sends on the original socket.
use super::{DatagramSocket, Profile, Sent, SocketError};
use gnunet_native::network::DatagramSource;
use gnunet_types::Error;
use socket2::SockRef;
use std::{
    future::Future,
    io,
    net::{Ipv6Addr, SocketAddr},
    num::NonZeroU32,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};
use tokio::{
    io::Interest,
    time::{Sleep, sleep_until},
};
pub(super) struct Pending {
    pub target: SocketAddr,
    source: DatagramSource,
    operation: u64,
    packet: [u8; 96],
    hard: Instant,
    timer: Pin<Box<Sleep>>,
}
impl DatagramSocket {
    pub(crate) fn join_discovery(&self, group: &Ipv6Addr, index: u32) -> Result<(), SocketError> {
        if self.profile != Profile::Ipv6 || index == 0 {
            return Err(Error::InvalidInput.into());
        }
        let socket = self.socket.as_deref().ok_or(Error::Closed)?;
        SockRef::from(socket).join_multicast_v6(group, index)?;
        Ok(())
    }
    pub(crate) fn leave_discovery(&self, group: &Ipv6Addr, index: u32) -> Result<(), SocketError> {
        let socket = self.socket.as_deref().ok_or(Error::Closed)?;
        SockRef::from(socket).leave_multicast_v6(group, index)?;
        Ok(())
    }
    pub(crate) fn queue_discovery(
        &mut self,
        source: SocketAddr,
        index: u32,
        target: SocketAddr,
        operation: u64,
        packet: [u8; 96],
        hard: Instant,
    ) -> Result<(), SocketError> {
        if self.has_pending_send() {
            return Err(Error::WouldBlock.into());
        }
        if !self.profile.accepts(source) || !self.profile.accepts(target) {
            return Err(Error::InvalidInput.into());
        }
        if Instant::now() >= hard {
            return Err(Error::Deadline.into());
        }
        let index = NonZeroU32::new(index).ok_or(Error::InvalidInput)?;
        let source = DatagramSource::new(source, index)?;
        let socket = self.socket.as_deref().ok_or(Error::Closed)?;
        if self.profile == Profile::Ipv4 {
            SockRef::from(socket).set_broadcast(true)?;
        }
        self.discovery = Some(Pending {
            source,
            target,
            operation,
            packet,
            hard,
            timer: Box::pin(sleep_until(hard.into())),
        });
        Ok(())
    }
    pub(crate) fn poll_discovery_guard(&mut self, cx: &mut Context<'_>) -> Result<(), SocketError> {
        if let Some(pending) = self.discovery.as_mut()
            && (Instant::now() >= pending.hard || pending.timer.as_mut().poll(cx).is_ready())
        {
            return Err(Error::Deadline.into());
        }
        Ok(())
    }
    pub(crate) fn poll_discovery_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Sent, SocketError>> {
        let Some(pending) = self.discovery.as_mut() else {
            return Poll::Pending;
        };
        // Native deadline is independent of canonical/source-clock progress and
        // precedes every attempt on the original immutable datagram.
        if Instant::now() >= pending.hard || pending.timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(Error::Deadline.into()));
        }
        let socket = self.socket.as_deref().ok_or(Error::Closed)?;
        match socket.poll_send_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result?,
        }
        if Instant::now() >= pending.hard {
            return Poll::Ready(Err(Error::Deadline.into()));
        }
        let result = socket.try_io(Interest::WRITABLE, || send(socket, pending));
        match result {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                // try_io clears readiness on WouldBlock. Register the same
                // original socket immediately, rather than returning an
                // unregistered pending wait after this readiness race.
                match socket.poll_send_ready(cx) {
                    Poll::Ready(Ok(())) => cx.waker().wake_by_ref(),
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                    Poll::Pending => {}
                }
                Poll::Pending
            }
            Err(error) => Poll::Ready(Err(error.into())),
            Ok(bytes) if bytes != pending.packet.len() => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short atomic discovery datagram",
            )
            .into())),
            Ok(bytes) => {
                let sent = Sent {
                    operation: pending.operation,
                    target: pending.target,
                    bytes,
                };
                self.discovery = None;
                Poll::Ready(Ok(sent))
            }
        }
    }
    pub(crate) fn cancel_discovery(&mut self) {
        self.discovery = None;
    }
}
fn send(socket: &tokio::net::UdpSocket, pending: &Pending) -> io::Result<usize> {
    #[cfg(unix)]
    let original = std::os::fd::AsFd::as_fd(socket);
    #[cfg(windows)]
    let original = std::os::windows::io::AsSocket::as_socket(socket);

    pending
        .source
        .send(original, pending.target, &pending.packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(flavor = "current_thread")]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Native loopback exercise asserts actual ancillary acceptance, packet bytes and selected source"
    )]
    async fn ancillary_source_selection_on_both_loopback_families() -> io::Result<()> {
        use std::net::{IpAddr, Ipv4Addr};
        let interfaces = gnunet_native::interfaces::snapshot(Default::default())?;
        for ip in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let index = interfaces
                .iter()
                .filter(|row| row.address.ip() == ip)
                .find_map(|row| NonZeroU32::new(row.index))
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "loopback interface"))?;
            let receiver = tokio::net::UdpSocket::bind(SocketAddr::new(ip, 0)).await?;
            let unspecified = if ip.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            };
            let sender = tokio::net::UdpSocket::bind(SocketAddr::new(unspecified, 0)).await?;
            let source = SocketAddr::new(ip, sender.local_addr()?.port());
            let until = Instant::now() + std::time::Duration::from_secs(2);
            let pending = Pending {
                source: DatagramSource::new(source, index)?,
                target: receiver.local_addr()?,
                operation: 1,
                packet: [0x47; 96],
                hard: until,
                timer: Box::pin(sleep_until(until.into())),
            };
            tokio::time::timeout_at(until.into(), async {
                loop {
                    sender.writable().await?;
                    match sender.try_io(Interest::WRITABLE, || send(&sender, &pending)) {
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                        result => {
                            assert_eq!(result?, pending.packet.len());
                            break;
                        }
                    }
                }
                let mut bytes = [0; 97];
                let (length, actual) = receiver.recv_from(&mut bytes).await?;
                assert_eq!(&bytes[..length], &pending.packet);
                assert_eq!(actual.ip(), source.ip());
                assert_eq!(actual.port(), source.port());
                Ok::<_, io::Error>(())
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "loopback ancillary send"))??;
        }
        Ok(())
    }
}
