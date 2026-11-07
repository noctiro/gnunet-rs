//! Safe sendmsg control construction for actual interface/source selection.
//! No raw FD owner or ancillary pointer is manufactured in this crate.
use super::{DatagramSocket, Profile, Sent, SocketError};
use gnunet_types::Error;
use socket2::{MsgHdr, SockAddr, SockRef};
use std::{
    future::Future,
    io::{self, IoSlice},
    net::{Ipv6Addr, SocketAddr},
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
    source: SocketAddr,
    index: u32,
    operation: u64,
    packet: [u8; 96],
    hard: Instant,
    timer: Pin<Box<Sleep>>,
}
impl DatagramSocket {
    /// Whether either original encrypted or discovery datagram owns TX. This
    /// must be checked before creating a new encrypted packet/consuming a nonce.
    pub fn has_pending_send(&self) -> bool {
        self.pending.is_some() || self.discovery.is_some()
    }
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
        if index == 0 || !self.profile.accepts(source) || !self.profile.accepts(target) {
            return Err(Error::InvalidInput.into());
        }
        if Instant::now() >= hard {
            return Err(Error::Deadline.into());
        }
        let socket = self.socket.as_deref().ok_or(Error::Closed)?;
        if self.profile == Profile::Ipv4 {
            SockRef::from(socket).set_broadcast(true)?;
        }
        // Validate/prepare ancillary metadata before publishing this pending
        // packet, preserving the existing pending packet on all refusals.
        control(source, index)?;
        self.discovery = Some(Pending {
            source,
            index,
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
    let (control, len) = control(pending.source, pending.index)?;
    let address = SockAddr::from(pending.target);
    let buffers = [IoSlice::new(&pending.packet)];
    let message = MsgHdr::new()
        .with_addr(&address)
        .with_buffers(&buffers)
        .with_control(&control[..len]);
    SockRef::from(socket).sendmsg(&message, 0)
}
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn field(out: &mut [u8], offset: usize, bytes: &[u8]) {
    out[offset..offset + bytes.len()].copy_from_slice(bytes);
}
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn control(source: SocketAddr, index: u32) -> io::Result<([u8; 64], usize)> {
    use std::mem::{align_of, offset_of, size_of};
    // FreeBSD CMSG_DATA/SPACE use native long alignment, which may exceed
    // the alignment of its socklen_t-based cmsghdr itself.
    let alignment = if cfg!(target_os = "freebsd") {
        size_of::<libc::c_long>()
    } else {
        align_of::<libc::cmsghdr>()
    };
    let align = |n: usize| (n + alignment - 1) & !(alignment - 1);
    let data = align(size_of::<libc::cmsghdr>());
    let (level, kind, payload) = match source {
        SocketAddr::V4(_) => {
            #[cfg(target_os = "freebsd")]
            {
                (
                    libc::IPPROTO_IP,
                    libc::IP_SENDSRCADDR,
                    size_of::<libc::in_addr>(),
                )
            }
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                (
                    libc::IPPROTO_IP,
                    libc::IP_PKTINFO,
                    size_of::<libc::in_pktinfo>(),
                )
            }
        }
        SocketAddr::V6(_) => (
            libc::IPPROTO_IPV6,
            libc::IPV6_PKTINFO,
            size_of::<libc::in6_pktinfo>(),
        ),
    };
    let length = data + payload;
    let total = data + align(payload);
    if total > 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ancillary buffer exceeds bound",
        ));
    }
    #[cfg(target_os = "linux")]
    let cmsg_len = length;
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    let cmsg_len = u32::try_from(length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "ancillary length"))?;
    let header = libc::cmsghdr {
        cmsg_len,
        cmsg_level: level,
        cmsg_type: kind,
    };
    let mut bytes = [0; 64];
    field(
        &mut bytes,
        offset_of!(libc::cmsghdr, cmsg_len),
        &header.cmsg_len.to_ne_bytes(),
    );
    field(
        &mut bytes,
        offset_of!(libc::cmsghdr, cmsg_level),
        &header.cmsg_level.to_ne_bytes(),
    );
    field(
        &mut bytes,
        offset_of!(libc::cmsghdr, cmsg_type),
        &header.cmsg_type.to_ne_bytes(),
    );
    match source {
        SocketAddr::V4(source) => {
            #[cfg(target_os = "freebsd")]
            field(&mut bytes, data, &source.ip().octets());
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                #[cfg(target_os = "linux")]
                let native_index = i32::try_from(index)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface index"))?;
                // Darwin's SDK specifies that a nonzero ipi_ifindex takes
                // precedence over ipi_spec_dst. Keep it zero there so an alias's
                // exact signed source IP, rather than an interface primary, wins.
                #[cfg(target_os = "macos")]
                let native_index = 0i32;
                field(
                    &mut bytes,
                    data + offset_of!(libc::in_pktinfo, ipi_ifindex),
                    &native_index.to_ne_bytes(),
                );
                field(
                    &mut bytes,
                    data + offset_of!(libc::in_pktinfo, ipi_spec_dst),
                    &source.ip().octets(),
                );
            }
        }
        SocketAddr::V6(source) => {
            field(
                &mut bytes,
                data + offset_of!(libc::in6_pktinfo, ipi6_addr),
                &source.ip().octets(),
            );
            field(
                &mut bytes,
                data + offset_of!(libc::in6_pktinfo, ipi6_ifindex),
                &index.to_ne_bytes(),
            );
        }
    }
    Ok((bytes, total))
}
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
fn control(_source: SocketAddr, _index: u32) -> io::Result<([u8; 64], usize)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native discovery source selection is not qualified on this target",
    ))
}

#[cfg(all(
    test,
    any(target_os = "linux", target_os = "macos", target_os = "freebsd")
))]
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
                .find(|row| row.address.ip() == ip && row.index != 0)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "loopback interface"))?
                .index;
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
                source,
                index,
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
