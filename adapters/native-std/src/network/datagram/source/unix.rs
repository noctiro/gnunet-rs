use socket2::{MsgHdr, SockAddr, SockRef};
use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    num::NonZeroU32,
    os::fd::BorrowedFd,
};

#[repr(align(8))]
pub(super) struct Control {
    bytes: [u8; 64],
    len: usize,
}

impl Control {
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd"
    ))]
    #[expect(
        unsafe_code,
        reason = "compute native CMSG extents and initialize the native header"
    )]
    pub(super) fn new(source: SocketAddr, interface: NonZeroU32) -> io::Result<Self> {
        use std::mem::offset_of;

        let (level, kind, payload) = match source {
            SocketAddr::V4(_) => {
                #[cfg(target_os = "freebsd")]
                let info = (libc::IP_SENDSRCADDR, size_of::<libc::in_addr>());
                #[cfg(not(target_os = "freebsd"))]
                let info = (libc::IP_PKTINFO, size_of::<libc::in_pktinfo>());
                (libc::IPPROTO_IP, info.0, info.1)
            }
            SocketAddr::V6(_) => (
                libc::IPPROTO_IPV6,
                libc::IPV6_PKTINFO,
                size_of::<libc::in6_pktinfo>(),
            ),
        };
        let mut bytes = [0; 64];
        // SAFETY: CMSG_LEN and CMSG_SPACE perform arithmetic on fixed, small lengths.
        let (data, length, len) = unsafe {
            (
                libc::CMSG_LEN(0) as usize,
                libc::CMSG_LEN(payload as u32),
                libc::CMSG_SPACE(payload as u32) as usize,
            )
        };
        if len > bytes.len() {
            return Err(io::Error::other(
                "UDP source control exceeds buffer capacity",
            ));
        }
        // SAFETY: cmsghdr and its platform padding contain only integers.
        let mut header: libc::cmsghdr = unsafe { std::mem::zeroed() };
        header.cmsg_len = length as _;
        field(
            &mut bytes,
            offset_of!(libc::cmsghdr, cmsg_len),
            &header.cmsg_len.to_ne_bytes(),
        );
        field(
            &mut bytes,
            offset_of!(libc::cmsghdr, cmsg_level),
            &level.to_ne_bytes(),
        );
        field(
            &mut bytes,
            offset_of!(libc::cmsghdr, cmsg_type),
            &kind.to_ne_bytes(),
        );

        match source {
            SocketAddr::V4(source) => {
                #[cfg(target_os = "freebsd")]
                field(&mut bytes, data, &source.ip().octets());
                #[cfg(not(target_os = "freebsd"))]
                {
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    {
                        let index = i32::try_from(interface.get())
                            .map_err(|_| io::ErrorKind::InvalidInput)?;
                        field(
                            &mut bytes,
                            data + offset_of!(libc::in_pktinfo, ipi_ifindex),
                            &index.to_ne_bytes(),
                        );
                    }
                    // Darwin gives a nonzero interface index priority over
                    // the exact local address. Keep that field zero there.
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
                    &interface.get().to_ne_bytes(),
                );
            }
        }
        Ok(Self { bytes, len })
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd"
    )))]
    pub(super) fn new(_source: SocketAddr, _interface: NonZeroU32) -> io::Result<Self> {
        Err(io::ErrorKind::Unsupported.into())
    }

    pub(super) fn send(
        &self,
        socket: BorrowedFd<'_>,
        target: SocketAddr,
        packet: &[u8],
    ) -> io::Result<usize> {
        let address = SockAddr::from(target);
        let buffers = [IoSlice::new(packet)];
        let message = MsgHdr::new()
            .with_addr(&address)
            .with_buffers(&buffers)
            .with_control(&self.bytes[..self.len]);
        SockRef::from(&socket).sendmsg(&message, 0)
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd"
))]
fn field(out: &mut [u8], offset: usize, bytes: &[u8]) {
    out[offset..offset + bytes.len()].copy_from_slice(bytes);
}
