//! Provider-specific synchronous WSASendMsg on the original borrowed socket.
use socket2::SockAddr;
use std::{
    ffi::c_void,
    io,
    mem::{align_of, size_of},
    net::SocketAddr,
    num::NonZeroU32,
    os::windows::io::{AsRawSocket, BorrowedSocket, RawSocket},
    ptr,
};
use windows_sys::Win32::Networking::WinSock::*;
use windows_sys::core::GUID;

// WSA_CMSG_DATA uses MAX_NATURAL_ALIGNMENT. WSA_CMSG_NXTHDR aligns the
// preceding record extent to TYPE_ALIGNMENT(WSACMSGHDR).
pub(super) const CONTROL_DATA: usize = size_of::<CMSGHDR>().next_multiple_of(size_of::<usize>());

pub(super) const fn align_control_header(length: usize) -> usize {
    length.next_multiple_of(align_of::<CMSGHDR>())
}

fn invalid() -> io::Error {
    io::ErrorKind::InvalidInput.into()
}
#[expect(
    unsafe_code,
    reason = "Reads only the calling thread Winsock error code"
)]
pub(super) fn last_error() -> io::Error {
    // SAFETY: thread-local Winsock diagnostic, with no borrowed memory.
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}

#[expect(
    unsafe_code,
    reason = "A synchronous provider query borrows the exact original socket and two fixed SDK storage extents"
)]
pub(super) fn extension_pointer(socket: BorrowedSocket<'_>, id: &GUID) -> io::Result<*mut c_void> {
    let mut pointer = ptr::null_mut::<c_void>();
    let mut returned = 0;
    // SAFETY: the initialized GUID and pointer-sized output storage match the
    // specified Winsock control code. No OVERLAPPED or completion callback escapes.
    let status = unsafe {
        WSAIoctl(
            socket.as_raw_socket() as SOCKET,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            ptr::from_ref(id).cast(),
            size_of::<GUID>() as u32,
            ptr::from_mut(&mut pointer).cast(),
            size_of::<*mut c_void>() as u32,
            &mut returned,
            ptr::null_mut(),
            None,
        )
    };
    if status == SOCKET_ERROR {
        return Err(last_error());
    }
    if returned as usize != size_of::<*mut c_void>() || pointer.is_null() {
        return Err(io::Error::other(
            "invalid Winsock extension provider result",
        ));
    }
    Ok(pointer)
}

pub(super) struct SendMsg {
    original: RawSocket,
    function: LPFN_WSASENDMSG,
}

impl SendMsg {
    #[expect(
        unsafe_code,
        reason = "The WSAID_WSASENDMSG GUID selects the SDK's LPFN_WSASENDMSG function type"
    )]
    pub(super) fn new(socket: BorrowedSocket<'_>) -> io::Result<Self> {
        let pointer = extension_pointer(socket, &WSAID_WSASENDMSG)?;
        // SAFETY: Winsock returned a checked non-null provider pointer for
        // exactly the SDK extension GUID and the original socket.
        let function = unsafe { std::mem::transmute::<*mut c_void, LPFN_WSASENDMSG>(pointer) };
        Ok(Self {
            original: socket.as_raw_socket(),
            function,
        })
    }

    #[expect(
        unsafe_code,
        reason = "Initialized SDK address/control buffers and the provider function are borrowed synchronously by this original socket"
    )]
    pub(super) fn send(
        &self,
        socket: BorrowedSocket<'_>,
        source: SocketAddr,
        interface: Option<NonZeroU32>,
        target: SocketAddr,
        packet: &[u8],
    ) -> io::Result<usize> {
        if socket.as_raw_socket() != self.original || !valid_source(source, target) {
            return Err(invalid());
        }
        let function = self
            .function
            .ok_or_else(|| io::Error::other("WSASendMsg provider unavailable"))?;
        let index = interface.map_or(0, NonZeroU32::get);
        let data = CONTROL_DATA;
        let (level, kind, payload) = match source {
            SocketAddr::V4(_) => (IPPROTO_IP, IP_PKTINFO, size_of::<IN_PKTINFO>()),
            SocketAddr::V6(_) => (IPPROTO_IPV6, IPV6_PKTINFO, size_of::<IN6_PKTINFO>()),
        };
        let mut control = [0_usize; 8];
        let length = (size_of::<CMSGHDR>() + align_control_header(payload))
            .next_multiple_of(size_of::<usize>());
        if length > size_of_val(&control) {
            return Err(invalid());
        }
        let bytes = control.as_mut_ptr().cast::<u8>();
        // SAFETY: usize storage aligns CMSGHDR and both plain SDK payloads; the
        // checked extent includes the complete header, data and zeroed padding.
        unsafe {
            ptr::write(
                bytes.cast::<CMSGHDR>(),
                CMSGHDR {
                    cmsg_len: data + payload,
                    cmsg_level: level,
                    cmsg_type: kind,
                },
            );
        }
        match source {
            SocketAddr::V4(address) => {
                let info = IN_PKTINFO {
                    ipi_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_addr: u32::from_ne_bytes(address.ip().octets()),
                        },
                    },
                    ipi_ifindex: index,
                };
                // SAFETY: bounded aligned plain IN_PKTINFO storage above.
                unsafe {
                    ptr::write(bytes.add(data).cast::<IN_PKTINFO>(), info);
                }
            }
            SocketAddr::V6(address) => {
                let info = IN6_PKTINFO {
                    ipi6_addr: IN6_ADDR {
                        u: IN6_ADDR_0 {
                            Byte: address.ip().octets(),
                        },
                    },
                    ipi6_ifindex: index,
                };
                // SAFETY: bounded aligned plain IN6_PKTINFO storage above.
                unsafe {
                    ptr::write(bytes.add(data).cast::<IN6_PKTINFO>(), info);
                }
            }
        }
        let target = SockAddr::from(match target {
            SocketAddr::V6(mut address) => {
                address.set_flowinfo(address.flowinfo().to_be());
                SocketAddr::V6(address)
            }
            address => address,
        });
        let mut buffer = WSABUF {
            len: u32::try_from(packet.len()).map_err(|_| invalid())?,
            buf: packet.as_ptr().cast_mut(),
        };
        let message = WSAMSG {
            name: target.as_ptr().cast_mut().cast(),
            namelen: target.len(),
            lpBuffers: &mut buffer,
            dwBufferCount: 1,
            Control: WSABUF {
                len: length as u32,
                buf: bytes,
            },
            dwFlags: 0,
        };
        let mut sent = 0;
        // SAFETY: synchronous call (no OVERLAPPED) reads the original immutable
        // payload and initialized address/control storage only until return.
        if unsafe {
            function(
                socket.as_raw_socket() as SOCKET,
                &message,
                0,
                &mut sent,
                ptr::null_mut(),
                None,
            )
        } == SOCKET_ERROR
        {
            return Err(last_error());
        }
        Ok(sent as usize)
    }
}

fn valid_source(source: SocketAddr, target: SocketAddr) -> bool {
    source.is_ipv4() == target.is_ipv4() && !source.ip().is_unspecified()
}

/// Send exactly one datagram using the selected local address and interface.
/// The socket stays owned by its caller. A successful return counts only local
/// kernel acceptance; errors retain their native code and imply no delivery.
/// The caller owns nonblocking mode and its readiness/deadline policy.
pub fn send_datagram_from(
    socket: BorrowedSocket<'_>,
    source: SocketAddr,
    index: u32,
    target: SocketAddr,
    packet: &[u8],
) -> io::Result<usize> {
    let index = NonZeroU32::new(index).ok_or_else(invalid)?;
    if !valid_source(source, target) {
        return Err(invalid());
    }
    SendMsg::new(socket)?.send(socket, source, Some(index), target, packet)
}
