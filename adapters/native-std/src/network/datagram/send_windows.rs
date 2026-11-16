//! Provider-specific synchronous WSASendMsg on the original borrowed socket.
use std::{
    io,
    mem::{align_of, size_of},
    net::SocketAddr,
    os::windows::io::{AsRawSocket, BorrowedSocket},
    ptr,
};
use windows_sys::Win32::Networking::WinSock::*;

fn invalid() -> io::Error {
    io::ErrorKind::InvalidInput.into()
}
#[expect(
    unsafe_code,
    reason = "Reads only the calling thread Winsock error code"
)]
fn last_error() -> io::Error {
    // SAFETY: thread-local Winsock diagnostic, with no borrowed memory.
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}
/// Send exactly one datagram using the selected local address and interface.
/// The socket stays owned by its caller. A successful return counts only local
/// kernel acceptance; errors retain their native code and imply no delivery.
/// The caller owns nonblocking mode and its readiness/deadline policy.
#[expect(
    unsafe_code,
    reason = "Initialized SDK address/control buffers and the provider function are borrowed synchronously by this original socket"
)]
pub fn send_datagram_from(
    socket: BorrowedSocket<'_>,
    source: SocketAddr,
    index: u32,
    target: SocketAddr,
    packet: &[u8],
) -> io::Result<usize> {
    if index == 0 || source.is_ipv4() != target.is_ipv4() || source.ip().is_unspecified() {
        return Err(invalid());
    }
    let mut function: LPFN_WSASENDMSG = None;
    let mut returned = 0;
    // SAFETY: all buffers have exactly their declared initialized size. The
    // extension belongs to this live socket's provider and is never cached.
    let status = unsafe {
        WSAIoctl(
            socket.as_raw_socket() as SOCKET,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            std::ptr::from_ref(&WSAID_WSASENDMSG).cast(),
            size_of_val(&WSAID_WSASENDMSG) as u32,
            (&mut function as *mut LPFN_WSASENDMSG).cast(),
            size_of::<LPFN_WSASENDMSG>() as u32,
            &mut returned,
            ptr::null_mut(),
            None,
        )
    };
    if status == SOCKET_ERROR {
        return Err(last_error());
    }
    if returned as usize != size_of::<LPFN_WSASENDMSG>() {
        return Err(io::Error::other("invalid WSASendMsg provider result"));
    }
    let function = function.ok_or_else(|| io::Error::other("WSASendMsg provider unavailable"))?;
    let align = |bytes: usize| (bytes + align_of::<usize>() - 1) & !(align_of::<usize>() - 1);
    let data = align(size_of::<CMSGHDR>());
    let (level, kind, payload) = match source {
        SocketAddr::V4(_) => (IPPROTO_IP, IP_PKTINFO, size_of::<IN_PKTINFO>()),
        SocketAddr::V6(_) => (IPPROTO_IPV6, IPV6_PKTINFO, size_of::<IN6_PKTINFO>()),
    };
    let mut control = [0_usize; 8];
    let length = data + align(payload);
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
    let mut v4 = SOCKADDR_IN::default();
    let mut v6 = SOCKADDR_IN6::default();
    let (name, namelen) = match target {
        SocketAddr::V4(address) => {
            v4.sin_family = AF_INET;
            v4.sin_port = address.port().to_be();
            v4.sin_addr.S_un = IN_ADDR_0 {
                S_addr: u32::from_ne_bytes(address.ip().octets()),
            };
            (
                (&mut v4 as *mut SOCKADDR_IN).cast(),
                size_of::<SOCKADDR_IN>(),
            )
        }
        SocketAddr::V6(address) => {
            v6.sin6_family = AF_INET6;
            v6.sin6_port = address.port().to_be();
            v6.sin6_flowinfo = address.flowinfo().to_be();
            v6.sin6_addr.u = IN6_ADDR_0 {
                Byte: address.ip().octets(),
            };
            v6.Anonymous = SOCKADDR_IN6_0 {
                sin6_scope_id: address.scope_id(),
            };
            (
                (&mut v6 as *mut SOCKADDR_IN6).cast(),
                size_of::<SOCKADDR_IN6>(),
            )
        }
    };
    let mut buffer = WSABUF {
        len: u32::try_from(packet.len()).map_err(|_| invalid())?,
        buf: packet.as_ptr().cast_mut(),
    };
    let message = WSAMSG {
        name,
        namelen: namelen as i32,
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
