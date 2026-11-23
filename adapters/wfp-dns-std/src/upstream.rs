//! ALE endpoint observations from the original borrowed upstream sockets.
//!
//! Keep the real socket owner alive independently of these numeric observations.
//! An endpoint value grants no kernel custody, exclusion or socket-lifetime proof.
use std::{
    fmt,
    num::NonZeroU64,
    os::windows::io::{AsRawSocket, AsSocket},
    ptr,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IPPROTO_UDP, SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE, SO_PROTOCOL_INFOW,
    SOCK_DGRAM, SOCKET_ERROR, SOL_SOCKET, WSAGetLastError, WSAIoctl, WSAPROTOCOL_INFOW,
    XP1_IFS_HANDLES, getsockopt,
};

/// Successful nonzero native identity observation, without a lifetime capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Endpoint(NonZeroU64);
impl Endpoint {
    /// Observed UINT64 identity; keep its original socket owner independently.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Original Winsock failure or invalid successful endpoint output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Exact WSAGetLastError value from the original failing operation.
    Winsock {
        /// Original synchronous Winsock operation.
        operation: &'static str,
        /// Original signed Winsock error carrier.
        code: i32,
    },
    /// The native query did not return exactly one UINT64.
    Extent {
        /// Original byte count reported by WSAIoctl.
        returned: u32,
    },
    /// Native protocol information did not have its exact complete SDK extent.
    ProtocolExtent {
        /// Original getsockopt length.
        returned: i32,
    },
    /// The original provider did not expose an IFS socket handle.
    NonIfs,
    /// The socket is not an IPv4 or IPv6 UDP datagram endpoint.
    Protocol,
    /// Native success returned no usable nonzero endpoint identity.
    MissingEndpoint,
}
impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Winsock { operation, code } => {
                write!(output, "{operation} returned Winsock error {code}")
            }
            Self::Extent { returned } => {
                write!(
                    output,
                    "ALE endpoint query returned {returned} bytes, expected 8"
                )
            }
            Self::ProtocolExtent { returned } => write!(
                output,
                "socket protocol query returned {returned} bytes, expected {}",
                size_of::<WSAPROTOCOL_INFOW>()
            ),
            Self::NonIfs => output.write_str("original upstream socket is not an IFS handle"),
            Self::Protocol => output.write_str("original upstream socket is not IPv4 or IPv6 UDP"),
            Self::MissingEndpoint => output.write_str("ALE endpoint query returned zero"),
        }
    }
}
impl std::error::Error for Error {}

/// Query the real original socket's ALE endpoint without sending or receiving.
/// The socket remains borrowed through this synchronous query. Retain its actual
/// owner through any later policy/driver use; this observation alone pins nothing.
/// See [Winsock IOCTLs](https://learn.microsoft.com/windows/win32/winsock/winsock-ioctls).
///
/// # Errors
/// Preserves original Winsock errors and refuses non-IFS/non-UDP sockets, zero
/// endpoint identities, or inexact native output.
/// The existing socket owner must already maintain Winsock initialization.
#[expect(
    unsafe_code,
    reason = "Synchronous WSAIoctl borrows the real socket and one aligned initialized UINT64 output; WSAGetLastError immediately preserves its failing operation"
)]
pub fn query(socket: &impl AsSocket) -> Result<Endpoint, Error> {
    let socket = socket.as_socket();
    let raw = socket.as_raw_socket() as usize;
    let mut protocol = WSAPROTOCOL_INFOW::default();
    let mut length = size_of::<WSAPROTOCOL_INFOW>() as i32;
    // SAFETY: the borrowed original socket and complete aligned protocol record
    // remain live through the synchronous call; optlen exactly bounds the output.
    let status = unsafe {
        getsockopt(
            raw,
            SOL_SOCKET,
            SO_PROTOCOL_INFOW,
            (&raw mut protocol).cast(),
            &mut length,
        )
    };
    if status == SOCKET_ERROR {
        // SAFETY: no intervening Winsock call changed the original error.
        let code = unsafe { WSAGetLastError() };
        return Err(Error::Winsock {
            operation: "getsockopt(SO_PROTOCOL_INFOW)",
            code,
        });
    }
    if length != size_of::<WSAPROTOCOL_INFOW>() as i32 {
        return Err(Error::ProtocolExtent { returned: length });
    }
    if protocol.dwServiceFlags1 & XP1_IFS_HANDLES == 0 {
        return Err(Error::NonIfs);
    }
    if protocol.iSocketType != SOCK_DGRAM
        || protocol.iProtocol != IPPROTO_UDP
        || ![i32::from(AF_INET), i32::from(AF_INET6)].contains(&protocol.iAddressFamily)
    {
        return Err(Error::Protocol);
    }
    let mut endpoint = 0_u64;
    let mut returned = 0;
    // SAFETY: original socket is borrowed, input is absent, output is one aligned
    // live UINT64, and null overlapped/completion arguments forbid retained data.
    let status = unsafe {
        WSAIoctl(
            raw,
            SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE,
            ptr::null(),
            0,
            (&raw mut endpoint).cast(),
            size_of::<u64>() as u32,
            &mut returned,
            ptr::null_mut(),
            None,
        )
    };
    if status == SOCKET_ERROR {
        // SAFETY: no intervening Winsock call changed this thread's last error.
        let code = unsafe { WSAGetLastError() };
        return Err(Error::Winsock {
            operation: "WSAIoctl(SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE)",
            code,
        });
    }
    if returned != size_of::<u64>() as u32 {
        return Err(Error::Extent { returned });
    }
    NonZeroU64::new(endpoint)
        .map(Endpoint)
        .ok_or(Error::MissingEndpoint)
}
