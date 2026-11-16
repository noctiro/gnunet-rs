//! Exclusive fresh-child capture and one-shot native socket reconstruction.
use super::{
    mapping::View,
    record::{HEADER, MAGIC, RECORD, VERSION, WORDS, ensure_winsock, extent, socket_error},
};
use std::{
    fmt, io,
    os::windows::io::{FromRawHandle, FromRawSocket, OwnedHandle, OwnedSocket},
    sync::atomic::{AtomicU32, Ordering},
};
use windows_sys::Win32::{
    Foundation::{
        GetHandleInformation, HANDLE_FLAG_INHERIT, HANDLE_FLAG_PROTECT_FROM_CLOSE,
        INVALID_HANDLE_VALUE, SetHandleInformation,
    },
    Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNIX, FROM_PROTOCOL_INFO, INVALID_SOCKET, IPPROTO_TCP, SOCK_STREAM,
        WSA_FLAG_NO_HANDLE_INHERIT, WSA_FLAG_OVERLAPPED, WSAPROTOCOL_INFOW, WSASocketW,
    },
    System::{
        Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE},
        Memory::FILE_MAP_READ,
        Threading::GetCurrentProcessId,
    },
};
/// Original inherited read-only section, captured before unrelated owners.
/// Import, discard or exit the fresh process: Drop closes the mapping but does
/// not settle still-unused provider reservations already installed in this PID.
#[must_use = "materialize/discard activation or exit the fresh process; provider reservations cannot be canceled by closing the section"]
pub struct Incoming {
    // View retires before its section handle.
    view: View,
    _handle: OwnedHandle,
    count: usize,
}
impl fmt::Debug for Incoming {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Incoming")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}
impl Incoming {
    /// Adopt exactly one exclusively offered inherited section handle. No socket
    /// descriptor is adopted from an integer; actual sockets come from WSASocket.
    ///
    /// # Safety
    /// Fresh single-threaded child before files/runtime/other native owners. The
    /// handle is exclusively transferred foreign ownership, not any Rust/CRT or
    /// cached owner. The handle grants read-only mapping access. The native publisher finished immutable metadata before
    /// resuming this process; it retains no writable aliases. Repeated capture,
    /// concurrent close/reuse and continuing after capture failure are forbidden.
    #[expect(
        unsafe_code,
        reason = "The fresh-process caller offers one exclusive inherited mapping; native validation precedes unique ownership adoption and bounded view access"
    )]
    pub unsafe fn capture(raw: usize) -> io::Result<Self> {
        let handle = raw as *mut core::ffi::c_void;
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // SAFETY: scalar standard-table queries create no owners.
        let standards = unsafe {
            [
                GetStdHandle(STD_INPUT_HANDLE),
                GetStdHandle(STD_OUTPUT_HANDLE),
                GetStdHandle(STD_ERROR_HANDLE),
            ]
        };
        if standards.contains(&handle) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "activation section aliases a standard route",
            ));
        }
        let mut flags = 0;
        // SAFETY: native validation of a scalar handle; no owner exists yet.
        if unsafe { GetHandleInformation(handle, &mut flags) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if flags & HANDLE_FLAG_INHERIT == 0 || flags & HANDLE_FLAG_PROTECT_FROM_CLOSE != 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut header = View::new(handle, FILE_MAP_READ, HEADER)?;
        // SAFETY: immutable bounded header, native page alignment and publisher's
        // release ordering. No SDK metadata is consumed before complete validation.
        let magic = unsafe { &*header.pointer().cast::<AtomicU32>() }.load(Ordering::Acquire);
        if magic != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unpublished native activation section",
            ));
        }
        let mut words = [0u32; 7];
        for (index, value) in words.iter_mut().enumerate() {
            // SAFETY: exact initialized immutable header word.
            *value = unsafe { header.pointer().add(4 + index * 4).cast::<u32>().read() };
        }
        let [version, count, record, target, total, reserved0, reserved1] = words;
        // SAFETY: scalar query with no resource transfer.
        let current = unsafe { GetCurrentProcessId() };
        if version != VERSION
            || record as usize != RECORD
            || target != current
            || reserved0 != 0
            || reserved1 != 0
            || total as usize != extent(count as usize)?
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let view = View::new(handle, FILE_MAP_READ, total as usize)?;
        header.close()?;
        // SAFETY: native section kind/extent validated; transfer is exclusive and
        // complete. Clear inheritance before any later unrelated child launch.
        let owned = unsafe { OwnedHandle::from_raw_handle(handle) };
        // SAFETY: original owned section, only its inheritance flag is changed.
        if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            view,
            _handle: owned,
            count: count as usize,
        })
    }
    /// Materialize every one-shot native record, retaining no section after
    /// success. Failure can leave unused provider reservations: exit this fresh
    /// process rather than replaying or continuing with a partial activation.
    #[expect(
        unsafe_code,
        reason = "Immutable exact native records are copied into aligned initialized storage; only successful WSASocketW descriptors receive fresh unique Rust owners"
    )]
    pub fn materialize(mut self) -> io::Result<Vec<OwnedSocket>> {
        let mut sockets = Vec::new();
        sockets
            .try_reserve_exact(self.count)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        ensure_winsock()?;
        for index in 0..self.count {
            let mut words = [0u32; WORDS];
            // SAFETY: both extents are exactly RECORD initialized bytes, disjoint;
            // u32 arrays preserve every ABI byte without reading Rust padding.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    self.view.pointer().add(HEADER + index * RECORD),
                    words.as_mut_ptr().cast::<u8>(),
                    RECORD,
                )
            };
            // SAFETY: compile-time size/alignment checks, all native fields are
            // integer/array/GUID values and accept every initialized bit pattern.
            let info = unsafe { &*words.as_ptr().cast::<WSAPROTOCOL_INFOW>() };
            if info.iSocketType != SOCK_STREAM
                || ![i32::from(AF_INET), i32::from(AF_INET6), i32::from(AF_UNIX)]
                    .contains(&info.iAddressFamily)
                || (info.iAddressFamily != i32::from(AF_UNIX) && info.iProtocol != IPPROTO_TCP)
                || !(-1..=7).contains(&info.ProtocolChain.ChainLen)
                || !info.szProtocol.contains(&0)
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            // SAFETY: complete original one-shot SDK record, no pointer retained.
            // Reuse is refused by Winsock with WSAEINVAL, never adopted twice.
            let raw = unsafe {
                WSASocketW(
                    FROM_PROTOCOL_INFO,
                    FROM_PROTOCOL_INFO,
                    FROM_PROTOCOL_INFO,
                    info,
                    0,
                    WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
                )
            };
            if raw == INVALID_SOCKET {
                return Err(socket_error());
            }
            // SAFETY: successful WSASocket returns one new uniquely owned socket.
            sockets.push(unsafe { OwnedSocket::from_raw_socket(raw as _) });
        }
        self.view.close()?;
        Ok(sockets)
    }
    /// Consume and close all imported descriptors without registering/listening
    /// through another owner. Any failure still requires fresh-process exit.
    pub fn discard(self) -> io::Result<()> {
        self.materialize().map(drop)
    }
}
