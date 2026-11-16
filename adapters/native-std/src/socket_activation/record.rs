//! Bounded native SDK record layout and process-lifetime Winsock initialization.
use std::{
    io,
    mem::{align_of, size_of},
    sync::OnceLock,
};
use windows_sys::Win32::Networking::WinSock::{
    WSADATA, WSAGetLastError, WSAPROTOCOL_INFOW, WSAStartup,
};
/// Maximum listeners admitted by one native startup transfer.
pub const MAX_LISTENERS: usize = 4096;
pub(super) const HEADER: usize = 32;
pub(super) const RECORD: usize = size_of::<WSAPROTOCOL_INFOW>();
pub(super) const WORDS: usize = RECORD / size_of::<u32>();
pub(super) const MAGIC: u32 = 0x414e_5247;
pub(super) const VERSION: u32 = 1;
const _: () = assert!(
    RECORD.is_multiple_of(4)
        && align_of::<WSAPROTOCOL_INFOW>() <= 4
        && cfg!(target_endian = "little")
);

pub(super) fn extent(count: usize) -> io::Result<usize> {
    if count > MAX_LISTENERS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native activation listener capacity",
        ));
    }
    count
        .checked_mul(RECORD)
        .and_then(|bytes| bytes.checked_add(HEADER))
        .ok_or_else(|| io::ErrorKind::InvalidInput.into())
}
#[expect(
    unsafe_code,
    reason = "WSAStartup fills exact writable WSADATA; one successful process-lifetime reference prevents reconstructed socket owners from outliving their Winsock initialization"
)]
pub(super) fn ensure_winsock() -> io::Result<()> {
    static STARTED: OnceLock<Result<(), i32>> = OnceLock::new();
    let result = STARTED.get_or_init(|| {
        let mut data = std::mem::MaybeUninit::<WSADATA>::uninit();
        // SAFETY: exact initialized extent, requested Winsock 2.2; the successful
        // reference is deliberately retained for this process's entire lifetime.
        let code = unsafe { WSAStartup(0x0202, data.as_mut_ptr()) };
        if code == 0 { Ok(()) } else { Err(code) }
    });
    match result {
        Ok(()) => Ok(()),
        Err(code) => Err(io::Error::from_raw_os_error(*code)),
    }
}
#[expect(
    unsafe_code,
    reason = "WSAGetLastError reads the current thread's original Winsock error before any cleanup/native call"
)]
pub(super) fn socket_error() -> io::Error {
    // SAFETY: scalar observation with no borrowed storage.
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}
