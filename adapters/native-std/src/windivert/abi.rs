//! WinDivert 2.2 C ABI. Fixed-width fields follow the official public header.
use crate::library::Library;
use std::{
    ffi::{c_char, c_void},
    io,
};
use windows_sys::Win32::{Foundation::HANDLE, System::IO::OVERLAPPED};
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Address {
    pub timestamp: i64,
    pub flags: u32,
    pub reserved: u32,
    pub data: [u64; 8],
}
const _: () = assert!(size_of::<Address>() == 80 && align_of::<Address>() == 8);
pub(super) const OUTBOUND: u32 = 1 << 17;
pub(super) const LOOPBACK: u32 = 1 << 18;
pub(super) const IPV6: u32 = 1 << 20;
pub(super) const IP_CHECKSUM: u32 = 1 << 21;
pub(super) const UDP_CHECKSUM: u32 = 1 << 23;
type Open = unsafe extern "C" fn(*const c_char, i32, i16, u64) -> HANDLE;
type Recv = unsafe extern "C" fn(
    HANDLE,
    *mut c_void,
    u32,
    *mut u32,
    u64,
    *mut Address,
    *mut u32,
    *mut OVERLAPPED,
) -> i32;
type SendPacket = unsafe extern "C" fn(
    HANDLE,
    *const c_void,
    u32,
    *mut u32,
    u64,
    *const Address,
    u32,
    *mut OVERLAPPED,
) -> i32;
type Shutdown = unsafe extern "C" fn(HANDLE, i32) -> i32;
type Close = unsafe extern "C" fn(HANDLE) -> i32;
type Set = unsafe extern "C" fn(HANDLE, i32, u64) -> i32;
type Get = unsafe extern "C" fn(HANDLE, i32, *mut u64) -> i32;
pub(super) struct Api {
    _library: Library,
    pub open: Open,
    pub recv: Recv,
    pub send: SendPacket,
    pub shutdown: Shutdown,
    pub close: Close,
    pub set: Set,
    pub get: Get,
}
#[expect(
    unsafe_code,
    reason = "This fully resolved WinDivert export table is immutable; the documented API supports calls from multiple threads and its Windows loader reference can be released on the final callback thread"
)]
// SAFETY: no Library operation is exposed after construction. Only immutable
// thread-safe WinDivert exports run; the last owner releases the loader reference.
unsafe impl Send for Api {}
#[expect(
    unsafe_code,
    reason = "Only the immutable, fully resolved thread-safe provider table is shared; no thread-local Library API is callable after publication"
)]
// SAFETY: all mutable device/operation state is separately synchronized.
unsafe impl Sync for Api {}
impl Api {
    #[expect(
        unsafe_code,
        reason = "The caller supplies the official trusted WinDivert C ABI; every exact signature is resolved before the table is shared"
    )]
    pub unsafe fn resolve(library: Library) -> io::Result<Self> {
        macro_rules! export {
            ($name:literal, $ty:ty) => {{
                let raw = library.symbol($name)?;
                // SAFETY: explicit provider trust certifies this exact C signature.
                unsafe { std::mem::transmute::<*mut c_void, $ty>(raw) }
            }};
        }
        Ok(Self {
            open: export!(c"WinDivertOpen", Open),
            recv: export!(c"WinDivertRecvEx", Recv),
            send: export!(c"WinDivertSendEx", SendPacket),
            shutdown: export!(c"WinDivertShutdown", Shutdown),
            close: export!(c"WinDivertClose", Close),
            set: export!(c"WinDivertSetParam", Set),
            get: export!(c"WinDivertGetParam", Get),
            _library: library,
        })
    }
}
