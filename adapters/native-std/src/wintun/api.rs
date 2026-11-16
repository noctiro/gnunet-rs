//! Exact WINAPI exports from the official Wintun public API header.
use crate::library::Library;
use std::{ffi::c_void, io};
use windows_sys::{
    Win32::{Foundation::HANDLE, NetworkManagement::Ndis::NET_LUID_LH},
    core::GUID,
};
type Create = unsafe extern "system" fn(*const u16, *const u16, *const GUID) -> *mut c_void;
type Open = unsafe extern "system" fn(*const u16) -> *mut c_void;
type Close = unsafe extern "system" fn(*mut c_void);
type Luid = unsafe extern "system" fn(*mut c_void, *mut NET_LUID_LH);
type Start = unsafe extern "system" fn(*mut c_void, u32) -> *mut c_void;
type End = unsafe extern "system" fn(*mut c_void);
type Event = unsafe extern "system" fn(*mut c_void) -> HANDLE;
type Receive = unsafe extern "system" fn(*mut c_void, *mut u32) -> *mut u8;
type Release = unsafe extern "system" fn(*mut c_void, *const u8);
type Allocate = unsafe extern "system" fn(*mut c_void, u32) -> *mut u8;
type Send = unsafe extern "system" fn(*mut c_void, *const u8);
pub(super) struct Api {
    pub(super) library: Library,
    pub(super) create: Create,
    pub(super) open: Open,
    pub(super) close: Close,
    pub(super) luid: Luid,
    pub(super) start: Start,
    pub(super) end: End,
    pub(super) event: Event,
    pub(super) receive: Receive,
    pub(super) release: Release,
    pub(super) allocate: Allocate,
    pub(super) send: Send,
}
impl Api {
    #[expect(
        unsafe_code,
        reason = "Each named export is converted to its exact official WINAPI function-pointer signature; caller certifies provider code/ABI and retains the library"
    )]
    pub(super) unsafe fn resolve(mut library: Library) -> io::Result<Self> {
        macro_rules! export {
            ($name:expr, $signature:ty) => {{
                let address = match library.symbol($name) {
                    Ok(address) => address,
                    Err(original) => {
                        return Err(refused(&mut library, original));
                    }
                };
                // SAFETY: caller certifies the named official export and its
                // exact concrete WINAPI signature; library outlives every call.
                unsafe { std::mem::transmute::<*mut c_void, $signature>(address) }
            }};
        }
        let mut api = Self {
            create: export!(c"WintunCreateAdapter", Create),
            open: export!(c"WintunOpenAdapter", Open),
            close: export!(c"WintunCloseAdapter", Close),
            luid: export!(c"WintunGetAdapterLUID", Luid),
            start: export!(c"WintunStartSession", Start),
            end: export!(c"WintunEndSession", End),
            event: export!(c"WintunGetReadWaitEvent", Event),
            receive: export!(c"WintunReceivePacket", Receive),
            release: export!(c"WintunReleaseReceivePacket", Release),
            allocate: export!(c"WintunAllocateSendPacket", Allocate),
            send: export!(c"WintunSendPacket", Send),
            library,
        };
        // Create/open/close can queue provider-owned cleanup callbacks. The
        // public ABI cannot join them, so pin before the first such export call.
        if let Err(original) = api.library.pin_for_process() {
            return Err(refused(&mut api.library, original));
        }
        Ok(api)
    }
}

fn refused(library: &mut Library, original: io::Error) -> io::Error {
    match library.close() {
        Ok(_) => original,
        Err(release) => io::Error::new(original.kind(), LoadFailure { original, release }),
    }
}

/// Independent provider-setup and DLL-release errors. The release was attempted
/// once; its failure is not proof of a still-usable DLL reference.
#[derive(Debug)]
pub struct LoadFailure {
    /// Actual original export-resolution or process-pin failure.
    pub original: io::Error,
    /// Actual independent original loader-reference release failure.
    pub release: io::Error,
}
impl std::fmt::Display for LoadFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Wintun provider setup: {}; independent DLL release: {}",
            self.original, self.release
        )
    }
}
impl std::error::Error for LoadFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}
