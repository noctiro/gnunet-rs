//! Windows SDK COM vtable prefixes; system ABI, no C++ implementation ABI.
use std::ffi::c_void;
use windows_sys::{
    Win32::{Foundation::HANDLE, Media::Audio::WAVEFORMATEX},
    core::GUID,
};
pub(super) const ENUMERATOR: GUID = GUID::from_u128(0xa95664d2_9614_4f35_a746_de8db63617e6);
pub(super) const AUDIO_CLIENT: GUID = GUID::from_u128(0x1cb9ad4c_dbfa_4c32_b178_c2f568a703b2);
pub(super) const CAPTURE: GUID = GUID::from_u128(0xc8adbd64_e71e_48a0_a4de_185c395cd317);
pub(super) const RENDER: GUID = GUID::from_u128(0xf294acfc_3146_4483_a7bf_addca7c260e2);
#[repr(C)]
pub(super) struct Unknown {
    pub query: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> i32,
    pub add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
    pub release: unsafe extern "system" fn(*mut c_void) -> u32,
}
#[repr(C)]
pub(super) struct Enumerator {
    pub unknown: Unknown,
    pub enumerate: *const c_void,
    pub default: unsafe extern "system" fn(*mut c_void, i32, i32, *mut *mut c_void) -> i32,
}
#[repr(C)]
pub(super) struct Endpoint {
    pub unknown: Unknown,
    pub activate: unsafe extern "system" fn(
        *mut c_void,
        *const GUID,
        u32,
        *const c_void,
        *mut *mut c_void,
    ) -> i32,
}
#[repr(C)]
pub(super) struct Client {
    pub unknown: Unknown,
    pub initialize: unsafe extern "system" fn(
        *mut c_void,
        i32,
        u32,
        i64,
        i64,
        *const WAVEFORMATEX,
        *const GUID,
    ) -> i32,
    pub size: unsafe extern "system" fn(*mut c_void, *mut u32) -> i32,
    pub latency: *const c_void,
    pub padding: unsafe extern "system" fn(*mut c_void, *mut u32) -> i32,
    pub supported: *const c_void,
    pub mix: *const c_void,
    pub period: *const c_void,
    pub start: unsafe extern "system" fn(*mut c_void) -> i32,
    pub stop: unsafe extern "system" fn(*mut c_void) -> i32,
    pub reset: unsafe extern "system" fn(*mut c_void) -> i32,
    pub event: unsafe extern "system" fn(*mut c_void, HANDLE) -> i32,
    pub service: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> i32,
}
#[repr(C)]
pub(super) struct Capture {
    pub unknown: Unknown,
    pub get: unsafe extern "system" fn(
        *mut c_void,
        *mut *mut u8,
        *mut u32,
        *mut u32,
        *mut u64,
        *mut u64,
    ) -> i32,
    pub release: unsafe extern "system" fn(*mut c_void, u32) -> i32,
    pub next: unsafe extern "system" fn(*mut c_void, *mut u32) -> i32,
}
#[repr(C)]
pub(super) struct Render {
    pub unknown: Unknown,
    pub get: unsafe extern "system" fn(*mut c_void, u32, *mut *mut u8) -> i32,
    pub release: unsafe extern "system" fn(*mut c_void, u32, u32) -> i32,
}
const _: () = {
    use std::mem::size_of;
    assert!(size_of::<Unknown>() == 3 * size_of::<usize>());
    assert!(size_of::<Enumerator>() == 5 * size_of::<usize>());
    assert!(size_of::<Endpoint>() == 4 * size_of::<usize>());
    assert!(size_of::<Client>() == 15 * size_of::<usize>());
    assert!(size_of::<Capture>() == 6 * size_of::<usize>());
    assert!(size_of::<Render>() == 5 * size_of::<usize>());
    assert!(size_of::<WAVEFORMATEX>() == 18);
};
