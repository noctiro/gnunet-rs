//! Anonymous section handles and uniquely owned bounded views.
use std::{
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
};
use windows_sys::Win32::{
    Foundation::{DuplicateHandle, HANDLE, INVALID_HANDLE_VALUE},
    System::{
        Memory::{
            CreateFileMappingW, FILE_MAP, FILE_MAP_READ, FILE_MAP_WRITE,
            MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile, PAGE_READWRITE, UnmapViewOfFile,
        },
        Threading::GetCurrentProcess,
    },
};

pub(super) struct View {
    address: Option<MEMORY_MAPPED_VIEW_ADDRESS>,
}
#[expect(
    unsafe_code,
    reason = "Win32 views are not thread-affine; moving the unique owner cannot overlap unmap or mutable access"
)]
// SAFETY: ownership and unmap may move between threads; no native thread affinity.
unsafe impl Send for View {}
#[expect(
    unsafe_code,
    reason = "Shared access lends only const pointers; mutation/unmap require exclusive ownership and no public pointer escapes"
)]
// SAFETY: shared borrows cannot mutate the view or unmap it. Private native
// writers require exclusive access, and incoming publication is immutable.
unsafe impl Sync for View {}
impl View {
    #[expect(
        unsafe_code,
        reason = "MapViewOfFile validates a borrowed live section handle and returns a view of at least the exact bounded requested extent"
    )]
    pub(super) fn new(handle: HANDLE, access: FILE_MAP, bytes: usize) -> io::Result<Self> {
        // SAFETY: zero offset and bounded nonzero length; no output pointer is adopted on failure.
        let address = unsafe { MapViewOfFile(handle, access, 0, 0, bytes) };
        if address.Value.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            address: Some(address),
        })
    }
    pub(super) fn pointer(&self) -> *const u8 {
        self.address.map_or(std::ptr::null(), |address| {
            address.Value.cast_const().cast()
        })
    }
    pub(super) fn pointer_mut(&mut self) -> *mut u8 {
        self.pointer().cast_mut()
    }
    #[expect(
        unsafe_code,
        reason = "UnmapViewOfFile retires only this uniquely owned original view; failed retirement keeps the owner for retry"
    )]
    pub(super) fn close(&mut self) -> io::Result<()> {
        let Some(address) = self.address else {
            return Ok(());
        };
        // SAFETY: exact live original mapping, not an interior/reconstructed address.
        if unsafe { UnmapViewOfFile(address) } == 0 {
            return Err(io::Error::last_os_error());
        }
        self.address = None;
        Ok(())
    }
}
impl Drop for View {
    fn drop(&mut self) {
        let _cleanup = self.close();
    }
}
pub(super) struct Writable {
    // View retirement precedes handle closure on every path.
    pub(super) view: View,
    _write: OwnedHandle,
    pub(super) read: OwnedHandle,
}
impl Writable {
    #[expect(
        unsafe_code,
        reason = "An anonymous pagefile-backed section and a read-only duplicate receive unique owners; native constructors copy no caller pointer beyond their synchronous calls"
    )]
    pub(super) fn new(bytes: usize) -> io::Result<Self> {
        let bytes = u32::try_from(bytes).map_err(|_| io::ErrorKind::InvalidInput)?;
        // SAFETY: anonymous pagefile section, no external pointer or name, exact nonzero size.
        let handle = unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                std::ptr::null(),
                PAGE_READWRITE,
                0,
                bytes,
                std::ptr::null(),
            )
        };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful constructor supplies this sole real section owner.
        let write = unsafe { OwnedHandle::from_raw_handle(handle) };
        let mut read = std::ptr::null_mut();
        // SAFETY: live original section; only FILE_MAP_READ rights are duplicated.
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                handle,
                GetCurrentProcess(),
                &mut read,
                FILE_MAP_READ,
                0,
                0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful duplication produced an independent read-only handle.
        let read = unsafe { OwnedHandle::from_raw_handle(read) };
        let view = View::new(write.as_raw_handle(), FILE_MAP_WRITE, bytes as usize)?;
        Ok(Self {
            view,
            _write: write,
            read,
        })
    }
}
