//! Read-only Windows file sections for trusted synchronous native consumers.
use super::{EntryInfo, file_info, validate_readonly};
use std::{
    ffi::c_void,
    fmt,
    fs::File,
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr::{self, NonNull},
};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_READ, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile, PAGE_READONLY,
    UnmapViewOfFile,
};
enum State {
    Empty,
    Mapped {
        _section: OwnedHandle,
        view: NonNull<c_void>,
        bytes: usize,
    },
    Closed,
}
/// One read-only native view pinned by its original file section. No whole-file
/// heap copy or Rust slice is created. Concurrent contents can still change;
/// source fencing and native in-page exception handling belong to the consumer.
pub struct ReadMapping {
    state: State,
}
impl fmt::Debug for ReadMapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadMapping")
            .field("bytes", &self.len())
            .field("open", &!matches!(self.state, State::Closed))
            .finish()
    }
}
impl ReadMapping {
    /// Map this read-only ordinary original file's exact expected extent. Native
    /// mapping pins the section, preventing ordinary truncation while it lives.
    /// A changed size, non-file or allocation/mapping failure remains an error.
    #[expect(
        unsafe_code,
        reason = "Synchronous native creation transfers one owned section and one bounded read-only view; all failure paths release their acquired resources"
    )]
    pub fn open(file: &File, bytes: u64) -> io::Result<Self> {
        validate_readonly(file)?;
        if !matches!(file_info(file)?, EntryInfo::File(info) if info.bytes == bytes) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "original mapping source extent changed",
            ));
        }
        if bytes == 0 {
            return Ok(Self {
                state: State::Empty,
            });
        }
        let length = usize::try_from(bytes).map_err(|_| io::ErrorKind::InvalidInput)?;
        if length > isize::MAX as usize {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let size = bytes.to_le_bytes();
        let low = u32::from_le_bytes([size[0], size[1], size[2], size[3]]);
        let high = u32::from_le_bytes([size[4], size[5], size[6], size[7]]);
        // SAFETY: original read-only file is live, mapping is unnamed and has no
        // inherited handle/security pointer. Its maximum is the admitted extent.
        let section = unsafe {
            CreateFileMappingW(
                file.as_raw_handle(),
                ptr::null(),
                PAGE_READONLY,
                high,
                low,
                ptr::null(),
            )
        };
        if section.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: one successful unique mapping handle, released on failure/Drop.
        let section = unsafe { OwnedHandle::from_raw_handle(section) };
        // SAFETY: original section is live, offset zero, exact admitted extent.
        let view = unsafe { MapViewOfFile(section.as_raw_handle(), FILE_MAP_READ, 0, 0, length) };
        let view = NonNull::new(view.Value).ok_or_else(io::Error::last_os_error)?;
        Ok(Self {
            state: State::Mapped {
                _section: section,
                view,
                bytes: length,
            },
        })
    }
    /// Borrow a raw read-only address for a trusted synchronous native ABI.
    /// Dereferencing requires native memory/exception and lifetime guarantees;
    /// no pointer may be retained after explicit close or Drop. Empty views use
    /// a non-null sentinel that must never be dereferenced.
    pub fn as_ptr(&self) -> io::Result<*const c_void> {
        match &self.state {
            State::Empty => Ok(NonNull::<u8>::dangling().as_ptr().cast()),
            State::Mapped { view, .. } => Ok(view.as_ptr().cast_const()),
            State::Closed => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "native mapping is closed",
            )),
        }
    }
    /// Admitted view length; closed and empty views have length zero.
    #[must_use]
    pub fn len(&self) -> usize {
        match &self.state {
            State::Mapped { bytes, .. } => *bytes,
            _ => 0,
        }
    }
    /// Whether this owner has no readable mapped bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Unmap before releasing the original section. A failed unmap keeps the
    /// owner for retry; Drop performs one best-effort attempt. Returns false only
    /// when the owner was already closed.
    #[expect(
        unsafe_code,
        reason = "Unmap consumes only this owner's original live view after native use ends; failed views remain owned"
    )]
    pub fn close(&mut self) -> io::Result<bool> {
        if let State::Mapped { view, .. } = &self.state {
            // SAFETY: original view still owned; the caller ended all native use.
            if unsafe {
                UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                    Value: view.as_ptr(),
                })
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        let previous = std::mem::replace(&mut self.state, State::Closed);
        Ok(!matches!(previous, State::Closed))
    }
}
impl Drop for ReadMapping {
    fn drop(&mut self) {
        let _cleanup = self.close();
    }
}
