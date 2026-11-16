//! Caller-trusted native library ownership with explicit, thread-local lifetime.
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
use std::{
    ffi::{CStr, c_void},
    fmt, io,
    marker::PhantomData,
    path::Path,
    ptr::NonNull,
    rc::Rc,
};
#[cfg(unix)]
use unix as platform;
#[cfg(unix)]
pub use unix::Diagnostic;
#[cfg(windows)]
use windows as platform;

/// One successful loader reference on its owning thread. Symbols do not own the
/// library and must not be used after explicit close or final Drop.
pub struct Library {
    handle: Option<NonNull<c_void>>,
    _thread: PhantomData<Rc<()>>,
}
impl fmt::Debug for Library {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Library")
            .field("open", &self.is_open())
            .finish()
    }
}
impl Library {
    /// Load an explicit absolute native path. Unix uses NOW/LOCAL; Windows
    /// searches dependencies in the DLL directory and System32. No global
    /// loader search settings are changed. Errors retain native diagnostics.
    ///
    /// # Safety
    /// The caller must trust library initialization, exports, destruction,
    /// dependencies and the process loader environment. Calls require each
    /// export's exact ABI. Symbols and borrowed library storage cannot outlive
    /// this reference, be used after close or independently unload it. Obey all
    /// library-specific thread/global-state exclusion requirements.
    #[expect(
        unsafe_code,
        reason = "Loading executes caller-trusted native initialization; the selected platform returns one unique reference"
    )]
    pub unsafe fn load(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "library path must be absolute",
            ));
        }
        // SAFETY: caller certifies native code and its lifetime/exclusion policy.
        let handle = unsafe { platform::load(path)? };
        Ok(Self {
            handle: Some(handle),
            _thread: PhantomData,
        })
    }
    /// Load one Unix basename through the process's trusted loader search paths.
    /// Unlike absolute-path loading, this deliberately admits the native search
    /// environment. Names containing path separators or dot components fail.
    ///
    /// # Safety
    /// The caller trusts every selectable provider, dependency and loader search
    /// directory, and supplies the same ABI/lifetime exclusions as `load`.
    #[cfg(unix)]
    #[expect(
        unsafe_code,
        reason = "Caller explicitly authorizes native loader search and provider code"
    )]
    pub unsafe fn load_basename(name: &CStr) -> io::Result<Self> {
        let bytes = name.to_bytes();
        if bytes.is_empty() || bytes.contains(&b'/') || matches!(bytes, b"." | b"..") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "one native library basename required",
            ));
        }
        // SAFETY: caller supplies native code and search-environment trust.
        let handle = unsafe { platform::load_name(name)? };
        Ok(Self {
            handle: Some(handle),
            _thread: PhantomData,
        })
    }
    /// Look up an export on this still-open reference. Calling the raw address
    /// requires the export's actual ABI and all native lifetime preconditions.
    pub fn symbol(&self, name: &CStr) -> io::Result<*mut c_void> {
        let handle = self.handle.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "native library is closed")
        })?;
        platform::symbol(handle, name)
    }
    /// Irreversibly retain this exact Windows module until process termination.
    /// The caller still owns and releases this loader reference normally. Pinning
    /// keeps foreign background code and native module storage valid after the
    /// last Rust owner closes; it grants no background-work completion receipt.
    /// Perform this before dispatching foreign work without a quiescence API.
    #[cfg(windows)]
    pub fn pin_for_process(&self) -> io::Result<()> {
        let handle = self.handle.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "native library is closed")
        })?;
        platform::pin_for_process(handle)
    }
    /// Whether this owner still permits symbol queries and calls.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.handle.is_some()
    }
    /// Attempt native release once, after all export calls have ended. An error
    /// retains the real native failure; this owner remains closed and does not
    /// retry an uncertain release. Success is not proof of physical unloading.
    /// Returns false only when this owner was already closed.
    pub fn close(&mut self) -> io::Result<bool> {
        let Some(handle) = self.handle.take() else {
            return Ok(false);
        };
        platform::close(handle)?;
        Ok(true)
    }
}
impl Drop for Library {
    fn drop(&mut self) {
        let _cleanup = self.close();
    }
}
