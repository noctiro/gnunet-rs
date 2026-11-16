//! Owned Win32/UCRT standard routes under explicit process exclusivity.
#[path = "console.rs"]
mod console;
use crate::windows_crt::{Errno, crt_error};
pub use console::ConsoleDetachFailure;
pub use console::DetachedStderr;
pub use console::detach_console;
use std::{
    ffi::c_int,
    fmt,
    fs::File,
    io,
    marker::PhantomData,
    os::windows::io::{
        AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, IntoRawHandle, OwnedHandle,
    },
    rc::Rc,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use windows_sys::Win32::{
    Foundation::{
        DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation,
    },
    System::{
        Console::{
            GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle,
        },
        Threading::GetCurrentProcess,
    },
};

static CLAIMED: AtomicBool = AtomicBool::new(false);
// Each standard-table entry borrows an independent retained owner. Owners stay
// after a logical capability drops; the next successful slot install replaces
// its old owner. CRT slots own different duplicates, never these handles.
static INSTALLED: Mutex<[Option<OwnedHandle>; 3]> = Mutex::new([None, None, None]);
const STANDARD_HANDLES: [u32; 3] = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE];

/// One child standard slot, independently of the parent's slot ownership.
#[derive(Clone, Copy, Debug)]
pub enum Stdio<'a> {
    /// Snapshot the corresponding native standard handle. A missing slot remains closed.
    Inherit,
    /// Explicitly leave this native child slot closed.
    Closed,
    /// Explicitly connect this slot to the native NUL device.
    Null,
    /// Duplicate this original kernel handle for the child; do not transfer it.
    Handle(BorrowedHandle<'a>),
}
enum PreparedRoute {
    Null,
    Closed,
    Handle(OwnedHandle),
}
/// Stable detached-child stderr selection. File/pipe handles are independently
/// duplicated; character devices become NUL and absent stderr remains closed.
/// No source owner, process-global table or console relationship is changed.
pub struct PreparedStderr(PreparedRoute);
impl PreparedStderr {
    /// Snapshot only this destination, retaining the original native failure.
    /// Inherit reads the current route once; callers exclude route replacement
    /// throughout preparation/launch when requiring a consistent process view.
    #[expect(
        unsafe_code,
        reason = "GetStdHandle returns a borrowed scalar process route; native classification and duplication validate it without constructing a foreign owner"
    )]
    pub fn new(source: Stdio<'_>) -> io::Result<Self> {
        let handle = match source {
            Stdio::Null => return Ok(Self(PreparedRoute::Null)),
            Stdio::Closed => return Ok(Self(PreparedRoute::Closed)),
            Stdio::Handle(handle) => handle.as_raw_handle(),
            // SAFETY: fixed valid selector; returned value is not adopted.
            Stdio::Inherit => unsafe { GetStdHandle(STD_ERROR_HANDLE) },
        };
        if handle.is_null() || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return Ok(Self(PreparedRoute::Closed));
        }
        match console::classify(handle)? {
            DetachedStderr::Null => Ok(Self(PreparedRoute::Null)),
            DetachedStderr::Preserved => {
                duplicate_raw(handle, false).map(|handle| Self(PreparedRoute::Handle(handle)))
            }
        }
    }
    /// Borrow this retained selection for native child creation. The original
    /// caller/file/table owner need not remain live after successful preparation.
    pub fn stdio(&self) -> Stdio<'_> {
        match &self.0 {
            PreparedRoute::Null => Stdio::Null,
            PreparedRoute::Closed => Stdio::Closed,
            PreparedRoute::Handle(handle) => Stdio::Handle(handle.as_handle()),
        }
    }
}
/// Failure point in a non-atomic Win32/UCRT installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallationPhase {
    /// Preparation failed. Standard handles were restored unless recovery failed.
    Prepare,
    /// Private descriptors were prepared, but restoring temporary standard slots failed.
    Restore,
    /// Selected UCRT slot replacement failed. Its Win32 route was installed unless recovery failed.
    Crt,
    /// Selected UCRT slot was installed, but publishing its independent Win32 handle failed.
    Win32,
}

/// Original installation error and any separate restoration/publication error.
/// Neither a failed CRT replacement nor a failed standard-table restore promises
/// unchanged process state. Inspect the phase before retrying under exclusivity.
#[derive(Debug)]
pub struct InstallationError {
    phase: InstallationPhase,
    error: io::Error,
    recovery: Option<io::Error>,
}
impl InstallationError {
    fn new(phase: InstallationPhase, error: io::Error) -> Self {
        Self {
            phase,
            error,
            recovery: None,
        }
    }
    /// Operation phase and its documented partial-installation state.
    #[must_use]
    pub fn phase(&self) -> InstallationPhase {
        self.phase
    }
    /// Original native error, including the Win32 or CRT error domain.
    #[must_use]
    pub fn error(&self) -> &io::Error {
        &self.error
    }
    /// Separate standard-table restoration or Win32 publication failure.
    #[must_use]
    pub fn recovery_error(&self) -> Option<&io::Error> {
        self.recovery.as_ref()
    }
}
impl fmt::Display for InstallationError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "standard stream {:?}: {}", self.phase, self.error)?;
        if let Some(error) = &self.recovery {
            write!(output, "; recovery: {error}")?;
        }
        Ok(())
    }
}
impl std::error::Error for InstallationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Unique, non-Send/non-Sync authority to install process stderr at startup.
/// Dropping it releases the claim, not the installed destinations.
pub struct ProcessStderr {
    _thread: PhantomData<Rc<()>>,
}
impl ProcessStderr {
    /// Claim exclusive process standard-error installation authority.
    ///
    /// # Safety
    /// All Rust/foreign standard-stream users, standard-handle mutation and child
    /// spawning must be quiescent during each installation. Buffered streams must
    /// be flushed first. No cached standard handle may span an installation.
    /// Temporary UCRT descriptors can occupy previously closed slots 0, 1 or 2;
    /// their Win32 table values are restored before publishing the destination.
    /// While claimed, unrelated code must not close, replace or take ownership of
    /// stderr. Installed Win32 handles remain process-owned borrowed handles after
    /// this capability is dropped: GetStdHandle does not transfer their ownership.
    /// The atomic claim coordinates this module's installation APIs only, not the rest of the process.
    #[expect(
        unsafe_code,
        reason = "Only the caller can establish process-wide standard-stream quiescence and ownership exclusion"
    )]
    pub unsafe fn claim() -> io::Result<Self> {
        CLAIMED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| io::Error::other("process stderr capability already claimed"))?;
        Ok(Self {
            _thread: PhantomData,
        })
    }

    /// Install independent duplicates of a borrowed file for Win32 stderr and
    /// UCRT fd2. Original-file and capability drops do not close either stream.
    /// Win32 stderr is inheritable; private preparation handles are not. CRT byte
    /// output uses binary mode, with no newline or character-encoding translation.
    /// A failure reports partial state; no fallible rollback is called success.
    pub fn install(&mut self, file: &File) -> Result<(), InstallationError> {
        install(Slot::Error, file)
    }
}
impl Drop for ProcessStderr {
    fn drop(&mut self) {
        CLAIMED.store(false, Ordering::Release);
    }
}

#[derive(Clone, Copy)]
enum Slot {
    Input,
    Output,
    Error,
}
impl Slot {
    fn index(self) -> usize {
        match self {
            Self::Input => 0,
            Self::Output => 1,
            Self::Error => 2,
        }
    }
}
// Caller holds the exclusive stream-mutation claim. Native and CRT owners stay
// independent for every logical slot, including after the claim is released.
fn install(slot: Slot, file: &File) -> Result<(), InstallationError> {
    let win32 = duplicate(file, true)
        .map_err(|error| InstallationError::new(InstallationPhase::Prepare, error))?;
    let source = prepare_crt(file)?;
    let mut installed = INSTALLED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _errno = Errno::clear();
    #[expect(
        unsafe_code,
        reason = "The unique capability excludes stream users; the privately owned live source is >=3, so closing it cannot close the installed standard slot"
    )]
    // SAFETY: the source is live and the selected target is a reserved, possibly closed CRT slot.
    let crt = unsafe { libc::dup2(source.0, slot.index() as c_int) };
    let crt_error = (crt < 0).then(|| crt_error("_dup2"));
    // UCRT may itself change the Win32 table when replacing a standard fd.
    // Publish the independent owner last, including after a CRT failure.
    #[expect(
        unsafe_code,
        reason = "The fresh live owned handle stays retained in INSTALLED after successful publication; no concurrent standard-table users exist"
    )]
    // SAFETY: SetStdHandle borrows the handle and takes no ownership.
    let published = unsafe { SetStdHandle(STANDARD_HANDLES[slot.index()], win32.as_raw_handle()) };
    let native_error = (published == 0).then(io::Error::last_os_error);
    if published != 0 {
        // No callback or fallible operation occurs between publication and
        // ownership transfer. The old independent owner is now unreferenced.
        installed[slot.index()] = Some(win32);
    }
    match (crt_error, native_error) {
        (None, None) => Ok(()),
        (Some(error), recovery) => Err(InstallationError {
            phase: InstallationPhase::Crt,
            error,
            recovery,
        }),
        (None, Some(error)) => Err(InstallationError::new(InstallationPhase::Win32, error)),
    }
}

fn duplicate(file: &File, inherit: bool) -> io::Result<OwnedHandle> {
    duplicate_raw(file.as_raw_handle(), inherit)
}
fn duplicate_raw(source: HANDLE, inherit: bool) -> io::Result<OwnedHandle> {
    let mut handle = std::ptr::null_mut();
    #[expect(
        unsafe_code,
        reason = "DuplicateHandle validates the borrowed scalar source handle and writes one fresh independently owned handle in this process; no foreign handle is adopted"
    )]
    // SAFETY: both process arguments designate this process; output is writable.
    let result = unsafe {
        let process = GetCurrentProcess();
        DuplicateHandle(
            process,
            source,
            process,
            &mut handle,
            0,
            i32::from(inherit),
            DUPLICATE_SAME_ACCESS,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    #[expect(
        unsafe_code,
        reason = "Successful DuplicateHandle transferred exactly one fresh valid handle to this scope"
    )]
    // SAFETY: this is the first and only owner of the returned duplicate.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

struct CrtFd(c_int);
impl Drop for CrtFd {
    #[expect(
        unsafe_code,
        reason = "This owner holds exactly one successfully allocated, still-live UCRT descriptor; _close also closes its uniquely owned OS handle"
    )]
    fn drop(&mut self) {
        let _errno = Errno::clear();
        // SAFETY: descriptors are never externally exposed or explicitly closed.
        unsafe {
            libc::close(self.0);
        }
    }
}

// _open_osfhandle/_dup can allocate closed standard CRT slots. Their transient
// SetStdHandle effects must not change independently valid stdin/stdout handles.
struct StandardTable {
    saved: [HANDLE; 3],
    active: bool,
}
impl StandardTable {
    #[expect(
        unsafe_code,
        reason = "GetStdHandle only copies process-owned borrowed values while the caller excludes mutation; null/INVALID values are preserved too"
    )]
    fn capture() -> Self {
        Self {
            // SAFETY: these are the three valid standard-device selectors.
            saved: STANDARD_HANDLES.map(|which| unsafe { GetStdHandle(which) }),
            active: true,
        }
    }
    fn restore(mut self) -> io::Result<()> {
        self.active = false;
        restore_table(&self.saved)
    }
}
impl Drop for StandardTable {
    fn drop(&mut self) {
        if self.active {
            drop(restore_table(&self.saved));
        }
    }
}
/// Failed Win32 table restorations, retained individually in an `io::Error`.
#[derive(Debug)]
pub struct RestorationError([Option<io::Error>; 3]);
impl RestorationError {
    /// Every failed native restoration, indexed by logical standard slot 0, 1
    /// or 2. Each error retains its original Win32 code; successful slots are absent.
    pub fn errors(&self) -> impl Iterator<Item = (usize, &io::Error)> {
        self.0
            .iter()
            .enumerate()
            .filter_map(|(slot, error)| error.as_ref().map(|error| (slot, error)))
    }
}
impl fmt::Display for RestorationError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (slot, error) in self.0.iter().enumerate() {
            if let Some(error) = error {
                write!(output, "restore standard slot {slot}: {error}; ")?;
            }
        }
        Ok(())
    }
}
impl std::error::Error for RestorationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.errors()
            .next()
            .map(|(_, error)| error as &(dyn std::error::Error + 'static))
    }
}
fn restore_table(saved: &[HANDLE; 3]) -> io::Result<()> {
    let errors = std::array::from_fn(|slot| {
        #[expect(
            unsafe_code,
            reason = "The saved table values are borrowed, unclosed originals; SetStdHandle stores them verbatim under exclusive process access"
        )]
        // SAFETY: each selector is valid, and no original handle was closed by preparation.
        (unsafe { SetStdHandle(STANDARD_HANDLES[slot], saved[slot]) } == 0)
            .then(io::Error::last_os_error)
    });
    if errors.iter().any(Option::is_some) {
        Err(io::Error::other(RestorationError(errors)))
    } else {
        Ok(())
    }
}

fn prepare_crt(file: &File) -> Result<CrtFd, InstallationError> {
    let handle = duplicate(file, false)
        .map_err(|error| InstallationError::new(InstallationPhase::Prepare, error))?;
    let table = StandardTable::capture();
    // Temporary standard descriptors close inside private_crt, before restore.
    let prepared = private_crt(handle);
    let restored = table.restore();
    match (prepared, restored) {
        (Ok(source), Ok(())) => Ok(source),
        (Err(error), restored) => Err(InstallationError {
            phase: InstallationPhase::Prepare,
            error,
            recovery: restored.err(),
        }),
        (Ok(_), Err(error)) => Err(InstallationError::new(InstallationPhase::Restore, error)),
    }
}
fn private_crt(handle: OwnedHandle) -> io::Result<CrtFd> {
    let _errno = Errno::clear();
    #[expect(
        unsafe_code,
        reason = "A fresh valid handle is lent to _open_osfhandle; ownership transfers only on success, with binary output and no inheritance"
    )]
    // SAFETY: the handle has one owner and is not a standard-table borrowed handle.
    let fd = unsafe {
        libc::open_osfhandle(
            handle.as_raw_handle() as isize,
            libc::O_BINARY | libc::O_NOINHERIT,
        )
    };
    if fd < 0 {
        return Err(crt_error("_open_osfhandle"));
    }
    let _transferred = handle.into_raw_handle();
    let mut source = CrtFd(fd);
    let mut reserved: [Option<CrtFd>; 3] = [None, None, None];
    for slot in &mut reserved {
        if source.0 >= 3 {
            break;
        }
        #[expect(
            unsafe_code,
            reason = "The source is a live uniquely owned CRT descriptor; _dup allocates the next free descriptor and returns independent ownership"
        )]
        // SAFETY: no invalid descriptor or concurrent CRT slot mutation is possible.
        let next = unsafe { libc::dup(source.0) };
        if next < 0 {
            return Err(crt_error("_dup"));
        }
        *slot = Some(std::mem::replace(&mut source, CrtFd(next)));
    }
    debug_assert!(source.0 >= 3);
    #[expect(
        unsafe_code,
        reason = "The descriptor is known live and privately owned; _dup may make its new handle inheritable, so clear that flag before returning preparation ownership"
    )]
    // SAFETY: _get_osfhandle only borrows this live descriptor's handle; no owner
    // is created and SetHandleInformation cannot close or replace the handle.
    let status = unsafe {
        SetHandleInformation(
            libc::get_osfhandle(source.0) as HANDLE,
            HANDLE_FLAG_INHERIT,
            0,
        )
    };
    if status == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(source)
}
