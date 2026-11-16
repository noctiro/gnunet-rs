//! Managed process detachment without replacing its original process identity.
use super::{InstallationError, ProcessStderr, Slot, install};
use std::{error::Error, fmt, fs::OpenOptions, io};
use windows_sys::Win32::{
    Foundation::{GetLastError, INVALID_HANDLE_VALUE, SetLastError},
    Storage::FileSystem::{
        FILE_TYPE_CHAR, FILE_TYPE_DISK, FILE_TYPE_PIPE, FILE_TYPE_REMOTE, GetFileType,
    },
    System::Console::{
        FreeConsole, GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    },
};

/// Actual stderr selection after native console detachment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetachedStderr {
    /// Preserve the existing file, pipe or absent stderr route.
    Preserved,
    /// Character-device stderr was replaced with independent NUL routes.
    Null,
}
/// Original failure and the already completed process-global mutation stages.
/// No rollback or unchanged state is claimed after a partial installation.
#[derive(Debug)]
pub enum ConsoleDetachFailure {
    /// Claim, stderr classification or NUL preparation failed before mutation.
    Prepare(io::Error),
    /// stdin installation failed; its precise partial state is retained.
    Input(InstallationError),
    /// stdin is installed; stdout failed with its precise partial state retained.
    Output(InstallationError),
    /// stdin/stdout are installed; character stderr installation failed.
    Stderr(InstallationError),
    /// Selected standard routes are installed, but FreeConsole failed.
    Console(io::Error),
}
impl fmt::Display for ConsoleDetachFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prepare(error) => write!(f, "detach preparation: {error}"),
            Self::Input(error) => write!(f, "detach stdin: {error}"),
            Self::Output(error) => write!(f, "detach stdout: {error}"),
            Self::Stderr(error) => write!(f, "detach stderr: {error}"),
            Self::Console(error) => write!(f, "FreeConsole: {error}"),
        }
    }
}
impl Error for ConsoleDetachFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Prepare(error) | Self::Console(error) => Some(error),
            Self::Input(error) | Self::Output(error) | Self::Stderr(error) => Some(error),
        }
    }
}
#[expect(
    unsafe_code,
    reason = "The caller excludes stream mutation; GetStdHandle borrows a process route and GetFileType observes its native kind without adopting or closing it"
)]
fn stderr_route() -> io::Result<DetachedStderr> {
    // SAFETY: fixed valid selector; route mutation is excluded by the caller.
    let routes = unsafe {
        [
            GetStdHandle(STD_INPUT_HANDLE),
            GetStdHandle(STD_OUTPUT_HANDLE),
            GetStdHandle(STD_ERROR_HANDLE),
        ]
    };
    for (index, handle) in routes.iter().enumerate() {
        if !handle.is_null()
            && *handle != INVALID_HANDLE_VALUE
            && routes[index + 1..].contains(handle)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "aliased native standard routes cannot be detached in place",
            ));
        }
    }
    let handle = routes[2];
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Ok(DetachedStderr::Preserved);
    }
    classify(handle)
}
#[expect(
    unsafe_code,
    reason = "GetFileType validates a borrowed scalar native handle and retains no pointer; LastError is captured immediately in its own error domain"
)]
pub(super) fn classify(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> io::Result<DetachedStderr> {
    // SAFETY: this is a borrowed process-owned route. Clearing and immediately
    // capturing LastError distinguishes a valid unknown kind from native failure.
    let (kind, error) = unsafe {
        SetLastError(0);
        let kind = GetFileType(handle);
        (kind, GetLastError())
    };
    match kind & !FILE_TYPE_REMOTE {
        FILE_TYPE_DISK | FILE_TYPE_PIPE => Ok(DetachedStderr::Preserved),
        FILE_TYPE_CHAR => Ok(DetachedStderr::Null),
        _ if error != 0 => Err(io::Error::from_raw_os_error(error as i32)),
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unknown stderr kind during console detachment",
        )),
    }
}
/// Detach this managed process in place, preserving its original HANDLE/PID.
/// stdin/stdout become NUL in both Win32 and UCRT. File/pipe/absent stderr stays;
/// character-device stderr becomes NUL so console invalidation cannot leave it
/// dangling. Both UCRT/Win32 destinations selected for replacement are replaced,
/// even if they previously differed. Installed owners persist after return.
///
/// # Safety
/// Call during fresh startup with every standard-stream user, mutation, native
/// child launch and console attachment operation quiescent. Flush output first.
/// No externally cached standard handle may span an installation. Aliases among
/// native standard slots are rejected before mutation. Nonabsent native
/// routes must be valid borrowed process-owned handles. Exclude unrelated CRT
/// descriptor mutation. Register console handlers after this call; FreeConsole
/// resets them. Partial failure requires explicit recovery or startup exit.
#[expect(
    unsafe_code,
    reason = "The fresh-process caller establishes global stream/console exclusion; the shared claim covers private slot installation and FreeConsole is one synchronous native effect"
)]
pub unsafe fn detach_console() -> Result<DetachedStderr, ConsoleDetachFailure> {
    // SAFETY: the caller establishes full stream/console ownership exclusion.
    let _claim = unsafe { ProcessStderr::claim() }.map_err(ConsoleDetachFailure::Prepare)?;
    let stderr = stderr_route().map_err(ConsoleDetachFailure::Prepare)?;
    let null = OpenOptions::new()
        .read(true)
        .write(true)
        .open("NUL")
        .map_err(ConsoleDetachFailure::Prepare)?;
    install(Slot::Input, &null).map_err(ConsoleDetachFailure::Input)?;
    install(Slot::Output, &null).map_err(ConsoleDetachFailure::Output)?;
    if stderr == DetachedStderr::Null {
        install(Slot::Error, &null).map_err(ConsoleDetachFailure::Stderr)?;
    }
    // SAFETY: stdio replacement settled; no competing attachment or handler
    // registration exists. This operation transfers no resource ownership.
    if unsafe { FreeConsole() } == 0 {
        return Err(ConsoleDetachFailure::Console(io::Error::last_os_error()));
    }
    Ok(stderr)
}
