//! Owned standard routes and native readiness/cancellation boundaries.
mod input;
pub use input::*;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;
#[cfg(windows)]
mod output;
#[cfg(unix)]
#[path = "stdio/unix.rs"]
mod output;
pub use output::Output;
mod text;
pub use text::TextInput;

/// Duplicate the original stdin route without buffered reads or flag changes.
/// Capture before buffered stdin use, excluding concurrent route mutation and
/// other readers. The caller owns execution and retirement of blocking I/O.
pub fn stdin_file() -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        Ok(std::fs::File::from(
            std::io::stdin().as_fd().try_clone_to_owned()?,
        ))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle;
        Ok(std::fs::File::from(
            std::io::stdin().as_handle().try_clone_to_owned()?,
        ))
    }
}
/// Duplicate stdout for raw bytes, preserving its original native object.
/// Capture excludes concurrent route mutation; the caller provides exclusive
/// output use and an explicit blocking-I/O execution/retirement policy.
pub fn stdout_file() -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        Ok(std::fs::File::from(
            std::io::stdout().as_fd().try_clone_to_owned()?,
        ))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle;
        Ok(std::fs::File::from(
            std::io::stdout().as_handle().try_clone_to_owned()?,
        ))
    }
}
