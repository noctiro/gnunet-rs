//! Explicit early-startup process stderr installation, separate from caller-owned
//! logging. Native ownership and mutation requirements belong to each backend.
#[cfg(unix)]
mod posix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
pub use posix::ProcessStderr;
#[cfg(unix)]
pub(crate) use posix::lift;
#[cfg(windows)]
pub use windows::ProcessStderr;
#[cfg(windows)]
pub(crate) use windows::lift;
