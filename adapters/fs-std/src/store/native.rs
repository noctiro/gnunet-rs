//! Native directory authority; hashing, verification and publication stay shared.
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
pub(super) use unix::Directory;
#[cfg(windows)]
pub(super) use windows::Directory;
