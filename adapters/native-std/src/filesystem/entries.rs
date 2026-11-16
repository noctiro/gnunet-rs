//! Independent native enumeration cursors; names are observations, not authority.
#[cfg(any(windows, test))]
mod record;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
pub use unix::Entries;
#[cfg(windows)]
pub use windows::Entries;
