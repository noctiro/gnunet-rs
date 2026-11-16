//! Absolute-date platform selection; microsecond policy stays at the host boundary.
#[cfg(unix)]
mod posix;
#[cfg(unix)]
pub(crate) use posix::absolute_calendar;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::absolute_calendar;
