//! Platform BRE backends share the logging policy interface, not native ownership.
#[cfg(unix)]
mod posix;
#[cfg(unix)]
pub(crate) use posix::{Regex, RegexCompileFailure};
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::{Regex, RegexCompileFailure};
#[cfg(any(windows, test))]
mod bre;
