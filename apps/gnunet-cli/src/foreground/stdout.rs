//! Platform output progress; protocol rows and their cursor stay with Output.
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
pub(crate) use unix::Stdout;
#[cfg(windows)]
pub(crate) use windows::Stdout;
