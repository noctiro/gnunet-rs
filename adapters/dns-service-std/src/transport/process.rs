//! Native child and pipe ownership behind the shared DNS framing driver.
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
use std::io;
#[cfg(unix)]
pub(super) use unix::{Child, Input, Output, spawn};
#[cfg(windows)]
pub(super) use windows::{Child, Input, Output, spawn};
pub(super) struct Spawned {
    pub child: Child,
    pub stdin: Option<Input>,
    pub stdout: Option<Output>,
    pub startup_error: Option<io::Error>,
}
#[derive(Clone, Copy)]
pub(super) enum Stop {
    Graceful,
    Force,
}
