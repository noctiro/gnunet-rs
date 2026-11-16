//! Standard automatic sharing PROGRAM; all publication uses the real FS API.
#![deny(unsafe_code)]
#[cfg(any(unix, windows))]
mod program;
#[cfg(any(unix, windows))]
mod startup;
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _diagnostic = writeln!(io::stderr().lock(), "gnunet-auto-share: {error}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(any(unix, windows)))]
fn run() -> Result<(), Box<dyn Error>> {
    Err("automatic sharing has no native runtime for this target".into())
}
#[cfg(any(unix, windows))]
#[expect(
    unsafe_code,
    reason = "Sole single-threaded initial parent descriptor transfer before any runtime, logger, worker or filesystem publication resource"
)]
fn run() -> Result<(), Box<dyn Error>> {
    // SAFETY: first operation of this process, no competing descriptor/environment
    // access, resource owner, prior capture, thread or asynchronous task exists.
    let parent = unsafe { startup::capture()? };
    program::run(parent)
}
