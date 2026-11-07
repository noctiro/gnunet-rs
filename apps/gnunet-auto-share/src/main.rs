//! Standard automatic sharing PROGRAM; all publication uses the real FS API.
#![deny(unsafe_code)]
#[cfg(unix)]
mod program;
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
#[cfg(not(unix))]
fn run() -> Result<(), Box<dyn Error>> {
    Err("automatic sharing requires Unix anchored directory support".into())
}
#[cfg(unix)]
#[expect(
    unsafe_code,
    reason = "Sole single-threaded initial parent descriptor transfer before any runtime, logger, worker or filesystem publication resource"
)]
fn run() -> Result<(), Box<dyn Error>> {
    use gnunet_service_startup::{InheritedMode, InheritedResources};
    // SAFETY: first operation of this process, no competing descriptor/environment
    // access, resource owner, prior capture, thread or asynchronous task exists.
    let captured = unsafe {
        gnunet_service_startup::capture_from_environment(InheritedMode::CloseAfterConfiguredBind)?
    };
    if let Some(notice) = captured.control_notice {
        writeln!(
            io::stderr().lock(),
            "gnunet-auto-share parent-control declaration: {notice:?}"
        )?;
    }
    match captured.inherited {
        InheritedResources::CloseAfterBind(hold) => {
            let nonempty = !hold.is_empty();
            let report = hold.abort();
            if nonempty {
                return Err(format!("automatic sharing has no SERVICE listener; inherited descriptors refused: {report:?}").into());
            }
        }
        InheritedResources::Listeners(_) => {
            return Err("unexpected automatic sharing descriptor mode".into());
        }
    }
    program::run(captured.parent_control)
}
