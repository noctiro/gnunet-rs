//! Standard official FS SERVICE using the existing actual Rust FS owners.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Cause = Box<dyn Error>;
#[cfg(any(unix, windows))]
mod control;
#[cfg(unix)]
mod early;
#[cfg(any(unix, windows))]
mod foreground;
#[cfg(any(unix, windows))]
mod lifecycle;
#[cfg(any(unix, windows))]
mod peer;
#[cfg(any(unix, windows))]
mod settings;
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            #[cfg(any(unix, windows))]
            if error.downcast_ref::<lifecycle::Reported>().is_some() {
                return ExitCode::FAILURE;
            }
            let _actual = writeln!(io::stderr().lock(), "gnunet-service-fs: {error}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(any(unix, windows)))]
fn run() -> Result<(), Cause> {
    Err("FS SERVICE requires a native Unix or Windows runtime".into())
}
#[cfg(any(unix, windows))]
fn finish(
    result: Result<(), Cause>,
    reports: &gnunet_program_host::reporting::Reporter,
) -> Result<(), Cause> {
    if let Err(error) = &result {
        reports.message(
            gnunet_program_host::policy::Level::ERROR,
            "fs.failure",
            format_args!("gnunet-service-fs: {error}"),
        );
    }
    gnunet_program_host::service::retain_diagnostic(result, reports.take_error())
        .map_err(|error| Box::new(lifecycle::Reported(error)) as Cause)
}

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix::run;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows::run;
