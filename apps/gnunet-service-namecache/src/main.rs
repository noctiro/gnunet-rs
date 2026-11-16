//! Standard official NAMECACHE SERVICE over the existing bounded cache/server.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
mod control;
#[cfg(unix)]
mod early;
mod foreground;
mod lifecycle;
mod settings;
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _actual = writeln!(io::stderr().lock(), "gnunet-service-namecache: {error}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix::run;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows::run;
fn finish(
    result: Result<(), Failure>,
    reports: &gnunet_program_host::reporting::Reporter,
) -> Result<(), Failure> {
    if let Err(error) = &result {
        reports.message(
            gnunet_program_host::policy::Level::ERROR,
            "namecache.failure",
            format_args!("gnunet-service-namecache: {error}"),
        );
    }
    gnunet_program_host::service::retain_diagnostic(result, reports.take_error())
}
