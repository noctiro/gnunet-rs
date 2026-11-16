//! Standard official GNS SERVICE using the existing actual Rust GNS owners.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Cause = Box<dyn Error>;
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
            if error.downcast_ref::<lifecycle::Reported>().is_some() {
                return ExitCode::FAILURE;
            }
            let _actual = writeln!(io::stderr().lock(), "gnunet-service-gns: {error}");
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
    result: Result<(), Cause>,
    reports: &gnunet_program_host::reporting::Reporter,
) -> Result<(), Cause> {
    if let Err(error) = &result {
        reports.message(
            gnunet_program_host::policy::Level::ERROR,
            "gns.failure",
            format_args!("gnunet-service-gns: {error}"),
        );
    }
    gnunet_program_host::service::retain_diagnostic(result, reports.take_error())
        .map_err(|error| Box::new(lifecycle::Reported(error)) as Cause)
}
