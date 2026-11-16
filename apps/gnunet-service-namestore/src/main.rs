//! Standard official NAMESTORE SERVICE using the existing actual Rust NAMESTORE owners.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
#[cfg(unix)]
mod early;
#[cfg(any(unix, windows))]
mod foreground;
#[cfg(any(unix, windows))]
mod lifecycle;
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
            let _actual = writeln!(io::stderr().lock(), "gnunet-service-namestore: {error}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(any(unix, windows)))]
fn run() -> Result<(), Failure> {
    Err("NAMESTORE SERVICE requires a native Unix or Windows runtime".into())
}

#[cfg(any(unix, windows))]
fn finish(
    result: Result<(), Failure>,
    reports: &gnunet_program_host::reporting::Reporter,
) -> Result<(), Failure> {
    if let Err(error) = &result {
        reports.message(
            gnunet_program_host::policy::Level::ERROR,
            "namestore.failure",
            format_args!("gnunet-service-namestore: {error}"),
        );
    }
    gnunet_program_host::service::retain_diagnostic(result, reports.take_error())
        .map_err(|error| Box::new(lifecycle::Reported(error)) as Failure)
}

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix::run;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows::run;
