//! Native PILS startup around one shared official authority service.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
mod foreground;
#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix::run;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows::run;
fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            let _actual = writeln!(io::stderr().lock(), "gnunet-service-pils: {error}");
            ExitCode::FAILURE
        }
    }
}
fn finish(
    result: Result<(), Failure>,
    reports: &gnunet_program_host::reporting::Reporter,
) -> Result<ExitCode, Failure> {
    use gnunet_program_host::{policy::Level, service};
    match service::retain_diagnostic(result, reports.take_error()) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(original) => {
            reports.message(
                Level::ERROR,
                "pils.failure",
                format_args!("gnunet-service-pils: {original}"),
            );
            if reports.failed() {
                let diagnostic = reports.take_error();
                let _actual = writeln!(
                    io::stderr().lock(),
                    "gnunet-service-pils: {original}; independent logging: {diagnostic:?}"
                );
            }
            Ok(ExitCode::FAILURE)
        }
    }
}
