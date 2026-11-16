//! Standard official REVOCATION SERVICE and original process/worker owners.
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
mod settings;
mod statistics;
fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            // Only errors before the selected service Reporter exists reach here.
            let _actual = writeln!(io::stderr().lock(), "gnunet-service-revocation: {error}");
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
fn startup_check(reports: &gnunet_program_host::reporting::Reporter) -> Result<(), Failure> {
    if let Some(error) = reports.take_error() {
        return Err(Box::new(error));
    }
    if reports.failed() {
        return Err("REVOCATION selected diagnostic destination already failed".into());
    }
    Ok(())
}
#[cfg(unix)]
fn finish_logger(
    result: Result<(), Failure>,
    logger: &mut gnunet_program_host::logging::Logger<'_>,
    clock: &gnunet_program_host::shared_clock::SharedClock,
) -> Result<ExitCode, Failure> {
    use gnunet_program_host::{policy::Level, service};
    match result {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(original) => {
            if let Err(diagnostic) = service::diagnostic(
                logger,
                clock,
                "revocation.startup.failure",
                Level::ERROR,
                format_args!("gnunet-service-revocation: {original}"),
            ) {
                let _actual = writeln!(
                    io::stderr().lock(),
                    "gnunet-service-revocation: {original}; independent logging failure: {diagnostic}"
                );
            }
            Ok(ExitCode::FAILURE)
        }
    }
}

#[cfg(windows)]
fn finish(
    result: Result<(), Failure>,
    reports: &gnunet_program_host::reporting::Reporter,
) -> Result<ExitCode, Failure> {
    match gnunet_program_host::service::retain_diagnostic(result, reports.take_error()) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(original) => {
            reports.message(
                gnunet_program_host::policy::Level::ERROR,
                "revocation.failure",
                format_args!("gnunet-service-revocation: {original}"),
            );
            if reports.failed() {
                let diagnostic = reports.take_error();
                let _reported = writeln!(
                    io::stderr().lock(),
                    "gnunet-service-revocation: {original}; independent logging: {diagnostic:?}"
                );
            }
            Ok(ExitCode::FAILURE)
        }
    }
}
