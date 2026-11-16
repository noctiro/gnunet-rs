//! Official DNS SERVICE entry and explicit original process/source ownership.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
#[cfg(unix)]
mod early;
mod foreground;
mod packet_source;
mod settings;
mod statistics;
fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            // Only initialization before the selected Reporter reaches here.
            let _actual = writeln!(io::stderr().lock(), "gnunet-service-dns: {error}");
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
pub(crate) fn startup_check(
    reports: &gnunet_program_host::reporting::Reporter,
) -> Result<(), Failure> {
    if reports.failed() {
        Err("DNS selected diagnostic destination failed".into())
    } else {
        Ok(())
    }
}

fn finish(
    result: Result<(), Failure>,
    reports: &gnunet_program_host::reporting::Reporter,
) -> Result<ExitCode, Failure> {
    let result = gnunet_program_host::service::retain_diagnostic(result, reports.take_error());
    match result {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(original) => {
            reports.message(
                gnunet_program_host::policy::Level::ERROR,
                "dns.failure",
                format_args!("gnunet-service-dns: {original}"),
            );
            if reports.failed() {
                let diagnostic = reports.take_error();
                let _actual = writeln!(
                    io::stderr().lock(),
                    "gnunet-service-dns: {original}; independent final logging failure: {diagnostic:?}"
                );
            }
            Ok(ExitCode::FAILURE)
        }
    }
}
