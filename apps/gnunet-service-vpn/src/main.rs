//! Standard VPN SERVICE; all detach/identity changes precede runtime owners.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
mod device;
use gnunet_vpn_host::discovery;
#[cfg(unix)]
mod early;
mod foreground;
mod lifecycle;
#[cfg(windows)]
mod recovery;
mod settings;
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
            let _actual = writeln!(io::stderr().lock(), "gnunet-service-vpn: {error}");
            ExitCode::FAILURE
        }
    }
}
fn finish(
    result: Result<(), Failure>,
    reports: &gnunet_program_host::reporting::Reporter,
) -> Result<ExitCode, Failure> {
    if let Err(error) = &result {
        reports.message(
            gnunet_program_host::policy::Level::ERROR,
            "vpn.failure",
            format_args!("gnunet-service-vpn: {error}"),
        );
    }
    match gnunet_program_host::service::retain_diagnostic(result, reports.take_error()) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => {
            if reports.failed() {
                let _actual = writeln!(io::stderr().lock(), "gnunet-service-vpn: {error}");
            }
            Ok(ExitCode::FAILURE)
        }
    }
}
