//! Official DNS SERVICE entry and explicit original process/source ownership.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
#[cfg(feature = "macos-dns-control")]
mod control;
#[cfg(unix)]
mod early;
mod foreground;
mod packet_source;
#[cfg(all(
    any(target_os = "macos", target_os = "ios"),
    feature = "apple-dns-proxy"
))]
mod provider;
#[cfg(all(target_os = "ios", feature = "apple-dns-proxy"))]
pub use provider::run_app_extension;
mod settings;
mod statistics;

/// Run the containing application's explicit DNS proxy management command.
#[cfg(feature = "macos-dns-control")]
pub fn run_control() -> ExitCode {
    control::run()
}

/// Enter the native DNS system-extension host. No provider is installed or
/// activated by this entry; the operating system must launch the signed bundle.
#[cfg(feature = "apple-dns-proxy")]
pub fn run_provider() -> ExitCode {
    #[cfg(target_os = "macos")]
    let result = provider::run_system_extension();
    #[cfg(not(target_os = "macos"))]
    let result: Result<(), Failure> =
        Err("the DNS system extension requires macOS 15 or later".into());
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _actual = writeln!(io::stderr().lock(), "gnunet-dns-proxy: {error}");
            ExitCode::FAILURE
        }
    }
}
/// Run the ordinary DNS service with its configured native source.
pub fn run() -> ExitCode {
    match run_native_service() {
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
use unix::run as run_native_service;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows::run as run_native_service;
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
