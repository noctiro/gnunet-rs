//! Actual official DNS utility PROGRAM entry point.
#![forbid(unsafe_code)]
use std::{
    io::{self, Write},
    process::ExitCode,
};
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _diagnostic = writeln!(io::stderr().lock(), "gnunet-dns-redirector: {error}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(unix)]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    gnunet_dns_tools_host::run(gnunet_dns_tools_host::Action::Redirect)
}
#[cfg(not(unix))]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    Err("DNS native utility needs Unix CLIENT transport".into())
}
