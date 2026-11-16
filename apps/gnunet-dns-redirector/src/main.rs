//! Actual official DNS utility PROGRAM entry point.
#![deny(unsafe_code)]
mod early;
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
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let early = early::capture()?;
    gnunet_dns_tools_host::run(gnunet_dns_tools_host::Action::Redirect, early.parent)
}
