//! Official ARM SERVICE fresh-process entry, independent from gnunet-arm CLI.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            let _actual = writeln!(io::stderr().lock(), "gnunet-service-arm: {error}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
use unix::run;
#[cfg(windows)]
use windows::run;
#[cfg(not(any(unix, windows)))]
fn run() -> Result<ExitCode, Failure> {
    Err("ARM SERVICE needs a native Unix or Windows process backend".into())
}
#[cfg(any(unix, windows))]
fn complete(
    result: Result<(), Failure>,
    logger: &mut gnunet_program_host::logging::Logger<'_>,
    clock: &gnunet_program_host::shared_clock::SharedClock,
) -> Result<ExitCode, Failure> {
    use gnunet_program_host::{policy::Level, service};
    let diagnostic = result.as_ref().err().and_then(|error| {
        service::diagnostic(
            logger,
            clock,
            "arm.main.failed",
            Level::ERROR,
            format_args!("ARM service failed: {error}"),
        )
        .err()
    });
    service::retain_diagnostic(result, diagnostic)?;
    Ok(ExitCode::SUCCESS)
}
