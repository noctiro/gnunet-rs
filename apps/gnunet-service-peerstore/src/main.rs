//! Independent official PEERSTORE SERVICE, with explicit process/worker owners.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
mod control;
mod foreground;
mod hellos;
mod reporting;
mod settings;
#[derive(Debug)]
struct Failures {
    original: Option<Failure>,
    cleanup: Vec<Failure>,
}
impl std::fmt::Display for Failures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PEERSTORE original={:?}; independent cleanup={:?}",
            self.original, self.cleanup
        )
    }
}
impl Error for Failures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original.as_deref()
    }
}
fn aggregate(result: Result<(), Failure>, cleanup: Vec<Failure>) -> Result<(), Failure> {
    if cleanup.is_empty() {
        return result;
    }
    Err(Box::new(Failures {
        original: result.err(),
        cleanup,
    }))
}
fn buffer(length: usize) -> Result<Vec<u8>, Failure> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length)?;
    bytes.resize(length, 0);
    Ok(bytes)
}
fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            let _actual = writeln!(io::stderr().lock(), "gnunet-service-peerstore: {error}");
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
    result: Result<(), Failure>,
    reports: &gnunet_program_host::reporting::Reporter,
) -> Result<ExitCode, Failure> {
    use gnunet_program_host::{policy::Level, service};
    match service::retain_diagnostic(result, reports.take_error()) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(original) => {
            reports.message(
                Level::ERROR,
                "peerstore.failure",
                format_args!("gnunet-service-peerstore: {original}"),
            );
            if reports.failed() {
                let diagnostic = reports.take_error();
                let _actual = writeln!(
                    io::stderr().lock(),
                    "gnunet-service-peerstore: {original}; independent logging: {diagnostic:?}"
                );
            }
            Ok(ExitCode::FAILURE)
        }
    }
}
