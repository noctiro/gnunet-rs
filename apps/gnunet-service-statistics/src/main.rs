//! Independent official STATISTICS SERVICE, with explicit startup, protocol and storage owners.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
#[cfg(any(unix, windows))]
#[derive(Debug)]
struct PhaseFailure {
    stage: &'static str,
    source: Failure,
}
#[cfg(any(unix, windows))]
impl std::fmt::Display for PhaseFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "statistics {}: {}", self.stage, self.source)
    }
}
#[cfg(any(unix, windows))]
impl Error for PhaseFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}
#[cfg(any(unix, windows))]
mod control;
#[cfg(any(unix, windows))]
mod host;
#[cfg(any(unix, windows))]
mod reporting;
#[cfg(any(unix, windows))]
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
            "STATISTICS original={:?}; independent cleanup={:?}",
            self.original, self.cleanup
        )
    }
}
impl Error for Failures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original.as_deref()
    }
}
fn aggregate(result: Result<(), Failure>, mut cleanup: Vec<Failure>) -> Result<(), Failure> {
    if cleanup.is_empty() {
        return result;
    }
    Err(Box::new(Failures {
        original: Some(result.err().unwrap_or_else(|| cleanup.remove(0))),
        cleanup,
    }))
}
fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            let _actual = writeln!(io::stderr().lock(), "gnunet-service-statistics: {error}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(any(unix, windows)))]
fn run() -> Result<ExitCode, Failure> {
    Err("the STATISTICS SERVICE requires a native Unix or Windows runtime".into())
}
fn complete(
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
                "statistics.failure",
                Level::ERROR,
                format_args!("gnunet-service-statistics: {original}"),
            ) {
                let _actual = writeln!(
                    io::stderr().lock(),
                    "gnunet-service-statistics: {original}; independent logging failure: {diagnostic}"
                );
            }
            Ok(ExitCode::FAILURE)
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
