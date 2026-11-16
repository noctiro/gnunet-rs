//! Standard DATASTORE SERVICE with selected logging and original worker cleanup.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
#[cfg(any(unix, windows))]
mod control;
#[cfg(any(unix, windows))]
mod foreground;
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
            "DATASTORE original={:?}; independent cleanup={:?}",
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
    let mut remaining = cleanup.into_iter();
    let Some(original) = result.err().or_else(|| remaining.next()) else {
        return Ok(());
    };
    let cleanup: Vec<_> = remaining.collect();
    if cleanup.is_empty() {
        return Err(original);
    }
    Err(Box::new(Failures {
        original: Some(original),
        cleanup,
    }))
}
fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            let _actual = writeln!(io::stderr().lock(), "gnunet-service-datastore: {error}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(any(unix, windows)))]
fn run() -> Result<ExitCode, Failure> {
    Err("DATASTORE SERVICE requires a native Unix or Windows runtime".into())
}
#[cfg(any(unix, windows))]
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
                "datastore.failure",
                Level::ERROR,
                format_args!("gnunet-service-datastore: {original}"),
            ) {
                let _actual = writeln!(
                    io::stderr().lock(),
                    "gnunet-service-datastore: {original}; independent logging failure: {diagnostic}"
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
