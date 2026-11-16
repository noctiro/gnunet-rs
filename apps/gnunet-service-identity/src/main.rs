//! Standard IDENTITY SERVICE over the original canonical store and Server.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
#[cfg(unix)]
mod early;
#[cfg(any(unix, windows))]
mod foreground;
#[cfg(any(unix, windows))]
mod lifecycle;
#[cfg(any(unix, windows))]
mod settings;

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            #[cfg(any(unix, windows))]
            if error.downcast_ref::<lifecycle::Reported>().is_some() {
                return ExitCode::FAILURE;
            }
            let _actual = writeln!(io::stderr().lock(), "gnunet-service-identity: {error}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(any(unix, windows)))]
fn run() -> Result<ExitCode, Failure> {
    Err("IDENTITY SERVICE requires a native Unix or Windows runtime".into())
}

#[cfg(any(unix, windows))]
fn finish(
    result: Result<(), Failure>,
    reports: &gnunet_program_host::reporting::Reporter,
) -> Result<ExitCode, Failure> {
    use gnunet_program_host::{policy::Level, service};
    match result {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(original) => {
            reports.message(
                Level::ERROR,
                "identity.failed",
                format_args!("gnunet-service-identity: {original}"),
            );
            let original: Result<(), Failure> =
                service::retain_diagnostic(Err(original), reports.take_error());
            let original = match original {
                Err(original) if reports.failed() => {
                    let fallback = {
                        let mut err = io::stderr().lock();
                        writeln!(err, "gnunet-service-identity: {original}")
                            .and_then(|()| err.flush())
                    };
                    service::retain_diagnostic(Err(original), fallback.err())
                }
                other => other,
            };
            original
                .map(|()| ExitCode::SUCCESS)
                .map_err(|error| Box::new(lifecycle::Reported(error)) as Failure)
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
